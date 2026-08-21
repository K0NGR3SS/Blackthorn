"""Evidence-oriented authentication and session lifecycle analysis.

The helpers in this module deliberately operate on bounded response snapshots and
keyed fingerprints.  They never persist bearer material, cookies, OAuth codes, or
state values.  Network execution remains behind the scoped transports in
``role_diff``; this module decides what the resulting observations prove.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import urlsplit

from .pentest_models import VerificationState, validate_url
from .redaction import redact_text
from .role_diff import ResponseSnapshot


MAX_SET_COOKIE_LINES = 128
MAX_SET_COOKIE_BYTES = 64 * 1024
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")


class AuthWorkflowError(ValueError):
    """Raised when lifecycle evidence is malformed or unsafe to retain."""


@dataclass(frozen=True)
class SessionCookieObservation:
    name: str
    fingerprint: str
    secure: bool
    http_only: bool
    same_site: str
    domain: str
    path: str
    expires_immediately: bool


@dataclass(frozen=True)
class CookiePolicyIssue:
    cookie_name: str
    severity: str
    issue: str


@dataclass(frozen=True)
class LoginRotationResult:
    verification: VerificationState
    retained_cookie_names: Tuple[str, ...]
    rotated_cookie_names: Tuple[str, ...]
    missing_after_login: Tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class LogoutInvalidationResult:
    verification: VerificationState
    status_before: int
    status_after: int
    protected_markers_before: Tuple[str, ...]
    protected_markers_after: Tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class OAuthFlowObservation:
    authorization_endpoint: str
    redirect_uri: str
    registered_redirect_uris: Tuple[str, ...]
    state_sent: bool
    state_matches: bool
    pkce_sent: bool
    pkce_verified: bool
    nonce_sent: bool = False
    nonce_verified: bool = False
    response_mode: str = "query"
    issuer_matches: bool = True

    def __post_init__(self) -> None:
        authorization = validate_url(self.authorization_endpoint, allow_ws=False)
        redirect = validate_url(self.redirect_uri, allow_ws=False)
        registered = tuple(
            validate_url(item, allow_ws=False) for item in self.registered_redirect_uris
        )
        if not registered or len(registered) > 64:
            raise AuthWorkflowError("between 1 and 64 registered redirect URIs are required")
        if any(redact_text(item) != item for item in (authorization, redirect, *registered)):
            raise AuthWorkflowError("OAuth URLs cannot contain secret-like material")
        mode = str(self.response_mode or "query").lower()
        if mode not in {"query", "form_post", "fragment"}:
            raise AuthWorkflowError("unsupported OAuth response mode")
        object.__setattr__(self, "authorization_endpoint", authorization)
        object.__setattr__(self, "redirect_uri", redirect)
        object.__setattr__(self, "registered_redirect_uris", registered)
        object.__setattr__(self, "response_mode", mode)


@dataclass(frozen=True)
class OAuthFlowResult:
    verification: VerificationState
    issues: Tuple[str, ...]
    controls_passed: Tuple[str, ...]


@dataclass(frozen=True)
class TimeoutProbePlan:
    intervals_seconds: Tuple[int, ...]
    total_duration_seconds: int
    request_count: int
    execution_supported: bool = False


def observe_set_cookie_headers(
    header_values: Iterable[str],
    *,
    fingerprint_key: bytes,
) -> Tuple[SessionCookieObservation, ...]:
    """Parse Set-Cookie lines while retaining only an HMAC of each value."""
    if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 16:
        raise AuthWorkflowError("fingerprint key must contain at least 16 bytes")
    lines = tuple(str(value) for value in header_values)
    if len(lines) > MAX_SET_COOKIE_LINES:
        raise AuthWorkflowError("too many Set-Cookie headers")
    if sum(len(line.encode("utf-8", errors="replace")) for line in lines) > MAX_SET_COOKIE_BYTES:
        raise AuthWorkflowError("Set-Cookie evidence exceeds the size limit")

    observations: List[SessionCookieObservation] = []
    for line in lines:
        if "\r" in line or "\n" in line or "\x00" in line:
            raise AuthWorkflowError("Set-Cookie evidence contains a control separator")
        parts = [part.strip() for part in line.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        name = name.strip()
        if not _COOKIE_NAME.fullmatch(name):
            continue
        attributes: Mapping[str, str]
        parsed = {}
        flags = set()
        for item in parts[1:]:
            if "=" in item:
                key, attr_value = item.split("=", 1)
                parsed[key.strip().lower()] = attr_value.strip()
            elif item:
                flags.add(item.strip().lower())
        attributes = parsed
        max_age = attributes.get("max-age", "")
        expires_immediately = value == "" or max_age == "0"
        fingerprint = hmac.new(
            fingerprint_key,
            (name + "\x00" + value).encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()
        observations.append(SessionCookieObservation(
            name=name,
            fingerprint=fingerprint,
            secure="secure" in flags,
            http_only="httponly" in flags,
            same_site=attributes.get("samesite", "").lower(),
            domain=attributes.get("domain", "").lower(),
            path=attributes.get("path", ""),
            expires_immediately=expires_immediately,
        ))
    return tuple(observations)


def analyze_cookie_policy(
    cookies: Sequence[SessionCookieObservation],
    *,
    https_origin: bool,
) -> Tuple[CookiePolicyIssue, ...]:
    issues: List[CookiePolicyIssue] = []
    for cookie in cookies:
        if cookie.expires_immediately:
            continue
        if https_origin and not cookie.secure:
            issues.append(CookiePolicyIssue(cookie.name, "high", "missing Secure attribute"))
        if not cookie.http_only:
            issues.append(CookiePolicyIssue(cookie.name, "medium", "missing HttpOnly attribute"))
        if cookie.same_site not in {"strict", "lax", "none"}:
            issues.append(CookiePolicyIssue(cookie.name, "medium", "missing or invalid SameSite attribute"))
        elif cookie.same_site == "none" and not cookie.secure:
            issues.append(CookiePolicyIssue(cookie.name, "high", "SameSite=None requires Secure"))
        if cookie.domain.startswith("."):
            issues.append(CookiePolicyIssue(cookie.name, "low", "cookie is scoped to all subdomains"))
    return tuple(issues)


def evaluate_login_rotation(
    before_login: Sequence[SessionCookieObservation],
    after_login: Sequence[SessionCookieObservation],
    *,
    authenticated_control_passed: bool,
) -> LoginRotationResult:
    before = {item.name: item for item in before_login if not item.expires_immediately}
    after = {item.name: item for item in after_login if not item.expires_immediately}
    retained = tuple(sorted(
        name for name in before.keys() & after.keys()
        if hmac.compare_digest(before[name].fingerprint, after[name].fingerprint)
    ))
    rotated = tuple(sorted(
        name for name in before.keys() & after.keys()
        if not hmac.compare_digest(before[name].fingerprint, after[name].fingerprint)
    ))
    missing = tuple(sorted(before.keys() - after.keys()))
    if retained and authenticated_control_passed:
        return LoginRotationResult(
            VerificationState.CANDIDATE,
            retained,
            rotated,
            missing,
            "pre-authentication cookie survived a successful login; confirm with an attacker-selected value",
        )
    if retained:
        return LoginRotationResult(
            VerificationState.OBSERVATION,
            retained,
            rotated,
            missing,
            "cookie retention observed, but the authenticated control did not pass",
        )
    return LoginRotationResult(
        VerificationState.REJECTED,
        retained,
        rotated,
        missing,
        "no retained pre-authentication cookie was observed",
    )


def evaluate_logout_invalidation(
    authenticated_before: ResponseSnapshot,
    replay_after_logout: ResponseSnapshot,
    *,
    logout_acknowledged: bool,
    protected_markers: Iterable[str],
) -> LogoutInvalidationResult:
    markers = tuple(str(marker)[:256] for marker in protected_markers if str(marker))
    if len(markers) > 32:
        raise AuthWorkflowError("too many protected response controls")
    if any(redact_text(marker) != marker for marker in markers):
        raise AuthWorkflowError("protected response controls cannot contain secret-like material")
    before = tuple(marker for marker in markers if marker in authenticated_before.text)
    after = tuple(marker for marker in markers if marker in replay_after_logout.text)
    if logout_acknowledged and before and set(before).issubset(after) and replay_after_logout.status < 400:
        verification = VerificationState.CONFIRMED
        reason = "the logged-out credential still reached the protected response control"
    elif after and replay_after_logout.status < 400:
        verification = VerificationState.CANDIDATE
        reason = "protected content remained visible, but logout success was not independently established"
    else:
        verification = VerificationState.REJECTED
        reason = "the post-logout replay did not satisfy the protected response control"
    return LogoutInvalidationResult(
        verification,
        authenticated_before.status,
        replay_after_logout.status,
        before,
        after,
        reason,
    )


def evaluate_oauth_flow(observation: OAuthFlowObservation) -> OAuthFlowResult:
    authorization = urlsplit(observation.authorization_endpoint)
    redirect = urlsplit(observation.redirect_uri)
    if authorization.scheme not in {"https", "http"} or not authorization.hostname:
        raise AuthWorkflowError("authorization endpoint must be an absolute HTTP(S) URL")
    if redirect.scheme not in {"https", "http"} or not redirect.hostname:
        raise AuthWorkflowError("redirect URI must be an absolute HTTP(S) URL")
    registered = {str(item) for item in observation.registered_redirect_uris}
    issues: List[str] = []
    controls: List[str] = []
    if observation.redirect_uri not in registered:
        issues.append("redirect URI does not exactly match the registered allowlist")
    else:
        controls.append("exact redirect URI match")
    if not observation.state_sent:
        issues.append("state parameter was not sent")
    elif not observation.state_matches:
        issues.append("returned state did not match the initiating request")
    else:
        controls.append("state round trip")
    if not observation.pkce_sent:
        issues.append("PKCE challenge was not sent")
    elif not observation.pkce_verified:
        issues.append("PKCE verifier was not enforced")
    else:
        controls.append("PKCE enforcement")
    if observation.nonce_sent and not observation.nonce_verified:
        issues.append("OIDC nonce was not enforced")
    elif observation.nonce_sent:
        controls.append("OIDC nonce enforcement")
    if observation.response_mode.lower() == "fragment":
        issues.append("authorization response used the browser fragment")
    if not observation.issuer_matches:
        issues.append("issuer did not match the configured authorization server")
    verification = VerificationState.CANDIDATE if issues else VerificationState.REJECTED
    return OAuthFlowResult(verification, tuple(issues), tuple(controls))


def plan_timeout_probes(
    *,
    expected_idle_timeout_seconds: int,
    checkpoints: int = 3,
    maximum_duration_seconds: int = 8 * 60 * 60,
) -> TimeoutProbePlan:
    timeout = int(expected_idle_timeout_seconds)
    checkpoints = int(checkpoints)
    maximum = int(maximum_duration_seconds)
    if timeout < 10 or maximum < 10:
        raise AuthWorkflowError("timeout and maximum duration must be at least 10 seconds")
    if not 2 <= checkpoints <= 12:
        raise AuthWorkflowError("checkpoint count must be between 2 and 12")
    if timeout > maximum:
        raise AuthWorkflowError("expected timeout exceeds the engagement duration limit")
    # Straddle the boundary without actually sleeping or issuing traffic.
    fractions = [0.5 + (index / (checkpoints - 1)) for index in range(checkpoints)]
    intervals = tuple(sorted({min(maximum, max(1, round(timeout * value))) for value in fractions}))
    return TimeoutProbePlan(
        intervals_seconds=intervals,
        total_duration_seconds=max(intervals),
        request_count=len(intervals),
    )
