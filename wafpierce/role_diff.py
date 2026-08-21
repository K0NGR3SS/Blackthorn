"""Captured-request replay and multi-identity authorization differentials."""
from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import requests

from .pentest_models import (
    CapturedRequest,
    IdentityProfile,
    VerificationState,
)
from .pentest_policy import ExecutionPolicy, PolicyViolation, RequestBudget
from .redaction import redact_text
from .secret_store import get_secret


MAX_REPLAY_BODY_BYTES = 4 * 1024 * 1024
_SECRET_PLACEHOLDER = re.compile(r"\{\{secret:([a-zA-Z0-9_.:-]{1,128})\}\}")
_VOLATILE = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f-]{27,}|\b1[5-9]\d{8,12}\b|"
    r"csrf[^\s\"']{0,24}[=:][^\s\"']+)",
    re.IGNORECASE,
)
_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "x-api-key",
    "api-key", "x-auth-token", "x-csrf-token",
})


class ReplayError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class CredentialMaterial:
    """Process-local identity material. This object is never persisted."""

    headers: Tuple[Tuple[str, str], ...] = ()
    template_values: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, repr=False)
class RenderedRequest:
    method: str
    url: str
    headers: Tuple[Tuple[str, str], ...]
    body: bytes
    identity_id: str


@dataclass(frozen=True, repr=False)
class ResponseSnapshot:
    status: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: float = 0.0

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def normalized_text(self) -> str:
        return _VOLATILE.sub("<volatile>", self.text[:100_000])


@dataclass(frozen=True)
class RoleComparison:
    identity_id: str
    identity_name: str
    role: str
    status: int
    size: int
    sha256: str
    similarity_to_owner: float
    expected_denied: bool
    protected_markers: Tuple[str, ...]
    suspicious: bool
    reasons: Tuple[str, ...]


@dataclass(frozen=True)
class AuthorizationMatrixResult:
    request_id: str
    owner_identity_id: str
    comparisons: Tuple[RoleComparison, ...]
    verification: VerificationState
    evidence: Dict[str, Any]


CredentialLoader = Callable[[IdentityProfile], CredentialMaterial]
Transport = Callable[[RenderedRequest], ResponseSnapshot]


def secret_store_credential_loader(identity: IdentityProfile) -> CredentialMaterial:
    """Resolve one identity from Blackthorn's process/keyring secret boundary."""
    kind = identity.auth_kind.lower()
    if kind in {"anonymous", "none"}:
        return CredentialMaterial()
    secret = get_secret(identity.credential_handle)
    if not secret:
        raise ReplayError("credential material is unavailable for identity %s" % identity.name)
    if kind == "bearer":
        headers = (("Authorization", "Bearer %s" % secret),)
    elif kind == "cookie":
        headers = (("Cookie", secret),)
    elif kind == "basic":
        token = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        headers = (("Authorization", "Basic %s" % token),)
    elif kind == "authorization":
        headers = (("Authorization", secret),)
    else:
        raise ReplayError("unsupported authentication kind: %s" % kind)
    return CredentialMaterial(
        headers=headers,
        template_values={identity.credential_handle: secret},
    )


def _render_template(value: str, material: CredentialMaterial) -> str:
    values = dict(material.template_values)

    def replace(match: re.Match[str]) -> str:
        handle = match.group(1)
        if handle not in values:
            # Header credentials are applied separately. Unresolved body values
            # must fail closed rather than send placeholder text to a target.
            raise ReplayError("secret handle is unavailable: %s" % handle)
        return values[handle]

    return _SECRET_PLACEHOLDER.sub(replace, value)


def render_for_identity(
    request: CapturedRequest,
    identity: IdentityProfile,
    material: CredentialMaterial,
) -> RenderedRequest:
    public_headers = [
        (name, value)
        for name, value in request.headers
        if name.lower() not in _SENSITIVE_HEADER_NAMES
    ]
    public_headers.extend(material.headers)
    body = _render_template(request.body_template, material).encode("utf-8")
    if len(body) > MAX_REPLAY_BODY_BYTES:
        raise ReplayError("rendered request body exceeds the replay limit")
    return RenderedRequest(
        method=request.method,
        url=request.url,
        headers=tuple(public_headers),
        body=body,
        identity_id=identity.identity_id,
    )


class RequestsReplayTransport:
    """Scope-checked requests transport for ordinary role comparison.

    Duplicate-header and connection-level work intentionally belongs to the raw
    transport module. This transport follows no redirects and reads a bounded
    response body so credentials cannot cross an origin boundary.
    """

    def __init__(
        self,
        policy: ExecutionPolicy,
        *,
        verify_tls: bool = True,
        session: Optional[requests.Session] = None,
        budget: Optional[RequestBudget] = None,
    ):
        self.policy = policy
        self.verify_tls = bool(verify_tls)
        self.session = session or requests.Session()
        self.budget = budget or RequestBudget(
            policy.request_budget, policy.minimum_delay
        )

    def __call__(self, request: RenderedRequest) -> ResponseSnapshot:
        from .pentest_models import ImpactLevel

        self.policy.require(request.url, ImpactLevel.SAFE)
        self.budget.consume()
        headers: Dict[str, str] = {}
        for name, value in request.headers:
            headers[name] = value
        started = time.monotonic()
        response = self.session.request(
            request.method,
            request.url,
            headers=headers,
            data=request.body if request.body else None,
            timeout=self.policy.timeout,
            verify=self.verify_tls,
            allow_redirects=False,
            stream=True,
        )
        chunks = []
        size = 0
        try:
            for chunk in response.iter_content(64 * 1024):
                size += len(chunk)
                if size > self.policy.max_response_bytes:
                    raise ReplayError("response exceeded the engagement byte limit")
                chunks.append(chunk)
        finally:
            response.close()
        safe_headers = {
            str(name).lower(): str(value)
            for name, value in response.headers.items()
            if str(name).lower() not in {"set-cookie", "authorization"}
        }
        return ResponseSnapshot(
            status=response.status_code,
            headers=safe_headers,
            body=b"".join(chunks),
            elapsed_ms=(time.monotonic() - started) * 1000,
        )


def _similarity(left: ResponseSnapshot, right: ResponseSnapshot) -> float:
    if left.sha256 == right.sha256:
        return 1.0
    return difflib.SequenceMatcher(
        None, left.normalized_text, right.normalized_text
    ).ratio()


class RoleMatrixTester:
    def __init__(self, transport: Transport, credential_loader: CredentialLoader):
        self.transport = transport
        self.credential_loader = credential_loader

    def test(
        self,
        request: CapturedRequest,
        identities: Sequence[IdentityProfile],
        owner_identity_id: str,
        *,
        expected_denied: Iterable[str] = (),
        protected_markers: Iterable[str] = (),
    ) -> AuthorizationMatrixResult:
        if not 2 <= len(identities) <= 64:
            raise ReplayError("role matrix requires between 2 and 64 identities")
        by_id = {identity.identity_id: identity for identity in identities}
        if owner_identity_id not in by_id:
            raise ReplayError("owner identity is missing from the role matrix")
        denied = set(expected_denied)
        unknown = denied - set(by_id)
        if unknown:
            raise ReplayError("expected-denied identities are missing: %s" % sorted(unknown))
        markers = tuple(str(item) for item in protected_markers if str(item))
        if len(markers) > 32 or any(len(marker) > 256 for marker in markers):
            raise ReplayError("protected response controls exceed the evidence limit")
        if any(redact_text(marker) != marker for marker in markers):
            raise ReplayError("protected response controls cannot contain secret-like material")
        snapshots: Dict[str, ResponseSnapshot] = {}
        for identity in identities:
            material = self.credential_loader(identity)
            rendered = render_for_identity(request, identity, material)
            snapshots[identity.identity_id] = self.transport(rendered)

        owner = snapshots[owner_identity_id]
        owner_success = 200 <= owner.status < 300
        comparisons: List[RoleComparison] = []
        positive_oracle = False
        for identity in identities:
            snapshot = snapshots[identity.identity_id]
            similarity = _similarity(owner, snapshot)
            matched = tuple(
                marker for marker in markers
                if marker in owner.text and marker in snapshot.text
            )
            should_deny = identity.identity_id in denied
            reasons: List[str] = []
            if should_deny and 200 <= snapshot.status < 300:
                reasons.append("expected-denied identity received a success response")
            if should_deny and owner_success and snapshot.sha256 == owner.sha256:
                reasons.append("response exactly matches the owner's protected response")
            elif should_deny and owner_success and similarity >= 0.97:
                reasons.append("response closely matches the owner's protected response")
            if should_deny and matched:
                reasons.append("user-supplied protected marker was returned")
                positive_oracle = True
            suspicious = bool(reasons)
            comparisons.append(RoleComparison(
                identity_id=identity.identity_id,
                identity_name=identity.name,
                role=identity.role,
                status=snapshot.status,
                size=len(snapshot.body),
                sha256=snapshot.sha256,
                similarity_to_owner=round(similarity, 6),
                expected_denied=should_deny,
                protected_markers=matched,
                suspicious=suspicious,
                reasons=tuple(reasons),
            ))

        suspicious = [item for item in comparisons if item.suspicious]
        negative_control = owner_success and bool(markers) and all(
            marker in owner.text for marker in markers
        )
        if positive_oracle and negative_control:
            verification = VerificationState.CONFIRMED
        elif suspicious:
            verification = VerificationState.CANDIDATE
        else:
            verification = VerificationState.OBSERVATION
        evidence = {
            "positive_oracle": positive_oracle,
            "negative_control": negative_control,
            "owner_status": owner.status,
            "protected_markers": list(markers),
            "suspicious_identity_ids": [item.identity_id for item in suspicious],
            "comparisons": [
                {
                    "identity_id": item.identity_id,
                    "role": item.role,
                    "status": item.status,
                    "size": item.size,
                    "sha256": item.sha256,
                    "similarity_to_owner": item.similarity_to_owner,
                    "expected_denied": item.expected_denied,
                    "matched_markers": list(item.protected_markers),
                    "reasons": list(item.reasons),
                }
                for item in comparisons
            ],
        }
        return AuthorizationMatrixResult(
            request_id=request.request_id,
            owner_identity_id=owner_identity_id,
            comparisons=tuple(comparisons),
            verification=verification,
            evidence=evidence,
        )
