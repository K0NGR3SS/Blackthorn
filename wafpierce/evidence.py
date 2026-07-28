"""Response comparison and proof extraction for Blackthorn findings.

The scanner sends many different kinds of probes.  This module keeps the
decision logic small and testable: compare a probe with a *matched* benign
control, apply an optional vulnerability-specific oracle, and return a
proof-carrying verdict.  It deliberately distinguishes confirmed findings,
suspected findings, and ordinary negative observations.
"""
from __future__ import annotations

import difflib
import hashlib
import html
import re
from typing import Any, Callable, Dict, Iterable, Optional
from urllib.parse import unquote, unquote_plus, urljoin, urlparse


ERROR_PATTERN = re.compile(
    r"(exception|traceback|stack\s*trace|sql\s*syntax|mysql_|postgresql|"
    r"ora-\d+|internal\s*server\s*error|500\s*internal|debug\s*mode|"
    r"fatal\s*error|warning:)",
    re.IGNORECASE,
)

_SAFE_RESPONSE_HEADERS = {
    "allow", "cache-control", "content-language", "content-length",
    "content-security-policy", "content-type", "location", "server",
    "vary", "www-authenticate", "x-content-type-options", "x-frame-options",
    "x-powered-by", "x-xss-protection",
}


def _header_dict(headers: Any) -> Dict[str, str]:
    try:
        return {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
    except Exception:
        return {}


def _excerpt(text: str, needle: str = "", limit: int = 700) -> str:
    """Return a bounded excerpt around the evidence instead of a whole page."""
    text = text or ""
    if not text:
        return ""
    start = 0
    if needle:
        pos = text.lower().find(needle.lower())
        if pos >= 0:
            start = max(0, pos - 180)
    sample = text[start:start + limit]
    return sample.replace("\x00", "\\0")


def snapshot_response(response: Any, normalize: Callable[[str], str]) -> Dict[str, Any]:
    """Create an internal response snapshot suitable for comparison/caching."""
    content = getattr(response, "content", b"") or b""
    try:
        text = getattr(response, "text", "") or ""
    except Exception:
        text = content.decode("utf-8", errors="replace")
    headers = _header_dict(getattr(response, "headers", {}))
    return {
        "status": int(getattr(response, "status_code", 0) or 0),
        "size": len(content),
        "content_type": headers.get("content-type", ""),
        "location": headers.get("location", ""),
        "headers": headers,
        "safe_headers": {
            k: v for k, v in headers.items() if k in _SAFE_RESPONSE_HEADERS
        },
        "hash": hashlib.sha256(content).hexdigest(),
        "text": text[:50000],
        "normalized": normalize(text[:50000]),
    }


def public_response(snapshot: Dict[str, Any], needle: str = "") -> Dict[str, Any]:
    """Strip comparison-only internals and return report-safe response evidence."""
    return {
        "status": snapshot.get("status", 0),
        "size": snapshot.get("size", 0),
        "content_type": snapshot.get("content_type", ""),
        "headers": dict(snapshot.get("safe_headers") or {}),
        "excerpt": _excerpt(str(snapshot.get("text") or ""), needle),
        "sha256": snapshot.get("hash", ""),
    }


def _first_new_regex(patterns: Iterable[str], observed: str, control: str):
    for raw in patterns:
        try:
            pattern = re.compile(raw, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        match = pattern.search(observed)
        if match and not pattern.search(control):
            return match.group(0)
    return None


def analyze_response(
    observed: Dict[str, Any],
    control: Dict[str, Any],
    *,
    oracle: Optional[Dict[str, Any]] = None,
    control_scope: str = "matched",
) -> Dict[str, Any]:
    """Compare a probe with its benign control and return a structured verdict.

    Supported oracle types:
      ``marker``     exact output marker, absent from the control
      ``regex``      one of a list of response-only regular expressions
      ``header``     exact response header/value pair
      ``redirect``   redirect Location resolves to an exact controlled host
      ``reflection`` raw payload reflected in the response (candidate only)
    """
    oracle = dict(oracle or {})
    observed_text = str(observed.get("text") or "")
    observed_norm = str(observed.get("normalized") or "")

    # A dynamic endpoint can legitimately return several stable variants. Pick
    # the closest sampled control before evaluating status/body differences,
    # while retaining the canonical request metadata from the parent snapshot.
    parent_control = control
    sampled = [
        sample for sample in (control.get("samples") or [])
        if isinstance(sample, dict)
    ]
    candidates = sampled or [control]
    if len(candidates) > 1:
        control = max(
            candidates,
            key=lambda sample: difflib.SequenceMatcher(
                None,
                str(sample.get("normalized") or ""),
                observed_norm,
            ).quick_ratio(),
        )
    control_text = str(control.get("text") or "")
    control_norm = str(control.get("normalized") or "")

    similarity = difflib.SequenceMatcher(
        None, control_norm, observed_norm
    ).quick_ratio() if (control_norm or observed_norm) else 1.0
    size_delta = int(observed.get("size", 0) or 0) - int(control.get("size", 0) or 0)
    control_size = max(1, int(control.get("size", 0) or 0))
    size_delta_percent = (abs(size_delta) / control_size) * 100.0
    metrics = {
        "control_scope": control_scope,
        "control_samples": len(candidates),
        "status_changed": observed.get("status") != control.get("status"),
        "size_delta": size_delta,
        "size_delta_percent": round(size_delta_percent, 1),
        "similarity": round(similarity, 4),
    }
    if parent_control is not control and parent_control.get("request"):
        control = {**control, "request": parent_control.get("request")}

    def verdict(*, bypass: bool, reason: str, severity: str, confidence: str,
                verification: str, kind: str, signal: str, matched: str = ""):
        return {
            "bypass": bypass,
            "reason": reason,
            "severity": severity,
            "confidence": confidence,
            "verification_status": verification,
            "kind": kind,
            "comparison": metrics,
            "evidence": [{
                "type": signal,
                "description": reason,
                "matched": matched,
                "excerpt": _excerpt(observed_text, matched),
            }],
            "evidence_needle": matched,
        }

    oracle_type = str(oracle.get("type") or "").lower()
    if oracle_type == "marker":
        marker = str(oracle.get("value") or "")
        payload = str(oracle.get("payload") or "")
        # Remove every exact reflected copy of the payload before looking for
        # the marker. Counting occurrences let a template that echoed the input
        # twice masquerade as command/template execution.
        execution_text = observed_text
        if payload:
            reflected_forms = {
                payload, unquote(payload), unquote_plus(payload),
                html.escape(payload, quote=True), html.unescape(payload),
            }
            for reflected_form in sorted(reflected_forms, key=len, reverse=True):
                if reflected_form:
                    execution_text = execution_text.replace(reflected_form, "")
        if marker and marker in execution_text and marker not in control_text:
            return verdict(
                bypass=True,
                reason=str(oracle.get("reason") or f"Expected execution marker observed: {marker}"),
                severity=str(oracle.get("severity") or "HIGH"),
                confidence=str(oracle.get("confidence") or "high"),
                verification=str(oracle.get("verification_status") or "confirmed"),
                kind=str(oracle.get("kind") or "finding"),
                signal="execution_marker", matched=marker,
            )
    elif oracle_type == "regex":
        match = _first_new_regex(oracle.get("patterns") or [], observed_text, control_text)
        if match:
            return verdict(
                bypass=True,
                reason=str(oracle.get("reason") or f"Response-only vulnerability signature: {match}"),
                severity=str(oracle.get("severity") or "HIGH"),
                confidence=str(oracle.get("confidence") or "high"),
                verification=str(oracle.get("verification_status") or "confirmed"),
                kind=str(oracle.get("kind") or "finding"),
                signal="response_signature", matched=match,
            )
    elif oracle_type == "header":
        name = str(oracle.get("name") or "").lower()
        expected = str(oracle.get("value") or "")
        actual = str((observed.get("headers") or {}).get(name, ""))
        control_value = str((control.get("headers") or {}).get(name, ""))
        if name and expected and expected in actual and expected not in control_value:
            return verdict(
                bypass=True,
                reason=str(oracle.get("reason") or f"Injected response header {name}: {expected}"),
                severity=str(oracle.get("severity") or "HIGH"),
                confidence="high", verification="confirmed", kind="finding",
                signal="response_header_injection", matched=f"{name}: {actual}",
            )
    elif oracle_type == "redirect":
        location = str(observed.get("location") or "")
        control_location = str(control.get("location") or "")
        base_url = str(oracle.get("base_url") or "")
        expected_hosts = {
            str(host).lower().rstrip('.')
            for host in (oracle.get("hosts") or [oracle.get("host")])
            if host
        }
        try:
            resolved = urlparse(urljoin(base_url, location))
            location_host = (resolved.hostname or "").lower().rstrip('.')
        except Exception:
            location_host = ""
        if (location and location != control_location and location_host
                and location_host in expected_hosts):
            return verdict(
                bypass=True,
                reason=str(oracle.get("reason") or
                           f"Redirect resolved to controlled host {location_host}"),
                severity=str(oracle.get("severity") or "HIGH"),
                confidence="high", verification="confirmed", kind="finding",
                signal="external_redirect", matched=location,
            )
    elif oracle_type == "reflection":
        payload = str(oracle.get("value") or "")
        if payload and payload in observed_text and payload not in control_text:
            return verdict(
                bypass=True,
                reason=str(oracle.get("reason") or
                           "Payload is reflected verbatim; execution/context still needs verification"),
                severity=str(oracle.get("severity") or "MEDIUM"),
                confidence="medium", verification="candidate", kind="suspected",
                signal="unencoded_reflection", matched=payload,
            )

    control_status = int(control.get("status", 0) or 0)
    observed_status = int(observed.get("status", 0) or 0)

    # A denied matched control becoming allowed is concrete access-control proof.
    # Route misses, unsupported methods, and rate limits can legitimately change
    # after an input mutation, so 404/405/429 transitions remain candidates below
    # unless a detector-specific oracle supplies vulnerability proof.
    if control_status in (401, 403) and 200 <= observed_status < 400:
        return verdict(
            bypass=True,
            reason=f"Matched control returned {control_status}; probe returned {observed_status}",
            severity="CRITICAL",
            confidence="high", verification="confirmed", kind="finding",
            signal="blocked_to_allowed", matched=str(observed_status),
        )

    if control_status in (404, 405, 429) and 200 <= observed_status < 400:
        return verdict(
            bypass=True,
            reason=(f"Matched control returned {control_status}; probe returned "
                    f"{observed_status}. The state change needs class-specific proof"),
            severity="MEDIUM", confidence="medium", verification="candidate",
            kind="suspected", signal="response_state_transition",
            matched=f"{control_status} -> {observed_status}",
        )

    # New backend errors are useful evidence, including on HTTP 5xx responses.
    error_match = ERROR_PATTERN.search(observed_text[:5000])
    control_error = ERROR_PATTERN.search(control_text[:5000])
    if error_match and not control_error:
        matched = error_match.group(0)
        return verdict(
            bypass=True,
            reason=f"Probe triggered a new backend error signature: {matched}",
            severity="HIGH", confidence="high", verification="candidate",
            kind="suspected", signal="new_backend_error", matched=matched,
        )

    # Ordinary 4xx/5xx responses without a new proof signal are negative probes.
    if observed_status >= 400:
        return verdict(
            bypass=False, reason=f"Probe rejected with HTTP {observed_status}",
            severity="INFO", confidence="none", verification="not_detected",
            kind="observation", signal="rejected",
        )

    if observed.get("location") and observed.get("location") != control.get("location"):
        return verdict(
            bypass=True,
            reason=f"Probe changed redirect target to {observed.get('location')}",
            severity="MEDIUM", confidence="medium", verification="candidate",
            kind="suspected", signal="redirect_changed",
            matched=str(observed.get("location") or ""),
        )

    # Generic deltas are candidates only.  Requiring a large normalized change
    # avoids the former "any hash mismatch == HIGH" false-positive path.
    materially_different = (
        similarity < 0.68
        and (abs(size_delta) > 200 or size_delta_percent > 25.0)
    )
    if materially_different:
        confidence = "medium" if control_scope == "matched" else "low"
        return verdict(
            bypass=True,
            reason=(f"Response differs from {control_scope} control "
                    f"({similarity * 100:.0f}% similar, {size_delta:+d} bytes); "
                    "vulnerability-specific proof is still required"),
            severity="MEDIUM", confidence=confidence, verification="candidate",
            kind="suspected", signal="material_response_delta",
        )

    return verdict(
        bypass=False,
        reason=(f"No proof signal ({similarity * 100:.0f}% similar to "
                f"{control_scope} control)"),
        severity="INFO", confidence="none", verification="not_detected",
        kind="observation", signal="no_signal",
    )
