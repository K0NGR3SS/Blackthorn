"""Secure notification delivery and passive-feed health tracking.

The automation workflow produces small, public notification records.  This
module delivers those records without storing connector credentials and keeps
only non-secret delivery/deduplication metadata on disk.  All network adapters
are opt-in through environment variables and fail closed on unsafe destinations.

Outbound HTTPS requests are resolved before connection and pinned to a validated
public address while TLS still verifies the original hostname.  Redirects are
never followed.  SMTP connections use the same public-address check and require
TLS (implicit TLS or STARTTLS).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import smtplib
import socket
import ssl
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

from .config import prepare_private_file
from .redaction import redact_text


STATE_VERSION = 1
MAX_EVENT_DETAILS_BYTES = 16 * 1024
MAX_HTTP_PAYLOAD_BYTES = 256 * 1024
MAX_HTTP_RESPONSE_BYTES = 64 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_HISTORY_ITEMS = 2000
MAX_DIGEST_EVENTS = 250
MAX_RESOLVED_ADDRESSES = 16
DEFAULT_HTTP_TIMEOUT = (5.0, 15.0)
DEFAULT_SMTP_TIMEOUT = 15.0

GENERIC_WEBHOOK_URL_ENV = "BLACKTHORN_AUTOMATION_WEBHOOK_URL"
SLACK_WEBHOOK_URL_ENV = "BLACKTHORN_SLACK_WEBHOOK_URL"
TEAMS_WEBHOOK_URL_ENV = "BLACKTHORN_TEAMS_WEBHOOK_URL"
JIRA_BASE_URL_ENV = "BLACKTHORN_JIRA_BASE_URL"
JIRA_EMAIL_ENV = "BLACKTHORN_JIRA_EMAIL"
JIRA_API_TOKEN_ENV = "BLACKTHORN_JIRA_API_TOKEN"
JIRA_PROJECT_KEY_ENV = "BLACKTHORN_JIRA_PROJECT_KEY"
JIRA_ISSUE_TYPE_ENV = "BLACKTHORN_JIRA_ISSUE_TYPE"
SMTP_HOST_ENV = "BLACKTHORN_SMTP_HOST"
SMTP_PORT_ENV = "BLACKTHORN_SMTP_PORT"
SMTP_USERNAME_ENV = "BLACKTHORN_SMTP_USERNAME"
SMTP_PASSWORD_ENV = "BLACKTHORN_SMTP_PASSWORD"
SMTP_FROM_ENV = "BLACKTHORN_SMTP_FROM"
SMTP_TO_ENV = "BLACKTHORN_SMTP_TO"
SMTP_SECURITY_ENV = "BLACKTHORN_SMTP_SECURITY"

_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {value: index for index, value in enumerate(_SEVERITIES)}
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
_PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
_JIRA_ISSUE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}-[1-9][0-9]{0,18}$")
_ISSUE_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|cookie|password|passwd|token|secret|api[_-]?key|credential|session)",
    re.IGNORECASE,
)


class DeliveryError(RuntimeError):
    """Base exception for a delivery failure with a non-secret error code."""

    def __init__(self, error_code: str, message: str = "delivery failed") -> None:
        self.error_code = _identifier(error_code, "error code")
        super().__init__(message)


class DeliveryValidationError(DeliveryError, ValueError):
    """Notification or adapter configuration is invalid."""


class DeliverySecurityError(DeliveryError, PermissionError):
    """An outbound destination failed a security policy."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Optional[datetime] = None) -> str:
    current = value or _now_utc()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str, field_name: str) -> datetime:
    text = _text(value, field_name, 64, required=True)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DeliveryValidationError("invalid_timestamp", "%s is not ISO-8601" % field_name) from exc
    if parsed.tzinfo is None:
        raise DeliveryValidationError("naive_timestamp", "%s must include a timezone" % field_name)
    return parsed.astimezone(timezone.utc)


def _canonical_time(value: str, field_name: str) -> str:
    return _iso(_parse_time(value, field_name))


def _text(value: Any, field_name: str, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise DeliveryValidationError("invalid_text", "%s must be text" % field_name)
    if "\x00" in value:
        raise DeliveryValidationError("invalid_text", "%s contains a NUL byte" % field_name)
    for character in value:
        if ord(character) < 32 and character not in "\t\r\n":
            raise DeliveryValidationError("invalid_text", "%s contains a control character" % field_name)
    clean = value.strip()
    if required and not clean:
        raise DeliveryValidationError("missing_field", "%s is required" % field_name)
    if len(clean) > maximum:
        raise DeliveryValidationError("field_too_long", "%s exceeds %d characters" % (field_name, maximum))
    return clean


def _identifier(value: Any, field_name: str, *, required: bool = True) -> str:
    clean = _text(value, field_name, 128, required=required)
    if clean and not _IDENTIFIER_RE.fullmatch(clean):
        raise DeliveryValidationError("invalid_identifier", "%s is invalid" % field_name)
    return clean


def _kind(value: Any) -> str:
    clean = _text(value, "kind", 64, required=True).lower()
    if not _KIND_RE.fullmatch(clean):
        raise DeliveryValidationError("invalid_kind", "kind is invalid")
    return clean


def _severity(value: Any) -> str:
    clean = _text(value, "severity", 16, required=True).lower()
    if clean not in _SEVERITY_RANK:
        raise DeliveryValidationError("invalid_severity", "severity is invalid")
    return clean


def _safe_public_value(value: Any, key: str, depth: int = 0) -> Any:
    if depth > 4:
        raise DeliveryValidationError("details_too_deep", "details nesting exceeds four levels")
    if _SENSITIVE_KEY_RE.search(key):
        return "<redacted>" if value not in (None, "") else value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise DeliveryValidationError("invalid_number", "details contains a non-finite number")
        return value
    if isinstance(value, str):
        return redact_text(_text(value, "details.%s" % key, 2048))
    if isinstance(value, Mapping):
        if len(value) > 50:
            raise DeliveryValidationError("details_too_large", "details contains too many keys")
        result: Dict[str, Any] = {}
        for raw_key, nested in value.items():
            clean_key = _text(raw_key, "details key", 64, required=True)
            result[clean_key] = _safe_public_value(nested, clean_key, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 100:
            raise DeliveryValidationError("details_too_large", "details contains too many values")
        return [_safe_public_value(item, key, depth + 1) for item in value]
    raise DeliveryValidationError("invalid_details", "details contains an unsupported value")


def _public_details(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DeliveryValidationError("invalid_details", "details must be a mapping")
    clean = _safe_public_value(value, "details")
    encoded = json.dumps(clean, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_EVENT_DETAILS_BYTES:
        raise DeliveryValidationError("details_too_large", "details exceeds the encoded size limit")
    return clean


def _freeze_public_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({
            str(key): _freeze_public_value(item) for key, item in value.items()
        })
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_public_value(item) for item in value)
    return value


def _thaw_public_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_public_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_public_value(item) for item in value]
    return value


@dataclass(frozen=True)
class NotificationEvent:
    """One bounded, non-secret event suitable for connector delivery."""

    event_id: str
    kind: str
    severity: str
    title: str
    summary: str
    occurred_at: str = field(default_factory=_iso)
    source: str = "automation"
    subject_id: str = ""
    asset_id: str = ""
    target: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _identifier(self.event_id, "event id"))
        object.__setattr__(self, "kind", _kind(self.kind))
        object.__setattr__(self, "severity", _severity(self.severity))
        object.__setattr__(self, "title", redact_text(_text(self.title, "title", 240, required=True)))
        object.__setattr__(self, "summary", redact_text(_text(self.summary, "summary", 4000)))
        object.__setattr__(self, "occurred_at", _canonical_time(self.occurred_at, "occurred at"))
        object.__setattr__(self, "source", _identifier(self.source, "source"))
        object.__setattr__(self, "subject_id", _identifier(self.subject_id, "subject id", required=False))
        object.__setattr__(self, "asset_id", _identifier(self.asset_id, "asset id", required=False))
        object.__setattr__(self, "target", redact_text(_text(self.target, "target", 2048)))
        object.__setattr__(
            self, "details", _freeze_public_value(_public_details(self.details))
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "occurred_at": self.occurred_at,
            "source": self.source,
            "subject_id": self.subject_id,
            "asset_id": self.asset_id,
            "target": self.target,
            "details": _thaw_public_value(self.details),
        }

    def dedupe_fingerprint(self) -> str:
        subject = self.subject_id or self.asset_id or self.target.casefold() or self.title.casefold()
        material = json.dumps(
            {"source": self.source, "kind": self.kind, "subject": subject},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class NotificationDigest:
    """A bounded group of events for periodic delivery."""

    digest_id: str
    title: str
    period_start: str
    period_end: str
    events: Tuple[NotificationEvent, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "digest_id", _identifier(self.digest_id, "digest id"))
        object.__setattr__(self, "title", redact_text(_text(self.title, "digest title", 240, required=True)))
        start = _canonical_time(self.period_start, "period start")
        end = _canonical_time(self.period_end, "period end")
        if _parse_time(end, "period end") < _parse_time(start, "period start"):
            raise DeliveryValidationError("invalid_period", "digest period ends before it starts")
        if not isinstance(self.events, tuple):
            object.__setattr__(self, "events", tuple(self.events))
        if not self.events or len(self.events) > MAX_DIGEST_EVENTS:
            raise DeliveryValidationError("invalid_digest_size", "digest event count is out of range")
        if any(not isinstance(event, NotificationEvent) for event in self.events):
            raise DeliveryValidationError("invalid_digest_event", "digest contains an invalid event")
        object.__setattr__(self, "period_start", start)
        object.__setattr__(self, "period_end", end)

    @classmethod
    def from_events(
        cls,
        events: Iterable[NotificationEvent],
        *,
        digest_id: str,
        title: str,
        period_start: str,
        period_end: str,
    ) -> "NotificationDigest":
        """Create a digest, retaining the newest/highest event per dedupe key."""
        selected: Dict[str, NotificationEvent] = {}
        for event in events:
            if not isinstance(event, NotificationEvent):
                raise DeliveryValidationError("invalid_digest_event", "digest contains an invalid event")
            key = event.dedupe_fingerprint()
            previous = selected.get(key)
            if previous is None:
                selected[key] = event
                continue
            previous_rank = _SEVERITY_RANK[previous.severity]
            current_rank = _SEVERITY_RANK[event.severity]
            if current_rank > previous_rank or (
                current_rank == previous_rank
                and _parse_time(event.occurred_at, "occurred at") > _parse_time(previous.occurred_at, "occurred at")
            ):
                selected[key] = event
        ordered = tuple(sorted(selected.values(), key=lambda event: event.occurred_at))
        return cls(digest_id, title, period_start, period_end, ordered)

    @property
    def highest_severity(self) -> str:
        return max(self.events, key=lambda event: _SEVERITY_RANK[event.severity]).severity

    @property
    def counts(self) -> Dict[str, int]:
        result = {severity: 0 for severity in _SEVERITIES}
        for event in self.events:
            result[event.severity] += 1
        return {key: value for key, value in result.items() if value}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "digest_id": self.digest_id,
            "title": self.title,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "highest_severity": self.highest_severity,
            "counts": self.counts,
            "events": [event.to_dict() for event in self.events],
        }


Notification = Union[NotificationEvent, NotificationDigest]


@dataclass(frozen=True)
class DedupePolicy:
    dedupe_window_seconds: int = 24 * 60 * 60
    minimum_severity: str = "info"
    escalate_on_severity_increase: bool = True

    def __post_init__(self) -> None:
        seconds = int(self.dedupe_window_seconds)
        if not 60 <= seconds <= 365 * 24 * 60 * 60:
            raise DeliveryValidationError("invalid_dedupe_window", "dedupe window is out of range")
        if not isinstance(self.escalate_on_severity_increase, bool):
            raise DeliveryValidationError("invalid_escalation_policy", "escalation policy must be boolean")
        object.__setattr__(self, "dedupe_window_seconds", seconds)
        object.__setattr__(self, "minimum_severity", _severity(self.minimum_severity))


@dataclass(frozen=True)
class DeliveryDecision:
    action: str
    reason: str
    fingerprint: str
    previous_severity: str = ""
    current_severity: str = "info"

    def __post_init__(self) -> None:
        if self.action not in {"deliver", "escalate", "deduplicate", "filter"}:
            raise DeliveryValidationError("invalid_decision", "delivery decision action is invalid")
        object.__setattr__(self, "reason", _identifier(self.reason, "decision reason"))
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise DeliveryValidationError("invalid_fingerprint", "delivery fingerprint is invalid")
        if self.previous_severity:
            object.__setattr__(self, "previous_severity", _severity(self.previous_severity))
        object.__setattr__(self, "current_severity", _severity(self.current_severity))


@dataclass(frozen=True)
class DeliveryResult:
    adapter: str
    status: str
    success: bool
    notification_id: str
    error_code: str = ""
    remote_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapter", _identifier(self.adapter, "adapter"))
        if self.status not in {"sent", "dry_run", "failed", "skipped"}:
            raise DeliveryValidationError("invalid_delivery_status", "delivery status is invalid")
        if not isinstance(self.success, bool):
            raise DeliveryValidationError("invalid_delivery_success", "delivery success flag must be boolean")
        object.__setattr__(self, "notification_id", _identifier(self.notification_id, "notification id"))
        object.__setattr__(self, "error_code", _identifier(self.error_code, "error code", required=False))
        object.__setattr__(self, "remote_id", _identifier(self.remote_id, "remote id", required=False))


@dataclass(frozen=True)
class DispatchResult:
    notification_id: str
    decision: Optional[DeliveryDecision]
    deliveries: Tuple[DeliveryResult, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "notification_id", _identifier(self.notification_id, "notification id"))
        if self.decision is not None and not isinstance(self.decision, DeliveryDecision):
            raise DeliveryValidationError("invalid_decision", "dispatch result decision is invalid")
        if not isinstance(self.deliveries, tuple):
            object.__setattr__(self, "deliveries", tuple(self.deliveries))
        if len(self.deliveries) > 20 or any(
            not isinstance(result, DeliveryResult) for result in self.deliveries
        ):
            raise DeliveryValidationError("invalid_delivery_results", "dispatch delivery results are invalid")

    @property
    def delivered(self) -> bool:
        return any(result.status == "sent" and result.success for result in self.deliveries)

    @property
    def successful(self) -> bool:
        return bool(self.deliveries) and all(result.success for result in self.deliveries)


def _empty_state() -> Dict[str, Any]:
    return {
        "schema_version": STATE_VERSION,
        "dedupe": {},
        "history": [],
        "source_health": {},
    }


class DeliveryStateStore:
    """Optional atomic JSON persistence containing no connector configuration.

    Only opaque fingerprints, event IDs, delivery outcomes, timestamps, and feed
    health codes are written.  URLs, message bodies, headers, email addresses,
    usernames, and credentials are never accepted by the persistence API.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = _text(str(path), "delivery state path", 4096) if path else ""
        self._lock = threading.RLock()
        self._state = self._read()

    def _read(self) -> Dict[str, Any]:
        if not self.path:
            return _empty_state()
        absolute = os.path.abspath(os.path.expanduser(self.path))
        self.path = absolute
        try:
            if not os.path.exists(absolute) or os.path.getsize(absolute) == 0:
                return _empty_state()
            if os.path.getsize(absolute) > MAX_STATE_BYTES:
                return _empty_state()
            with open(absolute, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict) or loaded.get("schema_version") != STATE_VERSION:
                return _empty_state()
            state = _empty_state()
            if isinstance(loaded.get("dedupe"), dict):
                state["dedupe"] = loaded["dedupe"]
            if isinstance(loaded.get("history"), list):
                state["history"] = loaded["history"][-MAX_HISTORY_ITEMS:]
            if isinstance(loaded.get("source_health"), dict):
                state["source_health"] = loaded["source_health"]
            return state
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return _empty_state()

    def _write(self) -> None:
        if not self.path:
            return
        parent = os.path.dirname(self.path) or "."
        os.makedirs(parent, exist_ok=True)
        encoded = json.dumps(
            self._state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_STATE_BYTES:
            raise DeliveryValidationError("state_too_large", "delivery state exceeds its size limit")
        descriptor, temporary = tempfile.mkstemp(prefix=".automation-delivery-", suffix=".tmp", dir=parent)
        try:
            os.close(descriptor)
            prepare_private_file(temporary)
            with open(temporary, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            prepare_private_file(self.path)
        finally:
            try:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            except OSError:
                pass

    def get_dedupe_record(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        if not re.fullmatch(r"[0-9a-f]{64}", str(fingerprint or "")):
            return None
        with self._lock:
            record = self._state["dedupe"].get(fingerprint)
            return dict(record) if isinstance(record, dict) else None

    def set_dedupe_record(
        self,
        fingerprint: str,
        *,
        event_id: str,
        severity: str,
        delivered_at: str,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", str(fingerprint or "")):
            raise DeliveryValidationError("invalid_fingerprint", "delivery fingerprint is invalid")
        record = {
            "event_id": _identifier(event_id, "event id"),
            "severity": _severity(severity),
            "delivered_at": _canonical_time(delivered_at, "delivered at"),
        }
        with self._lock:
            self._state["dedupe"][fingerprint] = record
            # A one-year maximum window makes older keys useless and bounds disk growth.
            cutoff = _parse_time(record["delivered_at"], "delivered at") - timedelta(days=366)
            stale = []
            for key, item in self._state["dedupe"].items():
                try:
                    if _parse_time(item.get("delivered_at", ""), "delivered at") < cutoff:
                        stale.append(key)
                except DeliveryError:
                    stale.append(key)
            for key in stale:
                self._state["dedupe"].pop(key, None)
            self._write()

    def add_history(
        self,
        *,
        notification_id: str,
        fingerprint: str,
        kind: str,
        severity: str,
        adapter: str,
        status: str,
        error_code: str = "",
        remote_id: str = "",
        recorded_at: Optional[str] = None,
    ) -> None:
        """Persist a deliberately narrow, non-content delivery audit record."""
        if not re.fullmatch(r"[0-9a-f]{64}", str(fingerprint or "")):
            raise DeliveryValidationError("invalid_fingerprint", "delivery fingerprint is invalid")
        if status not in {"sent", "dry_run", "failed", "skipped"}:
            raise DeliveryValidationError("invalid_delivery_status", "delivery status is invalid")
        record = {
            "notification_id": _identifier(notification_id, "notification id"),
            "fingerprint": fingerprint,
            "kind": _kind(kind),
            "severity": _severity(severity),
            "adapter": _identifier(adapter, "adapter"),
            "status": status,
            "error_code": _identifier(error_code, "error code", required=False),
            "remote_id": _identifier(remote_id, "remote id", required=False),
            "recorded_at": _canonical_time(recorded_at or _iso(), "recorded at"),
        }
        with self._lock:
            self._state["history"].append(record)
            del self._state["history"][:-MAX_HISTORY_ITEMS]
            self._write()

    def history(self, limit: int = 100) -> Tuple[Dict[str, Any], ...]:
        count = int(limit)
        if not 1 <= count <= MAX_HISTORY_ITEMS:
            raise DeliveryValidationError("invalid_history_limit", "history limit is out of range")
        with self._lock:
            return tuple(dict(item) for item in self._state["history"][-count:])

    def get_health_record(self, source: str) -> Optional[Dict[str, Any]]:
        clean_source = _identifier(source, "source")
        with self._lock:
            value = self._state["source_health"].get(clean_source)
            return dict(value) if isinstance(value, dict) else None

    def set_health_record(self, source: str, record: Mapping[str, Any]) -> None:
        clean_source = _identifier(source, "source")
        allowed = {
            "last_attempt_at", "last_success_at", "last_failure_at",
            "last_rate_limited_at", "last_data_at", "rate_limited_until",
            "last_error_code", "consecutive_failures",
        }
        if not isinstance(record, Mapping) or set(record) - allowed:
            raise DeliveryValidationError("invalid_health_record", "source health record is invalid")
        clean: Dict[str, Any] = {}
        for key in allowed:
            value = record.get(key, "")
            if key == "consecutive_failures":
                number = int(value or 0)
                if not 0 <= number <= 1_000_000:
                    raise DeliveryValidationError("invalid_failure_count", "failure count is out of range")
                clean[key] = number
            elif key == "last_error_code":
                clean[key] = _identifier(value, "error code", required=False)
            else:
                clean[key] = _canonical_time(value, key) if value else ""
        with self._lock:
            self._state["source_health"][clean_source] = clean
            self._write()

    def health_sources(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._state["source_health"]))


class DedupeTracker:
    """Decide suppression/escalation and record only successful deliveries."""

    def __init__(
        self,
        policy: Optional[DedupePolicy] = None,
        store: Optional[DeliveryStateStore] = None,
    ) -> None:
        self.policy = policy or DedupePolicy()
        self.store = store or DeliveryStateStore()
        self._lock = threading.RLock()

    def decide(self, event: NotificationEvent, *, now: Optional[datetime] = None) -> DeliveryDecision:
        if not isinstance(event, NotificationEvent):
            raise DeliveryValidationError("invalid_event", "dedupe requires a notification event")
        fingerprint = event.dedupe_fingerprint()
        if _SEVERITY_RANK[event.severity] < _SEVERITY_RANK[self.policy.minimum_severity]:
            return DeliveryDecision("filter", "below_minimum_severity", fingerprint, "", event.severity)
        with self._lock:
            previous = self.store.get_dedupe_record(fingerprint)
        if not previous:
            return DeliveryDecision("deliver", "new_subject", fingerprint, "", event.severity)
        previous_severity = previous.get("severity", "info")
        try:
            delivered_at = _parse_time(previous.get("delivered_at", ""), "delivered at")
        except DeliveryError:
            return DeliveryDecision("deliver", "invalid_previous_state", fingerprint, "", event.severity)
        current_time = now or _now_utc()
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        elapsed = max(0.0, (current_time.astimezone(timezone.utc) - delivered_at).total_seconds())
        if (
            self.policy.escalate_on_severity_increase
            and _SEVERITY_RANK[event.severity] > _SEVERITY_RANK.get(previous_severity, 0)
        ):
            return DeliveryDecision(
                "escalate", "severity_increased", fingerprint, previous_severity, event.severity
            )
        if elapsed < self.policy.dedupe_window_seconds:
            return DeliveryDecision(
                "deduplicate", "within_dedupe_window", fingerprint, previous_severity, event.severity
            )
        return DeliveryDecision("deliver", "dedupe_window_elapsed", fingerprint, previous_severity, event.severity)

    def record_delivery(
        self,
        event: NotificationEvent,
        decision: DeliveryDecision,
        *,
        delivered_at: Optional[datetime] = None,
    ) -> None:
        if decision.fingerprint != event.dedupe_fingerprint():
            raise DeliveryValidationError("fingerprint_mismatch", "delivery decision does not match the event")
        if decision.action not in {"deliver", "escalate"}:
            raise DeliveryValidationError("invalid_record_action", "a suppressed event cannot be recorded as delivered")
        with self._lock:
            self.store.set_dedupe_record(
                decision.fingerprint,
                event_id=event.event_id,
                severity=event.severity,
                delivered_at=_iso(delivered_at),
            )


@dataclass(frozen=True)
class SourceHealth:
    source: str
    status: str
    last_attempt_at: str = ""
    last_success_at: str = ""
    last_failure_at: str = ""
    last_rate_limited_at: str = ""
    last_data_at: str = ""
    rate_limited_until: str = ""
    last_error_code: str = ""
    consecutive_failures: int = 0
    freshness_seconds: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _identifier(self.source, "source"))
        if self.status not in {"never", "healthy", "degraded", "rate_limited", "stale", "unavailable"}:
            raise DeliveryValidationError("invalid_health_status", "source health status is invalid")
        for name in (
            "last_attempt_at", "last_success_at", "last_failure_at",
            "last_rate_limited_at", "last_data_at", "rate_limited_until",
        ):
            value = getattr(self, name)
            if value:
                object.__setattr__(self, name, _canonical_time(value, name))
        object.__setattr__(
            self,
            "last_error_code",
            _identifier(self.last_error_code, "error code", required=False),
        )
        if not 0 <= int(self.consecutive_failures) <= 1_000_000:
            raise DeliveryValidationError("invalid_failure_count", "failure count is out of range")
        object.__setattr__(self, "consecutive_failures", int(self.consecutive_failures))
        if self.freshness_seconds is not None and int(self.freshness_seconds) < 0:
            raise DeliveryValidationError("invalid_freshness", "freshness cannot be negative")
        if self.freshness_seconds is not None:
            object.__setattr__(self, "freshness_seconds", int(self.freshness_seconds))


class FeedHealthTracker:
    """Persist and derive freshness/availability for passive intelligence feeds."""

    def __init__(
        self,
        store: Optional[DeliveryStateStore] = None,
        *,
        stale_after_seconds: int = 6 * 60 * 60,
    ) -> None:
        seconds = int(stale_after_seconds)
        if not 60 <= seconds <= 90 * 24 * 60 * 60:
            raise DeliveryValidationError("invalid_stale_window", "stale window is out of range")
        self.store = store or DeliveryStateStore()
        self.stale_after_seconds = seconds
        self._lock = threading.RLock()

    def record_success(
        self,
        source: str,
        *,
        at: Optional[datetime] = None,
        data_timestamp: str = "",
    ) -> SourceHealth:
        clean_source = _identifier(source, "source")
        when = _iso(at)
        if data_timestamp:
            data_timestamp = _canonical_time(data_timestamp, "data timestamp")
        with self._lock:
            previous = self.store.get_health_record(clean_source) or {}
            previous.update({
                "last_attempt_at": when,
                "last_success_at": when,
                "last_data_at": data_timestamp or previous.get("last_data_at", ""),
                "rate_limited_until": "",
                "last_error_code": "",
                "consecutive_failures": 0,
            })
            self.store.set_health_record(clean_source, previous)
        return self.get(clean_source, now=at)

    def record_failure(
        self,
        source: str,
        *,
        error_code: str = "fetch_failed",
        at: Optional[datetime] = None,
        rate_limited: bool = False,
        retry_after_seconds: Optional[int] = None,
    ) -> SourceHealth:
        clean_source = _identifier(source, "source")
        clean_error = _identifier(error_code, "error code")
        when_dt = at or _now_utc()
        if when_dt.tzinfo is None:
            when_dt = when_dt.replace(tzinfo=timezone.utc)
        retry_after = int(retry_after_seconds or 0)
        if not 0 <= retry_after <= 7 * 24 * 60 * 60:
            raise DeliveryValidationError("invalid_retry_after", "retry-after is out of range")
        if retry_after and not rate_limited:
            raise DeliveryValidationError("invalid_retry_after", "retry-after requires a rate-limit event")
        when = _iso(when_dt)
        with self._lock:
            previous = self.store.get_health_record(clean_source) or {}
            failures = min(1_000_000, int(previous.get("consecutive_failures") or 0) + 1)
            previous.update({
                "last_attempt_at": when,
                "last_failure_at": when,
                "last_error_code": clean_error,
                "consecutive_failures": failures,
            })
            if rate_limited:
                previous["last_rate_limited_at"] = when
                previous["rate_limited_until"] = _iso(when_dt + timedelta(seconds=retry_after))
            self.store.set_health_record(clean_source, previous)
        return self.get(clean_source, now=when_dt)

    def record_rate_limit(
        self,
        source: str,
        *,
        retry_after_seconds: int,
        at: Optional[datetime] = None,
    ) -> SourceHealth:
        if int(retry_after_seconds) < 1:
            raise DeliveryValidationError("invalid_retry_after", "rate-limit retry-after must be positive")
        return self.record_failure(
            source,
            error_code="rate_limited",
            at=at,
            rate_limited=True,
            retry_after_seconds=retry_after_seconds,
        )

    def get(self, source: str, *, now: Optional[datetime] = None) -> SourceHealth:
        clean_source = _identifier(source, "source")
        record = self.store.get_health_record(clean_source) or {}
        current = now or _now_utc()
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
        success = record.get("last_success_at", "")
        data_timestamp = record.get("last_data_at", "")
        failure = record.get("last_failure_at", "")
        limited_until = record.get("rate_limited_until", "")
        freshness: Optional[int] = None
        freshness_source = data_timestamp or success
        if freshness_source:
            freshness = max(0, int((
                current - _parse_time(freshness_source, "feed data timestamp")
            ).total_seconds()))
        if limited_until and _parse_time(limited_until, "rate limited until") > current:
            status = "rate_limited"
        elif not success:
            status = "unavailable" if failure else "never"
        elif freshness is not None and freshness > self.stale_after_seconds:
            status = "stale"
        elif failure and _parse_time(failure, "last failure") >= _parse_time(success, "last success"):
            status = "degraded"
        else:
            status = "healthy"
        return SourceHealth(
            source=clean_source,
            status=status,
            last_attempt_at=record.get("last_attempt_at", ""),
            last_success_at=success,
            last_failure_at=failure,
            last_rate_limited_at=record.get("last_rate_limited_at", ""),
            last_data_at=data_timestamp,
            rate_limited_until=limited_until,
            last_error_code=record.get("last_error_code", ""),
            consecutive_failures=int(record.get("consecutive_failures") or 0),
            freshness_seconds=freshness,
        )

    def snapshot(
        self,
        sources: Optional[Iterable[str]] = None,
        *,
        now: Optional[datetime] = None,
    ) -> Tuple[SourceHealth, ...]:
        selected = tuple(sources) if sources is not None else self.store.health_sources()
        if len(selected) > 1000:
            raise DeliveryValidationError("too_many_sources", "source health snapshot is too large")
        return tuple(self.get(source, now=now) for source in sorted(set(selected)))


Resolver = Callable[..., Any]


@dataclass(frozen=True)
class ResolvedEndpoint:
    """An HTTPS endpoint whose complete DNS answer set passed policy checks."""

    host: str
    port: int
    request_target: str = field(repr=False)
    addresses: Tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _text(self.host, "host", 253, required=True).lower())
        if not 1 <= int(self.port) <= 65535:
            raise DeliveryValidationError("invalid_port", "port is out of range")
        object.__setattr__(self, "port", int(self.port))
        target = _text(self.request_target, "request target", 8192, required=True)
        if not target.startswith("/") or "\r" in target or "\n" in target:
            raise DeliveryValidationError("invalid_request_target", "request target is invalid")
        object.__setattr__(self, "request_target", target)
        if not self.addresses or len(self.addresses) > MAX_RESOLVED_ADDRESSES:
            raise DeliveryValidationError("invalid_dns_answer", "resolved address count is invalid")
        for address in self.addresses:
            _require_public_ip(address)


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __post_init__(self) -> None:
        status = int(self.status_code)
        if not 100 <= status <= 599:
            raise DeliveryValidationError("invalid_http_status", "HTTP status is out of range")
        object.__setattr__(self, "status_code", status)
        if not isinstance(self.headers, Mapping) or len(self.headers) > 100:
            raise DeliveryValidationError("invalid_http_headers", "HTTP response headers are invalid")
        clean_headers: Dict[str, str] = {}
        for key, value in self.headers.items():
            name = _text(str(key), "response header name", 128, required=True).lower()
            clean_headers[name] = _text(str(value), "response header value", 4096)
        object.__setattr__(self, "headers", clean_headers)
        body = self.body
        if isinstance(body, str):
            body = body.encode("utf-8")
        if not isinstance(body, (bytes, bytearray)):
            raise DeliveryValidationError("invalid_http_body", "HTTP response body is invalid")
        object.__setattr__(self, "body", bytes(body))


HTTPTransport = Callable[
    [ResolvedEndpoint, str, Mapping[str, str], bytes, Tuple[float, float], int],
    TransportResponse,
]


def _require_public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError as exc:
        raise DeliverySecurityError("invalid_dns_address", "DNS returned an invalid address") from exc
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or not address.is_global
    ):
        raise DeliverySecurityError("non_public_destination", "outbound destination is not public")
    return str(address)


def _resolver_addresses(resolver: Resolver, host: str, port: int) -> Tuple[str, ...]:
    try:
        try:
            answer = resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except TypeError:
            answer = resolver(host, port)
    except (OSError, socket.gaierror) as exc:
        raise DeliverySecurityError("dns_resolution_failed", "destination could not be resolved") from exc
    if isinstance(answer, (str, bytes)):
        answer = [answer]
    result: List[str] = []
    for item in answer or []:
        address = ""
        if isinstance(item, str):
            address = item
        elif isinstance(item, bytes):
            address = item.decode("ascii", "strict")
        elif isinstance(item, tuple) and len(item) >= 5 and isinstance(item[4], tuple):
            address = str(item[4][0])
        elif isinstance(item, tuple) and item:
            address = str(item[0])
        if not address:
            continue
        clean = _require_public_ip(address)
        if clean not in result:
            result.append(clean)
        if len(result) > MAX_RESOLVED_ADDRESSES:
            raise DeliverySecurityError("too_many_dns_addresses", "destination resolved to too many addresses")
    if not result:
        raise DeliverySecurityError("dns_resolution_failed", "destination did not resolve")
    return tuple(result)


def resolve_public_host(
    host: str,
    port: int,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> Tuple[str, ...]:
    """Resolve a host and reject the whole answer when any address is non-public."""
    try:
        clean_port = int(port)
    except (TypeError, ValueError, OverflowError) as exc:
        raise DeliveryValidationError("invalid_port", "port is invalid") from exc
    if not 1 <= clean_port <= 65535:
        raise DeliveryValidationError("invalid_port", "port is out of range")
    clean = _text(host, "host", 253, required=True).rstrip(".")
    if any(character in clean for character in "@/\\?#[]") or any(character.isspace() for character in clean):
        raise DeliverySecurityError("invalid_destination_host", "destination hostname is invalid")
    try:
        clean = clean.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DeliverySecurityError("invalid_destination_host", "destination hostname is invalid") from exc
    if clean == "localhost" or clean.endswith(".localhost"):
        raise DeliverySecurityError("non_public_destination", "outbound destination is not public")
    try:
        literal = ipaddress.ip_address(clean)
    except ValueError:
        literal = None
    if literal is not None:
        return (_require_public_ip(str(literal)),)
    return _resolver_addresses(resolver, clean, clean_port)


def validate_https_endpoint(
    url: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> ResolvedEndpoint:
    """Validate and resolve an HTTPS URL for a single, redirect-free request."""
    clean = _text(url, "destination URL", 8192, required=True)
    if "\\" in clean or any(character.isspace() for character in clean):
        raise DeliverySecurityError("invalid_destination_url", "destination URL is invalid")
    try:
        parsed = urlsplit(clean)
        port = parsed.port or 443
    except ValueError as exc:
        raise DeliverySecurityError("invalid_destination_url", "destination URL is invalid") from exc
    if parsed.scheme.lower() != "https":
        raise DeliverySecurityError("https_required", "outbound HTTP destinations must use HTTPS")
    if not parsed.hostname or not parsed.netloc:
        raise DeliverySecurityError("invalid_destination_url", "destination URL has no hostname")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise DeliverySecurityError("url_credentials_forbidden", "credentials in destination URLs are forbidden")
    if parsed.fragment:
        raise DeliverySecurityError("url_fragment_forbidden", "destination URL fragments are forbidden")
    host = parsed.hostname.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DeliverySecurityError("invalid_destination_host", "destination hostname is invalid") from exc
    addresses = resolve_public_host(host, port, resolver=resolver)
    path = parsed.path or "/"
    target = path + (("?" + parsed.query) if parsed.query else "")
    return ResolvedEndpoint(host=host, port=port, request_target=target, addresses=addresses)


def _validate_timeout(timeout: Tuple[float, float]) -> Tuple[float, float]:
    if not isinstance(timeout, tuple) or len(timeout) != 2:
        raise DeliveryValidationError("invalid_timeout", "timeout must contain connect/read values")
    try:
        connect, read = float(timeout[0]), float(timeout[1])
    except (TypeError, ValueError, OverflowError) as exc:
        raise DeliveryValidationError("invalid_timeout", "timeout values are invalid") from exc
    if not 0.1 <= connect <= 60.0 or not 0.1 <= read <= 120.0:
        raise DeliveryValidationError("invalid_timeout", "timeout values are out of range")
    return connect, read


def _validate_request_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    if not isinstance(headers, Mapping) or len(headers) > 50:
        raise DeliveryValidationError("invalid_http_headers", "HTTP request headers are invalid")
    result: Dict[str, str] = {}
    seen = set()
    for raw_name, raw_value in headers.items():
        name = str(raw_name)
        normalized_name = name.casefold()
        if not _HEADER_NAME_RE.fullmatch(name):
            raise DeliveryValidationError("invalid_http_header", "HTTP header name is invalid")
        if normalized_name in seen:
            raise DeliveryValidationError(
                "duplicate_http_header", "HTTP header names must be unique"
            )
        seen.add(normalized_name)
        value = _text(str(raw_value), "HTTP header value", 8192)
        if "\r" in value or "\n" in value:
            raise DeliveryValidationError("invalid_http_header", "HTTP header value is invalid")
        result[name] = value
    return result


def _pinned_https_transport(
    endpoint: ResolvedEndpoint,
    method: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: Tuple[float, float],
    max_response_bytes: int,
) -> TransportResponse:
    """Connect to a prevalidated address while retaining hostname TLS checks."""
    connect_timeout, read_timeout = _validate_timeout(timeout)
    last_error: Optional[BaseException] = None
    for address in endpoint.addresses:
        connection = http.client.HTTPSConnection(
            endpoint.host,
            endpoint.port,
            timeout=connect_timeout,
            context=ssl.create_default_context(),
        )

        def pinned_connection(
            _destination: Tuple[str, int],
            connection_timeout: Optional[float] = None,
            source_address: Optional[Tuple[str, int]] = None,
            *args: Any,
            **kwargs: Any,
        ) -> socket.socket:
            return socket.create_connection(
                (address, endpoint.port),
                timeout=connection_timeout,
                source_address=source_address,
            )

        connection._create_connection = pinned_connection  # type: ignore[attr-defined]
        try:
            connection.connect()
            if connection.sock is not None:
                connection.sock.settimeout(read_timeout)
            connection.request(method, endpoint.request_target, body=body, headers=dict(headers))
            response = connection.getresponse()
            content_length = response.getheader("Content-Length")
            if content_length:
                try:
                    if int(content_length) > max_response_bytes:
                        raise DeliverySecurityError("response_too_large", "connector response exceeds its size limit")
                except ValueError:
                    pass
            response_body = response.read(max_response_bytes + 1)
            if len(response_body) > max_response_bytes:
                raise DeliverySecurityError("response_too_large", "connector response exceeds its size limit")
            response_headers = {key: value for key, value in response.getheaders()}
            return TransportResponse(response.status, response_headers, response_body)
        except DeliveryError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise DeliveryError("transport_failed", "HTTPS connector request failed") from last_error


class SecureHTTPClient:
    """Small redirect-free JSON client with injectable DNS and transport."""

    def __init__(
        self,
        *,
        resolver: Resolver = socket.getaddrinfo,
        transport: Optional[HTTPTransport] = None,
        timeout: Tuple[float, float] = DEFAULT_HTTP_TIMEOUT,
        max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES,
    ) -> None:
        if not callable(resolver) or (transport is not None and not callable(transport)):
            raise DeliveryValidationError("invalid_transport", "HTTP resolver and transport must be callable")
        self.resolver = resolver
        self.transport = transport or _pinned_https_transport
        self.timeout = _validate_timeout(timeout)
        response_limit = int(max_response_bytes)
        if not 1 <= response_limit <= 1024 * 1024:
            raise DeliveryValidationError("invalid_response_limit", "response limit is out of range")
        self.max_response_bytes = response_limit

    def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        headers: Optional[Mapping[str, str]] = None,
        dry_run: bool = False,
    ) -> Optional[TransportResponse]:
        endpoint = validate_https_endpoint(url, resolver=self.resolver)
        if not isinstance(payload, Mapping):
            raise DeliveryValidationError("invalid_payload", "connector payload must be a mapping")
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise DeliveryValidationError("invalid_payload", "connector payload is not JSON-safe") from exc
        if len(encoded) > MAX_HTTP_PAYLOAD_BYTES:
            raise DeliveryValidationError("payload_too_large", "connector payload exceeds its size limit")
        caller_headers = _validate_request_headers(headers or {})
        forbidden = {
            "host", "content-length", "transfer-encoding", "connection",
            "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
            "trailer", "upgrade",
        }
        if any(name.casefold() in forbidden for name in caller_headers):
            raise DeliverySecurityError(
                "reserved_http_header",
                "connector headers cannot override routing or message framing",
            )
        request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        request_headers.update(caller_headers)
        request_headers["Content-Length"] = str(len(encoded))
        header_host = "[%s]" % endpoint.host if ":" in endpoint.host else endpoint.host
        request_headers["Host"] = header_host if endpoint.port == 443 else "%s:%d" % (header_host, endpoint.port)
        request_headers = _validate_request_headers(request_headers)
        if dry_run:
            return None
        try:
            response = self.transport(
                endpoint,
                "POST",
                request_headers,
                encoded,
                self.timeout,
                self.max_response_bytes,
            )
        except DeliveryError:
            raise
        except Exception as exc:
            raise DeliveryError("transport_failed", "connector transport failed") from exc
        if not isinstance(response, TransportResponse):
            raise DeliveryError("invalid_transport_response", "connector transport returned an invalid response")
        if len(response.body) > self.max_response_bytes:
            raise DeliverySecurityError("response_too_large", "connector response exceeds its size limit")
        if 300 <= response.status_code <= 399:
            raise DeliverySecurityError("redirect_forbidden", "connector redirects are forbidden")
        return response


def _notification_id(notification: Notification) -> str:
    return notification.event_id if isinstance(notification, NotificationEvent) else notification.digest_id


def _notification_kind(notification: Notification) -> str:
    return notification.kind if isinstance(notification, NotificationEvent) else "digest"


def _notification_severity(notification: Notification) -> str:
    return notification.severity if isinstance(notification, NotificationEvent) else notification.highest_severity


def notification_payload(notification: Notification) -> Dict[str, Any]:
    """Return the stable generic-webhook envelope for an event or digest."""
    if isinstance(notification, NotificationEvent):
        return {"schema_version": 1, "notification_type": "event", "event": notification.to_dict()}
    if isinstance(notification, NotificationDigest):
        return {"schema_version": 1, "notification_type": "digest", "digest": notification.to_dict()}
    raise DeliveryValidationError("invalid_notification", "notification type is invalid")


def render_notification_text(notification: Notification, *, maximum: int = 4000) -> str:
    """Render bounded plain text shared by chat and email adapters."""
    limit = int(maximum)
    if not 128 <= limit <= 100_000:
        raise DeliveryValidationError("invalid_render_limit", "render limit is out of range")
    if isinstance(notification, NotificationEvent):
        lines = [
            "[%s] %s" % (notification.severity.upper(), notification.title),
            notification.summary or "No additional summary.",
        ]
        if notification.target:
            lines.append("Target: %s" % notification.target)
        lines.extend(("Kind: %s" % notification.kind, "Source: %s" % notification.source))
    elif isinstance(notification, NotificationDigest):
        counts = ", ".join("%s=%d" % (key, value) for key, value in notification.counts.items())
        lines = [
            notification.title,
            "Period: %s to %s" % (notification.period_start, notification.period_end),
            "Events: %d (%s)" % (len(notification.events), counts or "none"),
            "",
        ]
        for event in notification.events:
            lines.append("[%s] %s" % (event.severity.upper(), event.title))
    else:
        raise DeliveryValidationError("invalid_notification", "notification type is invalid")
    return "\n".join(lines)[:limit]


def _required_env(environ: Mapping[str, str], name: str, maximum: int, *, secret: bool = False) -> str:
    clean_name = _identifier(name, "environment variable name")
    value = environ.get(clean_name, "")
    try:
        return _text(value, clean_name, maximum, required=True)
    except DeliveryValidationError as exc:
        code = "missing_secret" if secret and not value else "invalid_environment_value"
        raise DeliveryValidationError(code, "required connector environment is invalid") from exc


def _optional_env(
    environ: Mapping[str, str],
    name: str,
    maximum: int,
    default: str = "",
) -> str:
    clean_name = _identifier(name, "environment variable name")
    value = environ.get(clean_name, default)
    return _text(value, clean_name, maximum)


def _http_error_code(status: int) -> str:
    if status in {401, 403}:
        return "authentication_failed"
    if status == 429:
        return "rate_limited"
    if 400 <= status <= 499:
        return "connector_rejected"
    if status >= 500:
        return "connector_unavailable"
    return "unexpected_http_status"


class _HTTPSAdapter:
    name = "https"

    def __init__(
        self,
        *,
        url_env: str,
        environ: Optional[Mapping[str, str]] = None,
        client: Optional[SecureHTTPClient] = None,
    ) -> None:
        self.url_env = _identifier(url_env, "URL environment variable")
        if environ is not None and not isinstance(environ, Mapping):
            raise DeliveryValidationError("invalid_environment", "connector environment must be a mapping")
        self._environ = environ if environ is not None else os.environ
        self.client = client or SecureHTTPClient()

    def _payload(self, notification: Notification) -> Dict[str, Any]:
        return notification_payload(notification)

    def _headers(self) -> Dict[str, str]:
        return {}

    def _url(self) -> str:
        # Webhook URLs routinely contain bearer material in their path/query and
        # therefore are treated as secrets even though they are destinations.
        return _required_env(self._environ, self.url_env, 8192, secret=True)

    def deliver(self, notification: Notification, *, dry_run: bool = False) -> DeliveryResult:
        notification_id = _notification_id(notification)
        try:
            response = self.client.post_json(
                self._url(),
                self._payload(notification),
                headers=self._headers(),
                dry_run=dry_run,
            )
            if dry_run:
                return DeliveryResult(self.name, "dry_run", True, notification_id)
            if response is not None and 200 <= response.status_code <= 299:
                return DeliveryResult(self.name, "sent", True, notification_id, remote_id=self._remote_id(response))
            code = _http_error_code(response.status_code if response is not None else 0)
            return DeliveryResult(self.name, "failed", False, notification_id, error_code=code)
        except DeliveryError as exc:
            return DeliveryResult(self.name, "failed", False, notification_id, error_code=exc.error_code)
        except Exception:
            return DeliveryResult(self.name, "failed", False, notification_id, error_code="adapter_failed")

    def _remote_id(self, response: TransportResponse) -> str:
        return ""


class GenericWebhookAdapter(_HTTPSAdapter):
    """Deliver the stable JSON envelope to a generic HTTPS webhook."""

    name = "webhook"

    def __init__(
        self,
        *,
        url_env: str = GENERIC_WEBHOOK_URL_ENV,
        environ: Optional[Mapping[str, str]] = None,
        client: Optional[SecureHTTPClient] = None,
    ) -> None:
        super().__init__(url_env=url_env, environ=environ, client=client)


class SlackWebhookAdapter(_HTTPSAdapter):
    """Deliver a bounded plain-text Slack incoming-webhook message."""

    name = "slack"

    def __init__(
        self,
        *,
        url_env: str = SLACK_WEBHOOK_URL_ENV,
        environ: Optional[Mapping[str, str]] = None,
        client: Optional[SecureHTTPClient] = None,
    ) -> None:
        super().__init__(url_env=url_env, environ=environ, client=client)

    def _payload(self, notification: Notification) -> Dict[str, Any]:
        return {"text": render_notification_text(notification, maximum=3900)}


class TeamsWebhookAdapter(_HTTPSAdapter):
    """Deliver a Microsoft Teams MessageCard through an HTTPS webhook."""

    name = "teams"

    def __init__(
        self,
        *,
        url_env: str = TEAMS_WEBHOOK_URL_ENV,
        environ: Optional[Mapping[str, str]] = None,
        client: Optional[SecureHTTPClient] = None,
    ) -> None:
        super().__init__(url_env=url_env, environ=environ, client=client)

    def _payload(self, notification: Notification) -> Dict[str, Any]:
        severity = _notification_severity(notification)
        title = notification.title
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title[:240],
            "themeColor": "D7263D" if severity in {"critical", "high"} else "0078D7",
            "sections": [{
                "activityTitle": title[:240],
                "text": render_notification_text(notification, maximum=7000),
                "markdown": True,
            }],
        }


def _jira_issue_url(base_url: str) -> str:
    clean = _text(base_url, "Jira base URL", 4096, required=True)
    if "\\" in clean or any(character.isspace() for character in clean):
        raise DeliverySecurityError("invalid_destination_url", "Jira base URL is invalid")
    try:
        parsed = urlsplit(clean)
    except ValueError as exc:
        raise DeliverySecurityError("invalid_destination_url", "Jira base URL is invalid") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise DeliverySecurityError("https_required", "Jira base URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise DeliverySecurityError("url_credentials_forbidden", "credentials in Jira URLs are forbidden")
    if parsed.query or parsed.fragment:
        raise DeliverySecurityError("invalid_destination_url", "Jira base URL cannot contain query or fragment data")
    path = parsed.path.rstrip("/") + "/rest/api/3/issue"
    return urlunsplit(("https", parsed.netloc, path, "", ""))


class JiraIssueAdapter(_HTTPSAdapter):
    """Create a Jira Cloud issue using environment-backed basic authentication."""

    name = "jira"

    def __init__(
        self,
        *,
        environ: Optional[Mapping[str, str]] = None,
        client: Optional[SecureHTTPClient] = None,
        base_url_env: str = JIRA_BASE_URL_ENV,
        email_env: str = JIRA_EMAIL_ENV,
        token_env: str = JIRA_API_TOKEN_ENV,
        project_env: str = JIRA_PROJECT_KEY_ENV,
        issue_type_env: str = JIRA_ISSUE_TYPE_ENV,
    ) -> None:
        super().__init__(url_env=base_url_env, environ=environ, client=client)
        self.email_env = _identifier(email_env, "Jira email environment variable")
        self.token_env = _identifier(token_env, "Jira token environment variable")
        self.project_env = _identifier(project_env, "Jira project environment variable")
        self.issue_type_env = _identifier(issue_type_env, "Jira issue type environment variable")

    def _url(self) -> str:
        return _jira_issue_url(_required_env(self._environ, self.url_env, 4096))

    def _jira_configuration(self) -> Tuple[str, str, str, str]:
        email = _required_env(self._environ, self.email_env, 320)
        _validate_email_address(email, "Jira email")
        token = _required_env(self._environ, self.token_env, 4096, secret=True)
        project = _required_env(self._environ, self.project_env, 32).upper()
        if not _PROJECT_RE.fullmatch(project):
            raise DeliveryValidationError("invalid_jira_project", "Jira project key is invalid")
        issue_type = _optional_env(self._environ, self.issue_type_env, 64, "Task") or "Task"
        if not _ISSUE_TYPE_RE.fullmatch(issue_type):
            raise DeliveryValidationError("invalid_jira_issue_type", "Jira issue type is invalid")
        return email, token, project, issue_type

    def _headers(self) -> Dict[str, str]:
        email, token, _, _ = self._jira_configuration()
        encoded = base64.b64encode((email + ":" + token).encode("utf-8")).decode("ascii")
        return {"Authorization": "Basic " + encoded}

    def _payload(self, notification: Notification) -> Dict[str, Any]:
        _, _, project, issue_type = self._jira_configuration()
        title = notification.title[:240]
        body = render_notification_text(notification, maximum=30_000)
        return {
            "fields": {
                "project": {"key": project},
                "issuetype": {"name": issue_type},
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": body}],
                    }],
                },
                "labels": ["blackthorn-automation"],
            }
        }

    def _remote_id(self, response: TransportResponse) -> str:
        try:
            parsed = json.loads(response.body.decode("utf-8")) if response.body else {}
            value = _text(parsed.get("key") or "", "Jira issue key", 64)
            return value if _JIRA_ISSUE_KEY_RE.fullmatch(value) else ""
        except (UnicodeError, ValueError, TypeError, AttributeError, DeliveryError):
            return ""


def _validate_email_address(value: str, field_name: str) -> str:
    clean = _text(value, field_name, 320, required=True)
    if "\r" in clean or "\n" in clean or "," in clean or ";" in clean:
        raise DeliveryValidationError("invalid_email", "%s is invalid" % field_name)
    display, address = parseaddr(clean)
    if display or address != clean or address.count("@") != 1:
        raise DeliveryValidationError("invalid_email", "%s is invalid" % field_name)
    local, domain = address.rsplit("@", 1)
    if not local or len(local) > 64 or not domain or "." not in domain:
        raise DeliveryValidationError("invalid_email", "%s is invalid" % field_name)
    return clean


@dataclass(frozen=True)
class SMTPDestination:
    """Resolved non-secret SMTP routing data passed to an injected transport."""

    host: str
    port: int
    addresses: Tuple[str, ...] = field(repr=False)
    security: str = "starttls"

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _text(self.host, "SMTP host", 253, required=True).lower())
        if not 1 <= int(self.port) <= 65535:
            raise DeliveryValidationError("invalid_smtp_port", "SMTP port is out of range")
        object.__setattr__(self, "port", int(self.port))
        if self.security not in {"ssl", "starttls"}:
            raise DeliveryValidationError("invalid_smtp_security", "SMTP must use SSL or STARTTLS")
        if not self.addresses or len(self.addresses) > MAX_RESOLVED_ADDRESSES:
            raise DeliverySecurityError("dns_resolution_failed", "SMTP destination did not resolve")
        for address in self.addresses:
            _require_public_ip(address)


SMTPTransport = Callable[
    [SMTPDestination, str, str, str, Tuple[str, ...], EmailMessage, float],
    None,
]


class _PinnedSMTP(smtplib.SMTP):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        self._pinned_address = address
        super().__init__(host=host, port=port, timeout=timeout)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return socket.create_connection((self._pinned_address, port), timeout=timeout)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(
        self,
        host: str,
        port: int,
        address: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        self._pinned_address = address
        super().__init__(host=host, port=port, timeout=timeout, context=context)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        raw = socket.create_connection((self._pinned_address, port), timeout=timeout)
        return self.context.wrap_socket(raw, server_hostname=self._host)


def _pinned_smtp_transport(
    destination: SMTPDestination,
    username: str,
    password: str,
    sender: str,
    recipients: Tuple[str, ...],
    message: EmailMessage,
    timeout: float,
) -> None:
    context = ssl.create_default_context()
    last_error: Optional[BaseException] = None
    for address in destination.addresses:
        client: Optional[smtplib.SMTP] = None
        try:
            if destination.security == "ssl":
                client = _PinnedSMTPSSL(
                    destination.host, destination.port, address, timeout, context
                )
            else:
                client = _PinnedSMTP(destination.host, destination.port, address, timeout)
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
            if username:
                client.login(username, password)
            refused = client.send_message(message, from_addr=sender, to_addrs=list(recipients))
            if refused:
                raise DeliveryError("smtp_recipients_refused", "SMTP rejected one or more recipients")
            try:
                client.quit()
            except smtplib.SMTPException:
                client.close()
            return
        except DeliveryError:
            raise
        except (OSError, ssl.SSLError, smtplib.SMTPException) as exc:
            last_error = exc
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
    raise DeliveryError("smtp_transport_failed", "SMTP delivery failed") from last_error


class SMTPEmailAdapter:
    """Send TLS-protected email using environment-only connection settings."""

    name = "smtp"

    def __init__(
        self,
        *,
        environ: Optional[Mapping[str, str]] = None,
        resolver: Resolver = socket.getaddrinfo,
        transport: Optional[SMTPTransport] = None,
        timeout: float = DEFAULT_SMTP_TIMEOUT,
    ) -> None:
        if environ is not None and not isinstance(environ, Mapping):
            raise DeliveryValidationError("invalid_environment", "connector environment must be a mapping")
        if not callable(resolver) or (transport is not None and not callable(transport)):
            raise DeliveryValidationError("invalid_transport", "SMTP resolver and transport must be callable")
        self._environ = environ if environ is not None else os.environ
        self.resolver = resolver
        self.transport = transport or _pinned_smtp_transport
        self.timeout = float(timeout)
        if not 0.1 <= self.timeout <= 120.0:
            raise DeliveryValidationError("invalid_timeout", "SMTP timeout is out of range")

    def _configuration(
        self,
    ) -> Tuple[SMTPDestination, str, str, str, Tuple[str, ...]]:
        host = _required_env(self._environ, SMTP_HOST_ENV, 253)
        security = _optional_env(self._environ, SMTP_SECURITY_ENV, 16, "starttls").lower() or "starttls"
        if security not in {"ssl", "starttls"}:
            raise DeliveryValidationError("invalid_smtp_security", "SMTP must use SSL or STARTTLS")
        default_port = 465 if security == "ssl" else 587
        raw_port = _optional_env(self._environ, SMTP_PORT_ENV, 5, str(default_port))
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise DeliveryValidationError("invalid_smtp_port", "SMTP port is invalid") from exc
        addresses = resolve_public_host(host, port, resolver=self.resolver)
        destination = SMTPDestination(host, port, addresses, security)
        username = _optional_env(self._environ, SMTP_USERNAME_ENV, 320)
        password = _optional_env(self._environ, SMTP_PASSWORD_ENV, 4096)
        if "\r" in username or "\n" in username:
            raise DeliveryValidationError("invalid_smtp_username", "SMTP username is invalid")
        if bool(username) != bool(password):
            raise DeliveryValidationError("incomplete_smtp_auth", "SMTP username and password must be provided together")
        sender = _validate_email_address(
            _required_env(self._environ, SMTP_FROM_ENV, 320),
            "SMTP sender",
        )
        raw_recipients = _required_env(self._environ, SMTP_TO_ENV, 8192)
        values = tuple(item.strip() for item in raw_recipients.split(",") if item.strip())
        if not values or len(values) > 50:
            raise DeliveryValidationError("invalid_recipients", "SMTP recipient count is out of range")
        recipients = tuple(_validate_email_address(value, "SMTP recipient") for value in values)
        return destination, username, password, sender, recipients

    def deliver(self, notification: Notification, *, dry_run: bool = False) -> DeliveryResult:
        notification_id = _notification_id(notification)
        try:
            destination, username, password, sender, recipients = self._configuration()
            message = EmailMessage()
            message["Subject"] = "[Blackthorn/%s] %s" % (
                _notification_severity(notification).upper(),
                notification.title[:180],
            )
            message["From"] = sender
            message["To"] = ", ".join(recipients)
            message.set_content(render_notification_text(notification, maximum=50_000))
            encoded = message.as_bytes()
            if len(encoded) > MAX_HTTP_PAYLOAD_BYTES:
                raise DeliveryValidationError("payload_too_large", "email payload exceeds its size limit")
            if dry_run:
                return DeliveryResult(self.name, "dry_run", True, notification_id)
            self.transport(
                destination,
                username,
                password,
                sender,
                recipients,
                message,
                self.timeout,
            )
            return DeliveryResult(self.name, "sent", True, notification_id)
        except DeliveryError as exc:
            return DeliveryResult(self.name, "failed", False, notification_id, error_code=exc.error_code)
        except Exception:
            return DeliveryResult(self.name, "failed", False, notification_id, error_code="adapter_failed")


DeliveryAdapter = Union[
    GenericWebhookAdapter,
    SlackWebhookAdapter,
    TeamsWebhookAdapter,
    JiraIssueAdapter,
    SMTPEmailAdapter,
]


class NotificationDispatcher:
    """Apply dedupe/escalation, deliver, and write non-secret audit history."""

    def __init__(
        self,
        adapters: Sequence[DeliveryAdapter],
        *,
        tracker: Optional[DedupeTracker] = None,
        store: Optional[DeliveryStateStore] = None,
    ) -> None:
        if not adapters or len(adapters) > 20:
            raise DeliveryValidationError("invalid_adapter_count", "adapter count is out of range")
        if any(not hasattr(adapter, "name") or not callable(getattr(adapter, "deliver", None)) for adapter in adapters):
            raise DeliveryValidationError("invalid_adapter", "delivery adapter is invalid")
        names = [_identifier(adapter.name, "adapter") for adapter in adapters]
        if len(names) != len(set(names)):
            raise DeliveryValidationError("duplicate_adapter", "adapter names must be unique")
        self.adapters = tuple(adapters)
        self.store = store or (tracker.store if tracker is not None else DeliveryStateStore())
        self.tracker = tracker or DedupeTracker(store=self.store)

    def dispatch_event(
        self,
        event: NotificationEvent,
        *,
        dry_run: bool = False,
        now: Optional[datetime] = None,
    ) -> DispatchResult:
        decision = self.tracker.decide(event, now=now)
        if decision.action not in {"deliver", "escalate"}:
            self.store.add_history(
                notification_id=event.event_id,
                fingerprint=decision.fingerprint,
                kind=event.kind,
                severity=event.severity,
                adapter="dispatcher",
                status="skipped",
                error_code=decision.reason,
                recorded_at=_iso(now),
            )
            return DispatchResult(event.event_id, decision, ())
        deliveries = self._deliver(event, decision.fingerprint, dry_run=dry_run, now=now)
        if not dry_run and any(result.status == "sent" and result.success for result in deliveries):
            self.tracker.record_delivery(event, decision, delivered_at=now)
        return DispatchResult(event.event_id, decision, deliveries)

    def dispatch_digest(
        self,
        digest: NotificationDigest,
        *,
        dry_run: bool = False,
        now: Optional[datetime] = None,
    ) -> DispatchResult:
        fingerprint = hashlib.sha256(("digest:" + digest.digest_id).encode("utf-8")).hexdigest()
        deliveries = self._deliver(digest, fingerprint, dry_run=dry_run, now=now)
        return DispatchResult(digest.digest_id, None, deliveries)

    def _deliver(
        self,
        notification: Notification,
        fingerprint: str,
        *,
        dry_run: bool,
        now: Optional[datetime],
    ) -> Tuple[DeliveryResult, ...]:
        results: List[DeliveryResult] = []
        for adapter in self.adapters:
            try:
                result = adapter.deliver(notification, dry_run=dry_run)
            except Exception:
                result = DeliveryResult(
                    adapter.name,
                    "failed",
                    False,
                    _notification_id(notification),
                    error_code="adapter_failed",
                )
            results.append(result)
            self.store.add_history(
                notification_id=_notification_id(notification),
                fingerprint=fingerprint,
                kind=_notification_kind(notification),
                severity=_notification_severity(notification),
                adapter=result.adapter,
                status=result.status,
                error_code=result.error_code,
                remote_id=result.remote_id,
                recorded_at=_iso(now),
            )
        return tuple(results)


__all__ = [
    "GENERIC_WEBHOOK_URL_ENV",
    "JIRA_API_TOKEN_ENV",
    "JIRA_BASE_URL_ENV",
    "JIRA_EMAIL_ENV",
    "JIRA_ISSUE_TYPE_ENV",
    "JIRA_PROJECT_KEY_ENV",
    "SLACK_WEBHOOK_URL_ENV",
    "SMTP_FROM_ENV",
    "SMTP_HOST_ENV",
    "SMTP_PASSWORD_ENV",
    "SMTP_PORT_ENV",
    "SMTP_SECURITY_ENV",
    "SMTP_TO_ENV",
    "SMTP_USERNAME_ENV",
    "TEAMS_WEBHOOK_URL_ENV",
    "DeliveryDecision",
    "DeliveryError",
    "DeliveryResult",
    "DeliverySecurityError",
    "DeliveryStateStore",
    "DeliveryValidationError",
    "DedupePolicy",
    "DedupeTracker",
    "DispatchResult",
    "FeedHealthTracker",
    "GenericWebhookAdapter",
    "JiraIssueAdapter",
    "NotificationDigest",
    "NotificationDispatcher",
    "NotificationEvent",
    "ResolvedEndpoint",
    "SMTPDestination",
    "SMTPEmailAdapter",
    "SecureHTTPClient",
    "SlackWebhookAdapter",
    "SourceHealth",
    "TeamsWebhookAdapter",
    "TransportResponse",
    "notification_payload",
    "render_notification_text",
    "resolve_public_host",
    "validate_https_endpoint",
]
