"""Fail-closed validation plans for exploit-intelligence matches.

The exploit-intelligence layer is deliberately read-only.  When a user chooses
to validate one of its matches, this module is the boundary between advisory
metadata and active traffic:

* recipes are immutable, built in, and covered by an Ed25519-signed registry;
* a manifest can only be rebuilt from those recipes;
* generated pipelines contain one Blackthorn ``--safe-mode`` scan and a local
  report -- never an external tool, downloaded definition, or free-form args;
* approvals bind the target, engagement, and exact manifest for a short period;
* current engagement scope is checked again immediately before a run starts.

The module is GUI-free.  ``automation_ui`` can use the controller to create a
request/approval, obtain an :class:`ExecutionGrant`, and pass the grant's fresh
pipeline definition to its existing worker infrastructure.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
from urllib.parse import urlsplit, urlunsplit

from .authorization import is_authorized
from .pentest_models import ModelValidationError, validate_url
from .redaction import redact_text


MANIFEST_VERSION = 1
REGISTRY_VERSION = 1
MAX_REQUEST_TTL_SECONDS = 30 * 60
MAX_APPROVAL_TTL_SECONDS = 15 * 60
MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 15 * 60
MAX_RUNS_PER_TARGET = 2
RATE_WINDOW_SECONDS = 5 * 60

_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^(?:CWE-)?([0-9]{1,6})$", re.IGNORECASE)

# Automation never enters the general-purpose scanner.  This single category
# denotes a dedicated, fixed-contract observation stage: one ordinary GET to
# the exact approved URL, no redirects, mutations, plugins, or exploit payloads.
ALLOWED_SAFE_CATEGORIES = frozenset({"authorized_http_observation"})
ALLOWED_REPORT_FORMATS = frozenset({"json", "html", "sarif"})


class ValidationError(ValueError):
    """A validation request or immutable record is malformed."""


class ValidationSecurityError(PermissionError):
    """A fail-closed automation safety boundary rejected an operation."""


class ManifestVerificationError(ValidationSecurityError):
    """The signed registry or selected manifest did not verify."""


class ApprovalError(ValidationSecurityError):
    """A request is not covered by a current, exact approval."""


class ScopeRecheckError(ValidationSecurityError):
    """The current engagement no longer authorizes the requested target."""


class RateLimitError(ValidationSecurityError):
    """Too many validations were started for the same target."""


class KillSwitchEngaged(ValidationSecurityError):
    """Global validation cancellation is active."""


def _canonical_json(value: Any) -> bytes:
    """Return the single accepted JSON representation for signed material."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("signed material must be canonical JSON") from exc
    return text.encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _text(value: Any, label: str, maximum: int = 512) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValidationError("%s is required" % label)
    if len(result) > maximum or "\x00" in result:
        raise ValidationError("%s is invalid" % label)
    return result


def _identifier(value: Any, label: str) -> str:
    result = _text(value, label, 128).lower()
    if not _IDENTIFIER_RE.fullmatch(result):
        raise ValidationError("%s contains unsupported characters" % label)
    return result


def _timestamp(value: Any, label: str = "timestamp") -> float:
    try:
        result = round(float(value), 6)
    except (TypeError, ValueError) as exc:
        raise ValidationError("%s is invalid" % label) from exc
    if result < 0 or result != result or result in (float("inf"), float("-inf")):
        raise ValidationError("%s is invalid" % label)
    return result


def _stable_id(kind: str, payload: Mapping[str, Any]) -> str:
    return "%s:%s" % (kind, _sha256(payload)[:24])


def _normalize_advisory(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text or len(text) > 128 or not re.fullmatch(r"[A-Z0-9_.:-]+", text):
        return ""
    return text


def _normalize_cwe(value: Any) -> str:
    match = _CWE_RE.fullmatch(str(value or "").strip())
    return "CWE-%s" % int(match.group(1)) if match else ""


def _normalize_category(value: Any) -> str:
    text = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    return text if re.fullmatch(r"[a-z0-9_]{1,64}", text) else ""


def _values(value: Any) -> Tuple[Any, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    try:
        return tuple(value)
    except TypeError:
        return (value,)


def _target_key(target: str) -> str:
    """Rate-limit an origin as one target, regardless of URL path spelling."""
    try:
        checked = validate_url(target, allow_ws=False)
        parsed = urlsplit(checked)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        default = 443 if scheme == "https" else 80
        rendered_host = "[%s]" % hostname if ":" in hostname else hostname
        authority = (
            rendered_host
            if port in (None, default)
            else "%s:%d" % (rendered_host, port)
        )
        return urlunsplit((scheme, authority, "", "", ""))
    except (ModelValidationError, TypeError, ValueError) as exc:
        raise ValidationError("target must be an absolute HTTP(S) URL") from exc


@dataclass(frozen=True)
class SafeValidatorRecipe:
    """One built-in mapping from advisory metadata to safe scanner coverage."""

    recipe_id: str
    title: str
    scan_categories: Tuple[str, ...]
    advisory_ids: Tuple[str, ...] = ()
    cwes: Tuple[str, ...] = ()
    categories: Tuple[str, ...] = ()
    timeout_seconds: int = 300
    request_budget: int = 250

    def __post_init__(self) -> None:
        recipe_id = _identifier(self.recipe_id, "recipe id")
        title = _text(self.title, "recipe title", 256)
        scan_categories = tuple(dict.fromkeys(
            _normalize_category(item) for item in self.scan_categories
            if _normalize_category(item)
        ))
        if not scan_categories or not set(scan_categories) <= ALLOWED_SAFE_CATEGORIES:
            raise ValidationError("recipe contains a non-allowlisted scanner category")
        advisory_ids = tuple(dict.fromkeys(
            item for item in (_normalize_advisory(v) for v in self.advisory_ids) if item
        ))
        cwes = tuple(dict.fromkeys(
            item for item in (_normalize_cwe(v) for v in self.cwes) if item
        ))
        categories = tuple(dict.fromkeys(
            item for item in (_normalize_category(v) for v in self.categories) if item
        ))
        if not advisory_ids and not cwes and not categories:
            raise ValidationError("recipe requires an advisory, CWE, or category mapping")
        timeout_seconds = int(self.timeout_seconds)
        request_budget = int(self.request_budget)
        if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValidationError("recipe timeout is out of range")
        if not 1 <= request_budget <= 5000:
            raise ValidationError("recipe request budget is out of range")
        object.__setattr__(self, "recipe_id", recipe_id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "scan_categories", scan_categories)
        object.__setattr__(self, "advisory_ids", advisory_ids)
        object.__setattr__(self, "cwes", cwes)
        object.__setattr__(self, "categories", categories)
        object.__setattr__(self, "timeout_seconds", timeout_seconds)
        object.__setattr__(self, "request_budget", request_budget)

    def canonical(self) -> Dict[str, Any]:
        return {
            "advisory_ids": list(self.advisory_ids),
            "categories": list(self.categories),
            "cwes": list(self.cwes),
            "recipe_id": self.recipe_id,
            "request_budget": self.request_budget,
            "scan_categories": list(self.scan_categories),
            "timeout_seconds": self.timeout_seconds,
            "title": self.title,
        }


# Registry entries map advisory metadata to an evidence-only HTTP observation.
# They never select scanner techniques or exploit payloads. CVEs not named below
# fall back to the generic recipe while CWE/category matches retain explainable
# reasons for why the same fixed observation was proposed.
BUILTIN_VALIDATOR_RECIPES: Tuple[SafeValidatorRecipe, ...] = (
    SafeValidatorRecipe(
        "advisory-observation",
        "One-request advisory exposure observation",
        ("authorized_http_observation",),
        advisory_ids=(
            "CVE-2014-0160", "CVE-2015-1635", "CVE-2019-10149",
            "CVE-2020-1938", "CVE-2021-23017", "CVE-2024-23897",
        ),
        categories=("advisory", "cve", "known_exploited", "exposure"),
        timeout_seconds=30,
        request_budget=1,
    ),
    SafeValidatorRecipe(
        "injection-observation",
        "One-request injection-advisory observation",
        ("authorized_http_observation",),
        advisory_ids=("CVE-2021-44228", "CVE-2024-4577"),
        cwes=("CWE-20", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89",
              "CWE-90", "CWE-91", "CWE-94", "CWE-611", "CWE-917"),
        categories=("injection", "xss", "sqli", "rce", "xxe"),
        timeout_seconds=30,
        request_budget=1,
    ),
    SafeValidatorRecipe(
        "path-boundary-observation",
        "One-request path-advisory observation",
        ("authorized_http_observation",),
        advisory_ids=("CVE-2021-41773", "CVE-2021-42013"),
        cwes=("CWE-22", "CWE-23", "CWE-35", "CWE-36"),
        categories=("path_traversal", "file_inclusion"),
        timeout_seconds=30,
        request_budget=1,
    ),
    SafeValidatorRecipe(
        "access-control-observation",
        "One-request access-control advisory observation",
        ("authorized_http_observation",),
        cwes=("CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-639", "CWE-862"),
        categories=("authentication", "authorization", "access_control", "jwt"),
        timeout_seconds=30,
        request_budget=1,
    ),
    SafeValidatorRecipe(
        "server-configuration-observation",
        "One-request server metadata observation",
        ("authorized_http_observation",),
        cwes=("CWE-16", "CWE-200", "CWE-319", "CWE-326", "CWE-693"),
        categories=("misconfiguration", "information_disclosure", "tls", "exposure"),
        timeout_seconds=30,
        request_budget=1,
    ),
    SafeValidatorRecipe(
        "request-routing-observation",
        "One-request routing-advisory observation",
        ("authorized_http_observation",),
        cwes=("CWE-918",),
        categories=("ssrf", "cloud", "metadata"),
        timeout_seconds=30,
        request_budget=1,
    ),
    SafeValidatorRecipe(
        "graphql-observation",
        "One-request GraphQL advisory observation",
        ("authorized_http_observation",),
        categories=("graphql",),
        timeout_seconds=30,
        request_budget=1,
    ),
)

_RECIPE_BY_ID = MappingProxyType({
    item.recipe_id: item for item in BUILTIN_VALIDATOR_RECIPES
})
if len(_RECIPE_BY_ID) != len(BUILTIN_VALIDATOR_RECIPES):  # pragma: no cover
    raise RuntimeError("duplicate built-in validator recipe id")


def _registry_payload() -> Dict[str, Any]:
    return {
        "registry_version": REGISTRY_VERSION,
        "recipes": [item.canonical() for item in BUILTIN_VALIDATOR_RECIPES],
    }


# Offline-generated Ed25519 public key/signature.  The private signing key is not
# distributed.  Replacing a registry entry without deliberately re-signing the
# source therefore fails closed.  Values are filled from the canonical payload
# and verified before any manifest is accepted.
BUILTIN_REGISTRY_HASH = "ff73d4492b378a55f01120ce91868db16116357e650e8b7270b3d0710415c0be"
BUILTIN_REGISTRY_PUBLIC_KEY = "vwRp5sxfveQ4QBn4l1JlfFDEDsK4TCmWgPrF5dxfcv4="
BUILTIN_REGISTRY_SIGNATURE = (
    "x8TDv51xV0mqx2fna/UIcOH/t9XRoCHXrrjIQaZulRbC3jNsuH9XQuY/JSgMJTpp"
    "IOtVsVa5Ig6hsUjcooX0Bw=="
)


def verify_registry_signature() -> bool:
    payload = _canonical_json(_registry_payload())
    if hashlib.sha256(payload).hexdigest() != BUILTIN_REGISTRY_HASH:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    try:
        public_key = base64.b64decode(BUILTIN_REGISTRY_PUBLIC_KEY, validate=True)
        signature = base64.b64decode(BUILTIN_REGISTRY_SIGNATURE, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (ValueError, InvalidSignature):
        return False
    return True


def list_validator_recipes() -> Tuple[SafeValidatorRecipe, ...]:
    """Return the immutable, signed built-in registry in display order."""
    if not verify_registry_signature():
        raise ManifestVerificationError("built-in validator registry signature failed")
    return BUILTIN_VALIDATOR_RECIPES


def _signal_value(signal: Any, key: str, default: Any = None) -> Any:
    if signal is None:
        return default
    if isinstance(signal, Mapping):
        return signal.get(key, default)
    return getattr(signal, key, default)


def match_validator_recipes(
    signal: Any = None,
    *,
    advisory_ids: Iterable[Any] = (),
    cwes: Iterable[Any] = (),
    categories: Iterable[Any] = (),
) -> Tuple[SafeValidatorRecipe, ...]:
    """Map an ``ExploitSignal`` (or explicit keys) to built-in safe recipes.

    ``signal`` intentionally uses duck typing so the intelligence backend does
    not become a dependency cycle.  Supported fields are ``identifier``,
    ``cve_id``, ``advisory_ids``, ``cwes``, and ``known_exploited``.
    """
    recipes = list_validator_recipes()
    advisory_values: List[Any] = list(_values(advisory_ids))
    for key in ("identifier", "cve_id"):
        value = _signal_value(signal, key, "")
        if value:
            advisory_values.append(value)
    advisory_values.extend(_values(_signal_value(signal, "advisory_ids", ())))
    cwe_values = list(_values(cwes))
    cwe_values.extend(_values(_signal_value(signal, "cwes", ())))
    category_values = list(_values(categories))
    if bool(_signal_value(signal, "known_exploited", False)):
        category_values.append("known_exploited")

    advisory_set = {
        item for item in (_normalize_advisory(value) for value in advisory_values) if item
    }
    cwe_set = {item for item in (_normalize_cwe(value) for value in cwe_values) if item}
    category_set = {
        item for item in (_normalize_category(value) for value in category_values) if item
    }
    if any(_CVE_RE.fullmatch(value) for value in advisory_set):
        category_set.add("cve")
        category_set.add("advisory")

    matched = []
    for recipe in recipes:
        if (
            advisory_set.intersection(recipe.advisory_ids)
            or cwe_set.intersection(recipe.cwes)
            or category_set.intersection(recipe.categories)
        ):
            matched.append(recipe)
    # A syntactically valid CVE always gets bounded generic observation even if
    # the current source revision predates that CVE.
    if advisory_set and any(_CVE_RE.fullmatch(value) for value in advisory_set):
        generic = _RECIPE_BY_ID["advisory-observation"]
        if generic not in matched:
            matched.append(generic)
    return tuple(sorted(matched, key=lambda item: item.recipe_id))


@dataclass(frozen=True)
class ManifestStage:
    stage_id: str
    stage_type: str
    categories: Tuple[str, ...] = ()
    report_format: str = ""
    threads: int = 3
    delay_milliseconds: int = 500
    safe_mode: bool = True

    def canonical(self) -> Dict[str, Any]:
        return {
            "categories": list(self.categories),
            "delay_milliseconds": self.delay_milliseconds,
            "report_format": self.report_format,
            "safe_mode": self.safe_mode,
            "stage_id": self.stage_id,
            "stage_type": self.stage_type,
            "threads": self.threads,
        }


@dataclass(frozen=True)
class ValidationManifest:
    manifest_version: int
    registry_hash: str
    recipe_ids: Tuple[str, ...]
    stages: Tuple[ManifestStage, ...]
    timeout_seconds: int
    request_budget: int
    manifest_hash: str
    manifest_signature: str

    def unsigned_payload(self) -> Dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "recipe_ids": list(self.recipe_ids),
            "registry_hash": self.registry_hash,
            "request_budget": self.request_budget,
            "stages": [stage.canonical() for stage in self.stages],
            "timeout_seconds": self.timeout_seconds,
        }


def _manifest_binding(payload: Mapping[str, Any]) -> str:
    """Bind a selected manifest to the signed registry without a runtime key."""
    material = {
        "manifest": payload,
        "registry_signature": BUILTIN_REGISTRY_SIGNATURE,
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def create_validation_manifest(recipe_ids: Iterable[str]) -> ValidationManifest:
    """Create an exact, signed-registry-derived safe pipeline manifest."""
    if not verify_registry_signature():
        raise ManifestVerificationError("built-in validator registry signature failed")
    identifiers = tuple(sorted(dict.fromkeys(
        _identifier(value, "recipe id") for value in recipe_ids
    )))
    if not identifiers:
        raise ValidationError("at least one validator recipe is required")
    try:
        recipes = tuple(_RECIPE_BY_ID[value] for value in identifiers)
    except KeyError as exc:
        raise ValidationSecurityError("third-party validator recipes are not accepted") from exc

    categories = tuple(sorted(set(
        category for recipe in recipes for category in recipe.scan_categories
    )))
    stages = (
        ManifestStage(
            "http-observation",
            "http_observation",
            categories=categories,
            threads=1,
            delay_milliseconds=0,
            safe_mode=True,
        ),
        ManifestStage(
            "local-report",
            "report",
            report_format="json",
            threads=0,
            delay_milliseconds=0,
            safe_mode=True,
        ),
    )
    timeout_seconds = min(
        MAX_TIMEOUT_SECONDS,
        max(recipe.timeout_seconds for recipe in recipes),
    )
    # Combining recipe reasons never multiplies network activity. The dedicated
    # observation stage has an immutable one-request budget.
    request_budget = 1
    provisional = ValidationManifest(
        MANIFEST_VERSION,
        BUILTIN_REGISTRY_HASH,
        identifiers,
        stages,
        timeout_seconds,
        request_budget,
        "",
        "",
    )
    payload = provisional.unsigned_payload()
    manifest_hash = _sha256(payload)
    return replace(
        provisional,
        manifest_hash=manifest_hash,
        manifest_signature=_manifest_binding(payload),
    )


def verify_manifest(manifest: ValidationManifest) -> bool:
    if not isinstance(manifest, ValidationManifest) or not verify_registry_signature():
        return False
    if manifest.manifest_version != MANIFEST_VERSION:
        return False
    if manifest.registry_hash != BUILTIN_REGISTRY_HASH:
        return False
    try:
        expected = create_validation_manifest(manifest.recipe_ids)
    except (ValidationError, ValidationSecurityError):
        return False
    return (
        manifest == expected
        and manifest.manifest_hash == _sha256(manifest.unsigned_payload())
        and manifest.manifest_signature == _manifest_binding(manifest.unsigned_payload())
    )


def assert_manifest_valid(manifest: ValidationManifest) -> None:
    if not verify_manifest(manifest):
        raise ManifestVerificationError("validation manifest is not an exact signed built-in plan")


def build_safe_pipeline(manifest: ValidationManifest) -> Dict[str, Any]:
    """Return a fresh PipelineRunner definition for a verified manifest."""
    assert_manifest_valid(manifest)
    observation_stage = manifest.stages[0]
    report_stage = manifest.stages[1]
    pipeline = {
        "name": "automation-validation-%s" % manifest.manifest_hash[:12],
        "schema_version": 1,
        "stages": [
            {
                "id": observation_stage.stage_id,
                "type": "http_observation",
                "config": {
                    "method": "GET",
                    "request_budget": manifest.request_budget,
                    "max_response_bytes": 256 * 1024,
                    "timeout": 10,
                    "follow_redirects": False,
                },
            },
            {
                "id": report_stage.stage_id,
                "type": "report",
                "config": {"format": report_stage.report_format},
            },
        ],
    }
    assert_safe_pipeline(pipeline, manifest)
    return pipeline


def validate_safe_pipeline(
    pipeline: Any,
    manifest: Optional[ValidationManifest] = None,
) -> Tuple[str, ...]:
    """Return every reason a proposed automation pipeline is unsafe."""
    errors: List[str] = []
    if not isinstance(pipeline, Mapping):
        return ("pipeline must be a mapping",)
    if set(pipeline) - {"name", "schema_version", "stages"}:
        errors.append("pipeline contains unsupported top-level fields")
    stages = pipeline.get("stages")
    if not isinstance(stages, list) or len(stages) != 2:
        return tuple(errors + [
            "pipeline must contain exactly one HTTP observation and one report"
        ])
    observation, report = stages
    if (
        not isinstance(observation, Mapping)
        or observation.get("type") != "http_observation"
    ):
        errors.append("first stage must be the fixed HTTP observation")
    else:
        cfg = observation.get("config")
        if not isinstance(cfg, Mapping):
            errors.append("HTTP observation config must be a mapping")
        else:
            expected = {
                "method": "GET",
                "request_budget": 1,
                "max_response_bytes": 256 * 1024,
                "timeout": 10,
                "follow_redirects": False,
            }
            if dict(cfg) != expected:
                errors.append(
                    "HTTP observation must use the immutable one-request contract"
                )
    if not isinstance(report, Mapping) or report.get("type") != "report":
        errors.append("second stage must be a local report")
    else:
        cfg = report.get("config")
        if not isinstance(cfg, Mapping) or set(cfg) != {"format"}:
            errors.append("report config contains arbitrary or missing arguments")
        elif cfg.get("format") not in ALLOWED_REPORT_FORMATS:
            errors.append("report format is not allowlisted")
    def prohibited_stage(stage: Any) -> bool:
        if not isinstance(stage, Mapping):
            return False
        config = stage.get("config")
        config_keys = config if isinstance(config, Mapping) else {}
        return bool(
            stage.get("type") in {"external_tool", "nuclei", "manual", "offensive"}
            or any(key in config_keys for key in (
                "tool", "extra_args", "args", "command", "full_impact", "intrusive",
                "offensive", "template", "template_url",
            ))
        )

    if any(prohibited_stage(stage) for stage in stages):
        errors.append("external, downloaded, or offensive stages are forbidden")
    if manifest is not None:
        try:
            assert_manifest_valid(manifest)
            if pipeline != build_safe_pipeline_without_revalidation(manifest):
                errors.append("pipeline does not exactly match its approved manifest")
        except ValidationSecurityError:
            errors.append("pipeline manifest is invalid")
    return tuple(dict.fromkeys(errors))


def build_safe_pipeline_without_revalidation(manifest: ValidationManifest) -> Dict[str, Any]:
    """Internal exact rendering used to avoid recursion in validation."""
    scan_stage, report_stage = manifest.stages
    return {
        "name": "automation-validation-%s" % manifest.manifest_hash[:12],
        "schema_version": 1,
        "stages": [
            {
                "id": scan_stage.stage_id,
                "type": "http_observation",
                "config": {
                    "method": "GET",
                    "request_budget": manifest.request_budget,
                    "max_response_bytes": 256 * 1024,
                    "timeout": 10,
                    "follow_redirects": False,
                },
            },
            {
                "id": report_stage.stage_id,
                "type": "report",
                "config": {"format": report_stage.report_format},
            },
        ],
    }


def assert_safe_pipeline(
    pipeline: Any,
    manifest: Optional[ValidationManifest] = None,
) -> None:
    errors = validate_safe_pipeline(pipeline, manifest)
    if errors:
        raise ValidationSecurityError("; ".join(errors))


@dataclass(frozen=True)
class ValidationRequest:
    request_id: str
    target: str
    engagement_id: str
    manifest: ValidationManifest
    requested_by: str
    requested_at: float
    expires_at: float
    record_hash: str

    def unsigned_payload(self) -> Dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "expires_at": self.expires_at,
            "manifest_hash": self.manifest.manifest_hash,
            "request_id": self.request_id,
            "requested_at": self.requested_at,
            "requested_by": self.requested_by,
            "target": self.target,
        }


@dataclass(frozen=True)
class ValidationApproval:
    approval_id: str
    request_id: str
    target: str
    engagement_id: str
    manifest_hash: str
    approved_by: str
    approved_at: float
    expires_at: float
    record_hash: str

    def unsigned_payload(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "engagement_id": self.engagement_id,
            "expires_at": self.expires_at,
            "manifest_hash": self.manifest_hash,
            "request_id": self.request_id,
            "target": self.target,
        }


def _verify_record(record: Any) -> bool:
    return bool(
        hasattr(record, "unsigned_payload")
        and getattr(record, "record_hash", "") == _sha256(record.unsigned_payload())
    )


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_id: str
    event_type: str
    occurred_at: float
    subject_id: str
    target: str
    outcome: str
    details: Tuple[Tuple[str, str], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "subject_id": self.subject_id,
            "target": self.target,
            "outcome": self.outcome,
            "details": dict(self.details),
        }


class GlobalKillSwitch:
    """Thread-safe shared stop state; generation changes cancel existing grants."""

    def __init__(self) -> None:
        self._engaged = False
        self._generation = 0
        self._reason = ""
        self._lock = threading.Lock()

    @property
    def engaged(self) -> bool:
        with self._lock:
            return self._engaged

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def engage(self, reason: str = "operator kill switch") -> None:
        with self._lock:
            if not self._engaged:
                self._generation += 1
            self._engaged = True
            self._reason = str(reason or "operator kill switch")[:256]

    def reset(self) -> None:
        with self._lock:
            self._generation += 1
            self._engaged = False
            self._reason = ""


GLOBAL_KILL_SWITCH = GlobalKillSwitch()


class CancellationState:
    def __init__(self, kill_switch: GlobalKillSwitch) -> None:
        self._kill_switch = kill_switch
        self._generation = kill_switch.generation
        self._local = threading.Event()
        self._reason = ""
        self._lock = threading.Lock()

    def cancel(self, reason: str = "validation cancelled") -> None:
        with self._lock:
            self._reason = str(reason or "validation cancelled")[:256]
            self._local.set()

    @property
    def cancelled(self) -> bool:
        return bool(
            self._local.is_set()
            or self._kill_switch.engaged
            or self._kill_switch.generation != self._generation
        )

    @property
    def reason(self) -> str:
        with self._lock:
            local_reason = self._reason
        return local_reason or self._kill_switch.reason or (
            "global kill-switch state changed" if self.cancelled else ""
        )


class PerTargetRateLimiter:
    def __init__(
        self,
        limit: int = MAX_RUNS_PER_TARGET,
        window_seconds: float = RATE_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if int(limit) < 1 or float(window_seconds) <= 0:
            raise ValidationError("rate-limit settings are invalid")
        self.limit = int(limit)
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._events: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._counter = 0
        self._lock = threading.Lock()

    def acquire(self, target: str) -> str:
        key = _target_key(target)
        now = float(self._clock())
        with self._lock:
            events = self._events[key]
            while events and now - events[0][0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                raise RateLimitError("per-target validation start limit reached")
            self._counter += 1
            token = "rate:%s:%d" % (hashlib.sha256(key.encode("utf-8")).hexdigest()[:12], self._counter)
            events.append((now, token))
            return token

    def release(self, target: str, token: str) -> None:
        key = _target_key(target)
        with self._lock:
            events = self._events.get(key)
            if not events:
                return
            self._events[key] = deque(item for item in events if item[1] != token)


@dataclass(frozen=True)
class ExecutionGrant:
    run_id: str
    request: ValidationRequest
    approval: ValidationApproval
    started_at: float
    timeout_seconds: int
    request_budget: int
    cancellation: CancellationState

    def build_pipeline(self) -> Dict[str, Any]:
        if self.cancellation.cancelled:
            raise KillSwitchEngaged(self.cancellation.reason or "validation cancelled")
        return build_safe_pipeline(self.request.manifest)

    @property
    def status(self) -> str:
        return "cancelled" if self.cancellation.cancelled else "authorized"


def engagement_scope_recheck(
    engagement_lookup: Callable[[str], Optional[Mapping[str, Any]]],
) -> Callable[[ValidationRequest], bool]:
    """Adapt a DB lookup to a current scope+exclusions authorization callback."""

    def check(request: ValidationRequest) -> bool:
        try:
            engagement = engagement_lookup(request.engagement_id)
        except Exception:
            return False
        if not isinstance(engagement, Mapping):
            return False
        if str(engagement.get("status") or "active").lower() != "active":
            return False
        scope = list(engagement.get("scope") or [])
        exclusions = list(engagement.get("exclusions") or [])
        if not scope or not is_authorized(request.target, scope):
            return False
        return not (exclusions and is_authorized(request.target, exclusions))

    return check


class SafeValidationController:
    """In-memory request/approval/run coordinator for the Automation UI.

    Persistence layers may serialize the immutable records, but they must load
    them back through their canonical hashes and restore them into a controller;
    an arbitrary caller-supplied approval is never trusted by ``begin_run``.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        max_runs_per_target: int = MAX_RUNS_PER_TARGET,
        rate_window_seconds: float = RATE_WINDOW_SECONDS,
        kill_switch: Optional[GlobalKillSwitch] = None,
    ) -> None:
        self._clock = clock
        self.kill_switch = kill_switch or GLOBAL_KILL_SWITCH
        self.rate_limiter = PerTargetRateLimiter(
            max_runs_per_target, rate_window_seconds, monotonic_clock
        )
        self._requests: Dict[str, ValidationRequest] = {}
        self._approvals: Dict[str, ValidationApproval] = {}
        self._consumed_approvals: set[str] = set()
        self._active: Dict[str, ExecutionGrant] = {}
        self._audit: List[AuditEvent] = []
        self._audit_sequence = 0
        self._lock = threading.RLock()

    def _now(self, supplied: Optional[float] = None) -> float:
        return _timestamp(self._clock() if supplied is None else supplied)

    def _record(
        self,
        event_type: str,
        subject_id: str,
        target: str,
        outcome: str,
        *,
        now: Optional[float] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> AuditEvent:
        occurred_at = self._now(now)
        safe_details = tuple(sorted(
            (redact_text(str(key))[:64], redact_text(str(value))[:256])
            for key, value in (details or {}).items()
            if value is not None
        ))
        safe_target = redact_text(str(target))
        with self._lock:
            self._audit_sequence += 1
            sequence = self._audit_sequence
            payload = {
                "details": list(safe_details),
                "event_type": str(event_type),
                "occurred_at": occurred_at,
                "outcome": str(outcome),
                "sequence": sequence,
                "subject_id": str(subject_id),
                "target": safe_target,
            }
            event = AuditEvent(
                sequence,
                _stable_id("audit", payload),
                str(event_type),
                occurred_at,
                str(subject_id),
                safe_target,
                str(outcome),
                safe_details,
            )
            self._audit.append(event)
            return event

    def audit_events(self) -> Tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._audit)

    def request_validation(
        self,
        target: str,
        engagement_id: Any,
        manifest: ValidationManifest,
        *,
        requested_by: str,
        ttl_seconds: int = 10 * 60,
        now: Optional[float] = None,
    ) -> ValidationRequest:
        assert_manifest_valid(manifest)
        target = validate_url(target, allow_ws=False)
        _target_key(target)
        engagement = _identifier(engagement_id, "engagement id")
        requester = _text(requested_by, "requester", 128)
        ttl_seconds = int(ttl_seconds)
        if not 1 <= ttl_seconds <= MAX_REQUEST_TTL_SECONDS:
            raise ValidationError("request expiry is out of range")
        requested_at = self._now(now)
        base = {
            "engagement_id": engagement,
            "expires_at": requested_at + ttl_seconds,
            "manifest_hash": manifest.manifest_hash,
            "requested_at": requested_at,
            "requested_by": requester,
            "target": target,
        }
        request_id = _stable_id("validation-request", base)
        provisional = ValidationRequest(
            request_id,
            target,
            engagement,
            manifest,
            requester,
            requested_at,
            _timestamp(requested_at + ttl_seconds),
            "",
        )
        request = replace(provisional, record_hash=_sha256(provisional.unsigned_payload()))
        with self._lock:
            self._requests[request.request_id] = request
        self._record(
            "validation_requested", request.request_id, target, "queued",
            now=requested_at,
            details={"engagement_id": engagement, "manifest_hash": manifest.manifest_hash},
        )
        return request

    def approve(
        self,
        request_id: str,
        *,
        approved_by: str,
        ttl_seconds: int = 5 * 60,
        now: Optional[float] = None,
    ) -> ValidationApproval:
        with self._lock:
            request = self._requests.get(str(request_id))
        if request is None or not _verify_record(request) or not verify_manifest(request.manifest):
            raise ApprovalError("validation request is unknown or has been altered")
        approved_at = self._now(now)
        if approved_at >= request.expires_at:
            raise ApprovalError("validation request has expired")
        ttl_seconds = int(ttl_seconds)
        if not 1 <= ttl_seconds <= MAX_APPROVAL_TTL_SECONDS:
            raise ValidationError("approval expiry is out of range")
        approver = _text(approved_by, "approver", 128)
        expires_at = min(request.expires_at, approved_at + ttl_seconds)
        base = {
            "approved_at": approved_at,
            "approved_by": approver,
            "engagement_id": request.engagement_id,
            "expires_at": expires_at,
            "manifest_hash": request.manifest.manifest_hash,
            "request_id": request.request_id,
            "target": request.target,
        }
        approval_id = _stable_id("validation-approval", base)
        provisional = ValidationApproval(
            approval_id,
            request.request_id,
            request.target,
            request.engagement_id,
            request.manifest.manifest_hash,
            approver,
            approved_at,
            _timestamp(expires_at),
            "",
        )
        approval = replace(provisional, record_hash=_sha256(provisional.unsigned_payload()))
        with self._lock:
            self._approvals[approval.approval_id] = approval
        self._record(
            "validation_approved", approval.approval_id, request.target, "approved",
            now=approved_at,
            details={"request_id": request.request_id, "manifest_hash": approval.manifest_hash},
        )
        return approval

    def _approved_pair(
        self, approval_id: str, now: float
    ) -> Tuple[ValidationRequest, ValidationApproval]:
        with self._lock:
            approval = self._approvals.get(str(approval_id))
            request = self._requests.get(approval.request_id) if approval else None
            consumed = bool(approval and approval.approval_id in self._consumed_approvals)
        if approval is None or request is None:
            raise ApprovalError("approval is unknown")
        if consumed:
            raise ApprovalError("validation approval has already been used")
        if not _verify_record(approval) or not _verify_record(request):
            raise ApprovalError("approval record has been altered")
        if (
            approval.target != request.target
            or approval.engagement_id != request.engagement_id
            or approval.manifest_hash != request.manifest.manifest_hash
        ):
            raise ApprovalError("approval does not bind the current request")
        if now >= approval.expires_at or now >= request.expires_at:
            raise ApprovalError("validation approval has expired")
        assert_manifest_valid(request.manifest)
        return request, approval

    def begin_run(
        self,
        approval_id: str,
        *,
        scope_recheck: Callable[[ValidationRequest], bool],
        now: Optional[float] = None,
    ) -> ExecutionGrant:
        started_at = self._now(now)
        target = ""
        subject_id = str(approval_id)
        rate_token = ""
        request: Optional[ValidationRequest] = None
        try:
            if self.kill_switch.engaged:
                raise KillSwitchEngaged(self.kill_switch.reason or "global kill switch engaged")
            request, approval = self._approved_pair(approval_id, started_at)
            target = request.target
            # Reserve the target slot before consulting mutable engagement state;
            # it is rolled back if that final check fails.
            rate_token = self.rate_limiter.acquire(target)
            try:
                currently_authorized = bool(scope_recheck(request))
            except Exception as exc:
                raise ScopeRecheckError("current engagement scope check failed") from exc
            if not currently_authorized:
                raise ScopeRecheckError("target is no longer in current engagement scope")
            # A kill can arrive while the DB callback is running.  Check again;
            # the grant's cancellation state also observes all later changes.
            if self.kill_switch.engaged:
                raise KillSwitchEngaged(self.kill_switch.reason or "global kill switch engaged")
            cancellation = CancellationState(self.kill_switch)
            run_payload = {
                "approval_id": approval.approval_id,
                "manifest_hash": request.manifest.manifest_hash,
                "started_at": started_at,
                "target": request.target,
            }
            run_id = _stable_id("validation-run", run_payload)
            grant = ExecutionGrant(
                run_id,
                request,
                approval,
                started_at,
                request.manifest.timeout_seconds,
                request.manifest.request_budget,
                cancellation,
            )
            with self._lock:
                if approval.approval_id in self._consumed_approvals:
                    raise ApprovalError("validation approval has already been used")
                self._consumed_approvals.add(approval.approval_id)
                self._active[run_id] = grant
            self._record(
                "validation_started", run_id, target, "running", now=started_at,
                details={"approval_id": approval.approval_id, "timeout_seconds": grant.timeout_seconds},
            )
            return grant
        except ValidationSecurityError as exc:
            if rate_token and target:
                self.rate_limiter.release(target, rate_token)
            self._record(
                "validation_blocked", subject_id, target, exc.__class__.__name__,
                now=started_at,
            )
            raise

    def complete_run(
        self,
        run_id: str,
        *,
        status: str = "completed",
        now: Optional[float] = None,
    ) -> None:
        allowed = {"completed", "failed", "cancelled", "timed_out"}
        if status not in allowed:
            raise ValidationError("run status is invalid")
        with self._lock:
            grant = self._active.pop(str(run_id), None)
        if grant is None:
            raise ValidationError("validation run is not active")
        if status in {"cancelled", "timed_out"}:
            grant.cancellation.cancel(status)
        self._record(
            "validation_completed", grant.run_id, grant.request.target, status, now=now,
            details={"request_id": grant.request.request_id},
        )

    def cancel_run(self, run_id: str, reason: str = "operator cancelled") -> bool:
        with self._lock:
            grant = self._active.get(str(run_id))
        if grant is None:
            return False
        grant.cancellation.cancel(reason)
        self._record(
            "validation_cancelled", grant.run_id, grant.request.target, "cancelled",
            details={"reason": reason},
        )
        return True

    def engage_kill_switch(self, reason: str = "operator kill switch") -> None:
        self.kill_switch.engage(reason)
        with self._lock:
            active = tuple(self._active.values())
        for grant in active:
            grant.cancellation.cancel(reason)
        self._record(
            "validation_kill_switch", "global", "", "engaged",
            details={"reason": reason, "active_runs": len(active)},
        )

    def reset_kill_switch(self) -> None:
        self.kill_switch.reset()
        self._record("validation_kill_switch", "global", "", "reset")

    def execute(
        self,
        approval_id: str,
        *,
        scope_recheck: Callable[[ValidationRequest], bool],
        runner: Callable[[ExecutionGrant], Any],
        now: Optional[float] = None,
    ) -> Any:
        """Run a cancellation-aware callback with a hard cancellation timer.

        The callback must poll ``grant.cancellation.cancelled`` (or wire it to
        ``PipelineHooks.is_aborted``) and register/kill its child processes using
        the existing pipeline worker.  Python cannot safely terminate an
        arbitrary callback thread, so the timer changes shared cancellation
        state rather than spawning an unkillable helper thread.
        """
        grant = self.begin_run(approval_id, scope_recheck=scope_recheck, now=now)
        timer = threading.Timer(
            grant.timeout_seconds,
            lambda: grant.cancellation.cancel("validation timed out"),
        )
        timer.daemon = True
        timer.start()
        status = "completed"
        try:
            result = runner(grant)
            if grant.cancellation.cancelled:
                status = (
                    "timed_out" if "timed out" in grant.cancellation.reason else "cancelled"
                )
            return result
        except Exception:
            status = "failed"
            raise
        finally:
            timer.cancel()
            try:
                self.complete_run(grant.run_id, status=status)
            except ValidationError:
                pass


__all__ = [
    "ALLOWED_REPORT_FORMATS",
    "ALLOWED_SAFE_CATEGORIES",
    "ApprovalError",
    "AuditEvent",
    "BUILTIN_REGISTRY_HASH",
    "BUILTIN_VALIDATOR_RECIPES",
    "CancellationState",
    "ExecutionGrant",
    "GLOBAL_KILL_SWITCH",
    "GlobalKillSwitch",
    "KillSwitchEngaged",
    "ManifestVerificationError",
    "PerTargetRateLimiter",
    "RateLimitError",
    "SafeValidationController",
    "SafeValidatorRecipe",
    "ScopeRecheckError",
    "ValidationApproval",
    "ValidationError",
    "ValidationManifest",
    "ValidationRequest",
    "ValidationSecurityError",
    "assert_manifest_valid",
    "assert_safe_pipeline",
    "build_safe_pipeline",
    "create_validation_manifest",
    "engagement_scope_recheck",
    "list_validator_recipes",
    "match_validator_recipes",
    "validate_safe_pipeline",
    "verify_manifest",
    "verify_registry_signature",
]
