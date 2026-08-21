"""Engagement-scoped software inventory, SBOM import, and risk lifecycle.

The inventory stores bounded, normalized observations only.  SBOM inputs are
treated as untrusted data: formats and sizes are allowlisted, JSON structure is
bounded, and XML DTD/entity declarations are rejected before parsing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from functools import cmp_to_key
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import unquote

from .config import prepare_private_file


INVENTORY_STATE_VERSION = 1
MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_COMPONENTS = 10000
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100000
MAX_XML_DEPTH = 32
MAX_XML_ELEMENTS = 50000
MAX_EVIDENCE = 20
MAX_TEXT = 8192
MAX_REMEDIATIONS = 10000
MAX_CHANGE_EVENTS = 20000

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SPACE_RE = re.compile(r"\s+")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_CRITICALITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_CLASSIFICATION_ORDER = {
    "not_affected": 0, "possible": 1, "likely": 2, "exact": 3,
}
_MATERIAL_FIELDS = (
    "version", "cpe", "purl", "ecosystem", "evidence", "confidence",
    "criticality", "internet_exposed", "source",
)


class InventoryValidationError(ValueError):
    """Raised when an inventory or SBOM boundary is unsafe or malformed."""


class RemediationStatus(str, Enum):
    OPEN = "Open"
    FIXING = "Fixing"
    RETEST = "Retest"
    RESOLVED = "Resolved"
    ACCEPTED = "Accepted"


@dataclass(frozen=True)
class InventoryRecord:
    record_id: str
    engagement_id: str
    host: str
    service: str
    product: str
    version: str = ""
    cpe: str = ""
    purl: str = ""
    ecosystem: str = ""
    evidence: Tuple[str, ...] = ()
    confidence: float = 0.5
    first_seen: str = ""
    last_seen: str = ""
    criticality: str = "medium"
    internet_exposed: bool = False
    source: str = "manual"


@dataclass(frozen=True)
class InventorySnapshot:
    engagement_id: str
    observed_at: str
    records: Tuple[InventoryRecord, ...] = ()


@dataclass(frozen=True)
class InventoryImportResult:
    format: str
    source_name: str
    records: Tuple[InventoryRecord, ...] = ()
    warnings: Tuple[str, ...] = ()


@dataclass(frozen=True)
class InventoryAdvisoryMatch:
    record_id: str
    advisory_id: str
    classification: str
    identity_basis: str
    version_status: str
    confidence: float
    reasons: Tuple[str, ...]


@dataclass(frozen=True)
class Mitigation:
    mitigation_id: str
    description: str
    effectiveness: float
    verified: bool = False
    expires_at: str = ""


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    rating: str
    contributions: Dict[str, float]
    explanations: Tuple[str, ...]


@dataclass(frozen=True)
class RemediationEvent:
    event_id: str
    from_status: str
    to_status: str
    at: str
    owner: str = ""
    note: str = ""


@dataclass(frozen=True)
class RemediationItem:
    remediation_id: str
    engagement_id: str
    record_id: str
    advisory_id: str
    status: str = RemediationStatus.OPEN.value
    owner: str = ""
    sla_due: str = ""
    exception_expiry: str = ""
    created_at: str = ""
    updated_at: str = ""
    mitigations: Tuple[Mitigation, ...] = ()
    history: Tuple[RemediationEvent, ...] = ()


@dataclass(frozen=True)
class RecordChange:
    record_id: str
    fields: Tuple[str, ...]
    before: InventoryRecord
    after: InventoryRecord


@dataclass(frozen=True)
class InventoryChangeEvent:
    event_id: str
    engagement_id: str
    event_type: str
    at: str
    record_id: str = ""
    host: str = ""
    changed_fields: Tuple[str, ...] = ()


@dataclass(frozen=True)
class InventoryDiff:
    engagement_id: str
    added: Tuple[InventoryRecord, ...] = ()
    removed: Tuple[InventoryRecord, ...] = ()
    changed: Tuple[RecordChange, ...] = ()
    events: Tuple[InventoryChangeEvent, ...] = ()


@dataclass(frozen=True)
class InventoryState:
    engagement_id: str
    snapshot: InventorySnapshot
    remediations: Tuple[RemediationItem, ...] = ()
    change_events: Tuple[InventoryChangeEvent, ...] = ()
    saved_at: str = ""


VersionComparator = Callable[[str, str], int]


def _text(value: Any, maximum: int = MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", "")
    text = "".join(ch if ch in "\t\r\n" or ord(ch) >= 32 else " " for ch in text)
    # Keep imported content inert even if a UI accidentally enables rich text.
    text = text.replace("<", "\u2039").replace(">", "\u203a")
    return _SPACE_RE.sub(" ", text).strip()[:maximum]


def _identifier(value: Any, field_name: str) -> str:
    text = _text(value, 128)
    if not _ID_RE.fullmatch(text):
        raise InventoryValidationError("%s is invalid" % field_name)
    return text


def _now(value: Optional[Any] = None) -> str:
    if value is None:
        current = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        current = value
    else:
        text = _text(value, 64)
        _parse_timestamp(text, "timestamp")
        return text
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, field_name: str) -> datetime:
    text = _text(value, 64)
    if not text:
        raise InventoryValidationError("%s is required" % field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InventoryValidationError("%s must be an ISO-8601 timestamp" % field_name) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _optional_timestamp(value: Any, field_name: str) -> str:
    text = _text(value, 64)
    if text:
        _parse_timestamp(text, field_name)
    return text


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(str(part or "").strip().casefold() for part in parts)
    digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:20]
    return "%s:%s" % (prefix, digest)


def _unique(values: Iterable[Any], maximum: int = MAX_EVIDENCE,
            text_limit: int = 1024) -> Tuple[str, ...]:
    output: List[str] = []
    seen = set()
    for value in values:
        text = _text(value, text_limit)
        marker = text.casefold()
        if not text or marker in seen:
            continue
        seen.add(marker)
        output.append(text)
        if len(output) >= maximum:
            break
    return tuple(output)


def _validate_purl(value: Any) -> str:
    text = _text(value, 2048)
    if not text:
        return ""
    if (not text.startswith("pkg:") or not text.isascii()
            or any(ch.isspace() for ch in text)):
        raise InventoryValidationError("PURL is invalid")
    core = text[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in core or not core.split("/", 1)[0] or not core.rsplit("/", 1)[-1]:
        raise InventoryValidationError("PURL is invalid")
    return text


def _split_cpe(value: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    escaped = False
    for char in value:
        if char == ":" and not escaped:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    parts.append("".join(current))
    return parts


def _validate_cpe(value: Any) -> str:
    text = _text(value, 2048)
    if not text:
        return ""
    if text.startswith("cpe:2.3:"):
        if len(_split_cpe(text)) != 13:
            raise InventoryValidationError("CPE 2.3 is invalid")
    elif text.startswith("cpe:/"):
        if len(text) < 7:
            raise InventoryValidationError("CPE 2.2 is invalid")
    else:
        raise InventoryValidationError("CPE is invalid")
    return text


def purl_identity(value: str) -> str:
    """Return the package identity portion of a validated PURL, without version."""
    text = _validate_purl(value)
    core = text.split("#", 1)[0].split("?", 1)[0]
    prefix, path = core.split(":", 1)
    del prefix
    package_type, remainder = path.split("/", 1)
    if "@" in remainder:
        remainder = remainder.rsplit("@", 1)[0]
    return "pkg:%s/%s" % (package_type.lower(), remainder)


def purl_version(value: str) -> str:
    text = _validate_purl(value)
    core = text.split("#", 1)[0].split("?", 1)[0]
    remainder = core.split("/", 1)[1]
    if "@" not in remainder:
        return ""
    return unquote(remainder.rsplit("@", 1)[1])


def purl_ecosystem(value: str) -> str:
    text = _validate_purl(value)
    return text[4:].split("/", 1)[0]


def cpe_identity(value: str) -> str:
    text = _validate_cpe(value)
    if text.startswith("cpe:2.3:"):
        parts = _split_cpe(text)
        return ":".join(parts[2:5]).casefold()
    parts = text[5:].split(":")
    return ":".join(parts[:3]).casefold()


def _record_identity(
    engagement_id: str, host: str, service: str, product: str, cpe: str, purl: str
) -> str:
    if purl:
        software = purl_identity(purl)
    elif cpe:
        software = cpe_identity(cpe)
    else:
        software = _normalize_name(product)
    return _stable_id("inventory", engagement_id, host, service, software)


def create_inventory_record(
    *,
    engagement_id: Any,
    product: Any,
    host: Any = "",
    service: Any = "",
    version: Any = "",
    cpe: Any = "",
    purl: Any = "",
    ecosystem: Any = "",
    evidence: Iterable[Any] = (),
    confidence: float = 0.5,
    observed_at: Optional[Any] = None,
    first_seen: Any = "",
    criticality: str = "medium",
    internet_exposed: bool = False,
    source: Any = "manual",
    record_id: Any = "",
) -> InventoryRecord:
    """Create a bounded canonical inventory record."""
    engagement = _identifier(engagement_id, "engagement id")
    clean_product = _text(product, 512)
    if not clean_product:
        raise InventoryValidationError("product is required")
    clean_host = _text(host, 512)
    clean_service = _text(service, 512)
    clean_cpe = _validate_cpe(cpe)
    clean_purl = _validate_purl(purl)
    supplied_version = _text(version, 256)
    declared_purl_version = purl_version(clean_purl) if clean_purl else ""
    if (
        supplied_version
        and declared_purl_version
        and supplied_version != declared_purl_version
    ):
        raise InventoryValidationError(
            "inventory version conflicts with the version declared by its PURL"
        )
    clean_version = supplied_version or declared_purl_version
    clean_ecosystem = _text(ecosystem, 128) or (purl_ecosystem(clean_purl) if clean_purl else "")
    try:
        clean_confidence = float(confidence)
    except (TypeError, ValueError, OverflowError) as exc:
        raise InventoryValidationError("confidence is invalid") from exc
    if not 0.0 <= clean_confidence <= 1.0:
        raise InventoryValidationError("confidence must be between 0 and 1")
    clean_criticality = _text(criticality, 32).lower()
    if clean_criticality not in _CRITICALITY:
        raise InventoryValidationError("criticality is invalid")
    observed = _now(observed_at)
    first = _optional_timestamp(first_seen, "first seen") or observed
    source_text = _text(source, 128) or "manual"
    generated_id = _record_identity(
        engagement, clean_host, clean_service, clean_product, clean_cpe, clean_purl
    )
    supplied_id = _identifier(record_id, "record id") if record_id else generated_id
    return InventoryRecord(
        record_id=supplied_id,
        engagement_id=engagement,
        host=clean_host,
        service=clean_service,
        product=clean_product,
        version=clean_version,
        cpe=clean_cpe,
        purl=clean_purl,
        ecosystem=clean_ecosystem,
        evidence=_unique(evidence),
        confidence=clean_confidence,
        first_seen=first,
        last_seen=observed,
        criticality=clean_criticality,
        internet_exposed=bool(internet_exposed),
        source=source_text,
    )


def record_from_dict(value: Mapping[str, Any]) -> InventoryRecord:
    return create_inventory_record(
        engagement_id=value.get("engagement_id"),
        product=value.get("product"),
        host=value.get("host"),
        service=value.get("service"),
        version=value.get("version"),
        cpe=value.get("cpe"),
        purl=value.get("purl"),
        ecosystem=value.get("ecosystem"),
        evidence=value.get("evidence") or (),
        confidence=value.get("confidence", 0.5),
        observed_at=value.get("last_seen"),
        first_seen=value.get("first_seen"),
        criticality=value.get("criticality", "medium"),
        internet_exposed=bool(value.get("internet_exposed")),
        source=value.get("source", "manual"),
        record_id=value.get("record_id"),
    )


def merge_inventory_records(records: Iterable[InventoryRecord]) -> List[InventoryRecord]:
    output: Dict[str, InventoryRecord] = {}
    for record in islice(records, MAX_COMPONENTS * 2):
        existing = output.get(record.record_id)
        if existing is None:
            if len(output) >= MAX_COMPONENTS:
                break
            output[record.record_id] = record
            continue
        if existing.engagement_id != record.engagement_id:
            raise InventoryValidationError("record id crosses engagement boundaries")
        first = min(existing.first_seen, record.first_seen)
        last = max(existing.last_seen, record.last_seen)
        newest = record if record.last_seen >= existing.last_seen else existing
        output[record.record_id] = replace(
            newest,
            evidence=_unique(existing.evidence + record.evidence),
            confidence=max(existing.confidence, record.confidence),
            first_seen=first,
            last_seen=last,
            internet_exposed=existing.internet_exposed or record.internet_exposed,
            criticality=max(
                (existing.criticality, record.criticality),
                key=lambda item: _CRITICALITY[item],
            ),
        )
    return sorted(output.values(), key=lambda row: (row.host, row.service, row.product))


def _reject_constant(value: str) -> None:
    raise InventoryValidationError("SBOM JSON contains a non-finite number")


def _unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryValidationError("SBOM JSON contains duplicate object keys")
        result[key] = value
    return result


def _validate_json_shape(
    root: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
    max_container_items: int = MAX_COMPONENTS,
) -> None:
    pending = [(root, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > max_depth:
            raise InventoryValidationError("SBOM JSON exceeds the nesting limit")
        if nodes > max_nodes:
            raise InventoryValidationError("SBOM JSON exceeds the structure limit")
        if isinstance(value, Mapping):
            if len(value) > max_container_items:
                raise InventoryValidationError("SBOM JSON object is too large")
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            if len(value) > max_container_items:
                raise InventoryValidationError("SBOM JSON array is too large")
            pending.extend((child, depth + 1) for child in value)


def _read_sbom(path: str, maximum: int) -> bytes:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise InventoryValidationError("SBOM file could not be read") from exc
    if not 1 <= size <= maximum:
        raise InventoryValidationError("SBOM file size is outside the supported bounds")
    try:
        with open(path, "rb") as handle:
            data = handle.read(maximum + 1)
    except OSError as exc:
        raise InventoryValidationError("SBOM file could not be read") from exc
    if len(data) > maximum:
        raise InventoryValidationError("SBOM file exceeds the size limit")
    return data


def import_sbom(
    path: str,
    *,
    engagement_id: Any,
    host: Any = "",
    service: Any = "",
    criticality: str = "medium",
    internet_exposed: bool = False,
    observed_at: Optional[Any] = None,
    max_bytes: int = MAX_SBOM_BYTES,
) -> InventoryImportResult:
    """Import one allowlisted CycloneDX JSON/XML or SPDX JSON file."""
    if not 1024 <= int(max_bytes) <= MAX_SBOM_BYTES:
        raise InventoryValidationError("SBOM size limit is invalid")
    source_name = os.path.basename(path)
    return parse_sbom_bytes(
        _read_sbom(path, int(max_bytes)),
        source_name=source_name,
        engagement_id=engagement_id,
        host=host,
        service=service,
        criticality=criticality,
        internet_exposed=internet_exposed,
        observed_at=observed_at,
        max_bytes=max_bytes,
    )


def parse_sbom_bytes(
    data: bytes,
    *,
    source_name: str,
    engagement_id: Any,
    host: Any = "",
    service: Any = "",
    criticality: str = "medium",
    internet_exposed: bool = False,
    observed_at: Optional[Any] = None,
    max_bytes: int = MAX_SBOM_BYTES,
) -> InventoryImportResult:
    """Parse bounded SBOM bytes.  Intended for importers and deterministic tests."""
    try:
        size_limit = int(max_bytes)
    except (TypeError, ValueError, OverflowError) as exc:
        raise InventoryValidationError("SBOM size limit is invalid") from exc
    if not 1024 <= size_limit <= MAX_SBOM_BYTES:
        raise InventoryValidationError("SBOM size limit is invalid")
    if not isinstance(data, bytes) or not 1 <= len(data) <= size_limit:
        raise InventoryValidationError("SBOM payload size is outside the supported bounds")
    name = _text(os.path.basename(source_name), 256)
    lower = name.lower()
    is_json = lower.endswith(".json")
    is_xml = lower.endswith(".xml")
    if not (is_json or is_xml):
        raise InventoryValidationError("SBOM file type is not supported")
    context = {
        "engagement_id": engagement_id,
        "host": host,
        "service": service,
        "criticality": criticality,
        "internet_exposed": internet_exposed,
        "observed_at": observed_at,
        "source_name": name,
    }
    if is_xml:
        return _parse_cyclonedx_xml(data, context)
    try:
        root = json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except InventoryValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InventoryValidationError("SBOM JSON is invalid") from exc
    _validate_json_shape(root)
    if not isinstance(root, Mapping):
        raise InventoryValidationError("SBOM JSON root must be an object")
    if root.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx_json(root, context)
    if str(root.get("spdxVersion") or "").startswith("SPDX-2."):
        return _parse_spdx_json(root, context)
    raise InventoryValidationError("SBOM JSON format is not supported")


def _safe_identifier_field(value: Any, kind: str, warnings: List[str]) -> str:
    try:
        return _validate_purl(value) if kind == "purl" else _validate_cpe(value)
    except InventoryValidationError:
        warnings.append("Ignored an invalid %s identifier" % kind.upper())
        return ""


def _component_record(
    row: Mapping[str, Any], context: Mapping[str, Any], source: str,
    warnings: List[str], path: str,
) -> Optional[InventoryRecord]:
    name = _text(row.get("name"), 512)
    if not name:
        warnings.append("Skipped a component without a name")
        return None
    group = _text(row.get("group"), 256)
    product = "%s:%s" % (group, name) if group else name
    purl = _safe_identifier_field(row.get("purl"), "purl", warnings)
    cpe = _safe_identifier_field(row.get("cpe"), "cpe", warnings)
    evidence = [
        "%s component path %s" % (source, path),
        "bom-ref=%s" % _text(row.get("bom-ref"), 256) if row.get("bom-ref") else "",
        "type=%s" % _text(row.get("type"), 64) if row.get("type") else "",
    ]
    supplier = row.get("supplier")
    if isinstance(supplier, Mapping) and supplier.get("name"):
        evidence.append("supplier=%s" % _text(supplier.get("name"), 256))
    confidence = 0.9 if purl or cpe else 0.75 if row.get("version") else 0.6
    return create_inventory_record(
        engagement_id=context["engagement_id"],
        host=context["host"],
        service=context["service"],
        product=product,
        version=row.get("version"),
        cpe=cpe,
        purl=purl,
        evidence=evidence,
        confidence=confidence,
        observed_at=context["observed_at"],
        criticality=context["criticality"],
        internet_exposed=context["internet_exposed"],
        source=source,
    )


def _cyclonedx_component_rows(root: Mapping[str, Any]) -> Iterable[Tuple[Mapping[str, Any], str]]:
    pending: List[Tuple[Any, str]] = []
    metadata = root.get("metadata")
    if isinstance(metadata, Mapping) and isinstance(metadata.get("component"), Mapping):
        pending.append((metadata["component"], "metadata.component"))
    for index, row in enumerate(root.get("components") or ()):
        pending.append((row, "components[%d]" % index))
    seen = 0
    while pending:
        row, path = pending.pop()
        if not isinstance(row, Mapping):
            continue
        seen += 1
        if seen > MAX_COMPONENTS:
            raise InventoryValidationError("CycloneDX component count exceeds the limit")
        yield row, path
        children = row.get("components")
        if isinstance(children, list):
            for index, child in enumerate(children):
                pending.append((child, "%s.components[%d]" % (path, index)))


def _parse_cyclonedx_json(
    root: Mapping[str, Any], context: Mapping[str, Any]
) -> InventoryImportResult:
    version = _text(root.get("specVersion"), 16)
    if not re.fullmatch(r"1\.[0-9]+", version):
        raise InventoryValidationError("CycloneDX specification version is invalid")
    warnings: List[str] = []
    records: List[InventoryRecord] = []
    for row, path in _cyclonedx_component_rows(root):
        record = _component_record(row, context, "cyclonedx_json", warnings, path)
        if record:
            records.append(record)
    services = root.get("services") if isinstance(root.get("services"), list) else ()
    for index, service_row in enumerate(services):
        if not isinstance(service_row, Mapping):
            continue
        row = dict(service_row)
        row.setdefault("type", "service")
        service_context = dict(context)
        endpoints = service_row.get("endpoints")
        if isinstance(endpoints, list) and endpoints:
            service_context["service"] = _text(endpoints[0], 512)
        elif service_row.get("name"):
            service_context["service"] = _text(service_row.get("name"), 512)
        record = _component_record(
            row, service_context, "cyclonedx_json", warnings, "services[%d]" % index
        )
        if record:
            records.append(record)
    return InventoryImportResult(
        format="cyclonedx_json",
        source_name=context["source_name"],
        records=tuple(merge_inventory_records(records)),
        warnings=_unique(warnings, 100, 512),
    )


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_child_text(element: ET.Element, name: str) -> str:
    for child in list(element):
        if _xml_local(child.tag) == name:
            return _text(child.text, 2048)
    return ""


def _validate_xml_shape(root: ET.Element) -> None:
    pending = [(root, 0)]
    count = 0
    while pending:
        element, depth = pending.pop()
        count += 1
        if depth > MAX_XML_DEPTH:
            raise InventoryValidationError("SBOM XML exceeds the nesting limit")
        if count > MAX_XML_ELEMENTS:
            raise InventoryValidationError("SBOM XML exceeds the element limit")
        pending.extend((child, depth + 1) for child in list(element))


def _xml_component_mapping(element: ET.Element) -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "bom-ref": element.attrib.get("bom-ref", ""),
        "type": element.attrib.get("type", ""),
    }
    for name in ("group", "name", "version", "cpe", "purl"):
        value[name] = _xml_child_text(element, name)
    supplier = next(
        (child for child in list(element) if _xml_local(child.tag) == "supplier"), None
    )
    if supplier is not None:
        value["supplier"] = {"name": _xml_child_text(supplier, "name")}
    return value


def _parse_cyclonedx_xml(
    data: bytes, context: Mapping[str, Any]
) -> InventoryImportResult:
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise InventoryValidationError("CycloneDX XML DTD/entity declarations are not allowed")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, RecursionError) as exc:
        raise InventoryValidationError("CycloneDX XML is invalid") from exc
    if _xml_local(root.tag) != "bom" or "cyclonedx.org/schema/bom" not in root.tag:
        raise InventoryValidationError("XML is not a CycloneDX BOM")
    _validate_xml_shape(root)
    warnings: List[str] = []
    records: List[InventoryRecord] = []
    count = 0
    for element in root.iter():
        local = _xml_local(element.tag)
        if local not in {"component", "service"}:
            continue
        # Nested identity/evidence components are still components, but elements
        # without a direct name are skipped by the canonical record builder.
        count += 1
        if count > MAX_COMPONENTS:
            raise InventoryValidationError("CycloneDX component count exceeds the limit")
        row = _xml_component_mapping(element)
        item_context = dict(context)
        if local == "service":
            item_context["service"] = row.get("name") or context["service"]
            row["type"] = "service"
        record = _component_record(
            row, item_context, "cyclonedx_xml", warnings, "%s[%d]" % (local, count - 1)
        )
        if record:
            records.append(record)
    return InventoryImportResult(
        format="cyclonedx_xml",
        source_name=context["source_name"],
        records=tuple(merge_inventory_records(records)),
        warnings=_unique(warnings, 100, 512),
    )


def _parse_spdx_json(
    root: Mapping[str, Any], context: Mapping[str, Any]
) -> InventoryImportResult:
    packages = root.get("packages")
    if not isinstance(packages, list):
        raise InventoryValidationError("SPDX packages array is required")
    if len(packages) > MAX_COMPONENTS:
        raise InventoryValidationError("SPDX package count exceeds the limit")
    warnings: List[str] = []
    records: List[InventoryRecord] = []
    for index, package in enumerate(packages):
        if not isinstance(package, Mapping):
            continue
        purl = ""
        cpe = ""
        for external in package.get("externalRefs") or ():
            if not isinstance(external, Mapping):
                continue
            kind = _text(external.get("referenceType"), 64).casefold()
            locator = external.get("referenceLocator")
            if kind == "purl" and not purl:
                purl = _safe_identifier_field(locator, "purl", warnings)
            elif kind in {"cpe22type", "cpe23type"} and not cpe:
                cpe = _safe_identifier_field(locator, "cpe", warnings)
        if not purl and package.get("packageUrl"):
            purl = _safe_identifier_field(package.get("packageUrl"), "purl", warnings)
        name = _text(package.get("name"), 512)
        if not name:
            warnings.append("Skipped an SPDX package without a name")
            continue
        evidence = [
            "SPDX package index %d" % index,
            "SPDXID=%s" % _text(package.get("SPDXID"), 256)
            if package.get("SPDXID") else "",
            "supplier=%s" % _text(package.get("supplier"), 256)
            if package.get("supplier") else "",
        ]
        records.append(create_inventory_record(
            engagement_id=context["engagement_id"],
            host=context["host"],
            service=context["service"],
            product=name,
            version=package.get("versionInfo"),
            cpe=cpe,
            purl=purl,
            evidence=evidence,
            confidence=0.9 if purl or cpe else 0.75 if package.get("versionInfo") else 0.6,
            observed_at=context["observed_at"],
            criticality=context["criticality"],
            internet_exposed=context["internet_exposed"],
            source="spdx_json",
        ))
    return InventoryImportResult(
        format="spdx_json",
        source_name=context["source_name"],
        records=tuple(merge_inventory_records(records)),
        warnings=_unique(warnings, 100, 512),
    )


def _semver_parts(value: str) -> Tuple[int, int, int, Tuple[str, ...]]:
    match = _SEMVER_RE.fullmatch(str(value or ""))
    if not match:
        raise InventoryValidationError("version is not valid SemVer 2.0")
    pre = tuple(match.group(4).split(".")) if match.group(4) else ()
    for item in pre:
        if item.isdigit() and len(item) > 1 and item.startswith("0"):
            raise InventoryValidationError("numeric SemVer prerelease identifiers cannot lead with zero")
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), pre


def compare_semver(left: str, right: str) -> int:
    """Compare strict SemVer 2.0 values, ignoring build metadata."""
    left_parts = _semver_parts(left)
    right_parts = _semver_parts(right)
    if left_parts[:3] != right_parts[:3]:
        return -1 if left_parts[:3] < right_parts[:3] else 1
    left_pre, right_pre = left_parts[3], right_parts[3]
    if not left_pre and not right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        left_numeric, right_numeric = left_item.isdigit(), right_item.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_item) < int(right_item) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_item < right_item else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1


def _boundary_compare(version: str, boundary: str, comparator: VersionComparator) -> int:
    if boundary == "0":
        return 1
    if "*" in boundary:
        return -1
    return comparator(version, boundary)


def osv_range_contains(
    version: str,
    range_data: Mapping[str, Any],
    *,
    comparator: Optional[VersionComparator] = None,
) -> Optional[bool]:
    """Evaluate one OSV range exactly, or return ``None`` when ordering is unknown."""
    clean_version = _text(version, 256)
    if not clean_version:
        return None
    range_type = _text(range_data.get("type"), 32).upper()
    if range_type == "SEMVER":
        compare = compare_semver
        _semver_parts(clean_version)
    elif range_type == "ECOSYSTEM" and comparator is not None:
        compare = comparator
    else:
        # GIT ordering requires repository topology; ECOSYSTEM ordering is
        # ecosystem-specific and must be explicitly supplied by the caller.
        return None
    events = range_data.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 256:
        raise InventoryValidationError("OSV range events are invalid")
    normalized: List[Tuple[str, str]] = []
    has_introduced = False
    terminal_kinds = set()
    for event in events:
        if not isinstance(event, Mapping):
            raise InventoryValidationError("OSV range event is invalid")
        present = [key for key in ("introduced", "fixed", "last_affected", "limit") if key in event]
        if len(present) != 1:
            raise InventoryValidationError("OSV range events must contain exactly one boundary")
        kind = present[0]
        boundary = _text(event.get(kind), 256)
        if not boundary:
            raise InventoryValidationError("OSV range boundary is empty")
        if kind == "introduced":
            has_introduced = True
        if kind in {"fixed", "last_affected"}:
            terminal_kinds.add(kind)
        normalized.append((kind, boundary))
    if not has_introduced or terminal_kinds == {"fixed", "last_affected"}:
        raise InventoryValidationError("OSV range event sequence is invalid")
    limits = [boundary for kind, boundary in normalized if kind == "limit"]
    if limits and not any(
        "*" in boundary or _boundary_compare(clean_version, boundary, compare) < 0
        for boundary in limits
    ):
        return False

    priority = {"introduced": 0, "last_affected": 1, "fixed": 2}
    status_events = [(kind, value) for kind, value in normalized if kind != "limit"]

    def event_compare(left: Tuple[str, str], right: Tuple[str, str]) -> int:
        if left[1] == right[1]:
            return priority[left[0]] - priority[right[0]]
        if left[1] == "0":
            return -1
        if right[1] == "0":
            return 1
        return compare(left[1], right[1])

    status_events.sort(key=cmp_to_key(event_compare))
    vulnerable = False
    for kind, boundary in status_events:
        comparison = _boundary_compare(clean_version, boundary, compare)
        if kind == "introduced" and comparison >= 0:
            vulnerable = True
        elif kind == "fixed" and comparison >= 0:
            vulnerable = False
        elif kind == "last_affected" and comparison > 0:
            vulnerable = False
    return vulnerable


def osv_affected_contains(
    version: str,
    affected: Mapping[str, Any],
    *,
    comparator: Optional[VersionComparator] = None,
) -> Optional[bool]:
    """Evaluate OSV ``affected.versions`` and ``affected.ranges`` semantics."""
    clean_version = _text(version, 256)
    if not clean_version:
        return None
    versions = affected.get("versions")
    if isinstance(versions, list) and any(clean_version == str(item) for item in versions):
        return True
    ranges = affected.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        return False if isinstance(versions, list) and versions else None
    if len(ranges) > 100:
        raise InventoryValidationError("OSV affected range count exceeds the limit")
    unknown = False
    for range_data in ranges:
        if not isinstance(range_data, Mapping):
            raise InventoryValidationError("OSV affected range is invalid")
        result = osv_range_contains(clean_version, range_data, comparator=comparator)
        if result is True:
            return True
        if result is None:
            unknown = True
    return None if unknown else False


def _normalize_name(value: Any) -> str:
    return " ".join(re.findall(r"[a-z0-9][a-z0-9.+_-]*", _text(value, 512).casefold()))


def _affected_identity(
    record: InventoryRecord, affected: Mapping[str, Any]
) -> Tuple[str, Tuple[str, ...]]:
    package = affected.get("package") if isinstance(affected.get("package"), Mapping) else {}
    package_purl = _text(package.get("purl"), 2048)
    if record.purl and package_purl:
        try:
            if purl_identity(record.purl) == purl_identity(package_purl):
                return "purl", ("PURL package identities match exactly",)
        except InventoryValidationError:
            pass
    affected_cpes: List[str] = []
    if affected.get("cpe"):
        affected_cpes.append(str(affected.get("cpe")))
    if isinstance(affected.get("cpes"), list):
        affected_cpes.extend(str(item) for item in affected.get("cpes") or ())
    if record.cpe:
        for cpe in affected_cpes:
            try:
                if cpe_identity(record.cpe) == cpe_identity(cpe):
                    return "cpe", ("CPE part/vendor/product identities match",)
            except InventoryValidationError:
                continue
    package_name = _normalize_name(package.get("name"))
    record_name = _normalize_name(record.product)
    package_ecosystem = _normalize_name(package.get("ecosystem"))
    record_ecosystem = _normalize_name(record.ecosystem)
    if package_name and record_name:
        name_matches = package_name == record_name or record_name.endswith(" " + package_name)
        ecosystem_matches = not package_ecosystem or package_ecosystem == record_ecosystem
        if name_matches and ecosystem_matches:
            return "name_ecosystem", ("Package name and ecosystem match",)
    product = _normalize_name(affected.get("product"))
    if product and product == record_name:
        return "product", ("Product names match but no strong package identifier is available",)
    return "none", ("Package identifiers do not match this inventory record",)


def classify_affected_package(
    record: InventoryRecord,
    affected: Mapping[str, Any],
    *,
    advisory_id: Any = "",
    comparator: Optional[VersionComparator] = None,
) -> InventoryAdvisoryMatch:
    """Classify one OSV-style affected package with explicit, conservative reasons."""
    identity, reasons = _affected_identity(record, affected)
    advisory = _text(advisory_id, 128)
    if identity == "none":
        return InventoryAdvisoryMatch(
            record.record_id, advisory, "not_affected", identity, "not_evaluated", 0.0, reasons
        )
    package = affected.get("package") if isinstance(affected.get("package"), Mapping) else {}
    package_purl = _text(package.get("purl"), 2048)
    if package_purl and record.purl:
        try:
            declared_version = purl_version(package_purl)
            if declared_version:
                affected_result: Optional[bool] = declared_version == record.version
            else:
                affected_result = osv_affected_contains(
                    record.version, affected, comparator=comparator
                )
        except InventoryValidationError:
            affected_result = None
    else:
        affected_result = osv_affected_contains(record.version, affected, comparator=comparator)
    if affected_result is False:
        return InventoryAdvisoryMatch(
            record.record_id,
            advisory,
            "not_affected",
            identity,
            "not_affected",
            1.0,
            reasons + ("The observed version is outside the advisory's affected versions/ranges",),
        )
    if affected_result is None:
        return InventoryAdvisoryMatch(
            record.record_id,
            advisory,
            "possible",
            identity,
            "unknown",
            min(record.confidence, 0.55),
            reasons + ("Version applicability could not be evaluated without guessing",),
        )
    if identity in {"purl", "cpe"}:
        classification, confidence = "exact", min(record.confidence, 1.0)
    elif identity == "name_ecosystem":
        classification, confidence = "likely", min(record.confidence, 0.85)
    else:
        classification, confidence = "possible", min(record.confidence, 0.6)
    return InventoryAdvisoryMatch(
        record.record_id,
        advisory,
        classification,
        identity,
        "affected",
        confidence,
        reasons + ("The observed version is included by the advisory data",),
    )


def classify_osv_advisory(
    record: InventoryRecord,
    advisory: Mapping[str, Any],
    *,
    comparator: Optional[VersionComparator] = None,
) -> InventoryAdvisoryMatch:
    advisory_id = _text(advisory.get("id"), 128)
    affected_rows = advisory.get("affected")
    if not isinstance(affected_rows, list) or not affected_rows:
        return InventoryAdvisoryMatch(
            record.record_id, advisory_id, "possible", "none", "unknown", 0.25,
            ("Advisory has no structured affected-package data",),
        )
    results = [
        classify_affected_package(
            record, affected, advisory_id=advisory_id, comparator=comparator
        )
        for affected in affected_rows[:100]
        if isinstance(affected, Mapping)
    ]
    if not results:
        return InventoryAdvisoryMatch(
            record.record_id, advisory_id, "possible", "none", "unknown", 0.25,
            ("Advisory affected-package data is malformed or empty",),
        )
    return max(results, key=lambda item: _CLASSIFICATION_ORDER[item.classification])


def _validate_mitigation(value: Mitigation) -> Mitigation:
    mitigation_id = _identifier(value.mitigation_id, "mitigation id")
    description = _text(value.description, 1024)
    if not description:
        raise InventoryValidationError("mitigation description is required")
    try:
        effectiveness = float(value.effectiveness)
    except (TypeError, ValueError, OverflowError) as exc:
        raise InventoryValidationError("mitigation effectiveness is invalid") from exc
    if not 0.0 <= effectiveness <= 1.0:
        raise InventoryValidationError("mitigation effectiveness must be between 0 and 1")
    expiry = _optional_timestamp(value.expires_at, "mitigation expiry")
    return Mitigation(mitigation_id, description, effectiveness, bool(value.verified), expiry)


def mitigation_from_dict(value: Mapping[str, Any]) -> Mitigation:
    """Revalidate one persisted or UI-provided mitigation mapping."""
    return _validate_mitigation(Mitigation(
        mitigation_id=str(value.get("mitigation_id") or ""),
        description=str(value.get("description") or ""),
        effectiveness=value.get("effectiveness", 0.0),
        verified=bool(value.get("verified")),
        expires_at=str(value.get("expires_at") or ""),
    ))


def score_risk(
    *,
    known_exploited: bool,
    epss_score: Optional[float],
    internet_exposed: bool,
    criticality: str,
    confidence: Any,
    mitigations: Iterable[Mitigation] = (),
    now: Optional[Any] = None,
) -> RiskAssessment:
    """Return a transparent 0-100 prioritization score, not exploitability proof."""
    critical = _text(criticality, 32).lower()
    if critical not in _CRITICALITY:
        raise InventoryValidationError("criticality is invalid")
    if isinstance(confidence, str):
        confidence_value = {"exact": 1.0, "likely": 0.8, "possible": 0.5,
                            "not_affected": 0.0}.get(confidence.lower())
        if confidence_value is None:
            raise InventoryValidationError("match confidence is invalid")
    else:
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError, OverflowError) as exc:
            raise InventoryValidationError("match confidence is invalid") from exc
        if not 0.0 <= confidence_value <= 1.0:
            raise InventoryValidationError("match confidence must be between 0 and 1")
    if epss_score is None:
        epss = 0.0
    else:
        try:
            epss = float(epss_score)
        except (TypeError, ValueError, OverflowError) as exc:
            raise InventoryValidationError("EPSS score is invalid") from exc
        if not 0.0 <= epss <= 1.0:
            raise InventoryValidationError("EPSS score must be between 0 and 1")
    contributions: Dict[str, float] = {
        "known_exploited": 35.0 if known_exploited else 0.0,
        "epss": round(30.0 * epss, 2),
        "internet_exposure": 15.0 if internet_exposed else 0.0,
        "criticality": (0.0, 5.0, 10.0, 15.0)[_CRITICALITY[critical]],
    }
    subtotal = sum(contributions.values())
    confidence_factor = 0.0 if confidence_value == 0.0 else 0.55 + (0.45 * confidence_value)
    contributions["confidence_adjustment"] = round(subtotal * confidence_factor - subtotal, 2)
    adjusted = subtotal * confidence_factor
    current = _parse_timestamp(_now(now), "current time")
    remaining = 1.0
    applied: List[str] = []
    for mitigation in islice(mitigations, 50):
        checked = _validate_mitigation(mitigation)
        active = not checked.expires_at or _parse_timestamp(
            checked.expires_at, "mitigation expiry"
        ) > current
        if checked.verified and active:
            remaining *= 1.0 - checked.effectiveness
            applied.append(checked.description)
    reduction = min(40.0, 40.0 * (1.0 - remaining))
    contributions["verified_mitigations"] = round(-reduction, 2)
    final = max(0, min(100, int(round(adjusted - reduction))))
    rating = "critical" if final >= 85 else "high" if final >= 65 else "medium" if final >= 40 else "low"
    explanations = [
        "Known-exploited status contributed %g points" % contributions["known_exploited"],
        "EPSS contributed %g points" % contributions["epss"],
        "Internet exposure contributed %g points" % contributions["internet_exposure"],
        "Asset criticality contributed %g points" % contributions["criticality"],
        "Match confidence adjusted the subtotal by %g points"
        % contributions["confidence_adjustment"],
    ]
    if applied:
        explanations.append(
            "Verified active mitigations reduced the score by %g points: %s"
            % (reduction, "; ".join(applied))
        )
    else:
        explanations.append("No verified active mitigation reduced the score")
    return RiskAssessment(final, rating, contributions, tuple(explanations))


_TRANSITIONS = {
    RemediationStatus.OPEN.value: {
        RemediationStatus.FIXING.value, RemediationStatus.ACCEPTED.value,
    },
    RemediationStatus.FIXING.value: {
        RemediationStatus.OPEN.value, RemediationStatus.RETEST.value,
        RemediationStatus.ACCEPTED.value,
    },
    RemediationStatus.RETEST.value: {
        RemediationStatus.FIXING.value, RemediationStatus.RESOLVED.value,
        RemediationStatus.OPEN.value, RemediationStatus.ACCEPTED.value,
    },
    RemediationStatus.RESOLVED.value: {
        RemediationStatus.OPEN.value, RemediationStatus.RETEST.value,
    },
    RemediationStatus.ACCEPTED.value: {
        RemediationStatus.OPEN.value, RemediationStatus.FIXING.value,
    },
}


def create_remediation(
    *,
    engagement_id: Any,
    record_id: Any,
    advisory_id: Any,
    owner: Any = "",
    sla_due: Any = "",
    at: Optional[Any] = None,
) -> RemediationItem:
    engagement = _identifier(engagement_id, "engagement id")
    record = _identifier(record_id, "record id")
    advisory = _identifier(advisory_id, "advisory id")
    timestamp = _now(at)
    return RemediationItem(
        remediation_id=_stable_id("remediation", engagement, record, advisory),
        engagement_id=engagement,
        record_id=record,
        advisory_id=advisory,
        status=RemediationStatus.OPEN.value,
        owner=_text(owner, 256),
        sla_due=_optional_timestamp(sla_due, "SLA due"),
        created_at=timestamp,
        updated_at=timestamp,
    )


def transition_remediation(
    item: RemediationItem,
    new_status: Any,
    *,
    owner: Optional[Any] = None,
    sla_due: Optional[Any] = None,
    exception_expiry: Optional[Any] = None,
    note: Any = "",
    at: Optional[Any] = None,
) -> RemediationItem:
    """Apply an allowed lifecycle transition and append immutable history."""
    try:
        status = (
            new_status.value
            if isinstance(new_status, RemediationStatus)
            else RemediationStatus(str(new_status)).value
        )
    except ValueError as exc:
        raise InventoryValidationError("remediation status is invalid") from exc
    if status not in _TRANSITIONS.get(item.status, set()):
        raise InventoryValidationError(
            "remediation transition %s -> %s is not allowed" % (item.status, status)
        )
    timestamp = _now(at)
    clean_owner = _text(owner, 256) if owner is not None else item.owner
    clean_sla = (
        _optional_timestamp(sla_due, "SLA due") if sla_due is not None else item.sla_due
    )
    clean_expiry = (
        _optional_timestamp(exception_expiry, "exception expiry")
        if exception_expiry is not None else item.exception_expiry
    )
    if status in {
        RemediationStatus.FIXING.value, RemediationStatus.RETEST.value,
        RemediationStatus.RESOLVED.value, RemediationStatus.ACCEPTED.value,
    } and not clean_owner:
        raise InventoryValidationError("an owner is required for this remediation status")
    if status == RemediationStatus.ACCEPTED.value:
        if not clean_expiry:
            raise InventoryValidationError("Accepted risk requires an exception expiry")
        if _parse_timestamp(clean_expiry, "exception expiry") <= _parse_timestamp(
            timestamp, "transition time"
        ):
            raise InventoryValidationError("Accepted risk exception must expire in the future")
    elif item.status == RemediationStatus.ACCEPTED.value:
        clean_expiry = ""
    event = RemediationEvent(
        event_id=_stable_id("remediation-event", item.remediation_id, timestamp, status),
        from_status=item.status,
        to_status=status,
        at=timestamp,
        owner=clean_owner,
        note=_text(note, 2048),
    )
    return replace(
        item,
        status=status,
        owner=clean_owner,
        sla_due=clean_sla,
        exception_expiry=clean_expiry,
        updated_at=timestamp,
        history=tuple(list(item.history)[-199:] + [event]),
    )


def update_remediation(
    item: RemediationItem,
    *,
    owner: Optional[Any] = None,
    sla_due: Optional[Any] = None,
    exception_expiry: Optional[Any] = None,
    note: Any = "",
    at: Optional[Any] = None,
) -> RemediationItem:
    """Edit lifecycle metadata without attempting an illegal self-transition."""
    timestamp = _now(at)
    clean_owner = _text(owner, 256) if owner is not None else item.owner
    clean_sla = (
        _optional_timestamp(sla_due, "SLA due") if sla_due is not None else item.sla_due
    )
    clean_expiry = (
        _optional_timestamp(exception_expiry, "exception expiry")
        if exception_expiry is not None else item.exception_expiry
    )
    if item.status in {
        RemediationStatus.FIXING.value, RemediationStatus.RETEST.value,
        RemediationStatus.RESOLVED.value, RemediationStatus.ACCEPTED.value,
    } and not clean_owner:
        raise InventoryValidationError("an owner is required for this remediation status")
    if item.status == RemediationStatus.ACCEPTED.value:
        if not clean_expiry:
            raise InventoryValidationError("Accepted risk requires an exception expiry")
        if _parse_timestamp(clean_expiry, "exception expiry") <= _parse_timestamp(
            timestamp, "update time"
        ):
            raise InventoryValidationError("Accepted risk exception must expire in the future")
    event = RemediationEvent(
        event_id=_stable_id(
            "remediation-event", item.remediation_id, timestamp, item.status, "metadata"
        ),
        from_status=item.status,
        to_status=item.status,
        at=timestamp,
        owner=clean_owner,
        note=_text(note, 2048) or "Remediation metadata updated",
    )
    return replace(
        item,
        owner=clean_owner,
        sla_due=clean_sla,
        exception_expiry=clean_expiry,
        updated_at=timestamp,
        history=tuple(list(item.history)[-199:] + [event]),
    )


def add_mitigation(
    item: RemediationItem,
    mitigation: Mitigation,
    *,
    at: Optional[Any] = None,
) -> RemediationItem:
    """Add or replace one structured mitigation and append an audit event."""
    checked = _validate_mitigation(mitigation)
    values = {
        existing.mitigation_id: existing
        for existing in item.mitigations[:50]
    }
    if checked.mitigation_id not in values and len(values) >= 50:
        raise InventoryValidationError("remediation mitigation count exceeds the limit")
    values[checked.mitigation_id] = checked
    timestamp = _now(at)
    event = RemediationEvent(
        event_id=_stable_id(
            "remediation-event", item.remediation_id, timestamp,
            item.status, "mitigation-added", checked.mitigation_id,
        ),
        from_status=item.status,
        to_status=item.status,
        at=timestamp,
        owner=item.owner,
        note="Mitigation added or updated: %s" % checked.description,
    )
    return replace(
        item,
        mitigations=tuple(values[key] for key in sorted(values)),
        updated_at=timestamp,
        history=tuple(list(item.history)[-199:] + [event]),
    )


def remove_mitigation(
    item: RemediationItem,
    mitigation_id: Any,
    *,
    at: Optional[Any] = None,
) -> RemediationItem:
    """Remove one mitigation by id and append an audit event."""
    identifier = _identifier(mitigation_id, "mitigation id")
    removed = next(
        (value for value in item.mitigations if value.mitigation_id == identifier), None
    )
    if removed is None:
        raise InventoryValidationError("mitigation was not found")
    values = tuple(
        value for value in item.mitigations if value.mitigation_id != identifier
    )
    timestamp = _now(at)
    event = RemediationEvent(
        event_id=_stable_id(
            "remediation-event", item.remediation_id, timestamp,
            item.status, "mitigation-removed", identifier,
        ),
        from_status=item.status,
        to_status=item.status,
        at=timestamp,
        owner=item.owner,
        note="Mitigation removed: %s" % removed.description,
    )
    return replace(
        item,
        mitigations=values,
        updated_at=timestamp,
        history=tuple(list(item.history)[-199:] + [event]),
    )


def exception_expired(item: RemediationItem, now: Optional[Any] = None) -> bool:
    return (
        item.status == RemediationStatus.ACCEPTED.value
        and bool(item.exception_expiry)
        and _parse_timestamp(item.exception_expiry, "exception expiry")
        <= _parse_timestamp(_now(now), "current time")
    )


def sla_state(item: RemediationItem, now: Optional[Any] = None) -> str:
    if item.status in {RemediationStatus.RESOLVED.value, RemediationStatus.ACCEPTED.value}:
        return "not_applicable"
    if not item.sla_due:
        return "unset"
    return (
        "overdue"
        if _parse_timestamp(item.sla_due, "SLA due") < _parse_timestamp(_now(now), "current time")
        else "on_track"
    )


def remediation_from_dict(value: Mapping[str, Any]) -> RemediationItem:
    base = create_remediation(
        engagement_id=value.get("engagement_id"),
        record_id=value.get("record_id"),
        advisory_id=value.get("advisory_id"),
        owner=value.get("owner"),
        sla_due=value.get("sla_due"),
        at=value.get("created_at"),
    )
    status = str(value.get("status") or RemediationStatus.OPEN.value)
    valid_statuses = {item.value for item in RemediationStatus}
    if status not in valid_statuses:
        raise InventoryValidationError("remediation status is invalid")
    history: List[RemediationEvent] = []
    for row in list(value.get("history") or ())[-200:]:
        if not isinstance(row, Mapping):
            continue
        from_status = str(row.get("from_status") or "")
        to_status = str(row.get("to_status") or "")
        if from_status not in valid_statuses or to_status not in valid_statuses:
            raise InventoryValidationError("remediation history status is invalid")
        history.append(RemediationEvent(
            event_id=_identifier(row.get("event_id"), "remediation event id"),
            from_status=from_status,
            to_status=to_status,
            at=_optional_timestamp(row.get("at"), "remediation event time"),
            owner=_text(row.get("owner"), 256),
            note=_text(row.get("note"), 2048),
        ))
    mitigations: List[Mitigation] = []
    for row in list(value.get("mitigations") or ())[:50]:
        if isinstance(row, Mapping):
            mitigations.append(mitigation_from_dict(row))
    if len({item.mitigation_id for item in mitigations}) != len(mitigations):
        raise InventoryValidationError("remediation contains duplicate mitigation ids")
    expiry = _optional_timestamp(value.get("exception_expiry"), "exception expiry")
    if status in {
        RemediationStatus.FIXING.value,
        RemediationStatus.RETEST.value,
        RemediationStatus.RESOLVED.value,
        RemediationStatus.ACCEPTED.value,
    } and not base.owner:
        raise InventoryValidationError(
            "an owner is required for this remediation status"
        )
    if status == RemediationStatus.ACCEPTED.value:
        if not expiry:
            raise InventoryValidationError("Accepted risk requires an exception expiry")
    return replace(
        base,
        remediation_id=_identifier(value.get("remediation_id"), "remediation id"),
        status=status,
        exception_expiry=expiry,
        updated_at=_optional_timestamp(value.get("updated_at"), "remediation updated time"),
        mitigations=tuple(mitigations),
        history=tuple(history),
    )


def diff_inventory(
    previous: InventorySnapshot,
    current: InventorySnapshot,
    *,
    at: Optional[Any] = None,
) -> InventoryDiff:
    """Return software and host change events without treating last-seen as a change."""
    if previous.engagement_id != current.engagement_id:
        raise InventoryValidationError("inventory snapshots belong to different engagements")
    engagement = _identifier(current.engagement_id, "engagement id")
    before = {row.record_id: row for row in previous.records}
    after = {row.record_id: row for row in current.records}
    added = tuple(after[key] for key in sorted(set(after) - set(before)))
    removed = tuple(before[key] for key in sorted(set(before) - set(after)))
    changed: List[RecordChange] = []
    for key in sorted(set(before) & set(after)):
        fields = tuple(
            field_name for field_name in _MATERIAL_FIELDS
            if getattr(before[key], field_name) != getattr(after[key], field_name)
        )
        if fields:
            changed.append(RecordChange(key, fields, before[key], after[key]))
    timestamp = _now(at)
    events: List[InventoryChangeEvent] = []
    before_hosts = {row.host for row in previous.records if row.host}
    after_hosts = {row.host for row in current.records if row.host}
    for host in sorted(after_hosts - before_hosts):
        events.append(_change_event(engagement, "asset_added", timestamp, host=host))
    for host in sorted(before_hosts - after_hosts):
        events.append(_change_event(engagement, "asset_removed", timestamp, host=host))
    for row in added:
        events.append(_change_event(
            engagement, "software_added", timestamp, record_id=row.record_id, host=row.host
        ))
    for row in removed:
        events.append(_change_event(
            engagement, "software_removed", timestamp, record_id=row.record_id, host=row.host
        ))
    for change in changed:
        events.append(_change_event(
            engagement,
            "software_changed",
            timestamp,
            record_id=change.record_id,
            host=change.after.host,
            fields=change.fields,
        ))
    return InventoryDiff(engagement, added, removed, tuple(changed), tuple(events))


def _change_event(
    engagement_id: str, event_type: str, at: str, *, record_id: str = "",
    host: str = "", fields: Tuple[str, ...] = (),
) -> InventoryChangeEvent:
    return InventoryChangeEvent(
        event_id=_stable_id(
            "inventory-event", engagement_id, event_type, at, record_id, host, fields
        ),
        engagement_id=engagement_id,
        event_type=event_type,
        at=at,
        record_id=record_id,
        host=host,
        changed_fields=fields,
    )


def _event_from_dict(value: Mapping[str, Any]) -> InventoryChangeEvent:
    return InventoryChangeEvent(
        event_id=_identifier(value.get("event_id"), "change event id"),
        engagement_id=_identifier(value.get("engagement_id"), "engagement id"),
        event_type=_text(value.get("event_type"), 64),
        at=_optional_timestamp(value.get("at"), "change event time"),
        record_id=_text(value.get("record_id"), 128),
        host=_text(value.get("host"), 512),
        changed_fields=_unique(value.get("changed_fields") or (), 50, 64),
    )


def _bounded_json(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        raise InventoryValidationError("inventory state exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise InventoryValidationError("inventory state contains a non-finite number")
        return value
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, Mapping):
        if len(value) > 500:
            raise InventoryValidationError("inventory state mapping is too large")
        return {
            _text(key, 128): _bounded_json(child, depth + 1)
            for key, child in value.items() if _text(key, 128)
        }
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CHANGE_EVENTS:
            raise InventoryValidationError("inventory state sequence is too large")
        return [_bounded_json(child, depth + 1) for child in value]
    raise InventoryValidationError("inventory state contains an unsupported value")


def save_inventory_state(path: str, state: InventoryState) -> None:
    """Atomically persist private, engagement-scoped inventory state."""
    engagement = _identifier(state.engagement_id, "engagement id")
    if state.snapshot.engagement_id != engagement:
        raise InventoryValidationError("snapshot crosses the inventory engagement boundary")
    records = [
        record_from_dict(asdict(row))
        for row in islice(state.snapshot.records, MAX_COMPONENTS)
    ]
    remediations = [
        remediation_from_dict(asdict(row))
        for row in islice(state.remediations, MAX_REMEDIATIONS)
    ]
    changes = [
        _event_from_dict(asdict(row))
        for row in islice(state.change_events, MAX_CHANGE_EVENTS)
    ]
    if any(row.engagement_id != engagement for row in records):
        raise InventoryValidationError("inventory record crosses engagement scope")
    if any(row.engagement_id != engagement for row in remediations):
        raise InventoryValidationError("remediation crosses engagement scope")
    if any(row.engagement_id != engagement for row in changes):
        raise InventoryValidationError("change event crosses engagement scope")
    payload = _bounded_json({
        "version": INVENTORY_STATE_VERSION,
        "engagement_id": engagement,
        "saved_at": _now(state.saved_at or None),
        "snapshot": {
            "engagement_id": engagement,
            "observed_at": _optional_timestamp(
                state.snapshot.observed_at, "snapshot observation time"
            ),
            "records": [asdict(row) for row in records],
        },
        "remediations": [asdict(row) for row in remediations],
        "change_events": [asdict(row) for row in changes],
    })
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise InventoryValidationError("inventory state exceeds the size limit")
    absolute = os.path.abspath(path)
    os.makedirs(os.path.dirname(absolute), exist_ok=True)
    temporary = absolute + ".tmp"
    prepare_private_file(temporary)
    try:
        Path(temporary).write_bytes(encoded)
        prepare_private_file(temporary)
        os.replace(temporary, absolute)
        prepare_private_file(absolute)
    finally:
        if os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass


def load_inventory_state(
    path: str, *, expected_engagement_id: Optional[Any] = None
) -> InventoryState:
    """Load and revalidate private inventory state, optionally enforcing engagement scope."""
    try:
        size = os.path.getsize(path)
        if not 1 <= size <= MAX_STATE_BYTES:
            raise InventoryValidationError("inventory state size is outside the supported bounds")
        value = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except InventoryValidationError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise InventoryValidationError("inventory state could not be loaded") from exc
    _validate_json_shape(
        value,
        max_depth=12,
        max_nodes=500000,
        max_container_items=MAX_CHANGE_EVENTS,
    )
    if not isinstance(value, Mapping) or value.get("version") != INVENTORY_STATE_VERSION:
        raise InventoryValidationError("inventory state version is not supported")
    engagement = _identifier(value.get("engagement_id"), "engagement id")
    if expected_engagement_id is not None and engagement != _identifier(
        expected_engagement_id, "expected engagement id"
    ):
        raise InventoryValidationError("inventory state belongs to a different engagement")
    snapshot_row = value.get("snapshot")
    if not isinstance(snapshot_row, Mapping) or snapshot_row.get("engagement_id") != engagement:
        raise InventoryValidationError("inventory snapshot engagement is invalid")
    records: List[InventoryRecord] = []
    for row in list(snapshot_row.get("records") or ())[:MAX_COMPONENTS]:
        if isinstance(row, Mapping):
            record = record_from_dict(row)
            if record.engagement_id != engagement:
                raise InventoryValidationError("inventory record crosses engagement scope")
            records.append(record)
    remediations: List[RemediationItem] = []
    for row in list(value.get("remediations") or ())[:MAX_REMEDIATIONS]:
        if isinstance(row, Mapping):
            item = remediation_from_dict(row)
            if item.engagement_id != engagement:
                raise InventoryValidationError("remediation crosses engagement scope")
            remediations.append(item)
    events: List[InventoryChangeEvent] = []
    for row in list(value.get("change_events") or ())[:MAX_CHANGE_EVENTS]:
        if isinstance(row, Mapping):
            event = _event_from_dict(row)
            if event.engagement_id != engagement:
                raise InventoryValidationError("change event crosses engagement scope")
            events.append(event)
    snapshot = InventorySnapshot(
        engagement_id=engagement,
        observed_at=_optional_timestamp(snapshot_row.get("observed_at"), "snapshot time"),
        records=tuple(merge_inventory_records(records)),
    )
    return InventoryState(
        engagement_id=engagement,
        snapshot=snapshot,
        remediations=tuple(remediations),
        change_events=tuple(events),
        saved_at=_optional_timestamp(value.get("saved_at"), "state save time"),
    )


__all__ = [
    "InventoryAdvisoryMatch", "InventoryChangeEvent", "InventoryDiff",
    "InventoryImportResult", "InventoryRecord", "InventorySnapshot", "InventoryState",
    "InventoryValidationError", "Mitigation", "RecordChange", "RemediationEvent",
    "RemediationItem", "RemediationStatus", "RiskAssessment", "add_mitigation",
    "classify_affected_package", "classify_osv_advisory", "compare_semver",
    "create_inventory_record",
    "create_remediation", "cpe_identity", "diff_inventory", "exception_expired",
    "import_sbom", "load_inventory_state", "merge_inventory_records",
    "mitigation_from_dict",
    "osv_affected_contains", "osv_range_contains", "parse_sbom_bytes", "purl_ecosystem",
    "purl_identity", "purl_version", "record_from_dict", "save_inventory_state",
    "remove_mitigation", "score_risk", "sla_state", "transition_remediation",
    "update_remediation",
]
