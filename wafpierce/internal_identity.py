"""BloodHound normalization and lockout-aware credential-test planning."""
from __future__ import annotations

import io
import json
import os
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .pentest_models import Asset, GraphEdge, stable_id
from .pentest_workspace import PentestWorkspace


MAX_BLOODHOUND_INPUT_BYTES = 256 * 1024 * 1024
MAX_BLOODHOUND_FILES = 256
MAX_BLOODHOUND_OBJECTS = 2_000_000


class IdentityImportError(ValueError):
    pass


_TYPE_KIND = {
    "users": "identity-user",
    "user": "identity-user",
    "computers": "identity-computer",
    "computer": "identity-computer",
    "groups": "identity-group",
    "group": "identity-group",
    "domains": "identity-domain",
    "domain": "identity-domain",
    "ous": "identity-ou",
    "ou": "identity-ou",
    "gpos": "identity-gpo",
    "gpo": "identity-gpo",
    "containers": "identity-container",
    "azusers": "entra-user",
    "azgroups": "entra-group",
    "azserviceprincipals": "entra-service-principal",
    "aztenants": "entra-tenant",
    "azsubscriptions": "azure-subscription",
}


def _clean(value: Any, maximum: int = 4096) -> str:
    return str(value or "").replace("\x00", "").strip()[:maximum]


def _identifier(item: Mapping[str, Any]) -> str:
    props = item.get("Properties") if isinstance(item.get("Properties"), Mapping) else {}
    return _clean(
        item.get("ObjectIdentifier")
        or item.get("objectid")
        or item.get("id")
        or props.get("objectid")
        or props.get("name"),
        1024,
    )


def _public_properties(item: Mapping[str, Any]) -> Dict[str, Any]:
    props = item.get("Properties") if isinstance(item.get("Properties"), Mapping) else {}
    allowed = {
        "name", "domain", "domainsid", "distinguishedname", "description",
        "enabled", "highvalue", "admincount", "unconstraineddelegation",
        "trustedtoauth", "dontreqpreauth", "hasspn", "serviceprincipalnames",
        "operatingsystem", "lastlogon", "lastlogontimestamp", "whencreated",
        "tenantid", "subscriptionid", "objectid", "type",
    }
    result = {}
    for key, value in props.items():
        normalized = str(key).lower()
        if normalized not in allowed:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[normalized] = value
        elif isinstance(value, list):
            result[normalized] = [_clean(part, 1024) for part in value[:1000]]
    return result


def _asset_for_object(item: Mapping[str, Any], object_type: str) -> Optional[Asset]:
    object_id = _identifier(item)
    if not object_id:
        return None
    normalized_type = str(object_type or "unknown").replace("_", "").lower()
    kind = _TYPE_KIND.get(normalized_type, "identity-object")
    metadata = _public_properties(item)
    metadata["object_type"] = normalized_type
    return Asset(kind, object_id, "bloodhound", metadata=metadata)


def _object_ref(value: Any) -> Tuple[str, str]:
    if isinstance(value, Mapping):
        object_id = _clean(
            value.get("ObjectIdentifier") or value.get("ObjectId")
            or value.get("MemberId") or value.get("id"), 1024
        )
        object_type = _clean(
            value.get("ObjectType") or value.get("MemberType") or value.get("type"), 128
        )
        return object_id, object_type
    return "", ""


@dataclass
class IdentityImportResult:
    assets: List[Asset] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def persist(self, workspace: PentestWorkspace, workspace_id: str) -> Dict[str, int]:
        for asset in self.assets:
            workspace.save_asset(workspace_id, asset)
        for edge in self.edges:
            workspace.save_edge(workspace_id, edge)
        return {
            "assets": len(self.assets),
            "edges": len(self.edges),
            "warnings": len(self.warnings),
        }


def parse_bloodhound_documents(documents: Iterable[Mapping[str, Any]]) -> IdentityImportResult:
    result = IdentityImportResult()
    assets_by_object: Dict[str, Asset] = {}
    pending_edges: List[Tuple[str, str, str, Dict[str, Any]]] = []
    count = 0

    for document in documents:
        meta = document.get("meta") if isinstance(document.get("meta"), Mapping) else {}
        object_type = _clean(meta.get("type") or document.get("type"), 128).lower()
        rows = document.get("data")
        if not isinstance(rows, list):
            rows = document.get("nodes") if isinstance(document.get("nodes"), list) else []
        for item in rows:
            if not isinstance(item, Mapping):
                continue
            count += 1
            if count > MAX_BLOODHOUND_OBJECTS:
                raise IdentityImportError("BloodHound input contains too many objects")
            asset = _asset_for_object(item, object_type)
            if asset is None:
                continue
            object_id = asset.value
            assets_by_object[object_id] = asset

            for member in item.get("Members", []) if isinstance(item.get("Members"), list) else []:
                member_id, member_type = _object_ref(member)
                if member_id:
                    pending_edges.append((
                        member_id, object_id, "member_of",
                        {"member_type": member_type},
                    ))

            for ace in item.get("Aces", []) if isinstance(item.get("Aces"), list) else []:
                if not isinstance(ace, Mapping):
                    continue
                principal = _clean(
                    ace.get("PrincipalSID") or ace.get("PrincipalId")
                    or ace.get("ObjectIdentifier"), 1024
                )
                right = _clean(ace.get("RightName") or ace.get("right"), 128).lower()
                if principal and right:
                    relation = "acl_%s" % right.replace(" ", "_").replace("-", "_")
                    pending_edges.append((
                        principal, object_id, relation,
                        {"inherited": bool(ace.get("IsInherited", False))},
                    ))

            for relation_name, relation in (
                ("Sessions", "has_session"),
                ("LocalAdmins", "local_admin_to"),
                ("RemoteDesktopUsers", "can_rdp"),
                ("DcomUsers", "can_dcom"),
                ("PSRemoteUsers", "can_psremote"),
            ):
                values = item.get(relation_name)
                if isinstance(values, Mapping):
                    values = values.get("Results") or []
                if not isinstance(values, list):
                    continue
                for value in values:
                    related_id, related_type = _object_ref(value)
                    if related_id:
                        # A user/group relation grants a capability against the
                        # current computer or object.
                        pending_edges.append((
                            related_id, object_id, relation,
                            {"object_type": related_type},
                        ))

    # Create explicit placeholder nodes for referenced principals that were not
    # part of the selected export files. This keeps graph provenance honest and
    # avoids silently dropping useful ACL/session relationships.
    for source_id, target_id, _relation, evidence in pending_edges:
        if source_id not in assets_by_object:
            assets_by_object[source_id] = Asset(
                "identity-object", source_id, "bloodhound-reference",
                confidence=0.6,
                metadata={"object_type": evidence.get("object_type", "unknown")},
            )
        if target_id not in assets_by_object:
            assets_by_object[target_id] = Asset(
                "identity-object", target_id, "bloodhound-reference", confidence=0.6
            )

    edges = []
    for source_id, target_id, relation, evidence in pending_edges:
        source_asset = assets_by_object[source_id]
        target_asset = assets_by_object[target_id]
        if source_asset.asset_id == target_asset.asset_id:
            continue
        edges.append(GraphEdge(
            source_asset.asset_id,
            target_asset.asset_id,
            relation,
            "bloodhound",
            evidence=evidence,
        ))
    result.assets = list(assets_by_object.values())
    result.edges = list({edge.edge_id: edge for edge in edges}.values())
    return result


def _read_json_bytes(data: bytes, name: str) -> Mapping[str, Any]:
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityImportError("invalid BloodHound JSON in %s" % name) from exc
    if not isinstance(document, Mapping):
        raise IdentityImportError("BloodHound JSON root must be an object")
    return document


def load_bloodhound(path: str) -> IdentityImportResult:
    resolved = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.isfile(resolved):
        raise IdentityImportError("BloodHound input file not found")
    if os.path.getsize(resolved) > MAX_BLOODHOUND_INPUT_BYTES:
        raise IdentityImportError("BloodHound input exceeds the size limit")
    documents: List[Mapping[str, Any]] = []
    if zipfile.is_zipfile(resolved):
        with zipfile.ZipFile(resolved) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            if len(members) > MAX_BLOODHOUND_FILES:
                raise IdentityImportError("BloodHound archive contains too many files")
            declared_total = sum(item.file_size for item in members)
            if declared_total > MAX_BLOODHOUND_INPUT_BYTES:
                raise IdentityImportError("BloodHound archive expands beyond the size limit")
            actual_total = 0
            for item in members:
                if not item.filename.lower().endswith(".json"):
                    continue
                if item.file_size > MAX_BLOODHOUND_INPUT_BYTES:
                    raise IdentityImportError("BloodHound archive member is too large")
                remaining = MAX_BLOODHOUND_INPUT_BYTES - actual_total
                with archive.open(item, "r") as member:
                    data = member.read(remaining + 1)
                actual_total += len(data)
                if actual_total > MAX_BLOODHOUND_INPUT_BYTES:
                    raise IdentityImportError("BloodHound archive expands beyond the size limit")
                documents.append(_read_json_bytes(data, item.filename))
    else:
        with open(resolved, "rb") as handle:
            documents.append(_read_json_bytes(
                handle.read(MAX_BLOODHOUND_INPUT_BYTES + 1), os.path.basename(resolved)
            ))
    return parse_bloodhound_documents(documents)


@dataclass(frozen=True)
class LockoutPolicy:
    threshold: int
    observation_window_minutes: int
    lockout_duration_minutes: int

    def __post_init__(self) -> None:
        threshold = int(self.threshold)
        window = int(self.observation_window_minutes)
        duration = int(self.lockout_duration_minutes)
        if not 2 <= threshold <= 1000:
            raise ValueError("a known lockout threshold of at least 2 is required")
        if not 1 <= window <= 10080 or not 0 <= duration <= 10080:
            raise ValueError("lockout timing is out of range")
        object.__setattr__(self, "threshold", threshold)
        object.__setattr__(self, "observation_window_minutes", window)
        object.__setattr__(self, "lockout_duration_minutes", duration)


@dataclass(frozen=True)
class SprayBatch:
    offset_seconds: int
    identity_ids: Tuple[str, ...]
    candidate_index: int


@dataclass(frozen=True)
class SprayPlan:
    batches: Tuple[SprayBatch, ...]
    maximum_attempts_per_identity: int
    request_count: int
    execution_supported: bool = False


def plan_lockout_aware_spray(
    identity_ids: Sequence[str],
    candidate_count: int,
    policy: LockoutPolicy,
    *,
    requested_attempts_per_identity: int = 1,
) -> SprayPlan:
    """Create a schedule only; Blackthorn intentionally does not execute it."""
    identities = tuple(dict.fromkeys(str(item) for item in identity_ids if str(item)))
    if not identities:
        raise ValueError("at least one identity is required")
    candidate_count = int(candidate_count)
    if not 1 <= candidate_count <= 10000:
        raise ValueError("candidate count is out of range")
    safe_attempts = min(
        int(requested_attempts_per_identity),
        candidate_count,
        max(1, policy.threshold - 1),
    )
    if safe_attempts < 1:
        raise ValueError("requested attempts are invalid")
    separation = policy.observation_window_minutes * 60 + 5
    batches = tuple(
        SprayBatch(index * separation, identities, index)
        for index in range(safe_attempts)
    )
    return SprayPlan(
        batches=batches,
        maximum_attempts_per_identity=safe_attempts,
        request_count=len(identities) * safe_attempts,
        execution_supported=False,
    )
