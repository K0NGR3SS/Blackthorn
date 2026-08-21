"""Cloud inventory, Prowler findings, IAM relations, and read-only plans."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .pentest_models import Asset, GraphEdge
from .pentest_workspace import PentestWorkspace
from .redaction import redact_finding, redact_text


MAX_CLOUD_INPUT_BYTES = 128 * 1024 * 1024
MAX_CLOUD_ROWS = 1_000_000
SUPPORTED_PROVIDERS = frozenset({"aws", "azure", "gcp"})


class CloudImportError(ValueError):
    pass


def _clean(value: Any, maximum: int = 8192) -> str:
    return str(value or "").replace("\x00", "").strip()[:maximum]


def _provider(value: Any) -> str:
    text = _clean(value, 32).lower()
    aliases = {"amazon": "aws", "microsoft": "azure", "google": "gcp"}
    text = aliases.get(text, text)
    if text not in SUPPORTED_PROVIDERS:
        raise CloudImportError("unsupported cloud provider: %s" % value)
    return text


@dataclass
class CloudImportResult:
    assets: List[Asset] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def persist(self, workspace: PentestWorkspace, workspace_id: str) -> Dict[str, int]:
        for asset in self.assets:
            workspace.save_asset(workspace_id, asset)
        for edge in self.edges:
            workspace.save_edge(workspace_id, edge)
        return {
            "assets": len(self.assets),
            "edges": len(self.edges),
            "findings": len(self.findings),
            "warnings": len(self.warnings),
        }


def parse_prowler_rows(rows: Iterable[Mapping[str, Any]]) -> CloudImportResult:
    result = CloudImportResult()
    assets: Dict[str, Asset] = {}
    edges: Dict[str, GraphEdge] = {}
    for index, row in enumerate(rows):
        if index >= MAX_CLOUD_ROWS:
            raise CloudImportError("cloud input contains too many rows")
        try:
            provider = _provider(row.get("Provider") or row.get("provider") or "aws")
        except CloudImportError as exc:
            result.warnings.append(str(exc))
            continue
        account_id = _clean(
            row.get("AccountId") or row.get("Account ID") or row.get("account_id")
            or row.get("SubscriptionId") or row.get("ProjectId"), 1024
        )
        resource_id = redact_text(_clean(
            row.get("ResourceArn") or row.get("ResourceId") or row.get("Resource ID")
            or row.get("resource_id") or row.get("Resource") or "unknown-resource", 4096
        ))
        status = _clean(row.get("Status") or row.get("status"), 64).upper()
        severity = _clean(row.get("Severity") or row.get("severity") or "INFO", 32).upper()
        check_id = _clean(row.get("CheckID") or row.get("Check ID") or row.get("check_id"), 256)
        region = _clean(row.get("Region") or row.get("region"), 128)
        account_value = "%s:%s" % (provider, account_id or "unknown-account")
        account = Asset(
            "cloud-account", account_value, "prowler",
            metadata={"provider": provider, "account_id": account_id},
        )
        resource = Asset(
            "cloud-resource", resource_id, "prowler",
            metadata={
                "provider": provider,
                "account_id": account_id,
                "region": region,
                "check_id": check_id,
                "status": status,
                "severity": severity,
            },
        )
        assets[account.asset_id] = account
        assets[resource.asset_id] = resource
        edge = GraphEdge(
            account.asset_id, resource.asset_id, "contains", "prowler",
            evidence={"provider": provider, "region": region},
        )
        edges[edge.edge_id] = edge
        if status in {"FAIL", "FAILED", "ERROR"}:
            result.findings.append(redact_finding({
                "source": "prowler",
                "provider": provider,
                "account_id": account_id,
                "resource_id": resource_id,
                "check_id": check_id,
                "severity": severity,
                "status": status,
                "title": _clean(
                    row.get("CheckTitle") or row.get("Check Title")
                    or row.get("check_title") or check_id, 2048
                ),
                "risk": _clean(row.get("Risk") or row.get("risk"), 8192),
            }))
    result.assets = list(assets.values())
    result.edges = list(edges.values())
    return result


def load_prowler_json(path: str) -> CloudImportResult:
    resolved = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.isfile(resolved):
        raise CloudImportError("Prowler JSON file not found")
    if os.path.getsize(resolved) > MAX_CLOUD_INPUT_BYTES:
        raise CloudImportError("Prowler JSON exceeds the size limit")
    try:
        with open(resolved, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudImportError("invalid Prowler JSON") from exc
    if isinstance(data, Mapping):
        rows = data.get("findings") or data.get("items") or data.get("data")
    else:
        rows = data
    if not isinstance(rows, list):
        raise CloudImportError("Prowler JSON must contain a list of findings")
    return parse_prowler_rows(item for item in rows if isinstance(item, Mapping))


def normalize_iam_relationships(
    provider: str,
    principals: Sequence[Mapping[str, Any]],
    resources: Sequence[Mapping[str, Any]],
    permissions: Sequence[Mapping[str, Any]],
) -> CloudImportResult:
    provider = _provider(provider)
    if len(principals) + len(resources) > MAX_CLOUD_ROWS or len(permissions) > MAX_CLOUD_ROWS:
        raise CloudImportError("IAM input contains too many rows")
    result = CloudImportResult()
    nodes: Dict[str, Asset] = {}
    by_external_id: Dict[str, Asset] = {}
    for row, kind in (
        *((item, "cloud-principal") for item in principals),
        *((item, "cloud-resource") for item in resources),
    ):
        external_id = redact_text(_clean(
            row.get("id") or row.get("arn") or row.get("name"), 4096
        ))
        if not external_id:
            result.warnings.append("ignored cloud object without an id")
            continue
        asset = Asset(
            kind, external_id, "%s-iam" % provider,
            metadata={
                "provider": provider,
                "display_name": _clean(row.get("name"), 1024),
                "object_type": _clean(row.get("type"), 128),
                "account_id": _clean(row.get("account_id"), 1024),
            },
        )
        nodes[asset.asset_id] = asset
        by_external_id[external_id] = asset

    edges: Dict[str, GraphEdge] = {}
    for row in permissions:
        principal_id = redact_text(_clean(
            row.get("principal_id") or row.get("principal"), 4096
        ))
        resource_id = redact_text(_clean(
            row.get("resource_id") or row.get("resource"), 4096
        ))
        principal = by_external_id.get(principal_id)
        resource = by_external_id.get(resource_id)
        if principal is None or resource is None:
            result.warnings.append("ignored IAM permission with an unknown endpoint")
            continue
        actions_value = row.get("actions") or row.get("action") or []
        if isinstance(actions_value, str):
            actions = [actions_value]
        else:
            try:
                actions = [str(item) for item in islice(actions_value, 1000) if str(item)]
            except TypeError:
                actions = []
        lower_actions = {action.lower() for action in actions}
        if any("assumerole" in action or "actas" in action for action in lower_actions):
            relation = "can_assume"
        elif "*" in lower_actions or any(action.endswith(":*") for action in lower_actions):
            relation = "admin_access"
        else:
            relation = "can_access"
        edge = GraphEdge(
            principal.asset_id,
            resource.asset_id,
            relation,
            "%s-iam" % provider,
            evidence={
                "actions": actions[:1000],
                "effect": _clean(row.get("effect") or "Allow", 32),
                "conditional": bool(row.get("condition")),
            },
        )
        edges[edge.edge_id] = edge
    result.assets = list(nodes.values())
    result.edges = list(edges.values())
    return result


READ_ONLY_INVENTORY_OPERATIONS = {
    "aws": (
        "sts:GetCallerIdentity", "iam:ListAccountAliases", "iam:ListRoles",
        "iam:ListUsers", "organizations:DescribeOrganization",
        "ec2:DescribeInstances", "s3:ListAllMyBuckets",
    ),
    "azure": (
        "Microsoft Graph /me", "Microsoft Graph /organization",
        "Microsoft Graph /users", "Microsoft Graph /groups",
        "Azure Resource Manager subscriptions/resources read",
    ),
    "gcp": (
        "oauth2.tokeninfo", "cloudresourcemanager.projects.list",
        "cloudresourcemanager.projects.getIamPolicy", "compute.instances.list",
        "storage.buckets.list",
    ),
}


def read_only_inventory_plan(provider: str, credential_handle: str) -> Dict[str, Any]:
    provider = _provider(provider)
    handle = _clean(credential_handle, 128)
    if not handle or any(char.isspace() for char in handle):
        raise CloudImportError("a secret-store credential handle is required")
    return {
        "provider": provider,
        "credential_handle": handle,
        "read_only": True,
        "operations": list(READ_ONLY_INVENTORY_OPERATIONS[provider]),
        "execution_supported": False,
    }
