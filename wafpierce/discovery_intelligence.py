"""Continuous discovery snapshots, diffs, and bug-bounty risk correlation.

Snapshots contain identifiers and non-sensitive metadata only.  Native scanner
responses stay in the one-run report and are never copied into history files.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import urlparse

from .config import prepare_private_file
from .redaction import redact_text


MAX_SNAPSHOT_ASSETS = 50000
MAX_RISK_SIGNALS = 5000
SNAPSHOT_VERSION = 1

_ENV_MARKERS = re.compile(
    r"(?i)(?:^|[.\-_/])(admin|api|auth|console|dashboard|debug|dev|internal|legacy|old|qa|sandbox|stage|staging|test|uat)(?:[.\-_/]|$)"
)
_SENSITIVE_PATH = re.compile(
    r"(?i)/(?:admin|api|graphql|swagger|openapi|debug|actuator|metrics|internal|private|console)(?:/|$)"
)
_HIGH_VALUE_PORTS = {
    21, 22, 23, 25, 110, 111, 135, 139, 445, 1433, 1521, 2049, 2375,
    2379, 2380, 3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900, 6379,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 11211, 27017,
}


def _text(value: Any, maximum: int = 2048) -> str:
    return redact_text(str(value or "").replace("\x00", ""))[:maximum]


def _asset_id(kind: str, value: str) -> str:
    material = f"{kind}\0{value}".encode("utf-8", "replace")
    return hashlib.sha256(material).hexdigest()[:24]


def _hostname(value: Any) -> str:
    text = _text(value).strip()
    if not text:
        return ""
    try:
        return (urlparse(text if "://" in text else "//" + text).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _append_asset(
    assets: Dict[str, Dict[str, Any]],
    kind: str,
    value: Any,
    source: str,
    **metadata: Any,
) -> None:
    clean = _text(value, 4096).strip()
    if not clean or len(assets) >= MAX_SNAPSHOT_ASSETS:
        return
    ident = _asset_id(kind, clean)
    current = assets.get(ident)
    if current is None:
        current = {
            "id": ident,
            "kind": kind,
            "value": clean,
            "sources": [],
            "metadata": {},
        }
        assets[ident] = current
    if source and source not in current["sources"]:
        current["sources"].append(source)
    for key, item in metadata.items():
        if item in (None, "", [], {}):
            continue
        if isinstance(item, (str, int, float, bool)):
            current["metadata"][_text(key, 128)] = _text(item, 1024)


def build_asset_snapshot(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Build a compact, secret-free canonical asset snapshot."""
    stages = report.get("stages") if isinstance(report.get("stages"), Mapping) else {}
    assets: Dict[str, Dict[str, Any]] = {}

    sources = stages.get("sources") if isinstance(stages.get("sources"), Mapping) else {}
    for host, providers in sources.items():
        values = providers if isinstance(providers, (list, tuple)) else [providers]
        for provider in values:
            _append_asset(assets, "host", host, _text(provider, 128))

    resolved = stages.get("resolved") if isinstance(stages.get("resolved"), Mapping) else {}
    for host, addresses in resolved.items():
        _append_asset(assets, "host", host, "dnsx")
        values = addresses if isinstance(addresses, (list, tuple)) else [addresses]
        for address in values:
            _append_asset(assets, "ip", address, "dnsx", hostname=host)

    for row in stages.get("http") or []:
        if not isinstance(row, Mapping) or not row.get("live"):
            continue
        url = row.get("url") or row.get("input")
        _append_asset(
            assets, "url", url, "httpx",
            status=row.get("status_code") or row.get("status-code"),
            title=row.get("title"),
        )

    for key, source in (
        ("historical", "gau"), ("endpoints", "katana"),
    ):
        for url in stages.get(key) or []:
            _append_asset(assets, "url", url, source)

    for key, source in (
        ("arjun", "arjun"), ("visual", "httpx_visual"),
    ):
        for row in stages.get(key) or []:
            if not isinstance(row, Mapping):
                continue
            url = row.get("url") or row.get("target") or row.get("source_url")
            kind = "parameter" if source == "arjun" else "url"
            _append_asset(
                assets, kind, url, source,
                method=row.get("method"), status=row.get("status"),
            )

    for key, source in (
        ("ports", "nmap"), ("uncover", "uncover"),
    ):
        for row in stages.get(key) or []:
            if not isinstance(row, Mapping):
                continue
            host = row.get("host") or row.get("ip") or row.get("address")
            port = row.get("port")
            value = f"{host}:{port}" if host and port not in (None, "") else host
            _append_asset(
                assets, "service", value, source,
                service=row.get("service"), product=row.get("product"),
            )

    for key, source, kind in (
        ("asnmap", "asnmap", "network_range"),
        ("cloudlist", "cloudlist", "cloud_asset"),
        ("takeovers", "nuclei_takeover", "takeover_candidate"),
    ):
        for row in stages.get(key) or []:
            if not isinstance(row, Mapping):
                continue
            value = (
                row.get("matched-at") or row.get("matched_at") or row.get("url")
                or row.get("host") or row.get("hostname") or row.get("cidr")
                or row.get("range") or row.get("address") or row.get("ip")
            )
            _append_asset(assets, kind, value, source)

    return {
        "version": SNAPSHOT_VERSION,
        "target": _text(report.get("target"), 512),
        "assets": sorted(assets.values(), key=lambda row: (row["kind"], row["value"])),
    }


def diff_snapshots(
    current: Mapping[str, Any], previous: Mapping[str, Any] | None
) -> Dict[str, Any]:
    """Return added, removed, and provenance-changed assets."""
    now = {
        str(row.get("id")): row
        for row in current.get("assets") or [] if isinstance(row, Mapping)
    }
    before = {
        str(row.get("id")): row
        for row in (previous or {}).get("assets") or [] if isinstance(row, Mapping)
    }
    added = [now[key] for key in sorted(set(now) - set(before))]
    removed = [before[key] for key in sorted(set(before) - set(now))]
    changed = []
    for key in sorted(set(now) & set(before)):
        if (
            sorted(now[key].get("sources") or []) != sorted(before[key].get("sources") or [])
            or dict(now[key].get("metadata") or {}) != dict(before[key].get("metadata") or {})
        ):
            changed.append({"before": before[key], "after": now[key]})
    return {
        "baseline_available": bool(previous),
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added": len(added), "removed": len(removed), "changed": len(changed),
            "current": len(now), "previous": len(before),
        },
    }


def _signal(
    output: List[Dict[str, Any]],
    target: str,
    score: int,
    reason: str,
    sources: Sequence[str],
    category: str,
) -> None:
    if len(output) >= MAX_RISK_SIGNALS:
        return
    output.append({
        "target": _text(target, 4096),
        "score": max(0, min(int(score), 100)),
        "severity": "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW",
        "category": category,
        "reason": _text(reason, 4096),
        "sources": list(dict.fromkeys(_text(source, 128) for source in sources if source)),
    })


def correlate_risks(
    report: Mapping[str, Any], snapshot: Mapping[str, Any], diff: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    """Rank high-signal attack-surface observations with explicit reasons."""
    signals: List[Dict[str, Any]] = []
    new_ids = {
        str(row.get("id")) for row in diff.get("added") or [] if isinstance(row, Mapping)
    }
    for asset in snapshot.get("assets") or []:
        if not isinstance(asset, Mapping):
            continue
        value = _text(asset.get("value"), 4096)
        sources = list(asset.get("sources") or [])
        base = 18 if str(asset.get("id")) in new_ids and diff.get("baseline_available") else 0
        marker = _ENV_MARKERS.search(value)
        if marker:
            _signal(
                signals, value, 42 + base,
                f"Environment or administrative marker '{marker.group(1)}' in discovered asset",
                sources, "interesting_asset",
            )
        if _SENSITIVE_PATH.search(value):
            _signal(
                signals, value, 48 + base,
                "Sensitive application path discovered",
                sources, "sensitive_path",
            )
        if asset.get("kind") == "service":
            try:
                port = int(value.rsplit(":", 1)[1])
            except (IndexError, TypeError, ValueError):
                port = 0
            if port in _HIGH_VALUE_PORTS:
                _signal(
                    signals, value, 52 + base,
                    f"High-value or nonstandard service port {port} is exposed",
                    sources, "exposed_service",
                )
        if asset.get("kind") == "secret_observation":
            _signal(
                signals, value, 76 + base,
                "JavaScript analysis identified a redacted potential secret",
                sources, "secret_exposure",
            )
        if asset.get("kind") == "takeover_candidate":
            _signal(
                signals, value, 85 + base,
                "A dedicated takeover template matched this scoped asset",
                sources, "subdomain_takeover",
            )
        if asset.get("kind") == "cloud_asset":
            _signal(
                signals, value, 44 + base,
                "Configured cloud inventory correlated this asset to the target",
                sources, "cloud_exposure",
            )

    # Deduplicate equivalent risk reasons while retaining the strongest score.
    dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in signals:
        key = (row["target"], row["category"])
        if key not in dedup or row["score"] > dedup[key]["score"]:
            dedup[key] = row
    return sorted(
        dedup.values(), key=lambda row: (-int(row["score"]), row["target"])
    )[:MAX_RISK_SIGNALS]


def history_path(history_dir: str, target: str) -> str:
    digest = hashlib.sha256(_text(target).encode("utf-8", "replace")).hexdigest()[:20]
    return os.path.join(os.path.abspath(history_dir), f"{digest}.json")


def load_snapshot(path: str) -> Dict[str, Any] | None:
    try:
        if os.path.getsize(path) > 25 * 1024 * 1024:
            return None
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping) or value.get("version") != SNAPSHOT_VERSION:
        return None
    return dict(value)


def save_snapshot(path: str, snapshot: Mapping[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    prepare_private_file(path)
    temporary = path + ".tmp"
    Path(temporary).write_text(
        json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8"
    )
    prepare_private_file(temporary)
    os.replace(temporary, path)
    prepare_private_file(path)


def apply_continuous_intelligence(
    report: Dict[str, Any], history_dir: str = ""
) -> Dict[str, Any]:
    """Attach snapshot/diff/risk stages and optionally update private history."""
    snapshot = build_asset_snapshot(report)
    path = history_path(history_dir, report.get("target", "")) if history_dir else ""
    previous = load_snapshot(path) if path else None
    diff = diff_snapshots(snapshot, previous)
    risks = correlate_risks(report, snapshot, diff)
    stages = report.setdefault("stages", {})
    stages["asset_snapshot"] = snapshot
    stages["asset_diff"] = diff
    stages["risk_signals"] = risks
    if path:
        save_snapshot(path, snapshot)
    return report
