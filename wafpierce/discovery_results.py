"""Safe, UI-neutral normalization for rich per-tool discovery results.

Recon reports intentionally retain the native structured output of each tool.
This module turns those stage arrays into predictable sections without flattening
multi-value results, while bounding how much untrusted tool output a GUI can
render at once.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any, Dict, List, Mapping, Sequence, Tuple
from urllib.parse import urlsplit

from .redaction import redact_text


MAX_RESULTS_PER_TOOL = 5000
MAX_RESULTS_TOTAL = 25000
MAX_DETAIL_NODES = 750
MAX_DETAIL_DEPTH = 5
MAX_DETAIL_TEXT = 8192

_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session)",
    re.IGNORECASE,
)

TOOL_METADATA: "OrderedDict[str, Tuple[str, str]]" = OrderedDict((
    ("subfinder", ("Subfinder", "Passive subdomain enumeration")),
    ("crtsh", ("Certificate Transparency", "Hostnames observed in public certificate logs")),
    ("dnsx", ("dnsx", "DNS resolution and address records")),
    ("httpx", ("httpx", "Live HTTP services, titles, servers, and technologies")),
    ("tlsx", ("tlsx", "TLS certificates, issuers, names, and SAN discoveries")),
    ("gau", ("gau", "Historical URLs from web archives and passive sources")),
    ("katana", ("katana", "Crawled application endpoints")),
    ("nuclei", ("Nuclei", "Template-backed vulnerability and exposure observations")),
    ("dalfox", ("Dalfox", "Parameterized URL and XSS observations")),
    ("nmap", ("Nmap", "Open ports and service/version fingerprints")),
    ("traceroute", ("Nmap traceroute", "Measured network paths and individual hops")),
    ("httpx_visual", ("httpx visual", "Screenshots, rendered DOM, favicon, JARM, and response hashes")),
    ("arjun", ("Arjun", "Hidden HTTP parameter discovery")),
    ("alterx", ("AlterX", "Pattern-aware subdomain permutation candidates")),
    ("uncover", ("Uncover", "Internet exposure search provider results")),
    ("asnmap", ("ASNMap", "Candidate ASN and CIDR ownership mappings")),
    ("cloudlist", ("Cloudlist", "Configured-cloud assets correlated to scope")),
    ("takeover", ("Takeover validation", "Dedicated Nuclei takeover template matches")),
    ("asset_diff", ("Discovery changes", "Added, removed, and changed assets since the previous run")),
    ("risk", ("Risk correlation", "Ranked cross-engine bug-bounty attack-surface signals")),
    ("blackthorn", ("Blackthorn correlation", "Cross-tool scope and coverage observations")),
))

_SOURCE_TOOL = {
    "subfinder": "subfinder",
    "certificate transparency": "crtsh",
    "crt.sh": "crtsh",
    "tls san": "tlsx",
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()


def _safe_text(value: Any, maximum: int = MAX_DETAIL_TEXT) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = redact_text(str(value).replace("\x00", ""))
    if len(text) > maximum:
        return text[:maximum] + "…"
    return text


def _safe_key(value: Any) -> str:
    return _safe_text(value, 128) or "value"


def _hostname(value: Any) -> str:
    text = _safe_text(value, 2048).strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else "//" + text)
        return (parsed.hostname or text).lower().rstrip(".")
    except ValueError:
        return text.lower().rstrip(".")


def infer_finding_tool(finding: Mapping[str, Any]) -> str:
    explicit = str(
        finding.get("source_tool") or finding.get("tool") or finding.get("engine") or ""
    ).strip().lower()
    aliases = {
        "certificate transparency": "crtsh",
        "crt.sh": "crtsh",
        "nmap traceroute": "traceroute",
        "httpx visual": "httpx_visual",
        "discovery changes": "asset_diff",
        "risk correlation": "risk",
    }
    explicit = aliases.get(explicit, explicit)
    if explicit in TOOL_METADATA:
        return explicit
    technique = str(finding.get("technique") or "").lower()
    for marker, tool in (
        ("tls", "tlsx"),
        ("dns", "dnsx"),
        ("http service", "httpx"),
        ("historical", "gau"),
        ("crawl", "katana"),
        ("vuln:", "nuclei"),
        ("xss", "dalfox"),
        ("network path", "traceroute"),
        ("open port", "nmap"),
        ("takeover", "takeover"),
        ("risk correlation", "risk"),
    ):
        if marker in technique:
            return tool
    return "blackthorn"


def discovery_tool_sections(
    report: Mapping[str, Any],
    *,
    max_results_per_tool: int = MAX_RESULTS_PER_TOOL,
    max_results_total: int = MAX_RESULTS_TOTAL,
) -> List[Dict[str, Any]]:
    """Return ordered tool sections from one structured recon report.

    ``total`` reports the complete source count while ``results`` is bounded for
    interactive rendering. A truncated section remains explicit in the UI.
    """
    per_tool = max(1, min(int(max_results_per_tool), MAX_RESULTS_PER_TOOL))
    global_limit = max(1, min(int(max_results_total), MAX_RESULTS_TOTAL))
    buckets: Dict[str, Dict[str, Any]] = {}
    rendered_total = 0

    def add(tool: str, record: Mapping[str, Any]) -> None:
        nonlocal rendered_total
        if tool not in TOOL_METADATA:
            tool = "blackthorn"
        bucket = buckets.setdefault(tool, {"total": 0, "results": []})
        bucket["total"] += 1
        if len(bucket["results"]) >= per_tool or rendered_total >= global_limit:
            return
        bucket["results"].append(dict(record))
        rendered_total += 1

    stages = _mapping(report.get("stages"))
    sources = _mapping(stages.get("sources"))
    for hostname, source_values in sources.items():
        for source in _sequence(source_values):
            tool = _SOURCE_TOOL.get(str(source).strip().lower())
            if tool:
                add(tool, {"hostname": hostname, "source": source})

    for hostname, addresses in _mapping(stages.get("resolved")).items():
        add("dnsx", {
            "hostname": hostname,
            "ip_addresses": list(_sequence(addresses)),
        })

    for row in _sequence(stages.get("http")):
        if isinstance(row, Mapping):
            add("httpx", row)
    for row in _sequence(stages.get("tls")):
        if isinstance(row, Mapping):
            add("tlsx", row)
    for url in _sequence(stages.get("historical")):
        add("gau", {"url": url})
    for url in _sequence(stages.get("endpoints")):
        add("katana", {"url": url})
    for stage_key, tool in (
        ("vulns", "nuclei"),
        ("xss", "dalfox"),
        ("ports", "nmap"),
        ("traceroute", "traceroute"),
        ("visual", "httpx_visual"),
        ("arjun", "arjun"),
        ("alterx", "alterx"),
        ("uncover", "uncover"),
        ("asnmap", "asnmap"),
        ("cloudlist", "cloudlist"),
        ("takeovers", "takeover"),
        ("risk_signals", "risk"),
    ):
        for row in _sequence(stages.get(stage_key)):
            if isinstance(row, Mapping):
                add(tool, row)
            else:
                add(tool, {"value": row})

    asset_diff = _mapping(stages.get("asset_diff"))
    for change in ("added", "removed", "changed"):
        for row in _sequence(asset_diff.get(change)):
            if isinstance(row, Mapping):
                record = dict(row)
                record["change"] = change
                add("asset_diff", record)

    # Legacy reports may contain only scanner-shaped findings. Current reports
    # keep just the cross-tool synthesized observations here to avoid duplicating
    # the richer native stage rows above.
    findings = _sequence(report.get("findings"))
    has_native_stages = any(
        key in stages for key in (
            "sources", "resolved", "http", "tls", "historical", "endpoints",
            "vulns", "xss", "ports", "traceroute", "visual", "arjun",
            "alterx", "uncover", "asnmap", "cloudlist", "takeovers",
            "risk_signals", "asset_diff",
        )
    )
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        tool = infer_finding_tool(finding)
        if has_native_stages and tool != "blackthorn":
            continue
        technique = str(finding.get("technique") or "")
        if has_native_stages and technique == "Discovered Host":
            continue  # already represented in the dedicated host inventory
        add(tool, finding)

    sections: List[Dict[str, Any]] = []
    for tool, (label, description) in TOOL_METADATA.items():
        bucket = buckets.get(tool)
        if not bucket:
            continue
        shown = len(bucket["results"])
        total = int(bucket["total"])
        sections.append({
            "tool": tool,
            "label": label,
            "description": description,
            "total": total,
            "shown": shown,
            "truncated": total > shown,
            "results": bucket["results"],
        })
    return sections


def discovery_result_summary(tool: str, record: Mapping[str, Any]) -> Dict[str, str]:
    """Create four concise columns without discarding the original record."""
    tool = tool if tool in TOOL_METADATA else "blackthorn"
    info = _mapping(record.get("info"))
    target = _safe_text(
        record.get("matched-at") or record.get("matched_at") or record.get("url")
        or record.get("input") or record.get("host") or record.get("hostname")
        or record.get("ip") or record.get("target") or record.get("value"),
        4096,
    )
    severity = str(
        record.get("severity") or info.get("severity") or (
            "HIGH" if tool == "dalfox" else "LOW" if tool == "nmap" else "INFO"
        )
    ).upper()
    if severity == "CRITICAL":
        severity = "CRITICAL"
    elif severity not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
        severity = "INFO"

    title = _safe_text(
        record.get("technique") or info.get("name") or record.get("name")
        or record.get("template-id") or record.get("templateID")
        or record.get("title") or record.get("hostname") or target or "Result",
        1024,
    )
    detail = _safe_text(record.get("reason") or record.get("description"), 4096)

    if tool == "dnsx":
        addresses = [_safe_text(item, 256) for item in _sequence(record.get("ip_addresses"))]
        title = _safe_text(record.get("hostname") or target, 1024)
        detail = ", ".join(item for item in addresses if item) or "Resolved without an A record"
    elif tool == "httpx":
        status = record.get("status_code") or record.get("status-code")
        web_title = _safe_text(record.get("title"), 1024)
        title = web_title or target or "HTTP service"
        bits = [
            "HTTP %s" % status if status is not None else "",
            _safe_text(record.get("webserver") or record.get("web-server"), 512),
        ]
        detail = " · ".join(bit for bit in bits if bit)
    elif tool == "tlsx":
        title = _safe_text(record.get("host") or record.get("hostname") or target, 1024)
        detail = _safe_text(
            record.get("subject_cn") or record.get("subject-cn")
            or record.get("issuer_cn") or record.get("issuer-cn") or "TLS certificate",
            2048,
        )
    elif tool in {"subfinder", "crtsh"}:
        title = _safe_text(record.get("hostname") or target, 1024)
        target = title
        detail = "Discovered hostname"
    elif tool in {"gau", "katana"}:
        title = target or "URL"
        detail = "Historical URL" if tool == "gau" else "Crawled endpoint"
    elif tool == "nmap":
        port = record.get("port")
        host = _safe_text(record.get("host") or record.get("ip") or target, 1024)
        target = "%s%s" % (host, (":" + str(port)) if port not in (None, "") else "")
        service = " ".join(
            _safe_text(record.get(key), 512)
            for key in ("service", "product", "version") if record.get(key)
        )
        title = service or ("Port %s" % port if port not in (None, "") else "Open port")
        detail = "%s/%s open" % (port, record.get("protocol") or "tcp") if port else "Open port"
    elif tool == "traceroute":
        title = _safe_text(record.get("target") or record.get("address") or target, 1024)
        hops = _sequence(record.get("hops"))
        detail = "%d measured hop(s)" % len(hops)
    elif tool == "nuclei":
        title = _safe_text(
            info.get("name") or record.get("template-id") or record.get("templateID") or title,
            1024,
        )
        detail = _safe_text(
            info.get("description") or record.get("matcher-name")
            or record.get("template-id") or detail,
            4096,
        )
    elif tool == "dalfox":
        title = _safe_text(record.get("type") or record.get("param") or "XSS observation", 1024)
        target = _safe_text(
            record.get("url") or record.get("data") or record.get("poc") or target,
            4096,
        )
        detail = _safe_text(record.get("evidence") or record.get("param") or detail, 4096)
    elif tool == "risk":
        title = _safe_text(record.get("category") or "Correlated risk", 1024).replace("_", " ").title()
        target = _safe_text(record.get("target") or target, 4096)
        detail = _safe_text(record.get("reason") or detail, 4096)
        severity = str(record.get("severity") or severity).upper()
    elif tool == "asset_diff":
        change = _safe_text(record.get("change") or "changed", 64)
        asset = _mapping(record.get("after") or record.get("before") or record)
        title = f"{change.title()}: {_safe_text(asset.get('kind') or 'asset', 128)}"
        target = _safe_text(asset.get("value") or target, 4096)
        detail = ", ".join(str(value) for value in asset.get("sources") or [])
        severity = "INFO"
    elif tool == "arjun":
        title = "Hidden parameters"
        target = _safe_text(record.get("url") or target, 4096)
        params = _sequence(record.get("parameters"))
        detail = f"{len(params)} parameter(s) · {_safe_text(record.get('method') or 'GET', 32)}"
    elif tool == "takeover":
        info = _mapping(record.get("info"))
        title = _safe_text(info.get("name") or record.get("template-id") or "Takeover candidate", 1024)
        target = _safe_text(record.get("matched-at") or record.get("host") or target, 4096)
        detail = "Dedicated takeover template matched"
        severity = str(info.get("severity") or "HIGH").upper()

    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        severity = "INFO"

    return {
        "title": title or "Result",
        "target": target,
        "severity": severity,
        "detail": detail,
        "hostname": _hostname(target),
    }


def discovery_detail_nodes(
    record: Mapping[str, Any],
    *,
    max_nodes: int = MAX_DETAIL_NODES,
    max_depth: int = MAX_DETAIL_DEPTH,
) -> List[Dict[str, Any]]:
    """Build bounded recursive field nodes for one untrusted tool result."""
    node_limit = max(1, min(int(max_nodes), MAX_DETAIL_NODES))
    depth_limit = max(1, min(int(max_depth), MAX_DETAIL_DEPTH))
    used = 0
    seen = set()

    def walk(label: str, value: Any, depth: int) -> Dict[str, Any]:
        nonlocal used
        used += 1
        if _SENSITIVE_KEY.search(label):
            return {"label": label, "value": "<redacted>", "children": []}
        if used >= node_limit:
            return {"label": label, "value": "render limit reached", "children": []}
        marker = id(value)
        if isinstance(value, (Mapping, list, tuple)):
            if marker in seen:
                return {"label": label, "value": "<recursive value>", "children": []}
            seen.add(marker)
        if isinstance(value, Mapping):
            item_count = len(value)
            node = {"label": label, "value": "%d field(s)" % item_count, "children": []}
            if depth >= depth_limit:
                node["value"] += " · depth limit reached"
                return node
            for key, child_value in value.items():
                if used >= node_limit:
                    break
                node["children"].append(walk(_safe_key(key), child_value, depth + 1))
            if len(node["children"]) < item_count:
                node["children"].append({
                    "label": "More",
                    "value": "%d field(s) not rendered" % (
                        item_count - len(node["children"])
                    ),
                    "children": [],
                })
            return node
        if isinstance(value, (list, tuple)):
            node = {"label": label, "value": "%d item(s)" % len(value), "children": []}
            if depth >= depth_limit:
                node["value"] += " · depth limit reached"
                return node
            for index, child_value in enumerate(value):
                if used >= node_limit:
                    break
                node["children"].append(walk("[%d]" % (index + 1), child_value, depth + 1))
            if len(node["children"]) < len(value):
                node["children"].append({
                    "label": "More",
                    "value": "%d item(s) not rendered" % (len(value) - len(node["children"])),
                    "children": [],
                })
            return node
        return {"label": label, "value": _safe_text(value), "children": []}

    nodes = []
    for key, value in record.items():
        if used >= node_limit:
            break
        nodes.append(walk(_safe_key(key), value, 1))
    if used >= node_limit:
        nodes.append({
            "label": "Render limit",
            "value": "Additional fields were omitted for UI safety",
            "children": [],
        })
    return nodes


def discovery_result_matches(tool: str, record: Mapping[str, Any], query: str) -> bool:
    needle = str(query or "").strip().lower()
    if not needle:
        return True
    summary = discovery_result_summary(tool, record)
    parts = list(summary.values())
    remaining = 128

    def collect(value: Any, depth: int = 0) -> None:
        nonlocal remaining
        if remaining <= 0 or depth > 4:
            return
        remaining -= 1
        if isinstance(value, Mapping):
            for key, child in value.items():
                if _SENSITIVE_KEY.search(str(key)):
                    continue
                parts.append(_safe_key(key))
                collect(child, depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value[:64]:
                collect(child, depth + 1)
        else:
            parts.append(_safe_text(value, 2048))

    collect(record)
    return needle in " ".join(parts).lower()
