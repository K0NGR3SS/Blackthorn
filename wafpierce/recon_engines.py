"""Optional bug-bounty discovery engines used by :mod:`wafpierce.recon`.

The core recon pipeline stays useful without these binaries.  Every adapter in
this module is deliberately bounded, accepts an argv-based runner (never a
shell command), and returns native structured records for the Discovery UI.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import urlparse


RunCommand = Callable[..., tuple]
WhichCommand = Callable[[str], Optional[str]]

MAX_ENGINE_RECORDS = 5000

_HOST_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
)


def _run(
    runner: RunCommand,
    argv: List[str],
    timeout: float,
    stdin_text: Optional[str] = None,
) -> tuple:
    """Call the shared runner while remaining friendly to simple test doubles."""
    if stdin_text is None:
        return runner(argv, timeout)
    try:
        return runner(argv, timeout, stdin_text=stdin_text)
    except TypeError:
        return runner(argv, timeout, stdin_text)


def _json_records(text: str, cap: int = MAX_ENGINE_RECORDS) -> List[Dict[str, Any]]:
    """Parse a JSON document or JSONL stream, ignoring malformed noise."""
    raw = (text or "").strip()
    if not raw:
        return []
    records: List[Dict[str, Any]] = []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        value = None
    if isinstance(value, Mapping):
        records.append(dict(value))
    elif isinstance(value, list):
        records.extend(dict(row) for row in value if isinstance(row, Mapping))
    else:
        for line in raw.splitlines():
            try:
                row = json.loads(line.strip())
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(row, Mapping):
                records.append(dict(row))
            elif isinstance(row, list):
                records.extend(dict(item) for item in row if isinstance(item, Mapping))
            if len(records) >= cap:
                break
    return records[:cap]


def _in_scope_host(value: str, domain: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        host = urlparse(text if "://" in text else "//" + text).hostname or ""
    except ValueError:
        return False
    host = host.lower().rstrip(".")
    domain = str(domain or "").lower().rstrip(".")
    return bool(host and domain and (host == domain or host.endswith("." + domain)))


def _safe_urls(values: Iterable[Any], domain: str, cap: int) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        url = str(value or "").strip()
        if url in seen or not url.lower().startswith(("http://", "https://")):
            continue
        if not _in_scope_host(url, domain):
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= cap:
            break
    return out


def visual_probe(
    urls: Sequence[str],
    domain: str,
    timeout: float,
    runner: RunCommand,
    which: WhichCommand,
    *,
    artifact_dir: str = "",
    cap: int = 100,
) -> List[Dict[str, Any]]:
    """Capture httpx screenshots plus rendered-DOM/fingerprint metadata."""
    targets = _safe_urls(urls, domain, max(1, min(cap, 500)))
    binary = which("httpx")
    if not targets or not binary:
        return []
    root = os.path.abspath(
        artifact_dir or tempfile.mkdtemp(prefix="blackthorn_httpx_visual_")
    )
    os.makedirs(root, exist_ok=True)
    cmd = [
        binary, "-silent", "-json", "-no-color", "-screenshot", "-esb",
        "-favicon", "-jarm", "-hash", "sha256", "-srd", root,
        "-t", "5", "-timeout", "10", "-retries", "1",
    ]
    _rc, out, _err = _run(runner, cmd, timeout, "\n".join(targets))
    rows = _json_records(out, cap=len(targets) * 2)
    for row in rows:
        row["engine"] = "httpx_visual"
        path = str(
            row.get("screenshot_path") or row.get("screenshot-path") or ""
        ).strip()
        if path:
            candidate = os.path.abspath(
                path if os.path.isabs(path) else os.path.join(root, path)
            )
            try:
                inside = os.path.commonpath([root, candidate]) == root
            except ValueError:
                inside = False
            if not inside:
                row.pop("screenshot_path", None)
                row.pop("screenshot-path", None)
            elif "screenshot_path" in row:
                row["screenshot_path"] = candidate
            elif "screenshot-path" in row:
                row["screenshot-path"] = candidate
    return rows


def _flatten_arjun(data: Any, source_url: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(data, Mapping):
        if any(key in data for key in ("params", "parameters")):
            params = data.get("params") or data.get("parameters") or []
            rows.append({
                "url": str(data.get("url") or source_url),
                "method": str(data.get("method") or "GET"),
                "parameters": list(params) if isinstance(params, (list, tuple)) else [params],
            })
        else:
            for key, value in data.items():
                rows.extend(_flatten_arjun(value, str(key) if str(key).startswith("http") else source_url))
    elif isinstance(data, list):
        if all(not isinstance(item, (Mapping, list, tuple)) for item in data):
            rows.append({"url": source_url, "method": "GET", "parameters": list(data)})
        else:
            for value in data:
                rows.extend(_flatten_arjun(value, source_url))
    return rows


def arjun_scan(
    urls: Sequence[str],
    domain: str,
    timeout: float,
    runner: RunCommand,
    which: WhichCommand,
    *,
    cap: int = 25,
) -> List[Dict[str, Any]]:
    """Discover hidden HTTP parameters with bounded Arjun executions."""
    binary = which("arjun")
    if not binary:
        return []
    rows: List[Dict[str, Any]] = []
    for url in _safe_urls(urls, domain, max(1, min(cap, 50))):
        fd, output_path = tempfile.mkstemp(prefix="blackthorn_arjun_", suffix=".json")
        os.close(fd)
        try:
            cmd = [
                binary, "-u", url, "-m", "GET", "--stable", "-t", "5",
                "-oJ", output_path,
            ]
            _rc, out, _err = _run(runner, cmd, timeout)
            data: Any = None
            try:
                raw = Path(output_path).read_text(encoding="utf-8")
                if raw.strip():
                    data = json.loads(raw)
            except (OSError, ValueError, json.JSONDecodeError):
                pass
            if data is None:
                try:
                    data = json.loads((out or "").strip())
                except (TypeError, ValueError, json.JSONDecodeError):
                    data = None
            rows.extend(_flatten_arjun(data, url))
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass
        if len(rows) >= MAX_ENGINE_RECORDS:
            break
    return rows[:MAX_ENGINE_RECORDS]


def alterx_generate(
    hosts: Sequence[str],
    domain: str,
    timeout: float,
    runner: RunCommand,
    which: WhichCommand,
    *,
    cap: int = 5000,
) -> List[Dict[str, Any]]:
    """Generate scope-constrained subdomain permutations with AlterX."""
    binary = which("alterx")
    seeds = sorted({host.lower().rstrip(".") for host in hosts if _in_scope_host(host, domain)})
    if not binary or not seeds:
        return []
    limit = max(1, min(cap, MAX_ENGINE_RECORDS))
    _rc, out, _err = _run(
        runner,
        [binary, "-silent", "-enrich", "-limit", str(limit)],
        timeout,
        "\n".join(seeds),
    )
    rows = []
    seen = set(seeds)
    for match in _HOST_RE.finditer(out or ""):
        host = match.group(0).lower().rstrip(".")
        if host in seen or not _in_scope_host(host, domain):
            continue
        seen.add(host)
        rows.append({"hostname": host, "source": "alterx", "seed_count": len(seeds)})
        if len(rows) >= limit:
            break
    return rows


def uncover_search(
    domain: str,
    query: str,
    engines: str,
    timeout: float,
    runner: RunCommand,
    which: WhichCommand,
    *,
    cap: int = 500,
) -> List[Dict[str, Any]]:
    """Query configured internet-exposure providers through Uncover."""
    binary = which("uncover")
    if not binary:
        return []
    safe_query = str(query or domain).strip()[:1000]
    safe_engines = ",".join(
        part for part in re.findall(r"[a-z0-9-]+", str(engines or "shodan,censys" ).lower())
    ) or "shodan,censys"
    limit = max(1, min(cap, 2000))
    cmd = [binary, "-q", safe_query, "-e", safe_engines, "-json", "-limit", str(limit)]
    _rc, out, _err = _run(runner, cmd, timeout)
    rows = _json_records(out, cap=limit)
    if rows:
        for row in rows:
            row.setdefault("scope_basis", domain)
        return rows
    result = []
    for line in (out or "").splitlines():
        value = line.strip()
        if value and not value.startswith("["):
            result.append({"address": value[:2048], "scope_basis": domain})
        if len(result) >= limit:
            break
    return result


def asnmap_lookup(
    domain: str,
    timeout: float,
    runner: RunCommand,
    which: WhichCommand,
) -> List[Dict[str, Any]]:
    """Map the authorized domain to candidate ASNs and CIDR ranges."""
    binary = which("asnmap")
    if not binary:
        return []
    _rc, out, _err = _run(runner, [binary, "-d", domain, "-json", "-silent"], timeout)
    return _json_records(out, cap=2000)


def _row_values(row: Mapping[str, Any]) -> Iterable[str]:
    for key in ("host", "hostname", "domain", "dns", "ip", "address", "public_ip", "url"):
        value = row.get(key)
        if isinstance(value, (str, int)):
            yield str(value)
        elif isinstance(value, (list, tuple)):
            yield from (str(item) for item in value)


def _known_ip(value: str, known_ips: set) -> bool:
    text = str(value or "").strip()
    try:
        parsed = urlparse(text if "://" in text else "//" + text)
        candidate = parsed.hostname or text
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return candidate in known_ips


def cloudlist_inventory(
    domain: str,
    known_ips: Iterable[str],
    timeout: float,
    runner: RunCommand,
    which: WhichCommand,
) -> List[Dict[str, Any]]:
    """Return only configured-cloud assets correlated to the current scope."""
    binary = which("cloudlist")
    if not binary:
        return []
    _rc, out, _err = _run(runner, [binary, "-json", "-silent"], timeout)
    allowed_ips = {str(value) for value in known_ips if value}
    rows = []
    for row in _json_records(out, cap=MAX_ENGINE_RECORDS):
        values = list(_row_values(row))
        if any(_in_scope_host(value, domain) or _known_ip(value, allowed_ips) for value in values):
            row["scope_correlation"] = domain
            rows.append(row)
    return rows
