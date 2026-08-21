"""Reconnaissance engine — external-tool driven.

Unlike the scanner (which is pure-Python), recon **shells out** to best-of-breed
recon binaries and **requires** them to be installed. If any required tool is
missing, recon refuses to run and prints exactly what to install. This is
deliberate: recon quality depends on these tools, so we don't silently degrade
into a half-working scan.

Pipeline::

    subdomains          ->  resolve  ->  http probe  ->  ports/services
    (subfinder + CT)        (dnsx)       (httpx)         (nmap)

Every result is emitted in the same dict shape the scanner uses (``technique`` /
``severity`` / ``reason`` / ``target`` / ``bypass`` …) tagged ``category='recon'``
so recon findings flow through the existing results views and exporters
unchanged.

Runs standalone (the GUI launches it exactly like the scanner, in a subprocess
whose stdout it streams)::

    python -m wafpierce.recon example.com -o out.json

or via the unified CLI::

    blackthorn recon example.com
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urlparse
import urllib.request

logger = logging.getLogger(__name__)

# Make tools downloaded by the in-app installer resolvable on PATH for both this
# process and the recon subprocess (which imports this module), without a restart.
try:
    from .recon_install import ensure_tools_on_path as _ensure_tools_on_path
    _ensure_tools_on_path()
except Exception:  # pragma: no cover - never block recon on installer wiring
    pass

# (binary, label, stage it powers, install hint). Recon will not run unless
# every one of these resolves on PATH. Tweak this list to change requirements.
REQUIRED_TOOLS: List[Tuple[str, str, str, str]] = [
    ('subfinder', 'subfinder', 'passive subdomain enumeration',
     'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'),
    ('dnsx', 'dnsx', 'DNS resolution / liveness',
     'go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest'),
    ('httpx', 'httpx', 'HTTP probing / tech detection',
     'go install github.com/projectdiscovery/httpx/cmd/httpx@latest  '
     '(the ProjectDiscovery binary, not the Python httpx lib)'),
]

# Optional tools. Recon runs fine without them, but each one that is present adds
# a richer stage. The in-app installer can fetch these too.
# (binary, label, stage it powers, install hint).
OPTIONAL_TOOLS: List[Tuple[str, str, str, str]] = [
    ('nmap', 'nmap', 'active port + service/version scan (opt-in)',
     'https://nmap.org/download  (apt install nmap / brew install nmap / choco install nmap)'),
    ('tlsx', 'tlsx', 'TLS certs + extra subdomains from SANs',
     'go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest'),
    ('gau', 'gau', 'historical URLs (wayback/commoncrawl/otx)',
     'go install github.com/lc/gau/v2/cmd/gau@latest'),
    ('katana', 'katana', 'web crawling / endpoint discovery (deep)',
     'go install github.com/projectdiscovery/katana/cmd/katana@latest'),
    ('nuclei', 'nuclei', 'vulnerability & misconfiguration scan (deep)',
     'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'),
    ('dalfox', 'dalfox', 'XSS scanning of URLs with parameters (deep)',
     'go install github.com/hahwul/dalfox/v2@latest'),
    ('arjun', 'Arjun', 'hidden HTTP parameter discovery',
     'pipx install arjun'),
    ('alterx', 'AlterX', 'intelligent subdomain permutations',
     'go install github.com/projectdiscovery/alterx/cmd/alterx@latest'),
    ('uncover', 'Uncover', 'internet exposure search providers',
     'go install github.com/projectdiscovery/uncover/cmd/uncover@latest'),
    ('asnmap', 'ASNMap', 'organization and ASN/CIDR mapping',
     'go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest'),
    ('cloudlist', 'Cloudlist', 'configured cloud account asset inventory',
     'go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest'),
]

# Binary needed by each optional stage key (used by the GUI to know what to
# offer for download when a stage is enabled but its tool is missing).
STAGE_TOOL = {
    'tls': 'tlsx',
    'historical': 'gau',
    'ports': 'nmap',
    'traceroute': 'nmap',
    'crawl': 'katana',
    'nuclei': 'nuclei',
    'xss': 'dalfox',
    'visual': 'httpx',
    'arjun': 'arjun',
    'alterx': 'alterx',
    'uncover': 'uncover',
    'asnmap': 'asnmap',
    'cloudlist': 'cloudlist',
    'takeover': 'nuclei',
}

# A hostname anywhere in noisy tool output. Intentionally permissive; callers
# filter to the in-scope apex afterwards.
_HOST_RE = re.compile(
    r'\b((?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,})\b'
)


def _emit(msg: str) -> None:
    """Print a progress line to stdout, flushed, so the GUI can stream it."""
    print(msg, flush=True)


_RECON_PROGRESS_PREFIX = '::blackthorn-recon-progress::'


def _emit_progress(label: str, progress: int) -> None:
    """Emit a machine-readable Discovery progress update for GUI consumers."""
    event = {
        'label': str(label or 'Discovery').strip()[:160],
        'progress': max(0, min(100, int(progress))),
    }
    _emit(_RECON_PROGRESS_PREFIX + json.dumps(event, separators=(',', ':')))


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
def _which(binary: str) -> Optional[str]:
    """Resolve a tool binary, rejecting the unrelated Python ``httpx`` CLI."""
    if binary != 'httpx':
        return shutil.which(binary)

    candidates = []
    first = shutil.which(binary)
    if first:
        candidates.append(first)
    for directory in os.environ.get('PATH', '').split(os.pathsep):
        if directory:
            candidates.append(os.path.join(directory, binary))
    candidates.extend([
        os.path.expanduser('~/.local/bin/httpx'),
        os.path.expanduser('~/go/bin/httpx'),
    ])

    seen = set()
    for path in candidates:
        path = os.path.abspath(path)
        if path in seen or not (os.path.isfile(path) and os.access(path, os.X_OK)):
            continue
        seen.add(path)
        try:
            check = subprocess.run(
                [path, '-version'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=4,
            )
        except Exception:
            continue
        output = f'{check.stdout}\n{check.stderr}'.lower()
        if check.returncode == 0 and (
                'projectdiscovery' in output or 'current version' in output):
            return path
    return None


def preflight(tools: Sequence[Tuple[str, str, str, str]] = REQUIRED_TOOLS
              ) -> List[Tuple[str, str, str, str]]:
    """Return the subset of ``tools`` that are NOT on PATH (empty == ready)."""
    return [t for t in tools if not _which(t[0])]


def format_preflight_error(missing: Sequence[Tuple[str, str, str, str]]) -> str:
    """A copy-paste-friendly 'install these first' message for missing tools."""
    lines = [
        "Recon requires external tools that are not installed:",
        "",
    ]
    for _bin, label, stage, hint in missing:
        lines.append(f"  [-] {label:<10} ({stage})")
        lines.append(f"        install:  {hint}")
    lines.append("")
    lines.append("Install the tools above, ensure they are on your PATH, then re-run recon.")
    lines.append("Tip: `blackthorn doctor` re-checks recon readiness.")
    return "\n".join(lines)


def _err_tail(err: str, limit: int = 200) -> str:
    """Last meaningful line of a tool's stderr, trimmed — for surfacing failures."""
    err = (err or '').strip()
    if not err:
        return ''
    return err.splitlines()[-1].strip()[:limit]


def diagnostics_banner() -> str:
    """A 'here is exactly what I'm running' banner so it's obvious recon is live
    and which binary each stage resolves to (vs. silently doing nothing)."""
    lines = ['[*] Recon toolchain:']
    for binary, label, _stage, _hint in REQUIRED_TOOLS:
        path = _which(binary)
        lines.append(f"    [{'ok' if path else 'XX'}] {label:<9} "
                     + (path or 'NOT FOUND (required)'))
    for binary, label, stage, _hint in OPTIONAL_TOOLS:
        path = _which(binary)
        lines.append(f"    [{'ok' if path else '..'}] {label:<9} "
                     + (path or f'not installed — {stage} skipped'))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Subprocess helper
# --------------------------------------------------------------------------- #
def _run(cmd: List[str], timeout: float,
         stdin_text: Optional[str] = None) -> Tuple[int, str, str]:
    """Run ``cmd``, capturing stdout/stderr. Never raises — returns a triple
    ``(returncode, stdout, stderr)``. A timeout yields rc 124, missing binary 127."""
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or '', proc.stderr or ''
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode('utf-8', 'replace') if isinstance(e.stdout, bytes) else (e.stdout or '')
        return 124, out, f'timed out after {timeout:.0f}s'
    except FileNotFoundError:
        return 127, '', f'{cmd[0]}: not found on PATH'
    except Exception as e:  # pragma: no cover - defensive
        return 1, '', f'{type(e).__name__}: {e}'


def _extract_hosts(text: str, suffix: str) -> Set[str]:
    """Pull hostnames ending in ``suffix`` out of arbitrary tool output."""
    suffix = suffix.lower().lstrip('.')
    out: Set[str] = set()
    for m in _HOST_RE.finditer(text or ''):
        h = m.group(1).lower().rstrip('.')
        if h == suffix or h.endswith('.' + suffix):
            out.add(h)
    return out


# --------------------------------------------------------------------------- #
# Target normalization
# --------------------------------------------------------------------------- #
def normalize_domain(target: str) -> str:
    """Reduce URLs and wildcard scope notation to an enumeration root.

    ``*.example.com`` is scope notation, not a literal DNS name. External
    enumeration tools expect ``example.com``, so leading wildcard labels are
    deliberately removed.
    """
    target = (target or '').strip()
    if not target:
        return target
    if '://' not in target:
        target = 'http://' + target
    host = (urlparse(target).hostname or '').lower().rstrip('.')
    while host.startswith('*.'):
        host = host[2:]
    return host


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _finding(technique: str, target: str, reason: str,
             severity: str = 'INFO', **extra: Any) -> Dict[str, Any]:
    """A recon result in the scanner's finding shape (so it reuses the same
    results table / exporters). ``bypass=False`` — recon is informational."""
    f: Dict[str, Any] = {
        'bypass': False,
        'category': 'recon',
        'recon': True,
        'kind': 'observation',
        'verification_status': 'informational',
        'technique': technique,
        'target': target,
        'reason': reason,
        'severity': severity,
    }
    f.update(extra)
    return f


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #
def certificate_transparency_hosts(
        domain: str, timeout: float, cap: int = 20000) -> Set[str]:
    """Return in-scope DNS names from public Certificate Transparency logs."""
    query = quote(f'%.{domain}', safe='')
    url = f'https://crt.sh/?q={query}&output=json'
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Blackthorn-recon',
            'Accept': 'application/json',
        },
    )
    try:
        from .recon_install import _urlopen

        with _urlopen(req, timeout=min(timeout, 45.0)) as response:
            raw = response.read(50 * 1024 * 1024 + 1)
        if len(raw) > 50 * 1024 * 1024:
            raise RuntimeError('Certificate Transparency response exceeded 50 MiB')
        rows = json.loads(raw.decode('utf-8', 'replace'))
    except Exception as exc:
        _emit(f"[!] Certificate Transparency: unavailable ({_err_tail(str(exc))})")
        return set()

    hosts: Set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for value in str(row.get('name_value') or '').splitlines():
            host = value.strip().lower().rstrip('.')
            while host.startswith('*.'):
                host = host[2:]
            if host == domain or host.endswith('.' + domain):
                hosts.add(host)
                if len(hosts) >= cap:
                    break
        if len(hosts) >= cap:
            break
    _emit(f"[+] Certificate Transparency: {len(hosts)} host(s)")
    return hosts


def enum_subdomains(domain: str, timeout: float, include_sources: bool = False):
    """Merge Subfinder and CT results with per-host provenance.

    The independent passive sources run concurrently.  Their complete outputs
    are merged only after every source finishes, so the shorter wall-clock time
    does not trade away coverage or source attribution.
    """
    found: Set[str] = {domain}
    sources: Dict[str, Set[str]] = {domain: {'scope root'}}

    _emit(f"[*] subfinder -all -d {domain}")
    _emit(f"[*] Certificate Transparency: querying {domain}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        subfinder_future = executor.submit(
            _run,
            ['subfinder', '-d', domain, '-all', '-silent'],
            timeout,
        )
        ct_future = executor.submit(
            certificate_transparency_hosts, domain, timeout
        )

        rc, out, err = subfinder_future.result()
        ct_hosts = ct_future.result()

    subs = _extract_hosts(out, domain)
    found |= subs
    for host in subs:
        sources.setdefault(host, set()).add('subfinder')
    line = f"[+] subfinder: {len(subs)} host(s)"
    if rc:
        line += f"  (rc={rc})"
        if _err_tail(err):
            line += f"\n    ! {_err_tail(err)}"
    _emit(line)

    found |= ct_hosts
    for host in ct_hosts:
        sources.setdefault(host, set()).add('certificate transparency')

    ordered = sorted(found)
    if include_sources:
        return ordered, {
            host: sorted(sources.get(host, {'unknown'}))
            for host in ordered
        }
    return ordered


def resolve_hosts(hosts: Sequence[str], timeout: float) -> Dict[str, List[str]]:
    """dnsx: keep only hosts that resolve, mapped to their A records."""
    if not hosts:
        return {}
    _emit(f"[*] dnsx: resolving {len(hosts)} host(s)")
    rc, out, err = _run(['dnsx', '-silent', '-a', '-resp', '-json'],
                        timeout, stdin_text='\n'.join(hosts))
    resolved: Dict[str, List[str]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = str(obj.get('host') or obj.get('input') or '').lower().rstrip('.')
        a = obj.get('a') or obj.get('resp') or []
        if isinstance(a, str):
            a = [a]
        if host:
            resolved[host] = sorted({
                str(ip) for ip in a if str(ip).strip()
            })
    msg = f"[+] dnsx: {len(resolved)} live host(s)"
    if rc and not resolved and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return resolved


def probe_http(hosts: Sequence[str], timeout: float) -> List[Dict[str, Any]]:
    """Probe HTTP(S) and retain both responsive and non-responsive hosts."""
    if not hosts:
        return []
    _emit(f"[*] httpx: probing {len(hosts)} host(s)")
    binary = _which('httpx') or 'httpx'
    core_cmd = [
        binary, '-silent', '-json', '-no-color', '-t', '50', '-timeout', '8',
        '-retries', '1', '-status-code', '-title', '-tech-detect',
        '-web-server', '-ip', '-cname', '-location',
    ]
    enrichment = [
        '-favicon', '-jarm', '-hash', 'sha256', '-content-length',
        '-content-type', '-response-time', '-method', '-asn', '-cdn',
    ]
    base_cmd = core_cmd + enrichment
    rc, out, err = _run(
        base_cmd + ['-probe'],
        timeout,
        stdin_text='\n'.join(hosts),
    )
    if rc and not out:
        _emit(
            "[*] httpx: retrying with compatibility flags; the installed "
            "version may not support every enrichment probe"
        )
        rc, out, err = _run(
            core_cmd,
            timeout,
            stdin_text='\n'.join(hosts),
        )
    rows: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        status = row.get('status_code') or row.get('status-code')
        failed = row.get('failed')
        if isinstance(failed, str):
            failed = failed.lower() in ('true', '1', 'yes')
        row['live'] = bool(
            not failed and (
                status is not None
                or str(row.get('url') or '').startswith(('http://', 'https://'))
            )
        )
        rows.append(row)
    live_inputs = {
        _http_row_hostname(row)
        for row in rows if row.get('live')
    }
    live_inputs.discard('')
    live = len(live_inputs)
    unavailable = max(0, len(set(hosts)) - live)
    msg = (
        f"[+] httpx: {live} live web service(s), "
        f"{unavailable} host(s) without an HTTP response"
    )
    if rc and not rows and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return rows


def _parse_nmap_xml(xml_text: str, target: str) -> List[Dict[str, Any]]:
    """Pull open ports + service/version out of `nmap -oX -` output."""
    import xml.etree.ElementTree as ET
    out: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out
    for host in root.findall('host'):
        addr_el = host.find('address')
        addr = addr_el.get('addr') if addr_el is not None else target
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        for port in ports_el.findall('port'):
            state_el = port.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            svc = port.find('service')
            portid = port.get('portid')
            proto = port.get('protocol', 'tcp')
            name = svc.get('name', '') if svc is not None else ''
            product = svc.get('product', '') if svc is not None else ''
            version = svc.get('version', '') if svc is not None else ''
            out.append({
                'host': addr,
                'port': int(portid) if portid and portid.isdigit() else portid,
                'protocol': proto,
                'service': name,
                'product': product.strip(),
                'version': version.strip(),
            })
    return out


def scan_ports(ips: Sequence[str], timeout: float,
               top_ports: int = 100) -> List[Dict[str, Any]]:
    """Opt-in, unprivileged Nmap connect scan with light version detection."""
    uniq = sorted({ip for ip in ips if ip})
    rows: List[Dict[str, Any]] = []
    for ip in uniq:
        _emit(f"[*] nmap -sT -sV --version-light --top-ports {top_ports} {ip}")
        rc, out, err = _run(
            [
                'nmap', '-Pn', '-sT', '-T3', '--top-ports', str(top_ports),
                '-sV', '--version-light', '-oX', '-', ip,
            ],
            timeout)
        parsed = _parse_nmap_xml(out, ip)
        rows.extend(parsed)
        msg = f"[+] nmap {ip}: {len(parsed)} open port(s)"
        if rc:
            msg += f"  (rc={rc})"
            if not parsed and _err_tail(err):
                msg += f"\n    ! {_err_tail(err)}"
        _emit(msg)
    return rows


def _parse_nmap_traceroute_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Parse Nmap XML routes without inventing entries for missing hops."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    routes: List[Dict[str, Any]] = []
    for host in root.findall('host'):
        address_el = host.find("address[@addrtype='ipv4']")
        if address_el is None:
            address_el = host.find('address')
        address = address_el.get('addr', '') if address_el is not None else ''
        trace = host.find('trace')
        if trace is None:
            continue
        hops = []
        for hop in trace.findall('hop'):
            row: Dict[str, Any] = {
                'ip': str(hop.get('ipaddr') or ''),
                'hostname': str(hop.get('host') or ''),
            }
            try:
                row['hop'] = int(hop.get('ttl', ''))
            except (TypeError, ValueError):
                pass
            try:
                row['rtt'] = float(hop.get('rtt', ''))
            except (TypeError, ValueError):
                pass
            if row.get('ip') or row.get('hostname'):
                hops.append(row)
        if hops:
            routes.append({
                'target': address,
                'protocol': str(trace.get('proto') or ''),
                'port': str(trace.get('port') or ''),
                'hops': hops,
            })
    return routes


def trace_routes(ips: Sequence[str], timeout: float) -> List[Dict[str, Any]]:
    """Opt-in Nmap traceroute for measured network paths to resolved hosts."""
    routes: List[Dict[str, Any]] = []
    for ip in sorted({value for value in ips if value}):
        _emit(f"[*] nmap --traceroute {ip}")
        rc, out, err = _run(
            ['nmap', '-sn', '-T3', '-n', '--traceroute', '-oX', '-', ip],
            timeout,
        )
        parsed = _parse_nmap_traceroute_xml(out)
        routes.extend(parsed)
        msg = f"[+] traceroute {ip}: {len(parsed[0]['hops']) if parsed else 0} hop(s)"
        if rc:
            msg += f"  (rc={rc})"
            if not parsed and _err_tail(err):
                msg += f"\n    ! {_err_tail(err)}"
        _emit(msg)
    return routes


# --------------------------------------------------------------------------- #
# Optional stages (run only when the tool is installed)
# --------------------------------------------------------------------------- #
def grab_tls(hosts: Sequence[str], timeout: float) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """tlsx: TLS certificate details + extra hostnames pulled from cert SANs."""
    if not hosts or not _which('tlsx'):
        return [], set()
    _emit(f"[*] tlsx: TLS grab on {len(hosts)} host(s)")
    rc, out, err = _run(['tlsx', '-silent', '-json', '-san', '-cn'],
                        timeout, stdin_text='\n'.join(hosts))
    rows: List[Dict[str, Any]] = []
    sans: Set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        rows.append(obj)
        for d in (obj.get('subject_an') or []):
            d = str(d).lstrip('*.').lower().strip()
            if d:
                sans.add(d)
    msg = f"[+] tlsx: {len(rows)} cert(s), {len(sans)} SAN name(s)"
    if rc and not rows and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return rows, sans


def historical_urls(domain: str, timeout: float, cap: int = 3000) -> List[str]:
    """gau: URLs seen historically (wayback / commoncrawl / otx / urlscan)."""
    if not _which('gau'):
        return []
    _emit(f"[*] gau: historical URLs for {domain}")
    rc, out, err = _run(['gau', '--subs', domain], timeout)
    urls: List[str] = []
    seen: Set[str] = set()
    for u in out.splitlines():
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
            if len(urls) >= cap:
                break
    msg = f"[+] gau: {len(urls)} historical URL(s)"
    if rc and not urls and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return urls


def crawl(urls: Sequence[str], timeout: float, depth: int = 2, cap: int = 3000) -> List[str]:
    """katana: crawl live web roots (incl. JS) for endpoints/URLs."""
    if not urls or not _which('katana'):
        return []
    _emit(f"[*] katana: crawling {len(urls)} root(s) (depth {depth})")
    rc, out, err = _run(['katana', '-silent', '-d', str(depth), '-jc'],
                        timeout, stdin_text='\n'.join(urls))
    found: List[str] = []
    seen: Set[str] = set()
    for u in out.splitlines():
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            found.append(u)
            if len(found) >= cap:
                break
    msg = f"[+] katana: {len(found)} endpoint(s)"
    if rc and not found and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return found


_NUCLEI_SEV = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
               'low': 'LOW', 'info': 'INFO', 'unknown': 'INFO'}


def vuln_scan(urls: Sequence[str], timeout: float,
              severity: str = 'low,medium,high,critical',
              tags: str = '') -> List[Dict[str, Any]]:
    """nuclei: run community templates against the live web services.

    ``severity`` filters by level; ``tags`` (e.g. 'cve,xss,sqli,lfi,rce,exposure,
    takeover') narrows to template categories — both are user-customizable.
    """
    if not urls or not _which('nuclei'):
        return []
    cmd = ['nuclei', '-silent', '-jsonl']
    if severity:
        cmd += ['-severity', severity]
    if tags:
        cmd += ['-tags', tags]
    _emit(f"[*] nuclei: scanning {len(urls)} target(s)  "
          f"(severity={severity or 'all'}{', tags=' + tags if tags else ''}) "
          f"— first run downloads templates")
    rc, out, err = _run(cmd, timeout, stdin_text='\n'.join(urls))
    rows: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    msg = f"[+] nuclei: {len(rows)} finding(s)"
    if rc and not rows and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return rows


def xss_scan(urls: Sequence[str], timeout: float) -> List[Dict[str, Any]]:
    """dalfox: test URLs that carry parameters for reflected/DOM XSS."""
    targets = [u for u in urls if '?' in u and '=' in u]
    if not targets or not _which('dalfox'):
        if urls and _which('dalfox'):
            _emit("[*] dalfox: no URLs with parameters to test for XSS")
        return []
    _emit(f"[*] dalfox: XSS scan on {len(targets)} parameterized URL(s)")
    rc, out, err = _run(
        ['dalfox', 'pipe', '--silence', '--no-color', '--format', 'json'],
        timeout, stdin_text='\n'.join(targets))
    rows: List[Dict[str, Any]] = []
    text = (out or '').strip()
    if text:
        try:
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
        except Exception:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    msg = f"[+] dalfox: {len(rows)} XSS finding(s)"
    if rc and not rows and _err_tail(err):
        msg += f"\n    ! {_err_tail(err)}"
    _emit(msg)
    return rows


def _http_row_hostname(row: Dict[str, Any]) -> str:
    """Best-effort source hostname for one ProjectDiscovery httpx JSON row."""
    for key in ('input', 'host', 'url'):
        value = str(row.get(key) or '').strip()
        if not value:
            continue
        parsed = urlparse(value if '://' in value else '//' + value)
        host = parsed.hostname or ''
        if host:
            return host.lower().rstrip('.')
    return ''


def build_host_inventory(
        domain: str,
        hosts: Sequence[str],
        sources: Dict[str, List[str]],
        resolved: Dict[str, List[str]],
        http_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build a discovered/DNS/HTTP status matrix for the UI and exports."""
    by_host: Dict[str, Dict[str, Any]] = {}
    for row in http_rows:
        host = _http_row_hostname(row)
        if host and row.get('live') and host not in by_host:
            by_host[host] = row

    inventory = []
    for host in sorted(set(hosts)):
        row = by_host.get(host) or {}
        status = row.get('status_code') or row.get('status-code')
        dns_live = host in resolved
        web_live = bool(row)
        inventory.append({
            'hostname': host,
            'is_apex': host == domain,
            'sources': list(sources.get(host, [])),
            'dns_status': 'resolved' if dns_live else 'unresolved',
            'dns_live': dns_live,
            'ip_addresses': list(resolved.get(host, [])),
            'http_status': status,
            'http_url': str(row.get('url') or ''),
            'http_live': web_live,
            'http_state': 'live' if web_live else (
                'no_response' if dns_live else 'not_tested'
            ),
            'title': str(row.get('title') or ''),
            'server': str(row.get('webserver') or row.get('web-server') or ''),
            'technologies': row.get('tech') or row.get('technologies') or [],
        })
    return inventory


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_recon(target: str, *, timeout: float = 300.0, top_ports: int = 100,
              max_hosts: int = 1000, crawl_depth: int = 2,
              nuclei_severity: str = 'low,medium,high,critical', nuclei_tags: str = '',
              do_tls: bool = True, do_historical: bool = True,
              do_crawl: bool = False, do_nuclei: bool = False, do_xss: bool = False,
              do_ports: bool = False, do_traceroute: bool = False,
              do_visual: bool = False, do_arjun: bool = False,
              do_alterx: bool = False,
              do_uncover: bool = False, do_asnmap: bool = False,
              do_cloudlist: bool = False, do_takeover: bool = False,
              uncover_engines: str = 'shodan,censys',
              uncover_query: str = '', artifact_dir: str = '',
              history_dir: str = '') -> Dict[str, Any]:
    """Run the recon pipeline against ``target`` and return a structured report.

    Each optional stage is individually switchable (``do_*``). The ``findings``
    key holds scanner-shaped result dicts; ``stages`` keeps the raw per-tool
    output for anything that wants the detail.
    """
    domain = normalize_domain(target)
    if not domain:
        raise ValueError(f"could not parse a hostname from target {target!r}")

    enabled = [n for n, on in (
        ('tls', do_tls), ('gau', do_historical),
        ('katana', do_crawl), ('nuclei', do_nuclei), ('dalfox', do_xss),
        ('nmap', do_ports), ('traceroute', do_traceroute),
        ('httpx-visual', do_visual), ('arjun', do_arjun),
        ('alterx', do_alterx),
        ('uncover', do_uncover), ('asnmap', do_asnmap),
        ('cloudlist', do_cloudlist), ('takeover', do_takeover),
    ) if on]
    _emit(diagnostics_banner())
    _emit_progress('Starting discovery', 2)
    _emit(f"[*] Recon target: {domain}  (stages: subfinder, CT, dnsx, httpx"
          + (', ' + ', '.join(enabled) if enabled else '') + ')')
    findings: List[Dict[str, Any]] = []

    # 1. Passive subdomains (Subfinder + Certificate Transparency).
    _emit_progress('Enumerating subdomains', 8)
    subdomains, host_sources = enum_subdomains(
        domain, timeout, include_sources=True
    )

    # 1b. Pattern-aware candidates remain separate until dnsx validates them.
    from .recon_engines import (
        alterx_generate,
        arjun_scan,
        asnmap_lookup,
        cloudlist_inventory,
        uncover_search,
        visual_probe,
    )

    alterx_rows: List[Dict[str, Any]] = []
    if do_alterx:
        _emit_progress('Generating DNS mutations', 16)
        alterx_rows = alterx_generate(
            subdomains, domain, timeout, _run, _which
        )
        _emit(f"[+] alterx: {len(alterx_rows)} scoped permutation candidate(s)")
    # 2. Resolve
    _emit_progress('Resolving DNS', 24)
    resolved = resolve_hosts(subdomains, timeout)
    if alterx_rows:
        mutation_candidate_set = {
            str(row.get('hostname') or '').lower().rstrip('.')
            for row in alterx_rows if isinstance(row, dict)
        }
        mutation_candidate_set.discard('')
        mutation_candidates = sorted(mutation_candidate_set - set(subdomains))
        mutation_resolved = resolve_hosts(mutation_candidates, timeout)
        for host in mutation_resolved:
            host_sources.setdefault(host, []).extend(['alterx', 'dnsx'])
        resolved.update(mutation_resolved)
        subdomains = sorted(set(subdomains) | set(mutation_resolved))
        _emit(
            f"[+] dnsx: validated {len(mutation_resolved)} AlterX candidate(s)"
        )

    uncover_rows: List[Dict[str, Any]] = []
    if do_uncover:
        _emit_progress('Querying exposure providers', 30)
        uncover_rows = uncover_search(
            domain, uncover_query or domain, uncover_engines,
            timeout, _run, _which,
        )
        _emit(f"[+] uncover: {len(uncover_rows)} exposure candidate(s)")

    asnmap_rows: List[Dict[str, Any]] = []
    if do_asnmap:
        asnmap_rows = asnmap_lookup(domain, timeout, _run, _which)
        _emit(f"[+] asnmap: {len(asnmap_rows)} ASN/CIDR mapping(s)")

    # 2b. TLS certs (tlsx, optional) — also harvests extra subdomains from SANs.
    tls_rows: List[Dict[str, Any]] = []
    if do_tls:
        _emit_progress('Inspecting TLS certificates', 38)
        tls_rows, sans = grab_tls(sorted(resolved.keys()) or subdomains, timeout)
        new_sans = sorted({s for s in sans
                           if s == domain or s.endswith('.' + domain)} - set(subdomains))
        if new_sans:
            for host in new_sans:
                host_sources.setdefault(host, []).append('TLS SAN')
            resolved.update(resolve_hosts(new_sans, timeout))
            subdomains = sorted(set(subdomains) | set(new_sans))
            findings.append(_finding(
                'TLS SAN Subdomains', domain,
                f"{len(new_sans)} extra subdomain(s) discovered via TLS certificates",
                subdomains=new_sans))

    subdomain_count = sum(1 for host in subdomains if host != domain)
    findings.append(_finding(
        'Subdomain Enumeration', domain,
        f"{subdomain_count} subdomain(s) discovered plus the scope root",
        subdomains=subdomains, sources=host_sources))

    for cert in tls_rows:
        host = cert.get('host') or domain
        cn = cert.get('subject_cn') or '?'
        issuer = cert.get('issuer_cn') or cert.get('issuer_org') or ''
        findings.append(_finding(
            'TLS Certificate', str(host),
            f"CN={cn}" + (f"  issuer={issuer}" if issuer else ''), tls=cert))

    # Cap the actively-probed host set. Wildcard DNS or a huge domain can resolve
    # thousands of hosts; probing them all stalls httpx/nmap and floods the table.
    # Always probe the apex + www first so the cap never skips the real site for
    # alphabetically-earlier junk (e.g. 0000.example.com).
    priority = [h for h in (domain, 'www.' + domain) if h in resolved]
    active = priority + [h for h in sorted(resolved.keys()) if h not in priority]
    if len(active) > max_hosts:
        _emit(f"[!] {len(active)} hosts resolved — actively probing the apex + first "
              f"{max_hosts} (raise --max-hosts to probe more)")
        findings.append(_finding(
            'Recon Scope', domain,
            f"{len(active)} hosts resolved; actively probing {max_hosts} (apex prioritized)"))
        active = active[:max_hosts]

    all_ips: Set[str] = set()
    for host in active:
        ips = resolved.get(host, [])
        all_ips.update(ips)
        findings.append(_finding(
            'DNS Resolution', host,
            f"{host} -> {', '.join(ips) if ips else 'no A record'}",
            ip_addresses=ips))

    cloudlist_rows: List[Dict[str, Any]] = []
    if do_cloudlist:
        cloudlist_rows = cloudlist_inventory(
            domain, all_ips, timeout, _run, _which
        )
        _emit(
            f"[+] cloudlist: {len(cloudlist_rows)} configured-cloud asset(s) "
            "correlated to scope"
        )

    # 3. HTTP probe (httpx)
    _emit_progress('Probing HTTP services', 48)
    web = probe_http(active or subdomains, timeout)
    live_web = [row for row in web if row.get('live')]
    live_urls: List[str] = []
    for row in live_web:
        url = row.get('url') or row.get('input') or ''
        if url:
            live_urls.append(url)
        status = row.get('status_code') or row.get('status-code')
        title = row.get('title') or ''
        server = row.get('webserver') or row.get('web-server') or ''
        tech = row.get('tech') or row.get('technologies') or []
        bits = [b for b in (f"HTTP {status}" if status else '', server,
                            (', '.join(tech) if tech else '')) if b]
        findings.append(_finding(
            'HTTP Service', url or row.get('host', domain),
            f"{title or 'live'} — {' | '.join(bits)}" if bits else (title or 'live web service'),
            http_status=status, title=title, server=server, tech=tech))
    live_urls = list(dict.fromkeys(live_urls))

    visual_rows: List[Dict[str, Any]] = []
    if do_visual and live_urls:
        visual_rows = visual_probe(
            live_urls, domain, timeout, _run, _which,
            artifact_dir=artifact_dir,
        )
        _emit(
            f"[+] httpx visual: {len(visual_rows)} screenshot/fingerprint record(s)"
        )

    inventory = build_host_inventory(
        domain,
        subdomains,
        host_sources,
        resolved,
        live_web,
    )
    for host in inventory:
        state_bits = [
            (
                'DNS: ' + ', '.join(host['ip_addresses'])
                if host['dns_live'] else 'DNS: unresolved'
            ),
        ]
        if host['http_live']:
            status = host.get('http_status')
            state_bits.append(
                f"HTTP: live{f' ({status})' if status is not None else ''}"
            )
        elif host['dns_live']:
            state_bits.append('HTTP: no response')
        state_bits.append(
            'Sources: ' + ', '.join(host.get('sources') or ['unknown'])
        )
        findings.append(_finding(
            'Discovered Host',
            host['hostname'],
            ' · '.join(state_bits),
            discovery=host,
            dns_status=host['dns_status'],
            http_status=host.get('http_status'),
            http_live=host['http_live'],
            sources=host.get('sources') or [],
        ))

    # 3b. Historical URLs (gau, optional)
    _emit_progress('Discovering application content', 60)
    historical: List[str] = []
    if do_historical:
        historical = historical_urls(domain, timeout)
        if historical:
            findings.append(_finding(
                'Historical URLs', domain,
                f"{len(historical)} URL(s) from wayback/commoncrawl/otx",
                urls=historical, sample=historical[:50]))

    # 3c. Crawl (katana)
    endpoints: List[str] = []
    if do_crawl and live_urls:
        endpoints = crawl(live_urls, timeout, depth=crawl_depth)
        if endpoints:
            findings.append(_finding(
                'Crawled Endpoints', domain,
                f"{len(endpoints)} endpoint(s) discovered by crawling live sites",
                endpoints=endpoints, sample=endpoints[:50]))

    # 3c.1. Parameter intelligence consumes only already-scoped URLs.
    arjun_rows: List[Dict[str, Any]] = []
    if do_arjun:
        _emit_progress('Discovering hidden parameters', 70)
        parameter_targets = list(dict.fromkeys(
            [url for url in endpoints + historical if '?' in url]
            + live_urls
        ))
        arjun_rows = arjun_scan(
            parameter_targets, domain, timeout, _run, _which
        )
        _emit(f"[+] Arjun: {len(arjun_rows)} parameter result(s)")

    # 3e. Vulnerabilities (nuclei)
    if do_nuclei or do_takeover or do_xss:
        _emit_progress('Checking vulnerabilities', 78)
    vulns: List[Dict[str, Any]] = []
    if do_nuclei and live_urls:
        scan_targets = list(dict.fromkeys(live_urls + endpoints))[:500]
        vulns = vuln_scan(scan_targets, timeout,
                          severity=nuclei_severity, tags=nuclei_tags)
        for vrow in vulns:
            info = vrow.get('info') or {}
            raw_sev = str(info.get('severity', 'info')).lower()
            sev = _NUCLEI_SEV.get(raw_sev, 'INFO')
            name = info.get('name') or vrow.get('template-id') or 'nuclei finding'
            matched = vrow.get('matched-at') or vrow.get('host') or vrow.get('url') or domain
            tid = vrow.get('template-id') or vrow.get('templateID') or ''
            findings.append(_finding(
                f"Vuln: {name}", str(matched),
                f"[{raw_sev}] {name}" + (f"  ({tid})" if tid else ''),
                severity=sev, template_id=tid, nuclei=vrow))

    takeovers: List[Dict[str, Any]] = []
    if do_takeover and subdomains:
        takeover_targets = [f"https://{host}" for host in subdomains[:500]]
        takeovers = vuln_scan(
            takeover_targets,
            timeout,
            severity='info,low,medium,high,critical',
            tags='takeover',
        )
        for row in takeovers:
            info = row.get('info') or {}
            matched = (
                row.get('matched-at') or row.get('host') or row.get('url')
                or domain
            )
            findings.append(_finding(
                'Subdomain Takeover Candidate', str(matched),
                str(info.get('name') or row.get('template-id') or 'takeover template matched'),
                severity='HIGH', source_tool='takeover', takeover=row,
            ))

    # 3f. XSS (dalfox) — tests URLs (live + crawled + historical) that carry params
    xss: List[Dict[str, Any]] = []
    if do_xss:
        xss_targets = list(dict.fromkeys(live_urls + endpoints + historical))[:1500]
        xss = xss_scan(xss_targets, timeout)
        for row in xss:
            data = row.get('data') or row.get('poc') or row.get('evidence') or ''
            param = row.get('param') or ''
            findings.append(_finding(
                'XSS', str(data or domain),
                f"XSS via param '{param}'" if param else 'XSS finding',
                severity='HIGH', param=param, dalfox=row))

    # 4. Ports / services (nmap) — cap IPs so a big resolve set doesn't run forever.
    if do_ports or do_traceroute:
        _emit_progress('Inspecting network services', 88)
    ports: List[Dict[str, Any]] = []
    if do_ports:
        nmap_ips = sorted(all_ips)[:min(10, max_hosts)]
        if len(all_ips) > len(nmap_ips):
            _emit(f"[!] {len(all_ips)} IP(s) resolved — port-scanning the first {len(nmap_ips)}")
        ports = scan_ports(nmap_ips, timeout, top_ports=top_ports)
        for p in ports:
            svc = ' '.join(x for x in (p.get('service'), p.get('product'),
                                       p.get('version')) if x)
            findings.append(_finding(
                'Open Port', f"{p['host']}:{p['port']}",
                f"{p['port']}/{p.get('protocol', 'tcp')} open"
                + (f" — {svc}" if svc else ''),
                severity='LOW', port=p.get('port'), service=p.get('service'),
                product=p.get('product'), version=p.get('version')))

    routes: List[Dict[str, Any]] = []
    if do_traceroute:
        route_ips = sorted(all_ips)[:min(25, max_hosts)]
        if len(all_ips) > len(route_ips):
            _emit(
                f"[!] {len(all_ips)} IP(s) resolved — tracing the first "
                f"{len(route_ips)}"
            )
        routes = trace_routes(route_ips, timeout)
        findings.append(_finding(
            'Network Paths', domain,
            f"{len(routes)} measured traceroute path(s)",
            severity='INFO', routes=len(routes),
        ))

    summary = {
        'subdomains': subdomain_count,
        'hosts_total': len(subdomains),
        'dns_live': len(resolved),
        'web_live': sum(1 for host in inventory if host['http_live']),
        'dns_without_http': sum(
            1 for host in inventory
            if host['dns_live'] and not host['http_live']
        ),
        'unresolved': sum(1 for host in inventory if not host['dns_live']),
        'routes': len(routes),
    }
    _emit_progress('Correlating attack-surface changes', 96)
    _emit(f"[+] Recon complete: {subdomain_count} subdomains, {len(resolved)} resolved, "
          f"{summary['web_live']} web hosts, {len(historical)} historical URLs, "
          f"{len(endpoints)} crawled, {len(arjun_rows)} parameter results, "
          f"{len(vulns)} vulns, {len(xss)} XSS, {len(ports)} open ports, "
          f"{len(routes)} routes")

    report = {
        'target': domain,
        'findings': findings,
        'stages': {
            'subdomains': subdomains,
            'sources': host_sources,
            'resolved': resolved,
            'hosts': inventory,
            'summary': summary,
            'tls': tls_rows,
            'http': web,
            'historical': historical,
            'endpoints': endpoints,
            'vulns': vulns,
            'xss': xss,
            'ports': ports,
            'traceroute': routes,
            'visual': visual_rows,
            'arjun': arjun_rows,
            'alterx': alterx_rows,
            'uncover': uncover_rows,
            'asnmap': asnmap_rows,
            'cloudlist': cloudlist_rows,
            'takeovers': takeovers,
            'coverage': {
                'dns': True,
                'http': True,
                'ports': bool(do_ports),
                'tls': bool(do_tls),
                'routes': bool(do_traceroute),
                'content': bool(do_crawl or do_historical),
                'vulnerabilities': bool(do_nuclei or do_xss or do_takeover),
                'visual': bool(do_visual),
                'api': bool(do_arjun),
                'mutations': bool(do_alterx),
                'exposure': bool(do_uncover or do_asnmap or do_cloudlist),
                'takeovers': bool(do_takeover),
            },
        },
    }
    from .discovery_intelligence import apply_continuous_intelligence

    apply_continuous_intelligence(report, history_dir=history_dir)
    for signal in report['stages'].get('risk_signals') or []:
        findings.append(_finding(
            'Risk Correlation', str(signal.get('target') or domain),
            str(signal.get('reason') or 'Correlated attack-surface signal'),
            severity=str(signal.get('severity') or 'LOW'),
            source_tool='risk', risk=signal,
        ))
    _emit_progress('Discovery complete', 100)
    return report


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='blackthorn recon',
        description='External-tool reconnaissance (subfinder/CT/dnsx/httpx/nmap).')
    p.add_argument('target', help='domain or URL, e.g. example.com or https://example.com')
    p.add_argument('-o', '--output', help='write findings JSON to this file')
    p.add_argument(
        '--report-output',
        help='write the full host inventory and findings report to this file',
    )
    p.add_argument('--timeout', type=float, default=300.0,
                   help='per-tool timeout in seconds (default: 300)')
    p.add_argument('--top-ports', type=int, default=100,
                   help='nmap top-ports count (default: 100)')
    p.add_argument('--max-hosts', type=int, default=1000,
                   help='max resolved hosts to actively probe with httpx (default: 1000)')
    p.add_argument('--crawl-depth', type=int, default=2,
                   help='katana crawl depth (default: 2)')
    p.add_argument('--nuclei-severity', default='low,medium,high,critical',
                   help='nuclei severities to report (default: low,medium,high,critical)')
    p.add_argument('--nuclei-tags', default='',
                   help='nuclei template tags, e.g. cve,xss,sqli,lfi,rce,exposure,takeover')
    # Per-stage switches (on-by-default extras vs opt-in active/heavy stages)
    p.add_argument(
        '--ports',
        action='store_true',
        help='opt in to an active Nmap connect/service scan (disabled by default)',
    )
    p.add_argument(
        '--traceroute',
        action='store_true',
        help='opt in to Nmap network-path discovery for topology hop data',
    )
    p.add_argument(
        '--no-ports',
        action='store_true',
        help=argparse.SUPPRESS,
    )
    p.add_argument('--no-tls', action='store_true', help='skip tlsx TLS/SAN stage')
    p.add_argument('--no-historical', action='store_true', help='skip gau historical URLs')
    p.add_argument('--no-extras', action='store_true',
                   help='skip all default extras (tlsx + gau)')
    p.add_argument('--crawl', action='store_true', help='enable katana crawl')
    p.add_argument('--nuclei', action='store_true', help='enable nuclei vuln scan')
    p.add_argument('--xss', action='store_true', help='enable dalfox XSS scan')
    p.add_argument('--visual', action='store_true',
                   help='enable httpx screenshots and visual/fingerprint enrichment')
    p.add_argument('--arjun', action='store_true',
                   help='enable hidden HTTP parameter discovery')
    p.add_argument('--alterx', action='store_true',
                   help='generate intelligent subdomain permutation candidates')
    p.add_argument('--uncover', action='store_true',
                   help='query configured internet exposure search providers')
    p.add_argument('--uncover-engines', default='shodan,censys',
                   help='comma-separated Uncover provider engines')
    p.add_argument('--uncover-query', default='',
                   help='provider search query (default: authorized root domain)')
    p.add_argument('--asnmap', action='store_true',
                   help='map the domain to candidate ASNs and CIDRs')
    p.add_argument('--cloudlist', action='store_true',
                   help='correlate configured-cloud inventory to the target scope')
    p.add_argument('--takeover', action='store_true',
                   help='run dedicated Nuclei takeover templates against scoped hosts')
    p.add_argument('--artifact-dir', default='',
                   help='directory for screenshot artifacts')
    p.add_argument('--history-dir', default='',
                   help='directory for secret-free continuous discovery snapshots')
    p.add_argument('--no-history', action='store_true',
                   help='disable continuous discovery snapshots and run-to-run diffs')
    p.add_argument('--advanced-discovery', action='store_true',
                   help='enable visual, crawl, parameter, mutation, exposure, ASN, and takeover stages')
    p.add_argument('--deep', action='store_true',
                   help='convenience: enable katana crawl + nuclei + dalfox')
    p.add_argument('--json', action='store_true',
                   help='also print the findings list as JSON to stdout')
    p.add_argument('--skip-preflight', action='store_true',
                   help='do not abort when required tools are missing (best-effort)')
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    missing = preflight()
    if missing and not args.skip_preflight:
        print(format_preflight_error(missing), file=sys.stderr)
        return 2
    if missing:
        _emit("[!] Proceeding with missing tools (--skip-preflight); results will be partial.")

    try:
        if args.no_history:
            history_dir = ''
        elif args.history_dir:
            history_dir = args.history_dir
        else:
            from .config import ensure_config_dir

            history_dir = os.path.join(
                ensure_config_dir(), 'discovery-history'
            )
        report = run_recon(
            args.target,
            timeout=args.timeout,
            top_ports=args.top_ports,
            max_hosts=args.max_hosts,
            crawl_depth=args.crawl_depth,
            nuclei_severity=args.nuclei_severity,
            nuclei_tags=args.nuclei_tags,
            do_tls=not (args.no_tls or args.no_extras),
            do_historical=not (args.no_historical or args.no_extras),
            do_crawl=args.crawl or args.deep or args.advanced_discovery,
            do_nuclei=args.nuclei or args.deep,
            do_xss=args.xss or args.deep,
            do_ports=args.ports and not args.no_ports,
            do_traceroute=args.traceroute,
            do_visual=args.visual or args.advanced_discovery,
            do_arjun=args.arjun or args.advanced_discovery,
            do_alterx=args.alterx or args.advanced_discovery,
            do_uncover=args.uncover or args.advanced_discovery,
            do_asnmap=args.asnmap or args.advanced_discovery,
            do_cloudlist=args.cloudlist,
            do_takeover=args.takeover or args.advanced_discovery,
            uncover_engines=args.uncover_engines,
            uncover_query=args.uncover_query,
            artifact_dir=args.artifact_dir,
            history_dir=history_dir,
        )
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    findings = report['findings']

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, default=str)
            _emit(f"[+] Wrote {len(findings)} finding(s) to {args.output}")
        except Exception as e:
            print(f"[!] Failed to write {args.output}: {e}", file=sys.stderr)
            return 1

    if args.report_output:
        try:
            with open(args.report_output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            _emit(
                f"[+] Wrote full discovery report to {args.report_output}"
            )
        except Exception as e:
            print(
                f"[!] Failed to write {args.report_output}: {e}",
                file=sys.stderr,
            )
            return 1

    if args.json or not (args.output or args.report_output):
        print(json.dumps(findings, indent=2, default=str))

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
