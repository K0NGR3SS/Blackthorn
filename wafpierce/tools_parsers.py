"""
WAFPierce tool output parsers  (findings-normalization layer, tool side).

Each ``parse_*`` function turns one external tool's output into a list of the
SAME canonical finding dict the scanner already produces, so tool findings flow
through the existing Results Explorer / DB / report funnel unchanged.

Contract:  ``parse_x(spec, target, stdout_text, ctx) -> list[dict]``
  * ``spec``        - the ToolSpec
  * ``target``      - the user's original target string
  * ``stdout_text`` - captured stdout/stderr (newline-joined)
  * ``ctx``         - the templating context (holds {outfile}/{out_json} paths)

Parsers are defensive: malformed output degrades to a single INFO "raw" finding
rather than raising. No Qt, no network.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from .tools_registry import ToolSpec


_SEV_MAP = {
    'critical': 'CRITICAL', 'crit': 'CRITICAL',
    'high': 'HIGH',
    'medium': 'MEDIUM', 'moderate': 'MEDIUM', 'med': 'MEDIUM',
    'low': 'LOW',
    'info': 'INFO', 'informational': 'INFO', 'information': 'INFO',
    'unknown': 'INFO', 'none': 'INFO',
}


def norm_severity(value, default: str = 'INFO') -> str:
    if value is None:
        return default
    return _SEV_MAP.get(str(value).strip().lower(), default)


def make_finding(spec: ToolSpec, target: str, *, technique: str,
                 severity: str = 'INFO', reason: str = '', url: str = '',
                 cvss_score: float = 0.0, cve_id: str = '', cwe_id: str = '',
                 reference_url: str = '', payload: str = '',
                 confidence: str = 'medium', **extra) -> Dict:
    """Build a canonical result tagged with tool provenance and proof state."""
    verification = str(extra.get('verification_status') or 'informational')
    kind = str(extra.get('kind') or (
        'suspected' if verification == 'candidate' else 'observation'
    ))
    f = {
        'target': target,
        'technique': f'[{spec.name}] {technique}',
        'category': f'TOOL:{spec.name}',
        'severity': norm_severity(severity),
        'cvss_score': float(cvss_score or 0.0),
        'bypass': False,                       # external/tool findings are informational
        'reason': reason or '',
        'url': url or target,
        'path': extra.get('path', ''),
        'payload': payload or '',
        'response_code': extra.get('response_code'),
        'response_time': extra.get('response_time'),
        'cve_id': cve_id or '',
        'cwe_id': cwe_id or '',
        'reference_url': reference_url or '',
        'confidence': confidence,
        'kind': kind,
        'verification_status': verification,
        'result_type': extra.get('result_type') or (
            'tool_candidate' if verification == 'candidate' else 'tool_observation'
        ),
        'evidence': list(extra.get('evidence') or []),
        'source': f'tool:{spec.key}',
        '_external_source': spec.name,
    }
    return f


def _read_outfile(ctx: Dict, *keys) -> Optional[str]:
    for k in keys:
        p = ctx.get(k)
        if p and os.path.isfile(p):
            try:
                with open(p, encoding='utf-8', errors='replace') as fh:
                    return fh.read()
            except Exception:
                pass
    return None


def _iter_jsonl(text: str):
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line[0] not in '{[':
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


# --------------------------------------------------------------------------- #
# Generic fallback
# --------------------------------------------------------------------------- #
def generic_lines(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    lines = [ln for ln in (text or '').splitlines() if ln.strip()]
    if not lines:
        return []
    sample = '\n'.join(lines[:40])
    return [make_finding(spec, target, technique='output',
                         severity=spec.default_severity,
                         reason=f'{len(lines)} line(s) of output. First lines:\n{sample}')]


# --------------------------------------------------------------------------- #
# ProjectDiscovery family (jsonl on stdout): httpx, subfinder, naabu, dnsx, katana
# --------------------------------------------------------------------------- #
def parse_pd_jsonl(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    out: List[Dict] = []
    for obj in _iter_jsonl(text):
        if not isinstance(obj, dict):
            continue
        host = obj.get('host') or obj.get('input') or obj.get('url') or ''
        bits = []
        for k in ('url', 'host', 'port', 'status_code', 'title', 'tech', 'ip', 'a', 'cname'):
            v = obj.get(k)
            if v:
                bits.append(f'{k}={v if not isinstance(v, list) else ",".join(map(str, v))}')
        out.append(make_finding(spec, target, technique=str(host or 'result'),
                                reason=' | '.join(bits) or json.dumps(obj)[:300],
                                url=obj.get('url') or '',
                                response_code=obj.get('status_code')))
    return out or generic_lines(spec, target, text, ctx)


def parse_nuclei_jsonl(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    out: List[Dict] = []
    for obj in _iter_jsonl(text):
        if not isinstance(obj, dict):
            continue
        info = obj.get('info', {}) if isinstance(obj.get('info'), dict) else {}
        classification = info.get('classification', {}) if isinstance(info.get('classification'), dict) else {}
        cves = classification.get('cve-id') or []
        cwes = classification.get('cwe-id') or []
        ref = info.get('reference') or []
        out.append(make_finding(
            spec, target,
            technique=obj.get('template-id') or info.get('name') or 'nuclei',
            severity=info.get('severity', 'info'),
            reason=f"{info.get('name', '')} @ {obj.get('matched-at') or obj.get('host', '')}".strip(),
            url=obj.get('matched-at') or obj.get('host') or '',
            cvss_score=(classification.get('cvss-score') or 0.0),
            cve_id=(cves[0] if isinstance(cves, list) and cves else (cves or '')),
            cwe_id=(cwes[0] if isinstance(cwes, list) and cwes else (cwes or '')),
            reference_url=(ref[0] if isinstance(ref, list) and ref else (ref or '')),
            confidence='high',
            kind='suspected',
            verification_status='candidate',
            result_type='tool_candidate',
            evidence=[{
                'type': 'external_tool_match',
                'description': (
                    f"Nuclei template {obj.get('template-id') or 'unknown'} matched"
                ),
                'matched': obj.get('matched-at') or obj.get('host') or '',
            }],
        ))
    return out or generic_lines(spec, target, text, ctx)


# --------------------------------------------------------------------------- #
# Recon
# --------------------------------------------------------------------------- #
def parse_nmap_xml(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    import xml.etree.ElementTree as ET
    out: List[Dict] = []
    try:
        root = ET.fromstring(text)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    for host in root.findall('host'):
        addr_el = host.find('address')
        addr = addr_el.get('addr') if addr_el is not None else target
        for port in host.findall('./ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            svc = port.find('service')
            sname = svc.get('name') if svc is not None else ''
            product = (svc.get('product') if svc is not None else '') or ''
            ver = (svc.get('version') if svc is not None else '') or ''
            out.append(make_finding(
                spec, target, technique=f"{addr}:{port.get('portid')}/{port.get('protocol')}",
                reason=f"open {sname} {product} {ver}".strip(),
                severity='INFO', confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


def parse_masscan_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    for entry in data if isinstance(data, list) else []:
        ip = entry.get('ip', '')
        for p in entry.get('ports', []) or []:
            out.append(make_finding(spec, target,
                                    technique=f"{ip}:{p.get('port')}/{p.get('proto')}",
                                    reason=f"open (ttl={p.get('ttl')})", confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


def parse_amass_jsonl(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    for obj in _iter_jsonl(raw):
        if isinstance(obj, dict) and obj.get('name'):
            addrs = ','.join(a.get('ip', '') for a in obj.get('addresses', []) if isinstance(a, dict))
            out.append(make_finding(spec, target, technique=obj['name'],
                                    reason=f'subdomain {addrs}'.strip(), confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


def parse_whatweb_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    out: List[Dict] = []
    try:
        data = json.loads(text) if text.strip().startswith('[') else [json.loads(text)]
    except Exception:
        return generic_lines(spec, target, text, ctx)
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get('plugins', {})
        techs = ', '.join(sorted(plugins.keys())) if isinstance(plugins, dict) else ''
        out.append(make_finding(spec, target, technique='tech stack',
                                url=entry.get('target', target),
                                reason=techs or 'identified technologies', confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


# --------------------------------------------------------------------------- #
# Content discovery
# --------------------------------------------------------------------------- #
def parse_ffuf_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    for r in data.get('results', []) if isinstance(data, dict) else []:
        out.append(make_finding(spec, target, technique=r.get('input', {}).get('FUZZ', r.get('url', '')),
                                url=r.get('url', ''), response_code=r.get('status'),
                                reason=f"status={r.get('status')} len={r.get('length')} words={r.get('words')}",
                                confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


def parse_ferox_jsonl(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    for obj in _iter_jsonl(raw):
        if isinstance(obj, dict) and obj.get('type') == 'response':
            out.append(make_finding(spec, target, technique=obj.get('url', ''),
                                    url=obj.get('url', ''), response_code=obj.get('status'),
                                    reason=f"status={obj.get('status')} len={obj.get('content_length')}",
                                    confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


def parse_gobuster_lines(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    import re
    out: List[Dict] = []
    for ln in (text or '').splitlines():
        ln = ln.strip()
        m = re.match(r'^(/\S+)\s+\(Status:\s*(\d+)\)', ln)
        if m:
            out.append(make_finding(spec, target, technique=m.group(1),
                                    url=target.rstrip('/') + m.group(1),
                                    response_code=int(m.group(2)),
                                    reason=ln, confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


def parse_dirsearch_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    results = data.get('results', data) if isinstance(data, dict) else data
    for r in results if isinstance(results, list) else []:
        if isinstance(r, dict):
            out.append(make_finding(spec, target, technique=r.get('path', r.get('url', '')),
                                    url=r.get('url', ''), response_code=r.get('status'),
                                    reason=f"status={r.get('status')} len={r.get('content-length')}",
                                    confidence='high'))
    return out or generic_lines(spec, target, text, ctx)


# --------------------------------------------------------------------------- #
# Vulnerability scanners
# --------------------------------------------------------------------------- #
def parse_nikto_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    vulns = data.get('vulnerabilities') if isinstance(data, dict) else (data if isinstance(data, list) else [])
    for v in vulns or []:
        if isinstance(v, dict):
            out.append(make_finding(spec, target, technique=v.get('id', 'finding'),
                                    severity='MEDIUM', url=v.get('url', ''),
                                    reason=v.get('msg', ''), confidence='medium',
                                    kind='suspected',
                                    verification_status='candidate',
                                    result_type='tool_candidate'))
    return out or generic_lines(spec, target, text, ctx)


def parse_wpscan_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    if not isinstance(data, dict):
        return generic_lines(spec, target, text, ctx)
    iface = data.get('interesting_findings', []) or []
    for f in iface:
        if isinstance(f, dict):
            out.append(make_finding(spec, target, technique=f.get('type', 'interesting'),
                                    url=f.get('url', ''), reason=' '.join(f.get('to_s', '').split())[:300]))
    for section in ('version', 'main_theme'):
        node = data.get(section)
        if isinstance(node, dict):
            for vuln in node.get('vulnerabilities', []) or []:
                if isinstance(vuln, dict):
                    out.append(make_finding(spec, target, technique=vuln.get('title', 'vuln'),
                                            severity='HIGH', reason=section,
                                            reference_url=(vuln.get('references', {}) or {}).get('url', [''])[0]
                                            if isinstance(vuln.get('references', {}), dict) else '',
                                            kind='suspected',
                                            verification_status='candidate',
                                            result_type='tool_candidate'))
    return out or generic_lines(spec, target, text, ctx)


def parse_dalfox_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    out: List[Dict] = []
    try:
        data = json.loads(text) if text.strip().startswith('[') else list(_iter_jsonl(text))
    except Exception:
        data = list(_iter_jsonl(text))
    for poc in data if isinstance(data, list) else []:
        if isinstance(poc, dict):
            out.append(make_finding(spec, target, technique=poc.get('type', 'XSS'),
                                    severity=norm_severity(poc.get('severity'), 'HIGH'),
                                    url=poc.get('data', poc.get('url', '')),
                                    payload=poc.get('payload', ''),
                                    cwe_id=poc.get('cwe', ''), reason=poc.get('message_str', 'reflected/verified XSS'),
                                    confidence='high', kind='suspected',
                                    verification_status='candidate',
                                    result_type='tool_candidate'))
    return out or generic_lines(spec, target, text, ctx)


def parse_sslyze_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    out: List[Dict] = []
    for sr in (data.get('server_scan_results', []) if isinstance(data, dict) else []):
        loc = sr.get('server_location', {}) if isinstance(sr, dict) else {}
        host = loc.get('hostname', target)
        out.append(make_finding(spec, target, technique=f'TLS scan {host}',
                                reason='SSLyze scan completed; review JSON for weak ciphers/protocols.',
                                confidence='medium'))
    return out or generic_lines(spec, target, text, ctx)


def parse_sqlmap_lines(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    out: List[Dict] = []
    for ln in (text or '').splitlines():
        low = ln.lower()
        if ('is vulnerable' in low or "parameter '" in low and 'vulnerable' in low
                or 'sqlmap identified' in low or 'injectable' in low):
            out.append(make_finding(spec, target, technique='SQL injection', severity='HIGH',
                                    reason=ln.strip(), cwe_id='CWE-89', confidence='high',
                                    kind='suspected',
                                    verification_status='candidate',
                                    result_type='tool_candidate'))
    return out or generic_lines(spec, target, text, ctx)


# --------------------------------------------------------------------------- #
# Cloud & secrets
# --------------------------------------------------------------------------- #
def parse_trufflehog_jsonl(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    out: List[Dict] = []
    for obj in _iter_jsonl(text):
        if isinstance(obj, dict) and (obj.get('DetectorName') or obj.get('Raw')):
            out.append(make_finding(spec, target,
                                    technique=obj.get('DetectorName', 'secret'),
                                    severity='HIGH', cwe_id='CWE-798',
                                    reason=f"verified={obj.get('Verified')} "
                                           f"file={(obj.get('SourceMetadata') or {})}", confidence='high',
                                    kind='suspected',
                                    verification_status='candidate',
                                    result_type='tool_candidate'))
    return out or generic_lines(spec, target, text, ctx)


def parse_gitleaks_json(spec: ToolSpec, target: str, text: str, ctx: Dict) -> List[Dict]:
    raw = _read_outfile(ctx, 'outfile') or text
    out: List[Dict] = []
    try:
        data = json.loads(raw)
    except Exception:
        return generic_lines(spec, target, text, ctx)
    for leak in data if isinstance(data, list) else []:
        if isinstance(leak, dict):
            out.append(make_finding(spec, target, technique=leak.get('RuleID', 'secret'),
                                    severity='HIGH', cwe_id='CWE-798',
                                    reason=f"{leak.get('Description', '')} in "
                                           f"{leak.get('File', '')}:{leak.get('StartLine', '')}",
                                    confidence='high', kind='suspected',
                                    verification_status='candidate',
                                    result_type='tool_candidate'))
    return out or generic_lines(spec, target, text, ctx)
