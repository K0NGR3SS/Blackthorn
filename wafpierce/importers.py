"""
Request importers — seed the scanner from recorded traffic.

Feed a HAR capture, a Postman collection, or a Burp items export and WAFPierce
will fuzz those exact (often authenticated) requests instead of only what the
crawler can reach. Each importer returns a list of normalized endpoint dicts:

    {'path': str, 'params': {name: value}, 'method': str,
     'headers': {name: value}, 'body': str|None, 'url': str}

which merge straight into ``scanner.crawl_targets`` / ``seed_targets``.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl

logger = logging.getLogger(__name__)


def _entry(url: str, method: str = 'GET', headers=None, body=None) -> Dict[str, Any]:
    parsed = urlparse(url)
    path = parsed.path or '/'
    if parsed.query:
        path = f"{path}?{parsed.query}"
    params = dict(parse_qsl(parsed.query)) if parsed.query else {}
    return {
        'path': path, 'params': params, 'method': (method or 'GET').upper(),
        'headers': dict(headers or {}), 'body': body, 'url': url,
    }


def from_har(path: str) -> List[Dict[str, Any]]:
    """Parse a HAR (HTTP Archive) file."""
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        har = json.load(f)
    out: List[Dict[str, Any]] = []
    for entry in har.get('log', {}).get('entries', []):
        req = entry.get('request', {})
        url = req.get('url')
        if not url:
            continue
        headers = {h.get('name'): h.get('value') for h in req.get('headers', [])
                   if h.get('name') and not h['name'].startswith(':')}
        body = (req.get('postData') or {}).get('text')
        out.append(_entry(url, req.get('method', 'GET'), headers, body))
    return out


def from_postman(path: str) -> List[Dict[str, Any]]:
    """Parse a Postman v2 collection (recursively, through folders)."""
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        coll = json.load(f)
    out: List[Dict[str, Any]] = []

    def _walk(items):
        for it in items or []:
            if 'item' in it:               # folder
                _walk(it['item'])
                continue
            req = it.get('request')
            if not isinstance(req, dict):
                continue
            url = req.get('url')
            if isinstance(url, dict):
                url = url.get('raw') or ''
            if not url:
                continue
            headers = {h.get('key'): h.get('value') for h in req.get('header', [])
                       if h.get('key')}
            body = (req.get('body') or {}).get('raw')
            out.append(_entry(url, req.get('method', 'GET'), headers, body))

    _walk(coll.get('item', []))
    return out


def from_burp(path: str) -> List[Dict[str, Any]]:
    """Parse a Burp Suite 'Save items' XML export (base64 or plain requests)."""
    import xml.etree.ElementTree as ET

    out: List[Dict[str, Any]] = []
    tree = ET.parse(path)
    for item in tree.getroot().findall('item'):
        url = (item.findtext('url') or '').strip()
        method = (item.findtext('method') or 'GET').strip()
        req_el = item.find('request')
        headers: Dict[str, str] = {}
        body = None
        if req_el is not None and req_el.text:
            raw = req_el.text
            if req_el.get('base64') == 'true':
                try:
                    raw = base64.b64decode(raw).decode('latin-1', 'replace')
                except Exception:
                    raw = ''
            headers, body = _parse_raw_http_headers(raw)
        if url:
            out.append(_entry(url, method, headers, body))
    return out


def _parse_raw_http_headers(raw: str):
    """Pull headers + body out of a raw HTTP request blob."""
    headers: Dict[str, str] = {}
    body = None
    try:
        head, _, body_part = raw.partition('\r\n\r\n')
        if not body_part and '\n\n' in raw:
            head, _, body_part = raw.partition('\n\n')
        lines = head.replace('\r\n', '\n').split('\n')[1:]  # skip request line
        for line in lines:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        body = body_part or None
    except Exception:
        pass
    return headers, body


def load_requests(path: str, fmt: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load requests from ``path``, auto-detecting the format if ``fmt`` is None."""
    fmt = (fmt or '').lower()
    if not fmt:
        low = path.lower()
        if low.endswith('.har'):
            fmt = 'har'
        elif low.endswith('.xml'):
            fmt = 'burp'
        elif low.endswith('.json'):
            # Postman vs HAR both JSON — sniff the content.
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    head = f.read(2048)
                fmt = 'har' if '"log"' in head and '"entries"' in head else 'postman'
            except Exception:
                fmt = 'postman'
        else:
            fmt = 'har'
    try:
        if fmt == 'har':
            return from_har(path)
        if fmt == 'postman':
            return from_postman(path)
        if fmt == 'burp':
            return from_burp(path)
    except Exception as e:
        logger.error(f"Failed to import {fmt} from {path}: {e}")
    return []


# --------------------------------------------------------------------------- #
# Finding importers (P6): bring external scanner *findings* (not requests) into
# the WAFPierce results funnel. Siblings of the request importers above.
# --------------------------------------------------------------------------- #
def from_burp_issues(path: str) -> List[Dict[str, Any]]:
    """Parse a Burp Suite 'Report issues' XML export into canonical findings."""
    import re
    import xml.etree.ElementTree as ET
    from .tooldrivers import burp_issue_to_finding
    findings: List[Dict[str, Any]] = []
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        logger.error(f"Burp issues parse failed for {path}: {e}")
        return []
    for node in root.iter('issue'):
        def _t(tag):
            el = node.find(tag)
            return (el.text or '').strip() if el is not None and el.text else ''
        vclass = _t('vulnerabilityClassifications')
        m = re.search(r'CWE-(\d+)', vclass)
        issue = {
            'name': _t('name'),
            'host': _t('host'),
            'path': _t('path'),
            'severity': _t('severity'),
            'confidence': _t('confidence'),
            'background': _t('issueBackground') or _t('issueDetail'),
            'cwe': m.group(1) if m else '',
        }
        findings.append(burp_issue_to_finding(issue))
    return findings


def load_findings(path: str, fmt: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load scanner findings from a Burp issues XML or a ZAP alerts JSON export,
    auto-detecting the format when ``fmt`` is None. Returns canonical finding dicts."""
    from .tooldrivers import zap_alert_to_finding
    fmt = (fmt or '').lower()
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            head = f.read(4096)
    except Exception:
        head = ''
    if not fmt:
        if '<issues' in head or '<issue>' in head:
            fmt = 'burp'
        elif '"alerts"' in head or '"@name"' in head or '"pluginId"' in head:
            fmt = 'zap'
        elif path.lower().endswith('.xml'):
            fmt = 'burp'
        else:
            fmt = 'zap'
    try:
        if fmt == 'burp':
            return from_burp_issues(path)
        if fmt == 'zap':
            with open(path, encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            alerts = []
            if isinstance(data, dict):
                if isinstance(data.get('alerts'), list):
                    alerts = data['alerts']
                else:
                    for site in (data.get('site') or []):
                        for a in (site.get('alerts') or []):
                            alerts.append(a)
            elif isinstance(data, list):
                alerts = data
            return [zap_alert_to_finding(a) for a in alerts if isinstance(a, dict)]
    except Exception as e:
        logger.error(f"Failed to import findings ({fmt}) from {path}: {e}")
    return []
