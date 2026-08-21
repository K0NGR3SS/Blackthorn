"""Browser-workflow engine integration helpers.

This module is intentionally Qt-free.  The GUI uses it to turn one captured
transaction into private, exact-request artifacts for the specialist engines
without ever constructing a shell command.  It also provides fast, side-effect
free readiness checks for the Browser stack.
"""
from __future__ import annotations

import base64
import importlib.util
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional
from urllib.parse import urlparse


MAX_ARTIFACT_BYTES = 5 * 1024 * 1024
_DROP_HEADERS = {
    'connection', 'content-length', 'host', 'proxy-authorization',
    'proxy-connection', 'transfer-encoding',
}


@dataclass(frozen=True)
class BrowserEngineStatus:
    key: str
    name: str
    role: str
    ready: bool
    detail: str
    path: str = ''


STACK_ROLES = (
    ('qtwebengine', 'QtWebEngine + DevTools', 'Manual browser'),
    ('playwright', 'Playwright', 'Automation and sessions'),
    ('proxy', 'Built-in proxy', 'Full capture backend'),
    ('zap_client_spider', 'ZAP Client Spider', 'Authenticated DOM crawler'),
    ('retire', 'Retire.js Site Scanner', 'JavaScript dependency analysis'),
    ('nuclei', 'Nuclei', 'Template validation'),
    ('dalfox', 'Dalfox', 'XSS validation'),
    ('sqlmap', 'sqlmap', 'SQL injection validation'),
    ('interactsh', 'Interactsh', 'Out-of-band validation'),
)


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def quick_stack_statuses(
    *,
    qt_ready: bool = True,
    proxy_running: bool = False,
    zap_running: Optional[bool] = None,
) -> List[BrowserEngineStatus]:
    """Return quick readiness states without version probes or network calls."""
    paths = {
        'retire': shutil.which('retire-site-scanner') or '',
        'nuclei': shutil.which('nuclei') or '',
        'dalfox': shutil.which('dalfox') or '',
        'sqlmap': shutil.which('sqlmap') or shutil.which('sqlmap.py') or '',
    }
    playwright_ready = _module_available('playwright.sync_api')
    rows = []
    for key, name, role in STACK_ROLES:
        path = paths.get(key, '')
        if key == 'qtwebengine':
            ready, detail = qt_ready, ('Embedded Chromium ready' if qt_ready else 'QtWebEngine unavailable')
        elif key == 'playwright':
            ready = playwright_ready
            detail = ('Python package ready' if ready else
                      'Install blackthorn[browser], then run playwright install chromium')
        elif key == 'proxy':
            ready = True
            detail = 'Running' if proxy_running else 'Ready to start'
        elif key == 'zap_client_spider':
            ready = bool(zap_running)
            detail = ('ZAP Client Spider API reachable' if zap_running else
                      ('ZAP API not reachable' if zap_running is False else
                       'Checked when a Client Spider run starts'))
        elif key == 'interactsh':
            ready, detail = True, 'Built-in correlated Interactsh client'
        else:
            ready = bool(path)
            detail = path or 'Not found; configure it in Tool manager'
        rows.append(BrowserEngineStatus(key, name, role, ready, detail, path))
    return rows


def _clean_headers(headers: Optional[Mapping]) -> Dict[str, str]:
    cleaned: Dict[str, str] = {}
    for raw_name, raw_value in (headers or {}).items():
        name = str(raw_name).strip()
        value = str(raw_value).strip()
        if not name or ':' in name or '\r' in name or '\n' in name:
            raise ValueError(f'Invalid HTTP header name: {name!r}')
        if '\r' in value or '\n' in value:
            raise ValueError(f'Invalid HTTP header value for {name!r}')
        cleaned[name] = value
    return cleaned


def normalize_transaction(transaction: Mapping) -> Dict:
    """Validate and normalize a GUI/proxy transaction for engine handoff."""
    method = str(transaction.get('method') or 'GET').strip().upper()
    if not method.isalpha() or len(method) > 16:
        raise ValueError('Invalid HTTP method in captured request.')
    url = str(transaction.get('url') or '').strip()
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Captured request must contain an absolute HTTP(S) URL.')
    headers = _clean_headers(
        transaction.get('reqHeaders') or transaction.get('req_headers')
        or transaction.get('headers') or {}
    )
    body = transaction.get(
        'reqBody', transaction.get('req_body', transaction.get('body', ''))
    )
    if isinstance(body, bytes):
        body = body.decode('utf-8', 'replace')
    elif body is None:
        body = ''
    else:
        body = str(body)
    if len(body.encode('utf-8', 'replace')) > MAX_ARTIFACT_BYTES:
        raise ValueError('Captured request body is too large for an engine handoff.')
    return {
        'method': method,
        'url': url,
        'headers': headers,
        'body': body,
        'status': transaction.get('status', transaction.get('status_code')),
        'response_headers': _clean_headers(
            transaction.get('respHeaders') or transaction.get('resp_headers')
            or transaction.get('response_headers') or {}
        ),
        'response_body': transaction.get(
            'respBody', transaction.get(
                'resp_body', transaction.get('response_body', '')
            )
        ) or '',
    }


def raw_http_request(transaction: Mapping) -> str:
    tx = normalize_transaction(transaction)
    parsed = urlparse(tx['url'])
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    lines = [f"{tx['method']} {path} HTTP/1.1", f'Host: {parsed.netloc}']
    for name, value in tx['headers'].items():
        if name.lower() not in ('host', 'content-length'):
            lines.append(f'{name}: {value}')
    body = tx['body']
    if body and not any(line.lower().startswith('content-length:') for line in lines):
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    return '\r\n'.join(lines) + '\r\n\r\n' + body


def burp_xml(transaction: Mapping) -> str:
    """Create a one-item Burp XML document accepted by Nuclei ``-im burp``."""
    tx = normalize_transaction(transaction)
    parsed = urlparse(tx['url'])
    root = ET.Element('items', {'burpVersion': 'Blackthorn', 'exportTime': ''})
    item = ET.SubElement(root, 'item')
    ET.SubElement(item, 'time').text = ''
    ET.SubElement(item, 'url').text = tx['url']
    ET.SubElement(item, 'host', {'ip': ''}).text = parsed.hostname or ''
    ET.SubElement(item, 'port').text = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
    ET.SubElement(item, 'protocol').text = parsed.scheme
    ET.SubElement(item, 'method').text = tx['method']
    ET.SubElement(item, 'path').text = parsed.path or '/'
    request = ET.SubElement(item, 'request', {'base64': 'true'})
    request.text = base64.b64encode(raw_http_request(tx).encode('utf-8')).decode('ascii')
    status = tx.get('status')
    ET.SubElement(item, 'status').text = str(status or 0)
    response_lines = [f'HTTP/1.1 {status or 0}']
    response_lines.extend(
        f'{name}: {value}' for name, value in tx['response_headers'].items()
    )
    response_raw = '\r\n'.join(response_lines) + '\r\n\r\n' + str(tx['response_body'])
    response = ET.SubElement(item, 'response', {'base64': 'true'})
    response.text = base64.b64encode(response_raw.encode('utf-8')).decode('ascii')
    return ET.tostring(root, encoding='unicode')


def private_artifact_dir(prefix: str = 'blackthorn_browser_') -> str:
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def write_private_text(directory: str, filename: str, content: str) -> str:
    if os.path.basename(filename) != filename:
        raise ValueError('Artifact filename must not contain a directory.')
    encoded = content.encode('utf-8')
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError('Engine artifact is too large.')
    path = os.path.abspath(os.path.join(directory, filename))
    root = os.path.abspath(directory)
    if os.path.commonpath([root, path]) != root:
        raise ValueError('Artifact path escaped its private directory.')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(encoded)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return path


def create_engine_artifacts(transaction: Mapping, directory: str) -> Dict[str, str]:
    return {
        'raw': write_private_text(directory, 'request.http', raw_http_request(transaction)),
        'burp': write_private_text(directory, 'request.xml', burp_xml(transaction)),
    }


def engine_command(
    engine: str,
    executable: str,
    transaction: Mapping,
    artifacts: Mapping[str, str],
    *,
    output_dir: Optional[str] = None,
) -> List[str]:
    """Build an argv-only exact-request command for a supported engine."""
    if not executable:
        raise ValueError(f'{engine} executable is not configured.')
    tx = normalize_transaction(transaction)
    if engine == 'nuclei':
        return [executable, '-l', artifacts['burp'], '-im', 'burp', '-silent', '-jsonl']
    if engine == 'dalfox':
        # Dalfox v3 auto-detects raw-HTTP files in scan mode.
        return [executable, 'scan', artifacts['raw'], '--format', 'jsonl', '--silence']
    if engine == 'sqlmap':
        return [
            executable, '-r', artifacts['raw'], '--batch', '--flush-session',
            '--output-dir', output_dir or os.path.dirname(artifacts['raw']),
        ]
    if engine == 'retire':
        cmd = [executable]
        cookie = ''
        for name, value in tx['headers'].items():
            if name.lower() == 'cookie':
                cookie = value
            elif name.lower() not in _DROP_HEADERS:
                cmd.extend(['--header', f'{name}: {value}'])
        if cookie:
            cmd.extend(['--cookies', cookie])
        cmd.append(tx['url'])
        return cmd
    raise ValueError(f'Unsupported Browser engine: {engine}')


def apply_injection_marker(transaction: Mapping, payload: str, marker: str = 'FUZZ') -> Dict:
    """Replace an explicit marker in an exact request; never guess an injection point."""
    tx = normalize_transaction(transaction)
    replaced = 0
    url = tx['url']
    if marker in url:
        replaced += url.count(marker)
        url = url.replace(marker, payload)
    body = tx['body']
    if marker in body:
        replaced += body.count(marker)
        body = body.replace(marker, payload)
    headers = {}
    for name, value in tx['headers'].items():
        if marker in value:
            replaced += value.count(marker)
            value = value.replace(marker, payload)
        headers[name] = value
    if not replaced:
        raise ValueError(
            f'Add the explicit {marker} marker to the URL, header, or body in Repeater first.'
        )
    return {
        'method': tx['method'], 'url': url, 'headers': headers, 'data': body,
        'marker_replacements': replaced,
    }


def redact_command(argv: Iterable[str], transaction: Optional[Mapping] = None) -> List[str]:
    """Return a display-safe argv. Artifact paths remain visible; secrets do not."""
    secrets = []
    if transaction:
        tx = normalize_transaction(transaction)
        for name, value in tx['headers'].items():
            if name.lower() in ('authorization', 'cookie', 'proxy-authorization', 'x-api-key'):
                secrets.append(value)
    safe = []
    for part in argv:
        text = str(part)
        for secret in secrets:
            if secret:
                text = text.replace(secret, '<redacted>')
        safe.append(text)
    return safe
