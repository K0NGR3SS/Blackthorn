"""
Built-in intercepting HTTP(S) proxy + Repeater backend (P4), Qt-free.

``build_proxy_engine`` returns the best available engine following detect-&-drive:
  1. mitmproxy (if importable)  -> not used unless installed
  2. cryptography (always present) -> BuiltinProxyEngine (stdlib CONNECT MITM)
  3. otherwise -> NullProxyEngine (.available = False)

The engine runs on a daemon thread; the ONLY thing that crosses back to the GUI
is the ``on_flow`` callback, which the GUI marshals to its thread via a queued
signal before touching the database/widgets (cross-thread sqlite/Qt safety, R1).

Recorded flows are plain dicts (see ``_make_flow``) matching the unified
``captured_requests`` schema with ``source='proxy'``.
"""
from __future__ import annotations

import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

_HOP_BY_HOP = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade', 'proxy-connection',
}


def _make_flow(source, method, url, req_headers, req_body, status, resp_headers,
               resp_body, elapsed_ms) -> Dict:
    p = urlparse(url)
    return {
        'source': source,
        'method': method,
        'scheme': p.scheme or 'http',
        'host': p.hostname or '',
        'port': p.port or (443 if p.scheme == 'https' else 80),
        'path': p.path or '/',
        'url': url,
        'req_headers': dict(req_headers or {}),
        'req_body': req_body or b'',
        'status_code': status,
        'resp_headers': dict(resp_headers or {}),
        'resp_body': resp_body or b'',
        'resp_time_ms': elapsed_ms,
        'intercepted': 0,
        'raw_request': build_raw_request(method, url, req_headers, req_body),
    }


def build_raw_request(method, url, headers, body) -> str:
    p = urlparse(url)
    path = p.path or '/'
    if p.query:
        path += '?' + p.query
    lines = [f'{method} {path} HTTP/1.1', f'Host: {p.netloc}']
    for k, v in (headers or {}).items():
        if k.lower() in ('host',):
            continue
        lines.append(f'{k}: {v}')
    raw = '\r\n'.join(lines) + '\r\n\r\n'
    if body:
        try:
            raw += body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body)
        except Exception:
            pass
    return raw


def _forward(method, url, headers, body, proxies=None, timeout=30):
    import requests
    fwd = {k: v for k, v in (headers or {}).items()
           if k.lower() not in _HOP_BY_HOP and k.lower() != 'content-length'}
    t0 = time.time()
    resp = requests.request(method, url, headers=fwd, data=body, allow_redirects=False,
                            verify=False, timeout=timeout, proxies=proxies)
    elapsed = (time.time() - t0) * 1000.0
    return resp.status_code, resp.reason, dict(resp.headers), resp.content, elapsed


def replay(method: str, url: str, headers: Dict, body, proxies=None, timeout=30) -> Dict:
    """Repeater: send one request and return a response dict (no recording)."""
    body_bytes = body.encode('utf-8') if isinstance(body, str) else (body or None)
    try:
        status, reason, rheaders, content, elapsed = _forward(method, url, headers, body_bytes, proxies, timeout)
        return {'ok': True, 'status': status, 'reason': reason, 'headers': rheaders,
                'body': content, 'elapsed_ms': elapsed}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


# --------------------------------------------------------------------------- #
# Engines
# --------------------------------------------------------------------------- #
class NullProxyEngine:
    name = 'null'
    available = False

    def __init__(self, reason: str):
        self.reason = reason
        self.host = None
        self.port = None

    def start(self, host='127.0.0.1', port=8081):
        raise RuntimeError(self.reason)

    def stop(self):
        pass


def _make_handler():
    class _ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        server_version = 'BlackthornProxy/1.0'

        def log_message(self, *a):
            pass

        # ---- plain HTTP (absolute-form request URI) ---- #
        def _handle_plain(self):
            engine = self.server.engine
            url = self.path
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length) if length else None
            try:
                status, reason, rheaders, content, elapsed = _forward(
                    self.command, url, self.headers, body, engine.upstream_proxies)
            except Exception as e:
                self.send_error(502, f'Blackthorn proxy error: {e}')
                return
            self._relay(status, reason, rheaders, content)
            engine.record(_make_flow('proxy', self.command, url, self.headers, body,
                                     status, rheaders, content, elapsed))

        def _relay(self, status, reason, headers, content):
            try:
                self.send_response_only(status, reason)
                for k, v in headers.items():
                    if k.lower() in _HOP_BY_HOP or k.lower() == 'content-length':
                        continue
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Connection', 'close')
                self.end_headers()
                if content:
                    self.wfile.write(content)
            except Exception:
                pass

        do_GET = _handle_plain
        do_POST = _handle_plain
        do_PUT = _handle_plain
        do_DELETE = _handle_plain
        do_HEAD = _handle_plain
        do_OPTIONS = _handle_plain
        do_PATCH = _handle_plain

        # ---- HTTPS MITM via CONNECT ---- #
        def do_CONNECT(self):
            engine = self.server.engine
            host, _, port_s = self.path.partition(':')
            port = int(port_s or 443)
            try:
                self.send_response(200, 'Connection Established')
                self.end_headers()
            except Exception:
                return
            try:
                cert_path, key_path = engine.ca.leaf_for(host)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert_path, key_path)
                tls = ctx.wrap_socket(self.connection, server_side=True)
            except Exception:
                return
            try:
                self._serve_tls(tls, host, port, engine)
            finally:
                try:
                    tls.close()
                except Exception:
                    pass

        def _serve_tls(self, tls, host, port, engine):
            rfile = tls.makefile('rb', buffering=0)
            try:
                request_line = rfile.readline()
                if not request_line:
                    return
                parts = request_line.decode('latin-1').strip().split(' ')
                if len(parts) < 2:
                    return
                method, path = parts[0], parts[1]
                headers = {}
                while True:
                    line = rfile.readline()
                    if not line or line in (b'\r\n', b'\n'):
                        break
                    k, _, v = line.decode('latin-1').partition(':')
                    headers[k.strip()] = v.strip()
                length = int(headers.get('Content-Length', 0) or 0)
                body = rfile.read(length) if length else None
                url = f'https://{host}:{port}{path}' if port != 443 else f'https://{host}{path}'
                try:
                    status, reason, rheaders, content, elapsed = _forward(
                        method, url, headers, body, engine.upstream_proxies)
                except Exception as e:
                    tls.sendall(f'HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(e))}\r\nConnection: close\r\n\r\n{e}'.encode())
                    return
                out = [f'HTTP/1.1 {status} {reason}'.encode('latin-1')]
                for k, v in rheaders.items():
                    if k.lower() in _HOP_BY_HOP or k.lower() == 'content-length':
                        continue
                    out.append(f'{k}: {v}'.encode('latin-1'))
                out.append(f'Content-Length: {len(content)}'.encode('latin-1'))
                out.append(b'Connection: close')
                out.append(b'')
                out.append(content if content else b'')
                tls.sendall(b'\r\n'.join(out))
                engine.record(_make_flow('proxy', method, url, headers, body,
                                         status, rheaders, content, elapsed))
            except Exception:
                pass

    return _ProxyHandler


class BuiltinProxyEngine:
    """Stdlib ThreadingHTTPServer proxy with CONNECT-based HTTPS MITM."""
    name = 'builtin'
    available = True

    def __init__(self, ca, on_flow: Callable[[Dict], None], upstream_proxies=None):
        self.ca = ca
        self.on_flow = on_flow
        self.upstream_proxies = upstream_proxies
        self.server: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.host = None
        self.port = None

    def record(self, flow: Dict):
        try:
            if self.on_flow:
                self.on_flow(flow)
        except Exception:
            pass

    def start(self, host='127.0.0.1', port=8081):
        handler = _make_handler()
        self.server = ThreadingHTTPServer((host, port), handler)
        self.server.engine = self
        self.server.daemon_threads = True
        self.host, self.port = host, self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.host, self.port

    def stop(self):
        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
        except Exception:
            pass
        self.server = None


def build_proxy_engine(ca_dir: str, on_flow, upstream_proxies=None):
    """Return the best available proxy engine (detect-&-drive)."""
    # cryptography is a hard dep, so the builtin engine is normally available.
    try:
        from .proxy_ca import CertAuthority
        ca = CertAuthority(ca_dir)
        return BuiltinProxyEngine(ca, on_flow, upstream_proxies)
    except Exception as e:
        return NullProxyEngine(f'Proxy unavailable (CA init failed): {e}')
