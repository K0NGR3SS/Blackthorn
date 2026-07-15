"""
Shared pytest fixtures for WAFPierce.

The centerpiece is ``mock_waf``: a tiny in-process HTTP server that behaves like
a target sitting behind a WAF, so engine behavior (baseline, bypass detection,
re-confirmation, repro) can be asserted against real sockets without touching
the network.
"""
import threading
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

# Body served at "/" — small and perfectly stable so the scanner learns a
# zero-jitter, non-dynamic baseline.
BASELINE_BODY = b"WAFPIERCE-HOME-BASELINE-PAGE"
# A clearly different, larger body that reads as a content-diff "bypass".
BIG_BODY = b"A" * 2000


class _MockWAFHandler(BaseHTTPRequestHandler):
    # Silence the default stderr request logging during tests.
    def log_message(self, *args, **kwargs):
        pass

    def _respond(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        params = {
            key: values[-1] if values else ''
            for key, values in parse_qs(
                parsed.query, keep_blank_values=True
            ).items()
        }
        # Drain any request body so keep-alive connections stay in sync.
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length:
            self.rfile.read(length)

        # An explicit "bypass" header always wins (simulates a header-based
        # WAF bypass): returns the big distinct body regardless of path.
        if self.headers.get('X-Bypass') == '1':
            return self._send(200, BIG_BODY)

        if path == '/' or path == '/same':
            return self._send(200, BASELINE_BODY)
        if path == '/big':
            return self._send(200, BIG_BODY)
        if path == '/blocked':
            return self._send(403, b"Request blocked by WAF")
        if path == '/endpoint-specific':
            # Deliberately unlike GET /. A matched query control should prevent
            # this ordinary route difference from becoming a finding.
            return self._send(200, b"ENDPOINT-PAGE-" + (b"E" * 1800))
        if path == '/ssti-reflect':
            value = params.get('test', '')
            return self._send(200, f"reflected:{value}".encode())
        if path == '/ssti-evaluate':
            value = params.get('test', '')
            evaluated = self._evaluate_arithmetic(value)
            body = (f"rendered:{evaluated}" if evaluated is not None
                    else "template-input-accepted")
            return self._send(200, body.encode())
        if path == '/command-reflect':
            return self._send(200, f"command:{params.get('cmd', '')}".encode())
        if path == '/db-error':
            if params.get('id') not in ('', 'blackthorn-control'):
                return self._send(
                    500, b"You have an error in your SQL syntax near supplied input"
                )
            return self._send(200, b"database-item-page")
        if path == '/generic-500':
            if params.get('id') not in ('', 'blackthorn-control'):
                return self._send(500, b"The request could not be completed")
            return self._send(200, b"generic-item-page")
        if path == '/oauth/authorize':
            redirect_uri = params.get('redirect_uri', '')
            location = (redirect_uri if 'blackthorn.invalid' in redirect_uri
                        else '/login')
            return self._send(302, b"oauth redirect", {'Location': location})
        # Unknown paths mirror the baseline (not a bypass).
        return self._send(200, BASELINE_BODY)

    @staticmethod
    def _evaluate_arithmetic(value):
        patterns = (
            r'\{\{(\d+)\*(\d+)\}\}',
            r'\$\{(\d+)\*(\d+)\}',
            r'#\{(\d+)\*(\d+)\}',
            r'<%=(\d+)\*(\d+)%>',
            r'\{(\d+)\*(\d+)\}',
            r'\[\[\$\{(\d+)\*(\d+)\}\]\]',
        )
        for pattern in patterns:
            match = re.fullmatch(pattern, value)
            if match:
                return int(match.group(1)) * int(match.group(2))
        return None

    def _send(self, code, body, headers=None):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond


@pytest.fixture(scope='session')
def mock_waf():
    """Start the mock WAF server on an ephemeral port; yield its base URL."""
    server = ThreadingHTTPServer(('127.0.0.1', 0), _MockWAFHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def baselined_scanner(mock_waf):
    """A scanner pointed at the mock WAF with its baseline already established.

    Replicates the baseline-init block of ``scan()`` (multi-sample jitter/dynamic
    learning) without running a full scan, so individual engine methods can be
    exercised in isolation.
    """
    import hashlib
    from wafpierce.pierce import CloudFrontBypasser, _normalize_body

    scanner = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=5)

    baseline = scanner._get_baseline()
    assert baseline is not None, "mock WAF baseline request failed"
    scanner._baseline_size = len(baseline.content)
    scanner._baseline_hash = hashlib.md5(baseline.content).hexdigest()
    scanner._baseline_status = baseline.status_code
    scanner._baseline_headers = dict(baseline.headers)
    scanner._baseline_body_sample = baseline.text[:5000]
    scanner._baseline_norm = _normalize_body(baseline.text)
    scanner._baseline_jitter = 0
    scanner._baseline_dynamic = False
    return scanner
