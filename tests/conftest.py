"""
Shared pytest fixtures for WAFPierce.

The centerpiece is ``mock_waf``: a tiny in-process HTTP server that behaves like
a target sitting behind a WAF, so engine behavior (baseline, bypass detection,
re-confirmation, repro) can be asserted against real sockets without touching
the network.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
        path = self.path.split('?', 1)[0]
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
        # Unknown paths mirror the baseline (not a bypass).
        return self._send(200, BASELINE_BODY)

    def _send(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
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
