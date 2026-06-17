"""Baseline establishment must not choke on non-2xx roots or UA filtering."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wafpierce.pierce import CloudFrontBypasser


class _ForbiddenHandler(BaseHTTPRequestHandler):
    """Returns 403 to everything (like an edge/WAF gating the root)."""
    def log_message(self, *a, **k):
        pass

    def do_GET(self):
        body = b"403 Forbidden"
        self.send_response(403)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_GET


@pytest.fixture(scope='module')
def forbidden_server():
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _ForbiddenHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_403_root_is_a_valid_baseline(forbidden_server):
    scanner = CloudFrontBypasser(forbidden_server, threads=2, delay=0, timeout=5)
    baseline = scanner._get_baseline()
    # A 403 Response is falsy under bool(), so the engine must check identity.
    assert baseline is not None
    assert baseline.status_code == 403
    assert (baseline is None) is False   # the scan()-level guard


def test_scan_proceeds_past_forbidden_baseline(forbidden_server):
    # The whole scan must get past baseline and complete (no BaselineFailedError).
    scanner = CloudFrontBypasser(forbidden_server, threads=2, delay=0, timeout=5)
    scanner.reconfirm = False
    results = scanner.scan(['security_misconfig'])
    assert isinstance(results, list)
    assert scanner._baseline_status == 403


def test_baseline_uses_session_user_agent(forbidden_server):
    # Baseline must ride the scanner session (Chrome UA), not a bare requests UA.
    scanner = CloudFrontBypasser(forbidden_server, threads=2, delay=0, timeout=5)
    assert 'Chrome' in scanner._session.headers.get('User-Agent', '')
