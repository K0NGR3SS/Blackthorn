"""Tests for the built-in proxy CA, the unified history store, and HTTP proxying (P4)."""
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from wafpierce import proxy as px
from wafpierce.proxy_ca import CertAuthority
from wafpierce.database import WAFPierceDB


def test_ca_creates_and_signs_leaf():
    d = tempfile.mkdtemp()
    ca = CertAuthority(d)
    assert b'BEGIN CERTIFICATE' in ca.ca_cert_pem
    cert_path, key_path = ca.leaf_for('example.com')
    assert os.path.isfile(cert_path) and os.path.isfile(key_path)
    # leaf is cached
    assert ca.leaf_for('example.com') == (cert_path, key_path)
    # verify SAN + issuer
    from cryptography import x509
    with open(cert_path, 'rb') as f:
        leaf = x509.load_pem_x509_certificate(f.read())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert 'example.com' in san.get_values_for_type(x509.DNSName)
    assert leaf.issuer == ca._ca_cert.subject


def test_ca_ip_san():
    ca = CertAuthority(tempfile.mkdtemp())
    cert_path, _ = ca.leaf_for('127.0.0.1')
    from cryptography import x509
    import ipaddress
    with open(cert_path, 'rb') as f:
        leaf = x509.load_pem_x509_certificate(f.read())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address('127.0.0.1') in san.get_values_for_type(x509.IPAddress)


def test_build_proxy_engine_is_builtin():
    eng = px.build_proxy_engine(tempfile.mkdtemp(), on_flow=lambda f: None)
    assert eng.available is True and eng.name == 'builtin'


def test_history_store_roundtrip():
    db = WAFPierceDB(db_path=os.path.join(tempfile.mkdtemp(), 'h.db'))
    flow = px._make_flow('proxy', 'GET', 'http://e/a?b=1', {'X': 'y'}, b'',
                         200, {'Content-Type': 'text/html'}, b'<html>', 12.3)
    rid = db.add_captured_request(flow)
    assert rid
    rows = db.get_captured_requests(limit=10, source='proxy')
    assert rows and rows[0]['host'] == 'e' and rows[0]['status_code'] == 200
    one = db.get_captured_request(rid)
    assert one['url'] == 'http://e/a?b=1'
    assert db.clear_captured_requests('proxy') and not db.get_captured_requests()


def test_build_raw_request():
    raw = px.build_raw_request('POST', 'http://h/p?q=1', {'Content-Type': 'application/json'}, b'{"a":1}')
    assert raw.startswith('POST /p?q=1 HTTP/1.1') and 'Host: h' in raw and '{"a":1}' in raw


def test_http_proxying_records_flow():
    # tiny upstream HTTP server
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            body = b'hello-from-upstream'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    sport = srv.server_address[1]

    flows = []
    eng = px.build_proxy_engine(tempfile.mkdtemp(), on_flow=flows.append)
    host, pport = eng.start('127.0.0.1', 0)
    try:
        import requests
        r = requests.get(f'http://127.0.0.1:{sport}/x',
                         proxies={'http': f'http://127.0.0.1:{pport}'}, timeout=10)
        assert r.status_code == 200 and r.text == 'hello-from-upstream'
        # allow the daemon thread to record
        for _ in range(50):
            if flows:
                break
            time.sleep(0.05)
        assert flows and flows[0]['method'] == 'GET'
        assert flows[0]['status_code'] == 200
        assert flows[0]['resp_body'] == b'hello-from-upstream'
    finally:
        eng.stop()
        srv.shutdown()
