"""Tests for TLS/HTTP2 fingerprint impersonation (curl_cffi)."""
import hashlib

import pytest

from wafpierce.pierce import CloudFrontBypasser, _normalize_body

curl_cffi = pytest.importorskip("curl_cffi")


def _baseline(scanner):
    b = scanner._get_baseline()
    assert b is not None
    scanner._baseline_size = len(b.content)
    scanner._baseline_hash = hashlib.md5(b.content).hexdigest()
    scanner._baseline_status = b.status_code
    scanner._baseline_headers = dict(b.headers)
    scanner._baseline_norm = _normalize_body(b.text)
    scanner._baseline_jitter = 0
    scanner._baseline_dynamic = False


def test_impersonation_session_is_active(mock_waf):
    scanner = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=5,
                                 impersonate='chrome')
    assert scanner._impersonating is True
    # Session is the curl_cffi one, not requests.Session.
    assert scanner._session.__class__.__module__.startswith('curl_cffi')


def test_impersonated_scan_detects_bypass(mock_waf):
    # The whole request path must still work through the curl_cffi session.
    scanner = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=5,
                                 impersonate='chrome124')
    _baseline(scanner)
    big = scanner._test_request(path='/big')
    same = scanner._test_request(path='/same')
    assert big['bypass'] is True
    assert same['bypass'] is False
    # Repro command still attached.
    assert big['curl'].startswith('curl ')


def test_invalid_target_falls_back_to_chrome(mock_waf):
    # A nonsense impersonation target must not crash; curl_cffi falls back.
    scanner = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=5,
                                 impersonate='not-a-real-browser-xyz')
    # Either impersonating with the 'chrome' fallback, or degraded to requests —
    # both are acceptable; what matters is the scanner is usable.
    _baseline(scanner)
    assert scanner._test_request(path='/big')['bypass'] is True
