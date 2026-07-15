"""Tests for v1.6 engine controls: CVSS, scope, safe-mode, jitter, proxy pool."""
import time

import requests

from wafpierce.cvss import score, annotate, cwe_for
from wafpierce.pierce import CloudFrontBypasser


# -- CVSS ----------------------------------------------------------------- #
def test_cvss_score_by_severity():
    s, vec, _ = score({'severity': 'CRITICAL'})
    assert s == 9.8 and vec.startswith('CVSS:3.1/')
    assert score({'severity': 'INFO'})[0] == 0.0


def test_cvss_cwe_mapping():
    assert cwe_for({'technique': 'SQLi bypass', 'category': 'INJECTION'}) == 'CWE-89'
    assert cwe_for({'technique': 'OOB-CONFIRMED SSRF', 'category': 'OOB'}) == 'CWE-918'
    assert cwe_for({'technique': 'nothing', 'category': 'X'}) is None


def test_cvss_annotate_in_place():
    results = [{'severity': 'HIGH', 'technique': 'XSS bypass', 'category': 'INJECTION'}]
    annotate(results)
    assert results[0]['cvss_score'] == 7.5
    assert results[0]['cwe_id'] == 'CWE-79'
    assert 'cvss_vector' in results[0]


def test_cvss_does_not_clobber_existing():
    results = [{'severity': 'HIGH', 'cvss_score': 6.1}]
    annotate(results)
    assert results[0]['cvss_score'] == 6.1


# -- scope ---------------------------------------------------------------- #
def test_scope_exclude_wins(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3,
                           scope={'exclude': [r'/admin']})
    assert s._in_scope(f"{mock_waf}/public") is True
    assert s._in_scope(f"{mock_waf}/admin/panel") is False


def test_scope_include_restricts(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3,
                           scope={'include': [r'/api/']})
    assert s._in_scope(f"{mock_waf}/api/v1/users") is True
    assert s._in_scope(f"{mock_waf}/marketing") is False


def test_no_scope_allows_all(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3)
    assert s._in_scope(f"{mock_waf}/anything") is True


def test_external_active_request_requires_authorization_pattern(mock_waf):
    class RecordingSession:
        def __init__(self):
            self.calls = []

        def request(self, **kwargs):
            self.calls.append(kwargs)
            response = requests.Response()
            response.status_code = 200
            response.url = kwargs['url']
            return response

    scanner = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3)
    scanner._recon_session = RecordingSession()
    assert scanner._scoped_safe_request('https://related.invalid/') is None
    assert scanner._recon_session.calls == []

    scanner.authorization_patterns = ['https://related.invalid']
    assert scanner._scoped_safe_request('https://related.invalid/') is not None
    assert len(scanner._recon_session.calls) == 1


def test_passive_lookup_uses_sterile_session_without_active_authorization(mock_waf):
    class RecordingSession:
        def request(self, **kwargs):
            response = requests.Response()
            response.status_code = 200
            response.url = kwargs['url']
            return response

    scanner = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3)
    scanner._recon_session = RecordingSession()
    response = scanner._scoped_safe_request(
        'https://passive.invalid/query', passive_lookup=True
    )
    assert response is not None and response.status_code == 200


# -- safe mode ------------------------------------------------------------ #
def test_safe_mode_skip_set_is_populated():
    assert '_test_race_condition' in CloudFrontBypasser.SAFE_MODE_SKIP
    assert '_test_smuggling_cl0' in CloudFrontBypasser.SAFE_MODE_SKIP


def test_safe_mode_flag_stored(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3, safe_mode=True)
    assert s.safe_mode is True


# -- max-time budget ------------------------------------------------------ #
def test_max_time_stops_before_techniques(mock_waf, capsys):
    # A microscopic budget expires before the technique loop starts, so it
    # breaks on the first iteration and reports the remaining count.
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3)
    s.reconfirm = False
    s.max_time = 1e-6
    results = s.scan(['injection_testing', 'header_manipulation'])
    out = capsys.readouterr().out
    assert '--max-time' in out and 'reached' in out
    assert 'skipping' in out
    assert isinstance(results, list)


def test_max_time_zero_is_unlimited(mock_waf):
    # Default (0) must not impose any limit / break early.
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3)
    assert getattr(s, 'max_time', 0) in (0, None)


# -- jitter / proxy pool -------------------------------------------------- #
def test_jitter_attribute(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3, jitter=0.05)
    assert s.jitter == 0.05


def test_proxy_pool_stored(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3,
                           proxy_pool=['http://127.0.0.1:8080'])
    assert s.proxy_pool == ['http://127.0.0.1:8080']
