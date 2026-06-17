"""Tests for v1.6 engine controls: CVSS, scope, safe-mode, jitter, proxy pool."""
import time

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


# -- safe mode ------------------------------------------------------------ #
def test_safe_mode_skip_set_is_populated():
    assert '_test_race_condition' in CloudFrontBypasser.SAFE_MODE_SKIP
    assert '_test_smuggling_cl0' in CloudFrontBypasser.SAFE_MODE_SKIP


def test_safe_mode_flag_stored(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3, safe_mode=True)
    assert s.safe_mode is True


# -- jitter / proxy pool -------------------------------------------------- #
def test_jitter_attribute(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3, jitter=0.05)
    assert s.jitter == 0.05


def test_proxy_pool_stored(mock_waf):
    s = CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3,
                           proxy_pool=['http://127.0.0.1:8080'])
    assert s.proxy_pool == ['http://127.0.0.1:8080']
