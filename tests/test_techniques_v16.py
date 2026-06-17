"""Tests for the v1.6 attack-module techniques."""
import hashlib

import pytest

from wafpierce.techniques_v16 import (
    analyze_csp, forge_jwt_with_embedded_jwk, decode_jwt_segments,
)
from wafpierce.pierce import CloudFrontBypasser, SCAN_CATEGORIES, _normalize_body


# -- pure helpers --------------------------------------------------------- #
def test_analyze_csp_flags_unsafe_inline_and_wildcard():
    issues = analyze_csp("script-src 'unsafe-inline' *; default-src 'self'")
    kinds = {i['issue'] for i in issues}
    assert any('unsafe-inline' in k for k in kinds)
    assert any('wildcard' in k or '*' in k for k in kinds)


def test_analyze_csp_clean_policy_has_few_issues():
    issues = analyze_csp("default-src 'self'; script-src 'self'; object-src 'none'; "
                         "frame-ancestors 'none'")
    # A locked-down policy should not raise the high-severity script issues.
    assert not any(i['severity'] == 'HIGH' for i in issues)


def test_analyze_csp_empty_is_empty():
    assert analyze_csp('') == []


def test_forge_jwt_is_wellformed_and_carries_jwk():
    token = forge_jwt_with_embedded_jwk({'sub': 'x', 'admin': True})
    assert token.count('.') == 2
    decoded = decode_jwt_segments(token)
    assert decoded is not None
    assert decoded['header']['alg'] == 'RS256'
    assert decoded['header']['jwk']['kty'] == 'RSA'
    assert decoded['payload']['admin'] is True


# -- wiring --------------------------------------------------------------- #
NEW_TECHNIQUES = [
    '_test_csp_analysis', '_test_jwt_jwk_injection', '_test_graphql_csrf',
    '_test_smuggling_cl0', '_test_saml_xsw', '_test_auth_logic',
    '_test_llm_prompt_injection', '_test_grpc_detection', '_test_http3_detection',
]


@pytest.mark.parametrize('name', NEW_TECHNIQUES)
def test_new_techniques_are_methods(name):
    assert callable(getattr(CloudFrontBypasser, name, None))


def test_new_techniques_registered_in_a_category():
    all_listed = {t for cat in SCAN_CATEGORIES.values() for t in cat['techniques']}
    for name in NEW_TECHNIQUES:
        assert name in all_listed, f"{name} not in any SCAN_CATEGORIES list"


def test_ai_attacks_category_exists():
    assert 'ai_attacks' in SCAN_CATEGORIES
    assert '_test_llm_prompt_injection' in SCAN_CATEGORIES['ai_attacks']['techniques']


# -- run against the mock WAF (should not error; CSP-missing is flagged) --- #
def _baselined(scanner):
    b = scanner._get_baseline()
    scanner._baseline_size = len(b.content)
    scanner._baseline_hash = hashlib.md5(b.content).hexdigest()
    scanner._baseline_status = b.status_code
    scanner._baseline_headers = dict(b.headers)
    scanner._baseline_body_sample = b.text[:5000]
    scanner._baseline_norm = _normalize_body(b.text)
    scanner._baseline_jitter = 0
    scanner._baseline_dynamic = False
    return scanner


def test_csp_missing_is_flagged_against_mock(baselined_scanner):
    # The mock WAF sends no CSP header -> a LOW "CSP Missing" finding.
    out = baselined_scanner._test_csp_analysis()
    assert any('CSP Missing' in r['technique'] for r in out)


@pytest.mark.parametrize('name', NEW_TECHNIQUES)
def test_techniques_run_without_error(mock_waf, name):
    s = _baselined(CloudFrontBypasser(mock_waf, threads=2, delay=0, timeout=3))
    out = getattr(s, name)()
    assert isinstance(out, list)
