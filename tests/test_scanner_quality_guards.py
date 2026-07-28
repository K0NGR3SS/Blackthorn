"""Regression guards for scanner accuracy, evidence, and impact boundaries."""

import ast
from collections import Counter
from pathlib import Path
import socket
from urllib.parse import quote, urljoin, urlparse

from wafpierce import cli
import wafpierce.pierce as pierce
from wafpierce.pierce import CloudFrontBypasser


def test_cloudfront_bypasser_has_no_duplicate_method_definitions():
    """Later methods must not silently shadow an earlier scanner implementation."""
    tree = ast.parse(
        Path(pierce.__file__).read_text(encoding='utf-8'),
        filename=pierce.__file__,
    )
    scanner_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == 'CloudFrontBypasser'
    )
    method_names = [
        node.name for node in scanner_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    duplicates = sorted(
        name for name, count in Counter(method_names).items() if count > 1
    )

    assert duplicates == []


def test_nxdomain_is_not_reported_as_subdomain_takeover(
        baselined_scanner, monkeypatch):
    def nxdomain(*_args, **_kwargs):
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

    monkeypatch.setattr(pierce.socket, 'getaddrinfo', nxdomain)

    assert baselined_scanner._test_subdomain_takeover() == []


def test_public_200_endpoint_is_not_reported_as_jwt_bypass(
        baselined_scanner):
    """A forged token is proof only after an invalid token was denied."""
    assert baselined_scanner._test_jwt_oauth_bypass() == []


def test_oauth_scanner_records_only_exact_controlled_redirect_hosts(
        baselined_scanner):
    findings = baselined_scanner._test_oauth_oidc()

    assert findings
    for finding in findings:
        assert baselined_scanner._result_has_evidence(
            finding, 'external_redirect'
        )
        location = finding['response']['headers']['location']
        assert urlparse(urljoin(baselined_scanner.target, location)).hostname == (
            'blackthorn.invalid'
        )


def test_oauth_redirect_oracle_rejects_hostname_substring_confusion(
        baselined_scanner):
    redirect_uri = 'https://blackthorn.invalid.attacker.example/callback'
    path = (
        '/oauth/authorize?response_type=code&client_id=test&redirect_uri='
        + quote(redirect_uri, safe='')
    )

    result = baselined_scanner._test_request(
        path=path,
        technique='OAuth hostname confusion regression',
        probe={
            'category': 'OAUTH',
            'parameter': 'redirect_uri',
            'payload': redirect_uri,
            'oracle': {
                'type': 'redirect',
                'host': 'blackthorn.invalid',
                'base_url': baselined_scanner.target,
            },
        },
    )

    assert result is not None
    assert result['verification_status'] != 'confirmed'
    assert not baselined_scanner._result_has_evidence(
        result, 'external_redirect'
    )


def test_intrusive_workflows_require_explicit_flag(capsys):
    assert cli.main([
        'scan', 'https://example.invalid', '--dry-run', '--no-color',
        '-c', 'business_logic',
    ]) == 0
    guarded = capsys.readouterr().out
    assert 'intrusive=off' in guarded
    assert '5 skipped by safety/accuracy guards' in guarded
    assert '      - business logic flaws' not in guarded

    assert cli.main([
        'scan', 'https://example.invalid', '--dry-run', '--no-color',
        '--intrusive', '-c', 'business_logic',
    ]) == 0
    enabled = capsys.readouterr().out
    assert 'intrusive=on' in enabled
    assert '      - business logic flaws' in enabled


def test_intrusive_flag_cannot_enable_unsupported_transport_checks(capsys):
    assert cli.main([
        'scan', 'https://example.invalid', '--dry-run', '--no-color',
        '--intrusive', '-c', 'protocol_level',
    ]) == 0
    output = capsys.readouterr().out

    assert '6 skipped by safety/accuracy guards' in output
    assert '      - transfer encoding smuggling' not in output
    assert '      - request smuggling v2' not in output
    assert '      - http desync' not in output


def test_declared_scanner_guards_reference_registered_techniques():
    registered = {
        technique
        for category in pierce.SCAN_CATEGORIES.values()
        for technique in category['techniques']
    }

    assert CloudFrontBypasser.INTRUSIVE_WORKFLOW_SKIP <= registered
    assert CloudFrontBypasser.DISABLED_TRANSPORT_TECHNIQUES <= registered
    assert CloudFrontBypasser.DISABLED_ACCURACY_TECHNIQUES <= registered


def test_every_registered_technique_has_truthful_capability_metadata():
    catalog = CloudFrontBypasser.capability_catalog()
    registered = {
        technique
        for category in pierce.SCAN_CATEGORIES.values()
        for technique in category['techniques']
    }

    assert set(catalog) == registered
    assert {item['capability'] for item in catalog.values()} <= {
        'proof', 'candidate', 'observation', 'disabled',
    }
    assert catalog['_test_sqli_bypass']['capability'] == 'proof'
    assert catalog['_test_host_header_injection']['capability'] == 'candidate'
    assert catalog['_test_http3_detection']['capability'] == 'observation'
    assert catalog['_test_http_desync']['capability'] == 'disabled'
