"""Regression tests for proof-carrying scanner findings and matched controls."""

import json
from urllib.parse import quote_plus

from wafpierce.evidence import analyze_response
from wafpierce.importers import from_har
from wafpierce.pierce import CloudFrontBypasser


def _query_target(path, parameter, value='seed'):
    return {'path': path, 'params': {parameter: value}, 'method': 'GET'}


def test_reflection_only_ssti_is_not_reported(baselined_scanner):
    old_payload = '{{.class}}'
    reflected = baselined_scanner._test_request(
        path=f'/ssti-reflect?test={quote_plus(old_payload)}',
        technique='SSTI reflection regression',
        probe={
            'category': 'SSTI', 'parameter': 'test', 'payload': old_payload,
            'oracle': {
                'type': 'marker', 'value': 'class', 'payload': old_payload,
            },
        },
    )
    assert reflected is not None
    assert reflected['verification_status'] != 'confirmed'
    assert not baselined_scanner._result_has_evidence(
        reflected, 'execution_marker'
    )

    baselined_scanner.crawl_targets = [
        _query_target('/ssti-reflect', 'test')
    ]
    assert baselined_scanner._test_ssti_detection() == []


def test_arithmetic_ssti_requires_and_records_paired_evaluation(
        baselined_scanner):
    baselined_scanner.crawl_targets = [
        _query_target('/ssti-evaluate', 'test')
    ]

    findings = baselined_scanner._test_ssti_detection()

    finding = next(
        item for item in findings
        if item.get('details', {}).get('engine') == 'Jinja2 / Twig / Pebble'
    )
    assert finding['bypass'] is True
    assert finding['verification_status'] == 'confirmed'
    assert finding['kind'] == 'finding'
    assert finding['confidence'] == 'high'
    assert finding['confirmations'] == '2/2 paired probes'
    assert len(finding['payloads']) == 2
    assert len({item['matched'] for item in finding['evidence']}) == 2
    assert all(item['type'] == 'execution_marker'
               for item in finding['evidence'])


def test_reflected_command_marker_is_not_command_execution(baselined_scanner):
    baselined_scanner.crawl_targets = [
        _query_target('/command-reflect', 'cmd')
    ]

    assert baselined_scanner._test_command_injection_bypass() == []


def test_marker_oracle_rejects_duplicate_and_url_decoded_reflections():
    control = {
        'status': 200, 'size': 7, 'text': 'control', 'normalized': 'control',
        'headers': {}, 'location': '',
    }
    marker = 'BT-REFLECT-123'
    raw_payload = f'echo {marker}'
    duplicate = dict(
        control, text=f'{raw_payload} {raw_payload}',
        normalized=f'{raw_payload} {raw_payload}', size=2 * len(raw_payload) + 1,
    )
    verdict = analyze_response(
        duplicate, control,
        oracle={'type': 'marker', 'value': marker, 'payload': raw_payload},
    )
    assert verdict['verification_status'] != 'confirmed'
    assert verdict['evidence'][0]['type'] != 'execution_marker'

    encoded = f'clean%0d%0a%0d%0a{marker}'
    decoded = f'clean\r\n\r\n{marker}'
    reflected = dict(control, text=decoded, normalized=decoded, size=len(decoded))
    verdict = analyze_response(
        reflected, control,
        oracle={'type': 'marker', 'value': marker, 'payload': encoded},
    )
    assert verdict['verification_status'] != 'confirmed'
    assert verdict['evidence'][0]['type'] != 'execution_marker'


def test_route_miss_to_success_is_candidate_but_auth_denial_is_confirmed():
    def response(status, text):
        return {
            'status': status, 'size': len(text), 'text': text,
            'normalized': text, 'headers': {}, 'location': '',
        }

    route_change = analyze_response(
        response(200, 'resource'), response(404, 'missing')
    )
    assert route_change['verification_status'] == 'candidate'
    assert route_change['evidence'][0]['type'] == 'response_state_transition'

    auth_change = analyze_response(
        response(200, 'account'), response(403, 'denied')
    )
    assert auth_change['verification_status'] == 'confirmed'
    assert auth_change['evidence'][0]['type'] == 'blocked_to_allowed'


def test_same_endpoint_control_prevents_route_delta_finding(baselined_scanner):
    result = baselined_scanner._test_request(
        path='/endpoint-specific?name=mutated',
        technique='matched endpoint control',
        probe={
            'category': 'INJECTION', 'parameter': 'name',
            'payload': 'mutated',
            'insertion_point': {'type': 'query', 'name': 'name'},
        },
    )

    assert result is not None
    assert result['bypass'] is False
    assert result['baseline']['scope'] == 'matched'
    assert result['baseline']['request']['path'] == (
        '/endpoint-specific?name=blackthorn-control'
    )
    assert result['comparison']['similarity'] == 1.0
    assert result['evidence'][0]['type'] == 'no_signal'


def _sql_error_probe(scanner, path):
    return scanner._test_request(
        path=f'{path}?id=1%27',
        technique='SQL error differential',
        probe={
            'category': 'INJECTION', 'parameter': 'id', 'payload': "1'",
            'insertion_point': {'type': 'query', 'name': 'id'},
            'detector_id': 'sqli-error-differential-v2',
            'oracle': {
                'type': 'regex',
                'patterns': [r'you have an error in your sql syntax'],
                'severity': 'HIGH',
                'reason': 'Database error appears only after the SQL probe',
                'verification_status': 'confirmed', 'kind': 'finding',
            },
        },
    )


def test_database_specific_500_is_detected_but_generic_500_is_not(
        baselined_scanner):
    database_error = _sql_error_probe(baselined_scanner, '/db-error')
    generic_error = _sql_error_probe(baselined_scanner, '/generic-500')

    assert database_error is not None
    assert database_error['status'] == 500
    assert database_error['bypass'] is True
    assert database_error['verification_status'] == 'confirmed'
    assert database_error['kind'] == 'finding'
    assert database_error['evidence'][0]['type'] == 'response_signature'

    assert generic_error is not None
    assert generic_error['status'] == 500
    assert generic_error['bypass'] is False
    assert generic_error['verification_status'] == 'not_detected'
    assert generic_error['evidence'][0]['type'] == 'rejected'


def test_confirmed_finding_contains_reproducible_evidence(baselined_scanner):
    finding = _sql_error_probe(baselined_scanner, '/db-error')

    assert finding is not None and finding['verification_status'] == 'confirmed'
    assert finding['request'] == {
        'method': 'GET',
        'url': f"{baselined_scanner.target}/db-error?id=1%27",
        'path': '/db-error?id=1%27',
        'headers': {},
        'body': None,
    }
    assert finding['response']['status'] == 500
    assert 'SQL syntax' in finding['response']['excerpt']
    assert finding['baseline']['status'] == 200
    assert finding['baseline']['scope'] == 'matched'
    assert finding['baseline']['request']['path'].startswith('/db-error?')
    assert finding['evidence'] and finding['evidence'][0]['matched']
    assert len(finding['fingerprint']) == 24
    assert finding['finding_id'] == f"bt-{finding['fingerprint']}"


def test_imported_query_stays_separate_and_request_context_survives(
        mock_waf, tmp_path):
    body = '{"query":"hello"}'
    har = {'log': {'entries': [{'request': {
        'method': 'POST',
        'url': f'{mock_waf}/search?mode=preview&empty=',
        'headers': [
            {'name': 'Content-Type', 'value': 'application/json'},
            {'name': 'X-Trace', 'value': 'trace-123'},
        ],
        'postData': {'text': body},
    }}]}}
    capture = tmp_path / 'request.har'
    capture.write_text(json.dumps(har), encoding='utf-8')

    imported = from_har(str(capture))
    assert imported[0]['path'] == '/search'
    assert imported[0]['params'] == {'mode': 'preview', 'empty': ''}
    assert imported[0]['headers']['X-Trace'] == 'trace-123'
    assert imported[0]['body'] == body

    scanner = CloudFrontBypasser(
        mock_waf, threads=1, delay=0, timeout=5,
        enable_crawl=False, enable_schema=False, seed_targets=imported,
    )
    scanner._run_discovery()
    assert scanner.crawl_targets == [{
        'path': '/search',
        'params': {'mode': 'preview', 'empty': ''},
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json', 'X-Trace': 'trace-123',
        },
        'body': body,
        'url': f'{mock_waf}/search?mode=preview&empty=',
    }]
