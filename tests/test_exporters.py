"""Smoke + content tests for the result exporters."""
import json

import pytest

from wafpierce.exporters import (
    export, to_html, to_sarif, to_nuclei, to_junit, to_csv,
    diff_results, to_html_diff, to_prometheus, to_har,
    result_state, is_confirmed_result,
)

SAMPLE = [
    {
        'bypass': True, 'severity': 'HIGH', 'technique': 'X-Forwarded-For',
        'category': 'header_manipulation', 'status': 200, 'reason': 'content diff',
        'path': '/admin', 'method': 'GET',
        'curl': "curl -i -s -k -H 'X-Forwarded-For: 127.0.0.1' 'https://t/admin'",
        'confidence': 'high', 'confirmations': '2/2',
    },
    {
        'bypass': False, 'severity': 'INFO', 'technique': 'baseline',
        'category': 'recon', 'status': 200, 'reason': 'ok', 'path': '/',
    },
]

RICH = [{
    'bypass': True, 'severity': 'HIGH', 'technique': 'SSTI arithmetic marker',
    'category': 'INJECTION_TESTING', 'reason': 'Expected marker observed',
    'verification_status': 'confirmed', 'confidence': 'high',
    'finding_id': 'bt-rich-1', 'kind': 'finding', 'cwe_id': 'CWE-1336',
    'cvss_score': 8.1, 'payload': '<script>{{7*7}}</script>',
    'insertion_point': {'type': 'query', 'name': 'q'},
    'request': {
        'method': 'POST', 'url': 'https://t.example/search?q=probe',
        'path': '/search?q=probe', 'headers': {'X-Probe': 'blackthorn'},
        'body': 'q={{7*7}}',
    },
    'response': {
        'status': 201, 'size': 120, 'content_type': 'text/html',
        'headers': {'content-type': 'text/html'},
        'excerpt': '<script>BT-49</script>', 'sha256': 'abc123',
    },
    'baseline': {
        'status': 200, 'size': 80, 'scope': 'matched',
        'headers': {'content-type': 'text/html'}, 'excerpt': '<clean>',
    },
    'comparison': {'similarity': 0.42, 'size_delta': 40},
    'evidence': [{
        'type': 'execution_marker', 'description': 'Rendered marker',
        'matched': 'BT-49', 'excerpt': '<script>BT-49</script>',
    }],
    'remediation': 'Use a sandboxed template environment and encode <output>.',
}]

SECRET = [{
    **RICH[0],
    'request': {
        **RICH[0]['request'],
        'headers': {
            'Authorization': 'Bearer nested-auth-secret',
            'Cookie': 'session=nested-cookie-secret',
            'X-API-Key': 'nested-api-secret',
        },
    },
    'curl': (
        "curl -H 'Authorization: Bearer curl-auth-secret' "
        "-H 'Cookie: session=curl-cookie-secret' 'https://t.example/search'"
    ),
}]


@pytest.mark.parametrize('fmt', ['json', 'html', 'sarif', 'nuclei'])
def test_export_returns_nonempty(fmt):
    out = export(SAMPLE, 'https://t.example', fmt)
    assert isinstance(out, str) and out.strip()


def test_json_export_roundtrips_and_keeps_curl():
    out = export(SAMPLE, 'https://t.example', 'json')
    data = json.loads(out)
    assert data[0]['curl'].startswith('curl ')
    assert data[0]['confidence'] == 'high'


@pytest.mark.parametrize('fmt', ['json', 'html', 'sarif', 'nuclei', 'har'])
def test_export_redacts_nested_headers_and_curl_by_default(fmt):
    out = export(SECRET, 'https://t.example', fmt)
    for secret in ('nested-auth-secret', 'nested-cookie-secret', 'nested-api-secret',
                   'curl-auth-secret', 'curl-cookie-secret'):
        assert secret not in out
    # Redaction works on a deep copy; live GUI/scan results remain reproducible.
    assert SECRET[0]['request']['headers']['Authorization'] == 'Bearer nested-auth-secret'
    assert 'curl-auth-secret' in SECRET[0]['curl']


def test_export_redaction_has_explicit_private_opt_out():
    out = export(SECRET, 'https://t.example', 'json', redact=False)
    assert 'nested-auth-secret' in out
    assert 'nested-cookie-secret' in out
    assert 'curl-auth-secret' in out


def test_direct_har_export_is_also_redacted_by_default():
    out = to_har('https://t.example', SECRET)
    assert 'nested-auth-secret' not in out
    assert 'nested-cookie-secret' not in out
    assert '<redacted>' in out


def test_html_includes_repro_and_confidence():
    out = to_html('https://t.example', SAMPLE)
    assert 'Reproduce' in out          # the new column header
    assert 'curl -i -s -k' in out      # the repro command rendered
    assert 'conf-high' in out          # confidence badge


def test_html_has_exec_summary_filters_and_copy():
    out = to_html('https://t.example', SAMPLE)
    assert 'Executive summary' in out
    assert 'Confirmed findings' in out
    assert "id=\"q\"" in out or "id='q'" in out      # search box
    assert 'applyFilters' in out                      # filter script
    assert 'copyRepro' in out                         # copy-curl button handler
    assert "data-sev='HIGH'" in out                   # filterable row


def test_html_cvss_tooltip_when_present():
    findings = [{'severity': 'HIGH', 'technique': 'SQLi', 'category': 'injection',
                 'cvss_score': '8.6', 'cvss_vector': 'AV:N/AC:L', 'cwe': 'CWE-89'}]
    out = to_html('https://t', findings)
    assert 'CVSS 8.6' in out
    assert 'AV:N/AC:L' in out
    assert 'CWE-89' in out


# -------------------------------------------------------------------- diff report
def test_diff_results_classifies():
    old = [{'technique': 'A', 'category': 'c', 'path': '/'},
           {'technique': 'B', 'category': 'c', 'path': '/'}]
    new = [{'technique': 'B', 'category': 'c', 'path': '/'},
           {'technique': 'C', 'category': 'c', 'path': '/'}]
    d = diff_results(old, new)
    assert [r['technique'] for r in d['new']] == ['C']
    assert [r['technique'] for r in d['resolved']] == ['A']
    assert [r['technique'] for r in d['unchanged']] == ['B']


def test_html_diff_renders_counts():
    old = [{'technique': 'A', 'category': 'c', 'path': '/', 'severity': 'HIGH'}]
    new = [{'technique': 'C', 'category': 'c', 'path': '/', 'severity': 'LOW'}]
    out = to_html_diff('https://t', old, new)
    assert '+1 new' in out and '-1 resolved' in out
    assert 'New findings (1)' in out and 'Resolved findings (1)' in out


def test_diff_reports_candidate_to_confirmed_as_state_change():
    old = [dict(RICH[0], verification_status='candidate', kind='suspected')]
    new = [dict(RICH[0], verification_status='confirmed', kind='finding')]
    diff = diff_results(old, new)
    assert not diff['new'] and not diff['resolved'] and not diff['unchanged']
    assert len(diff['changed']) == 1
    assert diff['changed'][0]['changes']['state'] == {
        'from': 'candidate', 'to': 'confirmed',
    }
    out = to_html_diff('https://t.example', old, new, redact=False)
    assert '~1 changed' in out
    assert 'Changed findings (1)' in out


def test_diff_fallback_identity_distinguishes_insertion_points():
    base = {'technique': 'SSTI', 'category': 'INJECTION', 'path': '/search',
            'method': 'GET', 'severity': 'HIGH'}
    old = [{**base, 'insertion_point': {'type': 'query', 'name': 'q'}}]
    new = [{**base, 'insertion_point': {'type': 'query', 'name': 'template'}}]
    diff = diff_results(old, new)
    assert len(diff['new']) == 1
    assert len(diff['resolved']) == 1


def test_json_export_survives_bytes_body():
    # A finding carrying a raw bytes body must not crash JSON export.
    findings = [{'severity': 'INFO', 'technique': 't', 'data': b'\x00\x01raw'}]
    out = export(findings, 'https://t.example', 'json')
    assert isinstance(out, str) and out.strip()


def test_sarif_is_valid_json_with_runs():
    out = to_sarif('https://t.example', SAMPLE)
    doc = json.loads(out)
    assert 'runs' in doc and isinstance(doc['runs'], list)


def test_sarif_preserves_structured_request_evidence_and_cwe():
    doc = json.loads(to_sarif('https://fallback.example', RICH))
    finding = doc['runs'][0]['results'][0]
    props = finding['properties']
    assert finding['locations'][0]['physicalLocation']['artifactLocation']['uri'] == \
        'https://t.example/search?q=probe'
    assert props['request']['method'] == 'POST'
    assert props['response']['excerpt'] == '<script>BT-49</script>'
    assert props['baseline']['scope'] == 'matched'
    assert props['evidence'][0]['matched'] == 'BT-49'
    assert props['cwe_id'] == 'CWE-1336'
    assert finding['partialFingerprints']['blackthorn/v1'] == 'bt-rich-1'


def test_sarif_does_not_invent_location_for_unavailable_request():
    unavailable = {
        **RICH[0],
        'request': {'available': False, 'note': 'exact request not recorded'},
    }
    finding = json.loads(
        to_sarif('https://fallback.example', [unavailable], redact=False)
    )['runs'][0]['results'][0]
    assert 'locations' not in finding
    assert finding['properties']['request']['available'] is False


def test_nuclei_is_nonempty_yaml_text():
    out = to_nuclei('https://t.example', RICH)
    assert 'id:' in out or 'info:' in out


def test_nuclei_replays_structured_request_and_matches_evidence():
    out = to_nuclei('https://fallback.example', RICH)
    assert 'method: POST' in out
    assert '"X-Probe": "blackthorn"' in out
    assert 'body: "q={{7*7}}"' in out
    assert '"BT-49"' in out
    assert 'cwe-id: "CWE-1336"' in out
    assert 'blackthorn-verification: "confirmed"' in out


def test_nuclei_skips_unconfirmed_candidates():
    candidate = dict(RICH[0], verification_status='candidate')
    assert 'No confirmed' in to_nuclei('https://t.example', [candidate])


def test_nuclei_skips_confirmed_result_without_exact_request():
    unavailable = {
        **RICH[0],
        'request': {'available': False, 'note': 'legacy detector omitted request'},
    }
    out = to_nuclei('https://t.example', [unavailable], redact=False)
    assert 'No confirmed' in out
    assert 'status_code >= 100' not in out


def test_nuclei_uses_header_matcher_for_redirect_location():
    redirect = {
        **RICH[0],
        'technique': 'Open redirect',
        'response': {'status': 302},
        'evidence': [{
            'type': 'external_redirect',
            'matched': 'https://blackthorn.invalid/callback',
        }],
    }
    out = to_nuclei('https://t.example', [redirect], redact=False)
    assert 'part: header' in out
    assert '"https://blackthorn.invalid/callback"' in out
    assert 'part: body' not in out


def test_nuclei_header_injection_matches_stable_value_not_header_casing():
    injected = {
        **RICH[0],
        'technique': 'CRLF response header injection',
        'evidence': [{
            'type': 'response_header_injection',
            'matched': 'x-blackthorn-proof: BT-HEADER-419',
        }],
    }
    out = to_nuclei('https://t.example', [injected], redact=False)
    assert 'part: header' in out
    assert '"BT-HEADER-419"' in out
    assert '"x-blackthorn-proof: BT-HEADER-419"' not in out


def test_nuclei_skips_differential_proof_that_one_request_cannot_verify():
    transition = {
        **RICH[0],
        'technique': 'Authorization transition',
        'evidence': [{'type': 'blocked_to_allowed', 'matched': '200'}],
    }
    out = to_nuclei('https://t.example', [transition], redact=False)
    assert 'No confirmed' in out
    assert 'words:' not in out


@pytest.mark.parametrize('fmt', ['junit', 'csv', 'prometheus', 'har'])
def test_new_formats_export_nonempty(fmt):
    out = export(SAMPLE, 'https://t.example', fmt)
    assert isinstance(out, str) and out.strip()


def test_prometheus_exposition():
    out = to_prometheus('https://t.example', SAMPLE)
    assert '# TYPE blackthorn_findings_total gauge' in out
    assert 'blackthorn_findings_total{target="https://t.example",severity="HIGH"} 1' in out
    assert 'blackthorn_bypasses_total{target="https://t.example"} 1' in out


def test_prometheus_counts_candidates_and_observations_separately():
    candidate = dict(RICH[0], verification_status='candidate', kind='suspected')
    observation = dict(RICH[0], bypass=False, verification_status='informational',
                       kind='observation', severity='CRITICAL')
    out = to_prometheus('https://t.example', [RICH[0], candidate, observation],
                        redact=False)
    assert 'blackthorn_findings{target="https://t.example"} 1' in out
    assert 'blackthorn_bypasses_total{target="https://t.example"} 1' in out
    assert 'blackthorn_candidates_total{target="https://t.example"} 1' in out
    assert 'blackthorn_observations_total{target="https://t.example"} 1' in out


def test_har_is_valid_and_importable():
    out = to_har('https://t.example', SAMPLE)
    doc = json.loads(out)
    assert doc['log']['version'] == '1.2'
    assert doc['log']['entries']
    e = doc['log']['entries'][0]
    assert e['request']['url'].startswith('https://t.example')
    assert 'method' in e['request']


def test_har_preserves_request_response_and_blackthorn_proof():
    doc = json.loads(to_har('https://fallback.example', RICH))
    entry = doc['log']['entries'][0]
    assert entry['request']['method'] == 'POST'
    assert entry['request']['url'] == 'https://t.example/search?q=probe'
    assert entry['request']['queryString'] == [{'name': 'q', 'value': 'probe'}]
    assert {'name': 'X-Probe', 'value': 'blackthorn'} in entry['request']['headers']
    assert entry['request']['postData']['text'] == 'q={{7*7}}'
    assert entry['response']['status'] == 201
    assert entry['response']['content']['text'] == '<script>BT-49</script>'
    assert entry['_blackthorn']['evidence'][0]['matched'] == 'BT-49'
    assert entry['_blackthorn']['cwe_id'] == 'CWE-1336'


def test_junit_is_wellformed_xml_with_failures():
    import xml.etree.ElementTree as ET
    out = to_junit('https://t.example', SAMPLE)
    root = ET.fromstring(out)            # raises if malformed
    assert root.tag == 'testsuites'
    # HIGH bypass -> a failure; INFO baseline -> a passing testcase.
    assert int(root.get('tests')) == 2
    assert int(root.get('failures')) == 1
    failures = root.findall('.//failure')
    assert len(failures) == 1
    assert failures[0].get('type') == 'HIGH'


def test_junit_only_fails_confirmed_findings():
    import xml.etree.ElementTree as ET
    candidate = dict(RICH[0], verification_status='candidate', kind='suspected',
                     severity='CRITICAL')
    observation = dict(RICH[0], bypass=False, verification_status='informational',
                       kind='observation', severity='CRITICAL')
    confirmed = dict(RICH[0], severity='MEDIUM')
    root = ET.fromstring(to_junit(
        'https://t.example', [candidate, observation, confirmed], redact=False
    ))
    assert int(root.get('failures')) == 1


def test_result_state_prefers_explicit_verification_over_bypass_boolean():
    assert result_state({'bypass': True, 'verification_status': 'candidate',
                         'kind': 'suspected'}) == 'candidate'
    assert not is_confirmed_result({'bypass': True, 'verification_status': 'candidate'})
    assert is_confirmed_result({'bypass': True})  # legacy compatibility


def test_csv_has_header_and_rows():
    import csv
    import io
    out = to_csv('https://t.example', SAMPLE)
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0][:10] == ['severity', 'category', 'technique', 'bypass', 'confidence',
                            'status', 'cvss_score', 'cwe', 'path', 'reason']
    assert 'verification_status' in rows[0]
    assert 'evidence' in rows[0]
    assert 'remediation' in rows[0]
    assert len(rows) == 3  # header + 2 findings
    # Most-severe first: HIGH row precedes INFO row.
    assert rows[1][0] == 'HIGH'
    assert rows[1][3] == 'yes'  # bypass column


def test_csv_uses_canonical_cwe_id_and_structured_proof():
    import csv
    import io
    rows = list(csv.DictReader(io.StringIO(to_csv('https://fallback.example', RICH))))
    row = rows[0]
    assert row['cwe'] == 'CWE-1336'
    assert row['verification_status'] == 'confirmed'
    assert row['method'] == 'POST'
    assert row['url'] == 'https://t.example/search?q=probe'
    assert 'BT-49' in row['evidence']
    assert row['baseline_status'] == '200'
    assert row['similarity'] == '0.42'


def test_html_renders_proof_fields_and_escapes_untrusted_values():
    out = to_html('https://fallback.example', RICH)
    for label in ('Proof &amp; request', 'Verification', 'Payload', 'Evidence',
                  'Observed response', 'Matched baseline', 'Remediation'):
        assert label in out
    assert '<script>BT-49</script>' not in out
    assert '&lt;script&gt;BT-49&lt;/script&gt;' in out
    assert '<output>' not in out and '&lt;output&gt;' in out


def test_pdf_export_writes_a_file(tmp_path):
    pytest.importorskip("reportlab")
    out_path = tmp_path / "report.pdf"
    written = export(SAMPLE, 'https://t.example', 'pdf', str(out_path))
    assert out_path.exists()
    assert out_path.stat().st_size > 0
    # Returned path points at the artifact actually written.
    assert written.endswith('.pdf')
    with open(out_path, 'rb') as f:
        assert f.read(4) == b'%PDF'
