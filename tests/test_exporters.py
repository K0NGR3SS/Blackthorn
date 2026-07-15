"""Smoke + content tests for the result exporters."""
import json

import pytest

from wafpierce.exporters import (
    export, to_html, to_sarif, to_nuclei, to_junit, to_csv,
    diff_results, to_html_diff, to_prometheus, to_har,
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


@pytest.mark.parametrize('fmt', ['json', 'html', 'sarif', 'nuclei'])
def test_export_returns_nonempty(fmt):
    out = export(SAMPLE, 'https://t.example', fmt)
    assert isinstance(out, str) and out.strip()


def test_json_export_roundtrips_and_keeps_curl():
    out = export(SAMPLE, 'https://t.example', 'json')
    data = json.loads(out)
    assert data[0]['curl'].startswith('curl ')
    assert data[0]['confidence'] == 'high'


def test_html_includes_repro_and_confidence():
    out = to_html('https://t.example', SAMPLE)
    assert 'Reproduce' in out          # the new column header
    assert 'curl -i -s -k' in out      # the repro command rendered
    assert 'conf-high' in out          # confidence badge


def test_html_has_exec_summary_filters_and_copy():
    out = to_html('https://t.example', SAMPLE)
    assert 'Executive summary' in out
    assert 'Confirmed bypasses' in out
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


def test_json_export_survives_bytes_body():
    # A finding carrying a raw bytes body must not crash JSON export.
    findings = [{'severity': 'INFO', 'technique': 't', 'data': b'\x00\x01raw'}]
    out = export(findings, 'https://t.example', 'json')
    assert isinstance(out, str) and out.strip()


def test_sarif_is_valid_json_with_runs():
    out = to_sarif('https://t.example', SAMPLE)
    doc = json.loads(out)
    assert 'runs' in doc and isinstance(doc['runs'], list)


def test_nuclei_is_nonempty_yaml_text():
    out = to_nuclei('https://t.example', SAMPLE)
    assert 'id:' in out or 'info:' in out


@pytest.mark.parametrize('fmt', ['junit', 'csv', 'prometheus', 'har'])
def test_new_formats_export_nonempty(fmt):
    out = export(SAMPLE, 'https://t.example', fmt)
    assert isinstance(out, str) and out.strip()


def test_prometheus_exposition():
    out = to_prometheus('https://t.example', SAMPLE)
    assert '# TYPE blackthorn_findings_total gauge' in out
    assert 'blackthorn_findings_total{target="https://t.example",severity="HIGH"} 1' in out
    assert 'blackthorn_bypasses_total{target="https://t.example"} 1' in out


def test_har_is_valid_and_importable():
    out = to_har('https://t.example', SAMPLE)
    doc = json.loads(out)
    assert doc['log']['version'] == '1.2'
    assert doc['log']['entries']
    e = doc['log']['entries'][0]
    assert e['request']['url'].startswith('https://t.example')
    assert 'method' in e['request']


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


def test_csv_has_header_and_rows():
    import csv
    import io
    out = to_csv('https://t.example', SAMPLE)
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == ['severity', 'category', 'technique', 'bypass', 'confidence',
                       'status', 'cvss_score', 'cwe', 'path', 'reason']
    assert len(rows) == 3  # header + 2 findings
    # Most-severe first: HIGH row precedes INFO row.
    assert rows[1][0] == 'HIGH'
    assert rows[1][3] == 'yes'  # bypass column


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
