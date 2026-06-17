"""Smoke + content tests for the result exporters."""
import json

import pytest

from wafpierce.exporters import export, to_html, to_sarif, to_nuclei

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
