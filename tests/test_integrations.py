"""Tests for outbound integrations (Slack / generic / DefectDojo)."""
from wafpierce.integrations import (
    format_slack, format_generic, format_defectdojo, send_slack,
)

RESULTS = [
    {'bypass': True, 'severity': 'CRITICAL', 'technique': 'OOB-CONFIRMED SSRF',
     'reason': 'callback received', 'path': '/x', 'cwe_id': 'CWE-918', 'cvss_score': 9.8},
    {'bypass': True, 'severity': 'MEDIUM', 'technique': 'CSP weakness',
     'reason': 'unsafe-inline', 'path': '/'},
    {'bypass': False, 'severity': 'INFO', 'technique': 'baseline', 'reason': 'ok'},
]


def test_format_slack_has_summary_and_top():
    payload = format_slack('https://t.example', RESULTS)
    assert 'text' in payload
    text = payload['text']
    assert 'Blackthorn' in text and 't.example' in text
    assert 'CRITICAL: 1' in text
    assert 'OOB-CONFIRMED SSRF' in text          # top finding listed


def test_format_generic_counts():
    payload = format_generic('https://t.example', RESULTS)
    assert payload['total'] == 3
    assert payload['confirmed'] == 2
    assert payload['summary']['CRITICAL'] == 1


def test_format_defectdojo_only_confirmed():
    rows = format_defectdojo('https://t.example', RESULTS)
    assert len(rows) == 2                         # INFO non-bypass excluded
    assert rows[0]['cwe'] == 918
    assert rows[0]['severity'] == 'Critical'


def test_send_slack_uses_session_and_reports_status():
    class _Resp:
        status_code = 200
    class _Sess:
        def __init__(self): self.calls = []
        def post(self, url, **kw): self.calls.append((url, kw)); return _Resp()
    sess = _Sess()
    ok = send_slack('https://hooks.slack/x', 'https://t.example', RESULTS, session=sess)
    assert ok is True
    assert sess.calls and sess.calls[0][0] == 'https://hooks.slack/x'
    assert 'json' in sess.calls[0][1]


def test_send_slack_handles_failure_gracefully():
    class _Sess:
        def post(self, *a, **k): raise RuntimeError("network down")
    assert send_slack('https://x', 't', RESULTS, session=_Sess()) is False
