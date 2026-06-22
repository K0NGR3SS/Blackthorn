"""Tests for the GUI's pure copy/repeater helpers (no PySide6 needed).

These live at module scope in wafpierce.gui specifically so they can be unit
tested without a display or Qt installed.
"""
from wafpierce.gui import _finding_url, _finding_to_curl, _finding_to_python


def test_finding_url_prefers_explicit_url():
    assert _finding_url({'url': 'https://x/y'}) == 'https://x/y'


def test_finding_url_builds_from_target_and_path():
    assert _finding_url({'target': 'https://t/', 'path': '/admin'}) == 'https://t/admin'
    assert _finding_url({'path': '/only'}) == '/only'


def test_curl_prefers_recorded_repro():
    f = {'curl': "curl -i 'https://t/a'"}
    assert _finding_to_curl(f) == "curl -i 'https://t/a'"


def test_curl_builds_when_absent():
    f = {'method': 'post', 'url': 'https://t/api', 'headers': {'X-A': '1'}}
    out = _finding_to_curl(f)
    assert out.startswith('curl ')
    assert '-X POST' in out
    assert "-H 'X-A: 1'" in out
    assert "'https://t/api'" in out


def test_python_snippet_is_runnable_shape():
    f = {'method': 'GET', 'url': 'https://t/x', 'headers': {'A': 'b'}, 'data': 'q=1'}
    out = _finding_to_python(f)
    assert 'import requests' in out
    assert "requests.request(" in out
    assert "'GET', 'https://t/x'" in out
    assert "headers={'A': 'b'}" in out
    assert "data='q=1'" in out
    assert 'verify=False' in out
    compile(out, '<snippet>', 'exec')  # must be valid Python
