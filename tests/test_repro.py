"""Unit tests for the reproduction-command builder."""
from wafpierce.repro import build_curl, build_raw_http


def test_curl_basic_get():
    cmd = build_curl('GET', 'https://t.example/admin',
                     {'X-Forwarded-For': '127.0.0.1'})
    assert cmd.startswith('curl ')
    assert "-H 'X-Forwarded-For: 127.0.0.1'" in cmd
    assert cmd.endswith("'https://t.example/admin'")
    # Plain GET should not force -X.
    assert '-X GET' not in cmd


def test_curl_post_sets_method_and_body():
    cmd = build_curl('POST', 'https://t.example/api',
                     {'Content-Type': 'application/json'}, '{"a":1}')
    assert '-X POST' in cmd
    assert "--data-raw '{\"a\":1}'" in cmd


def test_curl_drops_content_length():
    # Stale Content-Length must not leak into the repro (curl recomputes it).
    cmd = build_curl('POST', 'https://t.example/x',
                     {'Content-Length': '999'}, 'abc')
    assert 'Content-Length' not in cmd


def test_curl_shell_escapes_single_quotes():
    cmd = build_curl('GET', 'https://t.example/q', {'X': "O'Brien"})
    # Single quote is closed/escaped/reopened, never left bare.
    assert "O'\\''Brien" in cmd
    assert "-H 'X: O'\\''Brien'" in cmd


def test_curl_dict_body_is_urlencoded():
    cmd = build_curl('GET', 'https://t.example/q', {}, {'q': "' OR 1=1--"})
    assert 'q=%27+OR+1%3D1--' in cmd


def test_raw_http_has_request_line_and_recomputed_length():
    raw = build_raw_http('POST', 'https://t.example/api',
                         {'Content-Type': 'application/json'}, '{"a":1}')
    assert raw.startswith('POST /api HTTP/1.1\r\n')
    assert 'Host: t.example\r\n' in raw
    assert 'Content-Length: 7\r\n' in raw
    assert raw.endswith('{"a":1}')
