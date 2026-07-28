"""Tests for the HAR / Postman / Burp request importers."""
import base64
import json

from wafpierce.importers import from_har, from_postman, from_burp, load_requests


def test_from_har(tmp_path):
    har = {"log": {"entries": [
        {"request": {"method": "GET",
                     "url": "https://t.example/search?q=hello&page=2",
                     "headers": [{"name": "User-Agent", "value": "x"},
                                 {"name": ":authority", "value": "skip"}]}},
        {"request": {"method": "POST", "url": "https://t.example/api/login",
                     "headers": [], "postData": {"text": "u=a&p=b"}}},
    ]}}
    f = tmp_path / "cap.har"
    f.write_text(json.dumps(har), encoding='utf-8')
    out = from_har(str(f))
    assert len(out) == 2
    assert out[0]['params'] == {'q': 'hello', 'page': '2'}
    assert out[0]['headers'] == {'User-Agent': 'x'}        # pseudo-header skipped
    assert out[1]['method'] == 'POST' and out[1]['body'] == 'u=a&p=b'


def test_from_har_serializes_postdata_params_when_text_is_missing(tmp_path):
    har = {"log": {"entries": [
        {"request": {
            "method": "POST",
            "url": "https://t.example/session",
            "headers": [{"name": "Cookie", "value": "sid=abc"}],
            "postData": {
                "mimeType": "application/x-www-form-urlencoded",
                "params": [
                    {"name": "user", "value": "alice"},
                    {"name": "remember", "value": ""},
                ],
            },
        }},
    ]}}
    f = tmp_path / "form.har"
    f.write_text(json.dumps(har), encoding='utf-8')

    request = from_har(str(f))[0]

    assert request['body'] == 'user=alice&remember='
    assert request['headers']['Cookie'] == 'sid=abc'


def test_from_postman_walks_folders(tmp_path):
    coll = {"item": [
        {"name": "folder", "item": [
            {"request": {"method": "GET",
                         "url": {"raw": "https://t.example/users?id=5"},
                         "header": [{"key": "Authorization", "value": "Bearer z"}]}}
        ]},
        {"request": {"method": "POST", "url": "https://t.example/create",
                     "body": {"raw": "{\"a\":1}"}, "header": []}},
    ]}
    f = tmp_path / "coll.json"
    f.write_text(json.dumps(coll), encoding='utf-8')
    out = from_postman(str(f))
    assert len(out) == 2
    assert out[0]['params'] == {'id': '5'}
    assert out[0]['headers']['Authorization'] == 'Bearer z'
    assert out[1]['body'] == '{"a":1}'


def test_from_postman_preserves_urlencoded_and_graphql_bodies(tmp_path):
    coll = {"item": [
        {"request": {
            "method": "POST",
            "url": "https://t.example/login?next=%2Fadmin",
            "body": {
                "mode": "urlencoded",
                "urlencoded": [
                    {"key": "email", "value": "a@example.test"},
                    {"key": "disabled", "value": "skip", "disabled": True},
                ],
            },
        }},
        {"request": {
            "method": "POST",
            "url": "https://t.example/graphql",
            "body": {
                "mode": "graphql",
                "graphql": {
                    "query": "query User($id: ID!) { user(id: $id) { id } }",
                    "variables": {"id": "7"},
                },
            },
        }},
    ]}
    f = tmp_path / "body-modes.json"
    f.write_text(json.dumps(coll), encoding='utf-8')

    out = from_postman(str(f))

    assert out[0]['params'] == {'next': '/admin'}
    assert out[0]['body'] == 'email=a%40example.test'
    assert json.loads(out[1]['body'])['variables'] == {'id': '7'}


def test_from_burp_base64(tmp_path):
    raw = ("GET /admin?debug=1 HTTP/1.1\r\nHost: t.example\r\n"
           "X-Test: yes\r\n\r\n")
    xml = f"""<?xml version="1.0"?><items>
      <item><url>https://t.example/admin?debug=1</url><method>GET</method>
      <request base64="true">{base64.b64encode(raw.encode()).decode()}</request></item>
    </items>"""
    f = tmp_path / "burp.xml"
    f.write_text(xml, encoding='utf-8')
    out = from_burp(str(f))
    assert len(out) == 1
    assert out[0]['params'] == {'debug': '1'}
    assert out[0]['headers'].get('X-Test') == 'yes'


def test_load_requests_autodetects(tmp_path):
    har = {"log": {"entries": [{"request": {"method": "GET", "url": "https://t/x", "headers": []}}]}}
    f = tmp_path / "auto.har"
    f.write_text(json.dumps(har), encoding='utf-8')
    out = load_requests(str(f))
    assert len(out) == 1 and out[0]['url'] == 'https://t/x'


def test_load_requests_missing_file_is_safe():
    assert load_requests('/no/such/file.har') == []
