import pytest

from wafpierce.payloads import (
    AUTHORIZED_USE_NOTICE,
    BUILTIN_PAYLOADS,
    PAYLOAD_CATEGORIES,
    build_payload_request,
    custom_payload_templates,
    encode_payload,
    families_for,
    filter_payloads,
    intruder_payload_sets,
    payload_request_to_curl,
    payloads_for_family,
)


def test_catalog_has_guidance_and_varied_coverage():
    category_keys = {category.key for category in PAYLOAD_CATEGORIES}
    assert {
        "sqli",
        "xss",
        "command",
        "traversal",
        "ssrf",
        "xxe",
        "ssti",
        "nosql",
        "custom",
    } <= category_keys
    assert all(category.description and category.workflow_hint for category in PAYLOAD_CATEGORIES)
    assert "permission" in AUTHORIZED_USE_NOTICE


def test_sql_injection_is_split_into_actionable_families():
    sqli = [item for item in BUILTIN_PAYLOADS if item.category == "sqli"]
    families = {item.family for item in sqli}
    assert {
        "Syntax probes",
        "Boolean / basic 1=1",
        "Authentication bypass",
        "UNION preparation",
        "UNION SELECT",
        "Error based",
        "Time based",
    } <= families
    assert any("1=1" in item.payload for item in sqli)
    assert any("UNION SELECT" in item.payload for item in sqli)
    assert {"MySQL / MariaDB", "PostgreSQL", "Microsoft SQL Server"} <= {
        item.platform for item in sqli
    }


def test_catalog_filter_searches_family_payload_platform_and_tags():
    union = filter_payloads(BUILTIN_PAYLOADS, category="sqli", family="UNION SELECT")
    assert len(union) >= 3
    assert all(item.category == "sqli" and item.family == "UNION SELECT" for item in union)
    assert filter_payloads(BUILTIN_PAYLOADS, query="postgresql")
    assert filter_payloads(BUILTIN_PAYLOADS, query="stop-before-credentials")
    assert "Time based" in families_for(BUILTIN_PAYLOADS, "SQL Injection")


def test_custom_database_rows_join_the_normal_catalog():
    rows = [
        {
            "id": 4,
            "name": "CTF marker",
            "category": "SQL Injection",
            "payload": "' OR 2=2-- -",
            "description": "Challenge-specific true branch",
            "severity": "LOW",
        }
    ]
    templates = custom_payload_templates(rows)
    assert len(templates) == 1
    assert templates[0].category == "sqli"
    assert templates[0].family == "My payloads"
    assert templates[0].source == "Custom"
    assert payloads_for_family("sqli", "My payloads", rows) == templates


def test_payload_encodings_are_explicit_and_validated():
    assert encode_payload("' OR 1=1", "url").startswith("%27")
    assert encode_payload("' OR 1=1", "double_url").startswith("%2527")
    assert encode_payload("abc", "base64") == "YWJj"
    assert encode_payload("<", "html") == "&lt;"
    assert encode_payload("A", "unicode") == "\\u0041"
    with pytest.raises(ValueError, match="Unknown payload encoding"):
        encode_payload("x", "rot13")


def test_query_request_preserves_target_and_shows_exact_destination():
    request = build_payload_request(
        method="GET",
        url="https://ctf.example/search?lang=en",
        payload="' OR '1'='1'-- -",
        location="query",
        name="q",
    )
    assert request.method == "GET"
    assert request.url.startswith("https://ctf.example/search?")
    assert "lang=en" in request.url
    assert "q=%27%20OR%20%271%27%3D%271%27--%20-" in request.url
    assert request.insertion_point == "Query parameter: q"
    preview = request.preview()
    assert preview.startswith("GET /search?")
    assert "Host: ctf.example" in preview


def test_form_json_header_cookie_path_and_raw_body_placements():
    form = build_payload_request(
        method="POST",
        url="app.example/login",
        payload="admin'-- -",
        location="form",
        name="username",
        base_body="remember=true",
    )
    assert form.body == "remember=true&username=admin%27--%20-"
    assert form.headers["Content-Type"] == "application/x-www-form-urlencoded"

    json_request = build_payload_request(
        method="POST",
        url="https://app.example/api",
        payload="{{7*7}}",
        location="json",
        name="displayName",
        base_body='{"role":"tester"}',
    )
    assert json_request.body == '{"role":"tester","displayName":"{{7*7}}"}'
    assert json_request.headers["Content-Type"] == "application/json"

    header = build_payload_request(
        method="GET",
        url="https://app.example/",
        payload="http://127.0.0.1/",
        location="header",
        name="X-Forwarded-Host",
    )
    assert header.headers["X-Forwarded-Host"] == "http://127.0.0.1/"

    cookie = build_payload_request(
        method="GET",
        url="https://app.example/",
        payload="1 OR 1=1",
        location="cookie",
        name="session",
        headers={"Cookie": "theme=dark; session=old"},
    )
    assert cookie.headers["Cookie"] == "theme=dark; session=1 OR 1=1"

    path = build_payload_request(
        method="GET",
        url="https://app.example/file/FUZZ",
        payload="../../etc/passwd",
        location="path",
    )
    assert path.url.endswith("/file/..%2F..%2Fetc%2Fpasswd")

    raw = build_payload_request(
        method="POST",
        url="https://app.example/xml",
        payload="<root>marker</root>",
        location="raw_body",
        headers={"Content-Type": "application/xml"},
    )
    assert raw.body == "<root>marker</root>"
    assert raw.headers["Content-Type"] == "application/xml"


def test_invalid_request_inputs_fail_with_clear_messages():
    with pytest.raises(ValueError, match="absolute HTTP"):
        build_payload_request(
            method="GET",
            url="/relative",
            payload="x",
            location="query",
        )
    with pytest.raises(ValueError, match="Base body is not valid JSON"):
        build_payload_request(
            method="POST",
            url="https://app.example/api",
            payload="x",
            location="json",
            base_body="{broken",
        )
    with pytest.raises(ValueError, match="Header values"):
        build_payload_request(
            method="GET",
            url="https://app.example/",
            payload="one\r\ntwo",
            location="header",
            name="X-Test",
        )


def test_curl_and_repeater_handoff_match_the_previewed_request():
    request = build_payload_request(
        method="POST",
        url="https://app.example/api",
        payload='{"username":{"$ne":null}}',
        location="raw_body",
        headers={"Content-Type": "application/json"},
    )
    curl = payload_request_to_curl(request)
    prefill = request.as_repeater_prefill()
    assert "curl -i -X POST" in curl
    assert "--data-raw" in curl
    assert prefill["method"] == request.method
    assert prefill["url"] == request.url
    assert prefill["headers"] == dict(request.headers)
    assert prefill["data"] == request.body


def test_intruder_sets_are_generated_from_the_same_catalog():
    sets = intruder_payload_sets()
    assert "SQL injection" in sets
    assert "Cross-site scripting" in sets
    assert any("UNION SELECT" in payload for payload in sets["SQL injection"])
    assert len(sets["SQL injection"]) == len(set(sets["SQL injection"]))
