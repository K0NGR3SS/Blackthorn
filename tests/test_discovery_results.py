from wafpierce.discovery_results import (
    discovery_detail_nodes,
    discovery_result_matches,
    discovery_result_summary,
    discovery_tool_sections,
)


def _report():
    return {
        "target": "example.test",
        "findings": [{
            "technique": "Subdomain Enumeration",
            "target": "example.test",
            "reason": "two tools contributed",
            "severity": "INFO",
        }],
        "stages": {
            "sources": {
                "api.example.test": ["subfinder"],
                "cdn.example.test": ["certificate transparency"],
            },
            "resolved": {"api.example.test": ["192.0.2.10", "192.0.2.11"]},
            "http": [{
                "url": "https://api.example.test",
                "status_code": 200,
                "title": "API",
                "tech": ["nginx", "GraphQL"],
            }],
            "historical": [
                "https://api.example.test/v1?a=1",
                "https://api.example.test/v2?a=2",
            ],
            "vulns": [{
                "template-id": "exposed-panel",
                "matched-at": "https://api.example.test/admin",
                "info": {
                    "name": "Exposed panel",
                    "severity": "medium",
                    "classification": {"cwe-id": ["CWE-200", "CWE-284"]},
                },
            }],
            "ports": [{
                "host": "192.0.2.10", "port": 443, "protocol": "tcp",
                "service": "https", "product": "nginx", "version": "1.25",
            }],
            "arjun": [{
                "url": "https://api.example.test/v2/users",
                "method": "GET",
                "parameters": ["debug", "expand"],
            }],
            "risk_signals": [{
                "target": "https://api.example.test/admin",
                "severity": "MEDIUM",
                "category": "sensitive_path",
                "reason": "Sensitive application path discovered",
                "sources": ["katana", "httpx"],
            }],
            "asset_diff": {
                "added": [{
                    "id": "one", "kind": "url",
                    "value": "https://api.example.test/v2/users",
                    "sources": ["arjun"], "metadata": {},
                }],
            },
        },
    }


def test_report_is_separated_into_native_tool_sections():
    sections = discovery_tool_sections(_report())
    by_tool = {section["tool"]: section for section in sections}
    assert set(by_tool) >= {
        "subfinder", "crtsh", "dnsx", "httpx", "gau", "nuclei", "nmap",
        "arjun", "risk", "asset_diff",
    }
    assert by_tool["gau"]["total"] == 2
    assert by_tool["dnsx"]["results"][0]["ip_addresses"] == [
        "192.0.2.10", "192.0.2.11",
    ]


def test_multi_value_fields_are_individual_recursive_nodes():
    nuclei = discovery_tool_sections(_report())
    record = next(section for section in nuclei if section["tool"] == "nuclei")["results"][0]
    nodes = discovery_detail_nodes(record)
    info = next(node for node in nodes if node["label"] == "info")
    classification = next(node for node in info["children"] if node["label"] == "classification")
    cwes = next(node for node in classification["children"] if node["label"] == "cwe-id")
    assert [item["value"] for item in cwes["children"]] == ["CWE-200", "CWE-284"]


def test_detail_rendering_redacts_secrets_and_is_bounded():
    nodes = discovery_detail_nodes({
        "authorization": "Bearer should-not-render",
        "output": "access_token=also-secret",
        "scanner_text": "found AKIAABCDEFGHIJKLMNOP in JavaScript",
        "items": list(range(2000)),
    })
    serialized = repr(nodes)
    assert "should-not-render" not in serialized
    assert "also-secret" not in serialized
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized
    assert "<redacted>" in serialized
    assert "Render limit" in serialized or "not rendered" in serialized


def test_summaries_and_search_use_nested_native_fields():
    record = _report()["stages"]["vulns"][0]
    summary = discovery_result_summary("nuclei", record)
    assert summary["title"] == "Exposed panel"
    assert summary["severity"] == "MEDIUM"
    assert discovery_result_matches("nuclei", record, "CWE-284") is True
    assert discovery_result_matches("nuclei", record, "unrelated") is False


def test_tool_section_limits_are_explicit():
    report = {"stages": {"historical": ["https://e.test/%d" % i for i in range(10)]}}
    section = discovery_tool_sections(report, max_results_per_tool=3)[0]
    assert section["total"] == 10
    assert section["shown"] == 3
    assert section["truncated"] is True
