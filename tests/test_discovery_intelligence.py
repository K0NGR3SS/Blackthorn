import json

from wafpierce.discovery_intelligence import (
    apply_continuous_intelligence,
    build_asset_snapshot,
    correlate_risks,
    diff_snapshots,
    history_path,
    load_snapshot,
)


def _report(extra_stages=None):
    stages = {
        "sources": {
            "api-dev.example.test": ["subfinder", "certificate transparency"],
        },
        "resolved": {"api-dev.example.test": ["192.0.2.10"]},
        "http": [{
            "url": "https://api-dev.example.test/admin",
            "status_code": 200,
            "live": True,
            "title": "Admin",
        }],
        "ports": [{"host": "192.0.2.10", "port": 9200}],
        "historical": [
            "https://api-dev.example.test/internal?access_token=secret-value",
        ],
        "takeovers": [{
            "matched-at": "https://old.example.test",
            "template-id": "takeover-detection",
        }],
    }
    stages.update(extra_stages or {})
    return {"target": "example.test", "findings": [], "stages": stages}


def test_snapshot_is_canonical_and_redacts_secret_query_values():
    snapshot = build_asset_snapshot(_report())
    serialized = json.dumps(snapshot)
    assert "api-dev.example.test" in serialized
    assert "secret-value" not in serialized
    assert all({"id", "kind", "value", "sources", "metadata"} <= set(asset)
               for asset in snapshot["assets"])


def test_diff_and_risk_correlation_prioritize_new_attack_surface():
    previous = build_asset_snapshot({
        "target": "example.test",
        "stages": {"sources": {"www.example.test": ["subfinder"]}},
    })
    current = build_asset_snapshot(_report())
    diff = diff_snapshots(current, previous)
    risks = correlate_risks(_report(), current, diff)

    assert diff["baseline_available"] is True
    assert diff["summary"]["added"] > 0
    assert {row["category"] for row in risks} >= {
        "interesting_asset", "sensitive_path", "exposed_service",
        "subdomain_takeover",
    }
    takeover = next(row for row in risks if row["category"] == "subdomain_takeover")
    assert takeover["severity"] == "HIGH"


def test_continuous_history_is_private_minimal_and_drives_next_diff(tmp_path):
    first = _report()
    apply_continuous_intelligence(first, str(tmp_path))
    path = history_path(str(tmp_path), "example.test")
    stored = load_snapshot(path)
    assert stored is not None
    assert "stages" not in stored

    second = _report({
        "historical": ["https://api-dev.example.test/internal/v2"],
    })
    apply_continuous_intelligence(second, str(tmp_path))
    diff = second["stages"]["asset_diff"]
    assert diff["baseline_available"] is True
    assert any(
        asset["value"] == "https://api-dev.example.test/internal/v2"
        for asset in diff["added"]
    )
