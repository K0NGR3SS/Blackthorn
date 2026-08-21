import json

from wafpierce import recon_engines as engines


def _which(name):
    return f"/tools/{name}"


def test_alterx_candidates_are_bounded_and_scope_checked():
    def runner(command, _timeout, stdin_text=None):
        assert command[:3] == ["/tools/alterx", "-silent", "-enrich"]
        assert "api.example.test" in stdin_text
        return 0, "dev.example.test\nattacker.test\napi.example.test\n", ""

    rows = engines.alterx_generate(
        ["api.example.test"], "example.test", 10, runner, _which
    )

    assert rows == [{
        "hostname": "dev.example.test",
        "source": "alterx",
        "seed_count": 1,
    }]


def test_parameter_adapter_preserves_multi_value_output(tmp_path):
    def arjun_runner(command, _timeout):
        output = command[command.index("-oJ") + 1]
        with open(output, "w", encoding="utf-8") as handle:
            json.dump({
                "https://api.example.test/v1/users": {
                    "method": "GET", "params": ["debug", "expand"],
                },
            }, handle)
        return 0, "", ""

    params = engines.arjun_scan(
        ["https://api.example.test/v1/users"], "example.test", 10,
        arjun_runner, _which,
    )
    assert params == [{
        "url": "https://api.example.test/v1/users",
        "method": "GET",
        "parameters": ["debug", "expand"],
    }]


def test_cloud_inventory_is_correlated_to_known_scope():
    output = "\n".join([
        json.dumps({
            "provider": "aws", "hostname": "cdn.example.test",
            "public_ip": "192.0.2.10",
        }),
        json.dumps({
            "provider": "aws", "hostname": "unrelated.test",
            "public_ip": "198.51.100.55",
        }),
    ])
    rows = engines.cloudlist_inventory(
        "example.test", {"192.0.2.10"}, 10,
        lambda *_args: (0, output, ""), _which,
    )
    assert len(rows) == 1
    assert rows[0]["hostname"] == "cdn.example.test"
    assert rows[0]["scope_correlation"] == "example.test"


def test_visual_probe_rejects_out_of_tree_artifact_paths(tmp_path):
    def runner(_command, _timeout, stdin_text=None):
        assert "outside.test" not in stdin_text
        return 0, json.dumps({
            "url": "https://app.example.test",
            "screenshot_path": str(tmp_path.parent / "outside.png"),
            "favicon": "1234",
            "jarm": "abc",
        }), ""

    rows = engines.visual_probe(
        ["https://app.example.test", "https://outside.test"],
        "example.test", 10, runner, _which,
        artifact_dir=str(tmp_path),
    )
    assert rows[0]["engine"] == "httpx_visual"
    assert "screenshot_path" not in rows[0]
