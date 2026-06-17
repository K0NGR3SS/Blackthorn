"""The shipped sample plugin must load and conform to the SDK contract."""
import os

from wafpierce.plugins import PluginManager, validate_plugin

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                      'plugins', 'sample_header_bypass.py')


def test_sample_plugin_loads():
    pm = PluginManager()
    plugin = pm.load_plugin(SAMPLE)
    assert plugin is not None
    assert plugin.name == "Trusted-Header Bypass"
    assert callable(getattr(plugin, 'execute', None))


def test_sample_plugin_validates():
    pm = PluginManager()
    plugin = pm.load_plugin(SAMPLE)
    errors = validate_plugin(plugin)
    assert errors == [], f"sample plugin failed validation: {errors}"


def test_sample_plugin_executes_against_mock(mock_waf):
    pm = PluginManager()
    plugin = pm.load_plugin(SAMPLE)
    import requests
    out = plugin.execute(mock_waf, requests.Session(), baseline_status=200,
                         baseline_size=10)
    # Mock WAF never returns 401/403, so no bypass — but the shape must be valid.
    assert isinstance(out, (dict, list))
    if isinstance(out, dict):
        assert 'bypass' in out and 'technique' in out
