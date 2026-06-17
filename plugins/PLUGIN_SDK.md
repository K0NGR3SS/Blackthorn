# WAFPierce Plugin SDK

Plugins let you add custom bypass/detection logic without touching the core
engine. They run as a scan phase and their findings are merged into the report
(and the GUI Results Explorer) like any built-in technique.

## Where plugins live

The plugin manager loads `*.py` files from your per-user plugins directory:

- **Windows:** `%APPDATA%\wafpierce\plugins`
- **macOS/Linux:** `~/.config/wafpierce/plugins`

The repo's `plugins/` folder holds examples — copy [sample_header_bypass.py](sample_header_bypass.py)
into your plugins directory to start.

## The contract

```python
from wafpierce.plugins import BypassPlugin   # falls back to `from plugins import ...`

class MyPlugin(BypassPlugin):
    name = "My Bypass"            # required
    version = "1.0.0"
    author = "you"
    description = "what it does"
    category = "header"   # one of: bypass, encoding, header, injection, protocol, cloud, recon
    tags = ["headers"]
    compatible_wafs = ["cloudflare"]   # informational

    def execute(self, target, session, **kwargs):
        # `session` is the live (authenticated, fingerprinted) requests/curl_cffi
        # session. `kwargs` includes baseline_status and baseline_size.
        ...
        return {                  # a single dict, or a list of dicts
            "success": True,
            "bypass": True,        # True => counts as a finding
            "technique": self.name,
            "reason": "why this is a bypass",
            "severity": "HIGH",   # CRITICAL|HIGH|MEDIUM|LOW|INFO
            "category": "PLUGIN",
            "method": "GET",
            "path": "/",
            "headers": {"X-Test": "1"},
            "status": 200,
        }

PLUGIN_CLASS = MyPlugin            # required (or the first BypassPlugin subclass is used)
```

### Result fields

| field      | meaning                                                        |
|------------|----------------------------------------------------------------|
| `bypass`   | `True` marks a real finding; `False`/`INFO` is informational   |
| `severity` | one of CRITICAL / HIGH / MEDIUM / LOW / INFO                   |
| `reason`   | human explanation shown in the report                          |
| `method`/`path`/`headers` | used to build the reproduction `curl` command   |

The engine automatically attaches a reproduction `curl`, a CVSS score, and a CWE
id to plugin findings, and (unless they opt out with `"_no_reconfirm": True`)
runs them through the re-confirmation pass.

## Helpers on `BypassPlugin`

- `self.encode_payload(payload, encoding=...)` — url / double_url / unicode / hex / base64
- `self.make_request(target, payload=..., method=..., headers=..., session=...)`
- `self.validate_target(target)` — override to skip irrelevant targets
- `self.setup(config)` / `self.teardown()` — lifecycle hooks

## Testing your plugin

```bash
python -c "from wafpierce.plugins import PluginManager; \
m=PluginManager(); print(m.load_plugin('plugins/sample_header_bypass.py'))"
```

A loaded plugin appears in the GUI Plugin Manager and runs on the next scan.
