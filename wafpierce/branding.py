"""Public-facing Blackthorn identity and bundled asset lookup.

The Python package and a few on-disk compatibility identifiers intentionally
retain their legacy names during the rebrand. User-facing code should import
the constants in this module instead of introducing new product-name literals.
"""

from __future__ import annotations

import os
import sys


PRODUCT_NAME = "Blackthorn"
CLI_NAME = "blackthorn"
TAGLINE = "Threat hunting & bug bounty web security toolkit"

TRANSPARENT_LOGO = "blackthorn-logo-transparent.png"
DARK_LOGO = "blackthornlogo-nottransparent.jpg"
BRAND_BANNER = "blackthornlogo-background.jpg"


def asset_path(filename: str) -> str:
    """Return the first available source, installed, or frozen brand asset."""
    package_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(package_dir)
    bundle_dir = os.environ.get("WAFPIERCE_BUNDLE_DIR") or getattr(sys, "_MEIPASS", "")

    candidates = []
    if bundle_dir:
        candidates.extend([
            os.path.join(bundle_dir, "wafpierce", "assets", filename),
            os.path.join(bundle_dir, filename),
        ])
    candidates.extend([
        os.path.join(package_dir, "assets", filename),
        os.path.join(project_root, filename),
        os.path.join(sys.prefix, "share", "blackthorn", filename),
    ])

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]
