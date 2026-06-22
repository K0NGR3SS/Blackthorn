"""Load scanner defaults from a config file so you don't retype 15 flags.

Supports JSON and TOML (TOML needs Python 3.11+ ``tomllib``, or the ``toml``/
``tomli`` package on older versions). The file maps flag names (dashes or
underscores) to values, e.g.::

    # wafpierce.toml
    threads = 20
    impersonate = "chrome"
    safe_mode = true
    scope_exclude = ["/logout", "/admin/delete"]

    [profiles.staging]
    target = "https://staging.example.com"
    oob = "interactsh"

Pick a named profile with ``--config-profile staging``; its keys overlay the
top-level keys. Explicit command-line flags always win over the config.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _load_toml(path: str) -> Dict[str, Any]:
    try:
        import tomllib  # Python 3.11+
        with open(path, 'rb') as f:
            return tomllib.load(f)
    except ModuleNotFoundError:
        pass
    for mod_name in ('tomli', 'toml'):
        try:
            mod = __import__(mod_name)
            if mod_name == 'tomli':
                with open(path, 'rb') as f:
                    return mod.load(f)
            with open(path, 'r', encoding='utf-8') as f:
                return mod.load(f)
        except ModuleNotFoundError:
            continue
    raise RuntimeError("TOML config needs Python 3.11+ (tomllib) or the 'tomli'/'toml' package")


def _load_raw(path: str) -> Dict[str, Any]:
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.toml',):
        return _load_toml(path)
    if ext in ('.json', ''):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    # Unknown extension: try JSON first, then TOML.
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return _load_toml(path)


def load_config(path: str, profile: Optional[str] = None) -> Dict[str, Any]:
    """Return a flat {flag_dest: value} dict from ``path`` (+ optional profile).

    Keys are normalized to argparse dests (dashes -> underscores). The
    ``profiles`` table is not returned as a key; the selected profile's keys are
    overlaid on the top-level keys.
    """
    raw = _load_raw(path)
    if not isinstance(raw, dict):
        raise RuntimeError(f"config root must be a mapping, got {type(raw).__name__}")

    profiles = raw.get('profiles') or {}
    flat = {k: v for k, v in raw.items() if k != 'profiles'}

    if profile:
        if profile not in profiles:
            raise RuntimeError(f"config profile '{profile}' not found "
                               f"(have: {', '.join(sorted(profiles)) or 'none'})")
        flat.update(profiles[profile])

    return {str(k).replace('-', '_'): v for k, v in flat.items()}


def apply_config(args, parser, config: Dict[str, Any]) -> None:
    """Apply config values to ``args`` for any dest still at its argparse default
    (so explicit command-line flags always win). Unknown keys are warned about."""
    for dest, value in config.items():
        if not hasattr(args, dest):
            logger.warning(f"config: ignoring unknown key '{dest}'")
            continue
        try:
            default = parser.get_default(dest)
        except Exception:
            default = None
        if getattr(args, dest) == default:
            setattr(args, dest, value)
