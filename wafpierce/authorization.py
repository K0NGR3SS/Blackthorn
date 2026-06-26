"""Authorization gate + audit logging.

A public WAF-bypass tool should make it hard to point at the wrong host. When
``--authorize <file>`` is supplied, the target's host must match one of the
allow-patterns in that file before any active test fires (fail-closed: an empty
or unreadable allowlist authorizes nothing). Every scan start/end is appended to
an audit log under the config dir so there's a record of what was tested.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import time
from typing import Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def load_allowlist(path: str) -> List[str]:
    """Read allow-patterns (one per line; '#' comments and blanks ignored)."""
    patterns: List[str] = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(line)
    except OSError as e:
        logger.error(f"Could not read authorization allowlist {path}: {e}")
    return patterns


def _host_of(target: str) -> str:
    parsed = urlparse(target if '://' in target else f'http://{target}')
    return (parsed.hostname or '').lower()


def is_authorized(target: str, patterns: List[str]) -> bool:
    """True if ``target``'s host matches an allow-pattern.

    Patterns may be bare hosts or globs (``*.example.com``), or full URL
    prefixes. Fail-closed: no patterns -> not authorized.
    """
    if not patterns:
        return False
    host = _host_of(target)
    if not host:
        return False
    for pat in patterns:
        p = pat.strip().lower()
        # Full-URL / scheme-prefix pattern: match against the target string.
        if '://' in p:
            if target.lower().startswith(p.rstrip('*')):
                return True
            continue
        # Strip any path on a host[/path] pattern; match the host part as a glob.
        host_pat = p.split('/', 1)[0]
        if fnmatch.fnmatch(host, host_pat) or host == host_pat:
            return True
    return False


def _audit_path() -> Optional[str]:
    try:
        from .config import ensure_config_dir
        return os.path.join(ensure_config_dir(), 'audit.log')
    except Exception:
        return None


def audit_log(event: str, **fields: Any) -> None:
    """Append a one-line JSON audit record (best-effort, never raises)."""
    path = _audit_path()
    if not path:
        return
    record = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'event': event}
    record.update(fields)
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, default=str) + '\n')
    except OSError as e:
        logger.debug(f"audit log write failed: {e}")
