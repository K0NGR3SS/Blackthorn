"""Authorization gate + audit logging.

A public WAF-bypass tool should make it hard to point at the wrong host. When
``--authorize <file>`` is supplied, the target's host must match one of the
allow-patterns in that file before any active test fires (fail-closed: an empty
or unreadable allowlist authorizes nothing). Every scan start/end is appended to
an audit log under the config dir so there's a record of what was tested.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, List, Optional
from urllib.parse import SplitResult, urlsplit

logger = logging.getLogger(__name__)


_DEFAULT_PORTS = {'http': 80, 'https': 443}
_HOST_LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
_BAD_PERCENT_ESCAPE_RE = re.compile(r'%(?![0-9a-fA-F]{2})')
_PERCENT_ESCAPE_RE = re.compile(r'%([0-9a-fA-F]{2})')
_UNRESERVED = frozenset(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'
)


@dataclass(frozen=True)
class _ParsedURL:
    scheme: str
    host: str
    port: int
    path: str


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


def _canonical_hostname(value: str) -> Optional[str]:
    """Return a comparison-safe ASCII hostname, or ``None`` when invalid."""
    if not value or any(ord(ch) <= 32 for ch in value):
        return None

    # A single terminal dot is a valid DNS absolute-name marker.  More than
    # one creates an empty label and is rejected below.
    host = value[:-1] if value.endswith('.') else value
    if not host or host.endswith('.') or any(ch in host for ch in '/\\@%'):
        return None

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return address.compressed.lower()

    # Colons are only valid in IP literals, handled above.  Reject numeric
    # lookalikes such as 999.0.0.1 and integer IPv4 spellings rather than
    # letting different URL/DNS stacks interpret them differently.
    if ':' in host or host.isdigit():
        return None
    if all(part.isdigit() for part in host.split('.')):
        return None

    try:
        ascii_host = host.encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return None
    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split('.')
    if not labels or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return ascii_host


def _valid_glob_label(label: str) -> bool:
    """Validate one ASCII hostname label while retaining fnmatch globs."""
    if not label or len(label) > 63 or label.startswith('-') or label.endswith('-'):
        return False
    index = 0
    while index < len(label):
        char = label[index]
        if char.isascii() and (char.isalnum() or char in '-*?'):
            index += 1
            continue
        if char == '[':
            end = label.find(']', index + 1)
            if end < 0:
                return False
            content = label[index + 1:end]
            if content.startswith('!'):
                content = content[1:]
            if not content or any(
                    not ch.isascii() or not (ch.isalnum() or ch == '-')
                    for ch in content):
                return False
            index = end + 1
            continue
        return False
    return True


def _canonical_host_pattern(value: str) -> Optional[str]:
    """Validate a hostname allow-pattern without weakening glob semantics."""
    if not value or any(ord(ch) <= 32 for ch in value):
        return None
    pattern = value[:-1] if value.endswith('.') else value
    if not pattern or pattern.endswith('.') or any(ch in pattern for ch in '/\\@%'):
        return None
    if not any(char in pattern for char in '*?['):
        return _canonical_hostname(pattern)
    if ':' in pattern or not pattern.isascii() or len(pattern) > 253:
        return None
    labels = pattern.lower().split('.')
    if not labels or any(not _valid_glob_label(label) for label in labels):
        return None
    return '.'.join(labels)


def _canonical_path(value: str) -> Optional[str]:
    """Canonicalize an HTTP path for conservative scope comparisons."""
    path = value or '/'
    if not path.startswith('/') or '\\' in path:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return None
    if _BAD_PERCENT_ESCAPE_RE.search(path):
        return None

    # Encoded separators have inconsistent treatment across clients, proxies,
    # and origin servers.  Failing closed prevents a path-scoped allow entry
    # from becoming broader after an intermediary decodes the URL.
    if re.search(r'%(?:2f|5c)', path, flags=re.IGNORECASE):
        return None

    def normalize_escape(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else match.group(0).upper()

    normalized = _PERCENT_ESCAPE_RE.sub(normalize_escape, path)
    if any(segment in {'.', '..'} for segment in normalized.split('/')):
        return None
    return normalized


def _split_url(value: str) -> Optional[SplitResult]:
    try:
        return urlsplit(value)
    except (TypeError, ValueError):
        return None


def _parse_url(value: str, *, allow_host_glob: bool = False,
               assume_http: bool = False) -> Optional[_ParsedURL]:
    text = value.strip()
    if not text:
        return None
    if assume_http and '://' not in text:
        text = f'http://{text}'
    parsed = _split_url(text)
    if parsed is None:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parsed.netloc:
        return None

    # Userinfo is not meaningful for authorization scope and can make a URL
    # look as though it targets the username rather than its actual hostname.
    try:
        if parsed.username is not None or parsed.password is not None:
            return None
        raw_host = parsed.hostname
        explicit_port = parsed.port
    except ValueError:
        return None
    if raw_host is None:
        return None
    host = (_canonical_host_pattern(raw_host) if allow_host_glob
            else _canonical_hostname(raw_host))
    path = _canonical_path(parsed.path)
    if host is None or path is None:
        return None
    if explicit_port is not None and explicit_port < 1:
        return None
    return _ParsedURL(
        scheme=scheme,
        host=host,
        port=(_DEFAULT_PORTS[scheme] if explicit_port is None else explicit_port),
        path=path,
    )


def _host_of(target: str) -> str:
    parsed = _parse_url(target, assume_http=True)
    return parsed.host if parsed is not None else ''


def _path_is_within(target_path: str, allowed_path: str) -> bool:
    """Return whether a path is the allowed segment or one of its children."""
    allowed = allowed_path.rstrip('/') or '/'
    if allowed == '/':
        return True
    target = target_path.rstrip('/') or '/'
    return target == allowed or target.startswith(f'{allowed}/')


def _bare_host_pattern(value: str) -> Optional[str]:
    """Extract and validate the host portion of a legacy host[/path] entry."""
    host_part = value.split('/', 1)[0]
    if not host_part or any(char in host_part for char in '@\\?#'):
        return None
    if host_part.startswith('[') and host_part.endswith(']'):
        host_part = host_part[1:-1]
    return _canonical_host_pattern(host_part)


def is_authorized(target: str, patterns: List[str]) -> bool:
    """True if ``target``'s host matches an allow-pattern.

    Patterns may be bare hosts or globs (``*.example.com``), or full URL
    scopes.  Full URLs must match by scheme, hostname, effective port, and a
    path-segment boundary.  Fail-closed: no patterns -> not authorized.
    """
    if not patterns:
        return False
    parsed_target = _parse_url(target, assume_http=True)
    if parsed_target is None:
        return False
    for pat in patterns:
        p = pat.strip()
        if not p:
            continue
        if '://' in p:
            allowed = _parse_url(p, allow_host_glob=True)
            if allowed is None:
                continue
            if (parsed_target.scheme == allowed.scheme
                    and parsed_target.port == allowed.port
                    and fnmatch.fnmatchcase(parsed_target.host, allowed.host)
                    and _path_is_within(parsed_target.path, allowed.path)):
                return True
            continue
        # Keep compatibility with host[/path] allow entries: without an
        # explicit scheme they authorize the matching host at any HTTP(S)
        # path/port.  Use a full URL entry when the path or port is significant.
        host_pat = _bare_host_pattern(p)
        if host_pat is not None and fnmatch.fnmatchcase(parsed_target.host, host_pat):
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
