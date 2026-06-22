"""Redact secrets from findings before they leave the machine.

Findings carry a reproduction ``curl`` and (sometimes) raw request data that can
include the *authenticated* session you scanned with — cookies, bearer tokens,
basic-auth, API keys. Sharing a report shouldn't leak your creds, so reports are
redacted by default; ``--no-redact`` keeps the raw values.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List

_REDACTED = '<redacted>'

# Patterns operate on free text (curl strings, header blobs, request bodies).
_TEXT_RULES = [
    # HTTP headers (curl -H '...', or raw "Name: value")
    (re.compile(r'(?i)(authorization\s*:\s*)(bearer\s+|basic\s+)?[^\'"\r\n]+'),
     lambda m: f"{m.group(1)}{m.group(2) or ''}{_REDACTED}"),
    (re.compile(r'(?i)(cookie\s*:\s*)[^\'"\r\n]+'),
     lambda m: f"{m.group(1)}{_REDACTED}"),
    (re.compile(r'(?i)(set-cookie\s*:\s*)[^\'"\r\n]+'),
     lambda m: f"{m.group(1)}{_REDACTED}"),
    (re.compile(r'(?i)((?:x-api-key|x-auth-token|api-key|apikey)\s*:\s*)[^\'"\r\n]+'),
     lambda m: f"{m.group(1)}{_REDACTED}"),
    # curl cookie flags: -b/--cookie <value>
    (re.compile(r"(?i)(\s(?:-b|--cookie)\s+)(?:'[^']*'|\"[^\"]*\"|\S+)"),
     lambda m: f"{m.group(1)}'{_REDACTED}'"),
    # curl basic auth: -u/--user user:pass
    (re.compile(r"(?i)(\s(?:-u|--user)\s+)(?:'[^']*'|\"[^\"]*\"|\S+)"),
     lambda m: f"{m.group(1)}'{_REDACTED}'"),
    # Secret-bearing query/body params
    (re.compile(r'(?i)\b(password|passwd|pwd|token|access_token|refresh_token|'
                r'api_key|apikey|secret|client_secret|session|sessionid|sid)'
                r'(=|%3D)[^&\s\'"]+'),
     lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}"),
]

# Finding keys whose *entire* value is sensitive header/cookie material.
_SENSITIVE_KEYS = {'cookie', 'cookies', 'bearer', 'authorization', 'basic_auth',
                   'auth', 'password', 'token', 'api_key', 'apikey', 'secret'}


def redact_text(s: str) -> str:
    """Scrub secrets from a free-text string (curl command, header blob, body)."""
    if not s:
        return s
    for pattern, repl in _TEXT_RULES:
        s = pattern.sub(repl, s)
    return s


def _redact_value(key: str, value: Any) -> Any:
    if isinstance(value, str):
        if key.lower() in _SENSITIVE_KEYS and value:
            return _REDACTED
        return redact_text(value)
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(key, v) for v in value)
    return value


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(finding)
    for k, v in list(out.items()):
        out[k] = _redact_value(k, v)
    return out


def redact_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return a deep copy of ``results`` with secrets scrubbed."""
    return [redact_finding(r) if isinstance(r, dict) else r for r in results]
