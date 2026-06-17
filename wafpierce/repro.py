"""
Reproduction-command builder.

Every finding should carry the exact request that produced it so a human can
copy-paste and reproduce / verify it without trusting the scanner's word. We
emit a portable ``curl`` command and (optionally) a raw HTTP request string.

Kept dependency-free and pure so it is trivially unit-testable.
"""
from typing import Any, Dict, Optional
from urllib.parse import urlencode

# Headers we never echo into a repro: curl re-derives them itself and emitting
# stale values would make the command wrong (e.g. a Content-Length that no
# longer matches the body after copy-paste editing).
_SKIP_HEADERS = {'content-length'}


def _shell_quote(s: str) -> str:
    """POSIX single-quote a string for safe shell paste.

    curl is invoked the same way on Linux/macOS and inside Git-Bash / WSL on
    Windows, so single-quote escaping is the portable choice.
    """
    s = str(s)
    if s == '':
        return "''"
    # Wrap in single quotes; close-escape-reopen any embedded single quote.
    return "'" + s.replace("'", "'\\''") + "'"


def _coerce_body(data: Any) -> str:
    """Render a request body the way ``requests`` would put it on the wire."""
    if data is None:
        return ''
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8', 'replace')
        except Exception:
            return repr(data)
    if isinstance(data, (dict, list, tuple)):
        try:
            return urlencode(data, doseq=True)
        except Exception:
            return str(data)
    return str(data)


def build_curl(method: str, url: str, headers: Optional[Dict[str, str]] = None,
               data: Any = None, insecure: bool = True) -> str:
    """Build a copy-paste ``curl`` command reproducing a request.

    Args:
        method: HTTP method.
        url: Absolute request URL.
        headers: Headers actually sent on the wire.
        data: Optional request body (str/bytes/dict).
        insecure: Add ``-k`` so self-signed / intercepted TLS still works
                  (the scanner itself runs with verification off).
    """
    method = (method or 'GET').upper()
    parts = ['curl', '-i', '-s']
    if insecure:
        parts.append('-k')
    if method != 'GET' or data is not None:
        parts += ['-X', method]

    for key, value in (headers or {}).items():
        if key.lower() in _SKIP_HEADERS:
            continue
        parts += ['-H', _shell_quote(f"{key}: {value}")]

    if data is not None:
        parts += ['--data-raw', _shell_quote(_coerce_body(data))]

    parts.append(_shell_quote(url))
    return ' '.join(parts)


def build_raw_http(method: str, url: str, headers: Optional[Dict[str, str]] = None,
                   data: Any = None, http_version: str = 'HTTP/1.1') -> str:
    """Build a raw HTTP request string (Burp-Repeater style)."""
    from urllib.parse import urlsplit

    method = (method or 'GET').upper()
    split = urlsplit(url)
    path = split.path or '/'
    if split.query:
        path = f"{path}?{split.query}"

    hdrs = dict(headers or {})
    # Ensure a Host line is present and first-ish, derived from the URL.
    host = split.netloc
    lines = [f"{method} {path} {http_version}"]
    if host and not any(k.lower() == 'host' for k in hdrs):
        lines.append(f"Host: {host}")
    for key, value in hdrs.items():
        if key.lower() == 'content-length':
            continue
        lines.append(f"{key}: {value}")

    body = _coerce_body(data)
    if body:
        lines.append(f"Content-Length: {len(body.encode('utf-8', 'replace'))}")
    raw = '\r\n'.join(lines) + '\r\n\r\n'
    if body:
        raw += body
    return raw
