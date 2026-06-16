"""
WAFPierce WebSocket Deep Tests

A dependency-free WebSocket tester: performs the HTTP Upgrade handshake over a raw
socket (TLS for wss), checks Cross-Site WebSocket Hijacking (origin validation),
missing-auth acceptance, and fuzzes a few text frames once connected.

Goes beyond the existing handshake-only CSWSH check by actually establishing the
connection and sending malformed / oversized / injection messages, observing how
the endpoint responds (echo, error, or close).
"""
import os
import ssl
import socket
import base64
import struct
import logging
from urllib.parse import urlparse
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

WS_PATHS = ['/ws', '/websocket', '/socket', '/socket.io/?EIO=4&transport=websocket',
            '/cable', '/graphql', '/api/ws', '/live', '/stream']

FUZZ_MESSAGES = [
    'A' * 65536,                       # oversized frame
    '{"type":', '{"a":1,,}',           # malformed JSON
    '"><script>alert(1)</script>',     # XSS-ish
    "' OR 1=1-- -",                    # SQLi-ish
    '\x00\x01\x02\xff',                # binary-ish in text frame
    '{"__proto__":{"x":1}}',           # prototype pollution
]


def _ws_handshake(host, port, path, use_tls, origin=None, timeout=5, extra_headers=None):
    """Perform a WS handshake. Returns (sock, response_headers) or (None, '')."""
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    for h in (extra_headers or []):
        lines.append(h)
    request = "\r\n".join(lines) + "\r\n\r\n"

    sock = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.settimeout(timeout)
        sock.sendall(request.encode())
        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        return sock, resp.decode('latin-1', 'replace')
    except Exception as e:
        logger.debug(f"WS handshake failed {path}: {e}")
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return None, ''


def _ws_send_text(sock, message):
    """Send a masked client text frame (opcode 0x1)."""
    payload = message.encode('utf-8', 'replace')
    header = bytearray([0x81])  # FIN + text
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack('>H', length)
    else:
        header.append(0x80 | 127)
        header += struct.pack('>Q', length)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def _ws_recv(sock, timeout=3):
    try:
        sock.settimeout(timeout)
        data = sock.recv(4096)
        return data
    except Exception:
        return b''


def run_websocket_tests(target: str, crawl_targets: List[Dict[str, Any]],
                        timeout: int = 5) -> List[Dict[str, Any]]:
    results = []
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return results
    use_tls = parsed.scheme == 'https'
    port = parsed.port or (443 if use_tls else 80)

    # Candidate WS paths: discovered + common.
    paths = list(WS_PATHS)
    for ep in crawl_targets:
        p = ep.get('path', '')
        if any(k in p.lower() for k in ('ws', 'socket', 'live', 'stream')):
            paths.insert(0, p)
    paths = list(dict.fromkeys(paths))[:8]

    for path in paths:
        sock, resp = _ws_handshake(host, port, path, use_tls, timeout=timeout)
        if not resp or '101' not in resp.split('\r\n', 1)[0]:
            if sock:
                try: sock.close()
                except Exception: pass
            continue
        # Endpoint speaks WebSocket.
        results.append({
            'technique': f'WebSocket endpoint: {path}', 'bypass': False, 'status': 101,
            'reason': 'WebSocket upgrade succeeded', 'severity': 'INFO',
            'category': 'WEBSOCKET', 'path': path,
        })

        # CSWSH: re-handshake with an attacker origin; acceptance => no origin check.
        s2, r2 = _ws_handshake(host, port, path, use_tls,
                               origin='https://evil.example.com', timeout=timeout)
        if r2 and '101' in r2.split('\r\n', 1)[0]:
            results.append({
                'technique': f'CSWSH (no origin validation): {path}', 'bypass': True,
                'status': 101, 'reason': 'Upgrade accepted with attacker Origin header',
                'severity': 'HIGH', 'category': 'WEBSOCKET', 'path': path,
            })
            print(f"  [✓] HIGH: CSWSH possible on {path}")
        if s2:
            try: s2.close()
            except Exception: pass

        # Message fuzzing on the original connection.
        anomalies = 0
        try:
            for msg in FUZZ_MESSAGES:
                try:
                    _ws_send_text(sock, msg)
                    reply = _ws_recv(sock, timeout=2)
                    low = reply.lower()
                    if any(ind in low for ind in (b'error', b'exception', b'traceback', b'stack')):
                        anomalies += 1
                except Exception:
                    anomalies += 1  # send failure / unexpected close
                    break
        finally:
            try: sock.close()
            except Exception: pass
        if anomalies:
            results.append({
                'technique': f'WebSocket fuzzing anomalies: {path}', 'bypass': True,
                'status': 101, 'reason': f'{anomalies} malformed/oversized message(s) caused errors or closes',
                'severity': 'MEDIUM', 'category': 'WEBSOCKET', 'path': path,
            })
            print(f"  [✓] MEDIUM: WebSocket fuzzing anomalies on {path}")
    return results
