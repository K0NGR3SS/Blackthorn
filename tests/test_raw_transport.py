import socket
import threading

import pytest

from wafpierce.pentest_policy import ExecutionPolicy, PolicyViolation
from wafpierce.raw_transport import (
    HTTP2_CLIENT_PREFACE,
    HTTP2Frame,
    RawHTTP1Request,
    RawHTTP1Transport,
    parse_http2_frames,
)


def _server():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    received = []

    def run():
        conn, _addr = listener.accept()
        conn.settimeout(2)
        try:
            data = conn.recv(65535)
            received.append(data)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return listener.getsockname()[1], received, thread


def _policy(url, **overrides):
    values = dict(
        scope=(url,),
        confirm_authorized=True,
        active=True,
        full_impact=True,
        intrusive=True,
        timeout=2,
    )
    values.update(overrides)
    return ExecutionPolicy(**values)


def test_http1_serializer_preserves_duplicate_headers_exactly():
    request = RawHTTP1Request(
        "http://example.test/path?q=1",
        headers=(("X-Test", "one"), ("X-Test", "two")),
    )
    wire = request.to_bytes()
    assert wire.count(b"X-Test:") == 2
    assert wire.startswith(b"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\n")


def test_http1_transport_is_scope_and_intrusive_gated():
    request = RawHTTP1Request("http://127.0.0.1:9/")
    safe_only = _policy("http://127.0.0.1:9/", full_impact=False, intrusive=False)
    with pytest.raises(PolicyViolation):
        RawHTTP1Transport(safe_only).exchange(request)


def test_http1_transport_sends_duplicate_headers_to_local_fixture():
    port, received, thread = _server()
    url = "http://127.0.0.1:%d/" % port
    request = RawHTTP1Request(
        url,
        headers=(("X-Duplicate", "first"), ("X-Duplicate", "second")),
    )
    exchange = RawHTTP1Transport(_policy(url)).exchange(request)
    thread.join(timeout=3)
    assert exchange.status_codes == (200,)
    assert received[0].count(b"X-Duplicate:") == 2


def test_http2_frame_encoding_and_parsing_are_exact():
    frame = HTTP2Frame(frame_type=0x6, flags=0x1, stream_id=0, payload=b"12345678")
    encoded = frame.to_bytes()
    assert encoded[:3] == b"\x00\x00\x08"
    assert encoded[3:5] == b"\x06\x01"
    assert parse_http2_frames(encoded) == (frame,)
    assert HTTP2_CLIENT_PREFACE.startswith(b"PRI * HTTP/2.0")
