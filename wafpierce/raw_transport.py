"""Exact HTTP/1.1 and HTTP/2 wire transports behind intrusive scope gates.

These transports provide the fidelity required for duplicate-header,
desynchronization, and frame-level research. They do not infer vulnerabilities;
callers must pair exchanges with a ProofContract and matched controls.
"""
from __future__ import annotations

import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .pentest_models import ImpactLevel, ModelValidationError, validate_header_pairs, validate_url
from .pentest_policy import ExecutionPolicy, PolicyViolation, RequestBudget


HTTP2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_RAW_REQUEST_BYTES = 8 * 1024 * 1024
MAX_HTTP2_FRAME_BYTES = (1 << 24) - 1
_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
_STATUS_LINE_RE = re.compile(br"(?m)^HTTP/1\.[01] ([1-5][0-9]{2})(?: |\r?$)")


class RawTransportError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class RawHTTP1Request:
    url: str
    method: str = "GET"
    request_target: str = ""
    headers: Tuple[Tuple[str, str], ...] = ()
    body: bytes = b""
    auto_host: bool = True
    auto_content_length: bool = False

    def __post_init__(self) -> None:
        url = validate_url(self.url, allow_ws=False)
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ModelValidationError("raw HTTP/1.1 requires HTTP or HTTPS")
        method = str(self.method or "GET").upper()
        if not _METHOD_RE.fullmatch(method):
            raise ModelValidationError("invalid raw HTTP method")
        target = self.request_target or (
            parsed.path or "/"
        ) + (("?" + parsed.query) if parsed.query else "")
        if not target.startswith("/") or "\r" in target or "\n" in target:
            raise ModelValidationError("raw request target must use origin form")
        headers = validate_header_pairs(self.headers, permit_secret_placeholders=False)
        body = bytes(self.body or b"")
        if len(body) > MAX_RAW_REQUEST_BYTES:
            raise ModelValidationError("raw request body is too large")
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "request_target", target)
        object.__setattr__(self, "headers", headers)
        object.__setattr__(self, "body", body)

    def to_bytes(self) -> bytes:
        parsed = urlsplit(self.url)
        headers = list(self.headers)
        lower_names = [name.lower() for name, _value in headers]
        if self.auto_host and "host" not in lower_names:
            hostname = parsed.hostname or ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = "[%s]" % hostname
            default_port = 443 if parsed.scheme == "https" else 80
            authority = hostname if parsed.port in (None, default_port) else "%s:%d" % (
                hostname, parsed.port
            )
            headers.insert(0, ("Host", authority))
            lower_names.insert(0, "host")
        if self.auto_content_length and self.body and "content-length" not in lower_names:
            headers.append(("Content-Length", str(len(self.body))))
        head = ["%s %s HTTP/1.1" % (self.method, self.request_target)]
        head.extend("%s: %s" % (name, value) for name, value in headers)
        data = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + self.body
        if len(data) > MAX_RAW_REQUEST_BYTES:
            raise ModelValidationError("serialized raw request is too large")
        return data


@dataclass(frozen=True, repr=False)
class RawExchange:
    target: str
    sent: bytes
    received: bytes
    duration_ms: float
    peer: str
    protocol: str

    @property
    def status_codes(self) -> Tuple[int, ...]:
        return tuple(int(match.group(1)) for match in _STATUS_LINE_RE.finditer(self.received))


class _SocketTransport:
    def __init__(
        self,
        policy: ExecutionPolicy,
        *,
        verify_tls: bool = True,
        budget: Optional[RequestBudget] = None,
    ):
        self.policy = policy
        self.verify_tls = bool(verify_tls)
        self.budget = budget or RequestBudget(
            policy.request_budget, policy.minimum_delay
        )

    def _connect(self, target: str, *, alpn: Optional[Sequence[str]] = None):
        parsed = urlsplit(target)
        host = parsed.hostname
        if not host:
            raise RawTransportError("target hostname is missing")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        sock = socket.create_connection((host, port), timeout=self.policy.timeout)
        sock.settimeout(self.policy.timeout)
        if parsed.scheme == "https":
            context = (
                ssl.create_default_context() if self.verify_tls
                else ssl._create_unverified_context()  # noqa: SLF001
            )
            if alpn:
                context.set_alpn_protocols(list(alpn))
            sock = context.wrap_socket(sock, server_hostname=host)
            if alpn and sock.selected_alpn_protocol() not in alpn:
                sock.close()
                raise RawTransportError("server did not negotiate the required ALPN protocol")
        return sock

    def _read_bounded(self, sock) -> bytes:
        chunks: List[bytes] = []
        total = 0
        while True:
            try:
                chunk = sock.recv(64 * 1024)
            except socket.timeout:
                break
            if not chunk:
                break
            total += len(chunk)
            if total > self.policy.max_response_bytes:
                raise RawTransportError("raw response exceeded the engagement byte limit")
            chunks.append(chunk)
        return b"".join(chunks)


class RawHTTP1Transport(_SocketTransport):
    def exchange(self, request: RawHTTP1Request) -> RawExchange:
        self.policy.require(request.url, ImpactLevel.INTRUSIVE)
        self.budget.consume()
        wire = request.to_bytes()
        started = time.monotonic()
        sock = self._connect(request.url, alpn=["http/1.1"] if request.url.startswith("https:") else None)
        try:
            peer = "%s:%s" % sock.getpeername()[:2]
            sock.sendall(wire)
            received = self._read_bounded(sock)
        finally:
            sock.close()
        return RawExchange(
            target=request.url,
            sent=wire,
            received=received,
            duration_ms=(time.monotonic() - started) * 1000,
            peer=peer,
            protocol="http/1.1",
        )


@dataclass(frozen=True, repr=False)
class HTTP2Frame:
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= int(self.frame_type) <= 255:
            raise ModelValidationError("HTTP/2 frame type is out of range")
        if not 0 <= int(self.flags) <= 255:
            raise ModelValidationError("HTTP/2 frame flags are out of range")
        if not 0 <= int(self.stream_id) <= 0x7FFFFFFF:
            raise ModelValidationError("HTTP/2 stream id is out of range")
        payload = bytes(self.payload or b"")
        if len(payload) > MAX_HTTP2_FRAME_BYTES:
            raise ModelValidationError("HTTP/2 frame payload is too large")
        object.__setattr__(self, "payload", payload)

    def to_bytes(self) -> bytes:
        length = len(self.payload)
        header = length.to_bytes(3, "big") + bytes((self.frame_type, self.flags))
        header += struct.pack("!I", self.stream_id & 0x7FFFFFFF)
        return header + self.payload


def parse_http2_frames(data: bytes, *, maximum_frames: int = 10000) -> Tuple[HTTP2Frame, ...]:
    frames: List[HTTP2Frame] = []
    offset = 0
    while offset + 9 <= len(data):
        if len(frames) >= maximum_frames:
            raise RawTransportError("HTTP/2 response contains too many frames")
        length = int.from_bytes(data[offset:offset + 3], "big")
        end = offset + 9 + length
        if end > len(data):
            break
        frames.append(HTTP2Frame(
            frame_type=data[offset + 3],
            flags=data[offset + 4],
            stream_id=struct.unpack("!I", data[offset + 5:offset + 9])[0] & 0x7FFFFFFF,
            payload=data[offset + 9:end],
        ))
        offset = end
    return tuple(frames)


class RawHTTP2Transport(_SocketTransport):
    """Send exact HTTP/2 frames over a TLS connection negotiated with ALPN.

    Callers provide already-encoded HPACK header blocks where needed. An empty
    client SETTINGS frame is added by default, preserving the caller's remaining
    frame bytes exactly.
    """

    def exchange_frames(
        self,
        target: str,
        frames: Iterable[HTTP2Frame],
        *,
        include_preface: bool = True,
        include_settings: bool = True,
    ) -> RawExchange:
        target = validate_url(target, allow_ws=False)
        if not target.startswith("https://"):
            raise RawTransportError("raw HTTP/2 transport currently requires TLS")
        self.policy.require(target, ImpactLevel.INTRUSIVE)
        self.budget.consume()
        frame_list = tuple(frames)
        wire = b""
        if include_preface:
            wire += HTTP2_CLIENT_PREFACE
        if include_settings:
            wire += HTTP2Frame(0x4, 0x0, 0, b"").to_bytes()
        wire += b"".join(frame.to_bytes() for frame in frame_list)
        if len(wire) > MAX_RAW_REQUEST_BYTES:
            raise RawTransportError("HTTP/2 frame sequence is too large")

        started = time.monotonic()
        sock = self._connect(target, alpn=["h2"])
        try:
            peer = "%s:%s" % sock.getpeername()[:2]
            sock.sendall(wire)
            received = self._read_bounded(sock)
        finally:
            sock.close()
        return RawExchange(
            target=target,
            sent=wire,
            received=received,
            duration_ms=(time.monotonic() - started) * 1000,
            peer=peer,
            protocol="h2",
        )
