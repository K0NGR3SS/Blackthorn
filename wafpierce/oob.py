"""
Out-of-band (OOB) interaction engine.

Blind vulnerabilities — SSRF, Log4Shell/JNDI, blind XXE, blind RCE, blind SQLi
with DNS exfil — fire a payload that makes the *target* reach out to a server we
control. Without somewhere to catch that callback, the scanner can only guess.
This module provides that catcher behind a small pluggable interface so the
engine doesn't care whether the callbacks land on a hosted Interactsh server or
a listener you run yourself.

Providers
---------
* :class:`InteractshClient`  — speaks the Interactsh protocol (public ``oast.*``
  servers run by ProjectDiscovery, or your own self-hosted instance). Pure
  ``cryptography`` (already a core dependency); no extra packages.
* :class:`SelfHostedListener` — a built-in HTTP (and best-effort DNS) callback
  server you bind on a host you own. Full control, no third party involved.

Both implement :class:`OOBProvider`. Use :func:`build_oob` to construct one from
simple config. OOB is **opt-in**: nothing here runs unless the caller explicitly
enables it, because callbacks may traverse third-party infrastructure.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import random
import socket
import string
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ProjectDiscovery's public Interactsh servers (rotated if one fails).
DEFAULT_INTERACTSH_SERVERS = [
    "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
]

_ALPHANUM = string.ascii_lowercase + string.digits


def _rand(n: int) -> str:
    return ''.join(random.choices(_ALPHANUM, k=n))


def _mk_token(label: Optional[str]) -> str:
    """A unique, DNS/path-safe correlation token. ``label`` (e.g. 'ssrf') is kept
    only as a human-readable prefix; the random suffix guarantees uniqueness so
    every individual probe correlates to exactly one finding."""
    base = ''.join(c for c in (label or '').lower() if c in _ALPHANUM)[:12]
    return (base or 'oob') + _rand(8)


@dataclass
class Interaction:
    """A single inbound callback caught by an OOB provider."""
    protocol: str                      # 'dns' | 'http' | 'ldap' | 'smtp' | ...
    token: Optional[str]               # correlation token, if we can resolve it
    source: str = ''                   # remote address that hit us
    raw: str = ''                      # raw request/query, truncated
    timestamp: str = ''
    full_id: str = ''                  # provider-specific id (e.g. the subdomain)


@dataclass
class OOBHandle:
    """An embeddable callback target handed back by :meth:`OOBProvider.register`."""
    token: str
    domain: str          # bare host to embed (DNS/LDAP/SMTP payloads)
    http_url: str        # full URL to embed (SSRF / HTTP payloads)


class OOBProvider(ABC):
    """Pluggable out-of-band callback catcher."""

    name: str = 'oob'

    @abstractmethod
    def register(self, label: Optional[str] = None) -> OOBHandle:
        """Mint a fresh, unique callback target correlated to ``label``."""

    @abstractmethod
    def poll(self) -> List[Interaction]:
        """Return interactions received since the last poll."""

    def close(self) -> None:  # pragma: no cover - trivial
        pass


# --------------------------------------------------------------------------- #
# Interactsh
# --------------------------------------------------------------------------- #
class InteractshClient(OOBProvider):
    """Minimal Interactsh protocol client (register + poll + decrypt).

    Implements exactly what the engine needs: register an RSA public key, mint
    unique subdomains under one correlation id, poll, and AES/RSA-decrypt the
    returned interactions.
    """

    name = 'interactsh'

    def __init__(self, server: Optional[str] = None, token: Optional[str] = None,
                 session=None, timeout: int = 10, auto_register: bool = True):
        # Lazy import so a missing 'requests' (it's core, but be safe) or crypto
        # surfaces as a clean disabled-provider rather than an import crash.
        import requests
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        self.timeout = timeout
        self.auth_token = token
        self._session = session or requests.Session()
        self._servers = [server] if server else list(DEFAULT_INTERACTSH_SERVERS)

        # 20-char correlation id (server keys interactions on this prefix) and a
        # per-client secret used to authorize polling.
        self.correlation_id = _rand(20)
        self.secret = _rand(36)

        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._pub_b64 = base64.b64encode(pub_pem).decode()

        # label (subdomain leftmost) -> token, for correlating interactions back.
        self._handles: Dict[str, str] = {}
        self.server: Optional[str] = None
        if auto_register:
            self._register()

    # -- registration ----------------------------------------------------- #
    def _register(self) -> None:
        body = {
            "public-key": self._pub_b64,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = self.auth_token
        last_err = None
        for server in self._servers:
            try:
                r = self._session.post(f"https://{server}/register", json=body,
                                       headers=headers, timeout=self.timeout, verify=True)
                if r.status_code == 200:
                    self.server = server
                    logger.info(f"Interactsh registered with {server}")
                    return
                last_err = f"{server}: HTTP {r.status_code}"
            except Exception as e:  # try the next server
                last_err = f"{server}: {e}"
        raise RuntimeError(f"Interactsh registration failed ({last_err})")

    # -- handles ----------------------------------------------------------- #
    def register(self, label: Optional[str] = None) -> OOBHandle:
        if not self.server:
            raise RuntimeError("Interactsh client not registered")
        # Subdomain = correlation_id (20) + random (13) = 33 chars, lowercase.
        sub = self.correlation_id + _rand(13)
        token = _mk_token(label)
        self._handles[sub] = token
        domain = f"{sub}.{self.server}"
        return OOBHandle(token=token, domain=domain, http_url=f"http://{domain}")

    # -- polling ----------------------------------------------------------- #
    def poll(self) -> List[Interaction]:
        if not self.server:
            return []
        headers = {}
        if self.auth_token:
            headers["Authorization"] = self.auth_token
        try:
            r = self._session.get(
                f"https://{self.server}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
                headers=headers, timeout=self.timeout, verify=True,
            )
            if r.status_code != 200:
                return []
            payload = r.json()
        except Exception as e:
            logger.debug(f"Interactsh poll error: {e}")
            return []

        data = payload.get("data") or []
        aes_key_b64 = payload.get("aes_key")
        if not data or not aes_key_b64:
            return []
        return self._decrypt_interactions(data, aes_key_b64)

    def _decrypt_interactions(self, data: List[str], aes_key_b64: str) -> List[Interaction]:
        """Decrypt a poll response. Separated out so it is unit-testable."""
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        # CFB is being relocated to hazmat.decrepit in cryptography 49+. Prefer
        # the new home, fall back to the legacy one on current releases.
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except Exception:
            from cryptography.hazmat.primitives.ciphers.modes import CFB

        try:
            aes_key = self._priv.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None),
            )
        except Exception as e:
            logger.debug(f"Interactsh AES-key decrypt failed: {e}")
            return []

        out: List[Interaction] = []
        for item in data:
            try:
                blob = base64.b64decode(item)
                iv, ct = blob[:16], blob[16:]
                dec = Cipher(algorithms.AES(aes_key), CFB(iv)).decryptor()
                plaintext = dec.update(ct) + dec.finalize()
                obj = json.loads(plaintext.decode('utf-8', 'replace'))
            except Exception as e:
                logger.debug(f"Interactsh interaction decrypt failed: {e}")
                continue
            full_id = obj.get('full-id') or obj.get('unique-id') or ''
            token = self._handles.get(full_id)
            out.append(Interaction(
                protocol=obj.get('protocol', '?'),
                token=token,
                source=obj.get('remote-address', ''),
                raw=(obj.get('raw-request') or '')[:2000],
                timestamp=obj.get('timestamp', ''),
                full_id=full_id,
            ))
        return out


# --------------------------------------------------------------------------- #
# Self-hosted listener
# --------------------------------------------------------------------------- #
class SelfHostedListener(OOBProvider):
    """Built-in HTTP (+ best-effort DNS) callback listener.

    Bind on a host you control. Tokens are embedded as the leftmost DNS label
    (``<token>.<public_domain>``) and/or the first HTTP path segment
    (``http://<host>/<token>``), so both DNS-driven (JNDI/LDAP) and HTTP-driven
    (SSRF) payloads correlate back to the originating test.
    """

    name = 'selfhosted'

    def __init__(self, public_domain: Optional[str] = None,
                 bind_host: str = '0.0.0.0', http_port: int = 0,
                 dns_port: Optional[int] = None, public_host: Optional[str] = None):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.public_domain = (public_domain or '').strip('.')
        self._interactions: List[Interaction] = []
        self._lock = threading.Lock()
        self._tokens: set = set()

        listener = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def _record_and_reply(self):
                host = self.headers.get('Host', '')
                token = listener._token_from(self.path, host)
                listener._add(Interaction(
                    protocol='http', token=token,
                    source=self.client_address[0],
                    raw=f"{self.command} {self.path} Host:{host}"[:2000],
                    timestamp=str(time.time()), full_id=host,
                ))
                body = b"ok"
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            do_GET = _record_and_reply
            do_POST = _record_and_reply

        self._http = ThreadingHTTPServer((bind_host, http_port), _Handler)
        self.http_port = self._http.server_address[1]
        self.public_host = public_host or f"{bind_host}:{self.http_port}"
        self._http_thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._http_thread.start()

        self._dns = None
        self._dns_thread = None
        if dns_port is not None:
            self._start_dns(bind_host, dns_port)

    # -- token correlation ------------------------------------------------- #
    def _token_from(self, path: str, host: str) -> Optional[str]:
        # HTTP path form: /<token>/...
        seg = path.lstrip('/').split('/', 1)[0].split('?', 1)[0]
        if seg in self._tokens:
            return seg
        # DNS/Host form: <token>.<public_domain>
        label = (host or '').split(':', 1)[0].split('.', 1)[0]
        if label in self._tokens:
            return label
        return None

    def _add(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.append(interaction)

    # -- DNS (best effort; needs privileged port / NS delegation) ---------- #
    def _start_dns(self, bind_host: str, dns_port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, dns_port))
        except Exception as e:
            logger.warning(f"OOB DNS listener disabled (bind {bind_host}:{dns_port} failed: {e})")
            return
        self._dns = sock
        self._dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
        self._dns_thread.start()

    def _dns_loop(self) -> None:
        while self._dns is not None:
            try:
                data, addr = self._dns.recvfrom(512)
            except OSError:
                break
            try:
                name = self._parse_dns_qname(data)
                label = name.split('.', 1)[0] if name else ''
                token = label if label in self._tokens else None
                self._add(Interaction(protocol='dns', token=token, source=addr[0],
                                      raw=name[:2000], timestamp=str(time.time()),
                                      full_id=name))
            except Exception:
                pass

    @staticmethod
    def _parse_dns_qname(data: bytes) -> str:
        # Skip the 12-byte header, then read length-prefixed labels.
        idx, labels = 12, []
        try:
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    break
                labels.append(data[idx + 1: idx + 1 + length].decode('ascii', 'replace'))
                idx += length + 1
        except Exception:
            pass
        return '.'.join(labels)

    # -- provider API ------------------------------------------------------ #
    def register(self, label: Optional[str] = None) -> OOBHandle:
        token = _mk_token(label)
        self._tokens.add(token)
        if self.public_domain:
            domain = f"{token}.{self.public_domain}"
            return OOBHandle(token=token, domain=domain, http_url=f"http://{domain}")
        # HTTP-only mode: no real domain, embed token in the path.
        return OOBHandle(token=token, domain=self.public_host,
                         http_url=f"http://{self.public_host}/{token}")

    def poll(self) -> List[Interaction]:
        with self._lock:
            out = self._interactions
            self._interactions = []
        return out

    def close(self) -> None:
        try:
            self._http.shutdown()
            self._http.server_close()
        except Exception:
            pass
        if self._dns is not None:
            sock, self._dns = self._dns, None
            try:
                sock.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def build_oob(mode: Optional[str], **cfg) -> Optional[OOBProvider]:
    """Construct an OOB provider from simple config, or ``None`` if disabled.

    Args:
        mode: 'interactsh' | 'selfhosted' | None/'off'.
        cfg : provider kwargs (server/token for interactsh; public_domain /
              bind_host / http_port / dns_port / public_host for selfhosted).
    """
    if not mode or mode.lower() in ('off', 'none', 'disabled'):
        return None
    mode = mode.lower()
    try:
        if mode == 'interactsh':
            return InteractshClient(server=cfg.get('server'), token=cfg.get('token'))
        if mode == 'selfhosted':
            return SelfHostedListener(
                public_domain=cfg.get('public_domain'),
                bind_host=cfg.get('bind_host', '0.0.0.0'),
                http_port=int(cfg.get('http_port', 0) or 0),
                dns_port=(int(cfg['dns_port']) if cfg.get('dns_port') else None),
                public_host=cfg.get('public_host'),
            )
    except Exception as e:
        logger.error(f"OOB provider '{mode}' failed to start: {e}")
        return None
    logger.warning(f"Unknown OOB mode: {mode}")
    return None
