"""
Certificate authority for the built-in intercepting proxy (P4).

Generates a local root CA (once) under ``%APPDATA%/wafpierce/ca`` and mints
short per-host leaf certificates signed by it, so the proxy can MITM HTTPS for
hosts the user chooses to intercept. Uses ``cryptography`` (already a hard dep).

SECURITY: the CA private key on disk can sign for any host. It is created with
restrictive permissions, lives only on this machine, and must be installed into
the trust store *explicitly* by the user (see ``certutil_add_cmd``). A one-click
removal command is provided. Never auto-installed.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import threading
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


CA_CERT_NAME = 'wafpierce_ca.pem'
CA_KEY_NAME = 'wafpierce_ca_key.pem'
_ONE_DAY = datetime.timedelta(days=1)


def _fixed_now() -> datetime.datetime:
    # Date.now() is unavailable in some sandboxes; use a fixed-but-valid notBefore.
    try:
        return datetime.datetime.utcnow()
    except Exception:
        return datetime.datetime(2020, 1, 1)


class CertAuthority:
    """Lazily creates/loads the root CA and issues cached per-host leaf certs."""

    def __init__(self, ca_dir: str):
        self.ca_dir = ca_dir
        os.makedirs(ca_dir, exist_ok=True)
        self.ca_cert_path = os.path.join(ca_dir, CA_CERT_NAME)
        self.ca_key_path = os.path.join(ca_dir, CA_KEY_NAME)
        self._ca_cert: Optional[x509.Certificate] = None
        self._ca_key = None
        self._leaf_cache: Dict[str, Tuple[str, str]] = {}
        self._lock = threading.Lock()
        self._load_or_create_ca()

    # -- root CA ----------------------------------------------------------- #
    def _load_or_create_ca(self):
        if os.path.isfile(self.ca_cert_path) and os.path.isfile(self.ca_key_path):
            try:
                with open(self.ca_key_path, 'rb') as f:
                    self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(self.ca_cert_path, 'rb') as f:
                    self._ca_cert = x509.load_pem_x509_certificate(f.read())
                return
            except Exception:
                pass
        self._create_ca()

    def _create_ca(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'WAFPierce Proxy CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'WAFPierce'),
        ])
        now = _fixed_now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _ONE_DAY)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(key, hashes.SHA256())
        )
        with open(self.ca_key_path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        with open(self.ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(self.ca_key_path, 0o600)
        except Exception:
            pass
        self._ca_cert, self._ca_key = cert, key

    @property
    def ca_cert_pem(self) -> bytes:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    # -- leaf certs -------------------------------------------------------- #
    def leaf_for(self, hostname: str) -> Tuple[str, str]:
        """Return (cert_pem_path, key_pem_path) for ``hostname``, minting+caching
        as needed. Files are written so ssl can load them by path."""
        with self._lock:
            if hostname in self._leaf_cache:
                return self._leaf_cache[hostname]
            cert_pem, key_pem = self._mint_leaf(hostname)
            cert_path = os.path.join(self.ca_dir, f'leaf_{_safe(hostname)}.pem')
            key_path = os.path.join(self.ca_dir, f'leaf_{_safe(hostname)}_key.pem')
            with open(cert_path, 'wb') as f:
                f.write(cert_pem)
            with open(key_path, 'wb') as f:
                f.write(key_pem)
            try:
                os.chmod(key_path, 0o600)
            except Exception:
                pass
            self._leaf_cache[hostname] = (cert_path, key_path)
            return cert_path, key_path

    def _mint_leaf(self, hostname: str) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            san = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)
        now = _fixed_now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _ONE_DAY)
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )
        return (cert.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))

    # -- trust-store helpers (commands only; never executed automatically) - #
    def certutil_add_cmd(self) -> list:
        """Windows command to install the CA into the CURRENT USER root store."""
        return ['certutil', '-addstore', '-user', 'Root', self.ca_cert_path]

    def certutil_del_cmd(self) -> list:
        return ['certutil', '-delstore', '-user', 'Root', 'WAFPierce Proxy CA']


def _safe(host: str) -> str:
    return ''.join(c if c.isalnum() or c in '.-' else '_' for c in host)[:80]
