"""Tests for the out-of-band (OOB) interaction engine."""
import base64
import json
import time

import pytest

from wafpierce.oob import InteractshClient, SelfHostedListener, build_oob


def _simulate_interactsh_server(client, interaction: dict):
    """Encrypt an interaction the way an Interactsh server would, so the client's
    decrypt path can be exercised without any network."""
    import os
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except Exception:
        from cryptography.hazmat.primitives.ciphers.modes import CFB

    aes_key = os.urandom(32)
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(aes_key), CFB(iv)).encryptor()
    ct = enc.update(json.dumps(interaction).encode()) + enc.finalize()
    data_b64 = base64.b64encode(iv + ct).decode()

    enc_key = client._priv.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    return [data_b64], base64.b64encode(enc_key).decode()


def test_interactsh_decrypt_roundtrip():
    # No network: skip registration, drive only the crypto.
    client = InteractshClient(auto_register=False)
    client.server = 'oast.test'
    handle = client.register(label='ssrf')
    full_id = handle.domain.split('.', 1)[0]
    assert handle.token.startswith('ssrf')   # label is a readable prefix

    interaction = {
        'protocol': 'dns', 'full-id': full_id, 'unique-id': full_id,
        'remote-address': '198.51.100.7', 'q-type': 'A',
        'raw-request': 'lookup', 'timestamp': '2026-06-17T00:00:00Z',
    }
    data, aes_key_b64 = _simulate_interactsh_server(client, interaction)

    results = client._decrypt_interactions(data, aes_key_b64)
    assert len(results) == 1
    ix = results[0]
    assert ix.protocol == 'dns'
    assert ix.source == '198.51.100.7'
    assert ix.token == handle.token          # correlated back to the exact handle


def test_interactsh_tokens_are_unique_per_probe():
    client = InteractshClient(auto_register=False)
    client.server = 'oast.test'
    tokens = {client.register(label='ssrf').token for _ in range(10)}
    assert len(tokens) == 10                  # no collisions across probes


def test_interactsh_subdomain_shape():
    client = InteractshClient(auto_register=False)
    client.server = 'oast.test'
    h = client.register()
    label = h.domain.split('.', 1)[0]
    assert label.startswith(client.correlation_id)
    assert len(label) == 33          # 20-char correlation id + 13-char random
    assert h.http_url == f"http://{h.domain}"


def test_selfhosted_listener_catches_http_callback():
    import requests

    listener = SelfHostedListener(public_domain=None, bind_host='127.0.0.1',
                                  http_port=0)
    try:
        handle = listener.register(label='ssrf')
        # HTTP-only mode embeds the unique token in the path.
        assert handle.token.startswith('ssrf')
        assert handle.http_url.endswith('/' + handle.token)

        requests.get(handle.http_url, timeout=3)
        # Give the threaded server a beat to record.
        time.sleep(0.2)
        interactions = listener.poll()
        assert any(i.protocol == 'http' and i.token == handle.token for i in interactions)
        # Drained on poll.
        assert listener.poll() == []
    finally:
        listener.close()


def test_build_oob_off_returns_none():
    assert build_oob('off') is None
    assert build_oob(None) is None


def test_build_oob_selfhosted_constructs():
    provider = build_oob('selfhosted', bind_host='127.0.0.1', http_port=0)
    assert provider is not None
    try:
        assert provider.name == 'selfhosted'
        h = provider.register()
        assert h.token and h.http_url.startswith('http://')
    finally:
        provider.close()
