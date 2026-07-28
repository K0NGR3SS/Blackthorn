import ssl
import urllib.error

import pytest

from wafpierce import recon_install


class _FakeContext:
    def __init__(self):
        self.loaded = []

    def load_verify_locations(self, cafile=None):
        self.loaded.append(cafile)


def test_download_context_adds_certifi_to_system_trust(monkeypatch, tmp_path):
    bundle = tmp_path / 'certifi.pem'
    bundle.write_text('test roots', encoding='utf-8')
    context = _FakeContext()
    monkeypatch.setattr(ssl, 'create_default_context', lambda: context)
    monkeypatch.setattr(recon_install.certifi, 'where', lambda: str(bundle))
    for name in recon_install._CA_BUNDLE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)

    assert recon_install._ctx() is context
    assert context.loaded == [str(bundle)]


def test_download_context_adds_private_ca_bundle(monkeypatch, tmp_path):
    certifi_bundle = tmp_path / 'certifi.pem'
    private_bundle = tmp_path / 'private.pem'
    certifi_bundle.write_text('public roots', encoding='utf-8')
    private_bundle.write_text('private root', encoding='utf-8')
    context = _FakeContext()
    monkeypatch.setattr(ssl, 'create_default_context', lambda: context)
    monkeypatch.setattr(
        recon_install.certifi, 'where', lambda: str(certifi_bundle)
    )
    monkeypatch.setenv('BLACKTHORN_CA_BUNDLE', str(private_bundle))
    for name in recon_install._CA_BUNDLE_ENV_VARS[1:]:
        monkeypatch.delenv(name, raising=False)

    assert recon_install._ctx() is context
    assert context.loaded == [str(certifi_bundle), str(private_bundle)]


def test_download_context_rejects_missing_private_ca(monkeypatch, tmp_path):
    bundle = tmp_path / 'certifi.pem'
    bundle.write_text('public roots', encoding='utf-8')
    monkeypatch.setattr(
        ssl, 'create_default_context', lambda: _FakeContext()
    )
    monkeypatch.setattr(recon_install.certifi, 'where', lambda: str(bundle))
    monkeypatch.setenv(
        'BLACKTHORN_CA_BUNDLE', str(tmp_path / 'does-not-exist.pem')
    )
    for name in recon_install._CA_BUNDLE_ENV_VARS[1:]:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match='BLACKTHORN_CA_BUNDLE.*does not exist'):
        recon_install._ctx()


def test_urlopen_explains_certificate_verification_failure(monkeypatch):
    certificate_error = ssl.SSLCertVerificationError(
        1, 'certificate verify failed'
    )

    def fail(*_args, **_kwargs):
        raise urllib.error.URLError(certificate_error)

    monkeypatch.setattr(urllib.request, 'urlopen', fail)
    monkeypatch.setattr(recon_install, '_ctx', lambda: _FakeContext())
    request = urllib.request.Request('https://api.github.com/')

    with pytest.raises(RuntimeError, match='BLACKTHORN_CA_BUNDLE'):
        recon_install._urlopen(request, timeout=1)


@pytest.mark.parametrize(
    ('name', 'expected_repo'),
    [
        ('tlsx', 'projectdiscovery/tlsx'),
        ('gau', 'lc/gau'),
    ],
)
def test_download_all_routes_failing_tools_through_github_installer(
        monkeypatch, name, expected_repo):
    calls = []
    monkeypatch.setattr(recon_install, 'ensure_tools_on_path', lambda: '/tools')

    def install(repo, binary, _log):
        calls.append((repo, binary))
        return f'/tools/{binary}'

    monkeypatch.setattr(recon_install, '_install_github_tool', install)

    result = recon_install.download_all(only=[name])

    assert result[name] == ('ok', f'/tools/{name}')
    assert calls == [(expected_repo, name)]
