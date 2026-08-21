import json
import os
import sqlite3
import stat

from wafpierce.database import WAFPierceDB
from wafpierce.gui import _load_prefs, _save_prefs
from wafpierce import secret_store


class _MemoryKeyring:
    def __init__(self):
        self.values = {}

    def get_password(self, service, name):
        return self.values.get((service, name))

    def set_password(self, service, name, value):
        self.values[(service, name)] = value

    def delete_password(self, service, name):
        self.values.pop((service, name), None)


def test_environment_secret_takes_precedence(monkeypatch):
    backend = _MemoryKeyring()
    monkeypatch.setattr(secret_store, '_keyring', lambda: backend)
    secret_store.set_ai_api_key('anthropic', 'keychain-value')
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'environment-value')

    assert secret_store.get_ai_api_key('anthropic') == 'environment-value'


def test_secret_store_uses_keyring_when_available(monkeypatch):
    backend = _MemoryKeyring()
    monkeypatch.setattr(secret_store, '_keyring', lambda: backend)

    assert secret_store.set_msf_password('rpc-secret') is True
    secret_store._SESSION_SECRETS.clear()
    assert secret_store.get_msf_password() == 'rpc-secret'


def test_generic_secret_handle_environment_variable(monkeypatch):
    handle = 'identity:alice:session'
    env_name = secret_store.secret_handle_env_name(handle)
    monkeypatch.setenv(env_name, 'environment-session')
    assert env_name == 'BLACKTHORN_SECRET_IDENTITY_ALICE_SESSION'
    assert secret_store.get_secret(handle) == 'environment-session'


def test_preferences_strip_and_migrate_plaintext_secrets(monkeypatch, tmp_path):
    prefs_path = tmp_path / 'gui_prefs.json'
    monkeypatch.setattr('wafpierce.gui.get_gui_prefs_path', lambda: str(prefs_path))
    monkeypatch.setattr(secret_store, '_keyring', lambda: None)
    secret_store._SESSION_SECRETS.clear()
    prefs_path.write_text(json.dumps({
        'ai_provider': 'anthropic',
        'anthropic_api_key': 'legacy-ai-secret',
        'msf_password': 'legacy-msf-secret',
        'zap_apikey': 'legacy-zap-secret',
        'advanced': {'safe_mode': True, 'ai_key': 'nested-secret'},
    }), encoding='utf-8')

    loaded = _load_prefs()
    persisted = prefs_path.read_text(encoding='utf-8')

    assert loaded['advanced'] == {'safe_mode': True}
    assert 'legacy-ai-secret' not in persisted
    assert 'legacy-msf-secret' not in persisted
    assert 'legacy-zap-secret' not in persisted
    assert 'nested-secret' not in persisted
    assert secret_store.get_ai_api_key('anthropic') == 'nested-secret'
    assert secret_store.get_msf_password() == 'legacy-msf-secret'
    assert secret_store.get_zap_api_key() == 'legacy-zap-secret'


def test_save_preferences_never_writes_nested_secrets(monkeypatch, tmp_path):
    prefs_path = tmp_path / 'gui_prefs.json'
    monkeypatch.setattr('wafpierce.gui.get_gui_prefs_path', lambda: str(prefs_path))

    _save_prefs({
        'language': 'en',
        'ai_api_key': 'top-secret',
        'advanced': {'safe_mode': True, 'ai_key': 'nested-secret'},
    })

    persisted = json.loads(prefs_path.read_text(encoding='utf-8'))
    assert persisted == {'language': 'en', 'advanced': {'safe_mode': True}}


def test_database_keeps_integration_secrets_out_of_sqlite(monkeypatch, tmp_path):
    monkeypatch.setattr(secret_store, '_keyring', lambda: None)
    secret_store._SESSION_SECRETS.clear()
    db_path = tmp_path / 'blackthorn.db'
    db = WAFPierceDB(str(db_path))

    assert db.save_tool_config('wpscan', api_key='tool-secret')
    db.add_proxy_config('corp', 'http', 'proxy.example', 8080,
                        username='analyst', password='proxy-secret')

    conn = sqlite3.connect(db_path)
    tool_value = conn.execute(
        'SELECT api_key FROM tool_configs WHERE tool_key=?', ('wpscan',)
    ).fetchone()[0]
    proxy_value = conn.execute(
        'SELECT password FROM proxy_configs WHERE name=?', ('corp',)
    ).fetchone()[0]
    conn.close()

    assert tool_value is None
    assert proxy_value is None
    assert db.get_tool_config('wpscan')['api_key'] == 'tool-secret'
    assert next(p for p in db.get_proxy_configs() if p['name'] == 'corp')[
        'password'
    ] == 'proxy-secret'


def test_database_strips_secrets_from_saved_pipelines(monkeypatch, tmp_path):
    monkeypatch.setattr(secret_store, '_keyring', lambda: None)
    secret_store._SESSION_SECRETS.clear()
    db_path = tmp_path / 'blackthorn.db'
    db = WAFPierceDB(str(db_path))
    definition = {
        'schema_version': 1,
        'stages': [{
            'id': 'wpscan',
            'type': 'external_tool',
            'config': {'tool': 'wpscan', 'api_key': 'pipeline-secret'},
        }],
    }

    assert db.save_pipeline('with-secret', definition)
    conn = sqlite3.connect(db_path)
    stored = conn.execute(
        'SELECT definition FROM pipelines WHERE name=?', ('with-secret',)
    ).fetchone()[0]
    conn.close()

    assert 'pipeline-secret' not in stored
    assert db.get_pipeline('with-secret')['definition']['stages'][0][
        'config'
    ] == {'tool': 'wpscan'}
    assert secret_store.get_tool_api_key('wpscan') == 'pipeline-secret'


def test_database_file_is_owner_only_on_unix(tmp_path):
    db_path = tmp_path / 'blackthorn.db'
    WAFPierceDB(str(db_path))
    if os.name != 'nt':
        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
