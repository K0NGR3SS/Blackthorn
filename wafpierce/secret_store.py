"""Small secret-storage boundary for local integrations.

Secrets are never written to Blackthorn's JSON preferences or SQLite database.
Environment variables take precedence. When the optional ``keyring`` package is
available, values entered in the GUI are stored in the operating-system
credential store; otherwise they remain available only for the current process.
"""
from __future__ import annotations

import os
import re
from typing import Iterable, Optional, Tuple


SERVICE_NAME = 'Blackthorn'
_SESSION_SECRETS = {}


def _keyring():
    try:
        import keyring
        return keyring
    except Exception:
        return None


def get_secret(name: str, env_names: Iterable[str] = ()) -> str:
    """Return a secret without exposing its source to callers."""
    for env_name in tuple(env_names) + (secret_handle_env_name(name),):
        value = os.environ.get(env_name)
        if value:
            return value
    if name in _SESSION_SECRETS:
        return _SESSION_SECRETS[name]
    backend = _keyring()
    if backend is not None:
        try:
            value = backend.get_password(SERVICE_NAME, name)
            if value:
                return value
        except Exception:
            pass
    return ''


def secret_handle_env_name(name: str) -> str:
    """Return the generic environment variable for an arbitrary secret handle."""
    safe = re.sub(r'[^A-Za-z0-9]+', '_', str(name or '')).strip('_').upper()
    return f'BLACKTHORN_SECRET_{safe}'


def set_secret(name: str, value: Optional[str]) -> bool:
    """Set or clear a secret.

    Returns ``True`` when the value was persisted in an OS credential store.
    A ``False`` result means a non-empty value is process-local only.
    """
    clean = str(value or '')
    backend = _keyring()
    if not clean:
        _SESSION_SECRETS.pop(name, None)
        if backend is not None:
            try:
                backend.delete_password(SERVICE_NAME, name)
            except Exception:
                pass
        return backend is not None

    _SESSION_SECRETS[name] = clean
    if backend is not None:
        try:
            backend.set_password(SERVICE_NAME, name, clean)
            return True
        except Exception:
            pass
    return False


def ai_secret_name(provider: str = 'anthropic') -> str:
    normalized = (provider or 'anthropic').strip().lower().replace('_', '-')
    return f'ai:{normalized}:api-key'


def ai_secret_env_names(provider: str = 'anthropic') -> Tuple[str, ...]:
    normalized = (provider or 'anthropic').strip().lower().replace('_', '-')
    if normalized == 'anthropic':
        return ('ANTHROPIC_API_KEY',)
    if normalized == 'openai-compatible':
        return ('AI_API_KEY', 'OPENAI_API_KEY')
    return ()


def get_ai_api_key(provider: str = 'anthropic') -> str:
    return get_secret(ai_secret_name(provider), ai_secret_env_names(provider))


def set_ai_api_key(provider: str, value: Optional[str]) -> bool:
    return set_secret(ai_secret_name(provider), value)


def get_msf_password() -> str:
    return get_secret('metasploit:rpc-password', ('MSF_RPC_PASSWORD',))


def set_msf_password(value: Optional[str]) -> bool:
    return set_secret('metasploit:rpc-password', value)


def get_zap_api_key() -> str:
    return get_secret('zap:api-key', ('ZAP_API_KEY',))


def set_zap_api_key(value: Optional[str]) -> bool:
    return set_secret('zap:api-key', value)


def tool_secret_env_name(tool_key: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9]+', '_', str(tool_key or '')).strip('_').upper()
    return f'BLACKTHORN_TOOL_{safe}_API_KEY'


def get_tool_api_key(tool_key: str) -> str:
    name = f'external-tool:{tool_key}:api-key'
    return get_secret(name, (tool_secret_env_name(tool_key),))


def set_tool_api_key(tool_key: str, value: Optional[str]) -> bool:
    return set_secret(f'external-tool:{tool_key}:api-key', value)


def proxy_secret_env_name(proxy_name: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9]+', '_', str(proxy_name or '')).strip('_').upper()
    return f'BLACKTHORN_PROXY_{safe}_PASSWORD'


def get_proxy_password(proxy_name: str) -> str:
    name = f'proxy:{proxy_name}:password'
    return get_secret(name, (proxy_secret_env_name(proxy_name),))


def set_proxy_password(proxy_name: str, value: Optional[str]) -> bool:
    return set_secret(f'proxy:{proxy_name}:password', value)
