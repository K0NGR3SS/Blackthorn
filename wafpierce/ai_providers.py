"""Provider-neutral AI helpers for WAFPierce.

The existing AI implementation is Anthropic-backed and remains the only
provider shipped today. This module gives the rest of the app a stable facade so
future providers or local agents can plug in without changing scanner flags.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class AIProviderStatus:
    provider: str
    configured: bool
    available: bool
    reason: str = ''

    @property
    def ready(self) -> bool:
        return self.configured and self.available


def provider_status(provider: str = 'anthropic', api_key: Optional[str] = None) -> AIProviderStatus:
    """Return non-secret readiness metadata for an AI provider."""
    provider = (provider or 'anthropic').lower()
    if provider != 'anthropic':
        return AIProviderStatus(provider, False, False, 'provider is not implemented')
    try:
        from . import ai_triage
    except Exception as e:
        return AIProviderStatus(provider, bool(api_key), False, str(e))
    configured = bool(api_key or os.environ.get('ANTHROPIC_API_KEY'))
    available = bool(getattr(ai_triage, 'ANTHROPIC_AVAILABLE', False))
    reason = ''
    if not available:
        reason = 'anthropic package is not installed'
    elif not configured:
        reason = 'ANTHROPIC_API_KEY is not configured'
    return AIProviderStatus(provider, configured, available, reason)


def triage_results(provider: str, target: str, results: List[Dict],
                   api_key: Optional[str] = None, model: Optional[str] = None,
                   max_findings: int = 60) -> Dict:
    """Provider-neutral triage facade. No-op when the provider is unavailable."""
    provider = (provider or 'anthropic').lower()
    if provider != 'anthropic':
        return {}
    from .ai_triage import triage_results as _triage
    return _triage(target, results, api_key=api_key, model=model,
                   max_findings=max_findings)


def write_report(provider: str, target: str, results: List[Dict],
                 api_key: Optional[str] = None, model: Optional[str] = None) -> str:
    """Provider-neutral report facade. Returns an empty string if unavailable."""
    provider = (provider or 'anthropic').lower()
    if provider != 'anthropic':
        return ''
    from .ai_triage import write_report as _write
    return _write(target, results, api_key=api_key, model=model)


def generate_payload_mutations(provider: str, seed_payloads: List[str],
                               context: str = 'generic WAF',
                               api_key: Optional[str] = None,
                               model: Optional[str] = None,
                               n: int = 12) -> List[str]:
    """Provider-neutral payload mutation facade."""
    provider = (provider or 'anthropic').lower()
    if provider != 'anthropic':
        return []
    from .ai_triage import generate_payload_mutations as _mutate
    return _mutate(seed_payloads, context=context, api_key=api_key,
                   model=model, n=n)
