"""Provider-neutral AI helpers for Blackthorn.

Supported providers:
  * anthropic            Existing Claude integration via ``anthropic`` package.
  * ollama               Local models such as qwen/coder via Ollama HTTP API.
  * openai-compatible    Any Chat Completions compatible endpoint.

Every call is opt-in and best-effort. Missing packages, offline local models, or
bad API keys return safe no-op values rather than breaking scans.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional


DEFAULT_OLLAMA_URL = 'http://127.0.0.1:11434'
DEFAULT_OLLAMA_MODEL = 'qwen2.5-coder:7b'


@dataclass(frozen=True)
class AIProviderStatus:
    provider: str
    configured: bool
    available: bool
    reason: str = ''
    model: str = ''
    base_url: str = ''

    @property
    def ready(self) -> bool:
        return self.configured and self.available


def normalize_provider(provider: str = '') -> str:
    p = (provider or 'anthropic').strip().lower().replace('_', '-')
    aliases = {
        'claude': 'anthropic',
        'anthropic': 'anthropic',
        'ollama': 'ollama',
        'local': 'ollama',
        'openai': 'openai-compatible',
        'openai-compatible': 'openai-compatible',
        'compatible': 'openai-compatible',
    }
    return aliases.get(p, p)


def provider_status(provider: str = 'anthropic', api_key: Optional[str] = None,
                    base_url: Optional[str] = None, model: Optional[str] = None,
                    timeout: float = 1.5) -> AIProviderStatus:
    """Return non-secret readiness metadata for an AI provider."""
    provider = normalize_provider(provider)
    model = model or ''
    base_url = (base_url or '').rstrip('/')
    if provider == 'anthropic':
        try:
            from . import ai_triage
        except Exception as e:
            return AIProviderStatus(provider, bool(api_key), False, str(e), model, base_url)
        configured = bool(api_key or os.environ.get('ANTHROPIC_API_KEY'))
        available = bool(getattr(ai_triage, 'ANTHROPIC_AVAILABLE', False))
        reason = ''
        if not available:
            reason = 'anthropic package is not installed'
        elif not configured:
            reason = 'ANTHROPIC_API_KEY is not configured'
        return AIProviderStatus(provider, configured, available, reason, model, base_url)

    if provider == 'ollama':
        base_url = base_url or DEFAULT_OLLAMA_URL
        model = model or DEFAULT_OLLAMA_MODEL
        configured = bool(base_url and model)
        if not configured:
            return AIProviderStatus(provider, False, False, 'Ollama URL/model missing',
                                    model, base_url)
        try:
            _http_json('GET', f'{base_url}/api/tags', timeout=timeout)
            return AIProviderStatus(provider, True, True, '', model, base_url)
        except Exception as e:
            return AIProviderStatus(provider, True, False,
                                    f'Ollama not reachable: {type(e).__name__}',
                                    model, base_url)

    if provider == 'openai-compatible':
        configured = bool(base_url and model)
        reason = '' if configured else 'Base URL and model are required'
        # Do not ping external endpoints during status checks; that would be a
        # surprising network side effect from merely opening the UI.
        return AIProviderStatus(provider, configured, configured, reason, model, base_url)

    return AIProviderStatus(provider, False, False, 'provider is not implemented',
                            model, base_url)


def triage_results(provider: str, target: str, results: List[Dict],
                   api_key: Optional[str] = None, model: Optional[str] = None,
                   base_url: Optional[str] = None,
                   max_findings: int = 60) -> Dict:
    """Annotate findings with false-positive likelihood + adjusted severity."""
    provider = normalize_provider(provider)
    if provider == 'anthropic':
        from .ai_triage import triage_results as _triage
        return _triage(target, results, api_key=api_key, model=model,
                       max_findings=max_findings)

    candidates = [r for r in results
                  if r.get('bypass') or r.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM')]
    candidates = candidates[:max_findings]
    if not candidates:
        return {}
    compact = [{
        'i': idx,
        'technique': r.get('technique', ''),
        'severity': r.get('severity', ''),
        'status': r.get('status', ''),
        'reason': str(r.get('reason', ''))[:220],
        'bypass': bool(r.get('bypass')),
    } for idx, r in enumerate(candidates)]
    prompt = (
        "You are helping with an authorized bug bounty workflow. Review these "
        f"automated Blackthorn findings for {target}. Return ONLY a JSON array, "
        "one object per finding, with keys: i, false_positive, confidence, "
        "adjusted_severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), rationale. "
        "Be conservative and avoid overstating automated evidence.\n\n"
        f"Findings:\n{json.dumps(compact, indent=1)}"
    )
    text = complete(provider, prompt, api_key=api_key, model=model, base_url=base_url,
                    max_tokens=4000)
    data = _extract_json(text)
    if not isinstance(data, list):
        return {}
    fp_count = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        i = item.get('i')
        if not isinstance(i, int) or i < 0 or i >= len(candidates):
            continue
        triage = {
            'false_positive': bool(item.get('false_positive')),
            'confidence': item.get('confidence'),
            'adjusted_severity': item.get('adjusted_severity'),
            'rationale': str(item.get('rationale', ''))[:240],
        }
        candidates[i]['ai_triage'] = triage
        if triage['false_positive']:
            fp_count += 1
    return {
        'triaged': len(candidates),
        'likely_false_positives': fp_count,
        'provider': provider,
        'model': model or '',
    }


def write_report(provider: str, target: str, results: List[Dict],
                 api_key: Optional[str] = None, model: Optional[str] = None,
                 base_url: Optional[str] = None) -> str:
    """Draft a concise markdown report. Empty string means provider unavailable."""
    provider = normalize_provider(provider)
    if provider == 'anthropic':
        from .ai_triage import write_report as _write
        return _write(target, results, api_key=api_key, model=model)
    findings = [r for r in results
                if r.get('bypass') or r.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM')]
    compact = [{
        'technique': r.get('technique', ''),
        'severity': r.get('severity', ''),
        'reason': str(r.get('reason', ''))[:240],
        'category': r.get('category', ''),
        'workflow_state': r.get('workflow_state', 'candidate'),
    } for r in findings[:80]]
    prompt = (
        f"Write a concise professional bug bounty report draft for {target}. "
        "Include Summary, Scope/Safety Notes, Findings by severity, Evidence to "
        "collect, and Remediation. Do not invent impact beyond the evidence. "
        "Use markdown.\n\n"
        f"Findings:\n{json.dumps(compact, indent=1)}"
    )
    return complete(provider, prompt, api_key=api_key, model=model,
                    base_url=base_url, max_tokens=4000)


def generate_payload_mutations(provider: str, seed_payloads: List[str],
                               context: str = 'generic WAF',
                               api_key: Optional[str] = None,
                               model: Optional[str] = None,
                               base_url: Optional[str] = None,
                               n: int = 12) -> List[str]:
    """Generate evasion payload ideas. Empty list means provider unavailable."""
    provider = normalize_provider(provider)
    if provider == 'anthropic':
        from .ai_triage import generate_payload_mutations as _mutate
        return _mutate(seed_payloads, context=context, api_key=api_key,
                       model=model, n=n)
    if not seed_payloads:
        return []
    prompt = (
        f"Authorized testing only. Given seed payloads for {context}, produce {n} "
        "WAF evasion variants. Return ONLY a JSON array of strings.\n\n"
        f"Seeds:\n{json.dumps(seed_payloads[:20])}"
    )
    text = complete(provider, prompt, api_key=api_key, model=model,
                    base_url=base_url, max_tokens=2000)
    data = _extract_json(text)
    if isinstance(data, list):
        return [str(x) for x in data if isinstance(x, (str, int))][:n]
    return []


def complete(provider: str, prompt: str, api_key: Optional[str] = None,
             model: Optional[str] = None, base_url: Optional[str] = None,
             max_tokens: int = 2000, timeout: float = 45.0) -> str:
    """Return a chat completion string for non-Anthropic HTTP providers."""
    provider = normalize_provider(provider)
    if provider == 'ollama':
        base = (base_url or DEFAULT_OLLAMA_URL).rstrip('/')
        mdl = model or DEFAULT_OLLAMA_MODEL
        payload = {
            'model': mdl,
            'stream': False,
            'messages': [{'role': 'user', 'content': prompt}],
            'options': {'num_predict': max_tokens},
        }
        try:
            data = _http_json('POST', f'{base}/api/chat', payload, timeout=timeout)
            msg = data.get('message') or {}
            return str(msg.get('content') or data.get('response') or '')
        except Exception:
            return ''

    if provider == 'openai-compatible':
        if not (base_url and model):
            return ''
        url = base_url.rstrip('/')
        if not url.endswith('/chat/completions'):
            url = url.rstrip('/') + '/chat/completions'
        payload = {
            'model': model,
            'messages': [{'role': 'user', 'content': prompt}],
            'max_tokens': max_tokens,
        }
        headers = {}
        key = api_key or os.environ.get('AI_API_KEY') or os.environ.get('OPENAI_API_KEY')
        if key:
            headers['Authorization'] = f'Bearer {key}'
        try:
            data = _http_json('POST', url, payload, headers=headers, timeout=timeout)
            choices = data.get('choices') or []
            if choices:
                msg = choices[0].get('message') or {}
                return str(msg.get('content') or choices[0].get('text') or '')
        except Exception:
            return ''
    return ''


def _http_json(method: str, url: str, payload: Optional[Dict] = None,
               headers: Optional[Dict[str, str]] = None,
               timeout: float = 10.0) -> Dict:
    data = None
    req_headers = {'Accept': 'application/json'}
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
        req_headers['Content-Type'] = 'application/json'
    req_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode('utf-8', 'replace')
    return json.loads(raw or '{}')


def _extract_json(text: str):
    text = (text or '').strip()
    if text.startswith('```'):
        parts = text.split('```')
        if len(parts) >= 3:
            text = parts[1].lstrip('json').strip()
    try:
        return json.loads(text)
    except Exception:
        for opener, closer in (('[', ']'), ('{', '}')):
            i, j = text.find(opener), text.rfind(closer)
            if i != -1 and j != -1 and j > i:
                try:
                    return json.loads(text[i:j + 1])
                except Exception:
                    pass
    return None
