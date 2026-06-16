"""
WAFPierce AI Triage (opt-in)

Uses the Anthropic API to add intelligence on top of raw scan results:

  * triage_results()            -> flag likely false positives + adjust severity
  * generate_payload_mutations()-> propose new evasion payloads from seeds
  * write_report()              -> draft a professional markdown report

This is OPT-IN: nothing here runs (or costs anything) unless the user supplies an
Anthropic API key (argument or the ANTHROPIC_API_KEY environment variable) AND the
`anthropic` package is installed. Every function degrades to a safe no-op otherwise.

    pip install anthropic
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    import anthropic  # type: ignore
    ANTHROPIC_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    anthropic = None
    ANTHROPIC_AVAILABLE = False

# Sonnet is the default for high-volume triage (cost/latency); Opus for the
# low-volume, quality-sensitive report. Both are overridable per call.
DEFAULT_TRIAGE_MODEL = "claude-sonnet-4-6"
DEFAULT_REPORT_MODEL = "claude-opus-4-8"
DEFAULT_MUTATION_MODEL = "claude-sonnet-4-6"


def is_enabled(api_key: Optional[str] = None) -> bool:
    """True if AI features can run (package present + a key available)."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    return bool(ANTHROPIC_AVAILABLE and key)


def _client(api_key: Optional[str] = None):
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not (ANTHROPIC_AVAILABLE and key):
        return None
    try:
        return anthropic.Anthropic(api_key=key)
    except Exception as e:
        logger.debug(f"Anthropic client init failed: {e}")
        return None


def _message_text(resp) -> str:
    """Extract text from a Messages API response."""
    try:
        return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
    except Exception:
        return ""


def _extract_json(text: str):
    """Best-effort JSON extraction from a model response."""
    text = text.strip()
    # Strip markdown fences if present.
    if text.startswith("```"):
        text = text.split("```", 2)[1] if "```" in text[3:] else text
        text = text.lstrip("json").strip("` \n")
    try:
        return json.loads(text)
    except Exception:
        # Try to locate the first JSON array/object.
        for opener, closer in (("[", "]"), ("{", "}")):
            i, j = text.find(opener), text.rfind(closer)
            if i != -1 and j != -1 and j > i:
                try:
                    return json.loads(text[i:j + 1])
                except Exception:
                    continue
    return None


def triage_results(target: str, results: List[Dict[str, Any]],
                   api_key: Optional[str] = None, model: Optional[str] = None,
                   max_findings: int = 60) -> Dict[str, Any]:
    """Annotate findings with false-positive likelihood + adjusted severity.

    Mutates each triaged result in place by adding an ``ai_triage`` field. Returns
    a summary dict. No-op (returns {}) when AI is not enabled.
    """
    client = _client(api_key)
    if client is None:
        return {}
    # Only triage actual findings (skip pure INFO noise) to control token cost.
    candidates = [r for r in results if r.get('bypass') or r.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM')]
    candidates = candidates[:max_findings]
    if not candidates:
        return {}

    compact = [{
        'i': idx,
        'technique': r.get('technique', ''),
        'severity': r.get('severity', ''),
        'status': r.get('status', ''),
        'reason': str(r.get('reason', ''))[:200],
        'bypass': bool(r.get('bypass')),
    } for idx, r in enumerate(candidates)]

    prompt = (
        "You are a senior web application penetration tester reviewing automated WAF/scanner "
        f"findings for {target}. Many automated 'bypass' findings are false positives caused by "
        "dynamic content, redirects, or generic error pages. For each finding decide whether it is "
        "a likely false positive and whether the severity should change.\n\n"
        "Return ONLY a JSON array, one object per finding, with keys: "
        '"i" (the index), "false_positive" (true/false), "confidence" (0-1), '
        '"adjusted_severity" (one of CRITICAL/HIGH/MEDIUM/LOW/INFO), "rationale" (<=160 chars).\n\n'
        f"Findings:\n{json.dumps(compact, indent=1)}"
    )
    try:
        resp = client.messages.create(
            model=model or DEFAULT_TRIAGE_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        logger.debug(f"AI triage request failed: {e}")
        return {}

    data = _extract_json(_message_text(resp))
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
            'rationale': item.get('rationale', ''),
        }
        candidates[i]['ai_triage'] = triage
        if triage['false_positive']:
            fp_count += 1
    return {
        'triaged': len(candidates),
        'likely_false_positives': fp_count,
        'model': model or DEFAULT_TRIAGE_MODEL,
    }


def generate_payload_mutations(seed_payloads: List[str], context: str = "generic WAF",
                               api_key: Optional[str] = None, model: Optional[str] = None,
                               n: int = 12) -> List[str]:
    """Ask the model for novel evasion variants of the given seed payloads."""
    client = _client(api_key)
    if client is None or not seed_payloads:
        return []
    prompt = (
        f"You are assisting an AUTHORIZED penetration test. Given these seed payloads used to "
        f"probe a {context}, produce {n} novel evasion variants that a WAF might fail to detect "
        "(encoding tricks, comment insertion, case/charset manipulation, alternate syntax). "
        "Return ONLY a JSON array of strings, no commentary.\n\n"
        f"Seeds:\n{json.dumps(seed_payloads[:20])}"
    )
    try:
        resp = client.messages.create(
            model=model or DEFAULT_MUTATION_MODEL,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        logger.debug(f"AI mutation request failed: {e}")
        return []
    data = _extract_json(_message_text(resp))
    if isinstance(data, list):
        return [str(x) for x in data if isinstance(x, (str, int))][:n]
    return []


def write_report(target: str, results: List[Dict[str, Any]],
                 api_key: Optional[str] = None, model: Optional[str] = None) -> str:
    """Draft a professional markdown pentest report from the findings."""
    client = _client(api_key)
    if client is None:
        return ""
    findings = [r for r in results if r.get('bypass') or r.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM')]
    compact = [{
        'technique': r.get('technique', ''), 'severity': r.get('severity', ''),
        'reason': str(r.get('reason', ''))[:200], 'category': r.get('category', ''),
    } for r in findings[:80]]
    prompt = (
        f"Write a concise professional security assessment report (markdown) for {target} based on "
        "these WAF/scanner findings. Include: Executive Summary, Findings grouped by severity with "
        "impact and remediation, and an overall risk rating. Be precise and avoid overstating "
        "automated findings.\n\n"
        f"Findings:\n{json.dumps(compact, indent=1)}"
    )
    try:
        resp = client.messages.create(
            model=model or DEFAULT_REPORT_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        logger.debug(f"AI report request failed: {e}")
        return ""
    return _message_text(resp)
