"""
Outbound integrations — push findings to Slack / Jira / DefectDojo / generic
webhooks. Each `send_*` does the network call; the matching `format_*` builds
the payload and is pure (unit-testable without sending anything).

All sends are best-effort and return a bool; failures are logged, never raised,
so a broken integration can't fail a scan.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
_SEV_EMOJI = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '⚪'}


def _counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for r in results:
        sev = str(r.get('severity', 'INFO')).upper()
        c[sev] = c.get(sev, 0) + 1
    return c


def _top_findings(results: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    confirmed = [r for r in results if r.get('bypass')]
    return sorted(confirmed,
                  key=lambda r: _SEV_ORDER.get(str(r.get('severity', 'INFO')).upper(), 9))[:limit]


def format_slack(target: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a Slack message payload summarizing a scan."""
    counts = _counts(results)
    summary = '  '.join(f"{_SEV_EMOJI.get(s,'')} {s}: {counts.get(s,0)}"
                        for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
                        if counts.get(s))
    lines = [f"*WAFPierce scan* — `{target}`", summary or "_no findings_"]
    top = _top_findings(results)
    if top:
        lines.append("")
        for r in top:
            sev = str(r.get('severity', 'INFO')).upper()
            lines.append(f"{_SEV_EMOJI.get(sev,'')} *{r.get('technique','?')}* — "
                         f"{r.get('reason','')[:140]}")
    return {'text': '\n'.join(lines)}


def send_slack(webhook_url: str, target: str, results: List[Dict[str, Any]],
               session=None) -> bool:
    """POST a scan summary to a Slack incoming webhook."""
    try:
        import requests
        sess = session or requests
        resp = sess.post(webhook_url, json=format_slack(target, results), timeout=10)
        ok = getattr(resp, 'status_code', 0) < 400
        if not ok:
            logger.warning(f"Slack push returned {getattr(resp,'status_code','?')}")
        return ok
    except Exception as e:
        logger.error(f"Slack push failed: {e}")
        return False


def format_generic(target: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generic JSON payload for arbitrary webhooks / SIEM ingestion."""
    return {
        'tool': 'WAFPierce', 'target': target,
        'summary': _counts(results),
        'total': len(results),
        'confirmed': sum(1 for r in results if r.get('bypass')),
        'findings': results,
    }


def send_webhook(webhook_url: str, target: str, results: List[Dict[str, Any]],
                 session=None) -> bool:
    """POST the full findings payload to a generic webhook."""
    try:
        import requests
        sess = session or requests
        payload = json.loads(json.dumps(format_generic(target, results), default=str))
        resp = sess.post(webhook_url, json=payload, timeout=15)
        return getattr(resp, 'status_code', 0) < 400
    except Exception as e:
        logger.error(f"Webhook push failed: {e}")
        return False


def format_defectdojo(target: str, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Map findings to DefectDojo generic-findings-import rows."""
    rows = []
    for r in results:
        if not r.get('bypass'):
            continue
        rows.append({
            'title': r.get('technique', 'Finding'),
            'severity': str(r.get('severity', 'Info')).title(),
            'description': r.get('reason', ''),
            'cwe': int(str(r.get('cwe_id', '')).replace('CWE-', '') or 0) or None,
            'cvssv3_score': r.get('cvss_score'),
            'endpoint': r.get('path', '/'),
            'mitigation': r.get('curl', ''),
        })
    return rows
