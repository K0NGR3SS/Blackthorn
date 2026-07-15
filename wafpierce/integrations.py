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
    lines = [f"*Blackthorn investigation* — `{target}`", summary or "_no findings_"]
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


def _summary_lines(target: str, results: List[Dict[str, Any]]) -> List[str]:
    """Plain-text summary lines shared by the chat integrations."""
    counts = _counts(results)
    summary = '  '.join(f"{s}: {counts.get(s, 0)}"
                        for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
                        if counts.get(s))
    lines = [f"Blackthorn investigation — {target}", summary or "no findings"]
    top = _top_findings(results)
    if top:
        lines.append("")
        for r in top:
            sev = str(r.get('severity', 'INFO')).upper()
            lines.append(f"{_SEV_EMOJI.get(sev, '')} {r.get('technique', '?')} — "
                         f"{(r.get('reason', '') or '')[:140]}")
    return lines


def format_discord(target: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a Discord webhook payload (content capped at Discord's 2000 chars)."""
    text = '\n'.join(_summary_lines(target, results))
    return {'content': text[:1990]}


def send_discord(webhook_url: str, target: str, results: List[Dict[str, Any]],
                 session=None) -> bool:
    """POST a scan summary to a Discord webhook."""
    try:
        import requests
        sess = session or requests
        resp = sess.post(webhook_url, json=format_discord(target, results), timeout=10)
        ok = getattr(resp, 'status_code', 0) < 400
        if not ok:
            logger.warning(f"Discord push returned {getattr(resp, 'status_code', '?')}")
        return ok
    except Exception as e:
        logger.error(f"Discord push failed: {e}")
        return False


def format_teams(target: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a Microsoft Teams MessageCard payload (Office 365 connector format)."""
    counts = _counts(results)
    facts = [{'name': s, 'value': str(counts.get(s, 0))}
             for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') if counts.get(s)]
    top = _top_findings(results)
    detail = '\n\n'.join(f"**{r.get('technique', '?')}** — {(r.get('reason', '') or '')[:160]}"
                         for r in top) or "_no confirmed bypasses_"
    crit = counts.get('CRITICAL', 0) + counts.get('HIGH', 0)
    return {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': 'D7263D' if crit else '0078D7',
        'summary': f"Blackthorn investigation of {target}",
        'sections': [{
            'activityTitle': f"Blackthorn investigation — {target}",
            'facts': facts or [{'name': 'findings', 'value': '0'}],
            'text': detail,
            'markdown': True,
        }],
    }


def send_teams(webhook_url: str, target: str, results: List[Dict[str, Any]],
               session=None) -> bool:
    """POST a scan summary to a Microsoft Teams incoming webhook."""
    try:
        import requests
        sess = session or requests
        resp = sess.post(webhook_url, json=format_teams(target, results), timeout=10)
        ok = getattr(resp, 'status_code', 0) < 400
        if not ok:
            logger.warning(f"Teams push returned {getattr(resp, 'status_code', '?')}")
        return ok
    except Exception as e:
        logger.error(f"Teams push failed: {e}")
        return False


def format_generic(target: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generic JSON payload for arbitrary webhooks / SIEM ingestion."""
    return {
        'tool': 'Blackthorn', 'target': target,
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
