"""
Blackthorn continuous monitoring.

Closes the loop on the existing scan history + ``compare_scans`` machinery: after a
scan, diff the target against its previous scan and surface only the NEW findings,
with an optional webhook alert. Intended to be driven by the scheduled-scans
feature so a target can be watched over time and you only hear about regressions.
"""
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def find_recent_scans_for_target(db, target: str, limit: int = 30) -> List[str]:
    """Return scan_ids that produced results for ``target``, most recent first."""
    scan_ids = []
    try:
        for scan in db.get_scan_history(limit=limit):
            sid = scan.get('scan_id')
            if not sid:
                continue
            rows = db.get_scan_results(sid)
            if any((r.get('target') or '').rstrip('/') == target.rstrip('/') for r in rows):
                scan_ids.append(sid)
    except Exception as e:
        logger.debug(f"find_recent_scans_for_target error: {e}")
    return scan_ids


def diff_latest(db, target: str, only_bypasses: bool = True) -> Dict[str, Any]:
    """Diff the two most recent scans of ``target``. Returns new/fixed findings.

    ``new``/``fixed`` are filtered to the target. Empty/partial result if there is
    not enough history yet.
    """
    scans = find_recent_scans_for_target(db, target, limit=30)
    if len(scans) < 2:
        return {'new': [], 'fixed': [], 'baseline_available': False,
                'reason': 'need at least two scans of this target'}
    current, previous = scans[0], scans[1]
    try:
        cmp = db.compare_scans(previous, current)
    except Exception as e:
        logger.debug(f"compare_scans error: {e}")
        return {'new': [], 'fixed': [], 'baseline_available': False, 'reason': str(e)}

    def _belongs(r):
        return (r.get('target') or '').rstrip('/') == target.rstrip('/')

    def _confirmed(r):
        verification = str(r.get('verification_status') or '').lower()
        kind = str(r.get('kind') or '').lower()
        if verification or kind:
            return bool(r.get('bypass')) and (
                verification == 'confirmed' or kind == 'finding'
            ) and verification != 'candidate'
        # Historical rows predate proof-state fields.
        return bool(r.get('bypass'))

    new = [r for r in cmp.get('new', []) if _belongs(r)]
    fixed = [r for r in cmp.get('fixed', []) if _belongs(r)]
    if only_bypasses:
        new = [r for r in new if _confirmed(r)]
        fixed = [r for r in fixed if _confirmed(r)]
    return {
        'new': new, 'fixed': fixed, 'baseline_available': True,
        'current_scan': current, 'previous_scan': previous,
        'unchanged_count': cmp.get('unchanged_count', 0),
    }


def format_alert(target: str, diff: Dict[str, Any]) -> str:
    """Human-readable alert text for the new/fixed findings."""
    if not diff.get('baseline_available'):
        return f"[monitor] {target}: {diff.get('reason', 'no baseline yet')}"
    new, fixed = diff.get('new', []), diff.get('fixed', [])
    if not new and not fixed:
        return f"[monitor] {target}: no change since last scan."
    lines = [f"[monitor] {target}: {len(new)} NEW, {len(fixed)} FIXED since last scan"]
    for r in new[:25]:
        lines.append(f"  + NEW [{r.get('severity','?')}] {r.get('technique','?')} — {str(r.get('reason',''))[:80]}")
    for r in fixed[:25]:
        lines.append(f"  - FIXED {r.get('technique','?')}")
    return "\n".join(lines)


def send_webhook(webhook_url: str, target: str, diff: Dict[str, Any], session=None) -> bool:
    """POST a JSON alert to a webhook (Slack-compatible 'text' + raw payload)."""
    if not webhook_url:
        return False
    payload = {
        'text': format_alert(target, diff),
        'target': target,
        'new_count': len(diff.get('new', [])),
        'fixed_count': len(diff.get('fixed', [])),
        'new': diff.get('new', [])[:50],
    }
    try:
        if session is not None:
            resp = session.post(webhook_url, json=payload, timeout=10, verify=False)
        else:
            import requests
            resp = requests.post(webhook_url, json=payload, timeout=10, verify=False)
        return resp.status_code < 400
    except Exception as e:
        logger.debug(f"Webhook post failed: {e}")
        return False


def monitor_target(db, target: str, webhook_url: Optional[str] = None,
                   only_bypasses: bool = True, session=None) -> Dict[str, Any]:
    """Diff the latest scans of a target and (optionally) fire a webhook alert.

    Returns the diff dict (with an added ``alerted`` flag).
    """
    diff = diff_latest(db, target, only_bypasses=only_bypasses)
    alert = format_alert(target, diff)
    print(alert)
    alerted = False
    if webhook_url and diff.get('new'):
        alerted = send_webhook(webhook_url, target, diff, session=session)
    diff['alerted'] = alerted
    return diff
