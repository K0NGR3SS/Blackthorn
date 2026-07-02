"""Opt-in local agent bridge for WAFPierce.

This is intentionally small and conservative: a JSON-lines stdio server for
local agents such as Codex or Claude Desktop. It exposes scope-aware workspace
metadata and dry-run planning by default. Active scans require an engagement,
safe mode, and an explicit authorization confirmation in the request.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

from .database import WAFPierceDB


ACTIVE_SCAN_TIMEOUT = 3600


def _ok(**data) -> Dict[str, Any]:
    return {'ok': True, **data}


def _err(message: str, code: str = 'error') -> Dict[str, Any]:
    return {'ok': False, 'error': message, 'code': code}


def _host(value: str) -> str:
    parsed = urlparse(value if '://' in value else 'https://' + value)
    return (parsed.hostname or value or '').lower()


def _in_scope(target: str, engagement: Dict[str, Any]) -> bool:
    host = _host(target)
    scope = engagement.get('scope') or []
    exclusions = engagement.get('exclusions') or []
    if not scope:
        return False
    for item in exclusions:
        item = str(item).strip().lower()
        if item and (item in host or item in target.lower()):
            return False
    for item in scope:
        item = str(item).strip().lower().lstrip('*.')
        if item and (host == item or host.endswith('.' + item) or item in target.lower()):
            return True
    return False


class AgentAPI:
    """Local, process-scoped API used by the stdio loop and unit tests."""

    def __init__(self, db: Optional[WAFPierceDB] = None):
        self.db = db or WAFPierceDB()

    def handle(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get('method')
        params = request.get('params') or {}
        try:
            if method == 'list_engagements':
                return _ok(engagements=self.db.list_engagements())
            if method == 'read_scope':
                return self._read_scope(params)
            if method == 'list_targets':
                return _ok(targets=self.db.get_persistent_targets())
            if method == 'list_findings':
                return self._list_findings(params)
            if method == 'fetch_evidence':
                return self._fetch_evidence(params)
            if method == 'draft_report':
                return self._draft_report(params)
            if method == 'suggest_next_steps':
                return self._suggest_next_steps(params)
            if method == 'start_scan':
                return self._start_scan(params)
            return _err(f'unknown method: {method}', 'unknown_method')
        except Exception as e:
            return _err(str(e))

    def _read_scope(self, params: Dict[str, Any]) -> Dict[str, Any]:
        engagement = self._engagement(params)
        if not engagement:
            return _err('engagement not found', 'not_found')
        return _ok(engagement=engagement)

    def _list_findings(self, params: Dict[str, Any]) -> Dict[str, Any]:
        engagement_id = params.get('engagement_id')
        limit = int(params.get('limit') or 100)
        conn = self._connect()
        try:
            if engagement_id:
                rows = conn.execute(
                    'SELECT * FROM results WHERE engagement_id=? '
                    'ORDER BY id DESC LIMIT ?', (engagement_id, limit)).fetchall()
            else:
                rows = conn.execute('SELECT * FROM results ORDER BY id DESC LIMIT ?',
                                    (limit,)).fetchall()
            return _ok(findings=[dict(r) for r in rows])
        finally:
            conn.close()

    def _fetch_evidence(self, params: Dict[str, Any]) -> Dict[str, Any]:
        result_id = params.get('result_id')
        if not result_id:
            return _err('result_id is required', 'bad_request')
        conn = self._connect()
        try:
            row = conn.execute('SELECT * FROM results WHERE id=?', (result_id,)).fetchone()
            return _ok(evidence=dict(row) if row else None)
        finally:
            conn.close()

    def _draft_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get('target') or 'selected engagement'
        api_key = params.get('api_key')
        model = params.get('model')
        provider = params.get('provider') or 'anthropic'
        findings = self._list_findings(params).get('findings', [])
        try:
            from .ai_providers import write_report
            report = write_report(provider, target, findings, api_key=api_key,
                                  model=model)
        except Exception:
            report = ''
        if not report:
            report = self._fallback_report(target, findings)
        return _ok(report=report, provider=provider if report else None)

    def _suggest_next_steps(self, params: Dict[str, Any]) -> Dict[str, Any]:
        findings = self._list_findings(params).get('findings', [])
        high = [f for f in findings if (f.get('severity') or '').upper() in ('CRITICAL', 'HIGH')]
        candidates = [f for f in findings if f.get('workflow_state', 'candidate') == 'candidate']
        steps = [
            'Confirm engagement scope and rules of engagement before active testing.',
            'Validate candidate findings with the least invasive reproduction path.',
            'Redact cookies, tokens, personal data, and unrelated response bodies before reporting.',
        ]
        if high:
            steps.insert(1, f'Prioritize {len(high)} critical/high finding(s) for manual validation.')
        if candidates:
            steps.append(f'Move validated findings out of candidate state; {len(candidates)} currently need triage.')
        return _ok(steps=steps)

    def _start_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get('target')
        engagement = self._engagement(params)
        dry_run = bool(params.get('dry_run', True))
        safe_mode = bool(params.get('safe_mode', True))
        if not target:
            return _err('target is required', 'bad_request')
        if not engagement:
            return _err('engagement_id is required before an agent can start a scan',
                        'authorization_required')
        if not _in_scope(target, engagement):
            return _err('target is outside the selected engagement scope',
                        'out_of_scope')
        if not dry_run and (not safe_mode or not params.get('confirm_authorized')):
            return _err('active agent scans require safe_mode=true and confirm_authorized=true',
                        'authorization_required')

        cmd = [sys.executable, '-m', 'wafpierce.pierce', target, '--safe-mode']
        if dry_run:
            cmd.append('--dry-run')
        if params.get('categories'):
            cmd.extend(['--categories', ','.join(params.get('categories') or [])])
        if params.get('threads'):
            cmd.extend(['--threads', str(int(params['threads']))])
        if params.get('delay') is not None:
            cmd.extend(['--delay', str(float(params['delay']))])
        if not dry_run:
            out = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
            out.close()
            cmd.extend(['--output', out.name])
        else:
            out = None

        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=ACTIVE_SCAN_TIMEOUT, errors='replace')
        return _ok(returncode=proc.returncode, stdout=proc.stdout,
                   stderr=proc.stderr, output_path=getattr(out, 'name', None),
                   dry_run=dry_run, safe_mode=True)

    def _engagement(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        engagement_id = params.get('engagement_id')
        if not engagement_id:
            return None
        return self.db.get_engagement(int(engagement_id))

    def _connect(self):
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _fallback_report(self, target: str, findings: Iterable[Dict[str, Any]]) -> str:
        rows = list(findings)
        lines = [f'# WAFPierce Report: {target}', '',
                 '## Summary',
                 f'- Findings reviewed: {len(rows)}',
                 '- AI provider was not available; this is a structured local draft.',
                 '',
                 '## Findings']
        for item in rows[:50]:
            lines.append(f"- {item.get('severity', 'INFO')}: {item.get('technique', 'Finding')} "
                         f"({item.get('workflow_state', 'candidate')})")
        return '\n'.join(lines) + '\n'


def serve_stdio(api: Optional[AgentAPI] = None, stdin=None, stdout=None) -> int:
    """Serve newline-delimited JSON requests on stdio."""
    api = api or AgentAPI()
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = api.handle(req)
        except Exception as e:
            resp = _err(str(e), 'invalid_json')
        stdout.write(json.dumps(resp, ensure_ascii=False) + '\n')
        stdout.flush()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='wafpierce agent-server',
                                     description='Local JSON-lines agent bridge')
    parser.add_argument('--stdio', action='store_true',
                        help='Serve JSON-lines requests over stdin/stdout')
    args = parser.parse_args(argv)
    if not args.stdio:
        parser.print_help()
        return 0
    return serve_stdio()


if __name__ == '__main__':
    raise SystemExit(main())
