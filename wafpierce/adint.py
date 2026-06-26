"""
Active Directory / internal recon helpers — BloodHound + Neo4j (P7), Qt-free.

A clearly-separated, optional, detect-&-drive module for *internal* AD assessment
(a different domain from WAFPierce's web/WAF focus). It never installs anything:

* ``detect_environment`` probes Neo4j (bolt port), a BloodHound CE API, and the
  SharpHound/AzureHound collectors.
* ``build_collector_cmd`` builds a killable argv for a collector run (SharpHound for
  on-prem AD, AzureHound for Entra ID).
* ``ingest_zip`` uploads collected data to BloodHound CE (when reachable) or returns
  a "manual drag-drop" strategy for legacy BloodHound.
* ``run_cypher`` runs a canned/free-form query via the optional ``neo4j`` driver,
  degrading to a clear "driver not installed" message when absent.

Credentials are passed in per call and are NOT persisted by this module.
"""
from __future__ import annotations

import os
import shutil
import socket
from typing import Dict, List, Optional


CANNED_QUERIES = {
    'Shortest paths to Domain Admins':
        "MATCH p=shortestPath((n)-[*1..]->(g:Group)) "
        "WHERE g.name STARTS WITH 'DOMAIN ADMINS' RETURN p LIMIT 25",
    'Kerberoastable users':
        "MATCH (u:User {hasspn:true}) RETURN u.name AS name, u.serviceprincipalnames AS spns",
    'AS-REP roastable users':
        "MATCH (u:User {dontreqpreauth:true}) RETURN u.name AS name",
    'Domain Admins members':
        "MATCH (g:Group)<-[:MemberOf*1..]-(u:User) "
        "WHERE g.name STARTS WITH 'DOMAIN ADMINS' RETURN DISTINCT u.name AS name",
    'Computers with unconstrained delegation':
        "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name AS name",
}


def detect_environment(neo4j_host: str = '127.0.0.1', neo4j_port: int = 7687,
                       bhce_url: str = 'http://127.0.0.1:8080',
                       sharphound_path: str = '', azurehound_path: str = '',
                       session=None) -> Dict[str, Dict]:
    """Probe each component. Returns {component: {state, detail}}.
    Never raises; states are 'running'/'installed'/'absent'/'unknown'."""
    out: Dict[str, Dict] = {}

    # Neo4j bolt
    try:
        with socket.create_connection((neo4j_host, int(neo4j_port)), timeout=0.6):
            out['neo4j'] = {'state': 'running', 'detail': f'{neo4j_host}:{neo4j_port}'}
    except Exception as e:
        out['neo4j'] = {'state': 'absent', 'detail': str(e)}

    # BloodHound CE API
    try:
        import requests
        sess = session or requests
        r = sess.get(bhce_url.rstrip('/') + '/api/version', timeout=2)
        out['bloodhound_ce'] = {'state': 'running' if r.status_code < 500 else 'absent',
                                'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        out['bloodhound_ce'] = {'state': 'absent', 'detail': str(e)}

    # Collectors
    sh = _resolve(sharphound_path, ('SharpHound', 'sharphound', 'SharpHound.exe'))
    out['sharphound'] = ({'state': 'installed', 'detail': sh} if sh
                         else {'state': 'absent', 'detail': 'not found'})
    ah = _resolve(azurehound_path, ('azurehound', 'AzureHound', 'azurehound.exe'))
    out['azurehound'] = ({'state': 'installed', 'detail': ah} if ah
                         else {'state': 'absent', 'detail': 'not found'})
    return out


def _resolve(custom: str, names) -> Optional[str]:
    if custom and os.path.isfile(custom):
        return custom
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def build_collector_cmd(collector: str, *, collector_path: str, output_dir: str,
                        domain: str = '', username: str = '', password: str = '',
                        tenant: str = '', jwt: str = '') -> List[str]:
    """Build the argv for a collector run. Raises ValueError on bad input."""
    if not collector_path:
        raise ValueError('collector path is required')
    if collector == 'sharphound':
        # .ps1 collectors run via PowerShell; .exe directly.
        if collector_path.lower().endswith('.ps1'):
            argv = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', collector_path]
        else:
            argv = [collector_path]
        argv += ['-c', 'All', '--outputdirectory', output_dir]
        if domain:
            argv += ['-d', domain]
        if username:
            argv += ['--ldapusername', username]
        if password:
            argv += ['--ldappassword', password]
        return argv
    if collector == 'azurehound':
        argv = [collector_path]
        if jwt:
            argv += ['--jwt', jwt]
        elif username:
            argv += ['-u', username, '-p', password]
        if tenant:
            argv += ['--tenant', tenant]
        argv += ['list', '-o', os.path.join(output_dir, 'azurehound.json')]
        return argv
    raise ValueError(f'unknown collector: {collector}')


def ingest_zip(zip_path: str, bhce_url: str = '', token: str = '', session=None) -> Dict:
    """Ingest a collected zip into BloodHound CE if reachable, else return a manual
    strategy. Returns {strategy, ok, message}. strategy in ce_api|manual|none."""
    if not zip_path or not os.path.isfile(zip_path):
        return {'strategy': 'none', 'ok': False, 'message': 'zip not found'}
    if not bhce_url:
        return {'strategy': 'manual', 'ok': False,
                'message': 'No BloodHound CE URL configured. Open BloodHound and '
                           'drag-and-drop the zip to ingest (legacy BloodHound).'}
    try:
        import requests
        sess = session or requests
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        # CE v2 file-upload flow (best-effort): start -> upload -> end.
        start = sess.post(bhce_url.rstrip('/') + '/api/v2/file-upload/start',
                          headers=headers, timeout=10)
        job = (start.json() or {}).get('data', {}).get('id') if start.ok else None
        if not job:
            return {'strategy': 'ce_api', 'ok': False,
                    'message': f'CE upload start failed (HTTP {start.status_code}).'}
        with open(zip_path, 'rb') as fh:
            up = sess.post(f"{bhce_url.rstrip('/')}/api/v2/file-upload/{job}",
                           headers={**headers, 'Content-Type': 'application/zip'},
                           data=fh, timeout=120)
        sess.post(f"{bhce_url.rstrip('/')}/api/v2/file-upload/{job}/end",
                  headers=headers, timeout=10)
        return {'strategy': 'ce_api', 'ok': up.ok,
                'message': f'CE upload {"accepted" if up.ok else "failed"} (job {job}).'}
    except Exception as e:
        return {'strategy': 'ce_api', 'ok': False, 'message': f'CE ingest error: {e}'}


def neo4j_available() -> bool:
    try:
        import neo4j  # noqa: F401
        return True
    except Exception:
        return False


def run_cypher(query: str, host: str = '127.0.0.1', port: int = 7687,
               user: str = 'neo4j', password: str = 'neo4j') -> Dict:
    """Run a Cypher query via the optional neo4j bolt driver. Returns
    {ok, rows|error}. Degrades cleanly when the driver is not installed."""
    if not neo4j_available():
        return {'ok': False, 'error': 'neo4j driver not installed (pip install neo4j)'}
    try:
        from neo4j import GraphDatabase
        uri = f'bolt://{host}:{int(port)}'
        driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            with driver.session() as s:
                rows = [dict(r) for r in s.run(query)]
        finally:
            driver.close()
        return {'ok': True, 'rows': rows}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
