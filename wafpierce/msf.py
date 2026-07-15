"""Metasploit integration over msfrpcd (RPC).

Two capabilities, both opt-in:

* **Handoff** — push confirmed WAFPierce findings into an MSF workspace
  (hosts + services + notes + vulns) so an operator can pivot straight to
  exploitation in `msfconsole`.
* **Aux scan** — run ``auxiliary/scanner/http/*`` modules against a target and
  fold their output back into WAFPierce findings.

Transport is Metasploit's RPC daemon, started with::

    msfrpcd -P <password> -p 55553 -S      # -S = no SSL,  drop it to keep SSL on

and spoken with the `pymetasploit3` library (``pip install pymetasploit3``).

Mirroring :mod:`wafpierce.integrations`, the ``format_*`` helpers are pure
(unit-testable, no network) and the action functions are **best-effort**: a
missing dependency or an unreachable daemon returns a clear error, it never
raises mid-scan.
"""
from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Sensible default web aux scanners for the handoff/enrichment step.
DEFAULT_AUX_HTTP: List[str] = [
    'scanner/http/http_version',
    'scanner/http/http_header',
    'scanner/http/options',
    'scanner/http/robots_txt',
]


@dataclass
class MsfConfig:
    """Connection settings for msfrpcd. ``password`` is the only required field."""
    password: str = ''
    host: str = '127.0.0.1'
    port: int = 55553
    ssl: bool = True
    workspace: str = 'wafpierce'

    @classmethod
    def from_env(cls, **overrides: Any) -> 'MsfConfig':
        """Build from MSF_RPC_* env vars, with explicit kwargs winning."""
        cfg = cls(
            password=os.environ.get('MSF_RPC_PASSWORD', ''),
            host=os.environ.get('MSF_RPC_HOST', '127.0.0.1'),
            port=int(os.environ.get('MSF_RPC_PORT', '55553') or 55553),
            ssl=os.environ.get('MSF_RPC_SSL', '1') not in ('0', 'false', 'False', ''),
            workspace=os.environ.get('MSF_RPC_WORKSPACE', 'wafpierce'),
        )
        for k, v in overrides.items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


# --------------------------------------------------------------------------- #
# Connection / preflight
# --------------------------------------------------------------------------- #
def connect(cfg: MsfConfig):
    """Return a connected ``MsfRpcClient`` (raises on failure — callers wrap)."""
    from pymetasploit3.msfrpc import MsfRpcClient
    return MsfRpcClient(cfg.password, server=cfg.host, port=cfg.port, ssl=cfg.ssl)


def preflight(cfg: MsfConfig) -> Tuple[bool, str]:
    """(ready, message). Checks the library, a password, and daemon reachability."""
    try:
        import pymetasploit3.msfrpc  # noqa: F401
    except Exception:
        return False, "pymetasploit3 not installed  ->  pip install pymetasploit3"
    if not cfg.password:
        return False, ("no RPC password configured  ->  start "
                       "`msfrpcd -P <pass> -p 55553 -S` and set it in Settings")
    try:
        client = connect(cfg)
        ver = client.core.version
        v = ver.get('version') if isinstance(ver, dict) else ver
        return True, f"msfrpcd reachable at {cfg.host}:{cfg.port} (Metasploit {v})"
    except Exception as e:
        return False, (f"cannot reach msfrpcd at {cfg.host}:{cfg.port} "
                       f"({type(e).__name__}: {e})")


# --------------------------------------------------------------------------- #
# Target parsing / pure formatters
# --------------------------------------------------------------------------- #
def target_parts(target: str) -> Tuple[str, int, bool]:
    """``https://host:8443/p`` -> ``(host, 8443, True)``. Defaults 80/443 by scheme."""
    t = (target or '').strip()
    if '://' not in t:
        t = 'http://' + t
    u = urlparse(t)
    host = u.hostname or ''
    ssl = (u.scheme == 'https')
    port = u.port or (443 if ssl else 80)
    return host, int(port), ssl


def _resolve(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def format_targets(results: List[Dict[str, Any]],
                   confirmed_only: bool = True) -> List[Dict[str, Any]]:
    """Pure: collapse findings into unique ``{host, ip, port, ssl}`` endpoints."""
    seen: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for r in results:
        if confirmed_only and not r.get('bypass'):
            continue
        tgt = r.get('target') or ''
        if not tgt:
            continue
        host, port, ssl = target_parts(tgt)
        if not host:
            continue
        key = (host, port)
        if key not in seen:
            seen[key] = {'host': host, 'ip': _resolve(host), 'port': port, 'ssl': ssl}
    return list(seen.values())


def format_notes(results: List[Dict[str, Any]],
                 confirmed_only: bool = True) -> List[Dict[str, Any]]:
    """Pure: one note per (confirmed) finding, keyed to its host."""
    notes: List[Dict[str, Any]] = []
    for r in results:
        if confirmed_only and not r.get('bypass'):
            continue
        host, _port, _ssl = target_parts(r.get('target') or '')
        if not host:
            continue
        notes.append({
            'host': host,
            'technique': r.get('technique', 'finding'),
            'severity': str(r.get('severity', 'INFO')).upper(),
            'reason': r.get('reason', ''),
            'path': r.get('path', '/'),
            'curl': r.get('curl', ''),
        })
    return notes


def _finding(technique: str, target: str, reason: str,
             severity: str = 'INFO', **extra: Any) -> Dict[str, Any]:
    """Scanner-shaped result tagged category='metasploit'."""
    f: Dict[str, Any] = {
        'bypass': False, 'category': 'metasploit', 'msf': True,
        'technique': technique, 'target': target, 'reason': reason,
        'severity': severity,
    }
    f.update(extra)
    return f


# --------------------------------------------------------------------------- #
# Handoff: push findings into an MSF workspace
# --------------------------------------------------------------------------- #
def push_findings(cfg: MsfConfig, results: List[Dict[str, Any]],
                  confirmed_only: bool = True) -> Dict[str, Any]:
    """Report hosts/services/notes/vulns into ``cfg.workspace``.

    Best-effort: returns a summary dict ``{ok, hosts, services, notes, vulns,
    error}``; individual RPC failures are counted, not raised.
    """
    summary = {'ok': False, 'hosts': 0, 'services': 0, 'notes': 0,
               'vulns': 0, 'error': None}
    try:
        client = connect(cfg)
    except Exception as e:
        summary['error'] = f"connect failed: {type(e).__name__}: {e}"
        logger.error(summary['error'])
        return summary

    ws = cfg.workspace

    def _call(method: str, opts: Dict[str, Any]) -> bool:
        try:
            client.call(method, [dict(opts, workspace=ws)])
            return True
        except Exception as e:
            logger.debug(f"{method} failed: {e}")
            return False

    # Workspace is created if missing; ignore "already exists".
    try:
        client.call('db.add_workspace', [ws])
    except Exception:
        pass

    for ep in format_targets(results, confirmed_only=confirmed_only):
        host_addr = ep['ip'] or ep['host']
        if _call('db.report_host', {'host': host_addr, 'name': ep['host']}):
            summary['hosts'] += 1
        if _call('db.report_service', {
                'host': host_addr, 'port': ep['port'], 'proto': 'tcp',
                'name': 'https' if ep['ssl'] else 'http', 'state': 'open'}):
            summary['services'] += 1

    for note in format_notes(results, confirmed_only=confirmed_only):
        host_addr = _resolve(note['host']) or note['host']
        data = f"[{note['severity']}] {note['technique']}: {note['reason']}"
        if _call('db.report_note', {
                'host': host_addr, 'type': 'wafpierce.finding', 'data': data}):
            summary['notes'] += 1
        if note['severity'] in ('CRITICAL', 'HIGH'):
            if _call('db.report_vuln', {
                    'host': host_addr, 'name': f"Blackthorn: {note['technique']}",
                    'info': note['reason'][:500]}):
                summary['vulns'] += 1

    summary['ok'] = summary['hosts'] > 0 or summary['notes'] > 0
    return summary


# --------------------------------------------------------------------------- #
# Aux scanners
# --------------------------------------------------------------------------- #
def run_aux_scanners(cfg: MsfConfig, target: str,
                     modules: Optional[List[str]] = None,
                     timeout: int = 120) -> List[Dict[str, Any]]:
    """Run ``auxiliary/scanner/http/*`` modules against ``target``.

    Returns scanner-shaped findings carrying each module's captured output.
    Best-effort: a connection failure yields a single ERROR finding.
    """
    modules = modules or DEFAULT_AUX_HTTP
    host, port, ssl = target_parts(target)
    try:
        client = connect(cfg)
    except Exception as e:
        return [_finding('Metasploit', target,
                         f"msfrpcd connect failed: {type(e).__name__}: {e}",
                         severity='INFO')]

    findings: List[Dict[str, Any]] = []
    console = None
    try:
        console = client.consoles.console()
        for mod_path in modules:
            try:
                mod = client.modules.use('auxiliary', mod_path)
            except Exception as e:
                findings.append(_finding(f"MSF {mod_path}", target,
                                         f"module load failed: {e}"))
                continue
            opts = mod.options if hasattr(mod, 'options') else []
            try:
                mod['RHOSTS'] = host
            except Exception:
                pass
            for name, val in (('RPORT', port), ('SSL', ssl)):
                if name in opts:
                    try:
                        mod[name] = val
                    except Exception:
                        pass
            try:
                output = console.run_module_with_output(mod) or ''
            except Exception as e:
                output = f"(execution error: {e})"
            findings.append(_finding(
                f"MSF {mod_path}", target,
                (output.strip()[:1500] or 'no output'),
                module=mod_path, output=output))
    finally:
        try:
            if console is not None:
                console.destroy()
        except Exception:
            pass

    return findings


# --------------------------------------------------------------------------- #
# CLI entry point  (`blackthorn msf ...`)
# --------------------------------------------------------------------------- #
def _add_conn_flags(p) -> None:
    p.add_argument('--msf-host', default=None, help='msfrpcd host (default 127.0.0.1)')
    p.add_argument('--msf-port', type=int, default=None, help='msfrpcd port (default 55553)')
    p.add_argument('--msf-password', default=None, help='msfrpcd password (or env MSF_RPC_PASSWORD)')
    p.add_argument('--msf-no-ssl', action='store_true', help='RPC without SSL (msfrpcd -S)')
    p.add_argument('--workspace', default=None, help='MSF workspace (default wafpierce)')


def _cfg_from_args(args) -> MsfConfig:
    cfg = MsfConfig.from_env(
        password=args.msf_password, host=args.msf_host,
        port=args.msf_port, workspace=args.workspace)
    if getattr(args, 'msf_no_ssl', False):
        cfg.ssl = False
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    p = argparse.ArgumentParser(
        prog='blackthorn msf',
        description='Metasploit RPC integration (handoff + aux scanners).')
    sub = p.add_subparsers(dest='action', required=True)

    pc = sub.add_parser('check', help='preflight: is msfrpcd reachable?')
    _add_conn_flags(pc)

    ps = sub.add_parser('scan', help='run auxiliary/scanner/http modules')
    ps.add_argument('target')
    ps.add_argument('-o', '--output', help='write findings JSON here')
    ps.add_argument('--modules', help='comma-separated aux module paths')
    _add_conn_flags(ps)

    pp = sub.add_parser('push', help='push findings JSON into an MSF workspace')
    pp.add_argument('results', help='a scan results JSON file')
    pp.add_argument('--all', action='store_true', help='push all findings, not just confirmed')
    _add_conn_flags(pp)

    args = p.parse_args(argv)
    cfg = _cfg_from_args(args)

    if args.action == 'check':
        ok, msg = preflight(cfg)
        print(('[+] ' if ok else '[-] ') + msg)
        return 0 if ok else 1

    ok, msg = preflight(cfg)
    if not ok:
        print(f"[-] {msg}", flush=True)
        return 1

    if args.action == 'scan':
        modules = args.modules.split(',') if args.modules else None
        findings = run_aux_scanners(cfg, args.target, modules=modules)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, default=str)
            print(f"[+] Wrote {len(findings)} finding(s) to {args.output}")
        else:
            print(json.dumps(findings, indent=2, default=str))
        return 0

    if args.action == 'push':
        with open(args.results, 'r', encoding='utf-8') as f:
            results = json.load(f)
        if not isinstance(results, list):
            print('[-] results file must be a JSON list of findings')
            return 1
        summary = push_findings(cfg, results, confirmed_only=not args.all)
        print(json.dumps(summary, indent=2))
        return 0 if summary.get('ok') else 1

    return 1


if __name__ == '__main__':
    raise SystemExit(main())
