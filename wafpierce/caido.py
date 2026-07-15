"""Caido integration — proxy passthrough + push/export.

`Caido <https://caido.io>`_ is a web-security proxy (a Burp alternative). Two
ways WAFPierce talks to it, both opt-in:

* **Proxy passthrough** — route the scanner/recon HTTP traffic *through* Caido's
  proxy listener so every request WAFPierce makes is captured in Caido's history
  and sitemap. This is just a ``requests`` proxies dict; see
  :func:`proxy_for` and the ``proxy=`` argument added to
  :func:`wafpierce.network.create_optimized_session`.

* **Push / export** — after a scan, *replay* the confirmed requests through the
  Caido proxy (:func:`replay_through_proxy`) so the interesting traffic lands in
  Caido even if the live scan didn't run through it, and/or dump the requests as
  raw HTTP for manual import (:func:`export_requests`). :func:`check` verifies
  Caido's local GraphQL endpoint is up.

Everything is best-effort and returns a value (bool / dict / count); a Caido
that isn't running must never break a scan.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class CaidoConfig:
    """Where Caido is listening. Defaults match a stock local Caido install;
    override the proxy port if you changed ``--proxy-listen``."""
    proxy_url: str = 'http://127.0.0.1:8080'        # proxy listener
    api_url: str = 'http://127.0.0.1:8080/graphql'  # local GraphQL endpoint
    api_token: str = ''                              # optional bearer token
    verify_ssl: bool = False                         # proxy MITMs TLS -> usually off

    @classmethod
    def from_env(cls, **overrides: Any) -> 'CaidoConfig':
        import os
        cfg = cls(
            proxy_url=os.environ.get('CAIDO_PROXY_URL', 'http://127.0.0.1:8080'),
            api_url=os.environ.get('CAIDO_API_URL', 'http://127.0.0.1:8080/graphql'),
            api_token=os.environ.get('CAIDO_API_TOKEN', ''),
        )
        for k, v in overrides.items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


# --------------------------------------------------------------------------- #
# Proxy passthrough
# --------------------------------------------------------------------------- #
def proxy_for(cfg: CaidoConfig) -> Dict[str, str]:
    """A ``requests``-style proxies dict, or ``{}`` if no proxy configured."""
    if not cfg.proxy_url:
        return {}
    return {'http': cfg.proxy_url, 'https': cfg.proxy_url}


# --------------------------------------------------------------------------- #
# GraphQL connectivity
# --------------------------------------------------------------------------- #
def graphql(cfg: CaidoConfig, query: str,
            variables: Optional[Dict[str, Any]] = None, timeout: float = 15.0):
    """POST a GraphQL query to Caido's local endpoint. Returns the response
    object (caller inspects status/json). Raises only on transport errors."""
    import requests
    headers = {'Content-Type': 'application/json'}
    if cfg.api_token:
        headers['Authorization'] = f'Bearer {cfg.api_token}'
    return requests.post(cfg.api_url,
                         json={'query': query, 'variables': variables or {}},
                         headers=headers, timeout=timeout, verify=cfg.verify_ssl)


def check(cfg: CaidoConfig) -> Tuple[bool, str]:
    """(reachable, message). Uses a schema-agnostic ``{ __typename }`` probe."""
    try:
        resp = graphql(cfg, 'query { __typename }')
    except Exception as e:
        return False, (f"Caido GraphQL unreachable at {cfg.api_url} "
                       f"({type(e).__name__}: {e})")
    code = getattr(resp, 'status_code', 0)
    if code and code < 400:
        return True, f"Caido GraphQL reachable ({cfg.api_url}, HTTP {code})"
    if code in (401, 403):
        return False, (f"Caido reachable but rejected the request (HTTP {code}); "
                       "set an API token in Settings")
    return False, f"Caido GraphQL returned HTTP {code or '?'}"


# --------------------------------------------------------------------------- #
# Request reconstruction (shared by replay + export)
# --------------------------------------------------------------------------- #
def _finding_url(r: Dict[str, Any]) -> str:
    """Best-effort absolute URL for a finding (target base + tested path)."""
    target = r.get('target') or r.get('url') or ''
    path = r.get('path') or ''
    if not target:
        return path
    if path:
        return urljoin(target, path)
    return target


def _select(results: List[Dict[str, Any]], confirmed_only: bool) -> List[Dict[str, Any]]:
    return [r for r in results if (r.get('bypass') or not confirmed_only)]


# --------------------------------------------------------------------------- #
# Push: replay through the proxy so requests land in Caido
# --------------------------------------------------------------------------- #
def replay_through_proxy(cfg: CaidoConfig, results: List[Dict[str, Any]],
                         confirmed_only: bool = True,
                         session=None, timeout: float = 15.0) -> Dict[str, Any]:
    """Re-issue each (confirmed) request *through* the Caido proxy so it shows up
    in Caido's HTTP history. Returns ``{ok, sent, failed, error}``."""
    summary = {'ok': False, 'sent': 0, 'failed': 0, 'error': None}
    proxies = proxy_for(cfg)
    if not proxies:
        summary['error'] = 'no Caido proxy_url configured'
        return summary
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception as e:  # pragma: no cover
        summary['error'] = f"requests unavailable: {e}"
        return summary

    sess = session or requests.Session()
    for r in _select(results, confirmed_only):
        url = _finding_url(r)
        if not url:
            continue
        method = (r.get('method') or 'GET').upper()
        headers = r.get('headers') if isinstance(r.get('headers'), dict) else {}
        data = r.get('data')
        try:
            sess.request(method, url, headers=headers, data=data,
                         proxies=proxies, verify=cfg.verify_ssl,
                         timeout=timeout, allow_redirects=False)
            summary['sent'] += 1
        except Exception as e:
            summary['failed'] += 1
            logger.debug(f"Caido replay failed for {url}: {e}")
    summary['ok'] = summary['sent'] > 0
    return summary


# --------------------------------------------------------------------------- #
# Export: raw HTTP requests for manual import
# --------------------------------------------------------------------------- #
def format_raw_request(r: Dict[str, Any]) -> str:
    """Pure: build a raw HTTP/1.1 request block from a finding."""
    url = _finding_url(r)
    u = urlparse(url if '://' in url else 'http://' + url)
    path = u.path or '/'
    if u.query:
        path += '?' + u.query
    method = (r.get('method') or 'GET').upper()
    lines = [f"{method} {path} HTTP/1.1", f"Host: {u.netloc}"]
    headers = r.get('headers') if isinstance(r.get('headers'), dict) else {}
    for k, v in headers.items():
        if k.lower() == 'host':
            continue
        lines.append(f"{k}: {v}")
    body = r.get('data') or ''
    block = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        block += body if isinstance(body, str) else str(body)
    return block


def export_requests(results: List[Dict[str, Any]], path: str,
                    confirmed_only: bool = True) -> int:
    """Write selected findings as raw HTTP requests (separated) for Caido import.
    Returns the number of requests written."""
    selected = _select(results, confirmed_only)
    blocks = [format_raw_request(r) for r in selected if _finding_url(r)]
    sep = "\r\n\r\n" + ("#" * 70) + "  Blackthorn -> Caido  " + ("#" * 8) + "\r\n\r\n"
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(sep.join(blocks))
    return len(blocks)


# --------------------------------------------------------------------------- #
# CLI entry point  (`blackthorn caido ...`)
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    p = argparse.ArgumentParser(
        prog='blackthorn caido',
        description='Caido integration (proxy check / push / export).')
    p.add_argument('--proxy-url', default=None, help='Caido proxy listener (default http://127.0.0.1:8080)')
    p.add_argument('--api-url', default=None, help='Caido GraphQL endpoint')
    p.add_argument('--api-token', default=None, help='Caido API bearer token')
    sub = p.add_subparsers(dest='action', required=True)

    sub.add_parser('check', help='is Caido reachable?')

    pp = sub.add_parser('push', help='replay findings through the Caido proxy')
    pp.add_argument('results', help='scan results JSON file')
    pp.add_argument('--all', action='store_true', help='replay all findings, not just confirmed')

    pe = sub.add_parser('export', help='export findings as raw HTTP requests')
    pe.add_argument('results', help='scan results JSON file')
    pe.add_argument('-o', '--output', required=True, help='output .txt path')
    pe.add_argument('--all', action='store_true', help='export all findings, not just confirmed')

    args = p.parse_args(argv)
    cfg = CaidoConfig.from_env(proxy_url=args.proxy_url, api_url=args.api_url,
                               api_token=args.api_token)

    if args.action == 'check':
        ok, msg = check(cfg)
        print(('[+] ' if ok else '[-] ') + msg)
        return 0 if ok else 1

    with open(args.results, 'r', encoding='utf-8') as f:
        results = json.load(f)
    if not isinstance(results, list):
        print('[-] results file must be a JSON list of findings')
        return 1

    if args.action == 'push':
        summary = replay_through_proxy(cfg, results, confirmed_only=not args.all)
        print(json.dumps(summary, indent=2))
        return 0 if summary.get('ok') else 1

    if args.action == 'export':
        n = export_requests(results, args.output, confirmed_only=not args.all)
        print(f"[+] Wrote {n} raw request(s) to {args.output}")
        return 0

    return 1


if __name__ == '__main__':
    raise SystemExit(main())
