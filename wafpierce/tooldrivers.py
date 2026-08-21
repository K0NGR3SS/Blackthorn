"""
Detect-&-drive OWASP ZAP and Burp Suite (P6), Qt-free.

* ZAP: a thin REST client (``http://<host>:<port>/JSON/...?apikey=``) that runs the
  spider + active scan and pulls alerts. Detection pings the version endpoint.
* Burp: Community has no general local REST, so the primary path is importing a
  Burp issues report (XML/HAR/JSON) — see :func:`wafpierce.importers.from_burp_issues`.
  An optional REST client is provided for Burp Enterprise/official REST.

Both map their native findings into the SAME canonical WAFPierce finding dict
(the shared normalization layer), tagged ``[ZAP]`` / ``[Burp]`` so they appear in
the Results Explorer and reports next to scanner findings.
"""
from __future__ import annotations

import shutil
from typing import Dict, List, Optional


# ZAP risk / Burp severity -> WAFPierce severity
_ZAP_RISK = {'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW',
             'informational': 'INFO', 'info': 'INFO'}
_BURP_SEV = {'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW',
             'information': 'INFO', 'informational': 'INFO', 'info': 'INFO'}
_CONFIDENCE = {'high': 'high', 'medium': 'medium', 'low': 'low',
               'certain': 'high', 'firm': 'medium', 'tentative': 'low'}


# --------------------------------------------------------------------------- #
# Normalization (the shared mapper style other features reuse)
# --------------------------------------------------------------------------- #
def zap_alert_to_finding(alert: Dict, target: str = '') -> Dict:
    cwe = str(alert.get('cweid', '') or '').strip()
    cwe_id = f'CWE-{cwe}' if cwe and cwe not in ('-1', '0') else ''
    return {
        'target': target or alert.get('url', ''),
        'technique': f"[ZAP] {alert.get('alert') or alert.get('name', 'alert')}",
        'category': 'external:zap',
        'severity': _ZAP_RISK.get(str(alert.get('risk', '')).lower(), 'INFO'),
        'cvss_score': 0.0,
        'bypass': False,
        'reason': ' '.join((alert.get('description') or '').split())[:400],
        'url': alert.get('url', ''),
        'path': '',
        'payload': alert.get('attack', '') or alert.get('param', ''),
        'response_code': None,
        'cve_id': '',
        'cwe_id': cwe_id,
        'reference_url': (alert.get('reference', '') or '').split('\n')[0],
        'confidence': _CONFIDENCE.get(str(alert.get('confidence', '')).lower(), 'medium'),
        'kind': 'suspected',
        'verification_status': 'candidate',
        'result_type': 'tool_candidate',
        'evidence': [{
            'type': 'external_tool_alert',
            'description': 'ZAP reported an alert that requires Blackthorn re-test',
            'matched': alert.get('url', ''),
        }],
        'source': 'external:zap',
        '_external_source': 'ZAP',
    }


def burp_issue_to_finding(issue: Dict, target: str = '') -> Dict:
    host = issue.get('host', '')
    path = issue.get('path', '')
    url = (host + path) if host else path
    cwe = str(issue.get('cwe', '') or '').strip()
    cwe_id = f'CWE-{cwe}' if cwe.isdigit() else (cwe if cwe.startswith('CWE-') else '')
    return {
        'target': target or url,
        'technique': f"[Burp] {issue.get('name', 'issue')}",
        'category': 'external:burp',
        'severity': _BURP_SEV.get(str(issue.get('severity', '')).lower(), 'INFO'),
        'cvss_score': 0.0,
        'bypass': False,
        'reason': ' '.join((issue.get('background') or issue.get('detail') or '').split())[:400],
        'url': url,
        'path': path,
        'payload': '',
        'response_code': None,
        'cve_id': '',
        'cwe_id': cwe_id,
        'reference_url': '',
        'confidence': _CONFIDENCE.get(str(issue.get('confidence', '')).lower(), 'medium'),
        'kind': 'suspected',
        'verification_status': 'candidate',
        'result_type': 'tool_candidate',
        'evidence': [{
            'type': 'external_tool_alert',
            'description': 'Burp reported an issue that requires Blackthorn re-test',
            'matched': url,
        }],
        'source': 'external:burp',
        '_external_source': 'Burp',
    }


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def detect_zap(host: str = '127.0.0.1', port: int = 8080, apikey: str = '',
               session=None) -> Dict:
    """Ping the ZAP REST API. Returns {state, version, base, error}.
    state: 'running' | 'absent'."""
    import requests
    base = f'http://{host}:{port}'
    sess = session or requests
    try:
        r = sess.get(f'{base}/JSON/core/view/version/',
                     params={'apikey': apikey} if apikey else {}, timeout=4)
        if r.status_code == 200:
            return {'state': 'running', 'version': r.json().get('version', '?'),
                    'base': base, 'error': ''}
        return {'state': 'absent', 'version': '', 'base': base,
                'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'state': 'absent', 'version': '', 'base': base, 'error': str(e)}


def detect_burp() -> Dict:
    """Locate a Burp binary on PATH/default dirs. Returns {state, path}.
    state: 'installed' | 'absent' (Community has no local REST to ping)."""
    for name in ('burpsuite', 'BurpSuiteCommunity', 'BurpSuitePro', 'burp'):
        p = shutil.which(name)
        if p:
            return {'state': 'installed', 'path': p}
    import os
    for cand in (r'C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe',
                 r'C:\Program Files\BurpSuitePro\BurpSuitePro.exe'):
        if os.path.isfile(cand):
            return {'state': 'installed', 'path': cand}
    return {'state': 'absent', 'path': ''}


# --------------------------------------------------------------------------- #
# ZAP REST client
# --------------------------------------------------------------------------- #
class ZAPClient:
    """Minimal ZAP REST driver using raw requests (avoids the python-owasp-zap dep)."""

    def __init__(self, host='127.0.0.1', port=8080, apikey='', session=None):
        self.base = f'http://{host}:{port}'
        self.apikey = apikey
        self._sess = session or __import__('requests').Session()

    def _get(self, path, **params):
        if self.apikey:
            params['apikey'] = self.apikey
        r = self._sess.get(f'{self.base}{path}', params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def version(self) -> str:
        return self._get('/JSON/core/view/version/').get('version', '?')

    def spider(self, url: str) -> str:
        return self._get('/JSON/spider/action/scan/', url=url).get('scan', '')

    def spider_status(self, scan_id: str) -> int:
        return int(self._get('/JSON/spider/view/status/', scanId=scan_id).get('status', 0))

    def client_spider(self, url: str, *, browser: str = 'firefox-headless',
                      max_depth: int = 5, page_load_time: int = 30,
                      browsers: int = 1, context_name: str = '',
                      user_name: str = '') -> str:
        """Start the modern DOM-aware Client Spider with strict scope checks."""
        params = {
            'url': url,
            'browser': browser,
            'subtreeOnly': 'false',
            'maxCrawlDepth': max(0, min(int(max_depth), 100)),
            'pageLoadTime': max(1, min(int(page_load_time), 300)),
            'numberOfBrowsers': max(1, min(int(browsers), 10)),
            'scopeCheck': 'STRICT',
            'logoutAvoidance': 'true',
        }
        if context_name:
            params['contextName'] = context_name
        if user_name:
            params['userName'] = user_name
        return self._get('/JSON/clientSpider/action/scan/', **params).get('scan', '')

    def client_spider_status(self, scan_id: str) -> int:
        return int(self._get(
            '/JSON/clientSpider/view/status/', scanId=scan_id
        ).get('status', 0))

    def client_spider_stop(self, scan_id: str):
        try:
            self._get('/JSON/clientSpider/action/stop/', scanId=scan_id)
        except Exception:
            pass

    def ascan(self, url: str) -> str:
        return self._get('/JSON/ascan/action/scan/', url=url).get('scan', '')

    def ascan_status(self, scan_id: str) -> int:
        return int(self._get('/JSON/ascan/view/status/', scanId=scan_id).get('status', 0))

    def ascan_stop(self, scan_id: str):
        try:
            self._get('/JSON/ascan/action/stop/', scanId=scan_id)
        except Exception:
            pass

    def alerts(self, baseurl: str = '') -> List[Dict]:
        params = {'baseurl': baseurl} if baseurl else {}
        return self._get('/JSON/core/view/alerts/', **params).get('alerts', [])

    def run_full(self, target: str, on_log=None, is_aborted=None,
                 do_spider=True, do_ascan=True) -> List[Dict]:
        """Spider + active-scan + collect alerts -> canonical findings."""
        import time
        log = on_log or (lambda *_: None)
        aborted = is_aborted or (lambda: False)
        if do_spider:
            sid = self.spider(target); log(f'[*] ZAP spider {sid}')
            while not aborted() and self.spider_status(sid) < 100:
                time.sleep(1.0)
        if do_ascan:
            aid = self.ascan(target); log(f'[*] ZAP active scan {aid}')
            while not aborted():
                st = self.ascan_status(aid)
                log(f'    ascan {st}%')
                if st >= 100:
                    break
                time.sleep(2.0)
            if aborted():
                self.ascan_stop(aid)
        alerts = self.alerts(target)
        log(f'[+] ZAP: {len(alerts)} alert(s)')
        return [zap_alert_to_finding(a, target) for a in alerts]
