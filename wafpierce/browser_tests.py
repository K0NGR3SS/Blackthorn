"""
WAFPierce Browser-Based Tests (optional)

DOM XSS and Client-Side Path Traversal detection that requires a real DOM, so it
runs in a headless browser via Playwright. This module is OPTIONAL: if Playwright
is not installed the scanner skips these tests cleanly. It is intentionally kept
out of the default PyInstaller build to keep the packaged .exe small.

Install with:
    pip install playwright
    python -m playwright install chromium
"""
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False

# A canary value we look for being reflected into a dangerous DOM sink.
_CANARY = "wafp_dom_canary_8217"
# DOM-XSS probe payloads injected into params / fragment.
_DOM_PAYLOADS = [
    f"<img src=x onerror=window.{_CANARY}=1>",
    f"javascript:window.{_CANARY}=1",
    f"'><svg onload=window.{_CANARY}=1>",
    f"#{_CANARY}",
]


def _with_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = {k: (v[0] if v else '') for k, v in parse_qs(p.query).items()}
    q[param] = value
    return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"


def run_dom_xss(target: str, crawl_targets: List[Dict[str, Any]],
                timeout: int = 5, max_urls: int = 12) -> List[Dict[str, Any]]:
    """Detect DOM-based XSS by injecting canary payloads and checking sinks.

    We hook window flags / dialog events and detect if our payload causes script
    execution or unsanitized reflection into innerHTML-like sinks.
    """
    results: List[Dict[str, Any]] = []
    if not PLAYWRIGHT_AVAILABLE:
        return results

    # Build candidate URLs: discovered GET endpoints with params, plus root w/ frag.
    candidates = []
    for ep in crawl_targets:
        if ep.get('method', 'GET') != 'GET':
            continue
        base = urljoin(target + '/', ep['path'].lstrip('/'))
        for pname in (ep.get('params') or {}):
            for payload in _DOM_PAYLOADS:
                candidates.append((_with_param(base, pname, payload), pname, payload))
    # Always probe the fragment on the root (common DOM-XSS source).
    for payload in _DOM_PAYLOADS:
        candidates.append((f"{target}/#{payload}", 'fragment', payload))
    candidates = candidates[:max_urls]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            triggered = {'hit': False}
            page.on('dialog', lambda d: (triggered.__setitem__('hit', True), d.dismiss()))
            for url, pname, payload in candidates:
                triggered['hit'] = False
                try:
                    page.goto(url, timeout=timeout * 1000, wait_until='load')
                    page.wait_for_timeout(300)
                    flag = page.evaluate(f"() => !!window.{_CANARY}")
                except Exception as e:
                    logger.debug(f"DOM XSS nav error {url}: {e}")
                    continue
                if flag or triggered['hit']:
                    results.append({
                        'technique': f'DOM XSS [{pname}]', 'bypass': True, 'status': 200,
                        'reason': f'Payload executed in DOM via {pname}: {payload[:40]}',
                        'severity': 'CRITICAL', 'category': 'INJECTION',
                        'details': {'url': url, 'param': pname},
                    })
                    print(f"  [✓] CRITICAL: DOM XSS via {pname}")
            browser.close()
    except Exception as e:
        logger.debug(f"DOM XSS runner error: {e}")
    return results


def run_client_side_path_traversal(target: str, crawl_targets: List[Dict[str, Any]],
                                   timeout: int = 5, max_urls: int = 12) -> List[Dict[str, Any]]:
    """Detect Client-Side Path Traversal: params that influence fetch()/XHR URLs.

    We inject ../ sequences and observe whether the page issues a request to an
    unexpected (traversed) path, indicating client-controlled request paths.
    """
    results: List[Dict[str, Any]] = []
    if not PLAYWRIGHT_AVAILABLE:
        return results

    marker = "wafp_cspt"
    candidates = []
    for ep in crawl_targets:
        if ep.get('method', 'GET') != 'GET':
            continue
        base = urljoin(target + '/', ep['path'].lstrip('/'))
        for pname in (ep.get('params') or {}):
            candidates.append((_with_param(base, pname, f"..%2f..%2f{marker}"), pname))
    candidates = candidates[:max_urls]
    if not candidates:
        return results

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            seen_requests = {'urls': []}
            page.on('request', lambda r: seen_requests['urls'].append(r.url))
            for url, pname in candidates:
                seen_requests['urls'] = []
                try:
                    page.goto(url, timeout=timeout * 1000, wait_until='networkidle')
                    page.wait_for_timeout(300)
                except Exception as e:
                    logger.debug(f"CSPT nav error {url}: {e}")
                    continue
                # If a subsequent request URL contains our marker after traversal,
                # the param controls a client-side request path.
                hit = any(marker in u and ('../' in u or '..%2f' in u.lower()) for u in seen_requests['urls'])
                if hit:
                    results.append({
                        'technique': f'Client-Side Path Traversal [{pname}]', 'bypass': True,
                        'status': 200, 'reason': f'Param {pname} controls a client-side request path',
                        'severity': 'HIGH', 'category': 'INJECTION',
                        'details': {'url': url, 'param': pname},
                    })
                    print(f"  [✓] HIGH: Client-Side Path Traversal via {pname}")
            browser.close()
    except Exception as e:
        logger.debug(f"CSPT runner error: {e}")
    return results
