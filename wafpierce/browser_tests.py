"""Blackthorn browser-based tests (optional).

DOM XSS and Client-Side Path Traversal detection that requires a real DOM, so it
runs in a headless browser via Playwright. This module is OPTIONAL: if Playwright
is not installed the scanner skips these tests cleanly. It is intentionally kept
out of the default PyInstaller build to keep the packaged .exe small.

Install with:
    pip install playwright
    python -m playwright install chromium
"""
import logging
import secrets
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False

def _with_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    replaced = False
    updated = []
    for name, current in pairs:
        if name == param and not replaced:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, current))
    if not replaced:
        updated.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path or '/', p.params,
                       urlencode(updated, doseq=True), p.fragment))


def _new_context(browser: Any, headers: Optional[Dict[str, str]],
                 cookies: Optional[List[Dict[str, Any]]]):
    safe_headers = {
        str(k): str(v) for k, v in (headers or {}).items()
        if str(k).lower() not in {'cookie', 'content-length', 'host'}
    }
    context = browser.new_context(
        ignore_https_errors=True,
        extra_http_headers=safe_headers or None,
    )
    if cookies:
        context.add_cookies(cookies)
    return context


def run_dom_xss(target: str, crawl_targets: List[Dict[str, Any]],
                timeout: int = 5, max_urls: int = 12,
                headers: Optional[Dict[str, str]] = None,
                cookies: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Detect DOM-based XSS by injecting canary payloads and checking sinks.

    We hook window flags / dialog events and detect if our payload causes script
    execution or unsanitized reflection into innerHTML-like sinks.
    """
    results: List[Dict[str, Any]] = []
    if not PLAYWRIGHT_AVAILABLE:
        return results

    token = secrets.token_hex(6)
    flag = f"__blackthorn_dom_{token}"
    marker = f"BT-DOM-{token}"
    payloads = [
        f'<img src=x onerror=window["{flag}"]="{marker}">',
        f"'><svg onload=window[\"{flag}\"]=\"{marker}\">",
        f'<svg onload=alert("{marker}")>',
    ]

    # Keep both fragment and query sources represented even with a small cap.
    fragment_candidates = [(f"{target.rstrip('/')}/#{payload}", 'fragment', payload)
                           for payload in payloads]
    query_candidates = []
    for ep in crawl_targets:
        if ep.get('method', 'GET') != 'GET':
            continue
        base = urljoin(target + '/', ep['path'].lstrip('/'))
        for pname in (ep.get('params') or {}):
            for payload in payloads:
                query_candidates.append((_with_param(base, pname, payload), pname, payload))
    reserve = min(len(fragment_candidates), max(1, max_urls // 3))
    candidates = (fragment_candidates[:reserve] +
                  query_candidates[:max(0, max_urls - reserve)])

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = _new_context(browser, headers, cookies)
            for url, pname, payload in candidates:
                page = ctx.new_page()
                triggered = {'hit': False}

                def on_dialog(dialog):
                    try:
                        if dialog.message == marker:
                            triggered['hit'] = True
                        dialog.dismiss()
                    except Exception:
                        pass

                page.on('dialog', on_dialog)
                try:
                    response = page.goto(url, timeout=timeout * 1000, wait_until='load')
                    page.wait_for_timeout(300)
                    flag_value = page.evaluate(f'() => window["{flag}"] || null')
                except Exception as e:
                    logger.debug(f"DOM XSS nav error {url}: {e}")
                    page.close()
                    continue
                if flag_value == marker or triggered['hit']:
                    status = response.status if response is not None else 0
                    results.append({
                        'technique': f'DOM XSS [{pname}]', 'bypass': True, 'status': status,
                        'reason': f'Payload executed in DOM via {pname}: {payload[:40]}',
                        'severity': 'CRITICAL', 'category': 'INJECTION',
                        'kind': 'finding', 'verification_status': 'confirmed',
                        'confidence': 'high', 'payload': payload,
                        'url': url, 'parameter': pname,
                        'insertion_point': {'type': pname if pname == 'fragment' else 'query',
                                            'name': pname},
                        'request': {'method': 'GET', 'url': url, 'headers': {}},
                        'response': {'status': status},
                        'evidence': [{
                            'type': 'browser_execution',
                            'description': 'Exact randomized browser canary executed',
                            'matched': marker,
                        }],
                        'details': {'url': url, 'param': pname, 'canary': marker},
                    })
                    print(f"  [✓] CRITICAL: DOM XSS via {pname}")
                page.close()
            ctx.close()
            browser.close()
    except Exception as e:
        logger.debug(f"DOM XSS runner error: {e}")
    return results


def run_client_side_path_traversal(target: str, crawl_targets: List[Dict[str, Any]],
                                   timeout: int = 5, max_urls: int = 12,
                                   headers: Optional[Dict[str, str]] = None,
                                   cookies: Optional[List[Dict[str, Any]]] = None
                                   ) -> List[Dict[str, Any]]:
    """Detect Client-Side Path Traversal: params that influence fetch()/XHR URLs.

    We inject ../ sequences and observe whether the page issues a request to an
    unexpected (traversed) path, indicating client-controlled request paths.
    """
    results: List[Dict[str, Any]] = []
    if not PLAYWRIGHT_AVAILABLE:
        return results

    marker = f"blackthorn-cspt-{secrets.token_hex(6)}"
    candidates = []
    for ep in crawl_targets:
        if ep.get('method', 'GET') != 'GET':
            continue
        base = urljoin(target + '/', ep['path'].lstrip('/'))
        for pname in (ep.get('params') or {}):
            # Give urlencode raw traversal text exactly once. Passing pre-encoded
            # text here previously turned %2f into %252f and changed the test.
            candidates.append((base, pname))
    candidates = candidates[:max_urls]
    if not candidates:
        return results

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = _new_context(browser, headers, cookies)
            for base, pname in candidates:
                control_url = _with_param(base, pname, 'blackthorn-control')
                probe_value = f'../../{marker}'
                url = _with_param(base, pname, probe_value)

                def request_graph(nav_url: str):
                    page = ctx.new_page()
                    seen = []
                    page.on('request', lambda request: (
                        seen.append(request.url)
                        if request.resource_type != 'document' else None
                    ))
                    response = None
                    try:
                        response = page.goto(
                            nav_url, timeout=timeout * 1000, wait_until='networkidle'
                        )
                        page.wait_for_timeout(300)
                    finally:
                        page.close()
                    return seen, (response.status if response is not None else 0)

                try:
                    control_requests, _ = request_graph(control_url)
                    probe_requests, status = request_graph(url)
                except Exception as e:
                    logger.debug(f"CSPT nav error {url}: {e}")
                    continue
                # URL parsers normalize away ../. The reliable signal is the
                # randomized marker in a non-document request that did not occur
                # in the benign request graph.
                hits = [u for u in probe_requests
                        if marker in u and u not in control_requests]
                if hits:
                    results.append({
                        'technique': f'Client-Side Path Traversal [{pname}]', 'bypass': True,
                        'status': status,
                        'reason': f'Param {pname} controls a client-side request path',
                        'severity': 'HIGH', 'category': 'INJECTION',
                        'kind': 'finding', 'verification_status': 'confirmed',
                        'confidence': 'high', 'payload': probe_value,
                        'url': url, 'parameter': pname,
                        'insertion_point': {'type': 'query', 'name': pname},
                        'request': {'method': 'GET', 'url': url, 'headers': {}},
                        'response': {'status': status},
                        'baseline': {'request_urls': control_requests[:20]},
                        'evidence': [{
                            'type': 'browser_request',
                            'description': ('Randomized traversal marker appeared in a '
                                            'new non-document browser request'),
                            'matched': hits[0],
                        }],
                        'details': {'url': url, 'param': pname,
                                    'request_url': hits[0]},
                    })
                    print(f"  [✓] HIGH: Client-Side Path Traversal via {pname}")
            ctx.close()
            browser.close()
    except Exception as e:
        logger.debug(f"CSPT runner error: {e}")
    return results
