"""Scoped Playwright automation worker used by the Browser workflow.

The GUI passes a private JSON configuration file rather than cookies or tokens on
the command line.  Output is JSONL IPC: transactions are consumed by the Browser
page and are never echoed to its human-readable engine log.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import deque
from urllib.parse import urljoin, urlparse


MAX_CONFIG_BYTES = 1024 * 1024
MAX_BODY_BYTES = 200_000


def _emit(kind: str, **payload) -> None:
    print(json.dumps({'type': kind, **payload}, default=str), flush=True)


def scope_allows(url: str, scope_host: str) -> bool:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or '').rstrip('.').lower()
        root = (scope_host or '').rstrip('.').lower()
        return (
            parsed.scheme in ('http', 'https')
            and bool(root)
            and (host == root or host.endswith('.' + root))
        )
    except ValueError:
        return False


def load_config(path: str) -> dict:
    absolute = os.path.abspath(path)
    if not os.path.isfile(absolute):
        raise ValueError('Playwright configuration file was not found.')
    if os.path.getsize(absolute) > MAX_CONFIG_BYTES:
        raise ValueError('Playwright configuration file is too large.')
    with open(absolute, 'r', encoding='utf-8') as handle:
        config = json.load(handle)
    start_url = str(config.get('start_url') or '').strip()
    scope_host = str(config.get('scope_host') or '').strip()
    if not scope_allows(start_url, scope_host):
        raise ValueError('Playwright start URL is outside the exact configured scope.')
    config['start_url'] = start_url
    config['scope_host'] = scope_host
    config['max_pages'] = max(1, min(int(config.get('max_pages') or 25), 100))
    return config


def _text_body(response) -> str:
    try:
        body = response.body()
    except Exception:
        return ''
    if not body:
        return ''
    clipped = body[:MAX_BODY_BYTES]
    content_type = str(response.headers.get('content-type') or '').lower()
    textual = any(token in content_type for token in (
        'text/', 'json', 'xml', 'javascript', 'graphql', 'x-www-form-urlencoded',
    ))
    if not textual:
        return f'[binary response: {len(body)} bytes]'
    text = clipped.decode('utf-8', 'replace')
    if len(body) > MAX_BODY_BYTES:
        text += ' ...(truncated)'
    return text


def run(config: dict) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        _emit('error', message=f'Playwright is unavailable: {exc}')
        return 2

    start_url = config['start_url']
    scope_host = config['scope_host']
    max_pages = config['max_pages']
    trace_path = str(config.get('trace_path') or '').strip()
    proxy_server = str(config.get('proxy_server') or '').strip()
    headers = {
        str(k): str(v) for k, v in (config.get('headers') or {}).items()
        if '\r' not in str(k) and '\n' not in str(k)
        and '\r' not in str(v) and '\n' not in str(v)
        and str(k).lower() not in ('host', 'content-length', 'connection')
    }

    with sync_playwright() as pw:
        launch = {'headless': True}
        if proxy_server:
            launch['proxy'] = {'server': proxy_server}
        try:
            browser = pw.chromium.launch(**launch)
        except Exception as exc:
            _emit(
                'error',
                message=(
                    f'Chromium could not start: {exc}. '
                    'Run `playwright install chromium` once for this environment.'
                ),
            )
            return 3

        context = browser.new_context(
            extra_http_headers=headers,
            ignore_https_errors=bool(proxy_server),
        )
        if config.get('cookies'):
            try:
                context.add_cookies(config['cookies'])
            except Exception as exc:
                _emit('log', message=f'Cookie state was skipped: {exc}')
        if trace_path:
            context.tracing.start(screenshots=True, snapshots=True, sources=True)

        def route_scoped(route):
            target = route.request.url
            parsed = urlparse(target)
            if parsed.scheme not in ('http', 'https') or scope_allows(target, scope_host):
                route.continue_()
            else:
                route.abort('blockedbyclient')

        context.route('**/*', route_scoped)
        page = context.new_page()

        def on_response(response):
            if config.get('emit_transactions', True) is False:
                return
            request = response.request
            if not scope_allows(response.url, scope_host):
                return
            try:
                post_data = request.post_data or ''
            except Exception:
                post_data = ''
            _emit('transaction', transaction={
                'method': request.method,
                'url': response.url,
                'type': request.resource_type,
                'status': response.status,
                'reqHeaders': dict(request.headers),
                'reqBody': post_data,
                'respHeaders': dict(response.headers),
                'respBody': _text_body(response),
                'source': 'playwright',
            })

        def on_websocket(ws):
            if not scope_allows(ws.url, scope_host):
                return
            _emit('websocket', direction='open', url=ws.url, payload='')
            ws.on('framesent', lambda payload: _emit(
                'websocket', direction='sent', url=ws.url,
                payload=str(payload)[:MAX_BODY_BYTES],
            ))
            ws.on('framereceived', lambda payload: _emit(
                'websocket', direction='received', url=ws.url,
                payload=str(payload)[:MAX_BODY_BYTES],
            ))
            ws.on('close', lambda: _emit(
                'websocket', direction='close', url=ws.url, payload='',
            ))

        page.on('response', on_response)
        page.on('websocket', on_websocket)
        page.on('console', lambda msg: _emit(
            'console', level=msg.type, message=msg.text[:4000], url=page.url,
        ))
        page.on('pageerror', lambda exc: _emit(
            'console', level='error', message=str(exc)[:4000], url=page.url,
        ))

        queue = deque([start_url])
        queued = {start_url}
        visited = []
        while queue and len(visited) < max_pages:
            url = queue.popleft()
            try:
                response = page.goto(url, wait_until='domcontentloaded', timeout=30_000)
                status = response.status if response else 0
                page.wait_for_timeout(350)
                links = page.eval_on_selector_all(
                    'a[href]', 'els => els.map(el => el.href).filter(Boolean)'
                )
                for value in links:
                    candidate = urljoin(url, str(value)).split('#', 1)[0]
                    if (
                        candidate not in queued
                        and scope_allows(candidate, scope_host)
                        and len(queued) < max_pages * 8
                    ):
                        queued.add(candidate)
                        queue.append(candidate)
                visited.append(url)
                _emit(
                    'progress', current=len(visited), total=max_pages,
                    url=url, status=status, queued=len(queue),
                )
            except Exception as exc:
                visited.append(url)
                _emit(
                    'progress', current=len(visited), total=max_pages,
                    url=url, status=0, error=str(exc)[:500], queued=len(queue),
                )

        if trace_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(trace_path)), exist_ok=True)
                context.tracing.stop(path=trace_path)
                try:
                    os.chmod(trace_path, 0o600)
                except OSError:
                    pass
                _emit('artifact', kind='trace', path=os.path.abspath(trace_path))
            except Exception as exc:
                _emit('log', message=f'Trace export failed: {exc}')
        context.close()
        browser.close()
    _emit('complete', pages=len(visited), queued=len(queue))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Blackthorn scoped Playwright worker')
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    try:
        return run(load_config(args.config))
    except Exception as exc:
        _emit('error', message=str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
