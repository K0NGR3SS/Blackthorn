"""
Embedded QtWebEngine browser (P5, source-only).

Guarded so the rest of the app works even when QtWebEngine (PySide6-Addons) is
absent. The browser uses an off-the-record profile and a URL request interceptor
that records request *metadata* into the unified history store (source='browser').

IMPORTANT (R1): ``interceptRequest`` runs on a Qt IO thread. The ``on_request_meta``
callback passed in must ONLY emit a queued Qt signal — never touch sqlite or
widgets directly. The GUI wires it to ProxySignals.flow_captured, whose GUI-thread
slot persists the row.

Capture fidelity is metadata-only (method/url/headers-less); full request/response
bodies require the P4 proxy. This is a documented, honest limitation.
"""
from __future__ import annotations

from urllib.parse import urlparse


def webengine_available():
    """Return (ok: bool, error: str). Never raises."""
    try:
        from PySide6 import QtWebEngineWidgets, QtWebEngineCore  # noqa: F401
        return True, ''
    except Exception as e:  # ImportError or platform/runtime issue
        return False, str(e)


def create_embedded_browser(on_request_meta, parent=None):
    """Build and return an EmbeddedBrowser widget. Raises if QtWebEngine is absent.

    ``on_request_meta(meta_dict)`` is invoked from the Qt IO thread for each
    request and must only emit a queued signal.
    """
    from PySide6 import QtCore
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWebEngineCore import (QWebEngineProfile, QWebEnginePage,
                                         QWebEngineUrlRequestInterceptor)

    class _Interceptor(QWebEngineUrlRequestInterceptor):
        def __init__(self, cb):
            super().__init__()
            self._cb = cb

        def interceptRequest(self, info):
            try:
                url = info.requestUrl().toString()
                p = urlparse(url)
                try:
                    method = bytes(info.requestMethod()).decode('latin-1', 'replace')
                except Exception:
                    method = 'GET'
                rtype = int(info.resourceType())
                meta = {
                    'source': 'browser',
                    'method': method,
                    'scheme': p.scheme or 'http',
                    'host': p.hostname or '',
                    'port': p.port or (443 if p.scheme == 'https' else 80),
                    'path': p.path or '/',
                    'url': url,
                    'first_party_url': info.firstPartyUrl().toString(),
                    'resource_type': rtype,
                    'navigation_type': int(info.navigationType()),
                    'is_navigation': 1 if rtype == 0 else 0,
                    'req_headers': {}, 'req_body': b'',
                    'status_code': None, 'resp_headers': {}, 'resp_body': b'',
                    'resp_time_ms': None, 'raw_request': '',
                    'notes': 'browser capture (metadata only)',
                }
                self._cb(meta)
            except Exception:
                pass

    class EmbeddedBrowser(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            lay = QVBoxLayout(self)
            bar = QHBoxLayout()
            back = QPushButton('◀'); fwd = QPushButton('▶'); reload_b = QPushButton('⟳')
            for w in (back, fwd, reload_b):
                w.setFixedWidth(36)
            self.url = QLineEdit(); self.url.setPlaceholderText('https://example.com')
            go = QPushButton('Go')
            bar.addWidget(back); bar.addWidget(fwd); bar.addWidget(reload_b)
            bar.addWidget(self.url, 1); bar.addWidget(go)
            lay.addLayout(bar)

            # Off-the-record profile (no on-disk cookies/cache) + interceptor.
            self.profile = QWebEngineProfile(self)
            self.interceptor = _Interceptor(on_request_meta)
            try:
                self.profile.setUrlRequestInterceptor(self.interceptor)
            except Exception:
                pass
            self.view = QWebEngineView(self)
            self.page = QWebEnginePage(self.profile, self.view)
            self.view.setPage(self.page)
            lay.addWidget(self.view, 1)

            def navigate():
                self.load(self.url.text().strip())
            go.clicked.connect(navigate)
            self.url.returnPressed.connect(navigate)
            back.clicked.connect(self.view.back)
            fwd.clicked.connect(self.view.forward)
            reload_b.clicked.connect(self.view.reload)
            self.view.urlChanged.connect(lambda q: self.url.setText(q.toString()))

        def load(self, url):
            if not url:
                return
            if '://' not in url:
                url = 'http://' + url
            self.view.setUrl(QtCore.QUrl(url))

    return EmbeddedBrowser(parent)
