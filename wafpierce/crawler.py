"""
WAFPierce Crawler / Spider

Lightweight, dependency-free (stdlib only) crawler that discovers real endpoints
and parameters on the target so that injection tests fuzz live inputs instead of
only probing ``/``. Sources:

  * BFS over same-host HTML links and forms
  * robots.txt (Allow/Disallow/Sitemap directives)
  * sitemap.xml (and sitemap indexes)

Each discovered endpoint is normalized into:

    {'path': '/search', 'params': {'q': 'test'}, 'method': 'GET'}

Designed to share the scanner's pooled ``requests.Session`` and to be strictly
bounded (max pages, depth, time) so it never runs away on a large site.
"""
import re
import time
import logging
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, List, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# File extensions not worth crawling for endpoints.
_SKIP_EXT = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov',
    '.pdf', '.zip', '.gz', '.tar', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx',
}


class _LinkFormParser(HTMLParser):
    """Extracts anchor hrefs, form actions/fields, and src/action attributes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._cur_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}
        if tag == 'a' and a.get('href'):
            self.links.append(a['href'])
        elif tag in ('link',) and a.get('href'):
            self.links.append(a['href'])
        elif tag in ('script', 'iframe') and a.get('src'):
            self.links.append(a['src'])
        elif tag == 'form':
            self._cur_form = {
                'action': a.get('action', ''),
                'method': (a.get('method') or 'GET').upper(),
                'fields': {},
            }
        elif tag in ('input', 'textarea', 'select') and self._cur_form is not None:
            name = a.get('name')
            if name:
                # Seed a benign default value for the field.
                self._cur_form['fields'][name] = a.get('value') or 'test'

    def handle_endtag(self, tag):
        if tag == 'form' and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


class Crawler:
    def __init__(self, base_url: str, session, timeout: int = 5,
                 max_pages: int = 60, max_depth: int = 3, max_seconds: int = 45,
                 limiter=None):
        self.base_url = base_url.rstrip('/')
        parsed = urlparse(self.base_url)
        self.scheme = parsed.scheme
        self.host = parsed.netloc
        self.session = session
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_seconds = max_seconds
        self.limiter = limiter  # optional _AdaptiveLimiter for concurrency pacing

        self._seen_urls: Set[str] = set()
        self._endpoints: Dict[str, Dict[str, Any]] = {}  # keyed by method+path+paramnames

    # ------------------------------------------------------------------ helpers
    def _same_host(self, url: str) -> bool:
        try:
            netloc = urlparse(url).netloc
            return netloc == '' or netloc == self.host
        except Exception:
            return False

    def _skip(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in _SKIP_EXT)

    def _get(self, url: str):
        if self.limiter is not None:
            self.limiter.acquire()
        try:
            current = url
            for _ in range(6):
                response = self.session.get(
                    current, timeout=self.timeout,
                    allow_redirects=False, verify=False,
                )
                if response.status_code not in (301, 302, 303, 307, 308):
                    return response
                location = response.headers.get('Location')
                if not location:
                    return response
                following = urljoin(current, location)
                # The crawler shares the authenticated scanner session. Never
                # follow it across the target-origin boundary.
                if not self._same_host(following):
                    logger.debug(
                        "Crawler stopped credentialed redirect at %s", following
                    )
                    return response
                current = following
            return response
        except Exception as e:
            logger.debug(f"Crawl GET failed {url}: {e}")
            return None
        finally:
            if self.limiter is not None:
                self.limiter.release()

    def _record(self, path: str, params: Dict[str, str], method: str = 'GET'):
        if not path:
            path = '/'
        key = f"{method}:{path}:{','.join(sorted(params.keys()))}"
        if key not in self._endpoints:
            self._endpoints[key] = {'path': path, 'params': dict(params), 'method': method}

    def _path_with_params(self, url: str) -> Tuple[str, Dict[str, str]]:
        p = urlparse(url)
        params = {k: (v[0] if v else 'test') for k, v in parse_qs(p.query).items()}
        return (p.path or '/'), params

    # -------------------------------------------------------------------- robots
    def _seed_from_robots(self) -> List[str]:
        seeds = []
        resp = self._get(f"{self.base_url}/robots.txt")
        if resp is None or resp.status_code >= 400:
            return seeds
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            low = line.lower()
            if low.startswith(('allow:', 'disallow:')):
                val = line.split(':', 1)[1].strip()
                if val and val != '/' and '*' not in val:
                    seeds.append(urljoin(self.base_url + '/', val.lstrip('/')))
            elif low.startswith('sitemap:'):
                sm = line.split(':', 1)[1].strip()
                seeds.extend(self._parse_sitemap(sm))
        return seeds

    def _parse_sitemap(self, sitemap_url: str, depth: int = 0) -> List[str]:
        if depth > 2:
            return []
        urls = []
        resp = self._get(sitemap_url)
        if resp is None or resp.status_code >= 400:
            return urls
        locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', resp.text, re.IGNORECASE)
        for loc in locs:
            if loc.lower().endswith('.xml'):
                urls.extend(self._parse_sitemap(loc, depth + 1))
            elif self._same_host(loc):
                urls.append(loc)
        return urls

    # --------------------------------------------------------------------- crawl
    def crawl(self) -> List[Dict[str, Any]]:
        """Run the crawl and return the list of discovered endpoints."""
        start = time.monotonic()
        queue: deque = deque()
        queue.append((self.base_url + '/', 0))

        # Seed from robots.txt + sitemap.xml
        for seed in self._seed_from_robots():
            if self._same_host(seed):
                queue.append((seed, 1))
        for seed in self._parse_sitemap(f"{self.base_url}/sitemap.xml"):
            queue.append((seed, 1))

        pages_fetched = 0
        while queue and pages_fetched < self.max_pages:
            if time.monotonic() - start > self.max_seconds:
                logger.info("Crawl time budget exhausted")
                break

            url, depth = queue.popleft()
            url = url.split('#', 1)[0]
            if url in self._seen_urls or depth > self.max_depth:
                continue
            if not self._same_host(url) or self._skip(url):
                continue
            self._seen_urls.add(url)

            # Record this URL's own path + params as an endpoint.
            path, params = self._path_with_params(url)
            if params:
                self._record(path, params, 'GET')

            resp = self._get(url)
            pages_fetched += 1
            if resp is None or resp.status_code >= 400:
                continue
            ctype = resp.headers.get('Content-Type', '')
            if 'html' not in ctype.lower():
                continue

            parser = _LinkFormParser()
            try:
                parser.feed(resp.text)
            except Exception:
                pass

            # Enqueue discovered links + record parameterized ones.
            for href in parser.links:
                nxt = urljoin(url, href)
                if not nxt.startswith(('http://', 'https://')):
                    continue
                if not self._same_host(nxt) or self._skip(nxt):
                    continue
                npath, nparams = self._path_with_params(nxt)
                if nparams:
                    self._record(npath, nparams, 'GET')
                if nxt not in self._seen_urls:
                    queue.append((nxt, depth + 1))

            # Record forms (these are the highest-value injection targets).
            for form in parser.forms:
                action = urljoin(url, form['action']) if form['action'] else url
                if not self._same_host(action):
                    continue
                fpath, fbase = self._path_with_params(action)
                fields = dict(fbase)
                fields.update(form['fields'])
                if fields:
                    self._record(fpath, fields, form['method'])

        logger.info(f"Crawl done: {pages_fetched} pages, {len(self._endpoints)} parameterized endpoints")
        return list(self._endpoints.values())


def crawl_target(base_url: str, session, **kwargs) -> List[Dict[str, Any]]:
    """Convenience wrapper. Returns discovered endpoints (never raises)."""
    try:
        return Crawler(base_url, session, **kwargs).crawl()
    except Exception as e:
        logger.debug(f"Crawler failed: {e}")
        return []


def build_injection_path(path: str, params: Dict[str, str], inject_param: str,
                         payload: str) -> str:
    """Build a path+query with ``payload`` placed into ``inject_param``.

    Other params keep their discovered/benign values so the request stays valid.
    """
    q = dict(params)
    q[inject_param] = payload
    query = urlencode(q, safe='')
    return f"{path}?{query}" if query else path
