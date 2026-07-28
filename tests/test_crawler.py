"""Crawler request-shape and origin-boundary tests."""

from wafpierce.crawler import Crawler


class _Response:
    def __init__(self, status_code=200, *, text='', headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def test_authenticated_crawler_does_not_follow_cross_origin_redirect():
    session = _Session([
        _Response(302, headers={'Location': 'https://outside.example/collect'}),
    ])
    crawler = Crawler('https://target.example', session)

    response = crawler._get('https://target.example/start')

    assert response.status_code == 302
    assert [call[0] for call in session.calls] == ['https://target.example/start']
    assert session.calls[0][1]['allow_redirects'] is False


def test_post_form_keeps_action_query_separate_from_body_fields():
    html = """
    <form action="/search?tenant=blue" method="post">
      <input name="query" value="report">
      <textarea name="notes"></textarea>
    </form>
    """
    # robots, sitemap, then the root page.
    session = _Session([
        _Response(404),
        _Response(404),
        _Response(200, text=html, headers={'Content-Type': 'text/html'}),
    ])

    endpoints = Crawler(
        'https://target.example', session, max_pages=1, max_depth=0
    ).crawl()

    assert endpoints == [{
        'path': '/search',
        'params': {'tenant': 'blue'},
        'method': 'POST',
        'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
        'body': 'query=report&notes=test',
        'parameter_location': 'body',
    }]
