"""Tests for Discord/Teams integrations, report redaction, and the authorize gate."""
import json

from wafpierce import integrations, redaction, authorization


SAMPLE = [
    {
        'bypass': True, 'severity': 'HIGH', 'technique': 'X-Forwarded-For',
        'category': 'header_manipulation', 'status': 200, 'reason': 'content diff',
        'path': '/admin',
        'curl': ("curl -i -s -k -H 'Authorization: Bearer sk-secret-TOKEN123' "
                 "-H 'Cookie: session=abc123; csrf=xyz' -b 'sid=deadbeef' "
                 "'https://t/admin?api_key=AKIAEXPOSED&q=1'"),
        'cookies': 'session=abc123; csrf=xyz',
        'bearer': 'sk-secret-TOKEN123',
    },
    {'bypass': False, 'severity': 'INFO', 'technique': 'baseline', 'category': 'recon'},
]


# ----------------------------------------------------------------- integrations
class _FakeResp:
    def __init__(self, code=200):
        self.status_code = code


class _FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        return _FakeResp(200)


def test_discord_payload_and_send():
    payload = integrations.format_discord('https://t', SAMPLE)
    assert 'content' in payload and len(payload['content']) <= 2000
    assert 'Blackthorn investigation' in payload['content']
    sess = _FakeSession()
    assert integrations.send_discord('https://discord/webhook', 'https://t', SAMPLE, session=sess) is True
    assert sess.calls and sess.calls[0][0] == 'https://discord/webhook'


def test_teams_payload_and_send():
    payload = integrations.format_teams('https://t', SAMPLE)
    assert payload['@type'] == 'MessageCard'
    assert payload['sections'][0]['facts']
    sess = _FakeSession()
    assert integrations.send_teams('https://teams/webhook', 'https://t', SAMPLE, session=sess) is True


def test_send_failures_are_swallowed():
    class _Boom:
        def post(self, *a, **k):
            raise RuntimeError('network down')
    assert integrations.send_discord('x', 't', SAMPLE, session=_Boom()) is False
    assert integrations.send_teams('x', 't', SAMPLE, session=_Boom()) is False


# -------------------------------------------------------------------- redaction
def test_redaction_scrubs_secrets():
    red = redaction.redact_findings(SAMPLE)
    blob = json.dumps(red)
    for secret in ('sk-secret-TOKEN123', 'session=abc123', 'deadbeef', 'AKIAEXPOSED'):
        assert secret not in blob, f"{secret} leaked through redaction"
    assert '<redacted>' in blob
    # Non-secret content survives.
    assert red[0]['technique'] == 'X-Forwarded-For'
    assert red[0]['severity'] == 'HIGH'


def test_redaction_does_not_mutate_input():
    before = json.dumps(SAMPLE)
    redaction.redact_findings(SAMPLE)
    assert json.dumps(SAMPLE) == before  # original untouched


def test_redact_text_handles_headers_and_params():
    s = "Authorization: Bearer abc.def.ghi  Cookie: a=1; b=2  token=supersecret"
    out = redaction.redact_text(s)
    assert 'abc.def.ghi' not in out
    assert 'supersecret' not in out
    assert 'a=1; b=2' not in out


def test_redaction_scrubs_structured_oauth_proxy_and_json_secrets():
    finding = {
        'access_token': 'oauth-access-secret',
        'refresh_token': 'oauth-refresh-secret',
        'client_secret': 'client-secret-value',
        'request': {'headers': {
            'Proxy-Authorization': 'Basic proxy-secret',
            'Set-Cookie': 'sid=cookie-secret; HttpOnly',
        }},
        'data': '{"token":"json-token-secret","safe":"keep-me"}',
    }
    blob = json.dumps(redaction.redact_finding(finding))
    for secret in (
        'oauth-access-secret', 'oauth-refresh-secret', 'client-secret-value',
        'proxy-secret', 'cookie-secret', 'json-token-secret',
    ):
        assert secret not in blob
    assert 'keep-me' in blob


# ---------------------------------------------------------------- authorization
def test_authorize_allows_matching_host(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# authorized\n*.example.com\nstaging.test\n", encoding="utf-8")
    patterns = authorization.load_allowlist(str(f))
    assert authorization.is_authorized('https://app.example.com/x', patterns)
    assert authorization.is_authorized('http://staging.test', patterns)


def test_authorize_blocks_nonmatching_and_empty():
    assert authorization.is_authorized('https://evil.com', ['*.example.com']) is False
    # Fail-closed: empty allowlist authorizes nothing.
    assert authorization.is_authorized('https://anything.com', []) is False


def test_authorize_full_url_prefix():
    pats = ['https://api.example.com/v2']
    assert authorization.is_authorized('https://api.example.com/v2/users', pats)
    assert authorization.is_authorized('https://api.example.com/v1/users', pats) is False
