"""Engine-level bypass detection tests against the mock WAF."""


def test_content_diff_is_flagged(baselined_scanner):
    # /big returns a much larger body than the baseline -> content-diff bypass.
    result = baselined_scanner._test_request(path='/big')
    assert result is not None
    assert result['bypass'] is True
    assert result['severity'] in ('HIGH', 'CRITICAL')


def test_identical_content_is_not_flagged(baselined_scanner):
    # /same mirrors the baseline body exactly -> not a bypass.
    result = baselined_scanner._test_request(path='/same')
    assert result is not None
    assert result['bypass'] is False


def test_blocked_status_is_not_a_bypass(baselined_scanner):
    result = baselined_scanner._test_request(path='/blocked')
    assert result is not None
    assert result['bypass'] is False
    assert '403' in result['reason']


def test_header_bypass_is_flagged(baselined_scanner):
    # X-Bypass:1 makes any path return the big body -> bypass detected.
    result = baselined_scanner._test_request(path='/', headers={'X-Bypass': '1'})
    assert result is not None
    assert result['bypass'] is True


def test_every_finding_carries_a_curl(baselined_scanner):
    result = baselined_scanner._test_request(path='/big')
    assert result.get('curl', '').startswith('curl ')
    assert '/big' in result['curl']
