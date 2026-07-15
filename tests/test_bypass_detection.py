"""Engine-level bypass detection tests against the mock WAF."""


def test_content_diff_is_a_candidate_not_a_confirmed_finding(baselined_scanner):
    # /big differs from the root, but no detector-specific proof exists.
    result = baselined_scanner._test_request(path='/big')
    assert result is not None
    assert result['bypass'] is True
    assert result['severity'] == 'MEDIUM'
    assert result['verification_status'] == 'candidate'
    assert result['kind'] == 'suspected'
    assert result['confidence'] == 'low'


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


def test_header_content_change_is_a_matched_control_candidate(baselined_scanner):
    # X-Bypass:1 changes the response, but a delta alone remains a candidate.
    result = baselined_scanner._test_request(path='/', headers={'X-Bypass': '1'})
    assert result is not None
    assert result['bypass'] is True
    assert result['verification_status'] == 'candidate'
    assert result['kind'] == 'suspected'
    assert result['confidence'] == 'medium'


def test_every_finding_carries_a_curl(baselined_scanner):
    result = baselined_scanner._test_request(path='/big')
    assert result.get('curl', '').startswith('curl ')
    assert '/big' in result['curl']
