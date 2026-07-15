"""Tests for the bypass re-confirmation pass."""


def test_stable_bypass_is_kept(baselined_scanner):
    # A stable generic delta remains a candidate; repetition is not proof.
    finding = {
        'bypass': True, 'path': '/big', 'method': 'GET', 'headers': {},
        'technique': 'stable', 'severity': 'HIGH', 'reason': 'content diff',
        'verification_status': 'candidate', 'kind': 'suspected',
    }
    baselined_scanner.results = [finding]
    baselined_scanner._reconfirm_bypasses(samples=2)
    assert finding['bypass'] is True
    assert finding['confidence'] == 'medium'
    assert finding['verification_status'] == 'candidate'
    assert finding['confirmations'] == '2/2'


def test_flaky_finding_is_demoted(baselined_scanner):
    # /same returns baseline-identical content, so a (pretend) earlier "bypass"
    # there fails to reproduce and must be demoted.
    finding = {
        'bypass': True, 'path': '/same', 'method': 'GET', 'headers': {},
        'technique': 'flaky', 'severity': 'HIGH', 'reason': 'content diff',
    }
    baselined_scanner.results = [finding]
    baselined_scanner._reconfirm_bypasses(samples=2)
    assert finding['bypass'] is False
    assert finding['confidence'] == 'low'
    assert finding['confirmations'] == '0/2'
    assert 'Unconfirmed' in finding['reason']


def test_recon_findings_with_absolute_url_are_skipped(baselined_scanner):
    finding = {
        'bypass': True, 'path': 'https://elsewhere.example/x', 'method': 'GET',
        'technique': 'recon', 'severity': 'INFO', 'reason': 'dns',
    }
    baselined_scanner.results = [finding]
    baselined_scanner._reconfirm_bypasses(samples=2)
    # Untouched: no replay attempted for off-target absolute URLs.
    assert finding['bypass'] is True
    assert 'confidence' not in finding


def test_reconfirm_replays_bypass_the_cache(baselined_scanner):
    # Prime the cache with a request to /big.
    baselined_scanner._test_request(path='/big')
    cache_size_before = len(baselined_scanner._response_cache)
    finding = {
        'bypass': True, 'path': '/big', 'method': 'GET', 'headers': {},
        'technique': 'stable', 'severity': 'HIGH', 'reason': 'x',
    }
    baselined_scanner.results = [finding]
    baselined_scanner._reconfirm_bypasses(samples=2)
    # Replays must not have written new cache entries (use_cache=False).
    assert len(baselined_scanner._response_cache) == cache_size_before


def test_confirmed_proof_is_demoted_when_replay_only_has_generic_delta(
        baselined_scanner):
    finding = {
        'bypass': True, 'path': '/big', 'method': 'GET', 'headers': {},
        'technique': 'pretend marker proof', 'severity': 'HIGH',
        'reason': 'marker executed', 'verification_status': 'confirmed',
        'kind': 'finding', 'detector_id': 'marker-detector',
        'evidence': [{'type': 'execution_marker', 'matched': 'BT-PROOF'}],
    }
    baselined_scanner.results = [finding]

    baselined_scanner._reconfirm_bypasses(samples=2)

    assert finding['bypass'] is False
    assert finding['verification_status'] == 'unconfirmed'
    assert finding['confirmations'] == '0/2'
