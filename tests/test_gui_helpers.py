"""Tests for the GUI's pure copy/repeater helpers (no PySide6 needed).

These live at module scope in wafpierce.gui specifically so they can be unit
tested without a display or Qt installed.
"""
import os

from wafpierce.gui import (
    _finding_url, _finding_to_curl, _finding_to_python, _finding_proof_html,
    _advanced_cli_flags, _finding_status_label, _is_candidate_result,
    _engagement_authorizes,
    profile_from_prefs, merge_profile, PROFILE_KEYS,
    _load_prefs, _normalize_language, _save_prefs,
    BANNER_PATH, LOGO_PATH, SIDEBAR_LOGO_PATH,
    LEGAL_ACCEPTANCE_VERSION, SCAN_CATEGORIES_GUI, SCAN_PROFILE_DEFINITIONS,
    legal_acceptance_is_current, parse_scan_phase_event,
    scan_preflight_summary, scan_profile_settings,
)


def test_blackthorn_brand_assets_are_available():
    paths = {BANNER_PATH, LOGO_PATH, SIDEBAR_LOGO_PATH}
    assert len(paths) == 3
    assert all(os.path.isfile(path) for path in paths)


def test_finding_url_prefers_explicit_url():
    assert _finding_url({'url': 'https://x/y'}) == 'https://x/y'


def test_finding_url_builds_from_target_and_path():
    assert _finding_url({'target': 'https://t/', 'path': '/admin'}) == 'https://t/admin'
    assert _finding_url({'path': '/only'}) == '/only'


def test_curl_prefers_recorded_repro():
    f = {'curl': "curl -i 'https://t/a'"}
    assert _finding_to_curl(f) == "curl -i 'https://t/a'"


def test_curl_builds_when_absent():
    f = {'method': 'post', 'url': 'https://t/api', 'headers': {'X-A': '1'}}
    out = _finding_to_curl(f)
    assert out.startswith('curl ')
    assert '-X POST' in out
    assert "-H 'X-A: 1'" in out
    assert "'https://t/api'" in out


def test_python_snippet_is_runnable_shape():
    f = {'method': 'GET', 'url': 'https://t/x', 'headers': {'A': 'b'}, 'data': 'q=1'}
    out = _finding_to_python(f)
    assert 'import requests' in out
    assert "requests.request(" in out
    assert "'GET', 'https://t/x'" in out
    assert "headers={'A': 'b'}" in out
    assert "data='q=1'" in out
    assert 'verify=False' in out
    compile(out, '<snippet>', 'exec')  # must be valid Python


def test_copy_helpers_support_structured_request():
    finding = {'request': {
        'method': 'POST', 'url': 'https://t/api?q=1',
        'headers': {'Content-Type': 'application/json'},
        'body': {'probe': 'blackthorn'},
    }}
    curl = _finding_to_curl(finding)
    python = _finding_to_python(finding)
    assert "https://t/api?q=1" in curl
    assert '--data-raw' in curl and 'blackthorn' in curl
    assert "'POST', 'https://t/api?q=1'" in python
    assert "{'probe': 'blackthorn'}" in python


def test_copy_helpers_do_not_invent_an_unavailable_request():
    finding = {
        'target': 'https://t.example', 'url': 'https://t.example/',
        'request': {'available': False, 'note': 'legacy detector omitted request'},
    }
    assert _finding_url(finding) == ''
    assert 'unavailable' in _finding_to_curl(finding).lower()
    assert 'unavailable' in _finding_to_python(finding).lower()
    proof = _finding_proof_html(finding)
    assert 'legacy detector omitted request' in proof
    assert 'https://t.example/' not in proof


def test_gui_status_distinguishes_candidate_from_confirmed():
    candidate = {'bypass': True, 'verification_status': 'candidate', 'kind': 'suspected'}
    confirmed = {'bypass': True, 'verification_status': 'confirmed', 'kind': 'finding'}
    observation = {'bypass': False, 'verification_status': 'informational',
                   'kind': 'observation'}
    assert _is_candidate_result(candidate)
    assert 'CANDIDATE' in _finding_status_label(candidate)
    assert 'CONFIRMED' in _finding_status_label(confirmed)
    assert 'Observation' in _finding_status_label(observation)


def test_gui_advanced_flags_forward_intrusive_opt_in():
    flags = _advanced_cli_flags({
        'safe_mode': True, 'intrusive': True,
        'scope_include': ['/api'], 'oob': 'off',
    })
    assert '--safe-mode' in flags
    assert '--intrusive' in flags
    assert flags[flags.index('--scope-include') + 1] == '/api'
    assert '--oob' not in flags


def test_gui_engagement_scope_is_fail_closed_and_honors_exclusions():
    scope = ['https://app.example.test/api']
    assert _engagement_authorizes(
        'https://app.example.test/api/users', scope
    )
    assert not _engagement_authorizes(
        'https://app.example.test/admin', scope
    )
    assert not _engagement_authorizes(
        'https://app.example.test/api/logout',
        scope,
        ['https://app.example.test/api/logout'],
    )
    assert not _engagement_authorizes('https://app.example.test/api', [])


def test_task_profiles_only_reference_registered_categories():
    registered = set(SCAN_CATEGORIES_GUI)
    for definition in SCAN_PROFILE_DEFINITIONS.values():
        assert set(definition['categories']) <= registered
        assert definition['intrusive'] is False
        assert definition['reconfirm'] is True

    custom = scan_profile_settings('custom', ['jwt_auth'])
    assert custom['categories'] == ('jwt_auth',)


def test_preflight_summary_exposes_safety_verification_and_authorization():
    summary = scan_preflight_summary(
        ['https://app.example.test'],
        'Authenticated app',
        ['jwt_auth', 'business_logic'],
        {
            'safe_mode': True,
            'no_reconfirm': False,
            'engagement_id': 7,
        },
    )

    assert '1 target' in summary
    assert '2 categories' in summary
    assert 'safe mode' in summary
    assert 're-confirmation on' in summary
    assert 'engagement scope linked' in summary


def test_structured_scan_phase_events_are_strict_and_bounded():
    assert parse_scan_phase_event(
        '::blackthorn-phase::{"label":"Testing selected techniques","progress":45}'
    ) == ('Testing selected techniques', 45)
    assert parse_scan_phase_event(
        '::blackthorn-phase::{"label":"Done","progress":800}'
    ) == ('Done', 100)
    assert parse_scan_phase_event('[*] Testing selected techniques') is None
    assert parse_scan_phase_event('::blackthorn-phase::{broken') is None


def test_legal_acceptance_is_versioned():
    assert legal_acceptance_is_current({
        'legal_accepted_version': LEGAL_ACCEPTANCE_VERSION,
    })
    assert not legal_acceptance_is_current({
        'legal_accepted_version': 'older-copy',
    })


def test_finding_proof_html_renders_structured_evidence_and_escapes_values():
    finding = {
        'verification_status': 'confirmed', 'confidence': 'high',
        'request': {'method': 'POST', 'url': 'https://t/search',
                    'headers': {'X-Probe': '<header>'}, 'body': 'q=<body>'},
        'payload': '<script>alert(1)</script>',
        'insertion_point': {'type': 'query', 'name': 'q'},
        'evidence': [{'type': 'execution_marker', 'description': '<proof>',
                      'matched': 'BT-49', 'excerpt': '<script>BT-49</script>'}],
        'response': {'status': 200, 'size': 88, 'content_type': 'text/html',
                     'headers': {'content-type': 'text/html'},
                     'excerpt': '<script>BT-49</script>'},
        'baseline': {'status': 200, 'size': 50, 'scope': 'matched',
                     'excerpt': '<clean>'},
        'comparison': {'similarity': 0.42, 'size_delta': 38},
        'remediation': 'Encode < and > in output.',
    }
    out = _finding_proof_html(finding)
    for label in ('Verification', 'Confidence', 'Payload', 'Evidence',
                  'Response', 'Matched baseline', 'Comparison', 'Remediation'):
        assert label in out
    assert '<script>' not in out
    assert '&lt;script&gt;' in out
    assert '<proof>' not in out and '&lt;proof&gt;' in out


# -- scan profile export/import ------------------------------------------- #
def test_profile_export_excludes_secrets():
    prefs = {'threads': 20, 'delay': 0.5, 'advanced': {'safe_mode': True},
             'anthropic_api_key': 'sk-SECRET', 'ai_model': 'claude-opus-4-8',
             'font_size': 14, 'language': 'en'}
    prof = profile_from_prefs(prefs)
    assert 'anthropic_api_key' not in prof          # secret never exported
    assert 'font_size' not in prof and 'language' not in prof  # non-scan prefs excluded
    assert prof['threads'] == 20
    assert prof['advanced'] == {'safe_mode': True}
    assert prof['ai_model'] == 'claude-opus-4-8'    # model is fine to share


def test_profile_merge_only_known_keys():
    base = {'threads': 5, 'font_size': 11}
    merged = merge_profile(base, {'threads': 30, 'delay': 1.0, 'bogus': 'x',
                                  'anthropic_api_key': 'sk-LEAK'})
    assert merged['threads'] == 30 and merged['delay'] == 1.0
    assert 'bogus' not in merged
    assert 'anthropic_api_key' not in merged        # not a profile key -> not merged
    assert merged['font_size'] == 11                # untouched


def test_profile_keys_have_no_secret():
    assert 'anthropic_api_key' not in PROFILE_KEYS


def test_language_pref_is_normalized_and_persisted(monkeypatch, tmp_path):
    prefs_path = tmp_path / 'gui_prefs.json'
    monkeypatch.setattr('wafpierce.gui.get_gui_prefs_path', lambda: str(prefs_path))

    _save_prefs({'language': 'en', 'font_size': 13})
    assert _load_prefs()['language'] == 'en'

    _save_prefs({'language': 'uk-UA'})
    assert _load_prefs()['language'] == 'uk'

    _save_prefs({'language': 'not-real'})
    assert _load_prefs()['language'] == 'en'
    assert _normalize_language('ua') == 'uk'
