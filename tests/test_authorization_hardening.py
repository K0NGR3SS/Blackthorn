"""Focused regression tests for the active-scan authorization gate."""

import pytest

from wafpierce.authorization import is_authorized


@pytest.mark.parametrize('target', [
    'https://api.example.com/v2',
    'https://api.example.com/v2/',
    'https://api.example.com/v2/users',
    'https://api.example.com:443/v2/users?active=true',
])
def test_full_url_scope_accepts_same_origin_path_children(target):
    assert is_authorized(target, ['https://api.example.com/v2'])


@pytest.mark.parametrize('target', [
    'http://api.example.com/v2',              # different scheme
    'https://api.example.com:444/v2',         # different effective port
    'https://api.example.com.evil/v2',        # hostname suffix confusion
    'https://api.example.com/v20',            # partial path segment
    'https://api.example.com/v2-preview',     # partial path segment
    'https://api.example.com/v2%2fadmin',     # encoded separator ambiguity
    'https://api.example.com/v2/../admin',    # dot-segment ambiguity
])
def test_full_url_scope_rejects_component_and_boundary_mismatches(target):
    assert not is_authorized(target, ['https://api.example.com/v2'])


def test_full_url_scope_compares_effective_default_ports():
    assert is_authorized(
        'https://api.example.com:443/v2/users',
        ['https://api.example.com/v2'],
    )
    assert is_authorized(
        'https://api.example.com/v2/users',
        ['https://api.example.com:443/v2'],
    )
    assert not is_authorized(
        'https://api.example.com:8443/v2/users',
        ['https://api.example.com/v2'],
    )


@pytest.mark.parametrize('target', [
    'https://api.example.com@evil.example/v2',
    'https://user@api.example.com/v2',
    'https://user:secret@api.example.com/v2',
])
def test_targets_with_userinfo_are_never_authorized(target):
    assert not is_authorized(
        target,
        ['api.example.com', 'evil.example', 'https://api.example.com/v2'],
    )


def test_full_url_allow_entry_with_userinfo_is_rejected():
    assert not is_authorized(
        'https://evil.example/v2',
        ['https://api.example.com@evil.example/v2'],
    )


@pytest.mark.parametrize('target', [
    'https://bad..example.com/',
    'https://-bad.example.com/',
    'https://bad-.example.com/',
    'https://bad_name.example.com/',
    'https://999.0.0.1/',
    'https://example.com:99999/',
    'https://example.com:0/',
])
def test_malformed_or_ambiguous_target_hosts_fail_closed(target):
    assert not is_authorized(target, ['*', '*.example.com', 'example.com'])


def test_host_globs_remain_anchored_and_supported():
    patterns = ['*.example.com']
    assert is_authorized('https://app.example.com/path', patterns)
    assert is_authorized('https://deep.app.example.com/path', patterns)
    assert not is_authorized('https://example.com/path', patterns)
    assert not is_authorized('https://app.example.com.evil/path', patterns)


def test_full_url_scope_supports_a_glob_hostname():
    patterns = ['https://*.example.com/v2']
    assert is_authorized('https://api.example.com/v2/users', patterns)
    assert not is_authorized('https://example.com/v2/users', patterns)
    assert not is_authorized('https://api.example.com.evil/v2/users', patterns)


def test_valid_ip_literals_are_compared_as_hosts():
    assert is_authorized('https://[2001:db8::1]/v2', ['https://[2001:db8::1]/v2'])
    assert is_authorized('http://192.0.2.10/path', ['192.0.2.10'])
