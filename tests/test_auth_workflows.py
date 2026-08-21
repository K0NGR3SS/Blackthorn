from wafpierce.auth_workflows import (
    OAuthFlowObservation,
    analyze_cookie_policy,
    evaluate_login_rotation,
    evaluate_logout_invalidation,
    evaluate_oauth_flow,
    observe_set_cookie_headers,
    plan_timeout_probes,
)
from wafpierce.pentest_models import VerificationState
from wafpierce.role_diff import ResponseSnapshot


KEY = b"test-only-fingerprint-key-value"


def test_cookie_observation_retains_fingerprint_not_secret():
    observed = observe_set_cookie_headers(
        ["sid=super-secret-session; Secure; HttpOnly; SameSite=Lax; Path=/"],
        fingerprint_key=KEY,
    )
    assert observed[0].name == "sid"
    assert observed[0].secure is True
    assert "super-secret-session" not in repr(observed)
    assert analyze_cookie_policy(observed, https_origin=True) == ()


def test_login_rotation_reports_retained_pre_auth_cookie_as_candidate():
    before = observe_set_cookie_headers(["sid=fixed; Secure; HttpOnly"], fingerprint_key=KEY)
    after = observe_set_cookie_headers(["sid=fixed; Secure; HttpOnly"], fingerprint_key=KEY)
    result = evaluate_login_rotation(before, after, authenticated_control_passed=True)
    assert result.verification == VerificationState.CANDIDATE
    assert result.retained_cookie_names == ("sid",)


def test_logout_invalidation_requires_logout_and_protected_controls():
    before = ResponseSnapshot(200, {}, b"account-id: 42 private dashboard")
    after = ResponseSnapshot(200, {}, b"account-id: 42 private dashboard")
    result = evaluate_logout_invalidation(
        before,
        after,
        logout_acknowledged=True,
        protected_markers=("account-id: 42",),
    )
    assert result.verification == VerificationState.CONFIRMED


def test_oauth_analysis_checks_exact_redirect_state_pkce_nonce_and_issuer():
    result = evaluate_oauth_flow(OAuthFlowObservation(
        authorization_endpoint="https://id.example.test/authorize",
        redirect_uri="https://app.example.test/callback.evil",
        registered_redirect_uris=("https://app.example.test/callback",),
        state_sent=True,
        state_matches=False,
        pkce_sent=True,
        pkce_verified=False,
        nonce_sent=True,
        nonce_verified=False,
        response_mode="fragment",
        issuer_matches=False,
    ))
    assert result.verification == VerificationState.CANDIDATE
    assert len(result.issues) == 6


def test_timeout_plan_is_bounded_and_never_executes():
    plan = plan_timeout_probes(expected_idle_timeout_seconds=1800, checkpoints=3)
    assert plan.intervals_seconds == (900, 1800, 2700)
    assert plan.request_count == 3
    assert plan.execution_supported is False


def test_logout_analysis_rejects_secret_bearing_markers():
    snapshot = ResponseSnapshot(200, {}, b"ok")
    import pytest

    with pytest.raises(ValueError, match="secret-like"):
        evaluate_logout_invalidation(
            snapshot,
            snapshot,
            logout_acknowledged=True,
            protected_markers=("access_token=do-not-echo",),
        )
