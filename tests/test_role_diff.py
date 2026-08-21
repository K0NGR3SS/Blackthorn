import pytest

from wafpierce.pentest_models import CapturedRequest, IdentityProfile, VerificationState
from wafpierce.role_diff import (
    CredentialMaterial,
    ReplayError,
    ResponseSnapshot,
    RoleMatrixTester,
    render_for_identity,
)


OWNER = IdentityProfile("Alice", "owner", "identity:alice:session", auth_kind="cookie")
OTHER = IdentityProfile("Bob", "user", "identity:bob:session", auth_kind="cookie")
ANON = IdentityProfile("Anonymous", "anonymous", "identity:anon:none", auth_kind="anonymous")


def loader(identity):
    values = {
        OWNER.identity_id: "sid=alice",
        OTHER.identity_id: "sid=bob",
    }
    if identity.auth_kind == "anonymous":
        return CredentialMaterial()
    return CredentialMaterial(headers=(("Cookie", values[identity.identity_id]),))


def test_render_replaces_original_sensitive_headers_with_identity_material():
    request = CapturedRequest(
        "GET", "https://app.example.test/api/orders/7",
        headers=(
            ("Accept", "application/json"),
            ("Cookie", "{{secret:identity:alice:session}}"),
        ),
    )
    rendered = render_for_identity(request, OTHER, loader(OTHER))
    assert ("Cookie", "sid=bob") in rendered.headers
    assert all("alice" not in value for _name, value in rendered.headers)


def test_role_matrix_confirms_explicit_protected_marker_cross_role_access():
    request = CapturedRequest(
        "GET", "https://app.example.test/api/orders/7"
    )

    def transport(rendered):
        if rendered.identity_id == ANON.identity_id:
            return ResponseSnapshot(401, {}, b"login required")
        return ResponseSnapshot(200, {}, b'{"order":7,"owner":"alice","marker":"ORDER-7"}')

    result = RoleMatrixTester(transport, loader).test(
        request,
        [OWNER, OTHER, ANON],
        OWNER.identity_id,
        expected_denied=[OTHER.identity_id, ANON.identity_id],
        protected_markers=["ORDER-7"],
    )
    assert result.verification == VerificationState.CONFIRMED
    assert result.evidence["suspicious_identity_ids"] == [OTHER.identity_id]


def test_role_matrix_keeps_similarity_only_as_candidate():
    request = CapturedRequest("GET", "https://app.example.test/api/orders/7")

    def transport(_rendered):
        return ResponseSnapshot(200, {}, b'{"order":7,"owner":"alice"}')

    result = RoleMatrixTester(transport, loader).test(
        request,
        [OWNER, OTHER],
        OWNER.identity_id,
        expected_denied=[OTHER.identity_id],
    )
    assert result.verification == VerificationState.CANDIDATE


def test_role_matrix_rejects_unknown_expected_identity():
    request = CapturedRequest("GET", "https://app.example.test/api/orders/7")
    with pytest.raises(ReplayError):
        RoleMatrixTester(lambda _request: ResponseSnapshot(200, {}, b"ok"), loader).test(
            request, [OWNER], OWNER.identity_id, expected_denied=["identity:missing"]
        )


def test_role_matrix_rejects_secret_bearing_response_marker():
    request = CapturedRequest("GET", "https://app.example.test/api/orders/7")
    with pytest.raises(ReplayError, match="secret-like"):
        RoleMatrixTester(lambda _request: ResponseSnapshot(200, {}, b"ok"), loader).test(
            request,
            [OWNER, OTHER],
            OWNER.identity_id,
            protected_markers=["access_token=do-not-echo"],
        )
