from dataclasses import replace

import pytest

import wafpierce.automation_validation as automation_validation
from wafpierce.automation_validation import (
    ApprovalError,
    GlobalKillSwitch,
    KillSwitchEngaged,
    RateLimitError,
    SafeValidationController,
    ScopeRecheckError,
    ValidationSecurityError,
    assert_safe_pipeline,
    build_safe_pipeline,
    create_validation_manifest,
    engagement_scope_recheck,
    match_validator_recipes,
    verify_manifest,
    verify_registry_signature,
)


class Clock:
    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


def _controller(clock=None, *, limit=2):
    clock = clock or Clock()
    return SafeValidationController(
        clock=clock,
        monotonic_clock=clock,
        max_runs_per_target=limit,
        rate_window_seconds=60,
        kill_switch=GlobalKillSwitch(),
    )


def _request_and_approve(controller, clock, target="https://app.example.test/api"):
    manifest = create_validation_manifest(("advisory-observation",))
    request = controller.request_validation(
        target,
        "engagement-7",
        manifest,
        requested_by="analyst",
        now=clock(),
    )
    approval = controller.approve(
        request.request_id,
        approved_by="reviewer",
        now=clock(),
    )
    return request, approval


def test_signed_registry_maps_intelligence_fields_to_safe_recipes():
    assert verify_registry_signature() is True
    signal = {
        "identifier": "CVE-2026-12345",
        "cve_id": "CVE-2026-12345",
        "cwes": ("CWE-79",),
        "known_exploited": True,
    }
    recipes = match_validator_recipes(signal)
    identifiers = {recipe.recipe_id for recipe in recipes}
    assert "advisory-observation" in identifiers
    assert "injection-observation" in identifiers


def test_signed_registry_rejects_a_changed_canonical_hash(monkeypatch):
    monkeypatch.setattr(
        automation_validation,
        "BUILTIN_REGISTRY_HASH",
        "0" * 64,
    )
    assert automation_validation.verify_registry_signature() is False
    with pytest.raises(automation_validation.ManifestVerificationError):
        automation_validation.list_validator_recipes()


def test_manifest_tampering_and_arbitrary_pipeline_fields_fail_closed():
    manifest = create_validation_manifest(("injection-observation",))
    assert verify_manifest(manifest) is True

    changed_stage = replace(manifest.stages[0], safe_mode=False)
    tampered = replace(manifest, stages=(changed_stage, manifest.stages[1]))
    assert verify_manifest(tampered) is False
    with pytest.raises(ValidationSecurityError):
        build_safe_pipeline(tampered)

    pipeline = build_safe_pipeline(manifest)
    assert pipeline["stages"][0] == {
        "id": "http-observation",
        "type": "http_observation",
        "config": {
            "method": "GET",
            "request_budget": 1,
            "max_response_bytes": 256 * 1024,
            "timeout": 10,
            "follow_redirects": False,
        },
    }
    pipeline["stages"][0]["config"]["extra_args"] = "--templates downloaded.yaml"
    with pytest.raises(ValidationSecurityError):
        assert_safe_pipeline(pipeline, manifest)

    pipeline = build_safe_pipeline(manifest)
    pipeline["stages"][0] = {
        "id": "offensive",
        "type": "external_tool",
        "config": {"tool": "nuclei", "extra_args": "-tags exploit"},
    }
    with pytest.raises(ValidationSecurityError):
        assert_safe_pipeline(pipeline, manifest)


def test_scope_is_rechecked_after_approval_and_honors_new_exclusions():
    clock = Clock()
    controller = _controller(clock)
    request, approval = _request_and_approve(controller, clock)
    engagement = {
        "status": "active",
        "scope": ["https://app.example.test/api"],
        "exclusions": [],
    }
    recheck = engagement_scope_recheck(lambda eid: engagement if eid == request.engagement_id else None)

    # Approval was valid under the original engagement, but a later exclusion
    # must stop the run before a pipeline is returned.
    engagement["exclusions"] = ["https://app.example.test/api"]
    with pytest.raises(ScopeRecheckError):
        controller.begin_run(approval.approval_id, scope_recheck=recheck, now=clock())
    assert controller.audit_events()[-1].event_type == "validation_blocked"


def test_expired_approval_is_rejected_before_scope_callback():
    clock = Clock()
    controller = _controller(clock)
    manifest = create_validation_manifest(("server-configuration-observation",))
    request = controller.request_validation(
        "https://app.example.test/",
        "engagement-1",
        manifest,
        requested_by="analyst",
        ttl_seconds=60,
        now=clock(),
    )
    approval = controller.approve(
        request.request_id,
        approved_by="reviewer",
        ttl_seconds=5,
        now=clock(),
    )
    clock.advance(5)
    called = {"value": False}

    def scope_recheck(_request):
        called["value"] = True
        return True

    with pytest.raises(ApprovalError):
        controller.begin_run(
            approval.approval_id,
            scope_recheck=scope_recheck,
            now=clock(),
        )
    assert called["value"] is False


def test_rate_limit_is_per_origin_and_resets_after_window():
    clock = Clock()
    controller = _controller(clock, limit=1)
    _request, approval = _request_and_approve(
        controller, clock, "https://app.example.test/api/a"
    )
    first = controller.begin_run(
        approval.approval_id,
        scope_recheck=lambda _request: True,
        now=clock(),
    )
    controller.complete_run(first.run_id, now=clock())

    # A different path is the same target/origin and cannot evade the limit.
    _request2, approval2 = _request_and_approve(
        controller, clock, "https://app.example.test/api/b"
    )
    with pytest.raises(RateLimitError):
        controller.begin_run(
            approval2.approval_id,
            scope_recheck=lambda _request: True,
            now=clock(),
        )

    clock.advance(60)
    grant = controller.begin_run(
        approval2.approval_id,
        scope_recheck=lambda _request: True,
        now=clock(),
    )
    assert grant.status == "authorized"


def test_approval_is_single_use_even_after_a_run_completes():
    clock = Clock()
    controller = _controller(clock)
    _request, approval = _request_and_approve(controller, clock)
    grant = controller.begin_run(
        approval.approval_id,
        scope_recheck=lambda _request: True,
        now=clock(),
    )
    controller.complete_run(grant.run_id, now=clock())

    with pytest.raises(ApprovalError, match="already been used"):
        controller.begin_run(
            approval.approval_id,
            scope_recheck=lambda _request: True,
            now=clock(),
        )
    assert controller.audit_events()[-1].event_type == "validation_blocked"


def test_global_kill_switch_blocks_new_runs_and_cancels_existing_grants():
    clock = Clock()
    controller = _controller(clock)
    _request, approval = _request_and_approve(controller, clock)
    grant = controller.begin_run(
        approval.approval_id,
        scope_recheck=lambda _request: True,
        now=clock(),
    )
    controller.engage_kill_switch("operator stop")
    assert grant.cancellation.cancelled is True
    with pytest.raises(KillSwitchEngaged):
        grant.build_pipeline()

    with pytest.raises(KillSwitchEngaged):
        controller.begin_run(
            approval.approval_id,
            scope_recheck=lambda _request: True,
            now=clock(),
        )

    controller.reset_kill_switch()
    # Reset allows future approvals, but can never revive an existing grant.
    assert grant.cancellation.cancelled is True


def test_audit_ids_are_deterministic_for_the_same_inputs():
    def event_ids():
        clock = Clock(1234)
        controller = _controller(clock)
        _request_and_approve(controller, clock)
        return [event.event_id for event in controller.audit_events()]

    assert event_ids() == event_ids()
