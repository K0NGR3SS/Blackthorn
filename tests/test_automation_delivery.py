"""Focused tests for secure automation notifications and feed health."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from wafpierce.automation_delivery import (
    DeliverySecurityError,
    DeliveryStateStore,
    DeliveryValidationError,
    DedupePolicy,
    DedupeTracker,
    FeedHealthTracker,
    GenericWebhookAdapter,
    JiraIssueAdapter,
    NotificationDigest,
    NotificationDispatcher,
    NotificationEvent,
    SMTPEmailAdapter,
    SecureHTTPClient,
    SlackWebhookAdapter,
    TeamsWebhookAdapter,
    TransportResponse,
    notification_payload,
    resolve_public_host,
    validate_https_endpoint,
)


PUBLIC_IP = "93.184.216.34"
NOW = datetime(2026, 8, 21, 10, 0, tzinfo=timezone.utc)


def public_resolver(host, port, *args):
    return [(2, 1, 6, "", (PUBLIC_IP, port))]


def private_resolver(host, port, *args):
    return [(2, 1, 6, "", ("127.0.0.1", port))]


def mixed_resolver(host, port, *args):
    return [
        (2, 1, 6, "", (PUBLIC_IP, port)),
        (2, 1, 6, "", ("10.0.0.1", port)),
    ]


def event(severity="high", event_id="evt-1", summary="Patch immediately"):
    return NotificationEvent(
        event_id=event_id,
        kind="exposure_match",
        severity=severity,
        title="CVE-2026-1234 matched an authorized asset",
        summary=summary,
        occurred_at="2026-08-21T09:00:00Z",
        source="cisa_kev",
        subject_id="CVE-2026-1234",
        asset_id="asset-1",
        target="https://app.example.test",
        details={"known_exploited": True, "epss": 0.93},
    )


class FakeHTTPTransport:
    def __init__(self, response=None):
        self.response = response or TransportResponse(204)
        self.calls = []

    def __call__(self, endpoint, method, headers, body, timeout, maximum):
        self.calls.append({
            "endpoint": endpoint,
            "method": method,
            "headers": dict(headers),
            "body": body,
            "timeout": timeout,
            "maximum": maximum,
        })
        return self.response


def http_client(transport=None, maximum=64 * 1024):
    return SecureHTTPClient(
        resolver=public_resolver,
        transport=transport or FakeHTTPTransport(),
        max_response_bytes=maximum,
    )


def test_notification_event_validates_and_redacts_public_details():
    item = NotificationEvent(
        "evt-2",
        "new_signal",
        "critical",
        "Urgent signal",
        "Authorization: Bearer secret-token",
        source="nvd",
        details={"api_token": "must-not-survive", "safe": "keep"},
    )
    blob = json.dumps(item.to_dict())
    assert "secret-token" not in blob
    assert "must-not-survive" not in blob
    assert "<redacted>" in blob
    assert item.details["safe"] == "keep"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"title": "x" * 241},
        {"summary": "x" * 4001},
        {"kind": "Not Valid"},
        {"severity": "urgent"},
        {"occurred_at": "2026-08-21T09:00:00"},
        {"details": {"rows": ["x"] * 101}},
    ],
)
def test_notification_event_rejects_invalid_or_oversized_input(kwargs):
    values = {
        "event_id": "evt-1",
        "kind": "new_signal",
        "severity": "high",
        "title": "Signal",
        "summary": "Summary",
        "occurred_at": "2026-08-21T09:00:00Z",
    }
    values.update(kwargs)
    with pytest.raises(DeliveryValidationError):
        NotificationEvent(**values)


def test_digest_deduplicates_subject_and_keeps_escalation():
    low = event("low", "evt-low")
    critical = event("critical", "evt-critical")
    digest = NotificationDigest.from_events(
        [low, critical],
        digest_id="digest-1",
        title="Daily exploit intelligence",
        period_start="2026-08-20T00:00:00Z",
        period_end="2026-08-21T00:00:00Z",
    )
    assert len(digest.events) == 1
    assert digest.events[0].event_id == "evt-critical"
    assert digest.highest_severity == "critical"
    assert digest.counts == {"critical": 1}
    assert notification_payload(digest)["notification_type"] == "digest"


def test_dedupe_suppresses_repeats_but_delivers_escalations_and_expiry(tmp_path):
    store = DeliveryStateStore(str(tmp_path / "delivery.json"))
    tracker = DedupeTracker(DedupePolicy(dedupe_window_seconds=3600), store)
    initial = event("medium", "evt-medium")
    decision = tracker.decide(initial, now=NOW)
    assert decision.action == "deliver"
    tracker.record_delivery(initial, decision, delivered_at=NOW)

    repeated = tracker.decide(event("medium", "evt-repeat"), now=NOW + timedelta(minutes=20))
    assert repeated.action == "deduplicate"
    escalated = tracker.decide(event("critical", "evt-critical"), now=NOW + timedelta(minutes=21))
    assert escalated.action == "escalate"
    expired = tracker.decide(event("medium", "evt-later"), now=NOW + timedelta(hours=2))
    assert expired.action == "deliver"


def test_dedupe_minimum_severity_filters():
    tracker = DedupeTracker(DedupePolicy(minimum_severity="high"))
    assert tracker.decide(event("medium")).action == "filter"


def test_state_store_persists_only_nonsecret_delivery_metadata(tmp_path):
    path = tmp_path / "state.json"
    store = DeliveryStateStore(str(path))
    fingerprint = event().dedupe_fingerprint()
    store.set_dedupe_record(
        fingerprint,
        event_id="evt-1",
        severity="high",
        delivered_at="2026-08-21T10:00:00Z",
    )
    store.add_history(
        notification_id="evt-1",
        fingerprint=fingerprint,
        kind="exposure_match",
        severity="high",
        adapter="webhook",
        status="sent",
    )
    serialized = path.read_text(encoding="utf-8")
    assert "super-secret" not in serialized
    assert "https://" not in serialized
    assert "Authorization" not in serialized
    assert DeliveryStateStore(str(path)).history()[0]["adapter"] == "webhook"


def test_feed_health_tracks_success_failure_rate_limit_staleness_and_persists(tmp_path):
    store = DeliveryStateStore(str(tmp_path / "health.json"))
    health = FeedHealthTracker(store, stale_after_seconds=3600)
    assert health.get("cisa_kev", now=NOW).status == "never"
    assert health.record_success(
        "cisa_kev", at=NOW, data_timestamp="2026-08-21T09:55:00Z"
    ).status == "healthy"
    degraded = health.record_failure("cisa_kev", error_code="timeout", at=NOW + timedelta(minutes=5))
    assert degraded.status == "degraded"
    assert degraded.last_failure_at
    limited = health.record_rate_limit(
        "cisa_kev", retry_after_seconds=600, at=NOW + timedelta(minutes=6)
    )
    assert limited.status == "rate_limited"
    stale = health.get("cisa_kev", now=NOW + timedelta(hours=2))
    assert stale.status == "stale"
    reloaded = FeedHealthTracker(DeliveryStateStore(str(tmp_path / "health.json")), stale_after_seconds=3600)
    assert reloaded.get("cisa_kev", now=NOW + timedelta(minutes=7)).last_rate_limited_at


def test_feed_health_failure_before_any_success_is_unavailable():
    health = FeedHealthTracker()
    assert health.record_failure("nvd", at=NOW).status == "unavailable"
    with pytest.raises(DeliveryValidationError):
        health.record_rate_limit("nvd", retry_after_seconds=0, at=NOW)


def test_feed_health_uses_data_timestamp_not_only_fetch_time():
    health = FeedHealthTracker(stale_after_seconds=3600)
    status = health.record_success(
        "nvd",
        at=NOW,
        data_timestamp=(NOW - timedelta(hours=2)).isoformat(),
    )
    assert status.status == "stale"
    assert status.freshness_seconds == 7200


@pytest.mark.parametrize(
    "url,error_code",
    [
        ("http://hooks.example.test/path", "https_required"),
        ("https://user:pass@hooks.example.test/path", "url_credentials_forbidden"),
        ("https://127.0.0.1/path", "non_public_destination"),
        ("https://[::1]/path", "non_public_destination"),
        ("https://hooks.example.test/path#fragment", "url_fragment_forbidden"),
    ],
)
def test_https_endpoint_rejects_unsafe_urls(url, error_code):
    with pytest.raises(DeliverySecurityError) as caught:
        validate_https_endpoint(url, resolver=public_resolver)
    assert caught.value.error_code == error_code


def test_dns_answer_fails_closed_when_any_address_is_private():
    with pytest.raises(DeliverySecurityError) as caught:
        resolve_public_host("hooks.example.test", 443, resolver=mixed_resolver)
    assert caught.value.error_code == "non_public_destination"
    with pytest.raises(DeliveryValidationError):
        resolve_public_host("hooks.example.test", 0, resolver=public_resolver)


def test_https_endpoint_accepts_public_resolution_without_exposing_path_in_repr():
    endpoint = validate_https_endpoint(
        "https://hooks.example.test/services/secret-token?sig=also-secret",
        resolver=public_resolver,
    )
    assert endpoint.host == "hooks.example.test"
    assert endpoint.addresses == (PUBLIC_IP,)
    assert "secret-token" not in repr(endpoint)


def test_secure_http_client_disables_redirects_and_bounds_response():
    redirect = FakeHTTPTransport(TransportResponse(302, {"Location": "https://other.test"}))
    client = http_client(redirect)
    with pytest.raises(DeliverySecurityError) as caught:
        client.post_json("https://hooks.example.test/x", {"ok": True})
    assert caught.value.error_code == "redirect_forbidden"

    oversized = FakeHTTPTransport(TransportResponse(200, body=b"x" * 11))
    client = http_client(oversized, maximum=10)
    with pytest.raises(DeliverySecurityError) as caught:
        client.post_json("https://hooks.example.test/x", {"ok": True})
    assert caught.value.error_code == "response_too_large"


def test_secure_http_client_dry_run_validates_but_never_calls_transport():
    transport = FakeHTTPTransport()
    client = http_client(transport)
    assert client.post_json(
        "https://hooks.example.test/path", {"ok": True}, dry_run=True
    ) is None
    assert transport.calls == []
    with pytest.raises(DeliveryValidationError):
        client.post_json("https://hooks.example.test/path", ["not", "a", "mapping"])


@pytest.mark.parametrize(
    "header",
    [
        {"host": "attacker.test"},
        {"content-length": "999"},
        {"Transfer-Encoding": "chunked"},
        {"Connection": "keep-alive"},
        {"Proxy-Authorization": "Basic secret"},
    ],
)
def test_secure_http_client_rejects_reserved_framing_and_routing_headers(header):
    transport = FakeHTTPTransport()
    client = http_client(transport)
    with pytest.raises(DeliverySecurityError) as caught:
        client.post_json(
            "https://hooks.example.test/path",
            {"ok": True},
            headers=header,
        )
    assert caught.value.error_code == "reserved_http_header"
    assert transport.calls == []


def test_generic_webhook_uses_environment_and_injected_transport():
    transport = FakeHTTPTransport(TransportResponse(202))
    adapter = GenericWebhookAdapter(
        environ={"BLACKTHORN_AUTOMATION_WEBHOOK_URL": "https://hooks.example.test/notify"},
        client=http_client(transport),
    )
    result = adapter.deliver(event())
    assert result.success and result.status == "sent"
    call = transport.calls[0]
    assert call["endpoint"].host == "hooks.example.test"
    body = json.loads(call["body"])
    assert body["notification_type"] == "event"
    assert body["event"]["event_id"] == "evt-1"


def test_webhook_missing_environment_fails_without_transport():
    transport = FakeHTTPTransport()
    adapter = GenericWebhookAdapter(environ={}, client=http_client(transport))
    result = adapter.deliver(event())
    assert not result.success
    assert result.error_code == "missing_secret"
    assert transport.calls == []


def test_slack_and_teams_emit_bounded_provider_payloads():
    slack_transport = FakeHTTPTransport()
    slack = SlackWebhookAdapter(
        environ={"BLACKTHORN_SLACK_WEBHOOK_URL": "https://hooks.example.test/slack"},
        client=http_client(slack_transport),
    )
    teams_transport = FakeHTTPTransport()
    teams = TeamsWebhookAdapter(
        environ={"BLACKTHORN_TEAMS_WEBHOOK_URL": "https://hooks.example.test/teams"},
        client=http_client(teams_transport),
    )
    assert slack.deliver(event()).success
    assert teams.deliver(event()).success
    assert "CVE-2026-1234" in json.loads(slack_transport.calls[0]["body"])["text"]
    assert json.loads(teams_transport.calls[0]["body"])["@type"] == "MessageCard"


def test_jira_creates_v3_issue_and_returns_only_safe_remote_id():
    transport = FakeHTTPTransport(TransportResponse(201, body=b'{"key":"SEC-123"}'))
    environment = {
        "BLACKTHORN_JIRA_BASE_URL": "https://tenant.atlassian.example",
        "BLACKTHORN_JIRA_EMAIL": "analyst@example.test",
        "BLACKTHORN_JIRA_API_TOKEN": "jira-super-secret",
        "BLACKTHORN_JIRA_PROJECT_KEY": "SEC",
        "BLACKTHORN_JIRA_ISSUE_TYPE": "Task",
    }
    adapter = JiraIssueAdapter(environ=environment, client=http_client(transport))
    result = adapter.deliver(event())
    assert result.success and result.remote_id == "SEC-123"
    call = transport.calls[0]
    assert call["endpoint"].request_target.endswith("/rest/api/3/issue")
    assert call["headers"]["Authorization"].startswith("Basic ")
    assert b"jira-super-secret" not in call["body"]
    assert "jira-super-secret" not in repr(result)


def test_jira_rejects_credentials_in_base_url_before_transport():
    environment = {
        "BLACKTHORN_JIRA_BASE_URL": "https://user:pass@tenant.example",
        "BLACKTHORN_JIRA_EMAIL": "analyst@example.test",
        "BLACKTHORN_JIRA_API_TOKEN": "token",
        "BLACKTHORN_JIRA_PROJECT_KEY": "SEC",
    }
    transport = FakeHTTPTransport()
    result = JiraIssueAdapter(environ=environment, client=http_client(transport)).deliver(event())
    assert not result.success and result.error_code == "url_credentials_forbidden"
    assert transport.calls == []


def smtp_environment():
    return {
        "BLACKTHORN_SMTP_HOST": "smtp.example.test",
        "BLACKTHORN_SMTP_PORT": "587",
        "BLACKTHORN_SMTP_USERNAME": "analyst@example.test",
        "BLACKTHORN_SMTP_PASSWORD": "smtp-super-secret",
        "BLACKTHORN_SMTP_FROM": "alerts@example.test",
        "BLACKTHORN_SMTP_TO": "team@example.test, owner@example.test",
        "BLACKTHORN_SMTP_SECURITY": "starttls",
    }


def test_smtp_adapter_uses_public_resolution_tls_and_injected_transport():
    calls = []

    def transport(destination, username, password, sender, recipients, message, timeout):
        calls.append((destination, username, password, sender, recipients, message, timeout))

    adapter = SMTPEmailAdapter(
        environ=smtp_environment(),
        resolver=public_resolver,
        transport=transport,
    )
    result = adapter.deliver(event())
    assert result.success and result.status == "sent"
    destination, username, password, sender, recipients, message, _ = calls[0]
    assert destination.addresses == (PUBLIC_IP,)
    assert destination.security == "starttls"
    assert username == "analyst@example.test" and password == "smtp-super-secret"
    assert recipients == ("team@example.test", "owner@example.test")
    assert "smtp-super-secret" not in message.as_string()
    assert "smtp-super-secret" not in repr(result)


def test_smtp_dry_run_never_calls_transport_and_private_destination_fails():
    calls = []
    adapter = SMTPEmailAdapter(
        environ=smtp_environment(),
        resolver=public_resolver,
        transport=lambda *args: calls.append(args),
    )
    assert adapter.deliver(event(), dry_run=True).status == "dry_run"
    assert calls == []

    blocked = SMTPEmailAdapter(environ=smtp_environment(), resolver=private_resolver)
    result = blocked.deliver(event())
    assert not result.success and result.error_code == "non_public_destination"


def test_smtp_rejects_header_injection_and_incomplete_auth():
    environment = smtp_environment()
    environment["BLACKTHORN_SMTP_TO"] = "team@example.test\r\nBcc: attacker@example.test"
    result = SMTPEmailAdapter(environ=environment, resolver=public_resolver).deliver(event(), dry_run=True)
    assert not result.success and result.error_code == "invalid_email"

    environment = smtp_environment()
    environment.pop("BLACKTHORN_SMTP_PASSWORD")
    result = SMTPEmailAdapter(environ=environment, resolver=public_resolver).deliver(event(), dry_run=True)
    assert not result.success and result.error_code == "incomplete_smtp_auth"


def test_dispatcher_records_success_then_suppresses_duplicate(tmp_path):
    path = tmp_path / "dispatch.json"
    store = DeliveryStateStore(str(path))
    transport = FakeHTTPTransport()
    adapter = GenericWebhookAdapter(
        environ={"BLACKTHORN_AUTOMATION_WEBHOOK_URL": "https://hooks.example.test/notify"},
        client=http_client(transport),
    )
    dispatcher = NotificationDispatcher([adapter], store=store)
    first = dispatcher.dispatch_event(event(), now=NOW)
    assert first.delivered
    second = dispatcher.dispatch_event(event(event_id="evt-duplicate"), now=NOW + timedelta(minutes=1))
    assert second.decision.action == "deduplicate"
    assert second.deliveries == ()
    assert len(transport.calls) == 1
    assert [row["status"] for row in store.history()] == ["sent", "skipped"]


def test_dispatcher_dry_run_does_not_consume_dedupe_window():
    transport = FakeHTTPTransport()
    adapter = GenericWebhookAdapter(
        environ={"BLACKTHORN_AUTOMATION_WEBHOOK_URL": "https://hooks.example.test/notify"},
        client=http_client(transport),
    )
    dispatcher = NotificationDispatcher([adapter])
    preview = dispatcher.dispatch_event(event(), dry_run=True, now=NOW)
    assert preview.deliveries[0].status == "dry_run"
    actual = dispatcher.dispatch_event(event(), now=NOW + timedelta(seconds=1))
    assert actual.decision.action == "deliver"
    assert actual.delivered


def test_dispatcher_does_not_record_failed_delivery_for_dedupe():
    failing = FakeHTTPTransport(TransportResponse(500))
    adapter = GenericWebhookAdapter(
        environ={"BLACKTHORN_AUTOMATION_WEBHOOK_URL": "https://hooks.example.test/notify"},
        client=http_client(failing),
    )
    dispatcher = NotificationDispatcher([adapter])
    first = dispatcher.dispatch_event(event(), now=NOW)
    assert not first.delivered
    second = dispatcher.dispatch_event(event(), now=NOW + timedelta(minutes=1))
    assert second.decision.action == "deliver"
