import json
from dataclasses import asdict, replace
from datetime import datetime, timezone

import pytest

from wafpierce.automation_inventory import (
    InventorySnapshot,
    InventoryState,
    InventoryValidationError,
    Mitigation,
    RemediationStatus,
    add_mitigation,
    classify_affected_package,
    compare_semver,
    create_inventory_record,
    create_remediation,
    diff_inventory,
    exception_expired,
    load_inventory_state,
    osv_affected_contains,
    osv_range_contains,
    parse_sbom_bytes,
    remove_mitigation,
    remediation_from_dict,
    save_inventory_state,
    score_risk,
    sla_state,
    transition_remediation,
    update_remediation,
)


NOW = "2026-08-21T12:00:00Z"


def _json_bytes(value):
    return json.dumps(value).encode("utf-8")


def test_cyclonedx_json_import_is_engagement_scoped_and_normalized():
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {
            "type": "application",
            "bom-ref": "portal-app",
            "group": "Acme",
            "name": "Portal",
            "version": "5.1.0",
            "purl": "pkg:pypi/acme-portal@5.1.0",
            "cpe": "cpe:2.3:a:acme:portal:5.1.0:*:*:*:*:*:*:*",
            "supplier": {"name": "<b>Acme</b>"},
        }},
        "components": [{
            "type": "library",
            "bom-ref": "jinja",
            "name": "jinja2",
            "version": "3.1.2",
            "purl": "pkg:pypi/jinja2@3.1.2",
            "components": [{
                "type": "library",
                "name": "markupsafe",
                "version": "2.1.2",
                "purl": "pkg:pypi/markupsafe@2.1.2",
            }],
        }],
    }
    result = parse_sbom_bytes(
        _json_bytes(payload),
        source_name="portal.cdx.json",
        engagement_id=7,
        host="portal.example.test",
        service="https:443",
        criticality="high",
        internet_exposed=True,
        observed_at=NOW,
    )

    assert result.format == "cyclonedx_json"
    assert len(result.records) == 3
    portal = next(row for row in result.records if row.product == "Acme:Portal")
    assert portal.engagement_id == "7"
    assert portal.host == "portal.example.test"
    assert portal.service == "https:443"
    assert portal.version == "5.1.0"
    assert portal.purl == "pkg:pypi/acme-portal@5.1.0"
    assert portal.ecosystem == "pypi"
    assert portal.internet_exposed is True
    assert portal.criticality == "high"
    assert portal.first_seen == NOW and portal.last_seen == NOW
    assert all("<b>" not in item for item in portal.evidence)


def test_inventory_rejects_conflicting_explicit_and_purl_versions():
    with pytest.raises(InventoryValidationError, match="conflicts"):
        create_inventory_record(
            engagement_id="eng:1",
            product="jinja2",
            version="3.1.2",
            purl="pkg:pypi/jinja2@9.9.9",
            observed_at=NOW,
        )


def test_cpe_22_and_23_product_identities_match():
    record = create_inventory_record(
        engagement_id="eng:1",
        product="Portal",
        version="5.1",
        cpe="cpe:/a:acme:portal:5.1",
        observed_at=NOW,
    )
    match = classify_affected_package(record, {
        "package": {},
        "cpe": "cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*",
        "versions": ["5.1"],
    })
    assert match.classification == "exact"


def test_cyclonedx_xml_import_rejects_dtd_and_never_resolves_entities():
    malicious = b'''<?xml version="1.0"?>
    <!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components/></bom>'''
    with pytest.raises(InventoryValidationError, match="DTD/entity"):
        parse_sbom_bytes(
            malicious, source_name="bom.cdx.xml", engagement_id="eng:1"
        )

    valid = b'''<?xml version="1.0"?>
    <bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
      <components>
        <component type="library" bom-ref="requests">
          <name>requests</name><version>2.31.0</version>
          <purl>pkg:pypi/requests@2.31.0</purl>
        </component>
      </components>
    </bom>'''
    result = parse_sbom_bytes(
        valid, source_name="bom.cdx.xml", engagement_id="eng:1", observed_at=NOW
    )
    assert result.format == "cyclonedx_xml"
    assert result.records[0].product == "requests"
    assert result.records[0].version == "2.31.0"


def test_spdx_json_import_reads_purl_cpe_and_bounds_untrusted_identifiers():
    payload = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [{
            "SPDXID": "SPDXRef-Package-spring",
            "name": "spring-framework",
            "versionInfo": "5.3.1",
            "supplier": "Organization: VMware",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:maven/org.springframework/spring-framework@5.3.1",
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": (
                        "cpe:2.3:a:vmware:spring_framework:5.3.1:*:*:*:*:*:*:*"
                    ),
                },
            ],
        }, {
            "SPDXID": "SPDXRef-Package-bad",
            "name": "odd-package",
            "versionInfo": "1",
            "externalRefs": [{
                "referenceType": "purl",
                "referenceLocator": "javascript:alert(1)",
            }],
        }],
    }
    result = parse_sbom_bytes(
        _json_bytes(payload), source_name="software.spdx.json",
        engagement_id="eng:spdx", observed_at=NOW,
    )

    spring = next(row for row in result.records if row.product == "spring-framework")
    assert spring.purl.startswith("pkg:maven/")
    assert spring.cpe.startswith("cpe:2.3:a:vmware")
    odd = next(row for row in result.records if row.product == "odd-package")
    assert odd.purl == ""
    assert result.warnings == ("Ignored an invalid PURL identifier",)


def test_sbom_parser_rejects_wrong_type_duplicate_keys_and_excess_depth():
    with pytest.raises(InventoryValidationError, match="file type"):
        parse_sbom_bytes(
            b"{}", source_name="bom.txt", engagement_id="eng:1"
        )
    duplicate = b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.5"}'
    with pytest.raises(InventoryValidationError, match="duplicate"):
        parse_sbom_bytes(
            duplicate, source_name="bom.json", engagement_id="eng:1"
        )
    nested = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    for _ in range(35):
        nested = {"wrapper": nested}
    with pytest.raises(InventoryValidationError, match="nesting"):
        parse_sbom_bytes(
            _json_bytes(nested), source_name="bom.json", engagement_id="eng:1"
        )


def test_semver_and_osv_range_matching_follow_boundary_semantics():
    assert compare_semver("1.0.0-alpha.1", "1.0.0-alpha.beta") < 0
    assert compare_semver("1.0.0", "1.0.0-rc.1") > 0
    assert compare_semver("1.0.0+build.1", "1.0.0+build.2") == 0
    affected = {
        "versions": ["0.9.9-custom"],
        "ranges": [{
            "type": "SEMVER",
            "events": [
                {"introduced": "1.0.0"}, {"fixed": "1.0.2"},
            ],
        }, {
            "type": "SEMVER",
            "events": [
                {"introduced": "3.0.0"}, {"last_affected": "3.2.5"},
            ],
        }],
    }
    assert osv_affected_contains("0.9.9-custom", affected) is True
    assert osv_affected_contains("1.0.1", affected) is True
    assert osv_affected_contains("1.0.2", affected) is False
    assert osv_affected_contains("3.2.5", affected) is True
    assert osv_affected_contains("3.2.6", affected) is False
    assert osv_range_contains("1.0.0", {
        "type": "SEMVER",
        "events": [{"introduced": "0"}, {"limit": "1.0.0"}],
    }) is False
    assert osv_range_contains("1.0.0", {
        "type": "ECOSYSTEM", "events": [{"introduced": "0"}],
    }) is None


def test_match_classification_is_explainable_and_does_not_guess_versions():
    exact_record = create_inventory_record(
        engagement_id="eng:1", product="jinja2", version="3.1.2",
        purl="pkg:pypi/jinja2@3.1.2", confidence=0.95, observed_at=NOW,
    )
    affected = {
        "package": {"ecosystem": "pypi", "name": "jinja2", "purl": "pkg:pypi/jinja2"},
        "ranges": [{
            "type": "SEMVER",
            "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.3"}],
        }],
    }
    exact = classify_affected_package(
        exact_record, affected, advisory_id="GHSA-abcd-1234-efgh"
    )
    assert exact.classification == "exact"
    assert exact.version_status == "affected"
    assert any("PURL" in reason for reason in exact.reasons)

    fixed = classify_affected_package(
        replace(exact_record, version="3.1.3"), affected
    )
    assert fixed.classification == "not_affected"
    assert fixed.version_status == "not_affected"

    possible = classify_affected_package(exact_record, {
        "package": {"ecosystem": "pypi", "name": "jinja2"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
    })
    assert possible.classification == "possible"
    assert possible.version_status == "unknown"
    assert "without guessing" in possible.reasons[-1]


def test_risk_scoring_uses_all_factors_and_verified_active_mitigations():
    unmitigated = score_risk(
        known_exploited=True,
        epss_score=0.9,
        internet_exposed=True,
        criticality="critical",
        confidence="exact",
        now=NOW,
    )
    mitigated = score_risk(
        known_exploited=True,
        epss_score=0.9,
        internet_exposed=True,
        criticality="critical",
        confidence="likely",
        mitigations=[
            Mitigation("mit:waf", "Verified virtual patch", 0.5, True, "2026-09-01T00:00:00Z"),
            Mitigation("mit:old", "Expired control", 1.0, True, "2026-08-01T00:00:00Z"),
            Mitigation("mit:claim", "Unverified claim", 1.0, False),
        ],
        now=NOW,
    )
    assert unmitigated.score == 92
    assert unmitigated.rating == "critical"
    assert mitigated.score < unmitigated.score
    assert mitigated.contributions["verified_mitigations"] == -20.0
    assert "Verified virtual patch" in mitigated.explanations[-1]
    assert "Expired control" not in mitigated.explanations[-1]


def test_remediation_lifecycle_enforces_retest_owner_sla_and_exception_expiry():
    item = create_remediation(
        engagement_id="eng:1",
        record_id="inventory:1234",
        advisory_id="CVE-2026-12345",
        sla_due="2026-08-25T00:00:00Z",
        at=NOW,
    )
    assert sla_state(item, "2026-08-22T00:00:00Z") == "on_track"
    with pytest.raises(InventoryValidationError, match="owner"):
        transition_remediation(item, RemediationStatus.FIXING, at=NOW)
    fixing = transition_remediation(
        item, "Fixing", owner="security@example.test", at="2026-08-21T13:00:00Z"
    )
    fixing = update_remediation(
        fixing,
        owner="platform-owner@example.test",
        sla_due="2026-08-26T00:00:00Z",
        note="Ownership transferred",
        at="2026-08-21T13:30:00Z",
    )
    assert fixing.status == "Fixing"
    assert fixing.owner == "platform-owner@example.test"
    assert fixing.history[-1].from_status == fixing.history[-1].to_status == "Fixing"
    with pytest.raises(InventoryValidationError, match="not allowed"):
        transition_remediation(fixing, "Resolved", at="2026-08-21T14:00:00Z")
    retest = transition_remediation(fixing, "Retest", at="2026-08-22T00:00:00Z")
    resolved = transition_remediation(retest, "Resolved", at="2026-08-22T01:00:00Z")
    assert resolved.status == "Resolved"
    assert len(resolved.history) == 4

    with pytest.raises(InventoryValidationError, match="exception expiry"):
        transition_remediation(item, "Accepted", owner="risk-owner", at=NOW)
    accepted = transition_remediation(
        item, "Accepted", owner="risk-owner",
        exception_expiry="2026-09-01T00:00:00Z", at=NOW,
    )
    assert exception_expired(accepted, "2026-09-02T00:00:00Z") is True
    with pytest.raises(InventoryValidationError, match="future"):
        update_remediation(
            accepted, exception_expiry="2026-08-01T00:00:00Z", at=NOW
        )


def test_remediation_structured_mitigations_are_validated_scored_and_removable():
    item = create_remediation(
        engagement_id="eng:1", record_id="inventory:1234",
        advisory_id="CVE-2026-12345", at=NOW,
    )
    item = add_mitigation(item, Mitigation(
        "mit:waf", "Verified virtual patch", 0.5, True, "2026-09-01T00:00:00Z"
    ), at="2026-08-21T13:00:00Z")
    assert item.mitigations[0].verified is True
    assessment = score_risk(
        known_exploited=True, epss_score=0.9, internet_exposed=True,
        criticality="high", confidence="exact", mitigations=item.mitigations, now=NOW,
    )
    assert assessment.contributions["verified_mitigations"] == -20.0
    item = remove_mitigation(item, "mit:waf", at="2026-08-21T14:00:00Z")
    assert item.mitigations == ()
    assert "removed" in item.history[-1].note.lower()
    with pytest.raises(InventoryValidationError, match="not found"):
        remove_mitigation(item, "mit:waf", at="2026-08-21T15:00:00Z")


def test_persisted_active_remediation_requires_an_owner():
    item = create_remediation(
        engagement_id="eng:1",
        record_id="inventory:1234",
        advisory_id="CVE-2026-12345",
        at=NOW,
    )
    invalid = replace(item, status=RemediationStatus.FIXING.value)
    with pytest.raises(InventoryValidationError, match="owner"):
        remediation_from_dict(asdict(invalid))


def test_inventory_diff_tracks_hosts_added_removed_and_version_changes():
    old_a = create_inventory_record(
        engagement_id="eng:1", host="a.example", product="portal", version="1.0.0",
        purl="pkg:npm/portal@1.0.0", observed_at="2026-08-20T00:00:00Z",
    )
    new_a = create_inventory_record(
        engagement_id="eng:1", host="a.example", product="portal", version="1.1.0",
        purl="pkg:npm/portal@1.1.0", observed_at=NOW,
    )
    removed = create_inventory_record(
        engagement_id="eng:1", host="old.example", product="old", version="1.0.0",
        observed_at="2026-08-20T00:00:00Z",
    )
    added = create_inventory_record(
        engagement_id="eng:1", host="new.example", product="new", version="2.0.0",
        observed_at=NOW,
    )
    diff = diff_inventory(
        InventorySnapshot("eng:1", "2026-08-20T00:00:00Z", (old_a, removed)),
        InventorySnapshot("eng:1", NOW, (new_a, added)),
        at=NOW,
    )
    assert len(diff.changed) == 1
    assert set(diff.changed[0].fields) >= {"version", "purl"}
    assert len(diff.added) == 1 and len(diff.removed) == 1
    assert {event.event_type for event in diff.events} == {
        "asset_added", "asset_removed", "software_added", "software_removed",
        "software_changed",
    }


def test_atomic_private_state_round_trip_enforces_engagement_scope(tmp_path):
    record = create_inventory_record(
        engagement_id="eng:1", host="portal.example", product="portal", version="1.0.0",
        purl="pkg:npm/portal@1.0.0", observed_at=NOW,
        evidence=["<script>untrusted</script>"],
    )
    remediation = create_remediation(
        engagement_id="eng:1", record_id=record.record_id,
        advisory_id="CVE-2026-12345", at=NOW,
    )
    remediation = add_mitigation(remediation, Mitigation(
        "mit:segment", "Network segmentation", 0.3, True,
        "2026-09-01T00:00:00Z",
    ), at="2026-08-21T13:00:00Z")
    state = InventoryState(
        engagement_id="eng:1",
        snapshot=InventorySnapshot("eng:1", NOW, (record,)),
        remediations=(remediation,),
        saved_at=NOW,
    )
    path = tmp_path / "inventory.json"
    save_inventory_state(str(path), state)
    loaded = load_inventory_state(str(path), expected_engagement_id="eng:1")

    assert loaded.snapshot.records[0].record_id == record.record_id
    assert loaded.remediations[0].advisory_id == "CVE-2026-12345"
    assert loaded.remediations[0].mitigations[0].description == "Network segmentation"
    assert "<script>" not in loaded.snapshot.records[0].evidence[0]
    assert not (tmp_path / "inventory.json.tmp").exists()
    with pytest.raises(InventoryValidationError, match="different engagement"):
        load_inventory_state(str(path), expected_engagement_id="eng:2")
