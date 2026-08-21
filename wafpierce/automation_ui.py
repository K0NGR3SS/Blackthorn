"""PySide6 Automation workspace for passive exploit intelligence.

The page intentionally keeps feed collection and target validation separate:
rules may create alerts or approval-queue items, but only an operator can open
the scope-enforced safe validation recipe.
"""
from __future__ import annotations

import hashlib
import getpass
import ipaddress
import json
import os
import queue
import re
import threading
import uuid
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from PySide6 import QtCore, QtWidgets

from .automation_delivery import (
    DeliveryError,
    DeliveryStateStore,
    DedupePolicy,
    DedupeTracker,
    FeedHealthTracker,
    GenericWebhookAdapter,
    JiraIssueAdapter,
    NotificationDigest,
    NotificationDispatcher,
    NotificationEvent,
    SMTPEmailAdapter,
    SlackWebhookAdapter,
    TeamsWebhookAdapter,
)
from .config import ensure_config_dir
from .automation_inventory import (
    InventoryRecord,
    InventorySnapshot,
    InventoryState,
    InventoryValidationError,
    Mitigation,
    RemediationItem,
    RemediationStatus,
    add_mitigation,
    create_inventory_record,
    create_remediation,
    diff_inventory,
    exception_expired,
    import_sbom,
    load_inventory_state,
    merge_inventory_records,
    save_inventory_state,
    score_risk,
    sla_state,
    transition_remediation,
    update_remediation,
)
from .automation_validation import (
    SafeValidationController,
    ValidationSecurityError,
    assert_safe_pipeline,
    build_safe_pipeline,
    create_validation_manifest,
    engagement_scope_recheck,
    match_validator_recipes,
)
from .exploit_intelligence import (
    AutomationRule,
    AuthorizedTechnologyAsset,
    ExploitSignal,
    ExposureMatch,
    PackageInventoryItem,
    deduplicate_signals,
    evaluate_rules,
    exposure_match_from_dict,
    load_automation_state,
    match_authorized_assets,
    refresh_intelligence,
    rule_from_dict,
    save_automation_state,
    signal_from_dict,
)


AUTOMATION_STATE_FILENAME = "automation-intelligence.json"
AUTOMATION_INVENTORY_PREFIX = "automation-inventory"
AUTOMATION_DELIVERY_FILENAME = "automation-delivery.json"

_VERSION_SUFFIX_RE = re.compile(
    r"^(.*?)(?:\s+|/|@|:v?)(v?[0-9]+(?:\.[0-9A-Za-z_-]+){0,6})$",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_text(value: Any, maximum: int = 2048) -> str:
    text = str(value or "").replace("\x00", "")
    text = "".join(ch if ch in "\t\r\n" or ord(ch) >= 32 else " " for ch in text)
    return " ".join(text.split())[:maximum]


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(_bounded_text(part, 2048).casefold() for part in parts)
    digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _active_engagement(host: Any) -> Tuple[Optional[dict], str]:
    engagement_id = (
        getattr(host, "_current_engagement_id", None)
        or getattr(host, "_prefs", {}).get("current_engagement_id")
    )
    database = getattr(host, "_db", None)
    if not engagement_id or database is None:
        return None, "Select an active engagement before matching or validating assets."
    try:
        engagement = database.get_engagement(int(engagement_id))
    except Exception:
        engagement = None
    if not engagement:
        return None, "The selected engagement is unavailable."
    if str(engagement.get("status") or "active").lower() != "active":
        return None, "The selected engagement is not active."
    if not engagement.get("scope"):
        return None, "The selected engagement has no authorized scope."
    return engagement, ""


def _scope_allows(target: str, engagement: Mapping[str, Any]) -> bool:
    from .authorization import is_authorized

    value = _bounded_text(target, 2048)
    if not value or not is_authorized(value, list(engagement.get("scope") or [])):
        return False
    return not is_authorized(value, list(engagement.get("exclusions") or []))


_TECH_KEYS = {
    "cms", "framework", "platform", "product", "products", "server",
    "service", "services", "tech", "technologies", "technology", "version",
}


def _technology_fragments(value: Any, *, depth: int = 0) -> List[str]:
    if depth > 3:
        return []
    if isinstance(value, Mapping):
        output: List[str] = []
        for key, item in value.items():
            if str(key).lower() in _TECH_KEYS:
                output.extend(_technology_fragments(item, depth=depth + 1))
            elif str(key).lower() in {"details", "discovery", "metadata"}:
                output.extend(_technology_fragments(item, depth=depth + 1))
        return output
    if isinstance(value, (list, tuple, set)):
        output = []
        for item in list(value)[:100]:
            output.extend(_technology_fragments(item, depth=depth + 1))
        return output
    text = _bounded_text(value, 256)
    return [text] if text else []


def _host_key(value: str) -> str:
    text = _bounded_text(value, 2048)
    try:
        parsed = urlsplit(text if "://" in text else "//" + text)
        return (parsed.hostname or text).lower().rstrip(".")
    except ValueError:
        return text.lower().rstrip(".")


def _package_item(
    value: Any, *, asset_id: str, authorized: bool,
) -> Optional[PackageInventoryItem]:
    if not isinstance(value, Mapping):
        return None
    name = _bounded_text(value.get("name") or value.get("package"), 256)
    version = _bounded_text(value.get("version"), 128)
    ecosystem = _bounded_text(value.get("ecosystem"), 128)
    purl = _bounded_text(value.get("purl"), 1024)
    if not (name and version and ecosystem):
        return None
    return PackageInventoryItem(
        asset_id=asset_id,
        name=name,
        version=version,
        ecosystem=ecosystem,
        authorized=authorized,
        purl=purl,
    )


def _split_product_version(value: Any) -> Tuple[str, str]:
    """Split a discovered technology label without inventing a version."""
    text = _bounded_text(value, 512)
    match = _VERSION_SUFFIX_RE.fullmatch(text)
    if not match or not match.group(1).strip():
        return text, ""
    product = match.group(1).strip(" /:@")
    version = match.group(2).lstrip("vV")
    return product or text, version


def _looks_internet_exposed(target: Any) -> bool:
    """Conservatively identify an explicitly addressed public HTTP(S) asset."""
    text = _bounded_text(target, 2048)
    try:
        parsed = urlsplit(text)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in {"localhost"} or hostname.endswith(
        (".local", ".localhost", ".internal", ".invalid", ".test")
    ):
        return False
    try:
        return ipaddress.ip_address(hostname).is_global
    except ValueError:
        # A scoped DNS name with an explicit HTTP(S) origin is the best evidence
        # available without performing an unapproved DNS/network lookup.
        return True


def collect_authorized_inventory(
    host: Any,
) -> Tuple[Optional[dict], List[AuthorizedTechnologyAsset], List[PackageInventoryItem]]:
    """Collect only technology evidence that is in the current engagement scope."""
    engagement, _reason = _active_engagement(host)
    if engagement is None:
        return None, [], []

    records: Dict[str, Dict[str, Any]] = {}

    def add_asset(target: Any, technology: Iterable[Any], packages: Iterable[Any] = ()):
        name = _bounded_text(target, 2048)
        if not name or not _scope_allows(name, engagement):
            return
        marker = _host_key(name) or name.casefold()
        record = records.setdefault(marker, {
            "name": name,
            "technology": [],
            "packages": [],
        })
        for item in technology:
            text = _bounded_text(item, 256)
            if text and text.casefold() not in {
                existing.casefold() for existing in record["technology"]
            }:
                record["technology"].append(text)
        record["packages"].extend(list(packages)[:100])

    recon_state = getattr(host, "_recon_state", {}) or {}
    report = recon_state.get("report") if isinstance(recon_state, Mapping) else None
    report = report if isinstance(report, Mapping) else {}
    stages = report.get("stages") if isinstance(report.get("stages"), Mapping) else {}
    http_technology: Dict[str, List[str]] = {}
    for row in stages.get("http") or ():
        if not isinstance(row, Mapping):
            continue
        marker = _host_key(row.get("url") or row.get("host") or "")
        http_technology.setdefault(marker, []).extend(_technology_fragments(row))
    for row in stages.get("hosts") or ():
        if not isinstance(row, Mapping):
            continue
        target = row.get("http_url") or row.get("hostname") or row.get("host")
        tech = _technology_fragments(row)
        tech.extend(http_technology.get(_host_key(str(target or "")), []))
        add_asset(target, tech)

    for finding in list(getattr(host, "_results", []) or [])[:10000]:
        if not isinstance(finding, Mapping):
            continue
        request = finding.get("request") if isinstance(finding.get("request"), Mapping) else {}
        target = (
            request.get("url") or finding.get("url")
            or finding.get("request_url") or finding.get("target")
        )
        package_rows: List[Any] = []
        for key in ("package", "packages", "dependency", "dependencies"):
            item = finding.get(key)
            if isinstance(item, list):
                package_rows.extend(item[:100])
            elif item:
                package_rows.append(item)
        details = finding.get("details")
        if isinstance(details, Mapping):
            for key in ("package", "packages", "dependency", "dependencies"):
                item = details.get(key)
                if isinstance(item, list):
                    package_rows.extend(item[:100])
                elif item:
                    package_rows.append(item)
        add_asset(target, _technology_fragments(finding), package_rows)

    assets: List[AuthorizedTechnologyAsset] = []
    packages: List[PackageInventoryItem] = []
    seen_packages = set()
    for record in records.values():
        asset_id = _stable_id("asset", record["name"])
        asset_packages: List[PackageInventoryItem] = []
        for package in record["packages"]:
            item = _package_item(package, asset_id=asset_id, authorized=True)
            if item is None:
                continue
            key = (item.asset_id, item.ecosystem.casefold(), item.name.casefold(), item.version)
            if key in seen_packages:
                continue
            seen_packages.add(key)
            asset_packages.append(item)
        package_technology = [
            f"{item.ecosystem} {item.name} {item.version}"
            for item in asset_packages
        ]
        technology = "; ".join(
            (record["technology"] + package_technology)[:100]
        )
        if technology:
            assets.append(AuthorizedTechnologyAsset(
                asset_id=asset_id,
                name=record["name"],
                technology_text=technology,
                authorized=True,
            ))
        packages.extend(asset_packages)
    return engagement, assets, packages


def _default_rules() -> List[AutomationRule]:
    return [
        AutomationRule(
            rule_id="rule:kev-match",
            name="Queue known-exploited matches",
            action="queue_safe_validation",
            event="exposure_match",
            require_known_exploited=True,
            require_asset_match=True,
        ),
        AutomationRule(
            rule_id="rule:high-epss",
            name="Request approval for high-EPSS matches",
            action="request_approval",
            event="exposure_match",
            min_severity="high",
            min_epss=0.65,
            require_asset_match=True,
        ),
        AutomationRule(
            rule_id="rule:critical-alert",
            name="Alert on critical exposure matches",
            action="alert",
            event="exposure_match",
            min_severity="critical",
            require_asset_match=True,
        ),
    ]


class AutomationPageController:
    def __init__(self, host: Any, save_prefs=None) -> None:
        self.host = host
        self.save_prefs = save_prefs
        self.path = os.path.join(ensure_config_dir(), AUTOMATION_STATE_FILENAME)
        self.signals: List[ExploitSignal] = []
        self.rules: List[AutomationRule] = []
        self.queue: List[dict] = []
        self.history: List[dict] = []
        self.source_status: Dict[str, str] = {}
        self.matches: List[ExposureMatch] = []
        self.direct_matches: List[ExposureMatch] = []
        self.assets: Dict[str, AuthorizedTechnologyAsset] = {}
        self.inventory_state: Optional[InventoryState] = None
        self.inventory_records: List[InventoryRecord] = []
        self.remediations: List[RemediationItem] = []
        self.inventory_engagement_id = ""
        self.match_context: Dict[str, dict] = {}
        self._known_match_keys: set = set()
        self.validation_controller = SafeValidationController()
        self._validation_grants: Dict[str, Any] = {}
        self._validation_workers: Dict[str, Any] = {}
        self._validation_timers: Dict[str, QtCore.QTimer] = {}
        self.delivery_store = DeliveryStateStore(os.path.join(
            ensure_config_dir(), AUTOMATION_DELIVERY_FILENAME
        ))
        self.feed_health = FeedHealthTracker(self.delivery_store)
        self.notification_events: List[NotificationEvent] = []
        self._delivery_events: queue.Queue = queue.Queue()
        self._delivery_active = 0
        self._known_match_state: Dict[Tuple[str, str], str] = {}
        self._match_state_initialized = False
        self.failures: List[str] = []
        self.refreshing = False
        self._refresh_events: queue.Queue = queue.Queue()
        self._load_state()
        self._ensure_inventory_context(sync_discovered=True)
        self.page = self._build_page()
        self._recompute_matches(run_rules=False)
        self._populate_all()
        self._apply_watch_schedule()

    # ---- state ---------------------------------------------------------
    def _settings(self) -> dict:
        prefs = getattr(self.host, "_prefs", {}) or {}
        raw_channels = prefs.get("automation_notification_channels", [])
        if isinstance(raw_channels, str):
            raw_channels = raw_channels.split(",")
        channels = tuple(
            value for value in (
                _bounded_text(item, 32).lower() for item in raw_channels
            )
            if value in {"webhook", "slack", "teams", "jira", "smtp"}
        )
        minimum = _bounded_text(
            prefs.get("automation_notification_min_severity", "high"), 16
        ).lower()
        if minimum not in {"info", "low", "medium", "high", "critical"}:
            minimum = "high"
        def strict_true(key: str) -> bool:
            return prefs.get(key, False) is True
        return {
            "paused": strict_true("automation_paused"),
            "watch_enabled": strict_true("automation_watch_enabled"),
            "watch_minutes": max(15, min(int(prefs.get("automation_watch_minutes", 60)), 1440)),
            "days": max(1, min(int(prefs.get("automation_feed_days", 7)), 120)),
            "notifications_enabled": strict_true(
                "automation_notifications_enabled"
            ),
            "notification_channels": channels,
            "notification_min_severity": minimum,
            "digest_enabled": strict_true("automation_digest_enabled"),
            "digest_hours": max(
                1, min(int(prefs.get("automation_digest_hours", 24)), 168)
            ),
            "last_digest_at": _bounded_text(
                prefs.get("automation_last_digest_at", ""), 64
            ),
        }

    def _save_settings(self, **updates: Any) -> None:
        prefs = getattr(self.host, "_prefs", {})
        prefs.update(updates)
        self.host._prefs = prefs
        if callable(self.save_prefs):
            try:
                self.save_prefs(prefs)
            except Exception:
                pass

    def _load_state(self) -> None:
        if not os.path.exists(self.path):
            self.rules = _default_rules()
            return
        try:
            state = load_automation_state(self.path)
        except ValueError:
            self.rules = _default_rules()
            return
        for row in state.get("signals") or ():
            try:
                self.signals.append(signal_from_dict(row))
            except (TypeError, ValueError):
                continue
        for row in state.get("rules") or ():
            try:
                self.rules.append(rule_from_dict(row))
            except (TypeError, ValueError, OverflowError):
                continue
        if not self.rules:
            self.rules = _default_rules()
        self.queue = [dict(item) for item in state.get("queue") or () if isinstance(item, Mapping)]
        self.history = [dict(item) for item in state.get("history") or () if isinstance(item, Mapping)]
        for row in state.get("direct_matches") or ():
            try:
                self.direct_matches.append(exposure_match_from_dict(row))
            except (TypeError, ValueError):
                continue
        self.source_status = {
            _bounded_text(key, 64): _bounded_text(value, 128)
            for key, value in dict(state.get("source_status") or {}).items()
        }

    def _save_state(self) -> None:
        try:
            save_automation_state(
                self.path,
                signals=self.signals,
                rules=self.rules,
                queue=self.queue,
                history=self.history,
                source_status=self.source_status,
                direct_matches=self.direct_matches,
            )
        except (OSError, ValueError) as exc:
            if hasattr(self, "status_label"):
                self.status_label.setText(f"State could not be saved: {_bounded_text(exc, 256)}")
        self._persist_inventory()

    def _inventory_path(self, engagement_id: str) -> str:
        marker = hashlib.sha256(
            str(engagement_id).encode("utf-8", "replace")
        ).hexdigest()[:20]
        return os.path.join(
            ensure_config_dir(), f"{AUTOMATION_INVENTORY_PREFIX}-{marker}.json"
        )

    def _blank_inventory_state(self, engagement_id: str) -> InventoryState:
        observed = _utc_now()
        return InventoryState(
            engagement_id=engagement_id,
            snapshot=InventorySnapshot(engagement_id, observed, ()),
        )

    def _ensure_inventory_context(
        self, *, sync_discovered: bool = False,
    ) -> Optional[dict]:
        engagement, _reason = _active_engagement(self.host)
        if engagement is None:
            self._persist_inventory()
            self.inventory_engagement_id = ""
            self.inventory_state = None
            self.inventory_records = []
            self.remediations = []
            return None
        engagement_id = _bounded_text(engagement.get("id"), 128)
        if not engagement_id:
            return None
        if engagement_id != self.inventory_engagement_id or self.inventory_state is None:
            self._persist_inventory()
            path = self._inventory_path(engagement_id)
            try:
                state = load_inventory_state(
                    path, expected_engagement_id=engagement_id
                ) if os.path.exists(path) else self._blank_inventory_state(engagement_id)
            except InventoryValidationError:
                state = self._blank_inventory_state(engagement_id)
            self.inventory_engagement_id = engagement_id
            self.inventory_state = state
            self.inventory_records = list(state.snapshot.records)
            self.remediations = list(state.remediations)
        if sync_discovered:
            self._sync_discovered_inventory(record_changes=False)
        return engagement

    def _persist_inventory(self) -> None:
        if not self.inventory_state or not self.inventory_engagement_id:
            return
        state = InventoryState(
            engagement_id=self.inventory_engagement_id,
            snapshot=InventorySnapshot(
                self.inventory_engagement_id,
                _utc_now(),
                tuple(self.inventory_records),
            ),
            remediations=tuple(self.remediations),
            change_events=self.inventory_state.change_events,
        )
        try:
            save_inventory_state(
                self._inventory_path(self.inventory_engagement_id), state
            )
            self.inventory_state = state
        except (OSError, InventoryValidationError) as exc:
            if hasattr(self, "status_label"):
                self.status_label.setText(
                    f"Inventory could not be saved: {_bounded_text(exc, 256)}"
                )

    def _discovered_inventory_records(self) -> List[InventoryRecord]:
        engagement, assets, packages = collect_authorized_inventory(self.host)
        if engagement is None:
            return []
        engagement_id = _bounded_text(engagement.get("id"), 128)
        asset_names = {asset.asset_id: asset.name for asset in assets}
        records: List[InventoryRecord] = []
        for asset in assets:
            for fragment in asset.technology_text.split(";")[:100]:
                product, version = _split_product_version(fragment)
                if not product:
                    continue
                try:
                    records.append(create_inventory_record(
                        engagement_id=engagement_id,
                        host=asset.name,
                        service="web",
                        product=product,
                        version=version,
                        evidence=(fragment,),
                        confidence=0.65 if version else 0.5,
                        internet_exposed=_looks_internet_exposed(asset.name),
                        source="discovery",
                    ))
                except InventoryValidationError:
                    continue
        for package in packages:
            host = asset_names.get(package.asset_id, package.asset_id)
            try:
                records.append(create_inventory_record(
                    engagement_id=engagement_id,
                    host=host,
                    service="application",
                    product=package.name,
                    version=package.version,
                    purl=package.purl,
                    ecosystem=package.ecosystem,
                    evidence=(
                        f"Observed {package.ecosystem} package "
                        f"{package.name} {package.version}",
                    ),
                    confidence=0.9,
                    internet_exposed=_looks_internet_exposed(host),
                    source="scan_finding",
                ))
            except InventoryValidationError:
                continue
        return merge_inventory_records(records)

    def _sync_discovered_inventory(
        self, *, record_changes: bool = True,
    ) -> Tuple[int, Tuple[Any, ...]]:
        if self.inventory_state is None:
            return 0, ()
        discovered = self._discovered_inventory_records()
        if not discovered:
            return 0, ()
        previous = InventorySnapshot(
            self.inventory_engagement_id,
            self.inventory_state.snapshot.observed_at or _utc_now(),
            tuple(self.inventory_records),
        )
        retained = [
            row for row in self.inventory_records
            if row.source not in {"discovery", "scan_finding"}
        ]
        merged = merge_inventory_records(retained + discovered)
        current = InventorySnapshot(
            self.inventory_engagement_id, _utc_now(), tuple(merged)
        )
        difference = diff_inventory(previous, current)
        events = self.inventory_state.change_events
        if record_changes:
            events = tuple(list(events)[-19000:] + list(difference.events))
        self.inventory_records = merged
        self.inventory_state = InventoryState(
            engagement_id=self.inventory_engagement_id,
            snapshot=current,
            remediations=tuple(self.remediations),
            change_events=events,
        )
        self._persist_inventory()
        return len(discovered), difference.events if record_changes else ()

    def _authorized_inventory(
        self,
    ) -> Tuple[Optional[dict], List[AuthorizedTechnologyAsset], List[PackageInventoryItem]]:
        engagement = self._ensure_inventory_context()
        if engagement is None:
            return None, [], []
        assets: List[AuthorizedTechnologyAsset] = []
        packages: List[PackageInventoryItem] = []
        for record in self.inventory_records:
            target = record.host
            if not target or not _scope_allows(target, engagement):
                continue
            technology = " ".join(filter(None, (
                record.product, record.version, record.cpe, record.purl,
            )))
            assets.append(AuthorizedTechnologyAsset(
                asset_id=record.record_id,
                name=target,
                technology_text=technology,
                authorized=True,
            ))
            if record.version and record.ecosystem:
                packages.append(PackageInventoryItem(
                    asset_id=record.record_id,
                    name=record.product,
                    version=record.version,
                    ecosystem=record.ecosystem,
                    authorized=True,
                    purl=record.purl,
                ))
        return engagement, assets, packages

    def _history_event(
        self, event: str, *, target: str = "", advisory: str = "",
        detail: str = "", decision_id: str = "",
    ) -> None:
        engagement_id = self.inventory_engagement_id or _bounded_text(
            getattr(self.host, "_prefs", {}).get("current_engagement_id"), 128
        )
        self.history.insert(0, {
            "id": "history:" + uuid.uuid4().hex,
            "timestamp": _utc_now(),
            "event": _bounded_text(event, 128),
            "target": _bounded_text(target, 2048),
            "advisory": _bounded_text(advisory, 128),
            "detail": _bounded_text(detail, 2048),
            "decision_id": _bounded_text(decision_id, 128),
            "engagement_id": engagement_id,
        })
        del self.history[5000:]

    # ---- page construction -------------------------------------------
    def _build_page(self):
        page = QtWidgets.QWidget()
        page.setObjectName("AutomationPage")
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        heading = QtWidgets.QHBoxLayout()
        title_box = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("Automation")
        title.setObjectName("PageTitle")
        subtitle = QtWidgets.QLabel(
            "Monitor public exploit intelligence, correlate it with authorized "
            "assets, and queue safe validation for explicit approval."
        )
        subtitle.setWordWrap(True)
        subtitle.setObjectName("FieldLabel")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        heading.addLayout(title_box, 1)
        self.pause_button = QtWidgets.QPushButton()
        self.pause_button.setCheckable(True)
        self.pause_button.setChecked(self._settings()["paused"])
        self.pause_button.clicked.connect(self._toggle_pause)
        heading.addWidget(self.pause_button)
        layout.addLayout(heading)

        self.metric_labels: Dict[str, QtWidgets.QLabel] = {}
        metrics = QtWidgets.QHBoxLayout()
        for key, label in (
            ("signals", "Exploit signals"),
            ("kev", "Known exploited"),
            ("matches", "Potential matches"),
            ("queue", "Awaiting approval"),
            ("remediation", "Open remediation"),
        ):
            box = QtWidgets.QGroupBox(label)
            box_layout = QtWidgets.QVBoxLayout(box)
            value = QtWidgets.QLabel("0")
            value.setObjectName(f"AutomationMetric{key.title()}")
            value.setStyleSheet("font-size:22px; font-weight:600;")
            box_layout.addWidget(value)
            self.metric_labels[key] = value
            metrics.addWidget(box)
        layout.addLayout(metrics)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setObjectName("AutomationPageTabs")
        self.tabs.setAccessibleName("Automation workflows")
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._build_radar_tab(), "Radar")
        self.tabs.addTab(self._build_inventory_tab(), "Inventory")
        self.tabs.addTab(self._build_matches_tab(), "Exposure Matches")
        self.tabs.addTab(self._build_remediation_tab(), "Remediation")
        self.tabs.addTab(self._build_rules_tab(), "Rules")
        self.tabs.addTab(self._build_queue_tab(), "Validation Queue")
        self.tabs.addTab(self._build_notifications_tab(), "Notifications & Health")
        self.tabs.addTab(self._build_schedule_tab(), "Watch Schedules")
        self.tabs.addTab(self._build_history_tab(), "Run History")
        self.tabs.currentChanged.connect(self._refresh_engagement_context)
        layout.addWidget(self.tabs, 1)
        return page

    def _build_radar_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationRadarTab")
        layout = QtWidgets.QVBoxLayout(tab)
        controls = QtWidgets.QHBoxLayout()
        self.refresh_button = QtWidgets.QPushButton("Refresh public intelligence")
        self.refresh_button.setAccessibleName("Refresh public exploit intelligence")
        self.refresh_button.clicked.connect(lambda: self._start_refresh("manual"))
        self.radar_search = QtWidgets.QLineEdit()
        self.radar_search.setPlaceholderText("Search advisory, product, vendor or source")
        self.radar_search.setAccessibleName("Search exploit intelligence")
        self.radar_search.textChanged.connect(self._populate_radar)
        self.radar_source = QtWidgets.QComboBox()
        self.radar_source.setAccessibleName("Exploit intelligence source filter")
        self.radar_source.currentIndexChanged.connect(self._populate_radar)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.radar_search, 1)
        controls.addWidget(self.radar_source)
        layout.addLayout(controls)
        self.status_label = QtWidgets.QLabel(
            "Feeds are read-only: CISA KEV, NVD, GitHub advisories, FIRST EPSS, "
            "and OSV for exact authorized package versions."
        )
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("AutomationFeedStatus")
        layout.addWidget(self.status_label)
        split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        self.radar_table = QtWidgets.QTableWidget(0, 8)
        self.radar_table.setObjectName("AutomationRadarTable")
        self.radar_table.setAccessibleName("Public exploit intelligence radar")
        self.radar_table.setHorizontalHeaderLabels([
            "Advisory", "Severity", "KEV", "EPSS", "Published", "Vendor",
            "Product", "Sources",
        ])
        self.radar_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.radar_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.radar_table.horizontalHeader().setStretchLastSection(True)
        self.radar_table.itemSelectionChanged.connect(self._show_signal_detail)
        split.addWidget(self.radar_table)
        self.radar_detail = QtWidgets.QPlainTextEdit()
        self.radar_detail.setReadOnly(True)
        self.radar_detail.setAccessibleName("Exploit intelligence detail")
        split.addWidget(self.radar_detail)
        split.setSizes([430, 180])
        layout.addWidget(split, 1)
        return tab

    def _build_inventory_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationInventoryTab")
        layout = QtWidgets.QVBoxLayout(tab)

        controls = QtWidgets.QHBoxLayout()
        self.inventory_engagement_label = QtWidgets.QLabel()
        self.inventory_engagement_label.setWordWrap(True)
        self.inventory_target = QtWidgets.QComboBox()
        self.inventory_target.setEditable(True)
        self.inventory_target.setMinimumWidth(280)
        self.inventory_target.setAccessibleName("Authorized inventory target")
        self.inventory_target.setToolTip(
            "SBOM components are bound to this exact in-scope asset."
        )
        sync_button = QtWidgets.QPushButton("Sync discovered assets")
        import_button = QtWidgets.QPushButton("Import SBOM")
        sync_button.clicked.connect(self._sync_inventory_clicked)
        import_button.clicked.connect(self._import_sbom_clicked)
        controls.addWidget(self.inventory_engagement_label, 1)
        controls.addWidget(QtWidgets.QLabel("Asset"))
        controls.addWidget(self.inventory_target)
        controls.addWidget(sync_button)
        controls.addWidget(import_button)
        layout.addLayout(controls)

        note = QtWidgets.QLabel(
            "Import CycloneDX JSON/XML or SPDX JSON. Files are bounded and parsed "
            "without external entities; components never create network traffic."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        self.inventory_table = QtWidgets.QTableWidget(0, 10)
        self.inventory_table.setObjectName("AutomationInventoryTable")
        self.inventory_table.setAccessibleName("Engagement software inventory")
        self.inventory_table.setHorizontalHeaderLabels([
            "Asset", "Service", "Product", "Version", "Identifier",
            "Confidence", "Exposure", "Criticality", "Source", "Last seen",
        ])
        self.inventory_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.inventory_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.inventory_table.horizontalHeader().setStretchLastSection(True)
        self.inventory_table.itemSelectionChanged.connect(self._show_inventory_detail)
        layout.addWidget(self.inventory_table, 1)

        self.inventory_detail = QtWidgets.QPlainTextEdit()
        self.inventory_detail.setReadOnly(True)
        self.inventory_detail.setMaximumHeight(120)
        self.inventory_detail.setAccessibleName("Inventory evidence detail")
        layout.addWidget(self.inventory_detail)

        form = QtWidgets.QGroupBox("Add observed software")
        grid = QtWidgets.QGridLayout(form)
        self.inventory_product = QtWidgets.QLineEdit()
        self.inventory_product.setPlaceholderText("Product or package name")
        self.inventory_version = QtWidgets.QLineEdit()
        self.inventory_version.setPlaceholderText("Observed version")
        self.inventory_service = QtWidgets.QLineEdit("web")
        self.inventory_ecosystem = QtWidgets.QLineEdit()
        self.inventory_ecosystem.setPlaceholderText("PyPI, npm, Maven…")
        self.inventory_purl = QtWidgets.QLineEdit()
        self.inventory_purl.setPlaceholderText("pkg:type/name@version")
        self.inventory_cpe = QtWidgets.QLineEdit()
        self.inventory_cpe.setPlaceholderText("cpe:2.3:…")
        self.inventory_criticality = QtWidgets.QComboBox()
        for value in ("low", "medium", "high", "critical"):
            self.inventory_criticality.addItem(value.title(), value)
        self.inventory_exposed = QtWidgets.QCheckBox("Internet-facing")
        add_button = QtWidgets.QPushButton("Add inventory record")
        add_button.clicked.connect(self._add_inventory_record)
        grid.addWidget(QtWidgets.QLabel("Product"), 0, 0)
        grid.addWidget(self.inventory_product, 0, 1)
        grid.addWidget(QtWidgets.QLabel("Version"), 0, 2)
        grid.addWidget(self.inventory_version, 0, 3)
        grid.addWidget(QtWidgets.QLabel("Service"), 1, 0)
        grid.addWidget(self.inventory_service, 1, 1)
        grid.addWidget(QtWidgets.QLabel("Ecosystem"), 1, 2)
        grid.addWidget(self.inventory_ecosystem, 1, 3)
        grid.addWidget(QtWidgets.QLabel("PURL"), 2, 0)
        grid.addWidget(self.inventory_purl, 2, 1)
        grid.addWidget(QtWidgets.QLabel("CPE"), 2, 2)
        grid.addWidget(self.inventory_cpe, 2, 3)
        grid.addWidget(QtWidgets.QLabel("Criticality"), 3, 0)
        grid.addWidget(self.inventory_criticality, 3, 1)
        grid.addWidget(self.inventory_exposed, 3, 2)
        grid.addWidget(add_button, 3, 3)
        layout.addWidget(form)
        return tab

    def _build_matches_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationMatchesTab")
        layout = QtWidgets.QVBoxLayout(tab)
        row = QtWidgets.QHBoxLayout()
        self.engagement_label = QtWidgets.QLabel()
        self.engagement_label.setWordWrap(True)
        recompute = QtWidgets.QPushButton("Match authorized assets")
        recompute.clicked.connect(self._recompute_matches)
        queue_button = QtWidgets.QPushButton("Queue safe validation")
        queue_button.clicked.connect(self._queue_selected_match)
        remediation_button = QtWidgets.QPushButton("Open remediation")
        remediation_button.clicked.connect(self._open_selected_remediation)
        row.addWidget(self.engagement_label, 1)
        row.addWidget(recompute)
        row.addWidget(queue_button)
        row.addWidget(remediation_button)
        layout.addLayout(row)
        note = QtWidgets.QLabel(
            "Technology and version correlations are labelled potentially affected; "
            "they are not proof of a vulnerability."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.match_table = QtWidgets.QTableWidget(0, 9)
        self.match_table.setObjectName("AutomationExposureTable")
        self.match_table.setAccessibleName("Authorized asset exposure matches")
        self.match_table.setHorizontalHeaderLabels([
            "Asset", "Advisory", "Assessment", "Confidence", "Risk",
            "Priority", "KEV", "EPSS", "Matched evidence",
        ])
        self.match_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.match_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.match_table.horizontalHeader().setStretchLastSection(True)
        self.match_table.itemSelectionChanged.connect(self._show_match_detail)
        layout.addWidget(self.match_table, 1)
        self.match_detail = QtWidgets.QPlainTextEdit()
        self.match_detail.setReadOnly(True)
        self.match_detail.setMaximumHeight(150)
        self.match_detail.setAccessibleName("Exposure match rationale")
        layout.addWidget(self.match_detail)
        return tab

    def _build_remediation_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationRemediationTab")
        layout = QtWidgets.QVBoxLayout(tab)
        intro = QtWidgets.QLabel(
            "Own each exposure through Open → Fixing → Retest → Resolved, or "
            "record a time-limited accepted-risk exception."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.remediation_table = QtWidgets.QTableWidget(0, 9)
        self.remediation_table.setObjectName("AutomationRemediationTable")
        self.remediation_table.setAccessibleName("Exposure remediation workflow")
        self.remediation_table.setHorizontalHeaderLabels([
            "Status", "SLA", "Risk", "Asset", "Advisory", "Owner",
            "Due", "Exception", "Updated",
        ])
        self.remediation_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.remediation_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.remediation_table.horizontalHeader().setStretchLastSection(True)
        self.remediation_table.itemSelectionChanged.connect(
            self._show_remediation_detail
        )
        layout.addWidget(self.remediation_table, 1)

        self.remediation_detail = QtWidgets.QPlainTextEdit()
        self.remediation_detail.setReadOnly(True)
        self.remediation_detail.setMaximumHeight(130)
        self.remediation_detail.setAccessibleName("Remediation audit detail")
        layout.addWidget(self.remediation_detail)

        form = QtWidgets.QGroupBox("Update selected remediation")
        grid = QtWidgets.QGridLayout(form)
        self.remediation_status = QtWidgets.QComboBox()
        for status in RemediationStatus:
            self.remediation_status.addItem(status.value, status.value)
        self.remediation_owner = QtWidgets.QLineEdit()
        self.remediation_owner.setPlaceholderText("Responsible analyst or team")
        self.remediation_due = QtWidgets.QLineEdit()
        self.remediation_due.setPlaceholderText("ISO-8601, e.g. 2026-09-01T17:00:00Z")
        self.remediation_exception = QtWidgets.QLineEdit()
        self.remediation_exception.setPlaceholderText("Required for Accepted risk")
        self.remediation_note = QtWidgets.QLineEdit()
        self.remediation_note.setPlaceholderText("Patch, mitigation, decision, or evidence note")
        grid.addWidget(QtWidgets.QLabel("Status"), 0, 0)
        grid.addWidget(self.remediation_status, 0, 1)
        grid.addWidget(QtWidgets.QLabel("Owner"), 0, 2)
        grid.addWidget(self.remediation_owner, 0, 3)
        grid.addWidget(QtWidgets.QLabel("SLA due"), 1, 0)
        grid.addWidget(self.remediation_due, 1, 1)
        grid.addWidget(QtWidgets.QLabel("Exception expiry"), 1, 2)
        grid.addWidget(self.remediation_exception, 1, 3)
        grid.addWidget(QtWidgets.QLabel("Note"), 2, 0)
        grid.addWidget(self.remediation_note, 2, 1, 1, 3)

        self.mitigation_description = QtWidgets.QLineEdit()
        self.mitigation_description.setPlaceholderText("Verified control or compensating mitigation")
        self.mitigation_effectiveness = QtWidgets.QDoubleSpinBox()
        self.mitigation_effectiveness.setRange(0.0, 1.0)
        self.mitigation_effectiveness.setSingleStep(0.1)
        self.mitigation_effectiveness.setValue(0.5)
        self.mitigation_verified = QtWidgets.QCheckBox("Verified")
        self.mitigation_expiry = QtWidgets.QLineEdit()
        self.mitigation_expiry.setPlaceholderText("Optional ISO-8601 expiry")
        grid.addWidget(QtWidgets.QLabel("Mitigation"), 3, 0)
        grid.addWidget(self.mitigation_description, 3, 1)
        grid.addWidget(self.mitigation_effectiveness, 3, 2)
        grid.addWidget(self.mitigation_verified, 3, 3)
        grid.addWidget(QtWidgets.QLabel("Mitigation expiry"), 4, 0)
        grid.addWidget(self.mitigation_expiry, 4, 1, 1, 3)
        layout.addWidget(form)

        buttons = QtWidgets.QHBoxLayout()
        apply_button = QtWidgets.QPushButton("Apply update")
        mitigation_button = QtWidgets.QPushButton("Add mitigation")
        retest_button = QtWidgets.QPushButton("Queue patch retest")
        apply_button.clicked.connect(self._apply_remediation_update)
        mitigation_button.clicked.connect(self._add_remediation_mitigation)
        retest_button.clicked.connect(self._queue_remediation_retest)
        buttons.addWidget(apply_button)
        buttons.addWidget(mitigation_button)
        buttons.addWidget(retest_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        return tab

    def _build_rules_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationRulesTab")
        layout = QtWidgets.QVBoxLayout(tab)
        intro = QtWidgets.QLabel(
            "When intelligence changes → if these conditions match → create a local "
            "alert or approval request. Rules never send target traffic."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.rules_table = QtWidgets.QTableWidget(0, 6)
        self.rules_table.setObjectName("AutomationRulesTable")
        self.rules_table.setAccessibleName("Automation rules")
        self.rules_table.setHorizontalHeaderLabels([
            "Enabled", "Name", "Event", "Minimum severity", "Minimum EPSS", "Action",
        ])
        self.rules_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.rules_table, 1)

        form = QtWidgets.QGroupBox("New When → If → Then rule")
        grid = QtWidgets.QGridLayout(form)
        self.rule_name = QtWidgets.QLineEdit()
        self.rule_name.setPlaceholderText("e.g. Queue KEV matches")
        self.rule_event = QtWidgets.QComboBox()
        self.rule_event.addItem("Exposure match", "exposure_match")
        self.rule_event.addItem("New signal", "new_signal")
        self.rule_event.addItem("Signal updated", "signal_updated")
        self.rule_severity = QtWidgets.QComboBox()
        for severity in ("unknown", "low", "medium", "high", "critical"):
            self.rule_severity.addItem(severity.title(), severity)
        self.rule_epss = QtWidgets.QDoubleSpinBox()
        self.rule_epss.setRange(0.0, 1.0)
        self.rule_epss.setSingleStep(0.05)
        self.rule_epss.setDecimals(2)
        self.rule_kev = QtWidgets.QCheckBox("Require CISA KEV / known exploited")
        self.rule_asset = QtWidgets.QCheckBox("Require authorized asset match")
        self.rule_asset.setChecked(True)
        self.rule_action = QtWidgets.QComboBox()
        self.rule_action.addItem("Alert only", "alert")
        self.rule_action.addItem("Queue safe validation", "queue_safe_validation")
        self.rule_action.addItem("Request approval", "request_approval")
        self.rule_action.addItem("Re-test after patch", "retest_after_patch")
        grid.addWidget(QtWidgets.QLabel("Name"), 0, 0)
        grid.addWidget(self.rule_name, 0, 1, 1, 3)
        grid.addWidget(QtWidgets.QLabel("When"), 1, 0)
        grid.addWidget(self.rule_event, 1, 1)
        grid.addWidget(QtWidgets.QLabel("Minimum severity"), 1, 2)
        grid.addWidget(self.rule_severity, 1, 3)
        grid.addWidget(QtWidgets.QLabel("Minimum EPSS"), 2, 0)
        grid.addWidget(self.rule_epss, 2, 1)
        grid.addWidget(self.rule_kev, 2, 2)
        grid.addWidget(self.rule_asset, 2, 3)
        grid.addWidget(QtWidgets.QLabel("Then"), 3, 0)
        grid.addWidget(self.rule_action, 3, 1, 1, 3)
        layout.addWidget(form)
        buttons = QtWidgets.QHBoxLayout()
        add_button = QtWidgets.QPushButton("Add rule")
        remove_button = QtWidgets.QPushButton("Remove selected")
        run_button = QtWidgets.QPushButton("Run rules now")
        add_button.clicked.connect(self._add_rule)
        remove_button.clicked.connect(self._remove_rule)
        run_button.clicked.connect(self._run_rules)
        buttons.addWidget(add_button)
        buttons.addWidget(remove_button)
        buttons.addStretch()
        buttons.addWidget(run_button)
        layout.addLayout(buttons)
        return tab

    def _build_queue_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationQueueTab")
        layout = QtWidgets.QVBoxLayout(tab)
        note = QtWidgets.QLabel(
            "Approval re-checks the current engagement and exact target scope. "
            "The prepared recipe forces Blackthorn safe mode and excludes arbitrary tools."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.queue_table = QtWidgets.QTableWidget(0, 7)
        self.queue_table.setObjectName("AutomationValidationQueue")
        self.queue_table.setAccessibleName("Automation validation approval queue")
        self.queue_table.setHorizontalHeaderLabels([
            "Status", "Target", "Advisory", "Rule", "Impact", "Created", "Rationale",
        ])
        self.queue_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.queue_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.queue_table.horizontalHeader().setStretchLastSection(True)
        self.queue_table.itemSelectionChanged.connect(self._show_queue_preview)
        layout.addWidget(self.queue_table, 1)
        self.queue_preview = QtWidgets.QPlainTextEdit()
        self.queue_preview.setReadOnly(True)
        self.queue_preview.setMaximumHeight(180)
        self.queue_preview.setAccessibleName("Safe validation request preview")
        layout.addWidget(self.queue_preview)
        buttons = QtWidgets.QHBoxLayout()
        approve = QtWidgets.QPushButton("Approve and open safe recipe")
        dismiss = QtWidgets.QPushButton("Dismiss selected")
        approve.clicked.connect(self._approve_selected_queue)
        dismiss.clicked.connect(self._dismiss_selected_queue)
        buttons.addWidget(approve)
        buttons.addWidget(dismiss)
        buttons.addStretch()
        layout.addLayout(buttons)
        return tab

    def _build_notifications_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationNotificationsTab")
        layout = QtWidgets.QVBoxLayout(tab)
        settings = self._settings()

        form = QtWidgets.QGroupBox("Alerts and daily digest")
        grid = QtWidgets.QGridLayout(form)
        self.notifications_enabled = QtWidgets.QCheckBox(
            "Deliver rule, KEV, EPSS, exposure, regression, and overdue-SLA alerts"
        )
        self.notifications_enabled.setChecked(settings["notifications_enabled"])
        self.notification_channels: Dict[str, QtWidgets.QCheckBox] = {}
        for column, (key, label) in enumerate((
            ("webhook", "Webhook"),
            ("slack", "Slack"),
            ("teams", "Teams"),
            ("jira", "Jira"),
            ("smtp", "Email"),
        )):
            checkbox = QtWidgets.QCheckBox(label)
            checkbox.setChecked(key in settings["notification_channels"])
            self.notification_channels[key] = checkbox
            grid.addWidget(checkbox, 1, column)
        self.notification_min_severity = QtWidgets.QComboBox()
        for value in ("info", "low", "medium", "high", "critical"):
            self.notification_min_severity.addItem(value.title(), value)
        index = self.notification_min_severity.findData(
            settings["notification_min_severity"]
        )
        self.notification_min_severity.setCurrentIndex(max(0, index))
        self.digest_enabled = QtWidgets.QCheckBox("Send periodic digest")
        self.digest_enabled.setChecked(settings["digest_enabled"])
        self.digest_hours = QtWidgets.QSpinBox()
        self.digest_hours.setRange(1, 168)
        self.digest_hours.setValue(settings["digest_hours"])
        self.digest_next = QtWidgets.QLabel("Not scheduled")
        save_button = QtWidgets.QPushButton("Save alert settings")
        validate_button = QtWidgets.QPushButton("Validate connectors")
        test_button = QtWidgets.QPushButton("Send test notification")
        save_button.clicked.connect(self._save_notification_settings)
        validate_button.clicked.connect(
            lambda: self._send_test_notification(dry_run=True)
        )
        test_button.clicked.connect(
            lambda: self._send_test_notification(dry_run=False)
        )
        grid.addWidget(self.notifications_enabled, 0, 0, 1, 5)
        grid.addWidget(QtWidgets.QLabel("Minimum severity"), 2, 0)
        grid.addWidget(self.notification_min_severity, 2, 1)
        grid.addWidget(self.digest_enabled, 2, 2)
        grid.addWidget(self.digest_hours, 2, 3)
        grid.addWidget(QtWidgets.QLabel("hours"), 2, 4)
        grid.addWidget(QtWidgets.QLabel("Next digest"), 3, 0)
        grid.addWidget(self.digest_next, 3, 1, 1, 2)
        grid.addWidget(validate_button, 3, 3)
        grid.addWidget(test_button, 3, 4)
        grid.addWidget(save_button, 4, 4)
        layout.addWidget(form)

        env_note = QtWidgets.QLabel(
            "Connector values are read only from environment variables at send time and "
            "are never saved: BLACKTHORN_AUTOMATION_WEBHOOK_URL; "
            "BLACKTHORN_SLACK_WEBHOOK_URL; BLACKTHORN_TEAMS_WEBHOOK_URL; Jira "
            "BLACKTHORN_JIRA_BASE_URL/_EMAIL/_API_TOKEN/_PROJECT_KEY; and SMTP "
            "BLACKTHORN_SMTP_HOST/_FROM/_TO with optional credentials. Destinations "
            "must resolve to public addresses and use TLS."
        )
        env_note.setWordWrap(True)
        layout.addWidget(env_note)

        split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        self.feed_health_table = QtWidgets.QTableWidget(0, 8)
        self.feed_health_table.setObjectName("AutomationFeedHealthTable")
        self.feed_health_table.setAccessibleName("Exploit intelligence feed health")
        self.feed_health_table.setHorizontalHeaderLabels([
            "Source", "Status", "Last success", "Last failure", "Freshness",
            "Failures", "Rate limit until", "Error",
        ])
        self.feed_health_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.feed_health_table.horizontalHeader().setStretchLastSection(True)
        split.addWidget(self.feed_health_table)

        self.delivery_history_table = QtWidgets.QTableWidget(0, 7)
        self.delivery_history_table.setObjectName("AutomationDeliveryHistory")
        self.delivery_history_table.setAccessibleName("Notification delivery history")
        self.delivery_history_table.setHorizontalHeaderLabels([
            "Time", "Event", "Kind", "Severity", "Adapter", "Status", "Error",
        ])
        self.delivery_history_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.delivery_history_table.horizontalHeader().setStretchLastSection(True)
        split.addWidget(self.delivery_history_table)
        split.setSizes([240, 220])
        layout.addWidget(split, 1)

        self.digest_timer = QtCore.QTimer(tab)
        self.digest_timer.timeout.connect(self._maybe_send_digest)
        self.digest_timer.start(60 * 1000)
        self._update_digest_label()
        return tab

    def _build_schedule_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationScheduleTab")
        layout = QtWidgets.QVBoxLayout(tab)
        form = QtWidgets.QGroupBox("Read-only intelligence watch")
        grid = QtWidgets.QGridLayout(form)
        settings = self._settings()
        self.watch_enabled = QtWidgets.QCheckBox("Refresh feeds while Blackthorn is open")
        self.watch_enabled.setChecked(settings["watch_enabled"])
        self.watch_minutes = QtWidgets.QSpinBox()
        self.watch_minutes.setRange(15, 1440)
        self.watch_minutes.setValue(settings["watch_minutes"])
        self.watch_days = QtWidgets.QSpinBox()
        self.watch_days.setRange(1, 120)
        self.watch_days.setValue(settings["days"])
        self.next_refresh = QtWidgets.QLabel("Not scheduled")
        apply_button = QtWidgets.QPushButton("Apply watch schedule")
        refresh_button = QtWidgets.QPushButton("Refresh now")
        apply_button.clicked.connect(self._save_watch_schedule)
        refresh_button.clicked.connect(lambda: self._start_refresh("manual"))
        grid.addWidget(self.watch_enabled, 0, 0, 1, 4)
        grid.addWidget(QtWidgets.QLabel("Interval (minutes)"), 1, 0)
        grid.addWidget(self.watch_minutes, 1, 1)
        grid.addWidget(QtWidgets.QLabel("Recent advisory window (days)"), 1, 2)
        grid.addWidget(self.watch_days, 1, 3)
        grid.addWidget(QtWidgets.QLabel("Next refresh"), 2, 0)
        grid.addWidget(self.next_refresh, 2, 1, 1, 3)
        grid.addWidget(apply_button, 3, 2)
        grid.addWidget(refresh_button, 3, 3)
        layout.addWidget(form)
        guard = QtWidgets.QLabel(
            "This timer only downloads bounded metadata from fixed official API hosts. "
            "It never scans assets, executes proof-of-concept code, or approves validations."
        )
        guard.setWordWrap(True)
        layout.addWidget(guard)
        self.watch_timer = QtCore.QTimer(tab)
        self.watch_timer.timeout.connect(lambda: self._start_refresh("schedule"))
        layout.addStretch()
        return tab

    def _build_history_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("AutomationHistoryTab")
        layout = QtWidgets.QVBoxLayout(tab)
        self.history_table = QtWidgets.QTableWidget(0, 6)
        self.history_table.setObjectName("AutomationRunHistory")
        self.history_table.setAccessibleName("Automation run and decision history")
        self.history_table.setHorizontalHeaderLabels([
            "Timestamp", "Event", "Target", "Advisory", "Detail", "Decision",
        ])
        self.history_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.history_table, 1)
        return tab

    # ---- population ---------------------------------------------------
    def _populate_all(self) -> None:
        self._refresh_engagement_context(recompute=False)
        self._populate_radar()
        self._populate_inventory()
        self._populate_matches()
        self._populate_remediations()
        self._populate_rules()
        self._populate_queue()
        self._populate_delivery()
        self._populate_history()
        self._update_metrics()
        self._update_pause_button()

    def _populate_radar(self, *_args) -> None:
        sources = sorted({source for signal in self.signals for source in signal.sources})
        current_source = self.radar_source.currentData()
        self.radar_source.blockSignals(True)
        self.radar_source.clear()
        self.radar_source.addItem("All sources", "")
        for source in sources:
            self.radar_source.addItem(source.replace("_", " ").title(), source)
        index = self.radar_source.findData(current_source)
        self.radar_source.setCurrentIndex(index if index >= 0 else 0)
        self.radar_source.blockSignals(False)
        needle = self.radar_search.text().strip().casefold()
        source_filter = str(self.radar_source.currentData() or "")
        rows = []
        for signal in self.signals:
            haystack = " ".join([
                signal.identifier, signal.title, signal.summary,
                *signal.vendors, *signal.products, *signal.packages, *signal.sources,
            ]).casefold()
            if needle and needle not in haystack:
                continue
            if source_filter and source_filter not in signal.sources:
                continue
            rows.append(signal)
        self.radar_table.setRowCount(min(len(rows), 1500))
        for row, signal in enumerate(rows[:1500]):
            values = [
                signal.identifier,
                signal.severity.upper(),
                "Yes" if signal.known_exploited else "No",
                f"{signal.epss_score:.2f}" if signal.epss_score is not None else "—",
                signal.published_at,
                ", ".join(signal.vendors),
                ", ".join(signal.products or signal.packages),
                ", ".join(signal.sources),
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(_bounded_text(value, 2048))
                if column == 0:
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, signal)
                self.radar_table.setItem(row, column, item)
        statuses = ", ".join(
            f"{key.replace('_', ' ')}: {value}"
            for key, value in sorted(self.source_status.items())
        )
        if statuses:
            self.status_label.setText(
                f"Source status — {statuses}."
                + (f"  Failures: {'; '.join(self.failures)}" if self.failures else "")
            )

    def _refresh_engagement_context(
        self, *_args, recompute: bool = True,
    ) -> None:
        previous = self.inventory_engagement_id
        engagement = self._ensure_inventory_context(sync_discovered=True)
        if hasattr(self, "inventory_engagement_label"):
            if engagement is None:
                _unused, reason = _active_engagement(self.host)
                self.inventory_engagement_label.setText(reason)
            else:
                self.inventory_engagement_label.setText(
                    f"Active engagement: {engagement.get('name', 'Engagement')}"
                )
        if engagement is not None and hasattr(self, "inventory_target"):
            current = self.inventory_target.currentText().strip()
            targets = sorted({
                record.host for record in self.inventory_records if record.host
            })
            self.inventory_target.blockSignals(True)
            self.inventory_target.clear()
            self.inventory_target.addItems(targets)
            self.inventory_target.setEditText(current or (targets[0] if targets else ""))
            self.inventory_target.blockSignals(False)
        if recompute and previous != self.inventory_engagement_id:
            self._recompute_matches(run_rules=False)
            self._populate_inventory()
            self._populate_remediations()

    def _populate_inventory(self) -> None:
        if not hasattr(self, "inventory_table"):
            return
        self.inventory_table.setRowCount(len(self.inventory_records))
        for row, record in enumerate(self.inventory_records):
            identifier = record.purl or record.cpe or "—"
            values = [
                record.host,
                record.service,
                record.product,
                record.version or "—",
                identifier,
                f"{record.confidence:.0%}",
                "Internet" if record.internet_exposed else "Not established",
                record.criticality.title(),
                record.source,
                record.last_seen,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(_bounded_text(value, 2048))
                if column == 0:
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, record)
                self.inventory_table.setItem(row, column, item)

    def _record_for_match(self, match: ExposureMatch) -> Optional[InventoryRecord]:
        direct = next(
            (row for row in self.inventory_records if row.record_id == match.asset_id),
            None,
        )
        if direct is not None:
            return direct
        marker = _host_key(match.asset_name)
        return next(
            (row for row in self.inventory_records if _host_key(row.host) == marker),
            None,
        )

    def _remediation_for(
        self, record_id: str, advisory_id: str,
    ) -> Optional[RemediationItem]:
        return next((
            item for item in self.remediations
            if item.record_id == record_id and item.advisory_id == advisory_id
        ), None)

    def _match_evaluation(self, match: ExposureMatch) -> dict:
        signal = next(
            (item for item in self.signals if item.identifier == match.signal_id), None
        )
        record = self._record_for_match(match)
        if match.source == "osv_package_query" and record and record.version:
            classification = "exact"
            reason = "OSV returned the advisory for this exact authorized package/version query."
        else:
            classification = "possible"
            reason = "Technology identifiers match; affected version/configuration is unverified."
        remediation = self._remediation_for(
            record.record_id if record else match.asset_id,
            match.cve_id or match.signal_id,
        )
        mitigations = remediation.mitigations if remediation else ()
        classification_confidence = {
            "exact": 1.0,
            "likely": 0.8,
            "possible": 0.5,
            "not_affected": 0.0,
        }[classification]
        evidence_confidence = (
            record.confidence
            if record is not None
            else (0.5 if match.confidence == "medium" else 0.3)
        )
        risk = score_risk(
            known_exploited=bool(signal and signal.known_exploited),
            epss_score=signal.epss_score if signal else None,
            internet_exposed=(
                record.internet_exposed if record else _looks_internet_exposed(match.asset_name)
            ),
            criticality=record.criticality if record else "medium",
            confidence=classification_confidence * evidence_confidence,
            mitigations=mitigations,
        )
        return {
            "classification": classification,
            "classification_label": {
                "exact": "Exact version match",
                "likely": "Likely affected",
                "possible": "Possible",
                "not_affected": "Not affected",
            }[classification],
            "reason": reason,
            "risk": risk,
            "record": record,
        }

    def _populate_matches(self) -> None:
        engagement, reason = _active_engagement(self.host)
        if engagement:
            self.engagement_label.setText(
                f"Active engagement: {engagement.get('name', 'Engagement')} · "
                f"{len(engagement.get('scope') or [])} scope rule(s)"
            )
        else:
            self.engagement_label.setText(reason)
        signal_map = {signal.identifier: signal for signal in self.signals}
        self.match_table.setRowCount(len(self.matches))
        self.match_context = {}
        for row, match in enumerate(self.matches):
            signal = signal_map.get(match.signal_id)
            context = self._match_evaluation(match)
            self.match_context[match.match_id] = context
            risk = context["risk"]
            values = [
                match.asset_name,
                match.cve_id or match.signal_id,
                context["classification_label"],
                f"{context['record'].confidence:.0%}"
                if context["record"] else match.confidence,
                f"{risk.score} · {risk.rating.upper()}",
                str(match.priority),
                "Yes" if signal and signal.known_exploited else "No",
                f"{signal.epss_score:.2f}" if signal and signal.epss_score is not None else "—",
                ", ".join(match.matched_terms),
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(_bounded_text(value, 2048))
                if column == 0:
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, match)
                self.match_table.setItem(row, column, item)

    def _populate_remediations(self) -> None:
        if not hasattr(self, "remediation_table"):
            return
        records = {record.record_id: record for record in self.inventory_records}
        signal_map = {
            (match.asset_id, match.cve_id or match.signal_id): match
            for match in self.matches
        }
        self.remediation_table.setRowCount(len(self.remediations))
        for row, remediation in enumerate(self.remediations):
            record = records.get(remediation.record_id)
            match = signal_map.get((remediation.record_id, remediation.advisory_id))
            if match:
                risk = self._match_evaluation(match)["risk"]
                risk_text = f"{risk.score} · {risk.rating.upper()}"
            else:
                risk_text = "—"
            values = [
                remediation.status,
                sla_state(remediation).replace("_", " ").title(),
                risk_text,
                record.host if record else remediation.record_id,
                remediation.advisory_id,
                remediation.owner or "—",
                remediation.sla_due or "—",
                remediation.exception_expiry or "—",
                remediation.updated_at,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(_bounded_text(value, 2048))
                if column == 0:
                    item.setData(
                        QtCore.Qt.ItemDataRole.UserRole, remediation.remediation_id
                    )
                self.remediation_table.setItem(row, column, item)

    def _populate_delivery(self) -> None:
        if not hasattr(self, "feed_health_table"):
            return
        sources = {
            "cisa_kev", "nvd", "github_advisories", "first_epss", "osv",
            *self.source_status.keys(),
        }
        try:
            health_rows = self.feed_health.snapshot(sources)
        except DeliveryError:
            health_rows = ()
        self.feed_health_table.setRowCount(len(health_rows))
        for row, health in enumerate(health_rows):
            freshness = (
                f"{health.freshness_seconds // 60} min"
                if health.freshness_seconds is not None else "—"
            )
            values = [
                health.source.replace("_", " ").title(),
                health.status.replace("_", " ").title(),
                health.last_success_at or "—",
                health.last_failure_at or "—",
                freshness,
                str(health.consecutive_failures),
                health.rate_limited_until or "—",
                health.last_error_code or "—",
            ]
            for column, value in enumerate(values):
                self.feed_health_table.setItem(
                    row, column,
                    QtWidgets.QTableWidgetItem(_bounded_text(value, 2048)),
                )
        try:
            delivery_rows = list(reversed(self.delivery_store.history(limit=250)))
        except DeliveryError:
            delivery_rows = []
        self.delivery_history_table.setRowCount(len(delivery_rows))
        for row, item in enumerate(delivery_rows):
            values = [
                item.get("recorded_at", ""),
                item.get("notification_id", ""),
                item.get("kind", ""),
                item.get("severity", ""),
                item.get("adapter", ""),
                item.get("status", ""),
                item.get("error_code", ""),
            ]
            for column, value in enumerate(values):
                self.delivery_history_table.setItem(
                    row, column,
                    QtWidgets.QTableWidgetItem(_bounded_text(value, 2048)),
                )

    def _populate_rules(self) -> None:
        self.rules_table.setRowCount(len(self.rules))
        for row, rule in enumerate(self.rules):
            enabled = QtWidgets.QCheckBox()
            enabled.setChecked(rule.enabled)
            enabled.setAccessibleName(f"Enable rule {rule.name}")
            enabled.toggled.connect(lambda checked, rule_id=rule.rule_id: self._toggle_rule(rule_id, checked))
            holder = QtWidgets.QWidget()
            holder_layout = QtWidgets.QHBoxLayout(holder)
            holder_layout.setContentsMargins(8, 0, 0, 0)
            holder_layout.addWidget(enabled)
            holder_layout.addStretch()
            self.rules_table.setCellWidget(row, 0, holder)
            for column, value in enumerate((
                rule.name,
                rule.event.replace("_", " ").title(),
                rule.min_severity.title(),
                f"{rule.min_epss:.2f}",
                rule.action.replace("_", " ").title(),
            ), 1):
                item = QtWidgets.QTableWidgetItem(value)
                if column == 1:
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, rule.rule_id)
                self.rules_table.setItem(row, column, item)

    def _populate_queue(self) -> None:
        self.queue_table.setRowCount(len(self.queue))
        for row, item in enumerate(self.queue):
            values = [
                item.get("status", "awaiting_approval"),
                item.get("target", ""),
                item.get("advisory", ""),
                item.get("rule", "manual"),
                item.get("impact", "safe"),
                item.get("created_at", ""),
                item.get("rationale", ""),
            ]
            for column, value in enumerate(values):
                cell = QtWidgets.QTableWidgetItem(_bounded_text(value, 2048))
                if column == 0:
                    cell.setData(QtCore.Qt.ItemDataRole.UserRole, item.get("id"))
                self.queue_table.setItem(row, column, cell)

    def _populate_history(self) -> None:
        self.history_table.setRowCount(len(self.history))
        for row, item in enumerate(self.history):
            for column, value in enumerate((
                item.get("timestamp", ""), item.get("event", ""),
                item.get("target", ""), item.get("advisory", ""),
                item.get("detail", ""), item.get("decision_id", ""),
            )):
                self.history_table.setItem(
                    row, column, QtWidgets.QTableWidgetItem(_bounded_text(value, 2048))
                )

    def _update_metrics(self) -> None:
        self.metric_labels["signals"].setText(str(len(self.signals)))
        self.metric_labels["kev"].setText(str(sum(1 for item in self.signals if item.known_exploited)))
        self.metric_labels["matches"].setText(str(len(self.matches)))
        awaiting = sum(
            1 for item in self.queue
            if item.get("status") in {"awaiting_approval", "approved"}
        )
        self.metric_labels["queue"].setText(str(awaiting))
        open_remediation = sum(
            1 for item in self.remediations
            if item.status not in {
                RemediationStatus.RESOLVED.value,
                RemediationStatus.ACCEPTED.value,
            }
        )
        self.metric_labels["remediation"].setText(str(open_remediation))

    # ---- selection detail --------------------------------------------
    def _selected_data(self, table: Any, column: int = 0) -> Any:
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, column)
        return item.data(QtCore.Qt.ItemDataRole.UserRole) if item else None

    def _show_signal_detail(self) -> None:
        signal = self._selected_data(self.radar_table)
        self.radar_detail.setPlainText(
            json.dumps(asdict(signal), indent=2, ensure_ascii=False)
            if isinstance(signal, ExploitSignal) else ""
        )

    def _show_match_detail(self) -> None:
        match = self._selected_data(self.match_table)
        if not isinstance(match, ExposureMatch):
            self.match_detail.clear()
            return
        context = self.match_context.get(match.match_id) or self._match_evaluation(match)
        value = asdict(match)
        value["explainable_assessment"] = {
            "classification": context["classification"],
            "reason": context["reason"],
            "risk": asdict(context["risk"]),
            "inventory_record": (
                asdict(context["record"]) if context["record"] else None
            ),
        }
        self.match_detail.setPlainText(
            json.dumps(value, indent=2, ensure_ascii=False)
        )

    def _show_inventory_detail(self) -> None:
        record = self._selected_data(self.inventory_table)
        if not isinstance(record, InventoryRecord):
            self.inventory_detail.clear()
            return
        self.inventory_detail.setPlainText(
            json.dumps(asdict(record), indent=2, ensure_ascii=False)
        )
        self.inventory_target.setEditText(record.host)
        self.inventory_product.setText(record.product)
        self.inventory_version.setText(record.version)
        self.inventory_service.setText(record.service)
        self.inventory_ecosystem.setText(record.ecosystem)
        self.inventory_purl.setText(record.purl)
        self.inventory_cpe.setText(record.cpe)
        index = self.inventory_criticality.findData(record.criticality)
        self.inventory_criticality.setCurrentIndex(max(0, index))
        self.inventory_exposed.setChecked(record.internet_exposed)

    def _selected_remediation(self) -> Optional[RemediationItem]:
        remediation_id = str(
            self._selected_data(self.remediation_table) or ""
        )
        return next((
            item for item in self.remediations
            if item.remediation_id == remediation_id
        ), None)

    def _show_remediation_detail(self) -> None:
        remediation = self._selected_remediation()
        if remediation is None:
            self.remediation_detail.clear()
            return
        record = next((
            row for row in self.inventory_records
            if row.record_id == remediation.record_id
        ), None)
        value = asdict(remediation)
        value["asset"] = asdict(record) if record else None
        self.remediation_detail.setPlainText(
            json.dumps(value, indent=2, ensure_ascii=False)
        )
        index = self.remediation_status.findData(remediation.status)
        self.remediation_status.setCurrentIndex(max(0, index))
        self.remediation_owner.setText(remediation.owner)
        self.remediation_due.setText(remediation.sla_due)
        self.remediation_exception.setText(remediation.exception_expiry)
        self.remediation_note.clear()

    def _tab_index(self, label: str) -> int:
        return next((
            index for index in range(self.tabs.count())
            if self.tabs.tabText(index) == label
        ), -1)

    # ---- inventory and remediation ---------------------------------
    def _sync_inventory_clicked(self) -> None:
        engagement = self._ensure_inventory_context()
        if engagement is None:
            QtWidgets.QMessageBox.warning(
                self.page, "Inventory", "Select an active engagement first."
            )
            return
        count, events = self._sync_discovered_inventory(record_changes=True)
        for event in events:
            self._history_event(
                f"Inventory {event.event_type.replace('_', ' ')}",
                target=event.host,
                detail=", ".join(event.changed_fields),
            )
            self._emit_inventory_change(event)
        self._history_event(
            "Inventory synchronized",
            detail=f"{count} current discovery/software observation(s) merged.",
        )
        self._populate_inventory()
        self._recompute_matches(run_rules=True)
        self._save_state()
        self._populate_history()

    def _import_sbom_clicked(self) -> None:
        engagement = self._ensure_inventory_context()
        if engagement is None:
            QtWidgets.QMessageBox.warning(
                self.page, "Import SBOM", "Select an active engagement first."
            )
            return
        target = self.inventory_target.currentText().strip()
        if not target or not _scope_allows(target, engagement):
            QtWidgets.QMessageBox.warning(
                self.page,
                "Import SBOM",
                "Choose an exact target authorized by the active engagement.",
            )
            return
        path, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
            self.page,
            "Import software bill of materials",
            "",
            "SBOM (*.json *.xml);;CycloneDX/SPDX JSON (*.json);;CycloneDX XML (*.xml)",
        )
        if not path:
            return
        try:
            result = import_sbom(
                path,
                engagement_id=self.inventory_engagement_id,
                host=target,
                service=self.inventory_service.text().strip() or "application",
                criticality=str(self.inventory_criticality.currentData()),
                internet_exposed=self.inventory_exposed.isChecked(),
            )
            previous = InventorySnapshot(
                self.inventory_engagement_id, _utc_now(), tuple(self.inventory_records)
            )
            self.inventory_records = merge_inventory_records(
                self.inventory_records + list(result.records)
            )
            current = InventorySnapshot(
                self.inventory_engagement_id, _utc_now(), tuple(self.inventory_records)
            )
            difference = diff_inventory(previous, current)
            self.inventory_state = InventoryState(
                self.inventory_engagement_id,
                current,
                tuple(self.remediations),
                tuple(
                    list(self.inventory_state.change_events if self.inventory_state else ())[-19000:]
                    + list(difference.events)
                ),
            )
        except (OSError, InventoryValidationError) as exc:
            QtWidgets.QMessageBox.warning(
                self.page, "Import SBOM", _bounded_text(exc, 512)
            )
            return
        for change_event in difference.events:
            self._emit_inventory_change(change_event)
        self._history_event(
            "SBOM imported",
            target=target,
            detail=(
                f"{result.format}: {len(result.records)} component(s). "
                + ("Warnings: " + "; ".join(result.warnings) if result.warnings else "")
            ),
        )
        self._persist_inventory()
        self._refresh_engagement_context(recompute=False)
        self._populate_inventory()
        self._recompute_matches(run_rules=True)
        self._save_state()
        QtWidgets.QMessageBox.information(
            self.page,
            "SBOM imported",
            f"Imported {len(result.records)} validated component(s) for {target}.",
        )

    def _add_inventory_record(self) -> None:
        engagement = self._ensure_inventory_context()
        target = self.inventory_target.currentText().strip()
        if engagement is None or not target or not _scope_allows(target, engagement):
            QtWidgets.QMessageBox.warning(
                self.page, "Inventory", "The inventory target must be in active scope."
            )
            return
        try:
            previous = InventorySnapshot(
                self.inventory_engagement_id, _utc_now(), tuple(self.inventory_records)
            )
            record = create_inventory_record(
                engagement_id=self.inventory_engagement_id,
                host=target,
                service=self.inventory_service.text().strip(),
                product=self.inventory_product.text().strip(),
                version=self.inventory_version.text().strip(),
                cpe=self.inventory_cpe.text().strip(),
                purl=self.inventory_purl.text().strip(),
                ecosystem=self.inventory_ecosystem.text().strip(),
                evidence=("Manually recorded by the local analyst",),
                confidence=0.8,
                criticality=str(self.inventory_criticality.currentData()),
                internet_exposed=self.inventory_exposed.isChecked(),
                source="manual",
            )
            self.inventory_records = merge_inventory_records(
                self.inventory_records + [record]
            )
            current = InventorySnapshot(
                self.inventory_engagement_id, _utc_now(), tuple(self.inventory_records)
            )
            difference = diff_inventory(previous, current)
            self.inventory_state = InventoryState(
                self.inventory_engagement_id,
                current,
                tuple(self.remediations),
                tuple(
                    list(self.inventory_state.change_events if self.inventory_state else ())[-19000:]
                    + list(difference.events)
                ),
            )
        except InventoryValidationError as exc:
            QtWidgets.QMessageBox.warning(
                self.page, "Inventory", _bounded_text(exc, 512)
            )
            return
        for change_event in difference.events:
            self._emit_inventory_change(change_event)
        self._history_event(
            "Inventory record added", target=target,
            detail=f"{record.product} {record.version}".strip(),
        )
        self.inventory_product.clear()
        self.inventory_version.clear()
        self.inventory_purl.clear()
        self.inventory_cpe.clear()
        self._persist_inventory()
        self._populate_inventory()
        self._recompute_matches(run_rules=True)
        self._save_state()

    def _open_selected_remediation(self) -> None:
        match = self._selected_data(self.match_table)
        if not isinstance(match, ExposureMatch):
            QtWidgets.QMessageBox.information(
                self.page, "Remediation", "Select an exposure match first."
            )
            return
        context = self.match_context.get(match.match_id) or self._match_evaluation(match)
        record = context.get("record")
        if not isinstance(record, InventoryRecord):
            QtWidgets.QMessageBox.warning(
                self.page,
                "Remediation",
                "This match has no durable inventory record. Sync Inventory first.",
            )
            return
        advisory = match.cve_id or match.signal_id
        existing = self._remediation_for(record.record_id, advisory)
        if existing is None:
            days = {"critical": 7, "high": 14, "medium": 30, "low": 90}[
                context["risk"].rating
            ]
            due = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat().replace(
                "+00:00", "Z"
            )
            try:
                existing = create_remediation(
                    engagement_id=self.inventory_engagement_id,
                    record_id=record.record_id,
                    advisory_id=advisory,
                    sla_due=due,
                )
            except InventoryValidationError as exc:
                QtWidgets.QMessageBox.warning(
                    self.page, "Remediation", _bounded_text(exc, 512)
                )
                return
            self.remediations.append(existing)
            self._history_event(
                "Remediation opened", target=record.host, advisory=advisory,
                detail=f"Risk {context['risk'].score}; SLA due {due}.",
            )
            self._save_state()
        self._populate_remediations()
        index = self._tab_index("Remediation")
        if index >= 0:
            self.tabs.setCurrentIndex(index)
        for row in range(self.remediation_table.rowCount()):
            item = self.remediation_table.item(row, 0)
            if item and item.data(QtCore.Qt.ItemDataRole.UserRole) == existing.remediation_id:
                self.remediation_table.selectRow(row)
                break

    def _replace_remediation(self, updated: RemediationItem) -> None:
        self.remediations = [
            updated if item.remediation_id == updated.remediation_id else item
            for item in self.remediations
        ]
        self._persist_inventory()
        self._populate_remediations()
        self._update_metrics()

    def _apply_remediation_update(self) -> None:
        item = self._selected_remediation()
        if item is None:
            QtWidgets.QMessageBox.information(
                self.page, "Remediation", "Select a remediation item first."
            )
            return
        status = str(self.remediation_status.currentData())
        kwargs = {
            "owner": self.remediation_owner.text().strip(),
            "sla_due": self.remediation_due.text().strip(),
            "exception_expiry": self.remediation_exception.text().strip(),
            "note": self.remediation_note.text().strip(),
        }
        try:
            updated = (
                update_remediation(item, **kwargs)
                if status == item.status
                else transition_remediation(item, status, **kwargs)
            )
        except InventoryValidationError as exc:
            QtWidgets.QMessageBox.warning(
                self.page, "Remediation", _bounded_text(exc, 512)
            )
            return
        self._replace_remediation(updated)
        self._history_event(
            "Remediation updated", advisory=updated.advisory_id,
            detail=f"{item.status} → {updated.status}; owner={updated.owner or 'unset'}",
        )
        self._save_state()
        self._populate_history()

    def _add_remediation_mitigation(self) -> None:
        item = self._selected_remediation()
        description = self.mitigation_description.text().strip()
        if item is None or not description:
            QtWidgets.QMessageBox.information(
                self.page, "Mitigation", "Select a remediation and enter a mitigation."
            )
            return
        mitigation = Mitigation(
            mitigation_id=_stable_id("mitigation", item.remediation_id, description),
            description=description,
            effectiveness=float(self.mitigation_effectiveness.value()),
            verified=self.mitigation_verified.isChecked(),
            expires_at=self.mitigation_expiry.text().strip(),
        )
        try:
            updated = add_mitigation(item, mitigation)
        except InventoryValidationError as exc:
            QtWidgets.QMessageBox.warning(
                self.page, "Mitigation", _bounded_text(exc, 512)
            )
            return
        self._replace_remediation(updated)
        self._history_event(
            "Mitigation recorded", advisory=item.advisory_id,
            detail=(
                f"{description}; verified={mitigation.verified}; "
                f"effectiveness={mitigation.effectiveness:.0%}"
            ),
        )
        self.mitigation_description.clear()
        self._recompute_matches(run_rules=False)
        self._save_state()

    def _queue_remediation_retest(self) -> None:
        item = self._selected_remediation()
        if item is None:
            return
        if item.status not in {
            RemediationStatus.FIXING.value,
            RemediationStatus.RETEST.value,
            RemediationStatus.RESOLVED.value,
        }:
            QtWidgets.QMessageBox.warning(
                self.page,
                "Patch retest",
                "Move the remediation to Fixing before requesting a patch retest.",
            )
            return
        updated = item
        if item.status != RemediationStatus.RETEST.value:
            try:
                updated = transition_remediation(
                    item,
                    RemediationStatus.RETEST.value,
                    owner=item.owner,
                    note="Safe patch retest requested",
                )
            except InventoryValidationError as exc:
                QtWidgets.QMessageBox.warning(
                    self.page, "Patch retest", _bounded_text(exc, 512)
                )
                return
            self._replace_remediation(updated)
        record = next((
            row for row in self.inventory_records if row.record_id == item.record_id
        ), None)
        if record is None:
            return
        match = next((
            row for row in self.matches
            if row.asset_id == item.record_id
            and (row.cve_id or row.signal_id) == item.advisory_id
        ), None)
        if match is None:
            signal = next((
                row for row in self.signals
                if item.advisory_id in {row.identifier, row.cve_id}
            ), None)
            match = ExposureMatch(
                match_id=_stable_id("retest-match", item.remediation_id),
                asset_id=record.record_id,
                asset_name=record.host,
                signal_id=signal.identifier if signal else item.advisory_id,
                cve_id=signal.cve_id if signal else item.advisory_id,
                confidence="medium",
                matched_terms=(record.product, record.version),
                reasons=("Post-remediation validation requested by the assigned owner.",),
                priority=50,
                source="remediation_retest",
            )
        self._append_queue(match, rule_name="Patch remediation retest")
        self._save_state()
        self._populate_queue()
        index = self._tab_index("Validation Queue")
        if index >= 0:
            self.tabs.setCurrentIndex(index)

    # ---- alerts, connectors, and feed health ------------------------
    def _emit_inventory_change(self, event: Any) -> None:
        record = next((
            row for row in self.inventory_records
            if row.record_id == getattr(event, "record_id", "")
        ), None)
        fields = tuple(getattr(event, "changed_fields", ()) or ())
        event_type = str(getattr(event, "event_type", "inventory_changed"))
        internet_change = "internet_exposed" in fields or bool(
            record and record.internet_exposed and event_type in {"asset_added", "software_added"}
        )
        severity = (
            "high" if internet_change
            else "medium" if event_type in {"asset_added", "software_added", "software_changed"}
            else "info"
        )
        target = getattr(event, "host", "") or (record.host if record else "")
        self._emit_notification(self._new_notification(
            kind="internet_exposed" if internet_change else event_type,
            severity=severity,
            title=(
                f"Asset exposure changed: {target}"
                if internet_change else event_type.replace("_", " ").title()
            ),
            summary=(
                f"Authorized inventory changed for {target or 'the active engagement'}. "
                f"Fields: {', '.join(fields) or 'record membership'}."
            ),
            subject_id=(
                getattr(event, "record_id", "")
                or _stable_id("inventory-subject", target)
            ),
            asset_id=getattr(event, "record_id", ""),
            target=target,
            unique=getattr(event, "event_id", "") or _utc_now(),
        ))

    def _enabled_notification_channels(self) -> Tuple[str, ...]:
        if hasattr(self, "notification_channels"):
            return tuple(
                name for name, checkbox in self.notification_channels.items()
                if checkbox.isChecked()
            )
        return tuple(self._settings()["notification_channels"])

    def _notification_adapters(self) -> List[Any]:
        factories = {
            "webhook": GenericWebhookAdapter,
            "slack": SlackWebhookAdapter,
            "teams": TeamsWebhookAdapter,
            "jira": JiraIssueAdapter,
            "smtp": SMTPEmailAdapter,
        }
        return [factories[name]() for name in self._enabled_notification_channels()]

    def _save_notification_settings(self, *_args, show_message: bool = True) -> None:
        channels = self._enabled_notification_channels()
        enabled = bool(self.notifications_enabled.isChecked())
        if not enabled:
            self.digest_enabled.setChecked(False)
        digest_enabled = enabled and bool(self.digest_enabled.isChecked())
        if enabled and not channels:
            QtWidgets.QMessageBox.warning(
                self.page,
                "Notification settings",
                "Select at least one connector, or disable outbound notifications.",
            )
            return
        self._save_settings(
            automation_notifications_enabled=enabled,
            automation_notification_channels=list(channels),
            automation_notification_min_severity=str(
                self.notification_min_severity.currentData()
            ),
            automation_digest_enabled=digest_enabled,
            automation_digest_hours=int(self.digest_hours.value()),
        )
        self._history_event(
            "Notification settings updated",
            detail=(
                f"enabled={enabled}; channels={','.join(channels) or 'none'}; "
                f"minimum={self.notification_min_severity.currentData()}; "
                f"digest_hours={self.digest_hours.value()}"
            ),
        )
        self._save_state()
        self._populate_history()
        self._update_digest_label()
        if show_message:
            QtWidgets.QMessageBox.information(
                self.page,
                "Notification settings",
                "Settings saved. Connector values remain environment-only.",
            )

    def _new_notification(
        self,
        *,
        kind: str,
        severity: str,
        title: str,
        summary: str,
        subject_id: str = "",
        asset_id: str = "",
        target: str = "",
        details: Optional[Mapping[str, Any]] = None,
        unique: str = "",
    ) -> NotificationEvent:
        return NotificationEvent(
            event_id=_stable_id(
                "notification", kind, subject_id or asset_id or target or title,
                unique or _utc_now(),
            ),
            kind=kind,
            severity=severity,
            title=title,
            summary=summary,
            subject_id=_bounded_text(subject_id, 128),
            asset_id=_bounded_text(asset_id, 128),
            target=target,
            details=dict(details or {}),
        )

    def _emit_notification(
        self, event: NotificationEvent, *, force: bool = False,
    ) -> None:
        self.notification_events.append(event)
        del self.notification_events[:-500]
        settings = self._settings()
        if not force and not settings["notifications_enabled"]:
            return
        adapters = self._notification_adapters()
        if not adapters:
            return
        try:
            tracker = DedupeTracker(
                DedupePolicy(
                    minimum_severity=settings["notification_min_severity"]
                ),
                store=self.delivery_store,
            )
            dispatcher = NotificationDispatcher(
                adapters, tracker=tracker, store=self.delivery_store
            )
        except DeliveryError as exc:
            self._history_event(
                "Notification configuration blocked", detail=_bounded_text(exc, 512)
            )
            return

        self._delivery_active += 1

        def worker():
            try:
                result = dispatcher.dispatch_event(event)
                self._delivery_events.put(("event", result, ""))
            except Exception:
                self._delivery_events.put((
                    "error", None, "Notification delivery failed safely."
                ))

        threading.Thread(target=worker, daemon=True).start()
        self.delivery_poll.start(150)

    def _dispatch_digest(self, digest: NotificationDigest, *, dry_run: bool) -> None:
        adapters = self._notification_adapters()
        if not adapters:
            QtWidgets.QMessageBox.warning(
                self.page, "Notifications", "Select at least one connector."
            )
            return
        try:
            dispatcher = NotificationDispatcher(
                adapters, store=self.delivery_store
            )
        except DeliveryError as exc:
            QtWidgets.QMessageBox.warning(
                self.page, "Notifications", _bounded_text(exc, 512)
            )
            return
        self._delivery_active += 1

        def worker():
            try:
                result = dispatcher.dispatch_digest(digest, dry_run=dry_run)
                self._delivery_events.put(("digest", result, ""))
            except Exception:
                self._delivery_events.put((
                    "error", None, "Notification connector validation failed safely."
                ))

        threading.Thread(target=worker, daemon=True).start()
        self.delivery_poll.start(150)

    def _drain_delivery(self) -> None:
        drained = 0
        while True:
            try:
                kind, result, message = self._delivery_events.get_nowait()
            except queue.Empty:
                break
            drained += 1
            self._delivery_active = max(0, self._delivery_active - 1)
            if kind == "error":
                self._history_event("Notification delivery failed", detail=message)
                continue
            deliveries = getattr(result, "deliveries", ())
            decision = getattr(result, "decision", None)
            detail = "; ".join(
                f"{item.adapter}={item.status}"
                + (f"({item.error_code})" if item.error_code else "")
                for item in deliveries
            ) or (
                f"decision={decision.action}" if decision is not None else "no delivery"
            )
            self._history_event(
                "Notification digest processed" if kind == "digest"
                else "Notification processed",
                detail=detail,
            )
        if self._delivery_active == 0:
            self.delivery_poll.stop()
        if drained:
            self._populate_delivery()
            self._populate_history()
            self._save_state()

    def _send_test_notification(self, *, dry_run: bool) -> None:
        if not self._enabled_notification_channels():
            QtWidgets.QMessageBox.warning(
                self.page, "Notifications", "Select at least one connector first."
            )
            return
        if not dry_run:
            answer = QtWidgets.QMessageBox.question(
                self.page,
                "Send test notification",
                "Send one real test message through every selected connector?",
            )
            if answer != QtWidgets.QMessageBox.StandardButton.Yes:
                return
        event = self._new_notification(
            kind="connector_test",
            severity="high",
            title="Blackthorn Automation connector test",
            summary=(
                "This is an operator-requested connector test. No target traffic "
                "or exploit code was used."
            ),
            subject_id="connector-test",
            unique=uuid.uuid4().hex,
        )
        digest = NotificationDigest.from_events(
            [event],
            digest_id=_stable_id("digest", "connector-test", uuid.uuid4().hex),
            title="Blackthorn connector validation",
            period_start=event.occurred_at,
            period_end=event.occurred_at,
        )
        self._dispatch_digest(digest, dry_run=dry_run)

    def _maybe_send_digest(self) -> None:
        self._check_remediation_alerts()
        settings = self._settings()
        if (
            not settings["notifications_enabled"]
            or not settings["digest_enabled"]
            or not self.notification_events
        ):
            self._update_digest_label()
            return
        now = datetime.now(timezone.utc)
        try:
            last = datetime.fromisoformat(
                settings["last_digest_at"].replace("Z", "+00:00")
            ) if settings["last_digest_at"] else now - timedelta(
                hours=settings["digest_hours"]
            )
        except ValueError:
            last = now - timedelta(hours=settings["digest_hours"])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if now - last < timedelta(hours=settings["digest_hours"]):
            self._update_digest_label()
            return
        selected = tuple(
            event for event in self.notification_events
            if datetime.fromisoformat(
                event.occurred_at.replace("Z", "+00:00")
            ) >= last
        )
        if not selected:
            self._update_digest_label()
            return
        digest = NotificationDigest.from_events(
            selected,
            digest_id=_stable_id("digest", last.isoformat(), now.isoformat()),
            title="Blackthorn Automation digest",
            period_start=last.isoformat().replace("+00:00", "Z"),
            period_end=now.isoformat().replace("+00:00", "Z"),
        )
        self._save_settings(
            automation_last_digest_at=now.isoformat().replace("+00:00", "Z")
        )
        self._dispatch_digest(digest, dry_run=False)
        self._update_digest_label()

    def _update_digest_label(self) -> None:
        if not hasattr(self, "digest_next"):
            return
        settings = self._settings()
        if not settings["digest_enabled"]:
            self.digest_next.setText("Not scheduled")
            return
        try:
            last = datetime.fromisoformat(
                settings["last_digest_at"].replace("Z", "+00:00")
            ) if settings["last_digest_at"] else datetime.now(timezone.utc)
        except ValueError:
            last = datetime.now(timezone.utc)
        next_at = last + timedelta(hours=settings["digest_hours"])
        self.digest_next.setText(next_at.astimezone().strftime("%Y-%m-%d %H:%M"))

    def _check_remediation_alerts(self) -> None:
        for item in self.remediations:
            if sla_state(item) == "overdue":
                self._emit_notification(self._new_notification(
                    kind="remediation_overdue",
                    severity="high",
                    title=f"Remediation SLA overdue: {item.advisory_id}",
                    summary=(
                        f"Remediation {item.remediation_id} is overdue and remains "
                        f"{item.status}. Owner: {item.owner or 'unassigned'}."
                    ),
                    subject_id=item.remediation_id,
                    asset_id=item.record_id,
                    unique=item.sla_due,
                ))
            if exception_expired(item):
                self._emit_notification(self._new_notification(
                    kind="exception_expired",
                    severity="critical",
                    title=f"Accepted-risk exception expired: {item.advisory_id}",
                    summary=(
                        f"The exception for {item.remediation_id} expired at "
                        f"{item.exception_expiry}. Reassess or reopen remediation."
                    ),
                    subject_id=item.remediation_id,
                    asset_id=item.record_id,
                    unique=item.exception_expiry,
                ))

    def _record_feed_health(self, snapshot: Any) -> None:
        failures = {failure.source: failure for failure in snapshot.failures}
        for source, status in snapshot.source_status.items():
            try:
                if status == "ok":
                    self.feed_health.record_success(
                        source, data_timestamp=snapshot.generated_at
                    )
                elif status == "partial":
                    self.feed_health.record_success(
                        source, data_timestamp=snapshot.generated_at
                    )
                    self.feed_health.record_failure(
                        source, error_code="partial_feed"
                    )
                elif status == "unavailable":
                    failure = failures.get(source)
                    self.feed_health.record_failure(
                        source,
                        error_code=(
                            "retryable_fetch_failed"
                            if failure and failure.retryable else "fetch_failed"
                        ),
                    )
            except DeliveryError:
                continue

    def _queue_item(self, item_id: str) -> Optional[dict]:
        return next((item for item in self.queue if item.get("id") == item_id), None)

    def _show_queue_preview(self) -> None:
        item = self._queue_item(str(self._selected_data(self.queue_table) or ""))
        if not item:
            self.queue_preview.clear()
            return
        preview = {
            "target": item.get("target"),
            "advisory": item.get("advisory"),
            "assessment": "potentially affected — verification required",
            "planned_impact": "safe",
            "signed_recipes": item.get("recipe_ids") or [],
            "manifest_hash": item.get("manifest_hash") or "not prepared",
            "timeout_seconds": item.get("timeout_seconds") or "—",
            "request_budget": item.get("request_budget") or "—",
            "approval": "required",
            "approval_expiry": "5 minutes after explicit approval",
            "scope_check": "re-evaluated immediately before execution",
            "recipe_integrity": "Ed25519-signed built-in registry; exact manifest locked",
            "automatic_exploit_execution": False,
        }
        self.queue_preview.setPlainText(json.dumps(preview, indent=2))

    # ---- intelligence and matching -----------------------------------
    def _start_refresh(self, reason: str) -> None:
        if self.refreshing or self._settings()["paused"]:
            return
        _engagement, _assets, packages = self._authorized_inventory()
        days = self._settings()["days"]
        self.refreshing = True
        self.refresh_button.setEnabled(False)
        self.status_label.setText("Refreshing fixed public intelligence feeds…")

        def worker():
            try:
                snapshot = refresh_intelligence(
                    days=days,
                    package_inventory=packages or None,
                )
                self._refresh_events.put(("done", reason, snapshot))
            except Exception:
                self._refresh_events.put((
                    "error", reason,
                    "Public intelligence refresh failed; cached data is unchanged.",
                ))

        threading.Thread(target=worker, daemon=True).start()
        self.refresh_poll.start(100)

    def _drain_refresh(self) -> None:
        try:
            kind, reason, payload = self._refresh_events.get_nowait()
        except queue.Empty:
            return
        self.refresh_poll.stop()
        self.refreshing = False
        self.refresh_button.setEnabled(True)
        if kind == "error":
            self.status_label.setText(str(payload))
            self._history_event("Intelligence refresh failed", detail=str(payload))
            self._save_state()
            self._populate_history()
            return
        snapshot = payload
        previous_signals = {signal.identifier: signal for signal in self.signals}
        self.signals = deduplicate_signals(list(self.signals) + list(snapshot.signals))
        self.source_status.update(snapshot.source_status)
        self.direct_matches = list(snapshot.direct_matches)
        self.failures = [
            f"{failure.source}: {failure.message}" for failure in snapshot.failures
        ]
        self._record_feed_health(snapshot)
        self._history_event(
            "Public intelligence refreshed",
            detail=(
                f"{len(snapshot.signals)} normalized signal(s); "
                f"{len(snapshot.failures)} source failure(s); trigger={reason}"
            ),
        )
        self._recompute_matches(run_rules=True)
        matched_signals = {match.signal_id for match in self.matches}
        new_for_rules: List[ExploitSignal] = []
        updated_for_rules: List[ExploitSignal] = []
        for signal in snapshot.signals:
            previous = previous_signals.get(signal.identifier)
            if previous is None:
                new_for_rules.append(signal)
            if previous and any((
                signal.modified_at != previous.modified_at,
                signal.severity != previous.severity,
                signal.known_exploited != previous.known_exploited,
                signal.epss_score != previous.epss_score,
            )):
                updated_for_rules.append(signal)
            if signal.identifier not in matched_signals:
                continue
            if signal.known_exploited and not (
                previous and previous.known_exploited
            ):
                self._emit_notification(self._new_notification(
                    kind="new_kev",
                    severity="critical",
                    title=f"Known-exploited exposure: {signal.cve_id or signal.identifier}",
                    summary=(
                        "CISA known-exploited status now correlates with at least one "
                        "authorized inventory asset. Review the exact evidence and SLA."
                    ),
                    subject_id=signal.identifier,
                    unique=signal.modified_at or snapshot.generated_at,
                    details={"known_exploited": True},
                ))
            old_epss = previous.epss_score if previous else None
            if (
                signal.epss_score is not None
                and old_epss is not None
                and signal.epss_score - old_epss >= 0.15
            ):
                self._emit_notification(self._new_notification(
                    kind="epss_spike",
                    severity="high",
                    title=f"EPSS increased: {signal.cve_id or signal.identifier}",
                    summary=(
                        f"EPSS rose from {old_epss:.2f} to {signal.epss_score:.2f} "
                        "for an advisory matched to authorized inventory."
                    ),
                    subject_id=signal.identifier,
                    unique=f"{old_epss:.4f}:{signal.epss_score:.4f}",
                ))
        if new_for_rules and not self._settings()["paused"]:
            self._run_rules(
                silent=True,
                event="new_signal",
                signals=new_for_rules,
            )
        if updated_for_rules and not self._settings()["paused"]:
            self._run_rules(
                silent=True,
                event="signal_updated",
                signals=updated_for_rules,
            )
        self._check_remediation_alerts()
        self._save_state()
        self._populate_all()
        self._schedule_next_label()

    def _recompute_matches(self, *_args, run_rules: bool = True) -> None:
        engagement, assets, _packages = self._authorized_inventory()
        self.assets = {asset.asset_id: asset for asset in assets}
        if engagement is None:
            self.matches = []
        else:
            matches = match_authorized_assets(self.signals, assets)
            matches.extend(
                replace(match, asset_name=self.assets[match.asset_id].name)
                if match.asset_id in self.assets else match
                for match in self.direct_matches
                if match.asset_id in self.assets
            )
            deduped: Dict[Tuple[str, str], ExposureMatch] = {}
            for match in matches:
                key = (match.asset_id, match.signal_id)
                existing = deduped.get(key)
                if (
                    existing is None
                    or match.priority > existing.priority
                    or (
                        match.priority == existing.priority
                        and match.source == "osv_package_query"
                        and existing.source != "osv_package_query"
                    )
                ):
                    deduped[key] = match
            self.matches = sorted(
                deduped.values(), key=lambda item: (-item.priority, item.asset_name, item.signal_id)
            )
        current_state: Dict[Tuple[str, str], str] = {}
        for match in self.matches:
            context = self._match_evaluation(match)
            key = (match.asset_id, match.cve_id or match.signal_id)
            current_state[key] = context["classification"]
            previous_classification = self._known_match_state.get(key)
            if not self._match_state_initialized:
                continue
            order = {"not_affected": 0, "possible": 1, "likely": 2, "exact": 3}
            is_new = previous_classification is None
            increased = (
                previous_classification is not None
                and order[context["classification"]] > order[previous_classification]
            )
            if is_new or increased:
                risk = context["risk"]
                self._emit_notification(self._new_notification(
                    kind="vulnerable_version" if is_new else "exposure_increased",
                    severity=risk.rating,
                    title=(
                        f"New exposure match: {key[1]}"
                        if is_new else f"Exposure confidence increased: {key[1]}"
                    ),
                    summary=(
                        f"{match.asset_name} is {context['classification_label'].lower()}; "
                        f"explainable risk score {risk.score}/100. {context['reason']}"
                    ),
                    subject_id=_stable_id("exposure", *key),
                    asset_id=match.asset_id,
                    target=match.asset_name,
                    unique=f"{previous_classification}:{context['classification']}",
                    details={"risk_score": risk.score, "classification": context["classification"]},
                ))
                remediation = self._remediation_for(*key)
                if remediation and remediation.status == RemediationStatus.RESOLVED.value:
                    try:
                        reopened = transition_remediation(
                            remediation,
                            RemediationStatus.OPEN.value,
                            owner=remediation.owner,
                            note="Exposure reappeared after resolution",
                        )
                        self._replace_remediation(reopened)
                        self._emit_notification(self._new_notification(
                            kind="regression",
                            severity="critical" if risk.rating == "critical" else "high",
                            title=f"Resolved exposure regressed: {key[1]}",
                            summary=(
                                f"{match.asset_name} matched again after remediation was "
                                "marked Resolved. The case was reopened automatically."
                            ),
                            subject_id=remediation.remediation_id,
                            asset_id=match.asset_id,
                            target=match.asset_name,
                            unique=_utc_now(),
                        ))
                    except InventoryValidationError:
                        pass
        self._known_match_state = current_state
        self._match_state_initialized = True
        self._populate_matches()
        self._update_metrics()
        if run_rules and not self._settings()["paused"]:
            self._run_rules(silent=True, event="exposure_match")

    # ---- rules and queue ----------------------------------------------
    def _toggle_rule(self, rule_id: str, enabled: bool) -> None:
        self.rules = [
            AutomationRule(**{**asdict(rule), "enabled": bool(enabled)})
            if rule.rule_id == rule_id else rule
            for rule in self.rules
        ]
        self._save_state()

    def _add_rule(self) -> None:
        name = self.rule_name.text().strip()
        if not name:
            QtWidgets.QMessageBox.information(self.page, "Automation rule", "Enter a rule name.")
            return
        action = str(self.rule_action.currentData())
        require_asset = self.rule_asset.isChecked() or action != "alert"
        rule = AutomationRule(
            rule_id=_stable_id("rule", name, uuid.uuid4().hex),
            name=name,
            action=action,
            event=str(self.rule_event.currentData()),
            min_severity=str(self.rule_severity.currentData()),
            min_epss=float(self.rule_epss.value()),
            require_known_exploited=self.rule_kev.isChecked(),
            require_asset_match=require_asset,
        )
        try:
            from .exploit_intelligence import validate_rule
            rule = validate_rule(rule)
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self.page, "Automation rule", str(exc))
            return
        self.rules.append(rule)
        self.rule_name.clear()
        self._history_event("Automation rule added", detail=rule.name)
        self._save_state()
        self._populate_rules()
        self._populate_history()

    def _remove_rule(self) -> None:
        rule_id = self._selected_data(self.rules_table, 1)
        if not rule_id:
            return
        self.rules = [rule for rule in self.rules if rule.rule_id != rule_id]
        self._history_event("Automation rule removed", detail=str(rule_id))
        self._save_state()
        self._populate_rules()
        self._populate_history()

    def _run_rules(
        self, *_args, silent: bool = False, event: Optional[str] = None,
        signals: Optional[Iterable[ExploitSignal]] = None,
    ) -> None:
        if self._settings()["paused"]:
            if not silent:
                QtWidgets.QMessageBox.information(self.page, "Automation paused", "Resume automation first.")
            return
        signal_rows = list(signals) if signals is not None else self.signals
        decisions = evaluate_rules(
            self.rules, signal_rows, self.matches, event=event
        )
        match_map = {(item.signal_id, item.asset_id): item for item in self.matches}
        existing_decisions = {
            str(item.get("decision_id") or "") for item in self.queue + self.history
        }
        signal_map = {signal.identifier: signal for signal in signal_rows}
        created = 0
        for decision in decisions:
            if decision.decision_id in existing_decisions:
                continue
            rule = next((item for item in self.rules if item.rule_id == decision.rule_id), None)
            signal = signal_map.get(decision.signal_id)
            match = match_map.get((decision.signal_id, decision.asset_id))
            advisory = signal.cve_id or signal.identifier if signal else decision.signal_id
            if decision.action == "alert":
                self._history_event(
                    "Automation alert",
                    target=match.asset_name if match else "",
                    advisory=advisory,
                    detail=rule.name if rule else decision.rule_id,
                    decision_id=decision.decision_id,
                )
                if signal is not None:
                    self._emit_notification(self._new_notification(
                        kind="automation_rule",
                        severity=signal.severity,
                        title=(
                            f"Automation rule matched: "
                            f"{rule.name if rule else decision.rule_id}"
                        ),
                        summary=(
                            f"{advisory} matched the configured rule"
                            + (f" for {match.asset_name}." if match else ".")
                        ),
                        subject_id=decision.decision_id,
                        asset_id=match.asset_id if match else "",
                        target=match.asset_name if match else "",
                        unique=signal.modified_at or signal.published_at,
                    ))
                created += 1
                continue
            if match is None:
                continue
            self._append_queue(
                match,
                rule_name=rule.name if rule else decision.rule_id,
                decision_id=decision.decision_id,
            )
            created += 1
        if created:
            self._save_state()
        self._populate_queue()
        self._populate_history()
        self._update_metrics()
        if not silent:
            QtWidgets.QMessageBox.information(
                self.page, "Automation rules", f"Created {created} new alert or approval item(s)."
            )

    def _append_queue(
        self, match: ExposureMatch, *, rule_name: str, decision_id: str = "",
    ) -> bool:
        engagement_id = self.inventory_engagement_id
        if not engagement_id:
            self._history_event(
                "Validation queue blocked",
                target=match.asset_name,
                advisory=match.cve_id or match.signal_id,
                detail="No active engagement is bound to the inventory match.",
            )
            return False
        item_id = _stable_id(
            "queue", engagement_id, match.asset_id, match.signal_id, rule_name
        )
        if any(item.get("id") == item_id for item in self.queue):
            return False
        advisory = match.cve_id or match.signal_id
        signal = next((
            item for item in self.signals if item.identifier == match.signal_id
        ), None)
        try:
            recipes = match_validator_recipes(
                signal,
                advisory_ids=(advisory,),
                categories=("advisory",),
            )
            manifest = create_validation_manifest(
                recipe.recipe_id for recipe in recipes
            )
        except (ValueError, ValidationSecurityError) as exc:
            self._history_event(
                "Validation recipe blocked",
                target=match.asset_name,
                advisory=advisory,
                detail=_bounded_text(exc, 512),
            )
            return False
        self.queue.insert(0, {
            "id": item_id,
            "decision_id": decision_id,
            "match_id": match.match_id,
            "asset_id": match.asset_id,
            "engagement_id": engagement_id,
            "signal_id": match.signal_id,
            "target": match.asset_name,
            "advisory": advisory,
            "rule": _bounded_text(rule_name, 256),
            "impact": "safe",
            "recipe_ids": list(manifest.recipe_ids),
            "manifest_hash": manifest.manifest_hash,
            "timeout_seconds": manifest.timeout_seconds,
            "request_budget": manifest.request_budget,
            "status": "awaiting_approval",
            "created_at": _utc_now(),
            "rationale": "; ".join(match.reasons),
        })
        self._history_event(
            "Safe validation queued",
            target=match.asset_name,
            advisory=advisory,
            detail=rule_name,
            decision_id=decision_id,
        )
        return True

    def _queue_selected_match(self) -> None:
        match = self._selected_data(self.match_table)
        if not isinstance(match, ExposureMatch):
            QtWidgets.QMessageBox.information(self.page, "Exposure match", "Select a match first.")
            return
        engagement, reason = _active_engagement(self.host)
        if engagement is None or not _scope_allows(match.asset_name, engagement):
            QtWidgets.QMessageBox.warning(self.page, "Scope required", reason or "Target is outside scope.")
            return
        self._append_queue(match, rule_name="Manual analyst queue")
        self._save_state()
        self._populate_queue()
        self._populate_history()
        self._update_metrics()

    def _approve_selected_queue(self) -> None:
        if self._settings()["paused"]:
            QtWidgets.QMessageBox.information(self.page, "Automation paused", "Resume automation first.")
            return
        item = self._queue_item(str(self._selected_data(self.queue_table) or ""))
        if not item:
            QtWidgets.QMessageBox.information(self.page, "Validation queue", "Select an item first.")
            return
        active_run_id = str(item.get("run_id") or "")
        if active_run_id and active_run_id in self._validation_grants:
            QtWidgets.QMessageBox.information(
                self.page,
                "Validation already active",
                "This queue item already has an authorized or running validation.",
            )
            return
        engagement, reason = _active_engagement(self.host)
        target = str(item.get("target") or "")
        queued_engagement = str(item.get("engagement_id") or "")
        current_engagement = str(engagement.get("id") or "") if engagement else ""
        if not queued_engagement or queued_engagement != current_engagement:
            item["status"] = "blocked_engagement"
            self._history_event(
                "Validation blocked by engagement",
                target=target,
                advisory=str(item.get("advisory") or ""),
                detail=(
                    "The queue item is not bound to the current engagement; "
                    "recompute the match and create a new approval item."
                ),
            )
            self._save_state(); self._populate_queue(); self._populate_history()
            QtWidgets.QMessageBox.warning(
                self.page,
                "Validation blocked",
                "This queue item belongs to a different or legacy engagement. "
                "Recompute the match and queue it again.",
            )
            return
        if engagement is None or not _scope_allows(target, engagement):
            item["status"] = "blocked_scope"
            self._history_event(
                "Validation blocked by scope", target=target,
                advisory=str(item.get("advisory") or ""), detail=reason,
            )
            self._save_state()
            self._populate_queue()
            self._populate_history()
            QtWidgets.QMessageBox.warning(
                self.page, "Validation blocked", reason or "The target is outside current scope."
            )
            return
        try:
            parsed_target = urlsplit(target)
        except ValueError:
            parsed_target = None
        if (
            parsed_target is None
            or parsed_target.scheme.lower() not in {"http", "https"}
            or not parsed_target.hostname
        ):
            item["status"] = "blocked_no_url"
            self._save_state()
            self._populate_queue()
            QtWidgets.QMessageBox.warning(
                self.page,
                "Validated URL required",
                "Safe validation requires the exact observed HTTP(S) URL. "
                "Sync Discover or bind the inventory component to that URL; "
                "Blackthorn will not invent a scheme for a bare host.",
            )
            return
        signal = next((
            row for row in self.signals
            if row.identifier == item.get("signal_id")
            or item.get("advisory") in {row.identifier, row.cve_id}
        ), None)
        try:
            recipe_ids = tuple(item.get("recipe_ids") or ())
            if not recipe_ids:
                recipe_ids = tuple(
                    recipe.recipe_id for recipe in match_validator_recipes(
                        signal,
                        advisory_ids=(item.get("advisory"),),
                        categories=("advisory",),
                    )
                )
            manifest = create_validation_manifest(recipe_ids)
            if item.get("manifest_hash") and item["manifest_hash"] != manifest.manifest_hash:
                raise ValidationSecurityError(
                    "queued validation manifest no longer matches the signed registry"
                )
            pipeline = build_safe_pipeline(manifest)
            assert_safe_pipeline(pipeline, manifest)
            operator = _bounded_text(
                getattr(self.host, "_prefs", {}).get("analyst_name")
                or getpass.getuser()
                or "local-operator",
                128,
            )
            request = self.validation_controller.request_validation(
                target,
                str(engagement.get("id")),
                manifest,
                requested_by=operator,
                ttl_seconds=10 * 60,
            )
        except (ValueError, ValidationSecurityError) as exc:
            item["status"] = "blocked_manifest"
            self._history_event(
                "Validation blocked by manifest",
                target=target,
                advisory=str(item.get("advisory") or ""),
                detail=_bounded_text(exc, 512),
            )
            self._save_state()
            self._populate_queue()
            QtWidgets.QMessageBox.warning(
                self.page, "Validation blocked", _bounded_text(exc, 512)
            )
            return
        answer = QtWidgets.QMessageBox.question(
            self.page,
            "Approve safe validation",
            f"Approve the signed safe validation for:\n\n{target}\n\n"
            f"Recipes: {', '.join(manifest.recipe_ids)}\n"
            f"Manifest: {manifest.manifest_hash[:20]}…\n"
            f"Timeout: {manifest.timeout_seconds}s · budget marker: "
            f"{manifest.request_budget} requests\n\n"
            "Approval expires in five minutes. Scope and exclusions are checked "
            "again immediately before execution.",
        )
        if answer != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            approval = self.validation_controller.approve(
                request.request_id,
                approved_by=operator,
                ttl_seconds=5 * 60,
            )
        except ValidationSecurityError as exc:
            QtWidgets.QMessageBox.warning(
                self.page, "Approval failed", _bounded_text(exc, 512)
            )
            return
        item["status"] = "approved"
        item["approved_at"] = _utc_now()
        item["approval_id"] = approval.approval_id
        item["request_id"] = request.request_id
        item["recipe_ids"] = list(manifest.recipe_ids)
        item["manifest_hash"] = manifest.manifest_hash
        item["approval_expires_at"] = datetime.fromtimestamp(
            approval.expires_at, timezone.utc
        ).isoformat().replace("+00:00", "Z")
        self._history_event(
            "Safe validation approved",
            target=target,
            advisory=str(item.get("advisory") or ""),
            detail=(
                f"Operator={operator}; manifest={manifest.manifest_hash}; "
                "expiring approval recorded."
            ),
        )
        self._save_state()
        self._populate_queue()

        grant_box: Dict[str, Any] = {}

        def preflight(run_target, proposed_pipeline):
            if run_target != request.target:
                return False, "The approved target was changed."
            try:
                assert_safe_pipeline(proposed_pipeline, manifest)
                database = getattr(self.host, "_db", None)
                if database is None:
                    raise ValidationSecurityError("engagement database is unavailable")
                scope_check = engagement_scope_recheck(
                    lambda engagement_id: database.get_engagement(int(engagement_id))
                )
                grant = self.validation_controller.begin_run(
                    approval.approval_id,
                    scope_recheck=scope_check,
                )
                assert_safe_pipeline(grant.build_pipeline(), manifest)
                grant_box["grant"] = grant
                self._validation_grants[grant.run_id] = grant
                item["run_id"] = grant.run_id
                item["status"] = "authorized"
                self._save_state()
                self._populate_queue()
                return True, ""
            except (ValueError, ValidationSecurityError) as exc:
                item["status"] = "blocked_preflight"
                self._history_event(
                    "Validation preflight blocked",
                    target=target,
                    advisory=str(item.get("advisory") or ""),
                    detail=_bounded_text(exc, 512),
                )
                self._save_state()
                self._populate_queue()
                self._populate_history()
                return False, _bounded_text(exc, 512)

        def started(_target, worker):
            grant = grant_box.get("grant")
            if grant is None:
                return False
            item["status"] = "running"
            self._validation_workers[grant.run_id] = worker
            self._history_event(
                "Safe validation started", target=target,
                advisory=str(item.get("advisory") or ""),
                detail=(
                    f"run={grant.run_id}; timeout={grant.timeout_seconds}s; "
                    f"manifest={manifest.manifest_hash}"
                ),
            )
            timer = QtCore.QTimer(self.page)
            timer.setSingleShot(True)

            def timed_out():
                if grant.run_id not in self._validation_grants:
                    return
                self.validation_controller.cancel_run(
                    grant.run_id, "validation timed out"
                )
                try:
                    self.validation_controller.complete_run(
                        grant.run_id, status="timed_out"
                    )
                except ValueError:
                    pass
                item["status"] = "timed_out"
                run_worker = self._validation_workers.get(grant.run_id)
                if run_worker is not None:
                    try:
                        run_worker.abort()
                    except Exception:
                        pass
                self._history_event(
                    "Safe validation timed out", target=target,
                    advisory=str(item.get("advisory") or ""),
                )
                self._save_state()
                self._populate_queue()
                self._populate_history()

            timer.timeout.connect(timed_out)
            timer.start(int(grant.timeout_seconds * 1000))
            self._validation_timers[grant.run_id] = timer
            self._save_state(); self._populate_queue(); self._populate_history()
            return True

        def finished(_target, _worker, outcome):
            grant = grant_box.get("grant")
            if grant is None:
                return
            timer = self._validation_timers.pop(grant.run_id, None)
            if timer is not None:
                timer.stop()
                timer.deleteLater()
            self._validation_workers.pop(grant.run_id, None)
            if item.get("status") == "timed_out":
                final_status = "timed_out"
            elif grant.cancellation.cancelled:
                final_status = "cancelled"
            elif not isinstance(outcome, Mapping) or outcome.get("ok") is not True:
                final_status = "failed"
            else:
                final_status = "completed"
            try:
                self.validation_controller.complete_run(
                    grant.run_id, status=final_status
                )
            except ValueError:
                pass
            self._validation_grants.pop(grant.run_id, None)
            item["status"] = (
                "needs_review" if final_status == "completed" else final_status
            )
            self._history_event(
                "Safe validation finished", target=target,
                advisory=str(item.get("advisory") or ""),
                detail=(
                    f"status={final_status}; review generated evidence before "
                    "changing the exposure assessment."
                    + (
                        f" Runner state={_bounded_text(outcome.get('state'), 64)}."
                        if isinstance(outcome, Mapping) and outcome.get("state")
                        else ""
                    )
                ),
            )
            self._save_state(); self._populate_queue(); self._populate_history()

        def stopped(_target, _worker):
            grant = grant_box.get("grant")
            if grant is None:
                return
            self.validation_controller.cancel_run(
                grant.run_id, "operator requested stop"
            )
            item["status"] = "cancelling"
            self._history_event(
                "Safe validation stop requested", target=target,
                advisory=str(item.get("advisory") or ""),
            )
            self._save_state()
            self._populate_queue()
            self._populate_history()

        def is_cancelled():
            grant = grant_box.get("grant")
            return bool(grant is not None and grant.cancellation.cancelled)

        self.host._show_pipeline_builder(
            initial_target=target,
            initial_pipeline=pipeline,
            automation_safe=True,
            automation_preflight=preflight,
            automation_is_cancelled=is_cancelled,
            on_started=started,
            on_finished=finished,
            on_stopped=stopped,
        )
        if grant_box.get("grant") is None and item.get("status") == "approved":
            item["status"] = "awaiting_approval"
            item.pop("approval_id", None)
            item.pop("request_id", None)
            item.pop("approval_expires_at", None)
            self._save_state()
            self._populate_queue()

    def _dismiss_selected_queue(self) -> None:
        item = self._queue_item(str(self._selected_data(self.queue_table) or ""))
        if not item:
            return
        run_id = str(item.get("run_id") or "")
        if run_id and run_id in self._validation_grants:
            QtWidgets.QMessageBox.information(
                self.page,
                "Validation active",
                "Stop the active validation before dismissing this queue item.",
            )
            return
        item["status"] = "dismissed"
        self._history_event(
            "Validation dismissed",
            target=str(item.get("target") or ""),
            advisory=str(item.get("advisory") or ""),
        )
        self._save_state(); self._populate_queue(); self._populate_history(); self._update_metrics()

    # ---- pause and schedule -------------------------------------------
    def _update_pause_button(self) -> None:
        paused = self._settings()["paused"]
        self.pause_button.setText("Resume automation" if paused else "Pause all automation")
        self.pause_button.setChecked(paused)

    def _toggle_pause(self, paused: bool) -> None:
        self._save_settings(automation_paused=bool(paused))
        if paused:
            self.watch_timer.stop()
            self.validation_controller.engage_kill_switch(
                "Automation paused by the local operator"
            )
            for worker in tuple(self._validation_workers.values()):
                try:
                    worker.abort()
                except Exception:
                    pass
            self._history_event(
                "Automation paused",
                detail="Feed schedules stopped and any active automation pipeline received a stop request.",
            )
        else:
            self.validation_controller.reset_kill_switch()
            self._history_event("Automation resumed")
            self._apply_watch_schedule()
        self._save_state(); self._populate_history(); self._update_pause_button()

    def _save_watch_schedule(self) -> None:
        self._save_settings(
            automation_watch_enabled=self.watch_enabled.isChecked(),
            automation_watch_minutes=int(self.watch_minutes.value()),
            automation_feed_days=int(self.watch_days.value()),
        )
        self._history_event(
            "Intelligence watch updated",
            detail=(
                f"enabled={self.watch_enabled.isChecked()}, "
                f"interval={self.watch_minutes.value()} minutes, "
                f"window={self.watch_days.value()} days"
            ),
        )
        self._save_state(); self._populate_history(); self._apply_watch_schedule()

    def _apply_watch_schedule(self) -> None:
        if not hasattr(self, "watch_timer"):
            return
        settings = self._settings()
        self.watch_enabled.setChecked(settings["watch_enabled"])
        self.watch_minutes.setValue(settings["watch_minutes"])
        self.watch_days.setValue(settings["days"])
        self.watch_timer.stop()
        if settings["watch_enabled"] and not settings["paused"]:
            self.watch_timer.start(settings["watch_minutes"] * 60 * 1000)
        self._schedule_next_label()

    def _schedule_next_label(self) -> None:
        settings = self._settings()
        if not settings["watch_enabled"] or settings["paused"]:
            self.next_refresh.setText("Paused" if settings["paused"] else "Not scheduled")
            return
        next_time = QtCore.QDateTime.currentDateTime().addSecs(settings["watch_minutes"] * 60)
        self.next_refresh.setText(next_time.toString("yyyy-MM-dd HH:mm"))

    @property
    def refresh_poll(self):
        timer = getattr(self, "_refresh_poll", None)
        if timer is None:
            timer = QtCore.QTimer(self.page)
            timer.timeout.connect(self._drain_refresh)
            self._refresh_poll = timer
        return timer

    @property
    def delivery_poll(self):
        timer = getattr(self, "_delivery_poll", None)
        if timer is None:
            timer = QtCore.QTimer(self.page)
            timer.timeout.connect(self._drain_delivery)
            self._delivery_poll = timer
        return timer


def build_automation_page(host: Any, save_prefs=None):
    """Build and retain a stateful Automation page for the main window."""
    controller = AutomationPageController(host, save_prefs=save_prefs)
    host._automation_controller = controller
    return controller.page


__all__ = [
    "AUTOMATION_STATE_FILENAME",
    "AutomationPageController",
    "build_automation_page",
    "collect_authorized_inventory",
]
