from types import SimpleNamespace

from wafpierce.automation_ui import AutomationPageController, collect_authorized_inventory


class _DB:
    def __init__(self, engagement):
        self.engagement = engagement

    def get_engagement(self, engagement_id):
        assert engagement_id == 7
        return self.engagement


def test_inventory_is_fail_closed_without_an_active_engagement():
    host = SimpleNamespace(
        _current_engagement_id=None,
        _prefs={},
        _db=None,
        _results=[{
            "target": "https://app.example.test",
            "technology": "nginx",
        }],
    )

    engagement, assets, packages = collect_authorized_inventory(host)

    assert engagement is None
    assert assets == []
    assert packages == []


def test_inventory_only_emits_currently_authorized_technology_and_packages():
    host = SimpleNamespace(
        _current_engagement_id=7,
        _prefs={},
        _db=_DB({
            "id": 7,
            "name": "Example",
            "status": "active",
            "scope": ["https://app.example.test"],
            "exclusions": ["https://app.example.test/logout"],
        }),
        _recon_state={
            "report": {
                "stages": {
                    "hosts": [
                        {
                            "hostname": "app.example.test",
                            "http_url": "https://app.example.test",
                            "server": "nginx 1.25",
                            "technologies": ["Django 5"],
                        },
                        {
                            "hostname": "outside.example.test",
                            "http_url": "https://outside.example.test",
                            "technologies": ["WordPress"],
                        },
                    ],
                    "http": [],
                },
            },
        },
        _results=[
            {
                "target": "https://app.example.test",
                "details": {
                    "package": {
                        "name": "jinja2",
                        "version": "3.1.2",
                        "ecosystem": "PyPI",
                    },
                },
            },
            {
                "target": "https://app.example.test/logout",
                "technology": "Excluded Product",
            },
        ],
    )

    engagement, assets, packages = collect_authorized_inventory(host)

    assert engagement["id"] == 7
    assert len(assets) == 1
    assert assets[0].authorized is True
    assert assets[0].name == "https://app.example.test"
    assert "nginx 1.25" in assets[0].technology_text
    assert "Django 5" in assets[0].technology_text
    assert len(packages) == 1
    assert packages[0].authorized is True
    assert packages[0].name == "jinja2"
    assert packages[0].version == "3.1.2"


def test_outbound_notification_opt_in_requires_exact_boolean_true():
    controller = object.__new__(AutomationPageController)
    controller.host = SimpleNamespace(_prefs={
        "automation_notifications_enabled": "false",
        "automation_digest_enabled": "1",
        "automation_watch_enabled": "true",
    })

    settings = controller._settings()

    assert settings["notifications_enabled"] is False
    assert settings["digest_enabled"] is False
    assert settings["watch_enabled"] is False
