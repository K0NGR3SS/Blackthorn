"""Small offscreen smoke test for the real Qt results workspace."""

import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def test_results_workspace_builds_with_evidence_actions(monkeypatch):
    from PySide6.QtWidgets import QApplication, QPushButton, QTreeWidget

    import wafpierce.database as database
    import wafpierce.gui as gui

    class _DB:
        def __init__(self, *args, **kwargs):
            pass

        def list_engagements(self):
            return []

        def get_persistent_targets(self):
            return []

        def get_scan_queue(self):
            return []

    monkeypatch.setattr(database, 'WAFPierceDB', _DB)
    monkeypatch.setattr(gui, '_show_disclaimer_qt', lambda _app: True)
    monkeypatch.setattr(gui, '_load_prefs', lambda: {
        'language': 'en',
        'qt_geometry': '1200x760',
        'advanced': {},
        'scan_profile': 'standard',
    })
    monkeypatch.setattr(gui, '_save_prefs', lambda _prefs: None)

    inspected = {'ok': False}

    def inspect_then_exit(_app):
        window = next(
            widget for widget in QApplication.topLevelWidgets()
            if hasattr(widget, '_build_results_page')
        )
        window._results = [{
            'target': 'https://app.example.test',
            'technique': 'Paired SSTI canary',
            'category': 'SSTI',
            'severity': 'HIGH',
            'kind': 'finding',
            'verification_status': 'confirmed',
            'request': {
                'method': 'GET',
                'url': 'https://app.example.test/?q=probe',
                'headers': {},
            },
            'evidence': [{'type': 'execution_marker', 'matched': '49'}],
        }]
        page = window._build_results_page()
        page.show()
        QApplication.processEvents()

        assert page.objectName() == 'ResultsPage'
        buttons = {button.text(): button for button in page.findChildren(QPushButton)}
        assert {'Copy cURL', 'Copy Python', 'Send to Repeater',
                'Re-test request', 'Save state'} <= set(buttons)
        tree = next(
            tree for tree in page.findChildren(QTreeWidget)
            if tree.columnCount() == 4
        )
        tree.setCurrentItem(tree.topLevelItem(0).child(0))
        QApplication.processEvents()
        assert buttons['Re-test request'].isEnabled()
        inspected['ok'] = True
        page.close()
        return 0

    monkeypatch.setattr(QApplication, 'exec', inspect_then_exit)

    with pytest.raises(SystemExit) as stopped:
        gui.main()

    assert stopped.value.code == 0
    assert inspected['ok']
