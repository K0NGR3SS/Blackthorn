"""Small offscreen smoke test for the real Qt results workspace."""

import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def test_results_workspace_builds_with_evidence_actions(monkeypatch):
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QLabel, QLineEdit, QListWidget,
        QPlainTextEdit, QPushButton, QSplitter, QTextBrowser, QTreeWidget,
        QTreeWidgetItem,
    )
    from PySide6.QtCore import Qt

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

        def get_custom_payloads(self):
            return []

        def get_dashboard_stats(self):
            return {
                'total_scans': 2,
                'total_findings': 5,
                'total_bypasses': 1,
                'severity_distribution': {'HIGH': 1, 'INFO': 4},
                'top_techniques': [
                    {'technique': 'Discovered Host', 'count': 4},
                ],
                'recent_activity': [
                    {
                        'date': '2026-07-28',
                        'scans': 1,
                        'findings': 5,
                        'bypasses': 1,
                    },
                ],
                'top_targets': ['example.test'],
            }

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
        window.resize(760, 560)
        QApplication.processEvents()
        assert window.width() == 760
        assert window.height() == 560
        window.resize(1400, 900)
        QApplication.processEvents()
        assert window.width() == 1400
        assert window.height() == 900
        target_input = next(
            field for field in window.findChildren(QLineEdit)
            if field.accessibleName() == 'Target URL'
        )
        assert target_input.accessibleDescription()
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
        page.resize(880, 620)
        page.show()
        QApplication.processEvents()

        assert page.objectName() == 'ResultsPage'
        buttons = {button.text(): button for button in page.findChildren(QPushButton)}
        assert {'Copy cURL', 'Copy Python', 'Send to Repeater',
                'Re-test request', 'Save state'} <= set(buttons)
        assert all(
            buttons[label].accessibleName()
            for label in (
                'Copy cURL', 'Copy Python', 'Send to Repeater',
                'Re-test request', 'Save state',
            )
        )
        assert page.findChild(QListWidget).accessibleName() == 'Result targets'
        assert page.findChild(QTextBrowser).accessibleName() == 'Finding evidence'
        results_splitter = page.findChild(
            QSplitter, 'ResultsWorkspaceSplitter'
        )
        assert results_splitter is not None
        assert results_splitter.count() == 3
        tree = next(
            tree for tree in page.findChildren(QTreeWidget)
            if tree.columnCount() == 4
        )
        tree.setCurrentItem(tree.topLevelItem(0).child(0))
        QApplication.processEvents()
        assert buttons['Re-test request'].isEnabled()

        recon_page = window._build_recon_page()
        recon_page.resize(880, 720)
        recon_page.show()
        scope = next(
            field for field in recon_page.findChildren(QLineEdit)
            if field.accessibleName() == 'Discovery scope'
        )
        scope.setText('*.nubank.com.br')
        QApplication.processEvents()
        assert any(
            'Enumeration root: nubank.com.br' in label.text()
            for label in recon_page.findChildren(QLabel)
        )
        assert next(
            checkbox for checkbox in recon_page.findChildren(QCheckBox)
            if checkbox.text().startswith('Active ports')
        ).isChecked() is False
        host_inventory = next(
            tree for tree in recon_page.findChildren(QTreeWidget)
            if tree.accessibleName() == 'Discovered host inventory'
        )
        assert host_inventory.columnCount() == 6
        assert host_inventory.contextMenuPolicy() == Qt.CustomContextMenu
        status_filter = next(
            combo for combo in recon_page.findChildren(QComboBox)
            if combo.accessibleName() == 'Discovery status filter'
        )
        filter_labels = {
            status_filter.itemText(index)
            for index in range(status_filter.count())
        }
        assert {
            'Resolved only', 'HTTP 2xx', 'HTTP 3xx', 'HTTP 4xx', 'HTTP 5xx'
        } <= filter_labels
        live_item = QTreeWidgetItem([
            'api.example.test', 'Resolved', 'Live · 200',
            'https://api.example.test', '192.0.2.1', 'subfinder',
        ])
        live_item.setData(0, 257, {
            'hostname': 'api.example.test',
            'http_url': 'https://api.example.test',
            'ip_addresses': ['192.0.2.1'],
        })
        host_inventory.addTopLevelItem(live_item)
        host_inventory.itemDoubleClicked.emit(live_item, 3)
        QApplication.processEvents()
        assert QApplication.clipboard().text() == 'https://api.example.test'
        assert recon_page.findChild(
            QSplitter, 'DiscoveryVerticalSplitter'
        ) is not None

        report_page = window._build_dashboard_page()
        report_page.resize(780, 620)
        report_page.show()
        QApplication.processEvents()
        assert report_page.findChild(
            QSplitter, 'ReportTablesSplitter'
        ) is not None
        assert report_page.findChild(
            QSplitter, 'ReportSummarySplitter'
        ) is not None

        payload_page = window._build_payloads_page()
        payload_page.resize(1180, 820)
        payload_page.show()
        QApplication.processEvents()
        assert payload_page.objectName() == 'PayloadsPage'
        catalog = payload_page.findChild(
            QTreeWidget, 'PayloadCatalogTree'
        )
        assert catalog is not None
        assert catalog.topLevelItemCount() >= 8
        category_filter = payload_page.findChild(
            QComboBox, 'PayloadCategoryFilter'
        )
        category_filter.setCurrentIndex(category_filter.findData('sqli'))
        QApplication.processEvents()
        assert catalog.topLevelItemCount() == 1
        sql_node = catalog.topLevelItem(0)
        family_names = {
            sql_node.child(index).text(0)
            for index in range(sql_node.childCount())
        }
        assert {'Boolean / basic 1=1', 'UNION SELECT', 'Time based'} <= family_names
        union_node = next(
            sql_node.child(index)
            for index in range(sql_node.childCount())
            if sql_node.child(index).text(0) == 'UNION SELECT'
        )
        catalog.setCurrentItem(union_node.child(0))
        QApplication.processEvents()

        payload_target = payload_page.findChild(
            QLineEdit, 'PayloadTargetInput'
        )
        payload_target.setText('https://ctf.example.test/search')
        QApplication.processEvents()
        preview = payload_page.findChild(
            QPlainTextEdit, 'PayloadRequestPreview'
        )
        assert 'Host: ctf.example.test' in preview.toPlainText()
        assert 'Query parameter: q' in next(
            label.text() for label in payload_page.findChildren(QLabel)
            if label.objectName() == 'PayloadDestinationSummary'
        )
        payload_buttons = {
            button.text(): button
            for button in payload_page.findChildren(QPushButton)
        }
        assert {
            'Copy payload',
            'Copy cURL',
            'Test this family in Intruder',
            'Open exact request in Repeater',
        } <= set(payload_buttons)
        assert payload_buttons['Open exact request in Repeater'].isEnabled()
        payload_buttons['Copy cURL'].click()
        assert 'https://ctf.example.test/search' in QApplication.clipboard().text()
        repeater_prefill = {}
        original_repeater_load = window._repeater_load
        window._repeater_load = lambda request: repeater_prefill.update(request)
        payload_buttons['Open exact request in Repeater'].click()
        assert repeater_prefill['url'].startswith(
            'https://ctf.example.test/search?'
        )
        assert repeater_prefill['method'] == 'GET'
        window._repeater_load = original_repeater_load

        intruder_handoff = {}
        original_intruder_load = window._intruder_load
        window._intruder_load = lambda config, payloads, label: intruder_handoff.update({
            'config': config,
            'payloads': payloads,
            'label': label,
        })
        payload_buttons['Test this family in Intruder'].click()
        assert intruder_handoff['config']['location'] == 'query'
        assert intruder_handoff['label'].endswith('UNION SELECT')
        assert len(intruder_handoff['payloads']) >= 3
        assert all(
            'UNION SELECT' in payload
            for payload in intruder_handoff['payloads']
        )
        window._intruder_load = original_intruder_load

        repeater_page = window._build_repeater_page()
        repeater_page.resize(1050, 760)
        repeater_page.show()
        QApplication.processEvents()
        intruder_sets = repeater_page.findChild(
            QComboBox, 'IntruderPayloadSetCombo'
        )
        set_names = {
            intruder_sets.itemText(index)
            for index in range(intruder_sets.count())
        }
        assert {
            'SQL injection',
            'Cross-site scripting',
            'Encoding / filter normalization',
        } <= set_names
        window._intruder_apply(
            intruder_handoff['config'],
            intruder_handoff['payloads'],
            intruder_handoff['label'],
        )
        QApplication.processEvents()
        assert 'q=FUZZ' in repeater_page.findChild(
            QLineEdit, 'IntruderUrlInput'
        ).text()
        assert 'Exact workbench placement is active' in next(
            label.text() for label in repeater_page.findChildren(QLabel)
            if label.objectName() == 'IntruderStatus'
        )

        inspected['ok'] = True
        repeater_page.close()
        payload_page.close()
        report_page.close()
        recon_page.close()
        page.close()
        return 0

    monkeypatch.setattr(QApplication, 'exec', inspect_then_exit)

    with pytest.raises(SystemExit) as stopped:
        gui.main()

    assert stopped.value.code == 0
    assert inspected['ok']
