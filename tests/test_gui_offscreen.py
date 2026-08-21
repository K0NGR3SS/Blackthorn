"""Small offscreen smoke test for the real Qt results workspace."""

import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def test_results_workspace_builds_with_evidence_actions(monkeypatch):
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QLabel, QLineEdit, QListWidget,
        QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QTabWidget,
        QTableWidget, QTextBrowser, QWidget,
        QTreeWidget, QTreeWidgetItem,
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

        def get_scan_history(self, limit=100):
            return []

        def get_scheduled_scans(self):
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
        dropdown_image = window._workbench_combo.grab().toImage()
        assert 'Dropdown menu' in window._workbench_combo.accessibleDescription()
        assert window._workbench_combo.objectName() == 'WorkbenchSelector'
        workbench_labels = {
            window._workbench_combo.itemData(index):
            window._workbench_combo.itemText(index)
            for index in range(window._workbench_combo.count())
            if window._workbench_combo.itemData(index)
        }
        assert workbench_labels['repeater'] == 'Request lab'
        assert workbench_labels['fuzzer'] == 'Content discovery'
        assert workbench_labels['sqli'] == 'SQLi automation'
        assert workbench_labels['tools'] == 'Tool manager'
        assert 'browser' not in workbench_labels
        assert window._nav_buttons['browser'].text().endswith('Browser')
        assert {'live', 'timeline', 'schedule'}.isdisjoint(workbench_labels)
        assert {'live', 'timeline', 'schedule'}.isdisjoint(
            window._page_builders()
        )
        group_rows = [
            index
            for index in range(window._workbench_combo.count())
            if window._workbench_combo.itemText(index).startswith('— ')
        ]
        assert len(group_rows) == 4
        assert all(
            not window._workbench_combo.model().item(index).isEnabled()
            for index in group_rows
        )
        dropdown_light_pixels = 0
        for x in range(
                max(0, dropdown_image.width() - 25),
                max(0, dropdown_image.width() - 5)):
            for y in range(dropdown_image.height()):
                color = dropdown_image.pixelColor(x, y)
                if (
                        color.red() > 180
                        and color.green() > 180
                        and color.blue() > 180):
                    dropdown_light_pixels += 1
        assert dropdown_light_pixels >= 3
        scan_disclosure = next(
            button for button in window.findChildren(QPushButton)
            if button.objectName() == 'DisclosureButton'
            and 'Advanced scan controls' in button.text()
        )
        assert scan_disclosure.text().startswith('▸')
        assert scan_disclosure.isChecked() is False
        assert 'collapsed' in scan_disclosure.accessibleDescription()
        scan_disclosure.click()
        QApplication.processEvents()
        assert scan_disclosure.text().startswith('▾')
        assert scan_disclosure.property('expanded') == 'true'
        assert 'expanded' in scan_disclosure.accessibleDescription()
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
        analyze_tabs = page.findChild(QTabWidget, 'ResultsPageTabs')
        assert analyze_tabs is not None
        assert [
            analyze_tabs.tabText(index)
            for index in range(analyze_tabs.count())
        ] == ['Findings', 'Live findings']
        assert next(
            tree for tree in page.findChildren(QTreeWidget)
            if tree.accessibleName() == 'Live findings stream'
        )
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
        tree = page.findChild(QTreeWidget, 'ResultsFindingsTree')
        assert tree is not None
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
        assert next(
            checkbox for checkbox in recon_page.findChildren(QCheckBox)
            if checkbox.text().startswith('Network paths')
        ).isChecked() is False
        progress = next(
            bar for bar in recon_page.findChildren(QProgressBar)
            if bar.accessibleName() == 'Discovery progress'
        )
        assert progress.minimum() == 0
        assert progress.maximum() == 100
        assert progress.value() == 0
        discovery_disclosure = next(
            button for button in recon_page.findChildren(QPushButton)
            if button.objectName() == 'DisclosureButton'
        )
        assert discovery_disclosure.text().startswith('▸')
        discovery_disclosure.click()
        QApplication.processEvents()
        assert discovery_disclosure.text().startswith('▾')
        assert discovery_disclosure.property('expanded') == 'true'
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
        window._recon_state['update_report']({
            'target': 'example.test',
            'findings': [{
                'technique': 'Discovered Host',
                'target': 'api.example.test',
                'severity': 'INFO',
                'reason': 'DNS resolved and HTTPS responded',
                'http_status': 200,
                'discovery': {'hostname': 'api.example.test'},
            }],
            'stages': {
                'sources': {
                    'api.example.test': [
                        'subfinder', 'certificate transparency',
                    ],
                },
                'resolved': {
                    'api.example.test': ['192.0.2.1', '192.0.2.2'],
                },
                'http': [{
                    'url': 'https://api.example.test',
                    'status_code': 200,
                    'title': 'Example API',
                    'tech': ['nginx', 'GraphQL'],
                }],
                'hosts': [{
                    'hostname': 'api.example.test',
                    'dns_live': True,
                    'http_live': True,
                    'http_status': 200,
                    'http_url': 'https://api.example.test',
                    'ip_addresses': ['192.0.2.1'],
                }],
                'ports': [{
                    'host': '192.0.2.1',
                    'port': 443,
                    'service': 'https',
                }],
            },
        })
        QApplication.processEvents()
        scanned_item = host_inventory.topLevelItem(0)
        assert scanned_item.childCount() >= 12
        assert scanned_item.isExpanded() is False
        host_inventory.itemClicked.emit(scanned_item, 0)
        QApplication.processEvents()
        assert scanned_item.isExpanded() is True
        topology_tabs = next(
            tabs for tabs in recon_page.findChildren(QTabWidget)
            if 'Topology' in {
                tabs.tabText(index) for index in range(tabs.count())
            }
        )
        assert 'Topology' in {
            topology_tabs.tabText(index)
            for index in range(topology_tabs.count())
        }
        topology_details = next(
            browser for browser in recon_page.findChildren(QTextBrowser)
            if browser.accessibleName() == 'Topology host details'
        )
        assert 'api.example.test' in topology_details.toPlainText()
        assert '443/tcp' in topology_details.toPlainText()
        assert 'Scan coverage' in topology_details.toPlainText()
        assert next(
            field for field in recon_page.findChildren(QLineEdit)
            if field.accessibleName() == 'Search topology hosts'
        )
        assert next(
            widget for widget in recon_page.findChildren(QListWidget)
            if widget.accessibleName() == 'Topology host navigator'
        ).count() >= 1
        assert next(
            combo for combo in recon_page.findChildren(QComboBox)
            if combo.accessibleName() == 'Topology radial layout'
        ).count() == 2
        discovery_findings = next(
            tree for tree in recon_page.findChildren(QTreeWidget)
            if tree.accessibleName() == 'Discovery findings'
        )
        tool_groups = {
            discovery_findings.topLevelItem(index).text(0).split(' · ', 1)[0]
            for index in range(discovery_findings.topLevelItemCount())
        }
        assert {
            'Subfinder', 'Certificate Transparency', 'dnsx', 'httpx', 'Nmap',
        } <= tool_groups
        httpx_group = next(
            discovery_findings.topLevelItem(index)
            for index in range(discovery_findings.topLevelItemCount())
            if discovery_findings.topLevelItem(index).text(0).startswith('httpx')
        )
        httpx_result = httpx_group.child(0)
        tech_field = next(
            httpx_result.child(index)
            for index in range(httpx_result.childCount())
            if httpx_result.child(index).text(0).strip() == 'tech'
        )
        assert tech_field.childCount() == 2
        assert [
            tech_field.child(index).text(1)
            for index in range(tech_field.childCount())
        ] == ['nginx', 'GraphQL']
        tool_filter = next(
            combo for combo in recon_page.findChildren(QComboBox)
            if combo.accessibleName() == 'Discovery tool filter'
        )
        tool_search = next(
            field for field in recon_page.findChildren(QLineEdit)
            if field.accessibleName() == 'Search discovery tool results'
        )
        assert tool_filter.findData('httpx') >= 0
        tool_search.setText('GraphQL')
        QApplication.processEvents()
        assert discovery_findings.topLevelItemCount() == 1
        assert discovery_findings.topLevelItem(0).text(0).startswith('httpx')
        tool_search.clear()
        QApplication.processEvents()
        finding_item = discovery_findings.topLevelItem(0)
        assert finding_item.childCount() >= 1
        discovery_findings.itemClicked.emit(finding_item, 0)
        assert finding_item.isExpanded() is True
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
        report_tabs = report_page.findChild(QTabWidget, 'DashboardPageTabs')
        assert report_tabs is not None
        assert [
            report_tabs.tabText(index)
            for index in range(report_tabs.count())
        ] == ['Summary', 'Timeline']
        assert report_page.findChild(
            QSplitter, 'ReportTablesSplitter'
        ) is not None
        assert report_page.findChild(
            QSplitter, 'ReportSummarySplitter'
        ) is not None

        automation_page = window._build_pipeline_page()
        automation_page.resize(1000, 760)
        automation_page.show()
        QApplication.processEvents()
        automation_tabs = automation_page.findChild(
            QTabWidget, 'AutomationPageTabs'
        )
        assert automation_tabs is not None
        assert [
            automation_tabs.tabText(index)
            for index in range(automation_tabs.count())
        ] == [
            'Radar', 'Inventory', 'Exposure Matches', 'Remediation', 'Rules',
            'Validation Queue', 'Notifications & Health', 'Watch Schedules',
            'Run History',
        ]
        assert automation_page.findChild(QTableWidget, 'AutomationRadarTable')
        assert automation_page.findChild(
            QTableWidget, 'AutomationInventoryTable'
        )
        assert automation_page.findChild(
            QTableWidget, 'AutomationRemediationTable'
        )
        assert automation_page.findChild(
            QTableWidget, 'AutomationValidationQueue'
        )
        assert automation_page.findChild(
            QTableWidget, 'AutomationFeedHealthTable'
        )
        assert automation_page.findChild(QWidget, 'BrowserPage') is None

        window._navigate('browser')
        QApplication.processEvents()
        browser_holder = window._pages['browser']
        browser_page = browser_holder.findChild(QWidget, 'BrowserPage')
        assert window._stack.currentWidget() is browser_holder
        assert browser_page is not None
        assert browser_page.objectName() == 'BrowserPage'
        assert browser_page.findChild(
            QTableWidget, 'BrowserEngineStack'
        ) is not None
        assert browser_page.findChild(
            QProgressBar, 'BrowserEngineProgress'
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
        assert category_filter.accessibleName() == 'Payload category dropdown'
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
        browser_holder.close()
        automation_page.close()
        report_page.close()
        recon_page.close()
        page.close()
        return 0

    monkeypatch.setattr(QApplication, 'exec', inspect_then_exit)

    with pytest.raises(SystemExit) as stopped:
        gui.main()

    assert stopped.value.code == 0
    assert inspected['ok']
