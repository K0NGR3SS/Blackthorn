"""Tests for ZAP/Burp drivers, normalization mappers, and finding importers (P6)."""
from wafpierce import tooldrivers as td
from wafpierce import importers as imp


def test_zap_alert_mapping():
    alert = {'alert': 'Reflected XSS', 'risk': 'High', 'confidence': 'Medium',
             'cweid': '79', 'url': 'https://e/q=1', 'description': 'desc here',
             'reference': 'https://ref\nmore'}
    f = td.zap_alert_to_finding(alert, 'https://e')
    assert f['severity'] == 'HIGH'
    assert f['cwe_id'] == 'CWE-79'
    assert f['technique'] == '[ZAP] Reflected XSS'
    assert f['source'] == 'external:zap' and f['bypass'] is False
    assert f['verification_status'] == 'candidate'
    assert f['kind'] == 'suspected'
    assert f['reference_url'] == 'https://ref'


def test_zap_alert_info_and_no_cwe():
    f = td.zap_alert_to_finding({'name': 'X', 'risk': 'Informational', 'cweid': '-1'})
    assert f['severity'] == 'INFO' and f['cwe_id'] == ''


def test_burp_issue_mapping():
    issue = {'name': 'SQLi', 'host': 'https://e', 'path': '/p', 'severity': 'High',
             'confidence': 'Certain', 'background': 'bg', 'cwe': '89'}
    f = td.burp_issue_to_finding(issue)
    assert f['severity'] == 'HIGH' and f['cwe_id'] == 'CWE-89'
    assert f['technique'] == '[Burp] SQLi' and f['url'] == 'https://e/p'
    assert f['confidence'] == 'high'
    assert f['verification_status'] == 'candidate'


def test_from_burp_issues(tmp_path):
    xml = '''<issues>
      <issue>
        <name>Cross-site scripting (reflected)</name>
        <host>https://e</host><path>/search</path>
        <severity>High</severity><confidence>Firm</confidence>
        <issueBackground>XSS background</issueBackground>
        <vulnerabilityClassifications>CWE-79: Improper Neutralization</vulnerabilityClassifications>
      </issue>
    </issues>'''
    p = tmp_path / 'burp.xml'
    p.write_text(xml, encoding='utf-8')
    findings = imp.from_burp_issues(str(p))
    assert len(findings) == 1
    assert findings[0]['severity'] == 'HIGH' and findings[0]['cwe_id'] == 'CWE-79'
    assert findings[0]['technique'].startswith('[Burp]')


def test_load_findings_autodetect(tmp_path):
    burp = tmp_path / 'b.xml'
    burp.write_text('<issues><issue><name>N</name><host>h</host><path>/p</path>'
                    '<severity>Low</severity></issue></issues>')
    assert imp.load_findings(str(burp))[0]['severity'] == 'LOW'

    zap = tmp_path / 'z.json'
    zap.write_text('{"alerts":[{"alert":"A","risk":"Medium","cweid":"200","url":"https://e"}]}')
    zf = imp.load_findings(str(zap))
    assert zf and zf[0]['severity'] == 'MEDIUM' and zf[0]['cwe_id'] == 'CWE-200'


def test_detect_zap_with_fake_session():
    class _Resp:
        status_code = 200
        def json(self):
            return {'version': '2.15.0'}
    class _Sess:
        def get(self, *a, **k):
            return _Resp()
    st = td.detect_zap(session=_Sess())
    assert st['state'] == 'running' and st['version'] == '2.15.0'


def test_detect_zap_absent():
    class _Sess:
        def get(self, *a, **k):
            raise OSError('refused')
    st = td.detect_zap(session=_Sess())
    assert st['state'] == 'absent'


def test_zap_client_spider_uses_modern_strict_scope_api(monkeypatch):
    calls = []
    client = td.ZAPClient(session=object())

    def fake_get(path, **params):
        calls.append((path, params))
        if '/action/scan/' in path:
            return {'scan': '12'}
        if '/view/status/' in path:
            return {'status': '67'}
        return {'Result': 'OK'}

    monkeypatch.setattr(client, '_get', fake_get)

    scan_id = client.client_spider(
        'https://app.example.test', context_name='App', user_name='Admin',
        max_depth=7, browsers=2,
    )
    assert scan_id == '12'
    assert client.client_spider_status(scan_id) == 67
    client.client_spider_stop(scan_id)

    path, params = calls[0]
    assert path == '/JSON/clientSpider/action/scan/'
    assert params['scopeCheck'] == 'STRICT'
    assert params['logoutAvoidance'] == 'true'
    assert params['contextName'] == 'App'
    assert params['userName'] == 'Admin'
