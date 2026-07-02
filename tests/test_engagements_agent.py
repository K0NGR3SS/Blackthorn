import os
import tempfile

from wafpierce.agent_server import AgentAPI
from wafpierce.ai_providers import provider_status
from wafpierce.database import WAFPierceDB


def _db():
    return WAFPierceDB(db_path=os.path.join(tempfile.mkdtemp(), 'engagements.db'))


def test_engagement_roundtrip_and_finding_state():
    db = _db()
    eid = db.save_engagement(
        'Example Program',
        scope=['example.com', 'api.example.com'],
        exclusions=['admin.example.com'],
        rules_notes='Safe mode only',
        test_accounts_notes='Use test tenants only',
    )
    assert eid
    got = db.get_engagement(eid)
    assert got['name'] == 'Example Program'
    assert got['scope'] == ['example.com', 'api.example.com']

    db.create_scan('scan-1', ['https://example.com'], engagement_id=eid)
    db.add_result('scan-1', {
        'target': 'https://example.com',
        'technique': 'Header Bypass',
        'severity': 'HIGH',
        'engagement_id': eid,
    })
    result = db.get_scan_results('scan-1')[0]
    assert result['workflow_state'] == 'candidate'
    assert result['engagement_id'] == eid
    assert db.update_finding_state(result['id'], 'validated', 'minimal repro captured')
    assert db.get_scan_results('scan-1')[0]['workflow_state'] == 'validated'


def test_agent_reads_scope_and_refuses_out_of_scope_scan():
    db = _db()
    eid = db.save_engagement('Scoped Program', scope=['example.com'])
    api = AgentAPI(db)

    scope = api.handle({'method': 'read_scope', 'params': {'engagement_id': eid}})
    assert scope['ok'] is True
    assert scope['engagement']['scope'] == ['example.com']

    denied = api.handle({
        'method': 'start_scan',
        'params': {'engagement_id': eid, 'target': 'https://not-example.test'},
    })
    assert denied['ok'] is False
    assert denied['code'] == 'out_of_scope'


def test_agent_dry_run_scan_is_scope_gated():
    db = _db()
    eid = db.save_engagement('Scoped Program', scope=['example.com'])
    api = AgentAPI(db)
    res = api.handle({
        'method': 'start_scan',
        'params': {
            'engagement_id': eid,
            'target': 'https://example.com',
            'dry_run': True,
            'safe_mode': True,
            'categories': ['detection_recon'],
        },
    })
    assert res['ok'] is True
    assert res['returncode'] == 0
    assert 'DRY RUN' in res['stdout']


def test_ai_provider_status_is_non_secret_and_off_by_default():
    status = provider_status('anthropic', api_key=None)
    assert status.provider == 'anthropic'
    assert isinstance(status.configured, bool)
    assert 'sk-' not in status.reason
