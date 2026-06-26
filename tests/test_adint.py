"""Tests for the AD / Internal (BloodHound + Neo4j) module (P7)."""
import os
import tempfile

import pytest

from wafpierce import adint
from wafpierce.database import WAFPierceDB


def test_build_sharphound_cmd_exe():
    argv = adint.build_collector_cmd('sharphound', collector_path='C:/t/SharpHound.exe',
                                     output_dir='C:/out', domain='corp.local',
                                     username='u', password='p')
    assert argv[0] == 'C:/t/SharpHound.exe'
    assert '-c' in argv and 'All' in argv and '--ldapusername' in argv and 'corp.local' in argv


def test_build_sharphound_cmd_ps1_uses_powershell():
    argv = adint.build_collector_cmd('sharphound', collector_path='C:/t/SharpHound.ps1',
                                     output_dir='C:/out')
    assert argv[0] == 'powershell' and '-File' in argv


def test_build_azurehound_cmd():
    argv = adint.build_collector_cmd('azurehound', collector_path='azurehound',
                                     output_dir='/out', tenant='t1', jwt='JWT')
    assert '--jwt' in argv and '--tenant' in argv and 'list' in argv


def test_build_unknown_collector():
    with pytest.raises(ValueError):
        adint.build_collector_cmd('mimikatz', collector_path='x', output_dir='y')


def test_detect_environment_absent(monkeypatch):
    # neo4j socket refused, no bhce, collectors absent
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: (_ for _ in ()).throw(OSError('refused')))
    env = adint.detect_environment(bhce_url='', sharphound_path='', azurehound_path='')
    assert env['neo4j']['state'] == 'absent'
    assert env['sharphound']['state'] == 'absent'


def test_ingest_zip_strategies(tmp_path):
    # no zip
    assert adint.ingest_zip('/nope.zip')['strategy'] == 'none'
    # zip present, no CE url -> manual
    z = tmp_path / 'd.zip'; z.write_bytes(b'PK\x03\x04')
    res = adint.ingest_zip(str(z), bhce_url='')
    assert res['strategy'] == 'manual'


def test_run_cypher_without_driver(monkeypatch):
    monkeypatch.setattr(adint, 'neo4j_available', lambda: False)
    res = adint.run_cypher('MATCH (n) RETURN n')
    assert res['ok'] is False and 'neo4j' in res['error'].lower()


def test_db_ad_run_roundtrip():
    db = WAFPierceDB(db_path=os.path.join(tempfile.mkdtemp(), 'ad.db'))
    assert db.save_ad_run('r1', 'sharphound', 'corp.local', '/out')
    assert db.add_ad_findings('r1', 'Kerberoastable users', [{'name': 'svc1'}, {'name': 'svc2'}])
    assert db.finish_ad_run('r1', 'done', ingested=True)
    row = db.get_ad_run('r1')
    assert row and row['status'] == 'done' and row['ingested'] == 1
