"""Unit tests for the GUI-free pipeline engine (P3)."""
import os
import tempfile

from wafpierce import pipeline as pl
from wafpierce.database import WAFPierceDB


def test_default_pipeline_is_valid():
    assert pl.validate_pipeline(pl.default_pipeline()) == []


def test_validate_catches_bad_stages():
    bad = {'stages': [
        {'id': 'a', 'type': 'nope'},
        {'id': 'b', 'type': 'external_tool', 'config': {'tool': 'not_a_tool'}},
        {'id': 'c', 'type': 'report', 'config': {'format': 'docx'}},
    ]}
    errs = pl.validate_pipeline(bad)
    assert any('unknown stage type' in e for e in errs)
    assert any('unknown tool' in e for e in errs)
    assert any('unsupported report format' in e for e in errs)


def test_validate_empty():
    assert pl.validate_pipeline({'stages': []})


def test_build_scan_argv_source_and_frozen():
    cfg = {'categories': ['injection_testing'], 'threads': 7, 'delay': 0.3, 'safe_mode': True}
    src = pl.build_scan_argv('https://e', cfg, '/tmp/o.json', frozen=False, python_exe='py')
    assert src[:5] == ['py', '-u', '-m', 'wafpierce.pierce', 'https://e']
    assert '-c' in src and 'injection_testing' in src and '--safe-mode' in src
    frz = pl.build_scan_argv('https://e', cfg, '/tmp/o.json', frozen=True, python_exe='py')
    assert '--scan-worker' in frz and '--categories' in frz and '--safe-mode' in frz


def test_build_scan_argv_requires_explicit_full_impact():
    cfg = {'safe_mode': False}
    src = pl.build_scan_argv(
        'https://e', cfg, '/tmp/o.json', frozen=False, python_exe='py'
    )
    frz = pl.build_scan_argv(
        'https://e', cfg, '/tmp/o.json', frozen=True, python_exe='py'
    )
    assert '--full-impact' in src
    assert '--full-impact' in frz


def test_db_pipeline_roundtrip():
    db = WAFPierceDB(db_path=os.path.join(tempfile.mkdtemp(), 'p.db'))
    pdef = pl.default_pipeline()
    assert db.save_pipeline('p1', pdef, 'desc')
    got = db.get_pipeline('p1')
    assert got and got['definition']['stages'][0]['type'] == 'wafpierce_scan'
    assert any(p['name'] == 'p1' for p in db.list_pipelines())
    # upsert
    pdef['stages'].append({'id': 'x', 'type': 'report', 'config': {'format': 'json'}})
    db.save_pipeline('p1', pdef)
    assert len(db.get_pipeline('p1')['definition']['stages']) == 4
    assert db.delete_pipeline('p1') and db.get_pipeline('p1') is None


def test_runner_report_only(tmp_path):
    out = tmp_path / 'rep.json'
    pdef = {'name': 't', 'stages': [
        {'id': 'r', 'type': 'report', 'config': {'format': 'json', 'path': str(out)}}]}
    logs = []
    runner = pl.PipelineRunner(pdef, 'https://e',
                               pl.PipelineHooks(on_log=logs.append))
    runner.all_findings = [{'technique': 't', 'severity': 'INFO', 'target': 'https://e'}]
    res = runner.run()
    assert res['ok'] is True
    assert out.exists()


def test_runner_blocks_active_pipeline_before_starting_out_of_scope_stage():
    logs = []
    pdef = {'name': 't', 'stages': [
        {'id': 'scan', 'type': 'wafpierce_scan', 'config': {}},
    ]}

    result = pl.PipelineRunner(
        pdef,
        'https://outside.example',
        pl.PipelineHooks(on_log=logs.append),
        authorize_target=lambda _target: False,
    ).run()

    assert result['ok'] is False
    assert result['state'] == 'scope_blocked'
    assert any('outside the active engagement scope' in line for line in logs)
