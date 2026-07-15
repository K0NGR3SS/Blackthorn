"""Tests for the unified CLI dispatcher, diagnostics, and the Wave-1 QoL flags.

These must never touch the network: every path asserted here either returns
before any request is sent (--dry-run, --list-*, version) or runs doctor with
network checks disabled.
"""
import json

import wafpierce
from wafpierce import cli, diagnostics, constants
from wafpierce.exporters import to_sarif


# --------------------------------------------------------------- version drift
def test_version_is_single_sourced():
    # User-Agent and SARIF tool version both derive from __init__.__version__.
    assert wafpierce.__version__ in constants.DEFAULT_USER_AGENT
    assert constants.DEFAULT_USER_AGENT.startswith('Blackthorn/')
    assert 'authorized web security research' in constants.DEFAULT_USER_AGENT

    doc = json.loads(to_sarif('https://example.com', []))
    assert doc['runs'][0]['tool']['driver']['version'] == wafpierce.__version__


# ----------------------------------------------------------------- diagnostics
def test_component_report_shape():
    report = diagnostics.component_report()
    names = {c['import_name'] for c in report}
    assert {'curl_cffi', 'reportlab', 'anthropic', 'playwright'} <= names
    for c in report:
        assert set(c) >= {'import_name', 'label', 'purpose', 'available', 'version'}
        assert isinstance(c['available'], bool)


def test_print_version_runs(capsys):
    diagnostics.print_version(no_color=True)
    out = capsys.readouterr().out
    assert wafpierce.__version__ in out
    assert 'Optional components' in out


def test_doctor_no_network_returns_zero(capsys):
    rc = diagnostics.run_doctor(no_color=True, check_network=False)
    out = capsys.readouterr().out
    assert rc == 0
    assert 'Core checks passed' in out
    assert 'Network' not in out  # network check skipped


# ------------------------------------------------------------------ dispatcher
def test_cli_version_flag(capsys):
    assert cli.main(['--version']) == 0
    assert wafpierce.__version__ in capsys.readouterr().out


def test_cli_version_subcommand(capsys):
    assert cli.main(['version']) == 0
    assert 'Optional components' in capsys.readouterr().out


def test_cli_no_args_shows_usage(capsys):
    assert cli.main([]) == 0
    assert 'usage: blackthorn' in capsys.readouterr().out


def test_cli_doctor(capsys):
    assert cli.main(['doctor', '--no-network', '--no-color']) == 0
    assert 'doctor' in capsys.readouterr().out


# ------------------------------------------------------------ list / dry-run
def test_list_categories(capsys):
    assert cli.main(['scan', '--list-categories']) == 0
    out = capsys.readouterr().out
    assert 'injection_testing' in out
    assert 'categories total' in out


def test_list_techniques(capsys):
    assert cli.main(['scan', '--list-techniques']) == 0
    out = capsys.readouterr().out
    assert 'techniques across' in out
    assert 'safe-mode' in out  # the '*' legend


def test_dry_run_no_network(capsys):
    rc = cli.main(['scan', 'https://example.invalid',
                   '--dry-run', '--safe-mode', '-c', 'protocol_level'])
    out = capsys.readouterr().out
    assert rc == 0
    assert 'DRY RUN' in out
    assert 'no requests were sent' in out
    # protocol_level has safe-mode-skipped techniques
    assert 'skipped' in out


def test_dry_run_bare_url_defaults_to_scan(capsys):
    # No subcommand -> treated as `scan`.
    rc = cli.main(['https://example.invalid', '--dry-run'])
    out = capsys.readouterr().out
    assert rc == 0
    assert 'DRY RUN' in out
    assert 'categories' in out


# ------------------------------------------------------------------ --profile
def _ns(**kw):
    import argparse
    base = dict(profile=None, threads=10, delay=0.2, jitter=0.0,
                safe_mode=False, impersonate=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_profile_stealth_applies_when_defaults():
    from wafpierce.pierce import _apply_profile
    args = _ns(profile='stealth')
    _apply_profile(args)
    assert args.threads == 3 and args.jitter == 1.5
    assert args.safe_mode is True and args.impersonate == 'chrome'


def test_profile_does_not_override_explicit_flags():
    from wafpierce.pierce import _apply_profile
    # User explicitly set threads=50 and impersonate; profile must not clobber.
    args = _ns(profile='aggressive', threads=50, impersonate='safari17_0')
    _apply_profile(args)
    assert args.threads == 50               # user value kept
    assert args.impersonate == 'safari17_0'  # user value kept
    assert args.delay == 0.0                # filled from preset (was default)


def test_profile_dry_run_reflects_preset(capsys):
    rc = cli.main(['scan', 'https://example.invalid', '--profile', 'stealth',
                   '--dry-run', '-c', 'detection_recon'])
    out = capsys.readouterr().out
    assert rc == 0
    assert 'threads=3' in out and 'jitter=1.5' in out
    assert 'safe_mode=on' in out
    assert 'impersonate=chrome' in out


def test_seed_is_accepted(capsys):
    rc = cli.main(['scan', 'https://example.invalid', '--seed', '42', '--dry-run'])
    assert rc == 0
    assert 'DRY RUN' in capsys.readouterr().out


# ------------------------------------------------------------------ config file
def test_config_load_json_and_profile(tmp_path):
    from wafpierce.configfile import load_config
    import json as _json
    cfg = tmp_path / "wp.json"
    cfg.write_text(_json.dumps({
        "threads": 20, "safe-mode": True,
        "profiles": {"staging": {"target": "https://staging.example.com", "oob": "interactsh"}},
    }), encoding="utf-8")
    flat = load_config(str(cfg))
    assert flat["threads"] == 20 and flat["safe_mode"] is True  # dash normalized
    assert "profiles" not in flat
    withp = load_config(str(cfg), profile="staging")
    assert withp["target"] == "https://staging.example.com"
    assert withp["oob"] == "interactsh"


def test_config_unknown_profile_raises(tmp_path):
    from wafpierce.configfile import load_config
    cfg = tmp_path / "wp.json"
    cfg.write_text('{"threads": 5}', encoding="utf-8")
    import pytest
    with pytest.raises(RuntimeError):
        load_config(str(cfg), profile="nope")


def test_config_apply_respects_explicit_flags():
    from wafpierce.configfile import apply_config
    args = _ns_for_config(threads=10, delay=0.2, oob='off')
    parser = _parser_for_config()
    apply_config(args, parser, {'threads': 30, 'oob': 'interactsh'})
    # threads was at default(10) -> overridden; but if user had set it, kept (next test)
    assert args.threads == 30
    assert args.oob == 'interactsh'


def test_config_does_not_override_explicit():
    from wafpierce.configfile import apply_config
    args = _ns_for_config(threads=50, delay=0.2, oob='off')   # user set threads=50
    parser = _parser_for_config()
    apply_config(args, parser, {'threads': 30})
    assert args.threads == 50  # explicit (non-default) value preserved


def test_config_end_to_end_supplies_target(tmp_path, capsys):
    import json as _json
    cfg = tmp_path / "wp.json"
    cfg.write_text(_json.dumps({"profiles": {"s": {"target": "https://from-config.invalid"}}}),
                   encoding="utf-8")
    rc = cli.main(['scan', '--config', str(cfg), '--config-profile', 's', '--dry-run'])
    out = capsys.readouterr().out
    assert rc == 0
    assert 'from-config.invalid' in out  # target came from the config profile


def _parser_for_config():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--threads', type=int, default=10)
    p.add_argument('--delay', type=float, default=0.2)
    p.add_argument('--oob', default='off')
    return p


def _ns_for_config(**kw):
    import argparse
    return argparse.Namespace(**kw)


# -------------------------------------------------------------- --fail-on gate
def test_fail_on_gating():
    from wafpierce.pierce import _fail_on_exit
    high = [{'severity': 'HIGH'}]
    low = [{'severity': 'LOW'}]
    assert _fail_on_exit(high, 'high') == 10        # meets threshold
    assert _fail_on_exit(low, 'high') is None        # below threshold
    assert _fail_on_exit(high, 'critical') is None   # HIGH < CRITICAL
    assert _fail_on_exit(low, 'low') == 10           # exactly at threshold
    assert _fail_on_exit(high, None) is None         # gating disabled
    assert _fail_on_exit([], 'info') is None         # nothing found


def test_fail_on_does_not_gate_unverified_candidates():
    from wafpierce.pierce import _fail_on_exit

    candidate = [{
        'severity': 'CRITICAL', 'bypass': True, 'kind': 'suspected',
        'verification_status': 'candidate',
    }]
    assert _fail_on_exit(candidate, 'low') is None
