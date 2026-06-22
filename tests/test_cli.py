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
    assert 'DrWAFPierce' not in constants.DEFAULT_USER_AGENT
    assert 'K0NGR3SS/WAFPierce' in constants.DEFAULT_USER_AGENT

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
    assert 'usage: wafpierce' in capsys.readouterr().out


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
