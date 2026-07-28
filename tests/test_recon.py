import json
import os
from types import SimpleNamespace

from wafpierce import recon


def test_normalize_domain_accepts_wildcard_scope():
    assert recon.normalize_domain('*.nubank.com.br') == 'nubank.com.br'
    assert recon.normalize_domain(
        'https://*.nubank.com.br/path'
    ) == 'nubank.com.br'
    assert recon.normalize_domain('nubank.com.br.') == 'nubank.com.br'


def test_httpx_resolution_rejects_python_cli_and_finds_projectdiscovery(
        monkeypatch, tmp_path):
    python_dir = tmp_path / 'python'
    pd_dir = tmp_path / 'pd'
    python_dir.mkdir()
    pd_dir.mkdir()
    python_cli = python_dir / 'httpx'
    pd_cli = pd_dir / 'httpx'
    for path in (python_cli, pd_cli):
        path.write_text('#!/bin/sh\n', encoding='utf-8')
        path.chmod(0o755)

    monkeypatch.setenv('PATH', os.pathsep.join([str(python_dir), str(pd_dir)]))
    monkeypatch.setattr(recon.shutil, 'which', lambda _name: str(python_cli))

    def version_check(cmd, **_kwargs):
        if cmd[0] == str(pd_cli):
            return SimpleNamespace(
                returncode=0,
                stdout='projectdiscovery.io\nCurrent Version: 1.7.0',
                stderr='',
            )
        return SimpleNamespace(
            returncode=2,
            stdout='',
            stderr='Usage: httpx [OPTIONS] URL',
        )

    monkeypatch.setattr(recon.subprocess, 'run', version_check)

    assert recon._which('httpx') == str(pd_cli)


def test_enumeration_merges_sources_and_certificate_transparency(monkeypatch):
    calls = []

    def run(cmd, _timeout, stdin_text=None):
        calls.append((cmd, stdin_text))
        if cmd[0] == 'subfinder':
            return 0, 'a.example.com\nshared.example.com\n', ''
        return 0, 'b.example.com\nshared.example.com\n', ''

    monkeypatch.setattr(recon, '_run', run)
    monkeypatch.setattr(
        recon,
        'certificate_transparency_hosts',
        lambda _domain, _timeout: {'ct.example.com', 'shared.example.com'},
    )

    hosts, sources = recon.enum_subdomains(
        'example.com', 30, include_sources=True
    )

    assert hosts == [
        'a.example.com',
        'b.example.com',
        'ct.example.com',
        'example.com',
        'shared.example.com',
    ]
    assert set(sources['shared.example.com']) == {
        'amass', 'certificate transparency', 'subfinder'
    }
    assert '-all' in calls[0][0]


def test_certificate_transparency_filters_wildcards_and_out_of_scope(
        monkeypatch):
    from wafpierce import recon_install

    payload = json.dumps([
        {
            'name_value': (
                '*.api.example.com\nwww.example.com\nattacker-example.com'
            )
        },
    ]).encode()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return payload

    monkeypatch.setattr(
        recon_install, '_urlopen', lambda _request, timeout: Response()
    )

    assert recon.certificate_transparency_hosts('example.com', 10) == {
        'api.example.com', 'www.example.com'
    }


def test_http_probe_marks_live_and_nonresponsive_rows(monkeypatch):
    monkeypatch.setattr(recon, '_which', lambda _name: '/tools/httpx')

    def run(cmd, _timeout, stdin_text=None):
        assert cmd[0] == '/tools/httpx'
        assert '-probe' in cmd
        assert stdin_text == 'live.example.com\ndead.example.com'
        return 0, '\n'.join([
            json.dumps({
                'input': 'live.example.com',
                'url': 'https://live.example.com',
                'status_code': 200,
            }),
            json.dumps({
                'input': 'dead.example.com',
                'failed': True,
            }),
        ]), ''

    monkeypatch.setattr(recon, '_run', run)

    rows = recon.probe_http(
        ['live.example.com', 'dead.example.com'], 30
    )

    assert [row['live'] for row in rows] == [True, False]


def test_host_inventory_distinguishes_dns_and_http_states():
    inventory = recon.build_host_inventory(
        'example.com',
        ['example.com', 'api.example.com', 'old.example.com'],
        {
            'example.com': ['scope root'],
            'api.example.com': ['subfinder'],
            'old.example.com': ['certificate transparency'],
        },
        {
            'example.com': ['192.0.2.1'],
            'api.example.com': ['192.0.2.2'],
        },
        [{
            'input': 'api.example.com',
            'url': 'https://api.example.com',
            'status_code': 403,
            'live': True,
        }],
    )

    by_host = {row['hostname']: row for row in inventory}
    assert by_host['api.example.com']['http_state'] == 'live'
    assert by_host['example.com']['http_state'] == 'no_response'
    assert by_host['old.example.com']['http_state'] == 'not_tested'


def test_run_recon_normalizes_wildcard_and_skips_nmap_by_default(monkeypatch):
    monkeypatch.setattr(recon, 'diagnostics_banner', lambda: '')
    monkeypatch.setattr(recon, '_emit', lambda _message: None)
    monkeypatch.setattr(
        recon,
        'enum_subdomains',
        lambda domain, _timeout, include_sources=False: (
            [domain, f'api.{domain}'],
            {
                domain: ['scope root'],
                f'api.{domain}': ['subfinder'],
            },
        ),
    )
    monkeypatch.setattr(
        recon,
        'resolve_hosts',
        lambda hosts, _timeout: {
            host: [f'192.0.2.{index + 1}']
            for index, host in enumerate(hosts)
        },
    )
    monkeypatch.setattr(
        recon,
        'probe_http',
        lambda _hosts, _timeout: [{
            'input': 'api.example.com',
            'url': 'https://api.example.com',
            'status_code': 200,
            'live': True,
        }],
    )
    monkeypatch.setattr(
        recon,
        'scan_ports',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('Nmap must be opt-in')
        ),
    )

    report = recon.run_recon(
        '*.example.com',
        do_tls=False,
        do_historical=False,
    )

    assert report['target'] == 'example.com'
    assert report['stages']['summary'] == {
        'subdomains': 1,
        'hosts_total': 2,
        'dns_live': 2,
        'web_live': 1,
        'dns_without_http': 1,
        'unresolved': 0,
    }
    assert len(report['stages']['hosts']) == 2


def test_nmap_uses_unprivileged_light_connect_scan(monkeypatch):
    commands = []

    def run(cmd, _timeout, stdin_text=None):
        commands.append(cmd)
        return 0, '<nmaprun></nmaprun>', ''

    monkeypatch.setattr(recon, '_run', run)
    assert recon.scan_ports(['192.0.2.10'], 20, top_ports=20) == []
    command = commands[0]
    assert '-sT' in command
    assert '-T3' in command
    assert '--version-light' in command
    assert '--script' not in command


def test_cli_can_write_full_discovery_report(monkeypatch, tmp_path):
    report = {
        'target': 'example.com',
        'findings': [],
        'stages': {'hosts': [], 'summary': {}},
    }
    monkeypatch.setattr(recon, 'preflight', lambda: [])
    monkeypatch.setattr(recon, 'run_recon', lambda *_args, **_kwargs: report)
    output = tmp_path / 'discovery.json'

    assert recon.main([
        '*.example.com',
        '--report-output', str(output),
    ]) == 0
    assert json.loads(output.read_text(encoding='utf-8')) == report


def test_frozen_recon_worker_writes_report_without_enabling_nmap(
        monkeypatch, tmp_path):
    import run_gui

    output = tmp_path / 'worker-report.json'
    calls = []

    def run(target, **kwargs):
        calls.append((target, kwargs))
        return {
            'target': 'example.com',
            'findings': [],
            'stages': {'hosts': [], 'summary': {}},
        }

    monkeypatch.setattr(recon, 'run_recon', run)
    monkeypatch.setattr(
        run_gui.sys,
        'argv',
        [
            'Blackthorn',
            '--recon-worker',
            '--target', '*.example.com',
            '--output', str(output),
        ],
    )

    assert run_gui._run_recon_worker() == 0
    assert calls[0][0] == '*.example.com'
    assert calls[0][1]['do_ports'] is False
    assert json.loads(output.read_text(encoding='utf-8'))['target'] == 'example.com'
