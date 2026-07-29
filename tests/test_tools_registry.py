"""Unit tests for the external-tool registry/runtime/parsers (P2 foundation).

These run without any external tool installed: detection of absent tools must be
clean (no install side-effects) and every parser must map a captured fixture into
the canonical WAFPierce finding dict.
"""
import sys

from wafpierce import tools_registry as reg
from wafpierce import tools_runtime as rt
from wafpierce import tools_parsers as tp


def test_every_spec_is_well_formed():
    for key, spec in reg.TOOL_REGISTRY.items():
        assert spec.key == key
        assert spec.category in reg.TOOL_CATEGORIES, (key, spec.category)
        assert spec.json_mode in reg.JSON_MODES, (key, spec.json_mode)
        assert spec.target_kind in reg.TARGET_KINDS, (key, spec.target_kind)
        assert hasattr(tp, spec.parser), f'{key}: missing parser {spec.parser}'
        assert spec.binaries, key


def test_build_argv_substitutes_placeholders():
    spec = reg.get_spec('nuclei')
    ctx = rt._build_context(spec, 'https://example.com/app', None, '/tmp/x')
    argv = rt.build_argv(spec, 'nuclei', ctx)
    assert argv == ['nuclei', '-u', 'https://example.com/app', '-jsonl', '-silent']


def test_build_argv_rejects_flag_like_target():
    spec = reg.get_spec('nmap')
    ctx = rt._build_context(spec, '-oG', None, '/tmp/x')
    try:
        rt.build_argv(spec, 'nmap', ctx)
        assert False, 'expected injection guard to fire'
    except ValueError:
        pass


def test_configured_command_applies_manager_settings_without_mutating_input(
        tmp_path):
    binary = tmp_path / 'ffuf-custom'
    binary.write_text('')
    original = ['ffuf', '-u', 'https://example.test/FUZZ']

    configured = rt.configured_command(
        original,
        custom_path=str(binary),
        extra_args='-H "X-Test: one two" -rate 10',
    )

    assert original[0] == 'ffuf'
    assert configured[:3] == [
        str(binary), '-u', 'https://example.test/FUZZ'
    ]
    assert configured[-4:] == ['-H', 'X-Test: one two', '-rate', '10']


def test_configured_command_rejects_missing_custom_path():
    try:
        rt.configured_command(
            ['ffuf'], custom_path='/definitely/missing/wafpierce-tool'
        )
        assert False, 'expected missing custom tool path to fail'
    except ValueError as exc:
        assert 'not found' in str(exc)


def test_detect_absent_tool_is_clean():
    spec = reg.ToolSpec(key='nope', name='Nope', category='recon',
                        binaries=('definitely_not_a_real_bin_xyz',))
    st = rt.detect(spec)
    assert st.found is False and st.state == 'not_installed'


def test_nuclei_parser_maps_classification():
    line = ('{"template-id":"xss","info":{"name":"Reflected XSS","severity":"high",'
            '"classification":{"cve-id":["CVE-2020-1234"],"cwe-id":["CWE-79"],"cvss-score":7.2}},'
            '"matched-at":"https://e/q=1"}')
    f = tp.parse_nuclei_jsonl(reg.get_spec('nuclei'), 'https://e', line, {})[0]
    assert f['severity'] == 'HIGH'
    assert f['cwe_id'] == 'CWE-79'
    assert f['cve_id'] == 'CVE-2020-1234'
    assert f['bypass'] is False
    assert f['verification_status'] == 'candidate'
    assert f['kind'] == 'suspected'
    assert f['source'] == 'tool:nuclei'
    assert f['technique'].startswith('[Nuclei]')


def test_nmap_and_gitleaks_and_ffuf_parsers(tmp_path):
    nmap = ('<nmaprun><host><address addr="1.2.3.4"/><ports><port protocol="tcp" portid="443">'
            '<state state="open"/><service name="https" product="nginx"/></port></ports></host></nmaprun>')
    assert '443' in tp.parse_nmap_xml(reg.get_spec('nmap'), '1.2.3.4', nmap, {})[0]['technique']

    gl = tmp_path / 'gl.json'
    gl.write_text('[{"RuleID":"aws-key","Description":"AWS key","File":"a.py","StartLine":3}]')
    g = tp.parse_gitleaks_json(reg.get_spec('gitleaks'), '.', '', {'outfile': str(gl)})[0]
    assert g['severity'] == 'HIGH' and g['cwe_id'] == 'CWE-798'

    ff = tmp_path / 'ff.json'
    ff.write_text('{"results":[{"input":{"FUZZ":"admin"},"url":"https://e/admin","status":200,"length":12}]}')
    r = tp.parse_ffuf_json(reg.get_spec('ffuf'), 'https://e', '', {'outfile': str(ff)})[0]
    assert r['response_code'] == 200 and 'admin' in r['technique']


def test_kill_proc_tree_terminates():
    p = rt.popen_killable([sys.executable, '-c', 'import time; time.sleep(30)'])
    rt.kill_proc_tree(p)
    p.wait(timeout=5)
    assert p.returncode is not None


def _python_tool(script, *, key='test-tool', needs_api_key=False):
    return reg.ToolSpec(
        key=key,
        name='Test Tool',
        category='vuln',
        binaries=('python3',),
        version_args=('--version',),
        argv_template=('-c', script),
        json_mode='lines',
        parser='generic_lines',
        needs_api_key=needs_api_key,
    )


def test_run_tool_enforces_timeout_without_blocking_on_stdout():
    spec = _python_tool('import time; time.sleep(5)')

    result = rt.run_tool(
        spec, 'https://example.test',
        custom_path=sys.executable, timeout=1,
    )

    assert result['ok'] is False
    assert result['state'] == 'timeout'


def test_run_tool_redacts_api_key_and_reports_nonzero_exit():
    secret = 'secret-token-value'
    spec = _python_tool(
        'import sys; print(sys.argv[-1]); sys.exit(3)',
        key='wpscan', needs_api_key=True,
    )
    logged = []

    result = rt.run_tool(
        spec, 'https://example.test',
        custom_path=sys.executable,
        api_key=secret,
        on_line=logged.append,
    )

    assert result['ok'] is False
    assert result['state'] == 'failed'
    assert result['returncode'] == 3
    assert secret not in ' '.join(result['argv'])
    assert secret not in '\n'.join(result['raw_lines'])
    assert secret not in '\n'.join(logged)


def test_run_tool_scope_block_and_empty_output_are_not_findings():
    spec = _python_tool('')
    blocked = rt.run_tool(
        spec, 'https://outside.test',
        custom_path=sys.executable,
        authorize_target=lambda _target: False,
    )
    completed = rt.run_tool(
        spec, 'https://inside.test',
        custom_path=sys.executable,
        authorize_target=lambda _target: True,
    )

    assert blocked['state'] == 'scope_blocked'
    assert completed['ok'] is True
    assert completed['findings'] == []


def test_guided_workbenches_cover_duplicate_specialist_runners():
    routes = {
        key: spec.guided_workbench
        for key, spec in reg.TOOL_REGISTRY.items()
        if spec.guided_workbench
    }
    assert {
        'ffuf': 'fuzzer',
        'feroxbuster': 'fuzzer',
        'gobuster': 'fuzzer',
        'sqlmap': 'sqli',
        'ghauri': 'sqli',
        'trufflehog': 'secrets',
        'gitleaks': 'secrets',
    }.items() <= routes.items()
