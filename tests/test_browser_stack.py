import base64
import xml.etree.ElementTree as ET

import pytest

from wafpierce.browser_automation import load_config, scope_allows
from wafpierce.browser_stack import (
    apply_injection_marker,
    burp_xml,
    create_engine_artifacts,
    engine_command,
    private_artifact_dir,
    raw_http_request,
    redact_command,
    write_private_text,
)


def _transaction():
    return {
        'method': 'POST',
        'url': 'https://api.example.test/v1/users?id=7',
        'reqHeaders': {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer very-secret',
            'Cookie': 'session=private',
        },
        'reqBody': '{"name":"alice"}',
        'status': 200,
        'respHeaders': {'Content-Type': 'application/json'},
        'respBody': '{"id":7}',
    }


def test_raw_and_burp_handoffs_preserve_exact_request():
    raw = raw_http_request(_transaction())
    assert raw.startswith('POST /v1/users?id=7 HTTP/1.1\r\n')
    assert 'Authorization: Bearer very-secret\r\n' in raw
    assert raw.endswith('{"name":"alice"}')

    root = ET.fromstring(burp_xml(_transaction()))
    encoded = root.findtext('./item/request')
    decoded = base64.b64decode(encoded).decode('utf-8')
    assert decoded == raw
    assert root.findtext('./item/method') == 'POST'
    assert root.findtext('./item/protocol') == 'https'


def test_handoff_rejects_header_injection():
    transaction = _transaction()
    transaction['reqHeaders']['X-Test'] = 'ok\r\nInjected: yes'
    with pytest.raises(ValueError, match='Invalid HTTP header value'):
        raw_http_request(transaction)


def test_engine_commands_are_argv_lists_and_use_private_artifacts(tmp_path):
    artifacts = create_engine_artifacts(_transaction(), str(tmp_path))
    assert engine_command(
        'nuclei', 'nuclei', _transaction(), artifacts
    ) == [
        'nuclei', '-l', artifacts['burp'], '-im', 'burp', '-silent', '-jsonl',
    ]
    assert engine_command(
        'dalfox', 'dalfox', _transaction(), artifacts
    )[:3] == ['dalfox', 'scan', artifacts['raw']]
    sqlmap = engine_command(
        'sqlmap', 'sqlmap', _transaction(), artifacts, output_dir=str(tmp_path)
    )
    assert sqlmap[:3] == ['sqlmap', '-r', artifacts['raw']]
    retire = engine_command(
        'retire', 'retire-site-scanner', _transaction(), artifacts
    )
    assert retire[-1] == _transaction()['url']
    assert '--cookies' in retire
    assert 'session=private' not in ' '.join(redact_command(retire, _transaction()))


def test_interactsh_requires_an_explicit_marker():
    with pytest.raises(ValueError, match='explicit FUZZ marker'):
        apply_injection_marker(_transaction(), 'http://callback.test')

    marked = _transaction()
    marked['url'] += '&next=FUZZ'
    marked['reqBody'] = '{"callback":"FUZZ"}'
    request = apply_injection_marker(marked, 'http://callback.test')
    assert request['marker_replacements'] == 2
    assert 'FUZZ' not in request['url']
    assert 'FUZZ' not in request['data']


def test_playwright_config_enforces_exact_scope(tmp_path):
    assert scope_allows('https://api.example.test/path', 'example.test')
    assert not scope_allows('https://example.test.attacker.invalid', 'example.test')

    config = tmp_path / 'playwright.json'
    config.write_text(
        '{"start_url":"https://api.example.test","scope_host":"example.test",'
        '"max_pages":999}',
        encoding='utf-8',
    )
    loaded = load_config(str(config))
    assert loaded['max_pages'] == 100

    config.write_text(
        '{"start_url":"https://attacker.invalid","scope_host":"example.test"}',
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='outside'):
        load_config(str(config))


def test_private_writer_blocks_path_escape():
    directory = private_artifact_dir()
    with pytest.raises(ValueError, match='filename'):
        write_private_text(directory, '../request.http', 'GET / HTTP/1.1')
