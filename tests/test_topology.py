from wafpierce.topology import (
    VULNERABLE_COLOR,
    build_topology,
    extract_live_hosts,
    find_topology_node,
    host_detail_rows,
    topology_positions,
)


def _report(with_hops=True):
    origin = {
        'hostname': 'example.test',
        'is_apex': True,
        'ip_addresses': ['192.0.2.1'],
        'os_fingerprint': 'Linux 6.x',
    }
    api = {
        'hostname': 'api.example.test',
        'ip_addresses': ['192.0.2.20'],
        'http_url': 'https://api.example.test',
        'http_status': 200,
    }
    if with_hops:
        origin['hop_distance'] = 0
        api['hop_distance'] = 2
    return {
        'target': 'example.test',
        'findings': [],
        'stages': {
            'hosts': [origin, api],
            'ports': [
                {
                    'host': '192.0.2.20',
                    'port': 443,
                    'protocol': 'tcp',
                    'service': 'https',
                    'product': 'nginx',
                },
            ],
            'naabu': [
                {'host': 'api.example.test', 'ip': '192.0.2.20', 'port': 8443},
            ],
            'vulns': [
                {
                    'matched-at': 'https://api.example.test/login',
                    'template-id': 'CVE-2099-0001',
                    'info': {'name': 'Example vulnerability'},
                },
            ],
            'connections': [
                {'source': 'example.test', 'target': 'api.example.test'},
            ],
        },
    }


def test_topology_joins_existing_discovery_output():
    graph = build_topology(_report())

    assert graph['layout'] == 'rings'
    assert graph['origin_id'] == 'example.test'
    assert graph['edges'] == [{
        'source': 'example.test',
        'target': 'api.example.test',
        'kind': 'connection',
    }]

    api = find_topology_node(graph, {'hostname': 'api.example.test'})
    assert api['port_count'] == 2
    assert api['vulnerable'] is True
    assert api['color'] == VULNERABLE_COLOR
    assert api['os'].startswith('Linux')
    assert api['radius'] > find_topology_node(graph, 'example.test')['radius']
    assert ('OS fingerprint', api['os']) in host_detail_rows(api)

    positions = topology_positions(graph)
    assert positions['example.test'] == (0.0, 0.0)
    assert positions['api.example.test'] != (0.0, 0.0)


def test_topology_falls_back_to_force_layout_and_discovery_links():
    report = _report(with_hops=False)
    report['stages'].pop('connections')
    graph = build_topology(report)

    assert graph['layout'] == 'force'
    assert graph['edges'][0]['kind'] == 'discovery'
    positions = topology_positions(graph)
    assert set(positions) == {'example.test', 'api.example.test'}
    assert all(len(position) == 2 for position in positions.values())


def test_traceroute_hops_create_rings_and_direct_edges():
    report = _report(with_hops=False)
    report['stages'].pop('connections')
    report['stages']['traceroute'] = {
        'hops': [
            {'hostname': 'example.test', 'hop': 0},
            {'hostname': 'api.example.test', 'hop': 1},
        ],
    }

    graph = build_topology(report)

    assert graph['layout'] == 'rings'
    assert graph['edges'] == [{
        'source': 'example.test',
        'target': 'api.example.test',
        'kind': 'traceroute',
    }]


def test_live_output_updates_hosts_without_out_of_scope_noise():
    hosts = extract_live_hosts(
        '[+] httpx host https://api.example.test 192.0.2.20\n'
        '[debug] https://unrelated.invalid 198.51.100.5\n'
        '[+] nmap 192.0.2.20: 2 open ports',
        '*.example.test',
    )

    assert [host['hostname'] for host in hosts] == ['api.example.test']
    assert hosts[0]['ip_addresses'] == ['192.0.2.20']
    assert hosts[0]['http_live'] is True
