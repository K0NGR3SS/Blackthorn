from wafpierce.topology import (
    PORT_COLORS,
    VULNERABLE_COLOR,
    build_topology,
    extract_live_hosts,
    find_topology_node,
    host_detail_rows,
    topology_distances,
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
    assert graph['edges'][0] == {
        'source': 'example.test',
        'target': 'api.example.test',
        'kind': 'connection',
        'evidence': 'reported',
        'latency_ms': None,
        'path_id': None,
    }

    api = find_topology_node(graph, {'hostname': 'api.example.test'})
    assert api['port_count'] == 2
    assert api['vulnerable'] is True
    assert api['color'] == VULNERABLE_COLOR
    assert api['fill_color'] == PORT_COLORS['low']
    assert api['os'].startswith('Linux')
    assert api['radius'] > find_topology_node(graph, 'example.test')['radius']
    assert ('OS fingerprint', api['os']) in host_detail_rows(api)

    positions = topology_positions(graph)
    assert positions['example.test'] == (0.0, 0.0)
    assert positions['api.example.test'] != (0.0, 0.0)


def test_topology_falls_back_to_radial_relationship_layers():
    report = _report(with_hops=False)
    report['stages'].pop('connections')
    graph = build_topology(report)

    assert graph['layout'] == 'rings'
    assert graph['distance_source'] == 'relationship'
    assert graph['edges'][0]['kind'] == 'discovery'
    assert graph['edges'][0]['evidence'] == 'inferred'
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
        'evidence': 'reported',
        'latency_ms': None,
        'path_id': 0,
    }]


def test_topology_recovers_rich_partial_stage_evidence_and_shared_ip():
    report = {
        'target': 'example.test',
        'stages': {
            'subdomains': ['example.test', 'api.example.test', 'www.example.test'],
            'sources': {
                'api.example.test': ['subfinder'],
                'www.example.test': ['certificate transparency'],
            },
            'resolved': {
                'example.test': ['192.0.2.1'],
                'api.example.test': ['192.0.2.20'],
                'www.example.test': ['192.0.2.20'],
            },
            'http': [{
                'input': 'api.example.test',
                'url': 'https://api.example.test',
                'status_code': 200,
                'title': 'API',
                'webserver': 'nginx',
                'tech': ['Go'],
                'cname': ['edge.example-cdn.test'],
                'live': True,
            }],
            'tls': [{
                'host': 'api.example.test',
                'subject_cn': 'api.example.test',
                'issuer_cn': 'Test CA',
            }],
            'ports': [{
                'host': '192.0.2.20', 'port': 443, 'protocol': 'tcp',
                'service': 'https', 'product': 'nginx',
            }],
            'endpoints': ['https://api.example.test/v1/users'],
            'historical': ['https://api.example.test/v0'],
            'vulns': [],
        },
    }

    graph = build_topology(report)
    api = find_topology_node(graph, 'api.example.test')
    www = find_topology_node(graph, 'www.example.test')

    assert api['port_count'] == 1
    assert www['port_count'] == 1
    assert api['title'] == 'API'
    assert api['technologies'] == ['Go']
    assert api['endpoint_count'] == 1
    assert api['historical_count'] == 1
    assert api['tls'][0]['issuer_cn'] == 'Test CA'
    assert api['coverage']['tls'] == 'observed'
    assert graph['summary']['hosts'] == 3
    assert any(
        node['id'] == 'address:192.0.2.20'
        for node in graph['nodes']
    )
    assert {edge['kind'] for edge in graph['edges']} >= {
        'cname', 'shared_address', 'discovery',
    }
    distances = topology_distances(graph)
    assert distances['address:192.0.2.20'] == distances['api.example.test']


def test_traceroute_keeps_intermediate_hops_latency_and_recentering():
    report = _report(with_hops=False)
    report['stages'].pop('connections')
    report['stages']['traceroute'] = [{
        'target': '192.0.2.20',
        'hops': [
            {'ip': '198.51.100.1', 'hop': 1, 'rtt': 3.4},
            {'ip': '192.0.2.20', 'hop': 2, 'rtt': 18.2},
        ],
    }]

    graph = build_topology(report)

    router = find_topology_node(graph, '198.51.100.1')
    assert router is not None
    assert router['is_intermediate'] is True
    assert router['latency_ms'] == 3.4
    route_edges = [edge for edge in graph['edges'] if edge['kind'] == 'traceroute']
    assert len(route_edges) == 2
    assert route_edges[-1]['latency_ms'] == 18.2
    assert topology_distances(graph, router['id'])[router['id']] == 0
    assert topology_positions(graph, router['id'])[router['id']] == (0.0, 0.0)


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


def test_asset_graph_includes_correlated_external_and_parameter_intelligence():
    report = _report(with_hops=False)
    report['stages'].update({
        'uncover': [{
            'host': 'dev.example.test', 'a': ['192.0.2.30'],
        }],
        'arjun': [{
            'url': 'https://api.example.test/v2/admin', 'method': 'POST',
            'parameters': ['tenant'],
        }],
        'risk_signals': [{
            'target': 'https://api.example.test/v2/admin',
            'severity': 'HIGH', 'category': 'sensitive_path',
            'reason': 'Sensitive API route discovered',
        }],
    })

    graph = build_topology(report)
    dev = find_topology_node(graph, 'dev.example.test')
    api = find_topology_node(graph, 'api.example.test')

    assert dev is not None
    assert 'uncover' in dev['sources']
    assert 'https://api.example.test/v2/admin' in api['endpoints']
    assert api['vulnerable'] is True
    assert api['risk_severity'] == 'HIGH'
