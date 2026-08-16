"""Discovery topology model and PySide6 visualization.

The model deliberately consumes the existing recon report shape.  It does not
run network tools or alter discovery behaviour; it only joins host, port,
service, OS, vulnerability, hop, and connection records for presentation.
"""
from __future__ import annotations

import html
import ipaddress
import math
import re
from collections import deque
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse


OS_COLORS = {
    'linux': '#5fc98f',
    'windows': '#62a8ff',
    'bsd': '#a78bfa',
    'network': '#f2b84b',
    'unknown': '#82909c',
}
VULNERABLE_COLOR = '#ff5d6c'
PORT_COLORS = {
    'unscanned': '#d8dee3',
    'low': '#5fc98f',
    'medium': '#e4b752',
    'high': '#ee6a65',
}
EDGE_COLORS = {
    'traceroute': '#4f9ccc',
    'alternate': '#dc9650',
    'connection': '#72a8a1',
    'cname': '#75b9c7',
    'shared_address': '#9b8bc7',
    'discovery': '#53636b',
}

_SEVERITY_ORDER = {
    'INFO': 0,
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}

_HOST_RE = re.compile(
    r'(?<![\w.-])((?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}'
    r'[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,})(?![\w.-])'
)
_IP_RE = re.compile(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])')
_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def _list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _target_host(value: Any) -> str:
    raw = str(value or '').strip().lower().rstrip('.')
    if not raw:
        return ''
    parsed = urlparse(raw if '://' in raw else '//' + raw)
    host = (parsed.hostname or raw.split('/')[0].split(':')[0]).rstrip('.')
    while host.startswith('*.'):
        host = host[2:]
    return host


def _valid_ip(value: Any) -> str:
    raw = str(value or '').strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ''


def _record_aliases(record: Mapping[str, Any]) -> List[str]:
    aliases = []
    for key in (
            'id', 'hostname', 'host', 'ip', 'ipaddr', 'address', 'target',
            'url', 'input', 'name', 'canonical_name'):
        value = record.get(key)
        if value:
            ip = _valid_ip(value)
            if ip:
                aliases.append(ip)
                continue
            host = _target_host(value)
            if host:
                aliases.append(host)
    for value in _list(record.get('ip_addresses')):
        ip = _valid_ip(value)
        if ip:
            aliases.append(ip)
    return list(dict.fromkeys(aliases))


def _strings(value: Any) -> List[str]:
    """Return unique, non-empty text values without flattening mappings."""
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return list(dict.fromkeys(
        str(item).strip() for item in values
        if item is not None and not isinstance(item, Mapping) and str(item).strip()
    ))


def _port_key(port: Mapping[str, Any]) -> Tuple[str, str]:
    return (
        str(port.get('port') or ''),
        str(port.get('protocol') or 'tcp').lower(),
    )


def _service_label(port: Mapping[str, Any]) -> str:
    product = ' '.join(
        str(port.get(key) or '').strip()
        for key in ('service', 'product', 'version')
        if port.get(key)
    )
    number, protocol = _port_key(port)
    endpoint = f'{number}/{protocol}' if number else protocol
    return f'{endpoint} — {product}' if product else endpoint


def _os_family(value: Any) -> str:
    text = str(value or '').lower()
    if any(token in text for token in ('windows', 'microsoft', 'iis', 'asp.net')):
        return 'windows'
    if any(token in text for token in ('freebsd', 'openbsd', 'netbsd')):
        return 'bsd'
    if any(token in text for token in (
            'cisco', 'junos', 'routeros', 'fortios', 'pan-os', 'network appliance')):
        return 'network'
    if any(token in text for token in (
            'linux', 'ubuntu', 'debian', 'centos', 'red hat', 'nginx', 'apache')):
        return 'linux'
    return 'unknown'


def _host_os(host: Mapping[str, Any], ports: Sequence[Mapping[str, Any]]) -> str:
    for key in ('os_fingerprint', 'operating_system', 'os', 'os_name'):
        value = host.get(key)
        if isinstance(value, Mapping):
            value = value.get('name') or value.get('family') or value.get('match')
        if value:
            return str(value)
    hints = ' '.join(
        [str(host.get('server') or '')]
        + [str(value) for value in _list(host.get('technologies'))]
        + [_service_label(port) for port in ports]
    )
    family = _os_family(hints)
    return {
        'linux': 'Linux / Unix (service hint)',
        'windows': 'Windows (service hint)',
        'bsd': 'BSD (service hint)',
        'network': 'Network appliance (service hint)',
        'unknown': 'Unknown',
    }[family]


def _hop_value(record: Mapping[str, Any]) -> Optional[int]:
    for key in ('hop_distance', 'hop', 'distance', 'ttl_distance'):
        try:
            value = int(record.get(key))
        except (TypeError, ValueError):
            continue
        if value >= 0:
            return value
    return None


def _looks_vulnerable(finding: Mapping[str, Any]) -> bool:
    technique = str(finding.get('technique') or finding.get('type') or '').lower()
    return bool(
        finding.get('vulnerability')
        or finding.get('cve')
        or finding.get('nuclei')
        or finding.get('dalfox')
        or technique.startswith('vuln:')
        or technique in {'xss', 'vulnerability'}
        or 'cve-' in technique
    )


def _vulnerability_label(record: Mapping[str, Any]) -> str:
    info = record.get('info') if isinstance(record.get('info'), Mapping) else {}
    return str(
        info.get('name')
        or record.get('name')
        or record.get('template-id')
        or record.get('template_id')
        or record.get('technique')
        or record.get('type')
        or 'Known vulnerability'
    )


def _finding_severity(record: Mapping[str, Any]) -> str:
    info = record.get('info') if isinstance(record.get('info'), Mapping) else {}
    severity = str(
        info.get('severity') or record.get('severity') or 'INFO'
    ).upper()
    return severity if severity in _SEVERITY_ORDER else 'INFO'


def _latency_ms(record: Mapping[str, Any]) -> Optional[float]:
    for key in ('latency_ms', 'rtt', 'rtt_ms', 'srtt'):
        try:
            value = float(record.get(key))
        except (TypeError, ValueError):
            continue
        if value >= 0:
            return value
    return None


def _device_type(host: Mapping[str, Any], os_name: str) -> str:
    text = ' '.join(
        str(value or '') for value in (
            host.get('device_type'), host.get('type'), host.get('role'), os_name,
        )
    ).lower()
    for value in ('firewall', 'router', 'switch', 'wireless'):
        if value in text:
            return value
    return 'host'


def _resolve_nodes(value: Any, aliases: Mapping[str, Any]) -> List[str]:
    if isinstance(value, Mapping):
        candidates = _record_aliases(value)
    else:
        raw = str(value or '').strip().lower().rstrip('.')
        candidates = [candidate for candidate in (
            raw if raw in aliases else '', _valid_ip(value), _target_host(value)
        ) if candidate]
    resolved: List[str] = []
    for candidate in candidates:
        matches = aliases.get(candidate, [])
        if isinstance(matches, str):
            matches = [matches]
        for match in matches:
            if match and match not in resolved:
                resolved.append(str(match))
    return resolved


def _resolve_node(value: Any, aliases: Mapping[str, str]) -> str:
    return next(iter(_resolve_nodes(value, aliases)), '')


def build_topology(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Join every available discovery stage into an evidence-aware graph.

    The graph never presents a guessed network path as measured.  Reported
    links and traceroute hops stay solid, DNS/CNAME infrastructure links keep
    their own kinds, and the scope-to-host fallback is explicitly inferred.
    """
    report = report if isinstance(report, Mapping) else {}
    stages = report.get('stages') if isinstance(report.get('stages'), Mapping) else {}
    target = _target_host(report.get('target'))
    nodes_by_id: Dict[str, Dict[str, Any]] = {}

    def ensure_node(record: Mapping[str, Any], *, node_type: str = 'host') -> Dict[str, Any]:
        raw = dict(record)
        aliases_found = _record_aliases(raw)
        node_id = (
            (str(raw.get('id') or '') if node_type != 'host' else '')
            or str(raw.get('hostname') or '').lower().rstrip('.')
            or next(iter(aliases_found), '')
            or str(raw.get('id') or f'host-{len(nodes_by_id) + 1}')
        )
        existing = nodes_by_id.get(node_id)
        if existing:
            existing['raw'].update(raw)
            direct_ip = _valid_ip(
                raw.get('ip') or raw.get('ipaddr') or raw.get('address')
            )
            existing['ip_addresses'] = list(dict.fromkeys(
                existing['ip_addresses'] + _strings(raw.get('ip_addresses'))
                + ([direct_ip] if direct_ip else [])
            ))
            existing['sources'] = list(dict.fromkeys(
                existing['sources'] + _strings(raw.get('sources'))
            ))
            if raw.get('dns_status') or raw.get('dns_live') is True:
                existing['dns_state'] = str(
                    raw.get('dns_status') or 'resolved'
                )
            if raw.get('http_state') or raw.get('http_live') is True:
                existing['http_state'] = str(
                    raw.get('http_state') or 'live'
                )
            for key in ('http_url', 'title', 'server'):
                if raw.get(key):
                    existing[key] = str(raw[key])
            if raw.get('http_status') is not None:
                existing['http_status'] = raw['http_status']
            existing['technologies'] = list(dict.fromkeys(
                existing['technologies'] + _strings(raw.get('technologies'))
            ))
            return existing
        hostname = str(
            raw.get('hostname') or raw.get('host') or raw.get('name') or node_id
        )
        node = {
            'id': node_id,
            'label': hostname,
            'hostname': hostname,
            'node_type': node_type,
            'ip_addresses': _strings(raw.get('ip_addresses')),
            'aliases': [],
            'sources': _strings(raw.get('sources')),
            'dns_state': str(
                raw.get('dns_status')
                or ('resolved' if raw.get('dns_live') is True else 'unknown')
            ),
            'http_state': str(
                raw.get('http_state')
                or ('live' if raw.get('http_live') is True else 'unknown')
            ),
            'http_url': str(raw.get('http_url') or ''),
            'http_status': raw.get('http_status'),
            'title': str(raw.get('title') or ''),
            'server': str(raw.get('server') or ''),
            'technologies': _strings(raw.get('technologies')),
            'cnames': [],
            'tls': [],
            'endpoints': [],
            'historical_urls': [],
            'ports': [],
            'services': [],
            'os': '',
            'os_family': 'unknown',
            'device_type': 'host',
            'vulnerabilities': [],
            'vulnerability_records': [],
            'risk_severity': 'INFO',
            'vulnerable': False,
            'hop': _hop_value(raw),
            'latency_ms': _latency_ms(raw),
            'is_origin': bool(raw.get('is_origin')),
            'is_intermediate': node_type == 'route',
            'is_external': bool(raw.get('is_external')),
            'raw': raw,
        }
        direct_ip = _valid_ip(raw.get('ip') or raw.get('ipaddr') or raw.get('address'))
        if direct_ip and direct_ip not in node['ip_addresses']:
            node['ip_addresses'].append(direct_ip)
        nodes_by_id[node_id] = node
        return node

    # Start from the inventory, then recover hosts which only appear in a raw
    # stage.  Partial and older reports therefore retain useful topology data.
    for host in _list(stages.get('hosts')):
        if isinstance(host, Mapping):
            ensure_node(host)
    for hostname in _strings(stages.get('subdomains')):
        ensure_node({'hostname': hostname})

    resolved = stages.get('resolved') if isinstance(stages.get('resolved'), Mapping) else {}
    for hostname, addresses in resolved.items():
        node = ensure_node({
            'hostname': hostname,
            'dns_status': 'resolved',
            'dns_live': True,
            'ip_addresses': _strings(addresses),
        })
        node['ip_addresses'] = list(dict.fromkeys(
            node['ip_addresses'] + _strings(addresses)
        ))

    sources_by_host = stages.get('sources') if isinstance(stages.get('sources'), Mapping) else {}
    for hostname, sources in sources_by_host.items():
        node = ensure_node({'hostname': hostname})
        node['sources'] = list(dict.fromkeys(node['sources'] + _strings(sources)))

    http_rows = [
        dict(row) for row in _list(stages.get('http'))
        if isinstance(row, Mapping)
    ]
    for row in http_rows:
        hostname = _target_host(
            row.get('input') or row.get('url') or row.get('host')
            or row.get('hostname')
        )
        if not hostname:
            continue
        node = ensure_node({'hostname': hostname})
        status = row.get('status_code') or row.get('status-code')
        url = str(row.get('url') or '')
        live = bool(row.get('live') or status is not None or url.startswith(('http://', 'https://')))
        if live:
            node['http_state'] = 'live'
        node['http_url'] = url or node['http_url']
        node['http_status'] = status if status is not None else node['http_status']
        node['title'] = str(row.get('title') or node['title'])
        node['server'] = str(
            row.get('webserver') or row.get('web-server') or node['server']
        )
        node['technologies'] = list(dict.fromkeys(
            node['technologies']
            + _strings(row.get('tech') or row.get('technologies'))
        ))
        node['cnames'] = list(dict.fromkeys(
            node['cnames'] + _strings(row.get('cname') or row.get('cnames'))
        ))

    if target:
        ensure_node({'hostname': target, 'is_apex': True})
    origin_id = next((
        node_id for node_id, node in nodes_by_id.items()
        if target and (node_id == target or target in _record_aliases(node['raw']))
    ), '')
    if not origin_id:
        origin_id = next((
            node_id for node_id, node in nodes_by_id.items()
            if node['raw'].get('is_origin') or node['raw'].get('is_apex')
        ), next(iter(nodes_by_id), ''))
    if origin_id:
        nodes_by_id[origin_id]['is_origin'] = True
        nodes_by_id[origin_id]['hop'] = 0

    def build_aliases() -> Dict[str, List[str]]:
        alias_map: Dict[str, List[str]] = {}
        for node_id, node in nodes_by_id.items():
            values = [node_id, str(node.get('hostname') or '').lower().rstrip('.')]
            values += _record_aliases(node.get('raw') or {})
            values += _strings(node.get('ip_addresses'))
            for alias in values:
                if alias:
                    alias_map.setdefault(alias, [])
                    if node_id not in alias_map[alias]:
                        alias_map[alias].append(node_id)
        return alias_map

    aliases = build_aliases()

    # Ports discovered for a shared address belong to every hostname resolving
    # to it. This avoids the old last-write-wins alias bug.
    port_rows: List[Dict[str, Any]] = []
    for key in ('ports', 'naabu'):
        port_rows.extend(
            dict(row) for row in _list(stages.get(key))
            if isinstance(row, Mapping)
        )
    for node in list(nodes_by_id.values()):
        for value in _list(node['raw'].get('ports')):
            row = dict(value) if isinstance(value, Mapping) else {
                'port': value, 'protocol': 'tcp',
            }
            row.setdefault('host', node['id'])
            port_rows.append(row)
    for port in port_rows:
        for node_id in _resolve_nodes(port, aliases):
            node = nodes_by_id[node_id]
            if _port_key(port) not in {_port_key(item) for item in node['ports']}:
                node['ports'].append(dict(port))

    os_rows = stages.get('os_fingerprints') or stages.get('operating_systems') or {}
    if isinstance(os_rows, Mapping):
        os_rows = [
            {'host': key, 'os_fingerprint': value}
            for key, value in os_rows.items()
        ]
    for os_row in _list(os_rows):
        if not isinstance(os_row, Mapping):
            continue
        for node_id in _resolve_nodes(os_row, aliases):
            nodes_by_id[node_id]['raw']['os_fingerprint'] = (
                os_row.get('os_fingerprint') or os_row.get('os')
                or os_row.get('name')
            )

    for cert in _list(stages.get('tls')):
        if not isinstance(cert, Mapping):
            continue
        for node_id in _resolve_nodes(cert, aliases):
            if dict(cert) not in nodes_by_id[node_id]['tls']:
                nodes_by_id[node_id]['tls'].append(dict(cert))

    for key, destination in (
            ('endpoints', 'endpoints'), ('historical', 'historical_urls')):
        for value in _list(stages.get(key)):
            url = str(value.get('url') if isinstance(value, Mapping) else value or '')
            for node_id in _resolve_nodes(url, aliases):
                if url and url not in nodes_by_id[node_id][destination]:
                    nodes_by_id[node_id][destination].append(url)

    vulnerability_rows: List[Dict[str, Any]] = []
    for key in ('vulns', 'vulnerabilities', 'xss'):
        vulnerability_rows.extend(
            dict(row) for row in _list(stages.get(key))
            if isinstance(row, Mapping)
        )
    vulnerability_rows.extend(
        dict(row) for row in _list(report.get('findings'))
        if isinstance(row, Mapping) and _looks_vulnerable(row)
    )
    for node in list(nodes_by_id.values()):
        for value in _list(node['raw'].get('vulnerabilities')):
            vulnerability_rows.append(
                dict(value, host=node['id']) if isinstance(value, Mapping)
                else {'name': value, 'host': node['id']}
            )
    for vulnerability in vulnerability_rows:
        match_value = (
            vulnerability.get('matched-at') or vulnerability.get('matched_at')
            or vulnerability.get('url') or vulnerability.get('host')
            or vulnerability.get('target') or vulnerability.get('data')
        )
        for node_id in _resolve_nodes(match_value, aliases):
            label = _vulnerability_label(vulnerability)
            node = nodes_by_id[node_id]
            if label not in node['vulnerabilities']:
                node['vulnerabilities'].append(label)
                node['vulnerability_records'].append({
                    'label': label,
                    'severity': _finding_severity(vulnerability),
                })

    # Recover every intermediate hop. The old model silently connected across
    # omitted routers, making paths look shorter and more certain than reported.
    traceroute = stages.get('traceroute') or stages.get('routes') or []
    route_groups: List[List[Mapping[str, Any]]] = []
    if isinstance(traceroute, Mapping):
        if isinstance(traceroute.get('hops'), (list, tuple)):
            route_groups.append([
                row for row in traceroute['hops'] if isinstance(row, Mapping)
            ])
        else:
            for value in traceroute.values():
                rows = value.get('hops') if isinstance(value, Mapping) else value
                if isinstance(rows, (list, tuple)):
                    route_groups.append([
                        row for row in rows if isinstance(row, Mapping)
                    ])
    elif isinstance(traceroute, (list, tuple)):
        flat_rows = []
        for value in traceroute:
            if isinstance(value, Mapping) and isinstance(value.get('hops'), (list, tuple)):
                route_groups.append([
                    row for row in value['hops'] if isinstance(row, Mapping)
                ])
            elif isinstance(value, Mapping):
                flat_rows.append(value)
        if flat_rows:
            route_groups.append(flat_rows)

    traceroute_connections: List[Dict[str, Any]] = []
    for route_index, route in enumerate(route_groups):
        previous_id = origin_id
        for row_index, hop_row in enumerate(route):
            aliases = build_aliases()
            node_id = _resolve_node(hop_row, aliases)
            hop = _hop_value(hop_row)
            if not node_id:
                address = (
                    _valid_ip(hop_row.get('ipaddr') or hop_row.get('ip') or hop_row.get('address'))
                )
                hostname = _target_host(hop_row.get('hostname') or hop_row.get('host'))
                node_id = hostname or address or f'unknown-hop-{route_index + 1}-{row_index + 1}'
                node = ensure_node({
                    'id': node_id,
                    'hostname': hostname or address or f'Unknown hop {hop or row_index + 1}',
                    'ip_addresses': [address] if address else [],
                    'hop': hop,
                    'latency_ms': _latency_ms(hop_row),
                    'is_intermediate': True,
                }, node_type='route')
                node_id = str(node['id'])
            node = nodes_by_id[node_id]
            node['is_intermediate'] = bool(node.get('is_intermediate') or node['node_type'] == 'route')
            if hop is not None:
                node['hop'] = hop
            latency = _latency_ms(hop_row)
            if latency is not None:
                node['latency_ms'] = latency
            if previous_id and previous_id != node_id:
                traceroute_connections.append({
                    'source': previous_id,
                    'target': node_id,
                    'kind': 'traceroute',
                    'latency_ms': latency,
                    'path_id': route_index,
                })
            previous_id = node_id

    # CNAME targets are meaningful infrastructure, even when they fall outside
    # the requested domain. Shared IPs get a junction only when they explain a
    # real many-to-one relationship.
    cname_connections: List[Tuple[str, str]] = []
    for node in list(nodes_by_id.values()):
        for cname in node['cnames']:
            target_name = _target_host(cname)
            if not target_name or target_name == node['id']:
                continue
            cname_node = ensure_node({
                'hostname': target_name,
                'is_external': bool(target and not (
                    target_name == target or target_name.endswith('.' + target)
                )),
            }, node_type='infrastructure')
            cname_connections.append((node['id'], cname_node['id']))

    address_connections: List[Tuple[str, str]] = []
    hosts_by_ip: Dict[str, List[str]] = {}
    for node in list(nodes_by_id.values()):
        if node['node_type'] == 'host':
            for address in node['ip_addresses']:
                hosts_by_ip.setdefault(address, []).append(node['id'])
    for address, host_ids in hosts_by_ip.items():
        unique_hosts = list(dict.fromkeys(host_ids))
        if len(unique_hosts) < 2:
            continue
        address_id = f'address:{address}'
        address_node = ensure_node({
            'id': address_id,
            'hostname': address,
            'ip_addresses': [address],
            'role': 'shared address',
        }, node_type='infrastructure')
        address_node['ports'] = []
        for host_id in unique_hosts:
            for port in nodes_by_id[host_id]['ports']:
                if _port_key(port) not in {
                        _port_key(item) for item in address_node['ports']}:
                    address_node['ports'].append(dict(port))
            address_connections.append((host_id, address_id))

    aliases = build_aliases()
    declared_coverage = (
        stages.get('coverage')
        if isinstance(stages.get('coverage'), Mapping) else {}
    )

    def covered(key: str, fallback: bool) -> bool:
        # Observed evidence wins over stale/incorrect configuration metadata.
        return bool(declared_coverage.get(key)) or fallback

    stage_coverage = {
        'dns': covered('dns', bool(resolved) or any(
            node.get('dns_state') != 'unknown' or node.get('ip_addresses')
            for node in nodes_by_id.values()
        )),
        'http': covered('http', bool(http_rows) or any(
            node.get('http_state') != 'unknown' or node.get('http_url')
            or node.get('http_status') is not None
            for node in nodes_by_id.values()
        )),
        'ports': covered('ports', bool(port_rows)),
        'tls': covered('tls', any(node['tls'] for node in nodes_by_id.values())),
        'routes': covered('routes', bool(route_groups)),
        'content': covered('content', any(
            node['endpoints'] or node['historical_urls']
            for node in nodes_by_id.values()
        )),
        'vulnerabilities': covered('vulnerabilities', bool(vulnerability_rows)),
    }

    for node in nodes_by_id.values():
        node['ports'].sort(key=lambda item: (
            int(item.get('port')) if str(item.get('port') or '').isdigit() else 65536,
            str(item.get('protocol') or 'tcp'),
        ))
        node['services'] = list(dict.fromkeys(
            _service_label(port) for port in node['ports']
        ))
        node['os'] = _host_os(node['raw'], node['ports'])
        node['os_family'] = _os_family(node['os'])
        node['device_type'] = _device_type(node['raw'], node['os'])
        node['vulnerable'] = bool(node['vulnerabilities'])
        node['risk_severity'] = max(
            (record['severity'] for record in node['vulnerability_records']),
            key=lambda severity: _SEVERITY_ORDER.get(severity, 0),
            default='INFO',
        )
        node['port_count'] = len(node['ports'])
        node['endpoint_count'] = len(node['endpoints'])
        node['historical_count'] = len(node['historical_urls'])
        node['radius'] = (
            11.0 if node['is_intermediate'] else
            min(30.0, 14.0 + math.sqrt(node['port_count']) * 4.2)
        )
        port_band = (
            'unscanned' if not stage_coverage['ports'] and not node['ports']
            else 'low' if node['port_count'] < 3
            else 'medium' if node['port_count'] < 7
            else 'high'
        )
        node['fill_color'] = PORT_COLORS[port_band]
        # Keep the historical API color while the renderer follows Zenmap's
        # port-count fill convention and uses risk as an outer ring.
        node['color'] = (
            VULNERABLE_COLOR if node['vulnerable']
            else OS_COLORS[node['os_family']]
        )
        node['aliases'] = list(dict.fromkeys(
            alias for alias in _record_aliases(node['raw'])
            if alias not in {node['id'], node['hostname']}
        ))
        node['coverage'] = {
            key: ('observed' if enabled else 'not_run')
            for key, enabled in stage_coverage.items()
        }
        if node['dns_state'] == 'unknown' and node['ip_addresses']:
            node['dns_state'] = 'resolved'
        if node['http_state'] == 'unknown' and node['http_url']:
            node['http_state'] = 'live'

    edge_by_pair: Dict[Tuple[str, str], Dict[str, Any]] = {}
    priority = {
        'discovery': 0,
        'shared_address': 1,
        'cname': 2,
        'connection': 3,
        'traceroute': 4,
        'alternate': 5,
    }

    def add_edge(
            source: Any, destination: Any, kind: str = 'connection',
            *, latency_ms: Optional[float] = None,
            path_id: Optional[int] = None) -> None:
        source_id = _resolve_node(source, aliases)
        destination_id = _resolve_node(destination, aliases)
        if not source_id or not destination_id or source_id == destination_id:
            return
        key = tuple(sorted((source_id, destination_id)))
        normalized_kind = kind if kind in priority else 'connection'
        edge = {
            'source': source_id,
            'target': destination_id,
            'kind': normalized_kind,
            'evidence': 'inferred' if normalized_kind == 'discovery' else 'reported',
            'latency_ms': latency_ms,
            'path_id': path_id,
        }
        existing = edge_by_pair.get(key)
        if existing and priority[existing['kind']] >= priority[normalized_kind]:
            return
        edge_by_pair[key] = edge

    for connection in _list(stages.get('connections')):
        if isinstance(connection, Mapping):
            add_edge(
                connection.get('source') or connection.get('from') or connection.get('host'),
                connection.get('target') or connection.get('to') or connection.get('peer'),
                str(connection.get('kind') or 'connection'),
                latency_ms=_latency_ms(connection),
            )
        elif isinstance(connection, (list, tuple)) and len(connection) >= 2:
            add_edge(connection[0], connection[1])
    for connection in traceroute_connections:
        add_edge(
            connection['source'], connection['target'], connection['kind'],
            latency_ms=connection.get('latency_ms'),
            path_id=connection.get('path_id'),
        )
    for source, destination in cname_connections:
        add_edge(source, destination, 'cname')
    for source, destination in address_connections:
        add_edge(source, destination, 'shared_address')
    for node in nodes_by_id.values():
        for peer in (
            _list(node['raw'].get('connections'))
            + _list(node['raw'].get('neighbors'))
            + _list(node['raw'].get('peers'))
        ):
            add_edge(node['id'], peer)

    reported_adjacency: Dict[str, List[str]] = {
        node_id: [] for node_id in nodes_by_id
    }
    for edge in edge_by_pair.values():
        reported_adjacency[edge['source']].append(edge['target'])
        reported_adjacency[edge['target']].append(edge['source'])
    connected_to_origin = {origin_id} if origin_id else set()
    pending_connections = deque(connected_to_origin)
    while pending_connections:
        source_id = pending_connections.popleft()
        for target_id in reported_adjacency.get(source_id, []):
            if target_id not in connected_to_origin:
                connected_to_origin.add(target_id)
                pending_connections.append(target_id)
    if origin_id:
        for node_id, node in nodes_by_id.items():
            if (
                    node_id != origin_id
                    and node_id not in connected_to_origin
                    and node['node_type'] == 'host'):
                add_edge(origin_id, node_id, 'discovery')

    nodes = list(nodes_by_id.values())
    edges = list(edge_by_pair.values())
    summary = {
        'hosts': sum(node['node_type'] == 'host' for node in nodes),
        'infrastructure': sum(node['node_type'] != 'host' for node in nodes),
        'resolved': sum(node['dns_state'] == 'resolved' for node in nodes if node['node_type'] == 'host'),
        'web_live': sum(node['http_state'] == 'live' for node in nodes if node['node_type'] == 'host'),
        'open_ports': sum(node['port_count'] for node in nodes if node['node_type'] == 'host'),
        'findings': sum(len(node['vulnerabilities']) for node in nodes),
        'measured_paths': sum(edge['kind'] in {'traceroute', 'connection'} for edge in edges),
        'inferred_links': sum(edge['kind'] == 'discovery' for edge in edges),
    }
    return {
        'nodes': nodes,
        'edges': edges,
        'origin_id': origin_id,
        'layout': 'rings',
        'distance_source': 'measured' if stage_coverage['routes'] else 'relationship',
        'coverage': stage_coverage,
        'summary': summary,
    }


def topology_distances(
        graph: Mapping[str, Any], focus_id: Optional[str] = None) -> Dict[str, int]:
    """Return graph/routing distance from the selected radial focus."""
    nodes = list(graph.get('nodes') or [])
    if not nodes:
        return {}
    node_ids = {str(node.get('id') or '') for node in nodes}
    origin_id = str(graph.get('origin_id') or next(iter(node_ids), ''))
    focus = str(focus_id or origin_id)
    if focus not in node_ids:
        focus = origin_id
    adjacency: Dict[str, List[Tuple[str, int]]] = {
        node_id: [] for node_id in node_ids
    }
    for edge in graph.get('edges') or []:
        source = str(edge.get('source') or '')
        target = str(edge.get('target') or '')
        if source in adjacency and target in adjacency:
            # DNS aliases and shared addresses describe the same network layer,
            # not another router hop. Keeping them at zero cost prevents a
            # shared-vhost junction from inflating measured route distance.
            weight = 0 if edge.get('kind') in {'cname', 'shared_address'} else 1
            adjacency[source].append((target, weight))
            adjacency[target].append((source, weight))
    distances = {focus: 0}
    pending = deque([focus])
    while pending:
        source = pending.popleft()
        for target, weight in sorted(adjacency[source]):
            candidate = distances[source] + weight
            if target not in distances or candidate < distances[target]:
                distances[target] = candidate
                if weight == 0:
                    pending.appendleft(target)
                else:
                    pending.append(target)
    if focus == origin_id and graph.get('distance_source') == 'measured':
        for node in nodes:
            if node.get('hop') is not None:
                distances[str(node['id'])] = max(0, int(node['hop']))
    outer = max(distances.values(), default=0) + 1
    for node_id in node_ids:
        distances.setdefault(node_id, outer)
    return distances


def topology_positions(
        graph: Mapping[str, Any], focus_id: Optional[str] = None,
        *, ring_gap: float = 132.0,
        layout_mode: str = 'weighted') -> Dict[str, Tuple[float, float]]:
    """Return deterministic Zenmap-style radial positions for a graph."""
    nodes = list(graph.get('nodes') or [])
    if not nodes:
        return {}
    nodes_by_id = {str(node['id']): node for node in nodes}
    distances = topology_distances(graph, focus_id)
    focus = next((node_id for node_id, distance in distances.items() if distance == 0), '')
    groups: Dict[int, List[Mapping[str, Any]]] = {}
    for node_id, distance in distances.items():
        groups.setdefault(distance, []).append(nodes_by_id[node_id])

    degrees = {node_id: 0 for node_id in nodes_by_id}
    for edge in graph.get('edges') or []:
        source, target = str(edge.get('source') or ''), str(edge.get('target') or '')
        if source in degrees:
            degrees[source] += 1
        if target in degrees:
            degrees[target] += 1

    positions: Dict[str, Tuple[float, float]] = {focus: (0.0, 0.0)} if focus else {}
    previous_radius = 0.0
    for distance, group in sorted(groups.items()):
        if distance == 0:
            for node in group:
                positions[str(node['id'])] = (0.0, 0.0)
            continue
        if layout_mode == 'symmetric':
            ordered = sorted(group, key=lambda item: str(item['id']))
        else:
            ordered = sorted(
                group,
                key=lambda item: (
                    -degrees.get(str(item['id']), 0),
                    str(item.get('node_type') or ''),
                    str(item['id']),
                ),
            )
        minimum_arc = sum(
            max(72.0, float(node.get('radius') or 14.0) * 2 + 54.0)
            for node in ordered
        )
        radius = max(
            distance * ring_gap,
            previous_radius + ring_gap,
            minimum_arc / (2 * math.pi),
        )
        previous_radius = radius
        offset = distance * math.pi * (3.0 - math.sqrt(5.0))
        for index, node in enumerate(ordered):
            angle = 2 * math.pi * index / max(1, len(ordered)) + offset
            positions[str(node['id'])] = (
                radius * math.cos(angle), radius * math.sin(angle)
            )
    return positions


def find_topology_node(graph: Mapping[str, Any], host: Any) -> Optional[Dict[str, Any]]:
    """Find the enriched graph node corresponding to a host row or alias."""
    candidates = set(_record_aliases(host) if isinstance(host, Mapping) else [_target_host(host)])
    for node in graph.get('nodes') or []:
        aliases = set(_record_aliases(node.get('raw') or {}))
        aliases.update([str(node.get('id') or ''), str(node.get('hostname') or '')])
        aliases.update(str(value) for value in node.get('ip_addresses') or [])
        if candidates & aliases:
            return node
    return None


def host_detail_rows(node: Optional[Mapping[str, Any]]) -> List[Tuple[str, str]]:
    """Produce the complete discovery evidence matrix for one graph node."""
    if not node:
        return []
    ports = ', '.join(
        f"{port.get('port')}/{port.get('protocol') or 'tcp'}"
        for port in node.get('ports') or []
    ) or 'No open ports reported'
    services = '; '.join(node.get('services') or []) or 'No services reported'
    vulnerabilities = '; '.join(node.get('vulnerabilities') or []) or 'None reported'
    tls_rows = []
    for cert in node.get('tls') or []:
        subject = cert.get('subject_cn') or cert.get('subject') or '?'
        issuer = cert.get('issuer_cn') or cert.get('issuer_org') or ''
        tls_rows.append(f'{subject}' + (f' · issuer {issuer}' if issuer else ''))
    http_bits = [str(node.get('http_state') or 'unknown').replace('_', ' ')]
    if node.get('http_status') is not None:
        http_bits.append(str(node['http_status']))
    if node.get('http_url'):
        http_bits.append(str(node['http_url']))
    coverage = node.get('coverage') or {}
    coverage_text = ', '.join(
        f"{key}: {'covered' if value == 'observed' else 'not run'}"
        for key, value in coverage.items()
    ) or 'No stage coverage reported'
    return [
        ('IP addresses', ', '.join(node.get('ip_addresses') or []) or 'None reported'),
        ('DNS state', str(node.get('dns_state') or 'Unknown').replace('_', ' ')),
        ('HTTP service', ' · '.join(http_bits)),
        ('Page title', str(node.get('title') or 'None reported')),
        ('CNAME chain', ' → '.join(node.get('cnames') or []) or 'None reported'),
        ('Discovery sources', ', '.join(node.get('sources') or []) or 'None reported'),
        ('Open ports', ports),
        ('Services', services),
        ('Technologies', ', '.join(node.get('technologies') or []) or 'None reported'),
        ('TLS certificates', '; '.join(tls_rows) or 'None reported'),
        ('Content URLs', (
            f"{node.get('endpoint_count', 0)} crawled · "
            f"{node.get('historical_count', 0)} historical"
        )),
        ('OS fingerprint', str(node.get('os') or 'Unknown')),
        ('Risk findings', vulnerabilities),
        ('Scan coverage', coverage_text),
    ]


def extract_live_hosts(
        output: str,
        target: str,
        existing: Iterable[Mapping[str, Any]] = ()) -> List[Dict[str, Any]]:
    """Extract host records from the discovery process's existing text stream.

    This is intentionally conservative: hostnames must be within the requested
    scope.  It lets the visualization react to host-bearing progress lines and
    partial/future report output without changing the scan engine protocol.
    """
    domain = _target_host(target)
    by_host: Dict[str, Dict[str, Any]] = {}
    for row in existing:
        if not isinstance(row, Mapping):
            continue
        key = str(row.get('hostname') or next(iter(_record_aliases(row)), '')).lower()
        if key:
            by_host[key] = dict(row)
    if not domain:
        return list(by_host.values())

    for line in str(output or '').splitlines():
        scoped_hosts = {
            match.group(1).lower().rstrip('.')
            for match in _HOST_RE.finditer(line)
            if (
                match.group(1).lower().rstrip('.') == domain
                or match.group(1).lower().rstrip('.').endswith('.' + domain)
            )
        }
        urls = _URL_RE.findall(line)
        for url in urls:
            hostname = _target_host(url)
            if hostname == domain or hostname.endswith('.' + domain):
                scoped_hosts.add(hostname)
        ips = []
        if re.search(r'\b(nmap|dnsx|httpx|host|resolved|open port)\b|->', line, re.I):
            ips = [
                ip for ip in (_valid_ip(match.group(1)) for match in _IP_RE.finditer(line))
                if ip
            ]
        for hostname in scoped_hosts:
            row = by_host.setdefault(hostname, {
                'hostname': hostname,
                'is_apex': hostname == domain,
                'sources': ['live discovery output'],
                'dns_live': bool(ips),
                'dns_status': 'resolved' if ips else 'pending',
                'ip_addresses': [],
                'http_live': False,
                'http_state': 'pending',
            })
            row['ip_addresses'] = list(dict.fromkeys(
                _list(row.get('ip_addresses')) + ips
            ))
            row['dns_live'] = bool(row['ip_addresses']) or bool(row.get('dns_live'))
            for url in urls:
                if _target_host(url) == hostname:
                    row['http_url'] = url.rstrip('.,;)')
                    row['http_live'] = True
                    row['http_state'] = 'live'
        if not scoped_hosts:
            for ip in ips:
                if any(
                        ip in _list(existing_row.get('ip_addresses'))
                        for existing_row in by_host.values()):
                    continue
                row = by_host.setdefault(ip, {
                    'hostname': ip,
                    'is_apex': False,
                    'sources': ['live discovery output'],
                    'dns_live': True,
                    'dns_status': 'resolved',
                    'ip_addresses': [ip],
                    'http_live': False,
                    'http_state': 'pending',
                })
                row['ip_addresses'] = list(dict.fromkeys(
                    _list(row.get('ip_addresses')) + [ip]
                ))
    return sorted(by_host.values(), key=lambda row: str(row.get('hostname') or ''))


def create_topology_widget(parent=None):
    """Create an evidence-rich, Zenmap-inspired Qt topology explorer."""
    from PySide6.QtCore import QPointF, QRectF, QSize, QTimer, Qt
    from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
    from PySide6.QtWidgets import (
        QCheckBox, QComboBox, QFrame, QGraphicsItem, QGraphicsLineItem,
        QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout,
        QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton, QSplitter,
        QTextBrowser, QVBoxLayout, QWidget,
    )
    from .theme import PALETTE

    class _TopologyView(QGraphicsView):
        def __init__(self, owner):
            super().__init__(owner)
            self.owner = owner
            self.interacted = False
            self.setRenderHints(
                QPainter.Antialiasing | QPainter.TextAntialiasing
                | QPainter.SmoothPixmapTransform
            )
            self.setDragMode(QGraphicsView.ScrollHandDrag)
            self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
            self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
            self.setBackgroundBrush(QBrush(QColor('#0b1014')))
            self.setFrameShape(QFrame.NoFrame)
            self.setFocusPolicy(Qt.StrongFocus)
            self.setAccessibleName('Interactive discovery topology graph')
            self.setToolTip(
                'Click to inspect · double-click to recenter · drag to pan · '
                'wheel to zoom · C returns to the scope origin'
            )

        def wheelEvent(self, event):
            self.interacted = True
            factor = 1.14 if event.angleDelta().y() > 0 else 1 / 1.14
            current = self.transform().m11()
            if 0.14 <= current * factor <= 7.0:
                self.scale(factor, factor)
            event.accept()

        def mousePressEvent(self, event):
            if event.button() in (Qt.LeftButton, Qt.MiddleButton):
                self.interacted = True
            super().mousePressEvent(event)

        def keyPressEvent(self, event):
            key = event.key()
            if key == Qt.Key_C:
                self.owner.center_origin()
            elif key == Qt.Key_H:
                self.owner.show_names.toggle()
            elif key == Qt.Key_A:
                self.owner.show_addresses.toggle()
            elif key == Qt.Key_L:
                self.owner.show_latency.toggle()
            elif key == Qt.Key_R:
                self.owner.show_rings.toggle()
            else:
                super().keyPressEvent(event)

    class _NodeItem(QGraphicsItem):
        def __init__(self, owner, node, x, y):
            super().__init__()
            self.owner = owner
            self.node = node
            self.radius = float(node.get('radius') or 14.0)
            self.hovered = False
            self.setPos(x, y)
            self.setFlag(QGraphicsItem.ItemIsSelectable, True)
            self.setAcceptHoverEvents(True)
            self.setZValue(3)
            self.primary_label = QGraphicsSimpleTextItem(self)
            self.secondary_label = QGraphicsSimpleTextItem(self)
            for label in (self.primary_label, self.secondary_label):
                label.setFlag(QGraphicsItem.ItemIgnoresTransformations, True)
            primary_font = QFont()
            primary_font.setPointSize(9)
            primary_font.setWeight(QFont.DemiBold)
            self.primary_label.setFont(primary_font)
            secondary_font = QFont()
            secondary_font.setPointSize(8)
            self.secondary_label.setFont(secondary_font)
            self.primary_label.setBrush(QBrush(QColor('#e9edf0')))
            self.secondary_label.setBrush(QBrush(QColor('#809099')))
            self.refresh_labels()
            self.setToolTip(self._tooltip())

        def boundingRect(self):
            extent = self.radius + 6
            return QRectF(-extent, -extent, extent * 2, extent * 2)

        def shape(self):
            path = QPainterPath()
            rect = QRectF(-self.radius, -self.radius, self.radius * 2, self.radius * 2)
            if self.node.get('device_type') in {'router', 'switch', 'wireless', 'firewall'}:
                path.addRoundedRect(rect, 3, 3)
            else:
                path.addEllipse(rect)
            return path

        def paint(self, painter, _option, _widget=None):
            rect = QRectF(-self.radius, -self.radius, self.radius * 2, self.radius * 2)
            is_route = bool(self.node.get('is_intermediate'))
            is_selected = self.isSelected()
            outline = '#c99a45' if is_selected or self.node.get('is_origin') else (
                EDGE_COLORS['traceroute'] if is_route else '#1c272d'
            )
            if self.hovered:
                outline = '#efd08d'
            pen = QPen(QColor(outline), 3.0 if is_selected else 2.0)
            if is_route or self.node.get('is_external'):
                pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            fill = QColor(str(self.node.get('fill_color') or PORT_COLORS['unscanned']))
            if is_route:
                fill.setAlpha(34)
            painter.setBrush(QBrush(fill))
            if self.node.get('device_type') in {'router', 'switch', 'wireless', 'firewall'}:
                painter.drawRoundedRect(rect, 3, 3)
            else:
                painter.drawEllipse(rect)

            if self.node.get('vulnerable'):
                painter.setBrush(Qt.NoBrush)
                painter.setPen(QPen(QColor(VULNERABLE_COLOR), 2.0))
                painter.drawEllipse(rect.adjusted(-4, -4, 4, 4))
            if self.node.get('http_state') == 'live':
                painter.setPen(QPen(QColor('#0b1014'), 1.2))
                painter.setBrush(QBrush(QColor('#50b8c6')))
                indicator = max(3.5, self.radius * 0.23)
                painter.drawEllipse(QPointF(self.radius * .68, -self.radius * .68), indicator, indicator)
            if self.node.get('is_origin'):
                painter.setBrush(Qt.NoBrush)
                painter.setPen(QPen(QColor('#f0d49b'), 1.0))
                painter.drawEllipse(rect.adjusted(-7, -7, 7, 7))

        def _tooltip(self):
            bits = [str(self.node.get('hostname') or self.node.get('id'))]
            addresses = ', '.join(self.node.get('ip_addresses') or [])
            if addresses:
                bits.append(addresses)
            bits.append(
                f"{self.node.get('port_count', 0)} open port(s) · "
                f"{self.node.get('os') or 'Unknown OS'}"
            )
            if self.node.get('http_state') == 'live':
                bits.append(
                    'HTTP live' + (
                        f" · {self.node['http_status']}"
                        if self.node.get('http_status') is not None else ''
                    )
                )
            if self.node.get('vulnerable'):
                bits.append(
                    f"{len(self.node.get('vulnerabilities') or [])} risk finding(s)"
                )
            return '\n'.join(bits)

        def refresh_labels(self):
            hostname = str(self.node.get('hostname') or self.node.get('id'))
            addresses = self.node.get('ip_addresses') or []
            primary = hostname if self.owner.show_names.isChecked() else (
                str(addresses[0]) if self.owner.show_addresses.isChecked() and addresses else ''
            )
            secondary_bits = []
            if self.owner.show_addresses.isChecked() and addresses and primary != addresses[0]:
                secondary_bits.append(str(addresses[0]))
            if self.owner.show_services.isChecked() and self.node.get('services'):
                secondary_bits.append(str(self.node['services'][0]))
            self.primary_label.setText(primary)
            self.secondary_label.setText('  ·  '.join(secondary_bits))
            for label, y in (
                    (self.primary_label, self.radius + 7),
                    (self.secondary_label, self.radius + 24)):
                bounds = label.boundingRect()
                label.setPos(-bounds.width() / 2, y)
                label.setVisible(bool(label.text()))

        def mousePressEvent(self, event):
            self.owner.inspect_node(str(self.node.get('id') or ''))
            super().mousePressEvent(event)

        def mouseDoubleClickEvent(self, event):
            self.owner.center_on(str(self.node.get('id') or ''))
            event.accept()

        def hoverEnterEvent(self, event):
            self.hovered = True
            self.update()
            super().hoverEnterEvent(event)

        def hoverLeaveEvent(self, event):
            self.hovered = False
            self.update()
            super().hoverLeaveEvent(event)

    class _TopologyWidget(QWidget):
        def __init__(self, widget_parent=None):
            super().__init__(widget_parent)
            self.setObjectName('DiscoveryTopologyWidget')
            self.setAccessibleName('Discovery network topology')
            self.graph: Dict[str, Any] = {'nodes': [], 'edges': [], 'summary': {}}
            self.node_items: Dict[str, _NodeItem] = {}
            self.edge_items: List[Tuple[QGraphicsLineItem, Mapping[str, Any]]] = []
            self.selected_id = ''
            self.focus_id = ''
            self._syncing_navigator = False

            p = PALETTE
            self.setStyleSheet(f"""
                QWidget#DiscoveryTopologyWidget {{ background: {p['surface']}; }}
                QFrame#TopologyHeader {{
                    background: {p['card']}; border: 1px solid {p['border_subtle']};
                    border-radius: 8px;
                }}
                QFrame#TopologyControls, QFrame#TopologyInspector {{
                    background: #10161a; border: 1px solid {p['border_subtle']};
                    border-radius: 8px;
                }}
                QLabel#TopologyTitle {{ color: {p['text']}; font-size: 16px; font-weight: 700; }}
                QLabel#TopologyPanelTitle {{ color: {p['text']}; font-size: 12px; font-weight: 700; }}
                QLabel#TopologyStatus {{ color: {p['text_muted']}; font-size: 11px; }}
                QLabel#TopologyMetric {{ color: #d6bd88; font-size: 11px; }}
                QLabel#TopologyLegend {{ color: {p['text_muted']}; font-size: 11px; }}
                QPushButton#TopologyToolButton {{ min-height: 26px; padding: 3px 9px; }}
                QListWidget#TopologyHostNavigator {{
                    background: #0b1014; border: 1px solid {p['border_subtle']};
                    border-radius: 5px; padding: 3px;
                }}
                QListWidget#TopologyHostNavigator::item {{ padding: 6px 7px; border-radius: 3px; }}
                QListWidget#TopologyHostNavigator::item:selected {{
                    background: {p['accent_soft']}; color: {p['text']};
                }}
                QTextBrowser#TopologyDetailBrowser {{
                    background: transparent; border: 0; padding: 0;
                }}
            """)

            outer = QVBoxLayout(self)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(9)

            header = QFrame()
            header.setObjectName('TopologyHeader')
            header_row = QHBoxLayout(header)
            header_row.setContentsMargins(12, 9, 10, 9)
            title_stack = QVBoxLayout()
            title_stack.setSpacing(1)
            title = QLabel('Discovery topology')
            title.setObjectName('TopologyTitle')
            self.status = QLabel('Waiting for discovery evidence')
            self.status.setObjectName('TopologyStatus')
            self.status.setAccessibleName('Topology layout status')
            title_stack.addWidget(title)
            title_stack.addWidget(self.status)
            header_row.addLayout(title_stack)
            header_row.addStretch()
            self.metrics = QLabel('0 hosts  ·  0 links')
            self.metrics.setObjectName('TopologyMetric')
            self.metrics.setAccessibleName('Topology discovery summary')
            header_row.addWidget(self.metrics)
            for text_value, name, callback in (
                    ('Zoom −', 'Zoom topology out', lambda: self._zoom(1 / 1.18)),
                    ('Zoom +', 'Zoom topology in', lambda: self._zoom(1.18)),
                    ('Fit', 'Fit topology to view', self.reset_view),
                    ('Scope center', 'Center topology on scope origin', self.center_origin)):
                button = QPushButton(text_value)
                button.setObjectName('TopologyToolButton')
                button.setAccessibleName(name)
                button.clicked.connect(callback)
                header_row.addWidget(button)
            outer.addWidget(header)

            splitter = QSplitter(Qt.Horizontal)
            splitter.setObjectName('DiscoveryTopologySplitter')
            splitter.setChildrenCollapsible(False)

            controls = QFrame()
            controls.setObjectName('TopologyControls')
            controls.setMinimumWidth(190)
            controls.setMaximumWidth(245)
            controls_layout = QVBoxLayout(controls)
            controls_layout.setContentsMargins(11, 11, 11, 11)
            controls_layout.setSpacing(8)
            nav_title = QLabel('Hosts and infrastructure')
            nav_title.setObjectName('TopologyPanelTitle')
            controls_layout.addWidget(nav_title)
            self.search = QLineEdit()
            self.search.setAccessibleName('Search topology hosts')
            self.search.setPlaceholderText('Host, IP, port, service…')
            self.search.setClearButtonEnabled(True)
            controls_layout.addWidget(self.search)
            self.node_filter = QComboBox()
            self.node_filter.setAccessibleName('Filter topology nodes')
            for label, value in (
                    ('All nodes', 'all'), ('Web live', 'web'),
                    ('Risk findings', 'risk'), ('Unresolved', 'unresolved'),
                    ('Route infrastructure', 'infrastructure')):
                self.node_filter.addItem(label, value)
            controls_layout.addWidget(self.node_filter)
            self.navigator = QListWidget()
            self.navigator.setObjectName('TopologyHostNavigator')
            self.navigator.setAccessibleName('Topology host navigator')
            controls_layout.addWidget(self.navigator, 1)

            map_title = QLabel('Map display')
            map_title.setObjectName('TopologyPanelTitle')
            controls_layout.addWidget(map_title)
            self.layout_mode = QComboBox()
            self.layout_mode.setAccessibleName('Topology radial layout')
            self.layout_mode.addItem('Weighted radial', 'weighted')
            self.layout_mode.addItem('Symmetric radial', 'symmetric')
            controls_layout.addWidget(self.layout_mode)
            self.show_names = QCheckBox('Hostnames')
            self.show_addresses = QCheckBox('IP addresses')
            self.show_services = QCheckBox('Primary service')
            self.show_latency = QCheckBox('Route latency')
            self.show_rings = QCheckBox('Distance rings')
            self.show_inferred = QCheckBox('Inferred links')
            for checkbox, checked in (
                    (self.show_names, True), (self.show_addresses, True),
                    (self.show_services, False), (self.show_latency, True),
                    (self.show_rings, True), (self.show_inferred, True)):
                checkbox.setChecked(checked)
                controls_layout.addWidget(checkbox)
            splitter.addWidget(controls)

            self.scene = QGraphicsScene(self)
            self.view = _TopologyView(self)
            self.view.setScene(self.scene)
            splitter.addWidget(self.view)

            details = QFrame()
            details.setObjectName('TopologyInspector')
            details.setMinimumWidth(285)
            details.setMaximumWidth(420)
            detail_layout = QVBoxLayout(details)
            detail_layout.setContentsMargins(13, 12, 13, 12)
            inspector_title = QLabel('Evidence inspector')
            inspector_title.setObjectName('TopologyPanelTitle')
            detail_layout.addWidget(inspector_title)
            self.detail = QTextBrowser()
            self.detail.setObjectName('TopologyDetailBrowser')
            self.detail.setAccessibleName('Topology host details')
            self.detail.setOpenExternalLinks(False)
            self.detail.setHtml(self._empty_detail_html())
            detail_layout.addWidget(self.detail, 1)
            self.center_selected_button = QPushButton('Center selected node')
            self.center_selected_button.setObjectName('TopologyToolButton')
            self.center_selected_button.setAccessibleName('Center topology on selected host')
            self.center_selected_button.setEnabled(False)
            self.center_selected_button.clicked.connect(
                lambda: self.center_on(self.selected_id)
            )
            detail_layout.addWidget(self.center_selected_button)
            splitter.addWidget(details)
            splitter.setStretchFactor(0, 0)
            splitter.setStretchFactor(1, 5)
            splitter.setStretchFactor(2, 0)
            splitter.setSizes([210, 720, 330])
            outer.addWidget(splitter, 1)

            legend = QLabel(
                '<b>Port exposure</b>&nbsp; '
                '<span style="color:#5fc98f">●</span> 0–2&nbsp;&nbsp; '
                '<span style="color:#e4b752">●</span> 3–6&nbsp;&nbsp; '
                '<span style="color:#ee6a65">●</span> 7+&nbsp;&nbsp; '
                '<span style="color:#d8dee3">○</span> not scanned&nbsp;&nbsp;&nbsp; '
                '<b>Evidence</b>&nbsp; blue = route&nbsp;&nbsp; teal = reported&nbsp;&nbsp; '
                'purple = shared IP&nbsp;&nbsp; dashed = inferred / unknown&nbsp;&nbsp; '
                '<span style="color:#ff5d6c">red ring</span> = risk finding'
            )
            legend.setObjectName('TopologyLegend')
            legend.setAccessibleName(
                'Topology legend: node fill is open port count, red ring is risk, '
                'line style identifies connection evidence'
            )
            legend.setWordWrap(True)
            outer.addWidget(legend)

            self.search.textChanged.connect(self._apply_filters)
            self.node_filter.currentIndexChanged.connect(self._apply_filters)
            self.navigator.itemSelectionChanged.connect(self._inspect_navigator_selection)
            self.layout_mode.currentIndexChanged.connect(self._render_graph)
            for checkbox in (
                    self.show_names, self.show_addresses, self.show_services):
                checkbox.toggled.connect(self._refresh_node_labels)
            self.show_latency.toggled.connect(self._render_graph)
            self.show_rings.toggled.connect(self._render_graph)
            self.show_inferred.toggled.connect(self._render_graph)

        def _empty_detail_html(self):
            return (
                '<p style="color:#89949b">Select a host, route hop, or shared '
                'address to inspect its discovery evidence and coverage gaps. '
                'Double-click a node to make it the map center.</p>'
            )

        def _zoom(self, factor):
            self.view.interacted = True
            current = self.view.transform().m11()
            if 0.14 <= current * factor <= 7.0:
                self.view.scale(factor, factor)

        def reset_view(self):
            self.view.interacted = False
            self.view.resetTransform()
            bounds = self.scene.itemsBoundingRect()
            if not bounds.isEmpty():
                self.view.fitInView(
                    bounds.adjusted(-70, -70, 70, 70), Qt.KeepAspectRatio
                )

        def center_origin(self):
            self.center_on(str(self.graph.get('origin_id') or ''))

        def center_on(self, node_id):
            if not node_id or node_id not in {
                    str(node.get('id')) for node in self.graph.get('nodes') or []}:
                return
            self.focus_id = str(node_id)
            self.view.interacted = False
            self._render_graph()
            self.inspect_node(node_id)

        def showEvent(self, event):
            super().showEvent(event)
            if not self.view.interacted:
                QTimer.singleShot(0, self.reset_view)

        def resizeEvent(self, event):
            super().resizeEvent(event)
            if not self.view.interacted:
                QTimer.singleShot(0, self.reset_view)

        def set_report(self, report):
            selected = self.selected_id
            previous_focus = self.focus_id
            self.graph = build_topology(report if isinstance(report, Mapping) else {})
            node_ids = {
                str(node.get('id') or '') for node in self.graph.get('nodes') or []
            }
            self.focus_id = (
                previous_focus if previous_focus in node_ids
                else str(self.graph.get('origin_id') or '')
            )
            self.selected_id = selected if selected in node_ids else ''
            self._populate_navigator()
            self._render_graph()
            if self.selected_id:
                self.inspect_node(self.selected_id)
            else:
                self.detail.setHtml(self._empty_detail_html())
                self.center_selected_button.setEnabled(False)

        def _populate_navigator(self):
            self._syncing_navigator = True
            self.navigator.clear()
            nodes = sorted(
                self.graph.get('nodes') or [],
                key=lambda node: (
                    not bool(node.get('is_origin')),
                    str(node.get('node_type') or ''),
                    str(node.get('hostname') or node.get('id')),
                ),
            )
            for node in nodes:
                hostname = str(node.get('hostname') or node.get('id'))
                details = []
                if node.get('node_type') != 'host':
                    details.append(str(node.get('node_type')).replace('_', ' '))
                if node.get('http_state') == 'live':
                    details.append('web live')
                if node.get('vulnerable'):
                    details.append(f"{node.get('risk_severity', 'INFO').lower()} risk")
                if node.get('port_count'):
                    details.append(f"{node['port_count']} ports")
                text_value = hostname + (f"  ·  {', '.join(details)}" if details else '')
                item = QListWidgetItem(text_value)
                item.setData(Qt.UserRole, str(node.get('id') or ''))
                item.setToolTip('\n'.join([
                    hostname,
                    ', '.join(node.get('ip_addresses') or []),
                    '; '.join(node.get('services') or [])[:220],
                ]).strip())
                item.setSizeHint(QSize(180, 31))
                self.navigator.addItem(item)
            self._syncing_navigator = False
            self._apply_filters()

        def _node_matches_filter(self, node):
            key = str(self.node_filter.currentData() or 'all')
            if key == 'web':
                return node.get('http_state') == 'live'
            if key == 'risk':
                return bool(node.get('vulnerable'))
            if key == 'unresolved':
                return node.get('node_type') == 'host' and node.get('dns_state') != 'resolved'
            if key == 'infrastructure':
                return node.get('node_type') != 'host'
            return True

        def _node_search_blob(self, node):
            values = [
                node.get('id'), node.get('hostname'), node.get('http_url'),
                node.get('title'), node.get('server'), node.get('os'),
                *list(node.get('ip_addresses') or []),
                *list(node.get('sources') or []),
                *list(node.get('services') or []),
                *list(node.get('technologies') or []),
                *list(node.get('vulnerabilities') or []),
            ]
            return ' '.join(str(value or '') for value in values).lower()

        def _apply_filters(self, *_args):
            query = self.search.text().strip().lower()
            nodes = {
                str(node.get('id')): node for node in self.graph.get('nodes') or []
            }
            matches = {
                node_id for node_id, node in nodes.items()
                if self._node_matches_filter(node)
                and (not query or query in self._node_search_blob(node))
            }
            for index in range(self.navigator.count()):
                item = self.navigator.item(index)
                item.setHidden(str(item.data(Qt.UserRole)) not in matches)
            active_filter = bool(query) or str(self.node_filter.currentData() or 'all') != 'all'
            for node_id, item in self.node_items.items():
                item.setOpacity(1.0 if not active_filter or node_id in matches else 0.13)
            for item, edge in self.edge_items:
                connected = (
                    str(edge.get('source')) in matches
                    or str(edge.get('target')) in matches
                )
                item.setOpacity(1.0 if not active_filter or connected else 0.12)

        def _refresh_node_labels(self, *_args):
            for item in self.node_items.values():
                item.refresh_labels()

        def _render_graph(self, *_args):
            selected = self.selected_id
            self.scene.clear()
            self.node_items = {}
            self.edge_items = []
            nodes = {
                str(node['id']): node for node in self.graph.get('nodes') or []
            }
            positions = topology_positions(
                self.graph,
                self.focus_id,
                layout_mode=str(self.layout_mode.currentData() or 'weighted'),
            )
            distances = topology_distances(self.graph, self.focus_id)

            if self.show_rings.isChecked():
                ring_radii: Dict[int, float] = {}
                for node_id, (x, y) in positions.items():
                    distance = distances.get(node_id, 0)
                    if distance > 0:
                        ring_radii[distance] = max(
                            ring_radii.get(distance, 0.0), math.hypot(x, y)
                        )
                measured = self.graph.get('distance_source') == 'measured'
                for distance, radius in sorted(ring_radii.items()):
                    ring_pen = QPen(QColor('#253138'), 1.0, Qt.DotLine)
                    ring = self.scene.addEllipse(
                        -radius, -radius, radius * 2, radius * 2, ring_pen
                    )
                    ring.setZValue(-3)
                    label = self.scene.addSimpleText(
                        f"{'hop' if measured else 'layer'} {distance}"
                    )
                    label.setBrush(QBrush(QColor('#56656c')))
                    label.setPos(radius + 7, -9)
                    label.setZValue(-2)

            for edge in self.graph.get('edges') or []:
                if edge.get('kind') == 'discovery' and not self.show_inferred.isChecked():
                    continue
                source = positions.get(str(edge.get('source')))
                target = positions.get(str(edge.get('target')))
                if source is None or target is None:
                    continue
                line = QGraphicsLineItem(source[0], source[1], target[0], target[1])
                kind = str(edge.get('kind') or 'connection')
                latency = edge.get('latency_ms')
                width = 1.35
                if latency is not None:
                    width += min(2.4, math.log1p(float(latency)) / 2.7)
                pen = QPen(QColor(EDGE_COLORS.get(kind, EDGE_COLORS['connection'])), width)
                if kind == 'discovery' or (
                        kind == 'traceroute' and latency is None):
                    pen.setStyle(Qt.DashLine)
                line.setPen(pen)
                line.setZValue(0)
                self.scene.addItem(line)
                self.edge_items.append((line, edge))
                if self.show_latency.isChecked() and latency is not None:
                    latency_label = self.scene.addSimpleText(f'{float(latency):.1f} ms')
                    latency_label.setBrush(QBrush(QColor('#718189')))
                    latency_label.setPos(
                        (source[0] + target[0]) / 2 + 4,
                        (source[1] + target[1]) / 2 + 3,
                    )
                    latency_label.setZValue(1)

            for node_id, node in nodes.items():
                x, y = positions.get(node_id, (0.0, 0.0))
                item = _NodeItem(self, node, x, y)
                self.node_items[node_id] = item
                self.scene.addItem(item)

            summary = self.graph.get('summary') or {}
            path_label = (
                'measured hop distance' if self.graph.get('distance_source') == 'measured'
                else 'relationship layers · routes not measured'
            )
            self.status.setText(
                f"Radial map · {path_label} · focus: "
                f"{nodes.get(self.focus_id, {}).get('hostname', 'scope')}"
            )
            self.metrics.setText(
                f"{summary.get('hosts', 0)} hosts  ·  {summary.get('web_live', 0)} web live  ·  "
                f"{summary.get('open_ports', 0)} ports  ·  {summary.get('findings', 0)} risks"
            )
            if not nodes:
                empty = self.scene.addSimpleText(
                    'Discovery evidence will assemble here as hosts resolve'
                )
                empty.setBrush(QBrush(QColor('#82909c')))
                empty.setPos(-190, -10)
            if selected in self.node_items:
                self.node_items[selected].setSelected(True)
            self._apply_filters()
            if not self.view.interacted:
                QTimer.singleShot(0, self.reset_view)

        def _inspect_navigator_selection(self):
            if self._syncing_navigator:
                return
            item = self.navigator.currentItem()
            if item is not None:
                self.inspect_node(str(item.data(Qt.UserRole) or ''))

        def _detail_html(self, node):
            rows = host_detail_rows(node)
            status = []
            if node.get('is_origin'):
                status.append('scope origin')
            if node.get('node_type') != 'host':
                status.append(str(node.get('node_type')).replace('_', ' '))
            if node.get('hop') is not None:
                status.append(f"hop {node['hop']}")
            if node.get('latency_ms') is not None:
                status.append(f"{float(node['latency_ms']):.1f} ms")
            if node.get('vulnerable'):
                status.append(f"{node.get('risk_severity', 'INFO').lower()} risk")
            body = ''.join(
                '<tr>'
                '<td style="color:#89949b;padding:5px 10px 5px 0;vertical-align:top;white-space:nowrap">'
                f'{html.escape(label)}</td>'
                '<td style="color:#e8e2d8;padding:5px 0;vertical-align:top">'
                f'{html.escape(value)}</td></tr>'
                for label, value in rows
            )
            hostname = html.escape(str(node.get('hostname') or node.get('id')))
            return (
                '<style>'
                'h2{color:#f1ece4;margin:0 0 3px 0;font-size:17px}'
                'p{color:#b7ad9f;margin:0 0 12px 0}'
                'table{border-collapse:collapse;font-size:12px}'
                '</style>'
                f'<h2>{hostname}</h2>'
                f'<p>{html.escape(" · ".join(status) or "discovered host")}</p>'
                f'<table>{body}</table>'
            )

        def inspect_node(self, node_id):
            node = next((
                item for item in self.graph.get('nodes') or []
                if str(item.get('id')) == str(node_id)
            ), None)
            if not node:
                return
            self.selected_id = str(node_id)
            for item_id, item in self.node_items.items():
                item.setSelected(item_id == self.selected_id)
                item.update()
            self._syncing_navigator = True
            for index in range(self.navigator.count()):
                item = self.navigator.item(index)
                if str(item.data(Qt.UserRole)) == self.selected_id:
                    self.navigator.setCurrentItem(item)
                    self.navigator.scrollToItem(item)
                    break
            self._syncing_navigator = False
            self.detail.setHtml(self._detail_html(node))
            self.center_selected_button.setEnabled(True)

        def select_host(self, host):
            node = find_topology_node(self.graph, host)
            if node:
                self.inspect_node(str(node.get('id') or ''))

    return _TopologyWidget(parent)
