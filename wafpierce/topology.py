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
    for key in ('id', 'hostname', 'host', 'ip', 'address', 'target', 'url'):
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


def _resolve_node(value: Any, aliases: Mapping[str, str]) -> str:
    if isinstance(value, Mapping):
        candidates = _record_aliases(value)
    else:
        candidates = [candidate for candidate in (
            _valid_ip(value), _target_host(value)
        ) if candidate]
    for candidate in candidates:
        if candidate in aliases:
            return aliases[candidate]
    return ''


def build_topology(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Join an existing discovery report into graph-ready nodes and edges."""
    report = report if isinstance(report, Mapping) else {}
    stages = report.get('stages') if isinstance(report.get('stages'), Mapping) else {}
    hosts = [
        dict(host) for host in _list(stages.get('hosts'))
        if isinstance(host, Mapping)
    ]
    target = _target_host(report.get('target'))

    nodes_by_id: Dict[str, Dict[str, Any]] = {}
    for index, host in enumerate(hosts):
        aliases = _record_aliases(host)
        node_id = (str(host.get('hostname') or '').lower().rstrip('.')
                   or next(iter(aliases), '') or f'host-{index + 1}')
        existing = nodes_by_id.get(node_id)
        if existing:
            existing['raw'].update(host)
            existing['ip_addresses'] = list(dict.fromkeys(
                existing['ip_addresses'] + [
                    str(value) for value in _list(host.get('ip_addresses'))
                ]
            ))
            continue
        hostname = str(host.get('hostname') or host.get('host') or node_id)
        nodes_by_id[node_id] = {
            'id': node_id,
            'label': hostname,
            'hostname': hostname,
            'ip_addresses': [
                str(value) for value in _list(host.get('ip_addresses'))
                if value
            ],
            'http_url': str(host.get('http_url') or ''),
            'http_status': host.get('http_status'),
            'ports': [],
            'services': [],
            'os': '',
            'os_family': 'unknown',
            'vulnerabilities': [],
            'vulnerable': False,
            'hop': _hop_value(host),
            'is_origin': bool(host.get('is_origin')),
            'raw': host,
        }

    origin_id = ''
    if target:
        origin_id = next((
            node_id for node_id, node in nodes_by_id.items()
            if target in _record_aliases(node['raw']) or node_id == target
        ), '')
        if not origin_id:
            origin_id = target
            nodes_by_id[origin_id] = {
                'id': origin_id,
                'label': target,
                'hostname': target,
                'ip_addresses': [],
                'http_url': '',
                'http_status': None,
                'ports': [],
                'services': [],
                'os': 'Unknown',
                'os_family': 'unknown',
                'vulnerabilities': [],
                'vulnerable': False,
                'hop': 0,
                'is_origin': True,
                'raw': {'hostname': target, 'is_origin': True},
            }
    if not origin_id:
        origin_id = next((
            node_id for node_id, node in nodes_by_id.items()
            if node['raw'].get('is_apex')
        ), next(iter(nodes_by_id), ''))
    if origin_id:
        nodes_by_id[origin_id]['is_origin'] = True
        if nodes_by_id[origin_id]['hop'] is None:
            nodes_by_id[origin_id]['hop'] = 0

    aliases: Dict[str, str] = {}
    for node_id, node in nodes_by_id.items():
        aliases[node_id] = node_id
        for alias in _record_aliases(node['raw']):
            aliases[alias] = node_id
        for ip in node['ip_addresses']:
            aliases[ip] = node_id

    # Existing port sources are joined to hosts/IPs; no probing occurs here.
    port_rows: List[Dict[str, Any]] = []
    for key in ('ports', 'naabu'):
        port_rows.extend(
            dict(row) for row in _list(stages.get(key))
            if isinstance(row, Mapping)
        )
    for node in nodes_by_id.values():
        for value in _list(node['raw'].get('ports')):
            if isinstance(value, Mapping):
                row = dict(value)
            else:
                row = {'port': value, 'protocol': 'tcp'}
            row.setdefault('host', node['id'])
            port_rows.append(row)
    for port in port_rows:
        node_id = _resolve_node(port, aliases)
        if not node_id:
            continue
        node = nodes_by_id[node_id]
        if _port_key(port) not in {_port_key(item) for item in node['ports']}:
            node['ports'].append(port)

    # Apply optional OS fingerprint collections when reports provide them.
    os_rows = stages.get('os_fingerprints') or stages.get('operating_systems') or {}
    if isinstance(os_rows, Mapping):
        os_rows = [
            {'host': key, 'os_fingerprint': value}
            for key, value in os_rows.items()
        ]
    for os_row in _list(os_rows):
        if not isinstance(os_row, Mapping):
            continue
        node_id = _resolve_node(os_row, aliases)
        if node_id:
            nodes_by_id[node_id]['raw'].update({
                'os_fingerprint': os_row.get('os_fingerprint')
                or os_row.get('os') or os_row.get('name')
            })

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
    for node in nodes_by_id.values():
        for value in _list(node['raw'].get('vulnerabilities')):
            if isinstance(value, Mapping):
                vulnerability_rows.append(dict(value, host=node['id']))
            elif value:
                vulnerability_rows.append({'name': value, 'host': node['id']})
    for vulnerability in vulnerability_rows:
        match_value = (
            vulnerability.get('matched-at') or vulnerability.get('matched_at')
            or vulnerability.get('url') or vulnerability.get('host')
            or vulnerability.get('target') or vulnerability.get('data')
        )
        node_id = _resolve_node(match_value, aliases)
        if not node_id:
            continue
        label = _vulnerability_label(vulnerability)
        node = nodes_by_id[node_id]
        if label not in node['vulnerabilities']:
            node['vulnerabilities'].append(label)

    # Traceroute data is optional.  When present it supplies ring distance.
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
            if isinstance(value, Mapping) and isinstance(
                    value.get('hops'), (list, tuple)):
                route_groups.append([
                    row for row in value['hops'] if isinstance(row, Mapping)
                ])
            elif isinstance(value, Mapping):
                flat_rows.append(value)
        if flat_rows:
            route_groups.append(flat_rows)
    traceroute_connections: List[Tuple[str, str]] = []
    for route in route_groups:
        previous_id = ''
        for hop_row in route:
            node_id = _resolve_node(hop_row, aliases)
            hop = _hop_value(hop_row)
            if node_id and hop is not None:
                nodes_by_id[node_id]['hop'] = hop
            if node_id and previous_id and node_id != previous_id:
                traceroute_connections.append((previous_id, node_id))
            # Do not imply a direct edge across a route hop absent from the host
            # inventory; only consecutive represented hosts are connected.
            previous_id = node_id

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
        node['vulnerable'] = bool(node['vulnerabilities'])
        node['port_count'] = len(node['ports'])
        node['radius'] = min(31.0, 15.0 + math.sqrt(node['port_count']) * 4.0)
        node['color'] = (
            VULNERABLE_COLOR if node['vulnerable']
            else OS_COLORS[node['os_family']]
        )

    edge_keys = set()
    edges: List[Dict[str, Any]] = []

    def add_edge(source: Any, destination: Any, kind: str = 'connection') -> None:
        source_id = _resolve_node(source, aliases)
        destination_id = _resolve_node(destination, aliases)
        if not source_id or not destination_id or source_id == destination_id:
            return
        key = tuple(sorted((source_id, destination_id)))
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({
            'source': source_id,
            'target': destination_id,
            'kind': kind,
        })

    for connection in _list(stages.get('connections')):
        if isinstance(connection, Mapping):
            add_edge(
                connection.get('source') or connection.get('from') or connection.get('host'),
                connection.get('target') or connection.get('to') or connection.get('peer'),
                str(connection.get('kind') or 'connection'),
            )
        elif isinstance(connection, (list, tuple)) and len(connection) >= 2:
            add_edge(connection[0], connection[1])
    for source, destination in traceroute_connections:
        add_edge(source, destination, 'traceroute')
    for node in nodes_by_id.values():
        for peer in (
            _list(node['raw'].get('connections'))
            + _list(node['raw'].get('neighbors'))
            + _list(node['raw'].get('peers'))
        ):
            add_edge(node['id'], peer)

    # Legacy/current recon has no connection stage.  Keep the graph useful by
    # showing the discovery relationship from its scope origin.
    if not edges and origin_id:
        for node_id in nodes_by_id:
            if node_id != origin_id:
                add_edge(origin_id, node_id, 'discovery')

    nodes = list(nodes_by_id.values())
    has_hops = any(
        node['hop'] is not None and node['hop'] > 0 for node in nodes
    )
    return {
        'nodes': nodes,
        'edges': edges,
        'origin_id': origin_id,
        'layout': 'rings' if has_hops else 'force',
    }


def topology_positions(graph: Mapping[str, Any]) -> Dict[str, Tuple[float, float]]:
    """Return deterministic ring or force-directed positions for a graph."""
    nodes = list(graph.get('nodes') or [])
    if not nodes:
        return {}
    origin_id = str(graph.get('origin_id') or '')
    if graph.get('layout') == 'rings':
        positions: Dict[str, Tuple[float, float]] = {}
        groups: Dict[int, List[Mapping[str, Any]]] = {}
        known_hops = [
            int(node['hop']) for node in nodes if node.get('hop') is not None
        ]
        fallback_hop = max(known_hops or [0]) + 1
        for node in nodes:
            hop = int(node['hop']) if node.get('hop') is not None else fallback_hop
            groups.setdefault(hop, []).append(node)
        for hop, group in sorted(groups.items()):
            group = sorted(group, key=lambda item: str(item['id']))
            if hop == 0:
                for index, node in enumerate(group):
                    if node['id'] == origin_id:
                        positions[node['id']] = (0.0, 0.0)
                    else:
                        angle = 2 * math.pi * index / max(1, len(group))
                        positions[node['id']] = (65 * math.cos(angle), 65 * math.sin(angle))
                continue
            radius = 125.0 + (hop - 1) * 115.0
            # Rotate successive rings by the golden angle so sparse traceroutes
            # do not collapse into a single horizontal spoke.
            offset = hop * math.pi * (3.0 - math.sqrt(5.0))
            for index, node in enumerate(group):
                angle = 2 * math.pi * index / max(1, len(group)) + offset
                positions[node['id']] = (
                    radius * math.cos(angle), radius * math.sin(angle)
                )
        return positions

    ordered = sorted(nodes, key=lambda item: str(item['id']))
    count = len(ordered)
    positions = {}
    golden_angle = math.pi * (3.0 - math.sqrt(5.0))
    for index, node in enumerate(ordered):
        if node['id'] == origin_id:
            positions[node['id']] = (0.0, 0.0)
            continue
        radius = 55.0 * math.sqrt(index + 1)
        angle = index * golden_angle
        positions[node['id']] = (radius * math.cos(angle), radius * math.sin(angle))

    adjacency = [
        (str(edge.get('source')), str(edge.get('target')))
        for edge in graph.get('edges') or []
    ]
    node_ids = [str(node['id']) for node in ordered]
    # A bounded force pass keeps large scans responsive while still separating
    # connected clusters.  Repulsion samples nearby deterministic peers.
    iterations = 55 if count <= 180 else 24
    peer_window = min(28, max(0, count - 1))
    for iteration in range(iterations):
        forces = {node_id: [0.0, 0.0] for node_id in node_ids}
        for index, node_id in enumerate(node_ids):
            x1, y1 = positions[node_id]
            for offset in range(1, peer_window + 1):
                other_id = node_ids[(index + offset) % count]
                if other_id == node_id:
                    continue
                x2, y2 = positions[other_id]
                dx, dy = x1 - x2, y1 - y2
                distance_sq = max(64.0, dx * dx + dy * dy)
                strength = 1300.0 / distance_sq
                distance = math.sqrt(distance_sq)
                forces[node_id][0] += dx / distance * strength
                forces[node_id][1] += dy / distance * strength
        for source, target in adjacency:
            if source not in positions or target not in positions:
                continue
            x1, y1 = positions[source]
            x2, y2 = positions[target]
            dx, dy = x2 - x1, y2 - y1
            distance = max(1.0, math.hypot(dx, dy))
            spring = (distance - 145.0) * 0.012
            fx, fy = dx / distance * spring, dy / distance * spring
            forces[source][0] += fx
            forces[source][1] += fy
            forces[target][0] -= fx
            forces[target][1] -= fy
        cooling = 1.0 - iteration / max(1, iterations) * 0.65
        for node_id in node_ids:
            if node_id == origin_id:
                positions[node_id] = (0.0, 0.0)
                continue
            x, y = positions[node_id]
            fx, fy = forces[node_id]
            positions[node_id] = (
                x + max(-12.0, min(12.0, fx)) * cooling,
                y + max(-12.0, min(12.0, fy)) * cooling,
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
    """Produce compact, expandable inventory details for one graph node."""
    if not node:
        return []
    ports = ', '.join(
        f"{port.get('port')}/{port.get('protocol') or 'tcp'}"
        for port in node.get('ports') or []
    ) or 'No open ports reported'
    services = '; '.join(node.get('services') or []) or 'No services reported'
    vulnerabilities = '; '.join(node.get('vulnerabilities') or []) or 'None reported'
    return [
        ('IP addresses', ', '.join(node.get('ip_addresses') or []) or 'None reported'),
        ('Open ports', ports),
        ('Services', services),
        ('OS fingerprint', str(node.get('os') or 'Unknown')),
        ('Vulnerabilities', vulnerabilities),
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
    """Create the interactive Qt topology widget, importing PySide6 lazily."""
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtGui import QBrush, QColor, QPainter, QPen
    from PySide6.QtWidgets import (
        QFrame, QGraphicsEllipseItem, QGraphicsItem, QGraphicsLineItem,
        QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout,
        QLabel, QPushButton, QSplitter, QTextBrowser, QVBoxLayout, QWidget,
    )

    class _TopologyView(QGraphicsView):
        def __init__(self, owner):
            super().__init__(owner)
            self.owner = owner
            self.interacted = False
            self.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
            self.setDragMode(QGraphicsView.ScrollHandDrag)
            self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
            self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
            self.setBackgroundBrush(QBrush(QColor('#0b1114')))
            self.setFrameShape(QFrame.NoFrame)
            self.setAccessibleName('Interactive discovery topology graph')
            self.setToolTip('Drag to pan, use the mouse wheel to zoom, and click a host to inspect it.')

        def wheelEvent(self, event):
            self.interacted = True
            factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
            current = self.transform().m11()
            if 0.16 <= current * factor <= 6.0:
                self.scale(factor, factor)
            event.accept()

        def mousePressEvent(self, event):
            if event.button() in (Qt.LeftButton, Qt.MiddleButton):
                self.interacted = True
            super().mousePressEvent(event)

    class _NodeItem(QGraphicsEllipseItem):
        def __init__(self, owner, node, x, y):
            radius = float(node.get('radius') or 15.0)
            super().__init__(-radius, -radius, radius * 2, radius * 2)
            self.owner = owner
            self.node = node
            self.setPos(x, y)
            self.setBrush(QBrush(QColor(str(node.get('color') or OS_COLORS['unknown']))))
            self.setPen(QPen(QColor('#e9f1f5' if node.get('is_origin') else '#17242a'), 2.2))
            self.setFlag(QGraphicsItem.ItemIsSelectable, True)
            self.setAcceptHoverEvents(True)
            self.setZValue(2)
            self.setToolTip(
                f"{node.get('hostname') or node.get('id')}\n"
                f"{node.get('port_count', 0)} open port(s) · {node.get('os') or 'Unknown OS'}"
            )
            label = QGraphicsSimpleTextItem(str(node.get('label') or node.get('id')), self)
            label.setBrush(QBrush(QColor('#dbe7ec')))
            label_rect = label.boundingRect()
            label.setPos(-label_rect.width() / 2, radius + 5)
            label.setFlag(QGraphicsItem.ItemIgnoresTransformations, True)

        def mousePressEvent(self, event):
            self.owner.inspect_node(str(self.node.get('id') or ''))
            super().mousePressEvent(event)

        def hoverEnterEvent(self, event):
            self.setPen(QPen(QColor('#6ee7d8'), 3.0))
            super().hoverEnterEvent(event)

        def hoverLeaveEvent(self, event):
            color = '#6ee7d8' if self.isSelected() else (
                '#e9f1f5' if self.node.get('is_origin') else '#17242a'
            )
            self.setPen(QPen(QColor(color), 2.4))
            super().hoverLeaveEvent(event)

    class _TopologyWidget(QWidget):
        def __init__(self, widget_parent=None):
            super().__init__(widget_parent)
            self.setObjectName('DiscoveryTopologyWidget')
            self.setAccessibleName('Discovery network topology')
            self.graph: Dict[str, Any] = {'nodes': [], 'edges': []}
            self.node_items: Dict[str, _NodeItem] = {}
            self.selected_id = ''

            outer = QVBoxLayout(self)
            outer.setContentsMargins(0, 0, 0, 0)
            controls = QHBoxLayout()
            title = QLabel('Network topology')
            title.setObjectName('FieldLabel')
            self.status = QLabel('Waiting for discovered hosts')
            self.status.setObjectName('TopologyStatus')
            self.status.setAccessibleName('Topology layout status')
            zoom_out = QPushButton('−')
            zoom_in = QPushButton('+')
            reset = QPushButton('Reset view')
            for button, name in (
                    (zoom_out, 'Zoom topology out'),
                    (zoom_in, 'Zoom topology in'),
                    (reset, 'Reset topology view')):
                button.setAccessibleName(name)
            controls.addWidget(title)
            controls.addWidget(self.status)
            controls.addStretch()
            controls.addWidget(zoom_out)
            controls.addWidget(zoom_in)
            controls.addWidget(reset)
            outer.addLayout(controls)

            splitter = QSplitter(Qt.Horizontal)
            splitter.setObjectName('DiscoveryTopologySplitter')
            splitter.setChildrenCollapsible(False)
            self.scene = QGraphicsScene(self)
            self.view = _TopologyView(self)
            self.view.setScene(self.scene)
            splitter.addWidget(self.view)

            details = QFrame()
            details.setObjectName('TopologyInspector')
            details.setMinimumWidth(255)
            detail_layout = QVBoxLayout(details)
            inspector_title = QLabel('Host inspector')
            inspector_title.setObjectName('FieldLabel')
            self.detail = QTextBrowser()
            self.detail.setAccessibleName('Topology host details')
            self.detail.setOpenExternalLinks(False)
            self.detail.setHtml(
                '<p style="color:#82909c">Select a node or host row to inspect '
                'its address, services, ports, OS fingerprint, and findings.</p>'
            )
            detail_layout.addWidget(inspector_title)
            detail_layout.addWidget(self.detail, 1)
            splitter.addWidget(details)
            splitter.setStretchFactor(0, 4)
            splitter.setStretchFactor(1, 1)
            splitter.setSizes([700, 270])
            outer.addWidget(splitter, 1)

            legend = QLabel(
                '<b>Legend</b>&nbsp;&nbsp; '
                '<span style="color:#5fc98f">●</span> Linux/Unix&nbsp;&nbsp; '
                '<span style="color:#62a8ff">●</span> Windows&nbsp;&nbsp; '
                '<span style="color:#a78bfa">●</span> BSD&nbsp;&nbsp; '
                '<span style="color:#f2b84b">●</span> Network device&nbsp;&nbsp; '
                '<span style="color:#82909c">●</span> Unknown&nbsp;&nbsp; '
                '<span style="color:#ff5d6c">●</span> Known vulnerability'
                '&nbsp;&nbsp; <small>Node size = open-port count · solid line = reported link · '
                'dashed line = discovery relationship · drag to pan · wheel to zoom</small>'
            )
            legend.setObjectName('TopologyLegend')
            legend.setAccessibleName(
                'Topology legend: color is OS or vulnerability status; size is open port count'
            )
            legend.setWordWrap(True)
            outer.addWidget(legend)

            zoom_in.clicked.connect(lambda: self._zoom(1.2))
            zoom_out.clicked.connect(lambda: self._zoom(1 / 1.2))
            reset.clicked.connect(self.reset_view)

        def _zoom(self, factor):
            self.view.interacted = True
            current = self.view.transform().m11()
            if 0.16 <= current * factor <= 6.0:
                self.view.scale(factor, factor)

        def reset_view(self):
            self.view.interacted = False
            self.view.resetTransform()
            bounds = self.scene.itemsBoundingRect()
            if not bounds.isEmpty():
                self.view.fitInView(bounds.adjusted(-45, -45, 45, 45), Qt.KeepAspectRatio)

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
            self.graph = build_topology(report if isinstance(report, Mapping) else {})
            positions = topology_positions(self.graph)
            self.scene.clear()
            self.node_items = {}
            nodes = {str(node['id']): node for node in self.graph['nodes']}
            if self.graph.get('layout') == 'rings':
                hops = sorted({
                    int(node['hop']) for node in nodes.values()
                    if node.get('hop') is not None and int(node['hop']) > 0
                })
                for hop in hops:
                    ring_radius = 125.0 + (hop - 1) * 115.0
                    ring_pen = QPen(QColor('#21343c'), 1.0, Qt.DotLine)
                    ring = self.scene.addEllipse(
                        -ring_radius, -ring_radius,
                        ring_radius * 2, ring_radius * 2,
                        ring_pen,
                    )
                    ring.setZValue(-2)
                    hop_label = self.scene.addSimpleText(f'hop {hop}')
                    hop_label.setBrush(QBrush(QColor('#4e6872')))
                    hop_label.setPos(ring_radius + 5, -10)
                    hop_label.setZValue(-1)
            for edge in self.graph['edges']:
                source = positions.get(str(edge.get('source')))
                target = positions.get(str(edge.get('target')))
                if not source or not target:
                    continue
                line = QGraphicsLineItem(source[0], source[1], target[0], target[1])
                pen = QPen(QColor('#34505b'), 1.35)
                if edge.get('kind') == 'discovery':
                    pen.setStyle(Qt.DashLine)
                line.setPen(pen)
                line.setZValue(0)
                self.scene.addItem(line)
            for node_id, node in nodes.items():
                x, y = positions.get(node_id, (0.0, 0.0))
                item = _NodeItem(self, node, x, y)
                self.node_items[node_id] = item
                self.scene.addItem(item)
            layout_name = (
                'Concentric rings · hop distance'
                if self.graph.get('layout') == 'rings'
                else 'Force-directed · traceroute unavailable'
            )
            self.status.setText(
                f"{len(nodes)} host(s) · {len(self.graph['edges'])} connection(s) · {layout_name}"
            )
            if not nodes:
                empty = self.scene.addSimpleText('Hosts will appear here as Discovery finds them')
                empty.setBrush(QBrush(QColor('#82909c')))
                empty.setPos(-155, -10)
            if selected in nodes:
                self.inspect_node(selected)
            elif selected:
                self.selected_id = ''
            if not self.view.interacted:
                self.reset_view()

        def inspect_node(self, node_id):
            node = next((
                item for item in self.graph.get('nodes') or []
                if str(item.get('id')) == str(node_id)
            ), None)
            if not node:
                return
            self.selected_id = str(node_id)
            for item_id, item in self.node_items.items():
                selected = item_id == self.selected_id
                item.setSelected(selected)
                item.setPen(QPen(QColor(
                    '#6ee7d8' if selected else (
                        '#e9f1f5' if item.node.get('is_origin') else '#17242a'
                    )
                ), 3.0 if selected else 2.2))
            rows = host_detail_rows(node)
            status = []
            if node.get('is_origin'):
                status.append('Scan origin')
            if node.get('vulnerable'):
                status.append('Known vulnerability')
            if node.get('hop') is not None:
                status.append(f"Hop {node['hop']}")
            body = ''.join(
                '<tr><td style="color:#82909c;padding:4px 10px 4px 0;vertical-align:top">'
                f'{html.escape(label)}</td><td style="padding:4px 0">{html.escape(value)}</td></tr>'
                for label, value in rows
            )
            self.detail.setHtml(
                f'<h3>{html.escape(str(node.get("hostname") or node.get("id")))}</h3>'
                f'<p>{html.escape(" · ".join(status) or "Discovered host")}</p>'
                f'<table>{body}</table>'
            )

        def select_host(self, host):
            node = find_topology_node(self.graph, host)
            if node:
                self.inspect_node(str(node.get('id') or ''))

    return _TopologyWidget(parent)
