"""Bounded reconnaissance importers for the pentest asset graph."""
from __future__ import annotations

import ipaddress
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from .pentest_models import Asset, Endpoint, GraphEdge, Service
from .pentest_workspace import PentestWorkspace
from .redaction import redact_text


MAX_NMAP_XML_BYTES = 32 * 1024 * 1024
MAX_NMAP_ELEMENTS = 250_000
MAX_SCRIPT_OUTPUT = 16 * 1024


class ReconImportError(ValueError):
    pass


def _bounded_file(path: str, maximum: int) -> bytes:
    resolved = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.isfile(resolved):
        raise ReconImportError("recon input file not found")
    size = os.path.getsize(resolved)
    if size > maximum:
        raise ReconImportError("recon input exceeds the %d-byte limit" % maximum)
    with open(resolved, "rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise ReconImportError("recon input exceeds the %d-byte limit" % maximum)
    return data


def _clean(value: Any, maximum: int = 4096) -> str:
    text = str(value or "").replace("\x00", "").strip()
    return text[:maximum]


def _unique(items: Iterable[Any], key) -> List[Any]:
    result = []
    seen = set()
    for item in items:
        marker = key(item)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


@dataclass
class NmapImportResult:
    assets: List[Asset] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    run_metadata: Dict[str, Any] = field(default_factory=dict)

    def persist(self, workspace: PentestWorkspace, workspace_id: str) -> Dict[str, int]:
        for asset in self.assets:
            workspace.save_asset(workspace_id, asset)
        for service in self.services:
            workspace.save_service(workspace_id, service)
        for endpoint in self.endpoints:
            workspace.save_endpoint(workspace_id, endpoint)
        for edge in self.edges:
            workspace.save_edge(workspace_id, edge)
        return {
            "assets": len(self.assets),
            "services": len(self.services),
            "endpoints": len(self.endpoints),
            "edges": len(self.edges),
            "warnings": len(self.warnings),
        }


def _parse_root(data: bytes) -> ET.Element:
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ReconImportError("DTD/entity declarations are not accepted in Nmap XML")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ReconImportError("invalid Nmap XML: %s" % exc) from exc
    if root.tag != "nmaprun":
        raise ReconImportError("expected an nmaprun XML document")
    if sum(1 for _ in root.iter()) > MAX_NMAP_ELEMENTS:
        raise ReconImportError("Nmap XML contains too many elements")
    return root


def _host_url(host: str, port: int, service_name: str, tunnel: str) -> Optional[str]:
    name = (service_name or "").lower()
    tunnel = (tunnel or "").lower()
    if name not in {
        "http", "https", "http-proxy", "https-alt", "ssl/http", "http-alt"
    } and tunnel != "ssl":
        return None
    scheme = "https" if "https" in name or tunnel == "ssl" or port in {443, 8443} else "http"
    try:
        parsed = ipaddress.ip_address(host)
        authority = "[%s]" % parsed.compressed if parsed.version == 6 else parsed.compressed
    except ValueError:
        authority = host
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return "%s://%s%s/" % (scheme, authority, "" if default else ":%d" % port)


def parse_nmap_xml_bytes(data: bytes) -> NmapImportResult:
    if len(data) > MAX_NMAP_XML_BYTES:
        raise ReconImportError("Nmap XML exceeds the import size limit")
    root = _parse_root(data)
    result = NmapImportResult(
        run_metadata={
            "scanner": _clean(root.get("scanner"), 128),
            "args": redact_text(_clean(root.get("args"), 8192)),
            "start": _clean(root.get("start"), 64),
            "version": _clean(root.get("version"), 128),
        }
    )

    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is not None and status.get("state") not in {None, "up"}:
            continue

        address_assets: List[Asset] = []
        for address in host_node.findall("address"):
            value = _clean(address.get("addr"), 512)
            addr_type = _clean(address.get("addrtype"), 32).lower()
            if not value:
                continue
            if addr_type in {"ipv4", "ipv6"}:
                try:
                    value = ipaddress.ip_address(value).compressed
                except ValueError:
                    result.warnings.append("ignored invalid IP address: %s" % value)
                    continue
                kind = "ip"
            elif addr_type == "mac":
                kind = "mac"
            else:
                kind = addr_type or "address"
            address_assets.append(Asset(
                kind, value, "nmap", metadata={
                    "vendor": _clean(address.get("vendor"), 512),
                    "address_type": addr_type,
                }
            ))

        hostname_assets: List[Asset] = []
        for hostname in host_node.findall("./hostnames/hostname"):
            value = _clean(hostname.get("name"), 253).rstrip(".").lower()
            if value:
                hostname_assets.append(Asset(
                    "hostname", value, "nmap", confidence=0.9,
                    metadata={"hostname_type": _clean(hostname.get("type"), 64)},
                ))

        address_assets = _unique(address_assets, lambda item: item.asset_id)
        hostname_assets = _unique(hostname_assets, lambda item: item.asset_id)
        result.assets.extend(address_assets)
        result.assets.extend(hostname_assets)
        for hostname in hostname_assets:
            for address in address_assets:
                if address.kind == "ip":
                    result.edges.append(GraphEdge(
                        hostname.asset_id, address.asset_id, "resolves_to", "nmap",
                        confidence=0.9,
                    ))

        primary = next(
            (asset for asset in hostname_assets),
            next((asset for asset in address_assets if asset.kind == "ip"), None),
        )
        if primary is None:
            result.warnings.append("ignored Nmap host without hostname/IP")
            continue

        host_scripts: Dict[str, str] = {}
        for script in host_node.findall("./hostscript/script"):
            script_id = _clean(script.get("id"), 256)
            if script_id:
                host_scripts[script_id] = redact_text(
                    _clean(script.get("output"), MAX_SCRIPT_OUTPUT)
                )

        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            state = _clean(state_node.get("state") if state_node is not None else "", 32)
            if state not in {"open", "open|filtered"}:
                continue
            try:
                port = int(port_node.get("portid", "0"))
            except ValueError:
                result.warnings.append("ignored Nmap port with invalid number")
                continue
            protocol = _clean(port_node.get("protocol"), 16).lower() or "tcp"
            service_node = port_node.find("service")
            service_name = _clean(
                service_node.get("name") if service_node is not None else "unknown", 256
            ) or "unknown"
            product = _clean(service_node.get("product") if service_node is not None else "")
            version = _clean(service_node.get("version") if service_node is not None else "")
            extra = _clean(service_node.get("extrainfo") if service_node is not None else "")
            tunnel = _clean(service_node.get("tunnel") if service_node is not None else "", 64)
            cpes = tuple(
                _clean(cpe.text, 1024)
                for cpe in (service_node.findall("cpe") if service_node is not None else [])
                if _clean(cpe.text, 1024)
            )
            scripts = {}
            for script in port_node.findall("script"):
                script_id = _clean(script.get("id"), 256)
                if script_id:
                    scripts[script_id] = redact_text(
                        _clean(script.get("output"), MAX_SCRIPT_OUTPUT)
                    )
            service = Service(
                primary.asset_id,
                port,
                protocol=protocol,
                name=service_name,
                product=product,
                version=version,
                state=state.replace("|", "-"),
                cpes=cpes,
                source="nmap",
                metadata={
                    "extra_info": extra,
                    "tunnel": tunnel,
                    "scripts": scripts,
                    "host_scripts": host_scripts,
                },
            )
            result.services.append(service)
            result.edges.append(GraphEdge(
                primary.asset_id, service.service_id, "exposes", "nmap",
                evidence={"port": port, "protocol": protocol, "state": state},
            ))
            endpoint_url = _host_url(primary.value, port, service_name, tunnel)
            if endpoint_url:
                endpoint = Endpoint(
                    primary.asset_id,
                    endpoint_url,
                    source="nmap",
                    metadata={"service_id": service.service_id},
                )
                result.endpoints.append(endpoint)
                result.edges.append(GraphEdge(
                    service.service_id, endpoint.endpoint_id, "serves", "nmap"
                ))

        for os_match in host_node.findall("./os/osmatch")[:10]:
            name = _clean(os_match.get("name"), 1024)
            if not name:
                continue
            try:
                accuracy = max(0.0, min(1.0, float(os_match.get("accuracy", "0")) / 100.0))
            except ValueError:
                accuracy = 0.0
            os_cpes = []
            for os_class in os_match.findall("osclass"):
                os_cpes.extend(
                    _clean(cpe.text, 1024) for cpe in os_class.findall("cpe") if cpe.text
                )
            os_asset = Asset(
                "operating-system", name, "nmap", confidence=accuracy,
                metadata={"cpes": sorted(set(os_cpes)), "accuracy": accuracy},
            )
            result.assets.append(os_asset)
            result.edges.append(GraphEdge(
                primary.asset_id, os_asset.asset_id, "fingerprinted_as", "nmap",
                confidence=accuracy,
            ))

        route_nodes: List[Asset] = []
        for hop in host_node.findall("./trace/hop"):
            ip_value = _clean(hop.get("ipaddr"), 512)
            if not ip_value:
                continue
            try:
                ip_value = ipaddress.ip_address(ip_value).compressed
            except ValueError:
                continue
            route_nodes.append(Asset(
                "ip", ip_value, "nmap-traceroute", confidence=0.8,
                metadata={
                    "ttl": _clean(hop.get("ttl"), 16),
                    "rtt_ms": _clean(hop.get("rtt"), 64),
                    "hostname": _clean(hop.get("host"), 253),
                },
            ))
        result.assets.extend(route_nodes)
        previous = None
        for route_node in route_nodes:
            if previous is not None and previous.asset_id != route_node.asset_id:
                result.edges.append(GraphEdge(
                    previous.asset_id, route_node.asset_id, "network_path", "nmap-traceroute",
                    confidence=0.8,
                ))
            previous = route_node
        if previous is not None and previous.asset_id != primary.asset_id:
            result.edges.append(GraphEdge(
                previous.asset_id, primary.asset_id, "network_path", "nmap-traceroute",
                confidence=0.8,
            ))

    result.assets = _unique(result.assets, lambda item: item.asset_id)
    result.services = _unique(result.services, lambda item: item.service_id)
    result.endpoints = _unique(result.endpoints, lambda item: item.endpoint_id)
    result.edges = _unique(result.edges, lambda item: item.edge_id)
    return result


def load_nmap_xml(path: str) -> NmapImportResult:
    return parse_nmap_xml_bytes(_bounded_file(path, MAX_NMAP_XML_BYTES))
