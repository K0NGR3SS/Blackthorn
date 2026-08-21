import pytest

from wafpierce.pentest_workspace import PentestWorkspace
from wafpierce.recon_ingest import ReconImportError, parse_nmap_xml_bytes


NMAP_XML = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -sV -O -oX out.xml">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="app.example.test" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25" tunnel="ssl">
          <cpe>cpe:/a:nginx:nginx:1.25</cpe>
        </service>
        <script id="http-title" output="Example App"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
    <os><osmatch name="Linux 6.x" accuracy="96"><osclass><cpe>cpe:/o:linux:linux_kernel:6</cpe></osclass></osmatch></os>
    <trace>
      <hop ttl="1" ipaddr="192.0.2.1" rtt="1.2"/>
      <hop ttl="2" ipaddr="192.0.2.10" rtt="2.4"/>
    </trace>
  </host>
</nmaprun>'''


def test_nmap_import_builds_service_cpe_endpoint_and_graph(tmp_path):
    result = parse_nmap_xml_bytes(NMAP_XML)
    assert {asset.value for asset in result.assets} >= {
        "app.example.test", "192.0.2.10", "Linux 6.x"
    }
    assert len(result.services) == 1
    assert result.services[0].cpes == ("cpe:/a:nginx:nginx:1.25",)
    assert result.endpoints[0].url == "https://app.example.test/"
    assert {edge.relation for edge in result.edges} >= {
        "resolves_to", "exposes", "serves", "fingerprinted_as"
    }

    workspace = PentestWorkspace(str(tmp_path / "recon.db"))
    workspace_id = workspace.create_workspace(
        "Recon", ["https://app.example.test"]
    )
    counts = result.persist(workspace, workspace_id)
    assert counts["services"] == 1
    assert workspace.summary(workspace_id)["edges"] >= 4


def test_nmap_import_rejects_dtds_and_wrong_documents():
    with pytest.raises(ReconImportError):
        parse_nmap_xml_bytes(b'<!DOCTYPE x [<!ENTITY x "boom">]><nmaprun/>')
    with pytest.raises(ReconImportError):
        parse_nmap_xml_bytes(b'<not-nmap/>')


def test_nmap_import_ignores_down_hosts():
    result = parse_nmap_xml_bytes(
        b'<nmaprun><host><status state="down"/><address addr="192.0.2.2" addrtype="ipv4"/></host></nmaprun>'
    )
    assert result.assets == []


def test_nmap_redacts_credentials_from_script_output():
    result = parse_nmap_xml_bytes(b"""<nmaprun args='nmap --script-args password=cli-secret'>
      <host><status state='up'/><address addr='192.0.2.1' addrtype='ipv4'/>
      <hostscript><script id='demo' output='token=script-secret'/></hostscript>
      <ports><port protocol='tcp' portid='80'><state state='open'/>
      <service name='http'/></port></ports></host></nmaprun>""")
    serialized = repr(result)
    assert "cli-secret" not in serialized
    assert "script-secret" not in serialized
    assert "<redacted>" in serialized
