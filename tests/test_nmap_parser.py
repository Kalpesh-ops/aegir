import pytest

pytest.importorskip("nmap")

from src.scanner.nmap_engine import NmapScanner


SAMPLE_XML = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <status state=\"up\" />
    <address addr=\"192.168.1.50\" addrtype=\"ipv4\" />
    <ports>
      <port protocol=\"tcp\" portid=\"22\">
        <state state=\"open\" />
        <service name=\"ssh\" product=\"OpenSSH\" version=\"8.4\" />
      </port>
      <port protocol=\"tcp\" portid=\"80\">
        <state state=\"open\" />
        <service name=\"http\" product=\"nginx\" version=\"1.18\" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_ports_from_xml_returns_expected_fields() -> None:
    scanner = NmapScanner.__new__(NmapScanner)
    ports = scanner.parse_ports_from_xml(SAMPLE_XML)
    assert len(ports) == 2
    by_port = {p["port"]: p for p in ports}
    assert by_port["22"]["service"] == "ssh"
    assert by_port["22"]["product"] == "OpenSSH"
    assert by_port["80"]["version"] == "1.18"
    assert by_port["80"]["state"] == "open"


def test_parse_ports_from_xml_empty_on_invalid_input() -> None:
    scanner = NmapScanner.__new__(NmapScanner)
    assert scanner.parse_ports_from_xml("<not-xml>") == []
    assert scanner.parse_ports_from_xml("") == []
