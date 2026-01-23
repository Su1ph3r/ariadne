"""Tests for Nmap parser."""

import pytest
from pathlib import Path

from ariadne.parsers.nmap import NmapParser
from ariadne.models.asset import Host, Service


class TestNmapParser:
    """Test NmapParser functionality."""

    def test_parser_attributes(self):
        """Test parser has correct attributes."""
        parser = NmapParser()
        assert parser.name == "nmap"
        assert "*.xml" in parser.file_patterns
        assert "Host" in parser.entity_types

    def test_can_parse_xml(self, tmp_path: Path):
        """Test file detection."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')

        assert NmapParser.can_parse(xml_file)

    def test_cannot_parse_json(self, tmp_path: Path):
        """Test non-XML files are rejected."""
        json_file = tmp_path / "scan.json"
        json_file.write_text('{"test": true}')

        assert not NmapParser.can_parse(json_file)

    def test_parse_simple_host(self, tmp_path: Path):
        """Test parsing a simple host."""
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="server.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(xml_content)

        parser = NmapParser()
        entities = list(parser.parse(xml_file))

        hosts = [e for e in entities if isinstance(e, Host)]
        services = [e for e in entities if isinstance(e, Service)]

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].hostname == "server.local"

        assert len(services) == 2
        service_ports = {s.port for s in services}
        assert service_ports == {22, 80}
