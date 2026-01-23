"""Tests for Masscan parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.masscan import MasscanParser
from ariadne.models.asset import Host, Service
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestMasscanParser(BaseParserTest):
    """Test MasscanParser functionality."""

    parser_class = MasscanParser
    expected_name = "masscan"
    expected_patterns = ["*masscan*.json", "*masscan*.xml"]
    expected_entity_types = ["Host", "Service"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_json_file(self, tmp_path: Path):
        """Test detection of JSON masscan output."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "proto": "tcp", "status": "open"}]
        }])
        json_file = tmp_path / "masscan_output.json"
        json_file.write_text(json_content)

        assert MasscanParser.can_parse(json_file)

    def test_can_parse_xml_file(self, tmp_path: Path):
        """Test detection of XML masscan output."""
        xml_content = """<?xml version="1.0"?>
<nmaprun scanner="masscan">
  <host>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        xml_file = tmp_path / "masscan_output.xml"
        xml_file.write_text(xml_content)

        assert MasscanParser.can_parse(xml_file)

    def test_cannot_parse_nmap_xml(self, tmp_path: Path):
        """Test that masscan parser does not match nmap XML files."""
        xml_content = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><address addr="192.168.1.1"/></host>
</nmaprun>"""
        xml_file = tmp_path / "nmap_scan.xml"
        xml_file.write_text(xml_content)

        # Masscan should NOT match nmap XML - only files with "masscan" identifier
        assert not MasscanParser.can_parse(xml_file)

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_single_host(self, tmp_path: Path):
        """Test parsing JSON with single host."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [{"port": 22, "proto": "tcp", "status": "open"}]
        }])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].source == "masscan"

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].port == 22
        assert services[0].name == "ssh"

    def test_parse_json_multiple_hosts(self, tmp_path: Path):
        """Test parsing JSON with multiple hosts."""
        json_content = json.dumps([
            {"ip": "192.168.1.1", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.2", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.3", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
        ])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 3
        host_ips = {h.ip for h in hosts}
        assert host_ips == {"192.168.1.1", "192.168.1.2", "192.168.1.3"}

    def test_parse_json_multiple_ports_same_host(self, tmp_path: Path):
        """Test parsing JSON with multiple ports on same host."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [
                {"port": 22, "proto": "tcp", "status": "open"},
                {"port": 80, "proto": "tcp", "status": "open"},
                {"port": 443, "proto": "tcp", "status": "open"},
            ]
        }])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1

        services = self.get_services(entities)
        assert len(services) == 3
        ports = {s.port for s in services}
        assert ports == {22, 80, 443}

    def test_parse_json_skips_closed_ports(self, tmp_path: Path):
        """Test that closed ports are not parsed."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [
                {"port": 22, "proto": "tcp", "status": "open"},
                {"port": 23, "proto": "tcp", "status": "closed"},
            ]
        }])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].port == 22

    def test_parse_jsonl_format(self, tmp_path: Path):
        """Test parsing JSONL (one object per line) format."""
        json_content = """{"ip": "192.168.1.1", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]}
{"ip": "192.168.1.2", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}"""
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 2

    # =========================================================================
    # XML Parsing Tests
    # =========================================================================

    def test_parse_xml_single_host(self, tmp_path: Path):
        """Test parsing XML with single host."""
        xml_content = """<?xml version="1.0"?>
<nmaprun scanner="masscan">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        xml_file = tmp_path / "masscan.xml"
        xml_file.write_text(xml_content)

        parser = MasscanParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].port == 22

    # =========================================================================
    # Service Guessing Tests
    # =========================================================================

    def test_service_name_guessing(self, tmp_path: Path):
        """Test that common port services are correctly guessed."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [
                {"port": 21, "proto": "tcp", "status": "open"},
                {"port": 22, "proto": "tcp", "status": "open"},
                {"port": 80, "proto": "tcp", "status": "open"},
                {"port": 443, "proto": "tcp", "status": "open"},
                {"port": 445, "proto": "tcp", "status": "open"},
                {"port": 3389, "proto": "tcp", "status": "open"},
            ]
        }])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        service_map = {s.port: s.name for s in services}

        assert service_map[21] == "ftp"
        assert service_map[22] == "ssh"
        assert service_map[80] == "http"
        assert service_map[443] == "https"
        assert service_map[445] == "microsoft-ds"
        assert service_map[3389] == "rdp"

    def test_unknown_port_service(self, tmp_path: Path):
        """Test that unknown ports get 'unknown' service name."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [{"port": 12345, "proto": "tcp", "status": "open"}]
        }])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].name == "unknown"

    # =========================================================================
    # Relationship Tests
    # =========================================================================

    def test_creates_service_to_host_relationships(self, tmp_path: Path):
        """Test that RUNS_ON relationships are created."""
        json_content = json.dumps([{
            "ip": "192.168.1.1",
            "ports": [{"port": 22, "proto": "tcp", "status": "open"}]
        }])
        json_file = tmp_path / "masscan.json"
        json_file.write_text(json_content)

        parser = MasscanParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        assert len(relationships) >= 1

        # Check relationship connects service to host
        hosts = self.get_hosts(entities)
        services = self.get_services(entities)
        assert any(
            r.target_id == hosts[0].id and r.source_id == services[0].id
            for r in relationships
        )
