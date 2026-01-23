"""Tests for RustScan parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.rustscan import RustScanParser
from ariadne.models.asset import Host, Service
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestRustScanParser(BaseParserTest):
    """Test RustScanParser functionality."""

    parser_class = RustScanParser
    expected_name = "rustscan"
    expected_patterns = ["*rustscan*.json", "*rustscan*.txt", "*rustscan*.greppable"]
    expected_entity_types = ["Host", "Service"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_rustscan_json(self, tmp_path: Path):
        """Test detection of RustScan JSON file."""
        data = {
            "ip": "192.168.1.100",
            "ports": [22, 80, 443]
        }
        json_file = tmp_path / "rustscan_output.json"
        json_file.write_text(json.dumps(data))

        assert RustScanParser.can_parse(json_file)

    def test_can_parse_rustscan_txt(self, tmp_path: Path):
        """Test detection of RustScan text output."""
        content = """RustScan
192.168.1.100 -> [22, 80, 443]
"""
        txt_file = tmp_path / "rustscan.txt"
        txt_file.write_text(content)

        assert RustScanParser.can_parse(txt_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not RustScanParser.can_parse(json_file)

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_simple(self, tmp_path: Path):
        """Test parsing simple JSON output."""
        data = {
            "ip": "192.168.1.100",
            "hostname": "server.local",
            "ports": [22, 80, 443]
        }
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"
        assert hosts[0].hostname == "server.local"

    def test_parse_json_with_port_objects(self, tmp_path: Path):
        """Test parsing JSON with detailed port objects."""
        data = {
            "ip": "192.168.1.100",
            "ports": [
                {"port": 22, "protocol": "tcp", "service": {"name": "ssh"}},
                {"port": 80, "protocol": "tcp", "service": {"name": "http"}}
            ]
        }
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 2
        assert any(s.port == 22 and s.name == "ssh" for s in services)
        assert any(s.port == 80 and s.name == "http" for s in services)

    def test_parse_json_array(self, tmp_path: Path):
        """Test parsing JSON array of hosts."""
        data = [
            {"ip": "192.168.1.100", "ports": [22]},
            {"ip": "192.168.1.101", "ports": [80]}
        ]
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2
        ips = [h.ip for h in hosts]
        assert "192.168.1.100" in ips
        assert "192.168.1.101" in ips

    def test_parse_json_creates_relationships(self, tmp_path: Path):
        """Test that JSON parsing creates service-host relationships."""
        data = {
            "ip": "192.168.1.100",
            "ports": [22, 80]
        }
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 2

    # =========================================================================
    # Text/Greppable Parsing Tests
    # =========================================================================

    def test_parse_simple_text(self, tmp_path: Path):
        """Test parsing simple RustScan text output."""
        content = """192.168.1.100 -> [22, 80, 443]
192.168.1.101 -> [3389]
"""
        txt_file = tmp_path / "rustscan.txt"
        txt_file.write_text(content)

        parser = RustScanParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

        services = self.get_services(entities)
        assert len(services) >= 4

    def test_parse_greppable_format(self, tmp_path: Path):
        """Test parsing greppable output format."""
        content = """Host: 192.168.1.100 () Ports: 22/open/tcp//ssh//, 80/open/tcp//http//, 443/open/tcp//https//
Host: 192.168.1.101 () Ports: 3389/open/tcp//rdp//
"""
        greppable_file = tmp_path / "rustscan.greppable"
        greppable_file.write_text(content)

        parser = RustScanParser()
        entities = list(parser.parse(greppable_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

        services = self.get_services(entities)
        assert len(services) >= 4
        assert any(s.port == 22 and s.protocol == "tcp" for s in services)

    def test_parse_greppable_extracts_service_name(self, tmp_path: Path):
        """Test that greppable format extracts service names."""
        content = """Host: 192.168.1.100 () Ports: 22/open/tcp//ssh//, 80/open/tcp//http//
"""
        greppable_file = tmp_path / "rustscan.greppable"
        greppable_file.write_text(content)

        parser = RustScanParser()
        entities = list(parser.parse(greppable_file))

        services = self.get_services(entities)
        assert len(services) >= 2
        # Check that service names are extracted
        service_names = [s.name for s in services]
        assert "ssh" in service_names or any("ssh" in str(n).lower() for n in service_names)

    # =========================================================================
    # Service Guessing Tests
    # =========================================================================

    def test_guesses_common_services(self, tmp_path: Path):
        """Test that common port services are guessed correctly."""
        data = {
            "ip": "192.168.1.100",
            "ports": [22, 80, 443, 3389, 5432]
        }
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        service_map = {s.port: s.name for s in services}
        assert service_map.get(22) == "ssh"
        assert service_map.get(80) == "http"
        assert service_map.get(443) == "https"
        assert service_map.get(3389) == "rdp"
        assert service_map.get(5432) == "postgresql"

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts_in_text(self, tmp_path: Path):
        """Test that duplicate hosts are not created in text parsing."""
        content = """Host: 192.168.1.100 () Ports: 22/open/tcp//ssh//
Host: 192.168.1.100 () Ports: 80/open/tcp//http//
"""
        txt_file = tmp_path / "rustscan.txt"
        txt_file.write_text(content)

        parser = RustScanParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        host_100 = [h for h in hosts if h.ip == "192.168.1.100"]
        assert len(host_100) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "rustscan_empty.json"
        json_file.write_text("")

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_handles_empty_ports(self, tmp_path: Path):
        """Test handling of entry with no ports."""
        data = {
            "ip": "192.168.1.100",
            "ports": []
        }
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        services = self.get_services(entities)
        assert len(services) == 0

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "rustscan.json"
        json_file.write_text("{invalid json}")

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_rustscan(self, tmp_path: Path):
        """Test that source is set to rustscan."""
        data = {
            "ip": "192.168.1.100",
            "ports": [22]
        }
        json_file = tmp_path / "rustscan.json"
        json_file.write_text(json.dumps(data))

        parser = RustScanParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "rustscan"
