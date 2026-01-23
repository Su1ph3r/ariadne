"""Tests for Censys parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.censys import CensysParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestCensysParser(BaseParserTest):
    """Test CensysParser functionality."""

    parser_class = CensysParser
    expected_name = "censys"
    expected_patterns = ["*censys*.json", "censys_*.json"]
    expected_entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_censys_json(self, tmp_path: Path):
        """Test detection of Censys JSON file by indicators."""
        data = {
            "ip": "192.168.1.100",
            "autonomous_system": {"asn": 12345},
            "services": [{"port": 80, "transport_protocol": "tcp"}]
        }
        json_file = tmp_path / "censys_results.json"
        json_file.write_text(json.dumps(data))

        assert CensysParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        data = {
            "ip": "192.168.1.100",
            "autonomous_system": {"asn": 12345},
            "services": [{"port": 443}],
            "location": {"country": "US"}
        }
        json_file = tmp_path / "results.json"
        json_file.write_text(json.dumps(data))

        assert CensysParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not CensysParser.can_parse(json_file)

    def test_cannot_parse_non_json(self, tmp_path: Path):
        """Test that non-JSON files are rejected."""
        txt_file = tmp_path / "censys.txt"
        txt_file.write_text("censys results")

        assert not CensysParser.can_parse(txt_file)

    # =========================================================================
    # Host Parsing Tests
    # =========================================================================

    def test_parse_host(self, tmp_path: Path):
        """Test parsing host from Censys data."""
        data = {
            "ip": "203.0.113.50",
            "dns": {"names": ["www.example.com", "example.com"]},
            "operating_system": {"product": "Linux"},
            "autonomous_system": {"asn": 12345, "name": "Example ASN"},
            "location": {"country": "US", "city": "New York"}
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "203.0.113.50"
        assert hosts[0].hostname == "www.example.com"
        assert hosts[0].os == "Linux"
        assert "internet-facing" in hosts[0].tags

    def test_parse_host_stores_metadata(self, tmp_path: Path):
        """Test that host metadata is stored in raw_properties."""
        data = {
            "ip": "192.168.1.100",
            "autonomous_system": {"asn": 99999, "name": "Test ASN"},
            "location": {"country": "DE", "city": "Berlin"},
            "dns": {"names": ["test.example.com"]}
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].raw_properties.get("asn") == 99999
        assert hosts[0].raw_properties.get("country") == "DE"

    def test_parse_host_reverse_dns(self, tmp_path: Path):
        """Test parsing hostname from reverse DNS."""
        data = {
            "ip": "192.168.1.100",
            "dns": {"reverse_dns": {"names": ["reverse.example.com"]}}
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "reverse.example.com"

    # =========================================================================
    # Service Parsing Tests (v2 format)
    # =========================================================================

    def test_parse_service(self, tmp_path: Path):
        """Test parsing service from Censys v2 format."""
        data = {
            "ip": "192.168.1.100",
            "services": [{
                "port": 443,
                "transport_protocol": "tcp",
                "service_name": "https",
                "software": [{"product": "nginx", "version": "1.18.0"}],
                "banner": "HTTP/1.1 200 OK"
            }]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 443
        assert services[0].protocol == "tcp"
        assert services[0].name == "https"
        assert services[0].product == "nginx"
        assert services[0].version == "1.18.0"

    def test_parse_service_creates_relationship(self, tmp_path: Path):
        """Test that service creates RUNS_ON relationship."""
        data = {
            "ip": "192.168.1.100",
            "services": [{"port": 80, "transport_protocol": "tcp"}]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    def test_parse_service_tls_flag(self, tmp_path: Path):
        """Test TLS flag detection in service."""
        data = {
            "ip": "192.168.1.100",
            "services": [{
                "port": 443,
                "service_name": "https",
                "tls": {"version": "TLSv1.2"}
            }]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].ssl == True

    # =========================================================================
    # Protocol Data Parsing (v1 format)
    # =========================================================================

    def test_parse_protocol_data(self, tmp_path: Path):
        """Test parsing protocol data from v1 format."""
        data = {
            "ip": "192.168.1.100",
            "http": {"port": 8080, "status": 200}
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].name == "http"

    # =========================================================================
    # TLS Misconfiguration Tests
    # =========================================================================

    def test_parse_self_signed_cert(self, tmp_path: Path):
        """Test detection of self-signed certificate."""
        data = {
            "ip": "192.168.1.100",
            "services": [{
                "port": 443,
                "service_name": "https",
                "tls": {
                    "certificates": {
                        "leaf_data": {
                            "issuer": {"common_name": "Self Signed CA"},
                            "subject": {"common_name": "Self Signed CA"}
                        }
                    }
                }
            }]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        self_signed = [m for m in misconfigs if "Self-Signed" in m.title]
        assert len(self_signed) >= 1

    def test_parse_weak_tls_version(self, tmp_path: Path):
        """Test detection of weak TLS version."""
        data = {
            "ip": "192.168.1.100",
            "services": [{
                "port": 443,
                "service_name": "https",
                "tls": {
                    "version_selected": "TLSv1.0"
                }
            }]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        weak_tls = [m for m in misconfigs if "Weak TLS" in m.title]
        assert len(weak_tls) >= 1

    # =========================================================================
    # HTTP Misconfiguration Tests
    # =========================================================================

    def test_parse_missing_security_headers(self, tmp_path: Path):
        """Test detection of missing security headers."""
        data = {
            "ip": "192.168.1.100",
            "services": [{
                "port": 80,
                "service_name": "http",
                "http": {
                    "response": {
                        "headers": {"server": "Apache"}
                    }
                }
            }]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        missing_headers = [m for m in misconfigs if "Missing Security Headers" in m.title]
        assert len(missing_headers) >= 1

    # =========================================================================
    # Multiple Entry Tests
    # =========================================================================

    def test_parse_json_array(self, tmp_path: Path):
        """Test parsing JSON array of Censys results."""
        data = [
            {"ip": "192.168.1.100", "services": [{"port": 80}]},
            {"ip": "192.168.1.101", "services": [{"port": 443}]}
        ]
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_results_wrapper(self, tmp_path: Path):
        """Test parsing results inside wrapper object."""
        data = {
            "results": [
                {"ip": "192.168.1.100"},
                {"ip": "192.168.1.101"}
            ]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_result_wrapper(self, tmp_path: Path):
        """Test parsing single result inside wrapper."""
        data = {
            "result": {"ip": "192.168.1.100", "services": [{"port": 22}]}
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    def test_parse_jsonl_format(self, tmp_path: Path):
        """Test parsing JSON Lines format."""
        content = """{"ip": "192.168.1.100", "services": [{"port": 80}]}
{"ip": "192.168.1.101", "services": [{"port": 443}]}
"""
        json_file = tmp_path / "censys.json"
        json_file.write_text(content)

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "censys_empty.json"
        json_file.write_text("[]")

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_ip(self, tmp_path: Path):
        """Test handling of entry without IP."""
        data = {"services": [{"port": 80}]}
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        # Should not crash, no hosts produced
        hosts = self.get_hosts(entities)
        assert len(hosts) == 0

    def test_handles_no_services(self, tmp_path: Path):
        """Test handling of entry without services."""
        data = {"ip": "192.168.1.100"}
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        services = self.get_services(entities)
        assert len(services) == 0

    def test_handles_alternative_ip_field(self, tmp_path: Path):
        """Test parsing with 'host' instead of 'ip' field."""
        data = {"host": "192.168.1.100"}
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_censys(self, tmp_path: Path):
        """Test that source is set to censys."""
        data = {
            "ip": "192.168.1.100",
            "services": [{"port": 80}]
        }
        json_file = tmp_path / "censys.json"
        json_file.write_text(json.dumps(data))

        parser = CensysParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "censys"
