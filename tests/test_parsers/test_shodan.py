"""Tests for Shodan parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.shodan import ShodanParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestShodanParser(BaseParserTest):
    """Test ShodanParser functionality."""

    parser_class = ShodanParser
    expected_name = "shodan"
    expected_patterns = ["*shodan*.json", "shodan_*.json"]
    expected_entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_shodan_json(self, tmp_path: Path):
        """Test detection of Shodan JSON file."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 80,
            "hostnames": ["server.example.com"],
            "asn": "AS12345"
        }
        json_file = tmp_path / "shodan_results.json"
        json_file.write_text(json.dumps(data))

        assert ShodanParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        data = {
            "_shodan": {"module": "http"},
            "ip_str": "192.168.1.100",
            "port": 80,
            "isp": "Example ISP"
        }
        json_file = tmp_path / "results.json"
        json_file.write_text(json.dumps(data))

        assert ShodanParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not ShodanParser.can_parse(json_file)

    # =========================================================================
    # Host Parsing Tests
    # =========================================================================

    def test_parse_host(self, tmp_path: Path):
        """Test parsing host from Shodan data."""
        data = {
            "ip_str": "203.0.113.50",
            "port": 443,
            "hostnames": ["www.example.com", "example.com"],
            "os": "Linux",
            "org": "Example Corp",
            "asn": "AS12345",
            "isp": "Example ISP",
            "country_code": "US",
            "city": "New York"
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
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
            "ip_str": "192.168.1.100",
            "port": 80,
            "org": "Test Organization",
            "asn": "AS99999",
            "isp": "Test ISP",
            "country_code": "DE"
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].raw_properties.get("org") == "Test Organization"
        assert hosts[0].raw_properties.get("asn") == "AS99999"

    # =========================================================================
    # Service Parsing Tests
    # =========================================================================

    def test_parse_service(self, tmp_path: Path):
        """Test parsing service from Shodan data."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.18.0",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
            "ssl": {"cert": {}}
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 443
        assert services[0].protocol == "tcp"
        assert services[0].product == "nginx"
        assert services[0].version == "1.18.0"
        assert services[0].ssl == True

    def test_parse_service_creates_relationship(self, tmp_path: Path):
        """Test that service creates RUNS_ON relationship."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 80
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    def test_detects_service_name_from_module(self, tmp_path: Path):
        """Test service name detection from Shodan module."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 22,
            "_shodan": {"module": "ssh-simple"}
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].name == "ssh"

    def test_detects_service_name_from_protocol_key(self, tmp_path: Path):
        """Test service name detection from protocol key."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 80,
            "http": {"status": 200}
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].name == "http"

    # =========================================================================
    # Vulnerability Parsing Tests
    # =========================================================================

    def test_parse_vulnerabilities(self, tmp_path: Path):
        """Test parsing vulnerabilities from Shodan data."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "vulns": {
                "CVE-2021-44228": {"cvss": 10.0, "verified": True},
                "CVE-2020-1234": {"cvss": 7.5}
            }
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 2
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2020-1234" in cve_ids

    def test_vuln_severity_from_cvss(self, tmp_path: Path):
        """Test that vulnerability severity is derived from CVSS."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "vulns": {
                "CVE-2021-9999": {"cvss": 9.5},  # critical
                "CVE-2021-8888": {"cvss": 7.5},  # high
                "CVE-2021-7777": {"cvss": 5.0},  # medium
                "CVE-2021-6666": {"cvss": 2.0}   # low
            }
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        vuln_map = {v.cve_id: v.severity for v in vulns}
        assert vuln_map.get("CVE-2021-9999") == "critical"
        assert vuln_map.get("CVE-2021-8888") == "high"
        assert vuln_map.get("CVE-2021-7777") == "medium"
        assert vuln_map.get("CVE-2021-6666") == "low"

    def test_vuln_list_format(self, tmp_path: Path):
        """Test parsing vulnerabilities in list format."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "vulns": ["CVE-2021-44228", "CVE-2020-1234"]
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 2

    # =========================================================================
    # Misconfiguration Parsing Tests
    # =========================================================================

    def test_parse_heartbleed(self, tmp_path: Path):
        """Test parsing Heartbleed vulnerability."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "opts": {"heartbleed": True}
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        heartbleed = [m for m in misconfigs if "Heartbleed" in m.title]
        assert len(heartbleed) >= 1
        assert heartbleed[0].severity == "critical"

    def test_parse_expired_cert(self, tmp_path: Path):
        """Test parsing expired SSL certificate."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "ssl": {
                "cert": {"expired": True}
            }
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        expired = [m for m in misconfigs if "Expired" in m.title]
        assert len(expired) >= 1
        assert expired[0].severity == "medium"

    def test_parse_weak_ssl_versions(self, tmp_path: Path):
        """Test parsing weak SSL/TLS versions."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 443,
            "ssl": {
                "versions": ["SSLv3", "TLSv1.0", "TLSv1.2"]
            }
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        weak_ssl = [m for m in misconfigs if "Weak SSL" in m.title]
        assert len(weak_ssl) >= 2  # SSLv3 and TLSv1.0

    def test_parse_anonymous_ftp(self, tmp_path: Path):
        """Test parsing anonymous FTP access."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 21,
            "data": "220 FTP Server Ready\r\n230 Anonymous login ok"
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        anon_ftp = [m for m in misconfigs if "Anonymous FTP" in m.title]
        assert len(anon_ftp) >= 1

    def test_parse_auth_disabled(self, tmp_path: Path):
        """Test parsing authentication disabled."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 6379,
            "data": "Redis Server - Authentication disabled"
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        no_auth = [m for m in misconfigs if "Authentication Disabled" in m.title]
        assert len(no_auth) >= 1
        assert no_auth[0].severity == "high"

    # =========================================================================
    # Multiple Entry Tests
    # =========================================================================

    def test_parse_json_array(self, tmp_path: Path):
        """Test parsing JSON array of Shodan results."""
        data = [
            {"ip_str": "192.168.1.100", "port": 80},
            {"ip_str": "192.168.1.101", "port": 443}
        ]
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_jsonl_format(self, tmp_path: Path):
        """Test parsing JSON Lines (JSONL) format."""
        content = """{"ip_str": "192.168.1.100", "port": 80}
{"ip_str": "192.168.1.101", "port": 443}
"""
        json_file = tmp_path / "shodan.json"
        json_file.write_text(content)

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "shodan_empty.json"
        json_file.write_text("[]")

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_ip(self, tmp_path: Path):
        """Test handling of entry without IP."""
        data = {"port": 80, "hostnames": ["example.com"]}
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        # Should not crash, may not produce hosts
        assert isinstance(entities, list)

    def test_handles_no_port(self, tmp_path: Path):
        """Test handling of entry without port."""
        data = {"ip_str": "192.168.1.100"}
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        services = self.get_services(entities)
        assert len(services) == 0

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_shodan(self, tmp_path: Path):
        """Test that source is set to shodan."""
        data = {
            "ip_str": "192.168.1.100",
            "port": 80
        }
        json_file = tmp_path / "shodan.json"
        json_file.write_text(json.dumps(data))

        parser = ShodanParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "shodan"
