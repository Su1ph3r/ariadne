"""Tests for TestSSL parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.testssl import TestSSLParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestTestSSLParser(BaseParserTest):
    """Test TestSSLParser functionality."""

    parser_class = TestSSLParser
    expected_name = "testssl"
    expected_patterns = ["*testssl*.json", "*ssl_scan*.json", "*tls_scan*.json"]
    expected_entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_testssl_json(self, tmp_path: Path):
        """Test detection of TestSSL JSON file."""
        # Use lowercase indicator that parser's can_parse will match
        # (parser does header.lower() so mixed-case scanResult won't match)
        data = [{
            "targethost": "192.168.1.100",
            "id": "heartbleed",
            "severity": "OK",
            "finding": "not vulnerable"
        }]
        json_file = tmp_path / "testssl_output.json"
        json_file.write_text(json.dumps(data))

        assert TestSSLParser.can_parse(json_file)

    def test_can_parse_by_vuln_indicators(self, tmp_path: Path):
        """Test detection by vulnerability indicators."""
        data = [{
            "targetHost": "192.168.1.100",
            "id": "heartbleed",
            "severity": "CRITICAL",
            "finding": "VULNERABLE"
        }]
        json_file = tmp_path / "results.json"
        json_file.write_text(json.dumps(data))

        assert TestSSLParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not TestSSLParser.can_parse(json_file)

    # =========================================================================
    # Host and Service Parsing Tests
    # =========================================================================

    def test_parse_host_and_service(self, tmp_path: Path):
        """Test parsing host and service from scan result."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 443
        assert services[0].ssl == True

    def test_parse_hostname_target(self, tmp_path: Path):
        """Test parsing with hostname instead of IP."""
        data = {
            "scanResult": [{
                "targetHost": "www.example.com",
                "port": 443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "www.example.com"
        assert hosts[0].ip == ""  # Not an IP

    def test_creates_runs_on_relationship(self, tmp_path: Path):
        """Test that RUNS_ON relationship is created."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    # =========================================================================
    # Critical Vulnerability Tests
    # =========================================================================

    def test_parse_heartbleed(self, tmp_path: Path):
        """Test parsing Heartbleed vulnerability."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "heartbleed",
            "severity": "CRITICAL",
            "finding": "VULNERABLE (CVE-2014-0160)"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        heartbleed = [v for v in vulns if "heartbleed" in v.title.lower()]
        assert len(heartbleed) >= 1
        assert heartbleed[0].severity == "critical"

    def test_parse_robot_vulnerability(self, tmp_path: Path):
        """Test parsing ROBOT vulnerability."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "robot",
            "severity": "CRITICAL",
            "finding": "Server is vulnerable to ROBOT attack"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        robot = [v for v in vulns if "robot" in v.title.lower()]
        assert len(robot) >= 1
        assert robot[0].severity == "critical"

    def test_skips_not_vulnerable(self, tmp_path: Path):
        """Test that 'not vulnerable' findings are skipped."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "heartbleed",
            "severity": "OK",
            "finding": "not vulnerable"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        heartbleed = [v for v in vulns if "heartbleed" in v.title.lower()]
        assert len(heartbleed) == 0

    # =========================================================================
    # High Severity Vulnerability Tests
    # =========================================================================

    def test_parse_poodle(self, tmp_path: Path):
        """Test parsing POODLE vulnerability."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "poodle_ssl",
            "severity": "HIGH",
            "finding": "VULNERABLE, uses SSLv3"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        poodle = [v for v in vulns if "poodle" in v.title.lower()]
        assert len(poodle) >= 1
        assert poodle[0].severity == "high"

    def test_parse_sweet32(self, tmp_path: Path):
        """Test parsing SWEET32 vulnerability."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "sweet32",
            "severity": "HIGH",
            "finding": "VULNERABLE, uses 3DES"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        sweet32 = [v for v in vulns if "sweet32" in v.title.lower()]
        assert len(sweet32) >= 1
        assert sweet32[0].severity == "high"

    # =========================================================================
    # Weak Protocol Tests
    # =========================================================================

    def test_parse_sslv3_enabled(self, tmp_path: Path):
        """Test parsing SSLv3 enabled."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "ssl3",
            "severity": "HIGH",
            "finding": "offered"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        ssl3 = [m for m in misconfigs if "ssl3" in m.title.lower() or "SSL3" in m.title]
        assert len(ssl3) >= 1
        assert ssl3[0].severity == "high"

    def test_parse_tls10_enabled(self, tmp_path: Path):
        """Test parsing TLS 1.0 enabled."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "tls1",
            "severity": "MEDIUM",
            "finding": "offered"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        tls1 = [m for m in misconfigs if "tls1" in m.title.lower() or "TLS1" in m.title]
        assert len(tls1) >= 1

    def test_parse_protocol_from_structured_data(self, tmp_path: Path):
        """Test parsing protocols from structured result format."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 443,
                "protocols": {
                    "ssl3": {"finding": "offered"},
                    "tls1_2": {"finding": "offered"}
                },
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        weak_proto = [m for m in misconfigs if "Weak protocol" in m.title]
        assert len(weak_proto) >= 1

    # =========================================================================
    # Weak Cipher Tests
    # =========================================================================

    def test_parse_rc4_cipher(self, tmp_path: Path):
        """Test parsing RC4 cipher detection."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "rc4",
            "severity": "MEDIUM",
            "finding": "offered"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        rc4 = [m for m in misconfigs if "rc4" in m.title.lower()]
        assert len(rc4) >= 1

    def test_parse_null_cipher(self, tmp_path: Path):
        """Test parsing NULL cipher detection."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "null_ciphers",
            "severity": "HIGH",
            "finding": "offered"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        null_cipher = [m for m in misconfigs if "null" in m.title.lower()]
        assert len(null_cipher) >= 1

    # =========================================================================
    # Certificate Tests
    # =========================================================================

    def test_parse_expired_cert(self, tmp_path: Path):
        """Test parsing expired certificate."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "cert_expiration",
            "severity": "MEDIUM",
            "finding": "certificate expired"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        expired = [m for m in misconfigs if "expired" in m.title.lower() or "expired" in m.description.lower()]
        assert len(expired) >= 1

    def test_parse_self_signed_cert(self, tmp_path: Path):
        """Test parsing self-signed certificate."""
        data = [{
            "targetHost": "192.168.1.100",
            "port": 443,
            "id": "cert_chain",
            "severity": "MEDIUM",
            "finding": "self-signed certificate"
        }]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        self_signed = [m for m in misconfigs if "self-signed" in m.title.lower() or "self-signed" in m.description.lower()]
        assert len(self_signed) >= 1

    # =========================================================================
    # Structured Vulnerability Tests
    # =========================================================================

    def test_parse_vulnerabilities_dict(self, tmp_path: Path):
        """Test parsing vulnerabilities from structured dict format."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 443,
                "vulnerabilities": {
                    "heartbleed": {"vulnerable": True, "finding": "Server is vulnerable"},
                    "poodle_ssl": {"vulnerable": False, "finding": "Not vulnerable"}
                },
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        heartbleed = [v for v in vulns if "heartbleed" in v.title.lower()]
        assert len(heartbleed) >= 1
        # POODLE should be skipped since vulnerable=False
        poodle = [v for v in vulns if "poodle" in v.title.lower()]
        assert len(poodle) == 0

    # =========================================================================
    # Multiple Targets Tests
    # =========================================================================

    def test_parse_multiple_targets(self, tmp_path: Path):
        """Test parsing multiple scan targets."""
        data = {
            "scanResult": [
                {"targetHost": "192.168.1.100", "port": 443, "findings": []},
                {"targetHost": "192.168.1.101", "port": 443, "findings": []}
            ]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2
        ips = [h.ip for h in hosts]
        assert "192.168.1.100" in ips
        assert "192.168.1.101" in ips

    def test_parse_findings_list_format(self, tmp_path: Path):
        """Test parsing findings list format."""
        data = [
            {"targetHost": "192.168.1.100", "port": 443, "id": "ssl3", "finding": "offered"},
            {"targetHost": "192.168.1.100", "port": 443, "id": "heartbleed", "finding": "VULNERABLE"}
        ]
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        # Should deduplicate to single host
        assert len(hosts) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_findings(self, tmp_path: Path):
        """Test handling of empty findings."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        # Should still create host and service
        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    def test_handles_missing_target(self, tmp_path: Path):
        """Test handling of missing target host."""
        data = {
            "scanResult": [{
                "port": 443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_handles_non_standard_port(self, tmp_path: Path):
        """Test handling of non-standard SSL port."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 8443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 8443
        assert services[0].name == "ssl"  # Not https since port != 443

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_testssl(self, tmp_path: Path):
        """Test that source is set to testssl."""
        data = {
            "scanResult": [{
                "targetHost": "192.168.1.100",
                "port": 443,
                "findings": []
            }]
        }
        json_file = tmp_path / "testssl.json"
        json_file.write_text(json.dumps(data))

        parser = TestSSLParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "testssl"
