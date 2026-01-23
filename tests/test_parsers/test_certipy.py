"""Tests for Certipy parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.certipy import CertipyParser
from ariadne.models.asset import Host
from ariadne.models.finding import Vulnerability, Misconfiguration
from .base import BaseParserTest


class TestCertipyParser(BaseParserTest):
    """Test CertipyParser functionality."""

    parser_class = CertipyParser
    expected_name = "certipy"
    expected_patterns = ["*certipy*.json", "*adcs*.json", "*bloodhound_certipy*.json"]
    expected_entity_types = ["Host", "User", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_certipy_json(self, tmp_path: Path):
        """Test detection of Certipy JSON output."""
        data = {
            "Certificate Authorities": {
                "CORP-CA": {
                    "DNS Name": "ca.corp.local"
                }
            }
        }
        json_file = tmp_path / "certipy_output.json"
        json_file.write_text(json.dumps(data))

        assert CertipyParser.can_parse(json_file)

    def test_can_parse_adcs_json(self, tmp_path: Path):
        """Test detection of ADCS JSON with templates."""
        data = {
            "Certificate Templates": {
                "User": {
                    "Vulnerabilities": ["ESC1"]
                }
            }
        }
        json_file = tmp_path / "adcs_scan.json"
        json_file.write_text(json.dumps(data))

        assert CertipyParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is not parsed as Certipy."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not CertipyParser.can_parse(json_file)

    def test_cannot_parse_txt_file(self, tmp_path: Path):
        """Test that text files are rejected."""
        txt_file = tmp_path / "certipy.txt"
        txt_file.write_text("Certipy output")

        assert not CertipyParser.can_parse(txt_file)

    # =========================================================================
    # Certificate Authority Parsing Tests
    # =========================================================================

    def test_parse_certificate_authority(self, tmp_path: Path):
        """Test parsing Certificate Authority information."""
        data = {
            "Certificate Authorities": {
                "CORP-CA": {
                    "DNS Name": "ca.corp.local",
                    "Certificate Subject": "CN=CORP-CA"
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "ca.corp.local"
        assert "certificate-authority" in hosts[0].tags
        assert hosts[0].source == "certipy"

    def test_parse_ca_with_esc6(self, tmp_path: Path):
        """Test detection of ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)."""
        data = {
            "Certificate Authorities": {
                "CORP-CA": {
                    "DNS Name": "ca.corp.local",
                    "User Specified SAN": "Enabled"
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        esc6 = next((m for m in misconfigs if "ESC6" in m.description), None)
        assert esc6 is not None
        assert esc6.severity == "high"
        assert esc6.check_id == "ESC6"

    def test_parse_ca_with_web_enrollment(self, tmp_path: Path):
        """Test detection of ESC8 (Web Enrollment)."""
        data = {
            "Certificate Authorities": {
                "CORP-CA": {
                    "DNS Name": "ca.corp.local",
                    "Web Enrollment": "Enabled"
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        esc8 = next((m for m in misconfigs if "ESC8" in m.description), None)
        assert esc8 is not None
        assert esc8.check_id == "ESC8"

    # =========================================================================
    # Certificate Template Parsing Tests
    # =========================================================================

    def test_parse_template_with_esc1(self, tmp_path: Path):
        """Test parsing template vulnerable to ESC1."""
        data = {
            "Certificate Templates": {
                "VulnerableTemplate": {
                    "Vulnerabilities": ["ESC1"],
                    "Enrollment Rights": ["Domain Users"]
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        esc1_vuln = next((v for v in vulns if "ESC1" in v.title), None)
        assert esc1_vuln is not None
        assert esc1_vuln.severity == "critical"
        assert "VulnerableTemplate" in esc1_vuln.title

    def test_parse_template_with_multiple_vulns(self, tmp_path: Path):
        """Test parsing template with multiple vulnerabilities."""
        data = {
            "Certificate Templates": {
                "BadTemplate": {
                    "Vulnerabilities": ["ESC1", "ESC2", "ESC3"]
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 3

    def test_parse_template_with_weak_enrollment(self, tmp_path: Path):
        """Test detection of weak enrollment rights."""
        data = {
            "Certificate Templates": {
                "WeakTemplate": {
                    "Enrollment Rights": ["Domain Users", "Authenticated Users"]
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        enrollment_issues = [m for m in misconfigs if "enrollment" in m.title.lower()]
        assert len(enrollment_issues) >= 2

    # =========================================================================
    # ESC Severity Tests
    # =========================================================================

    def test_esc_severity_mapping(self, tmp_path: Path):
        """Test that ESC vulnerabilities have correct severity."""
        # ESC1, ESC3, ESC6, ESC8 should be critical
        critical_escs = ["ESC1", "ESC3", "ESC6", "ESC8"]
        # Other ESCs should be high
        high_escs = ["ESC2", "ESC4", "ESC5", "ESC7", "ESC9", "ESC10"]

        for esc in critical_escs:
            data = {
                "Certificate Templates": {
                    "TestTemplate": {"Vulnerabilities": [esc]}
                }
            }
            json_file = tmp_path / f"certipy_{esc}.json"
            json_file.write_text(json.dumps(data))

            parser = CertipyParser()
            entities = list(parser.parse(json_file))

            vulns = self.get_vulnerabilities(entities)
            assert len(vulns) >= 1
            assert vulns[0].severity == "critical", f"{esc} should be critical"

        for esc in high_escs:
            data = {
                "Certificate Templates": {
                    "TestTemplate": {"Vulnerabilities": [esc]}
                }
            }
            json_file = tmp_path / f"certipy_{esc}.json"
            json_file.write_text(json.dumps(data))

            parser = CertipyParser()
            entities = list(parser.parse(json_file))

            vulns = self.get_vulnerabilities(entities)
            assert len(vulns) >= 1
            assert vulns[0].severity == "high", f"{esc} should be high"

    # =========================================================================
    # Enrollment Services Tests
    # =========================================================================

    def test_parse_enrollment_services(self, tmp_path: Path):
        """Test parsing enrollment service information."""
        data = {
            "Enrollment Services": {
                "CORP-CA": {
                    "DNS Name": "ca.corp.local"
                },
                "CORP-CA2": {
                    "DNS Name": "ca2.corp.local"
                }
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2
        hostnames = {h.hostname for h in hosts}
        assert "ca.corp.local" in hostnames
        assert "ca2.corp.local" in hostnames

    # =========================================================================
    # Explicit Vulnerabilities Tests
    # =========================================================================

    def test_parse_explicit_vulnerabilities(self, tmp_path: Path):
        """Test parsing explicit vulnerability findings."""
        data = {
            "Vulnerabilities": [
                {
                    "Vulnerability": "ESC1",
                    "Template": "User",
                    "CA": "CORP-CA"
                }
            ]
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert "ESC1" in vulns[0].title
        assert "User" in vulns[0].title

    def test_parse_lowercase_vulnerabilities(self, tmp_path: Path):
        """Test parsing vulnerabilities with lowercase keys."""
        data = {
            "vulnerabilities": [
                {
                    "type": "ESC1",
                    "template": "BadTemplate",
                    "ca": "CORP-CA"
                }
            ]
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_certipy(self, tmp_path: Path):
        """Test that source is set to certipy."""
        data = {
            "Certificate Authorities": {
                "CORP-CA": {"DNS Name": "ca.corp.local"}
            }
        }
        json_file = tmp_path / "certipy.json"
        json_file.write_text(json.dumps(data))

        parser = CertipyParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "certipy"
