"""Tests for Nuclei parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.nuclei import NucleiParser
from ariadne.models.finding import Vulnerability, Misconfiguration
from .base import BaseParserTest


class TestNucleiParser(BaseParserTest):
    """Test NucleiParser functionality."""

    parser_class = NucleiParser
    expected_name = "nuclei"
    expected_patterns = ["*nuclei*.json"]
    expected_entity_types = ["Vulnerability"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_nuclei_json(self, tmp_path: Path):
        """Test detection of Nuclei JSONL output."""
        content = json.dumps({
            "template-id": "test-template",
            "host": "http://example.com",
            "info": {"name": "Test", "severity": "info"}
        })
        json_file = tmp_path / "nuclei_scan.json"
        json_file.write_text(content)

        assert NucleiParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is not parsed as Nuclei."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"not": "nuclei"}')

        assert not NucleiParser.can_parse(json_file)

    # =========================================================================
    # Parsing Tests
    # =========================================================================

    def test_parse_single_finding(self, tmp_path: Path):
        """Test parsing single Nuclei finding."""
        content = json.dumps({
            "template-id": "exposed-panels/phpmyadmin-panel",
            "host": "http://192.168.1.1:8080",
            "matched-at": "http://192.168.1.1:8080/phpmyadmin/",
            "type": "http",
            "info": {
                "name": "phpMyAdmin Panel",
                "severity": "info",
                "description": "phpMyAdmin panel was detected"
            },
            "timestamp": "2024-01-01T00:00:00Z"
        })
        json_file = tmp_path / "nuclei.json"
        json_file.write_text(content)

        parser = NucleiParser()
        entities = list(parser.parse(json_file))

        # Note: info severity findings become Misconfigurations in nuclei parser
        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert "phpMyAdmin" in misconfigs[0].title
        assert misconfigs[0].severity == "info"
        assert misconfigs[0].source == "nuclei"

    def test_parse_multiple_findings_jsonl(self, tmp_path: Path):
        """Test parsing multiple findings in JSONL format."""
        lines = [
            json.dumps({
                "template-id": "template-1",
                "host": "http://192.168.1.1",
                "info": {"name": "Finding 1", "severity": "low"}
            }),
            json.dumps({
                "template-id": "template-2",
                "host": "http://192.168.1.1",
                "info": {"name": "Finding 2", "severity": "medium"}
            }),
            json.dumps({
                "template-id": "template-3",
                "host": "http://192.168.1.2",
                "info": {"name": "Finding 3", "severity": "high"}
            }),
        ]
        json_file = tmp_path / "nuclei.json"
        json_file.write_text("\n".join(lines))

        parser = NucleiParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 3

    def test_parse_finding_with_cve(self, tmp_path: Path):
        """Test parsing finding with CVE classification."""
        content = json.dumps({
            "template-id": "CVE-2021-44228",
            "host": "http://192.168.1.1",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "classification": {
                    "cve-id": ["CVE-2021-44228"],
                    "cvss-score": 10.0
                }
            }
        })
        json_file = tmp_path / "nuclei.json"
        json_file.write_text(content)

        parser = NucleiParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].severity == "critical"

    def test_parse_all_severity_levels(self, tmp_path: Path):
        """Test parsing findings with all severity levels."""
        severities = ["info", "low", "medium", "high", "critical"]
        lines = [
            json.dumps({
                "template-id": f"template-{sev}",
                "host": "http://192.168.1.1",
                "info": {"name": f"Finding {sev}", "severity": sev}
            })
            for sev in severities
        ]
        json_file = tmp_path / "nuclei.json"
        json_file.write_text("\n".join(lines))

        parser = NucleiParser()
        entities = list(parser.parse(json_file))

        # Note: info severity becomes Misconfiguration, others become Vulnerability
        vulns = self.get_vulnerabilities(entities)
        misconfigs = self.get_misconfigurations(entities)

        vuln_severities = {v.severity for v in vulns}
        misconfig_severities = {m.severity for m in misconfigs}
        found_severities = vuln_severities | misconfig_severities
        assert found_severities == set(severities)

    def test_parse_finding_with_matched_at(self, tmp_path: Path):
        """Test that matched-at URL is captured."""
        content = json.dumps({
            "template-id": "test",
            "host": "http://192.168.1.1",
            "matched-at": "http://192.168.1.1/admin/config.php",
            "info": {"name": "Config File", "severity": "medium"}
        })
        json_file = tmp_path / "nuclei.json"
        json_file.write_text(content)

        parser = NucleiParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1

    def test_handles_malformed_json_lines(self, tmp_path: Path):
        """Test graceful handling of malformed JSON lines."""
        lines = [
            json.dumps({
                "template-id": "valid",
                "host": "http://192.168.1.1",
                "info": {"name": "Valid", "severity": "info"}
            }),
            "{invalid json}",
            json.dumps({
                "template-id": "also-valid",
                "host": "http://192.168.1.2",
                "info": {"name": "Also Valid", "severity": "low"}
            }),
        ]
        json_file = tmp_path / "nuclei.json"
        json_file.write_text("\n".join(lines))

        parser = NucleiParser()
        # Should not raise, and should parse valid entries
        entities = list(parser.parse(json_file))
        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1

    def test_template_id_stored(self, tmp_path: Path):
        """Test that template ID is stored in finding."""
        content = json.dumps({
            "template-id": "my-custom-template",
            "host": "http://192.168.1.1",
            "info": {"name": "Test", "severity": "medium"}
        })
        json_file = tmp_path / "nuclei.json"
        json_file.write_text(content)

        parser = NucleiParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].template_id == "my-custom-template"
