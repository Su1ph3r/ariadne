"""Tests for Watson parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.watson import WatsonParser
from ariadne.models.asset import Host
from ariadne.models.finding import Vulnerability
from .base import BaseParserTest


class TestWatsonParser(BaseParserTest):
    """Test WatsonParser functionality."""

    parser_class = WatsonParser
    expected_name = "watson"
    expected_patterns = ["*watson*.txt", "*watson*.json", "*Watson*.txt"]
    expected_entity_types = ["Host", "Vulnerability"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_watson_txt(self, tmp_path: Path):
        """Test detection of Watson text output."""
        lines = [
            "[*] OS: Microsoft Windows 10 Pro",
            "[*] Build: 19041",
            "[*] CVE-2021-1675: PrintNightmare",
        ]
        txt_file = tmp_path / "watson_output.txt"
        txt_file.write_text("\n".join(lines))

        assert WatsonParser.can_parse(txt_file)

    def test_can_parse_watson_json(self, tmp_path: Path):
        """Test detection of Watson JSON output."""
        data = {
            "OS": "Microsoft Windows 10",
            "Build": "19041",
            "Vulnerabilities": [
                {"CVE": "CVE-2021-1675", "Description": "PrintNightmare"}
            ]
        }
        json_file = tmp_path / "watson.json"
        json_file.write_text(json.dumps(data))

        assert WatsonParser.can_parse(json_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just random text.")

        assert not WatsonParser.can_parse(txt_file)

    # =========================================================================
    # Text Parsing Tests
    # =========================================================================

    def test_parse_text_os_info(self, tmp_path: Path):
        """Test parsing OS information."""
        lines = [
            "OS: Microsoft Windows 10 Pro",
            "Build: 19041",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "Windows 10" in hosts[0].os
        assert "19041" in hosts[0].os

    def test_parse_text_cve_vulnerabilities(self, tmp_path: Path):
        """Test parsing CVE vulnerabilities."""
        # Note: content must not start with "[" to avoid JSON detection
        lines = [
            "Watson v1.0 Results",
            "[*] CVE-2021-1675: PrintNightmare - Windows Print Spooler RCE",
            "[+] CVE-2020-1472: Zerologon - Netlogon Elevation of Privilege",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 2

        printnightmare = next((v for v in vulns if "CVE-2021-1675" in v.title), None)
        assert printnightmare is not None
        assert printnightmare.severity == "critical"
        assert "privesc" in printnightmare.tags

    def test_parse_text_ms_bulletins(self, tmp_path: Path):
        """Test parsing MS bulletin vulnerabilities."""
        lines = [
            "Watson Results",
            "[*] MS17-010: EternalBlue - SMBv1 Remote Code Execution",
            "[+] MS16-032: Secondary Logon Handle Elevation of Privilege",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 2

        eternalblue = next((v for v in vulns if "MS17-010" in v.title), None)
        assert eternalblue is not None
        assert eternalblue.severity == "critical"

    def test_parse_text_kb_patches(self, tmp_path: Path):
        """Test parsing missing KB patches."""
        lines = [
            "Missing: KB4571756",
            "Not Installed: KB5003173",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 2
        assert all("missing-patch" in v.tags for v in vulns)

    def test_parse_text_exploit_url(self, tmp_path: Path):
        """Test parsing exploit URLs."""
        lines = [
            "Watson Results",
            "[*] CVE-2020-0787: BITS Elevation of Privilege",
            "Exploit: https://github.com/example/poc",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        bits_vuln = next((v for v in vulns if "CVE-2020-0787" in v.title), None)
        assert bits_vuln is not None
        if bits_vuln.raw_data:
            assert "exploit_url" in bits_vuln.raw_data

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_os_info(self, tmp_path: Path):
        """Test parsing JSON OS information."""
        data = {
            "OS": "Microsoft Windows Server 2019",
            "Build": "17763",
            "Hostname": "DC01"
        }
        json_file = tmp_path / "watson.json"
        json_file.write_text(json.dumps(data))

        parser = WatsonParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "DC01"
        assert "Windows Server 2019" in hosts[0].os

    def test_parse_json_vulnerabilities(self, tmp_path: Path):
        """Test parsing JSON vulnerabilities."""
        data = {
            "OS": "Microsoft Windows 10",
            "Vulnerabilities": [
                {"CVE": "CVE-2021-1675", "Description": "PrintNightmare"},
                {"CVE": "CVE-2020-1472", "Description": "Zerologon"},
            ]
        }
        json_file = tmp_path / "watson.json"
        json_file.write_text(json.dumps(data))

        parser = WatsonParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 2

    def test_parse_json_with_kb(self, tmp_path: Path):
        """Test parsing JSON with KB information."""
        data = {
            "Vulnerabilities": [
                {"CVE": "CVE-2021-1675", "Description": "PrintNightmare", "KB": "KB5003173"}
            ]
        }
        json_file = tmp_path / "watson.json"
        json_file.write_text(json.dumps(data))

        parser = WatsonParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert "KB5003173" in vulns[0].description

    # =========================================================================
    # Known CVE Severity Tests
    # =========================================================================

    def test_known_cves_get_correct_severity(self, tmp_path: Path):
        """Test that known CVEs get correct severity."""
        lines = [
            "Watson Results",
            "[*] CVE-2020-0796: SMBGhost",  # Critical
            "[*] CVE-2019-0836: Kernel Elevation",  # High
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)

        smbghost = next((v for v in vulns if "CVE-2020-0796" in v.title), None)
        assert smbghost is not None
        assert smbghost.severity == "critical"

        kernel = next((v for v in vulns if "CVE-2019-0836" in v.title), None)
        assert kernel is not None
        assert kernel.severity == "high"

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_vulnerabilities(self, tmp_path: Path):
        """Test that duplicate vulnerabilities are not created."""
        lines = [
            "Watson Results",
            "[*] CVE-2021-1675: PrintNightmare",
            "[+] CVE-2021-1675: PrintNightmare (duplicate)",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        printnightmare = [v for v in vulns if "CVE-2021-1675" in v.title]
        assert len(printnightmare) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "watson_empty.txt"
        txt_file.write_text("")

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "watson.json"
        json_file.write_text("{invalid json}")

        parser = WatsonParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_unknown_cve_gets_high_severity(self, tmp_path: Path):
        """Test that unknown CVEs get high severity by default."""
        lines = [
            "Watson Results",
            "[*] CVE-2099-9999: Unknown Future Vulnerability",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].severity == "high"

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_watson(self, tmp_path: Path):
        """Test that source is set to watson."""
        lines = [
            "Watson Results",
            "[*] CVE-2021-1675: PrintNightmare",
        ]
        txt_file = tmp_path / "watson.txt"
        txt_file.write_text("\n".join(lines))

        parser = WatsonParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "watson"
