"""Tests for SharpUp parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.sharpup import SharpUpParser
from ariadne.models.asset import Host
from ariadne.models.finding import Vulnerability, Misconfiguration
from .base import BaseParserTest


class TestSharpUpParser(BaseParserTest):
    """Test SharpUpParser functionality."""

    parser_class = SharpUpParser
    expected_name = "sharpup"
    expected_patterns = ["*sharpup*.txt", "*sharpup*.json", "*SharpUp*.txt", "*privesc*.txt"]
    expected_entity_types = ["Host", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_sharpup_txt(self, tmp_path: Path):
        """Test detection of SharpUp text output."""
        lines = [
            "=== SharpUp: Running Privilege Escalation Checks ===",
            "[*] Checking Modifiable Services...",
            "[+] Found Modifiable Service",
        ]
        txt_file = tmp_path / "sharpup_output.txt"
        txt_file.write_text("\n".join(lines))

        assert SharpUpParser.can_parse(txt_file)

    def test_can_parse_sharpup_json(self, tmp_path: Path):
        """Test detection of SharpUp JSON output."""
        data = [
            {"Type": "ModifiableService", "Service": "VulnSvc", "Path": "C:\\vuln.exe"}
        ]
        json_file = tmp_path / "sharpup.json"
        json_file.write_text(json.dumps(data))

        assert SharpUpParser.can_parse(json_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just random text.")

        assert not SharpUpParser.can_parse(txt_file)

    # =========================================================================
    # Text Parsing - Modifiable Service Tests
    # =========================================================================

    def test_parse_text_modifiable_service(self, tmp_path: Path):
        """Test parsing modifiable service findings."""
        content = "Modifiable Service: VulnService  Path: C:\\Program Files\\Vuln\\service.exe"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        modifiable = [v for v in vulns if "Modifiable Service" in v.title]
        assert len(modifiable) >= 1
        assert modifiable[0].severity == "high"
        assert "privesc" in modifiable[0].tags

    def test_parse_text_unquoted_service_path(self, tmp_path: Path):
        """Test parsing unquoted service path findings."""
        content = "Unquoted Service Path: BackupSvc  Path: C:\\Program Files\\Backup Service\\backup.exe"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        unquoted = [v for v in vulns if "Unquoted" in v.title]
        assert len(unquoted) >= 1
        assert unquoted[0].severity == "medium"
        assert "unquoted-path" in unquoted[0].tags

    def test_parse_text_modifiable_registry(self, tmp_path: Path):
        """Test parsing modifiable registry findings."""
        content = "Modifiable Service Registry: VulnSvc"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        registry = [v for v in vulns if "Registry" in v.title]
        assert len(registry) >= 1
        assert "privesc" in registry[0].tags

    # =========================================================================
    # Text Parsing - Misconfiguration Tests
    # =========================================================================

    def test_parse_text_always_install_elevated(self, tmp_path: Path):
        """Test parsing AlwaysInstallElevated setting."""
        # The parser checks for "AlwaysInstallElevated" in content
        content = "AlwaysInstallElevated is enabled in registry"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        aie = next((m for m in misconfigs if "AlwaysInstallElevated" in m.title), None)
        assert aie is not None
        assert aie.severity == "high"

    def test_parse_text_dangerous_privileges(self, tmp_path: Path):
        """Test parsing dangerous token privileges."""
        lines = [
            "SeImpersonatePrivilege is enabled",
            "SeDebugPrivilege is enabled",
        ]
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text("\n".join(lines))

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        priv_findings = [m for m in misconfigs if "Privilege" in m.title]
        assert len(priv_findings) >= 2

    def test_parse_text_scheduled_task(self, tmp_path: Path):
        """Test parsing modifiable scheduled task findings."""
        content = "Modifiable Scheduled Task: BackupTask  Path: C:\\scripts\\backup.bat"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        scheduled = [v for v in vulns if "Scheduled Task" in v.title]
        assert len(scheduled) >= 1
        assert "scheduled-task" in scheduled[0].tags

    def test_parse_text_writable_path(self, tmp_path: Path):
        """Test parsing writable PATH directory findings."""
        content = "Writable PATH Directory: C:\\Utils"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        path_hijack = [v for v in vulns if "PATH" in v.title]
        assert len(path_hijack) >= 1
        assert "path-hijack" in path_hijack[0].tags

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_modifiable_finding(self, tmp_path: Path):
        """Test parsing JSON modifiable finding."""
        data = [
            {
                "Type": "ModifiableService",
                "Service": "VulnSvc",
                "Path": "C:\\vuln.exe",
                "Description": "Service binary is modifiable"
            }
        ]
        json_file = tmp_path / "sharpup.json"
        json_file.write_text(json.dumps(data))

        parser = SharpUpParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert "privesc" in vulns[0].tags

    def test_parse_json_misc_finding(self, tmp_path: Path):
        """Test parsing JSON misconfiguration finding."""
        data = [
            {
                "Type": "AlwaysInstallElevated",
                "Description": "AlwaysInstallElevated is enabled"
            }
        ]
        json_file = tmp_path / "sharpup.json"
        json_file.write_text(json.dumps(data))

        parser = SharpUpParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1

    def test_parse_json_nested_findings(self, tmp_path: Path):
        """Test parsing JSON with nested findings."""
        data = {
            "ModifiableServices": [
                {"Service": "Svc1", "Path": "C:\\svc1.exe"},
                {"Service": "Svc2", "Path": "C:\\svc2.exe"},
            ]
        }
        json_file = tmp_path / "sharpup.json"
        json_file.write_text(json.dumps(data))

        parser = SharpUpParser()
        entities = list(parser.parse(json_file))

        # Should parse nested findings
        assert len(entities) >= 1

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_findings(self, tmp_path: Path):
        """Test that duplicate findings are not created."""
        lines = [
            "Modifiable Service: VulnSvc  Path: C:\\vuln.exe",
            "Modifiable Service: VulnSvc  Path: C:\\vuln.exe",
        ]
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text("\n".join(lines))

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        vuln_svc = [v for v in vulns if "VulnSvc" in v.title]
        assert len(vuln_svc) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "sharpup_empty.txt"
        txt_file.write_text("")

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "sharpup.json"
        json_file.write_text("{invalid json}")

        parser = SharpUpParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_skips_not_vulnerable(self, tmp_path: Path):
        """Test that 'not vulnerable' findings are skipped."""
        lines = [
            "[*] Not vulnerable to AlwaysInstallElevated",
            "[*] No issues found with services",
        ]
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text("\n".join(lines))

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        # Should not create findings for "not vulnerable"
        vulns = self.get_vulnerabilities(entities)
        misconfigs = self.get_misconfigurations(entities)
        assert len(vulns) == 0
        assert len(misconfigs) == 0

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_sharpup(self, tmp_path: Path):
        """Test that source is set to sharpup."""
        content = "Modifiable Service: VulnSvc  Path: C:\\vuln.exe"
        txt_file = tmp_path / "sharpup.txt"
        txt_file.write_text(content)

        parser = SharpUpParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "sharpup"
