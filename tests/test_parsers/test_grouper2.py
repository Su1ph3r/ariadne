"""Tests for Grouper2 parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.grouper2 import Grouper2Parser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Vulnerability, Misconfiguration, Credential
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestGrouper2Parser(BaseParserTest):
    """Test Grouper2Parser functionality."""

    parser_class = Grouper2Parser
    expected_name = "grouper2"
    expected_patterns = ["*grouper2*.json", "*grouper2*.html", "*grouper*.json", "*gpo_audit*.json"]
    expected_entity_types = ["Host", "User", "Vulnerability", "Misconfiguration", "Credential"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_grouper2_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        data = {"GPOName": "Test GPO", "FindingType": "Script"}
        json_file = tmp_path / "grouper2_output.json"
        json_file.write_text(json.dumps(data))

        assert Grouper2Parser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        data = {
            "GpoName": "Default Domain Policy",
            "FindingType": "Scheduled Task",
            "FindingDetail": "Found scheduled task with interesting permissions"
        }
        json_file = tmp_path / "output.json"
        json_file.write_text(json.dumps(data))

        assert Grouper2Parser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not Grouper2Parser.can_parse(json_file)

    # =========================================================================
    # GPP Password Parsing Tests
    # =========================================================================

    def test_parse_gpp_cpassword(self, tmp_path: Path):
        """Test parsing GPP cpassword finding."""
        data = {
            "GPOName": "Vulnerable GPO",
            "FindingType": "cpassword",
            "FindingDetail": "Found GPP password",
            "cpassword": "encrypted_password_here",
            "username": "admin"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].severity == "critical"
        assert "gpp" in creds[0].tags

    def test_parse_gpp_decrypted_password(self, tmp_path: Path):
        """Test parsing GPP with decrypted password."""
        data = {
            "GPOName": "Vulnerable GPO",
            "FindingType": "Group Policy Preferences",
            "FindingDetail": "Found credential in GPP",
            "password": "PlaintextPassword123",
            "username": "svc_account"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "password"
        assert creds[0].username == "svc_account"

    def test_parse_credential_exposure(self, tmp_path: Path):
        """Test parsing credential exposure finding without actual password."""
        data = {
            "GPOName": "Test GPO",
            "FindingType": "Credential",
            "FindingDetail": "Credential may be exposed"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        cred_misconfig = [m for m in misconfigs if "Credential" in m.title]
        assert len(cred_misconfig) >= 1

    # =========================================================================
    # Script/Task Finding Tests
    # =========================================================================

    def test_parse_scheduled_task(self, tmp_path: Path):
        """Test parsing scheduled task finding."""
        data = {
            "GPOName": "Task GPO",
            "FindingType": "Scheduled Task",
            "FindingDetail": "Found scheduled task that runs as SYSTEM",
            "Severity": "red"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        script_misconfig = [m for m in misconfigs if "Script/Task" in m.title]
        assert len(script_misconfig) >= 1

    def test_parse_immediate_task(self, tmp_path: Path):
        """Test parsing immediate task finding."""
        data = {
            "GPOName": "Immediate Task GPO",
            "FindingType": "Immediate Task",
            "FindingDetail": "Immediate task runs with elevated privileges"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        task_misconfig = [m for m in misconfigs if "Script/Task" in m.title]
        assert len(task_misconfig) >= 1

    # =========================================================================
    # Privilege Assignment Tests
    # =========================================================================

    def test_parse_privilege_assignment(self, tmp_path: Path):
        """Test parsing privilege assignment finding."""
        data = {
            "GPOName": "Priv GPO",
            "FindingType": "User Right Assignment",
            "FindingDetail": "SeDebugPrivilege granted to Domain Users",
            "Setting": "SeDebugPrivilege",
            "Value": "Domain Users"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        priv_misconfig = [m for m in misconfigs if "Privilege" in m.title]
        assert len(priv_misconfig) >= 1

    # =========================================================================
    # Registry Setting Tests
    # =========================================================================

    def test_parse_registry_setting(self, tmp_path: Path):
        """Test parsing registry setting finding."""
        data = {
            "GPOName": "Registry GPO",
            "FindingType": "Registry Value",
            "FindingDetail": "Interesting registry modification",
            "Setting": "HKLM\\Software\\Test",
            "Value": "SomeValue"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        reg_misconfig = [m for m in misconfigs if "Registry" in m.title]
        assert len(reg_misconfig) >= 1

    # =========================================================================
    # Severity Mapping Tests
    # =========================================================================

    def test_severity_from_color(self, tmp_path: Path):
        """Test severity mapping from color."""
        data = [
            {"GPOName": "GPO1", "FindingType": "Test", "Severity": "black"},
            {"GPOName": "GPO2", "FindingType": "Test", "Severity": "red"},
            {"GPOName": "GPO3", "FindingType": "Test", "Severity": "yellow"},
            {"GPOName": "GPO4", "FindingType": "Test", "Severity": "green"}
        ]
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        severities = {m.title.split(": ")[1]: m.severity for m in misconfigs if "GPO Finding" in m.title}
        assert severities.get("GPO1") == "critical"
        assert severities.get("GPO2") == "high"
        assert severities.get("GPO3") == "medium"
        assert severities.get("GPO4") == "low"

    def test_severity_from_interest(self, tmp_path: Path):
        """Test severity mapping from interest level."""
        data = {
            "GPOName": "Test GPO",
            "FindingType": "Test",
            "Interest": "1"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert misconfigs[0].severity == "critical"

    # =========================================================================
    # Format Variations Tests
    # =========================================================================

    def test_parse_array_format(self, tmp_path: Path):
        """Test parsing array of findings."""
        data = [
            {"GPOName": "GPO1", "FindingType": "Test1"},
            {"GPOName": "GPO2", "FindingType": "Test2"}
        ]
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 2

    def test_parse_findings_wrapper(self, tmp_path: Path):
        """Test parsing findings inside wrapper."""
        data = {
            "findings": [
                {"GPOName": "GPO1", "FindingType": "Test"}
            ]
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1

    def test_parse_gpo_name_as_key(self, tmp_path: Path):
        """Test parsing with GPO name as dictionary key."""
        data = {
            "Default Domain Policy": {
                "FindingType": "Password Policy",
                "FindingDetail": "Weak password policy"
            },
            "Test GPO": [
                {"FindingType": "Script", "FindingDetail": "Script found"}
            ]
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 2

    # =========================================================================
    # Vulnerability Detection Tests
    # =========================================================================

    def test_parse_vulnerability_finding(self, tmp_path: Path):
        """Test parsing vulnerability finding."""
        data = {
            "GPOName": "Vulnerable GPO",
            "FindingType": "Security Issue",
            "FindingDetail": "This is an interesting vulnerability that can be abused"
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_json(self, tmp_path: Path):
        """Test handling of empty JSON."""
        json_file = tmp_path / "grouper2.json"
        json_file.write_text("[]")

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_gpo_name(self, tmp_path: Path):
        """Test handling of finding without GPO name but with proper structure."""
        # Use wrapper format with a finding missing GPOName
        data = {
            "findings": [
                {"FindingType": "Test", "FindingDetail": "Test detail without GPO name"}
            ]
        }
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        # Should use "Unknown GPO" as default and produce output
        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_grouper2(self, tmp_path: Path):
        """Test that source is set to grouper2."""
        data = {"GPOName": "Test GPO", "FindingType": "Test"}
        json_file = tmp_path / "grouper2.json"
        json_file.write_text(json.dumps(data))

        parser = Grouper2Parser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "grouper2"
