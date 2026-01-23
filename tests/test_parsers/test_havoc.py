"""Tests for Havoc C2 parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.havoc import HavocParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestHavocParser(BaseParserTest):
    """Test HavocParser functionality."""

    parser_class = HavocParser
    expected_name = "havoc"
    expected_patterns = ["*havoc*.json", "*havoc*.log", "*demon*.log", "*demon*.json"]
    expected_entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_havoc_json(self, tmp_path: Path):
        """Test detection of Havoc JSON file."""
        data = {
            "DemonID": "abc123",
            "Computer": "TARGET01",
            "Elevated": True
        }
        json_file = tmp_path / "havoc_export.json"
        json_file.write_text(json.dumps(data))

        assert HavocParser.can_parse(json_file)

    def test_can_parse_demon_log(self, tmp_path: Path):
        """Test detection of demon log file."""
        content = """[*] Demon registered from admin@TARGET01 (192.168.1.100)
[+] Agent connected
"""
        log_file = tmp_path / "demon.log"
        log_file.write_text(content)

        assert HavocParser.can_parse(log_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not HavocParser.can_parse(json_file)

    # =========================================================================
    # JSON Demon Entry Tests
    # =========================================================================

    def test_parse_json_demon_entry(self, tmp_path: Path):
        """Test parsing demon entry from JSON."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "Internal": "192.168.1.100",
            "User": "admin",
            "Domain": "CORP",
            "OS": "Windows 10",
            "Arch": "x64",
            "PID": 1234,
            "Process": "explorer.exe",
            "Elevated": True
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "TARGET01"
        assert hosts[0].ip == "192.168.1.100"
        assert "demon" in hosts[0].tags
        assert "compromised" in hosts[0].tags

    def test_parse_json_creates_user(self, tmp_path: Path):
        """Test that JSON parsing creates user entity."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "User": "jsmith",
            "Domain": "CORP",
            "Elevated": False
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "CORP"
        assert "compromised" in users[0].tags

    def test_parse_json_elevated_creates_critical_misconfig(self, tmp_path: Path):
        """Test that elevated demons create critical misconfiguration."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "Elevated": True
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        demon_misconfig = [m for m in misconfigs if "Demon" in m.title]
        assert len(demon_misconfig) >= 1
        assert demon_misconfig[0].severity == "critical"

    def test_parse_json_non_elevated_creates_high_misconfig(self, tmp_path: Path):
        """Test that non-elevated demons create high severity misconfiguration."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "Elevated": False
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        demon_misconfig = [m for m in misconfigs if "Demon" in m.title]
        assert len(demon_misconfig) >= 1
        assert demon_misconfig[0].severity == "high"

    def test_parse_json_with_credentials(self, tmp_path: Path):
        """Test parsing credentials from JSON."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "Credentials": [
                {"Username": "admin", "Domain": "CORP", "Hash": "aabbccdd11223344aabbccdd11223344"}
            ]
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "ntlm"
        assert "harvested" in creds[0].tags

    def test_parse_json_with_password(self, tmp_path: Path):
        """Test parsing password credentials from JSON."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "Credentials": [
                {"Username": "svc_account", "Password": "SecretPass123"}
            ]
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "password"

    def test_parse_json_multiple_demons(self, tmp_path: Path):
        """Test parsing multiple demon entries."""
        data = [
            {"DemonID": "d1", "Computer": "TARGET01", "Internal": "192.168.1.100"},
            {"DemonID": "d2", "Computer": "TARGET02", "Internal": "192.168.1.101"}
        ]
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    # =========================================================================
    # Log Parsing Tests
    # =========================================================================

    def test_parse_log_demon_registered(self, tmp_path: Path):
        """Test parsing demon registration from log."""
        # Content must not start with [ or { to avoid JSON detection
        content = """Havoc C2 Log
demon registered from admin@TARGET01 (192.168.1.100)
"""
        log_file = tmp_path / "havoc.log"
        log_file.write_text(content)

        parser = HavocParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "TARGET01"
        assert hosts[0].ip == "192.168.1.100"

    def test_parse_log_creates_user(self, tmp_path: Path):
        """Test that log parsing creates user from demon registration."""
        content = """Havoc C2 Log
demon registered from jsmith@WORKSTATION (192.168.1.50)
"""
        log_file = tmp_path / "havoc.log"
        log_file.write_text(content)

        parser = HavocParser()
        entities = list(parser.parse(log_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"

    def test_parse_log_mimikatz_output(self, tmp_path: Path):
        """Test parsing mimikatz output from log."""
        content = """Havoc C2 Log
== Mimikatz Output ==
Username : admin
Domain : CORP
NTLM : aabbccdd11223344aabbccdd11223344
"""
        log_file = tmp_path / "havoc.log"
        log_file.write_text(content)

        parser = HavocParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "ntlm"
        assert "mimikatz" in creds[0].tags

    def test_parse_log_credential_pattern(self, tmp_path: Path):
        """Test parsing credential pattern from log."""
        content = """Havoc C2 Log
Extracted: CORP\\jsmith:aabbccdd11223344aabbccdd11223344
"""
        log_file = tmp_path / "havoc.log"
        log_file.write_text(content)

        parser = HavocParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].username == "jsmith"
        assert creds[0].domain == "CORP"

    def test_parse_log_lateral_movement(self, tmp_path: Path):
        """Test parsing lateral movement from log."""
        content = """Havoc C2 Log
psexec to DC01.corp.local
jump to 192.168.1.10
"""
        log_file = tmp_path / "havoc.log"
        log_file.write_text(content)

        parser = HavocParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        lateral_hosts = [h for h in hosts if "lateral-target" in h.tags]
        assert len(lateral_hosts) >= 2

    # =========================================================================
    # Raw Properties Tests
    # =========================================================================

    def test_stores_raw_properties(self, tmp_path: Path):
        """Test that demon metadata is stored in raw_properties."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01",
            "PID": 4567,
            "Process": "notepad.exe",
            "Elevated": True
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].raw_properties.get("demon_id") == "demon123"
        assert hosts[0].raw_properties.get("pid") == 4567
        assert hosts[0].raw_properties.get("elevated") == True

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        data = [
            {"DemonID": "d1", "Computer": "TARGET01"},
            {"DemonID": "d2", "Computer": "TARGET01"}
        ]
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        target_hosts = [h for h in hosts if h.hostname == "TARGET01"]
        assert len(target_hosts) == 1

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        data = [
            {"DemonID": "d1", "Computer": "TARGET01", "User": "admin"},
            {"DemonID": "d2", "Computer": "TARGET02", "User": "admin"}
        ]
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "havoc_empty.json"
        json_file.write_text("")

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "havoc.json"
        json_file.write_text("{invalid json}")

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_skips_null_credentials(self, tmp_path: Path):
        """Test that null/empty credentials are skipped."""
        content = """Havoc C2 Log
Username : (null)
Domain : CORP
NTLM : (null)
"""
        log_file = tmp_path / "havoc.log"
        log_file.write_text(content)

        parser = HavocParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        assert len(creds) == 0

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_havoc(self, tmp_path: Path):
        """Test that source is set to havoc."""
        data = {
            "DemonID": "demon123",
            "Computer": "TARGET01"
        }
        json_file = tmp_path / "havoc.json"
        json_file.write_text(json.dumps(data))

        parser = HavocParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "havoc"
