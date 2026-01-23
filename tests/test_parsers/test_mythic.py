"""Tests for Mythic C2 parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.mythic import MythicParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestMythicParser(BaseParserTest):
    """Test MythicParser functionality."""

    parser_class = MythicParser
    expected_name = "mythic"
    expected_patterns = ["*mythic*.json", "*mythic*.log", "*callback*.json", "*apfell*.json"]
    expected_entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_mythic_json(self, tmp_path: Path):
        """Test detection of Mythic JSON file."""
        data = {
            "agent_callback_id": "cb123",
            "host": "TARGET01",
            "payload_type": "apollo"
        }
        json_file = tmp_path / "mythic_export.json"
        json_file.write_text(json.dumps(data))

        assert MythicParser.can_parse(json_file)

    def test_can_parse_callback_json(self, tmp_path: Path):
        """Test detection of callback JSON file."""
        data = {
            "callbacks": [{
                "id": "cb123",
                "host": "TARGET01",
                "integrity_level": "high"
            }]
        }
        json_file = tmp_path / "callback.json"
        json_file.write_text(json.dumps(data))

        assert MythicParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not MythicParser.can_parse(json_file)

    # =========================================================================
    # Callback Parsing Tests
    # =========================================================================

    def test_parse_callback_entry(self, tmp_path: Path):
        """Test parsing callback entry from JSON."""
        data = {
            "id": "cb123",
            "host": "TARGET01",
            "ip": "192.168.1.100",
            "user": "admin",
            "domain": "CORP",
            "os": "Windows 10",
            "architecture": "x64",
            "pid": 1234,
            "process_name": "explorer.exe",
            "integrity_level": "high",
            "payload_type": "apollo"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "TARGET01"
        assert hosts[0].ip == "192.168.1.100"
        assert "callback" in hosts[0].tags
        assert "compromised" in hosts[0].tags

    def test_parse_callback_creates_user(self, tmp_path: Path):
        """Test that callback parsing creates user entity."""
        data = {
            "id": "cb123",
            "host": "TARGET01",
            "user": "jsmith",
            "domain": "CORP",
            "integrity_level": "medium"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "CORP"
        assert "compromised" in users[0].tags

    def test_parse_callback_high_integrity_creates_critical(self, tmp_path: Path):
        """Test that high integrity callbacks create critical misconfiguration."""
        data = {
            "id": "cb123",
            "host": "TARGET01",
            "integrity_level": "high"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        callback_misconfig = [m for m in misconfigs if "Callback" in m.title]
        assert len(callback_misconfig) >= 1
        assert callback_misconfig[0].severity == "critical"

    def test_parse_callback_system_integrity_creates_critical(self, tmp_path: Path):
        """Test that SYSTEM integrity callbacks create critical misconfiguration."""
        data = {
            "id": "cb123",
            "host": "TARGET01",
            "integrity_level": "SYSTEM"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        callback_misconfig = [m for m in misconfigs if "Callback" in m.title]
        assert len(callback_misconfig) >= 1
        assert callback_misconfig[0].severity == "critical"

    def test_parse_callback_medium_integrity_creates_high(self, tmp_path: Path):
        """Test that medium integrity callbacks create high severity misconfiguration."""
        data = {
            "id": "cb123",
            "host": "TARGET01",
            "integrity_level": "medium"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        callback_misconfig = [m for m in misconfigs if "Callback" in m.title]
        assert len(callback_misconfig) >= 1
        assert callback_misconfig[0].severity == "high"

    def test_parse_callbacks_list(self, tmp_path: Path):
        """Test parsing callbacks list from JSON."""
        data = {
            "callbacks": [
                {"id": "cb1", "host": "TARGET01", "ip": "192.168.1.100"},
                {"id": "cb2", "host": "TARGET02", "ip": "192.168.1.101"}
            ]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    # =========================================================================
    # Task Parsing Tests
    # =========================================================================

    def test_parse_mimikatz_task(self, tmp_path: Path):
        """Test parsing mimikatz task output."""
        data = {
            "tasks": [{
                "command": "mimikatz",
                "status": "completed",
                "response": """Username : admin
Domain : CORP
NTLM : aabbccdd11223344aabbccdd11223344"""
            }]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "ntlm"
        assert "mimikatz" in creds[0].tags

    def test_parse_hashdump_task(self, tmp_path: Path):
        """Test parsing hashdump task output."""
        data = {
            "tasks": [{
                "command": "hashdump",
                "status": "completed",
                "response": """Administrator:500:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
localuser:1001:aad3b435b51404eeaad3b435b51404ee:11223344aabbccdd11223344aabbccdd:::"""
            }]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 2
        assert all(c.credential_type == "ntlm" for c in creds)
        assert all("hashdump" in c.tags for c in creds)

    def test_skips_empty_ntlm_hash(self, tmp_path: Path):
        """Test that empty NTLM hashes are skipped."""
        data = {
            "tasks": [{
                "command": "hashdump",
                "status": "completed",
                "response": """Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"""
            }]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        guest_creds = [c for c in creds if c.username == "Guest"]
        assert len(guest_creds) == 0

    def test_skips_incomplete_task(self, tmp_path: Path):
        """Test that incomplete tasks are skipped."""
        data = {
            "tasks": [{
                "command": "mimikatz",
                "status": "pending",
                "response": "Username : admin\nNTLM : aabbccdd..."
            }]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) == 0

    # =========================================================================
    # Raw Properties Tests
    # =========================================================================

    def test_stores_raw_properties(self, tmp_path: Path):
        """Test that callback metadata is stored in raw_properties."""
        data = {
            "id": "cb123",
            "host": "TARGET01",
            "pid": 4567,
            "process_name": "notepad.exe",
            "integrity_level": "high",
            "payload_type": "apollo"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].raw_properties.get("callback_id") == "cb123"
        assert hosts[0].raw_properties.get("pid") == 4567
        assert hosts[0].raw_properties.get("payload_type") == "apollo"

    # =========================================================================
    # Log Parsing Tests
    # =========================================================================

    def test_parse_log_callback(self, tmp_path: Path):
        """Test parsing callback from log file."""
        # Content must not start with [ or { to avoid JSON detection
        content = """Mythic C2 Log
callback registered host: TARGET01, ip: 192.168.1.100
"""
        log_file = tmp_path / "mythic.log"
        log_file.write_text(content)

        parser = MythicParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        data = {
            "callbacks": [
                {"id": "cb1", "host": "TARGET01"},
                {"id": "cb2", "host": "TARGET01"}
            ]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        target_hosts = [h for h in hosts if h.hostname == "TARGET01"]
        assert len(target_hosts) == 1

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        data = {
            "callbacks": [
                {"id": "cb1", "host": "TARGET01", "user": "admin"},
                {"id": "cb2", "host": "TARGET02", "user": "admin"}
            ]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "mythic_empty.json"
        json_file.write_text("")

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "mythic.json"
        json_file.write_text("{invalid json}")

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_skips_null_credentials(self, tmp_path: Path):
        """Test that null/empty credentials are skipped in task output."""
        data = {
            "tasks": [{
                "command": "mimikatz",
                "status": "completed",
                "response": """Username : (null)
Domain : CORP
NTLM : (null)"""
            }]
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) == 0

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_mythic(self, tmp_path: Path):
        """Test that source is set to mythic."""
        data = {
            "id": "cb123",
            "host": "TARGET01"
        }
        json_file = tmp_path / "mythic.json"
        json_file.write_text(json.dumps(data))

        parser = MythicParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "mythic"
