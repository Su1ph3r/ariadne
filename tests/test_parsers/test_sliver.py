"""Tests for Sliver C2 parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.sliver import SliverParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestSliverParser(BaseParserTest):
    """Test SliverParser functionality."""

    parser_class = SliverParser
    expected_name = "sliver"
    expected_patterns = ["*sliver*.json", "*sliver*.log", "*implant*.json", "*beacon*.json"]
    expected_entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_sliver_json(self, tmp_path: Path):
        """Test detection of Sliver JSON output."""
        data = {
            "ID": "abc123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Username": "CORP\\admin"
        }
        json_file = tmp_path / "sliver_sessions.json"
        json_file.write_text(json.dumps(data))

        assert SliverParser.can_parse(json_file)

    def test_can_parse_sliver_log(self, tmp_path: Path):
        """Test detection of Sliver log file."""
        content = """[*] Sliver C2 Framework
[*] Session opened for admin@TARGET01 (192.168.1.100)
"""
        log_file = tmp_path / "sliver.log"
        log_file.write_text(content)

        assert SliverParser.can_parse(log_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not SliverParser.can_parse(json_file)

    # =========================================================================
    # JSON Parsing Tests - Sessions
    # =========================================================================

    def test_parse_json_session(self, tmp_path: Path):
        """Test parsing session from JSON."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Username": "admin",
            "OS": "windows",
            "Arch": "amd64"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "TARGET01"
        assert hosts[0].ip == "192.168.1.100"
        assert "implant" in hosts[0].tags
        assert "compromised" in hosts[0].tags

    def test_parse_json_session_with_domain_user(self, tmp_path: Path):
        """Test parsing session with domain user."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Username": "CORP\\admin"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"
        assert users[0].domain == "CORP"
        assert "compromised" in users[0].tags

    def test_parse_json_creates_implant_misconfiguration(self, tmp_path: Path):
        """Test that active implants create misconfigurations."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Username": "admin",
            "PID": 1234
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        implants = [m for m in misconfigs if "Implant" in m.title]
        assert len(implants) >= 1
        assert implants[0].severity == "critical"
        assert "c2" in implants[0].tags

    def test_parse_json_multiple_sessions(self, tmp_path: Path):
        """Test parsing multiple sessions."""
        data = [
            {"ID": "sess1", "Hostname": "TARGET01", "RemoteAddress": "192.168.1.100:443"},
            {"ID": "sess2", "Hostname": "TARGET02", "RemoteAddress": "192.168.1.101:443"},
        ]
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_json_with_credentials(self, tmp_path: Path):
        """Test parsing session with harvested credentials."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Credentials": [
                {"Username": "admin", "Domain": "CORP", "Hash": "aabbccdd11223344aabbccdd11223344"}
            ]
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "ntlm"
        assert "harvested" in creds[0].tags

    def test_parse_json_with_password_credential(self, tmp_path: Path):
        """Test parsing session with password credential."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Credentials": [
                {"Username": "svc_account", "Password": "ServicePass123"}
            ]
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "password"

    # =========================================================================
    # JSON Parsing Tests - Raw Properties
    # =========================================================================

    def test_parse_json_stores_raw_properties(self, tmp_path: Path):
        """Test that session metadata is stored in raw_properties."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "PID": 1234,
            "Filename": "beacon.exe",
            "Transport": "mtls"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].raw_properties.get("session_id") == "session123"
        assert hosts[0].raw_properties.get("pid") == 1234
        assert hosts[0].raw_properties.get("transport") == "mtls"

    # =========================================================================
    # Log Parsing Tests
    # =========================================================================

    def test_parse_log_session(self, tmp_path: Path):
        """Test parsing session from log file."""
        # Note: Content must not start with "[" to avoid JSON detection
        content = """Sliver C2 Framework - Session Log
Session opened for admin@TARGET01 (192.168.1.100)
Beacon connected
"""
        log_file = tmp_path / "sliver.log"
        log_file.write_text(content)

        parser = SliverParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "TARGET01"
        assert "implant" in hosts[0].tags

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"

    def test_parse_log_hashdump(self, tmp_path: Path):
        """Test parsing hashdump from log file."""
        # Note: Content must not start with "[" to avoid JSON detection
        content = """Sliver C2 - Hashdump Results
Administrator:500:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
        log_file = tmp_path / "sliver.log"
        log_file.write_text(content)

        parser = SliverParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        # Should have Admin but not Guest (empty hash)
        admin_creds = [c for c in creds if "Administrator" in c.title]
        assert len(admin_creds) >= 1
        assert "hashdump" in admin_creds[0].tags

    def test_parse_log_pivots(self, tmp_path: Path):
        """Test parsing pivot information from log."""
        # Note: Content must not start with "[" to avoid JSON detection
        content = """Sliver C2 - Pivot Log
pivot through 10.0.0.50
tunnel to internal-server.corp.local
"""
        log_file = tmp_path / "sliver.log"
        log_file.write_text(content)

        parser = SliverParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        pivot_hosts = [h for h in hosts if "pivot-target" in h.tags]
        assert len(pivot_hosts) >= 1

    # =========================================================================
    # Relationship Tests
    # =========================================================================

    def test_creates_session_relationship(self, tmp_path: Path):
        """Test that HAS_SESSION relationship is created."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "Username": "admin"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        session_rels = [r for r in relationships if r.relation_type.value == "has_session"]
        assert len(session_rels) >= 1

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        data = [
            {"ID": "sess1", "Hostname": "TARGET01", "RemoteAddress": "192.168.1.100:443"},
            {"ID": "sess2", "Hostname": "TARGET01", "RemoteAddress": "192.168.1.100:443"},
        ]
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        target_hosts = [h for h in hosts if h.hostname == "TARGET01"]
        assert len(target_hosts) == 1

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        data = [
            {"ID": "sess1", "Hostname": "TARGET01", "Username": "admin"},
            {"ID": "sess2", "Hostname": "TARGET02", "Username": "admin"},
        ]
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "sliver_empty.json"
        json_file.write_text("")

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "sliver.json"
        json_file.write_text("{invalid json}")

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_handles_empty_credentials_array(self, tmp_path: Path):
        """Test handling of empty credentials array."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "Credentials": []
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) == 0

    def test_handles_upn_format_username(self, tmp_path: Path):
        """Test handling of UPN format usernames."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "Username": "admin@corp.local"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"
        assert users[0].domain == "corp.local"

    # =========================================================================
    # OS/Architecture Tests
    # =========================================================================

    def test_parses_os_info(self, tmp_path: Path):
        """Test that OS info is parsed."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443",
            "OS": "windows",
            "Arch": "amd64"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "windows" in hosts[0].os.lower()

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_sliver(self, tmp_path: Path):
        """Test that source is set to sliver."""
        data = {
            "ID": "session123",
            "Hostname": "TARGET01",
            "RemoteAddress": "192.168.1.100:443"
        }
        json_file = tmp_path / "sliver.json"
        json_file.write_text(json.dumps(data))

        parser = SliverParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "sliver"
