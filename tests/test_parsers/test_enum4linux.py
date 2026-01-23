"""Tests for Enum4linux parser."""

import pytest
from pathlib import Path

from ariadne.parsers.enum4linux import Enum4linuxParser
from ariadne.models.asset import Host, Service, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestEnum4linuxParser(BaseParserTest):
    """Test Enum4linuxParser functionality."""

    parser_class = Enum4linuxParser
    expected_name = "enum4linux"
    expected_patterns = ["*enum4linux*.txt", "*enum4linux*.log"]
    expected_entity_types = ["Host", "Service", "User", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_enum4linux_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        content = "Target Information: 192.168.1.100"
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        assert Enum4linuxParser.can_parse(txt_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """Starting enum4linux v0.9.1
Target Information: 192.168.1.100
Nbtstat Information for 192.168.1.100
"""
        txt_file = tmp_path / "results.txt"
        txt_file.write_text(content)

        assert Enum4linuxParser.can_parse(txt_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text is rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("random text content")

        assert not Enum4linuxParser.can_parse(txt_file)

    def test_cannot_parse_json(self, tmp_path: Path):
        """Test that JSON files are rejected."""
        json_file = tmp_path / "results.json"
        json_file.write_text('{"data": "test"}')

        assert not Enum4linuxParser.can_parse(json_file)

    # =========================================================================
    # Target Information Parsing Tests
    # =========================================================================

    def test_parse_target_ip(self, tmp_path: Path):
        """Test parsing target IP address."""
        content = """Starting enum4linux
Target Information: 192.168.1.100
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"
        assert "smb-enumerated" in hosts[0].tags

    def test_parse_target_hostname(self, tmp_path: Path):
        """Test parsing target with hostname."""
        content = """Target Information: server.corp.local
NetBIOS computer name: SERVER01
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "SERVER01"

    def test_parse_target_domain(self, tmp_path: Path):
        """Test parsing domain information."""
        content = """Target Information: 192.168.1.100
Domain Name: CORP.LOCAL
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].domain == "CORP.LOCAL"

    def test_parse_target_os(self, tmp_path: Path):
        """Test parsing OS information."""
        content = """Target Information: 192.168.1.100
OS: Windows Server 2019 Standard 17763
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "Windows" in hosts[0].os

    # =========================================================================
    # Service Creation Tests
    # =========================================================================

    def test_creates_smb_service(self, tmp_path: Path):
        """Test that SMB service is created."""
        content = """Target Information: 192.168.1.100
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 445
        assert services[0].name == "microsoft-ds"

    def test_creates_service_relationship(self, tmp_path: Path):
        """Test that service-host relationship is created."""
        content = """Target Information: 192.168.1.100
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    # =========================================================================
    # User Parsing Tests
    # =========================================================================

    def test_parse_users_with_rid(self, tmp_path: Path):
        """Test parsing users with RID."""
        content = """Target Information: 192.168.1.100
Users on 192.168.1.100:
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[jsmith] rid:[0x3e8]
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 3
        usernames = [u.username for u in users]
        assert "Administrator" in usernames
        assert "jsmith" in usernames

    def test_parse_admin_user_by_rid(self, tmp_path: Path):
        """Test that user with RID 500 is marked as admin."""
        content = """Target Information: 192.168.1.100
user:[Administrator] rid:[0x1f4]
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "Administrator"]
        assert len(admin_users) >= 1
        assert admin_users[0].is_admin == True

    def test_parse_users_stores_rid(self, tmp_path: Path):
        """Test that RID is stored in raw_properties."""
        content = """Target Information: 192.168.1.100
user:[testuser] rid:[0x3e8]
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].raw_properties.get("rid") == 1000  # 0x3e8 = 1000

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        content = """Target Information: 192.168.1.100
user:[admin] rid:[0x1f4]
user:[admin] rid:[0x1f4]
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Share Parsing Tests
    # =========================================================================

    def test_parse_shares(self, tmp_path: Path):
        """Test parsing share information."""
        content = """Target Information: 192.168.1.100
Share Enumeration:
ADMIN$           Disk      Remote Admin
C$               Disk      Default share
IPC$             IPC       Remote IPC
Public           Disk      Public files
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        share_misconfigs = [m for m in misconfigs if "Share Discovered" in m.title]
        assert len(share_misconfigs) >= 3

    def test_parse_admin_shares_high_severity(self, tmp_path: Path):
        """Test that admin shares are high severity."""
        content = """Target Information: 192.168.1.100
C$               Disk      Default share
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        c_share = [m for m in misconfigs if "C$" in m.title]
        assert len(c_share) >= 1
        assert c_share[0].severity == "high"

    def test_parse_accessible_shares(self, tmp_path: Path):
        """Test parsing accessible share from mapping."""
        content = """Target Information: 192.168.1.100
//192.168.1.100/Public Mapping: OK
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        accessible = [m for m in misconfigs if "Accessible" in m.title]
        assert len(accessible) >= 1

    # =========================================================================
    # Misconfiguration Tests
    # =========================================================================

    def test_parse_anonymous_session(self, tmp_path: Path):
        """Test detection of anonymous session."""
        content = """Target Information: 192.168.1.100
Anonymous session allowed
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        anon = [m for m in misconfigs if "Anonymous" in m.title or "Null" in m.title]
        assert len(anon) >= 1

    def test_parse_null_session(self, tmp_path: Path):
        """Test detection of null session."""
        content = """Target Information: 192.168.1.100
Null session successful
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        null_session = [m for m in misconfigs if "Anonymous" in m.title or "Null" in m.title]
        assert len(null_session) >= 1

    def test_parse_no_min_password(self, tmp_path: Path):
        """Test detection of no minimum password length."""
        content = """Target Information: 192.168.1.100
Minimum password length: 0
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        no_min = [m for m in misconfigs if "Minimum Password" in m.title]
        assert len(no_min) >= 1
        assert no_min[0].severity == "high"

    def test_parse_no_password_complexity(self, tmp_path: Path):
        """Test detection of disabled password complexity."""
        content = """Target Information: 192.168.1.100
Password Complexity: Disabled
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        no_complexity = [m for m in misconfigs if "Complexity" in m.title]
        assert len(no_complexity) >= 1

    def test_parse_no_lockout(self, tmp_path: Path):
        """Test detection of no account lockout."""
        content = """Target Information: 192.168.1.100
Account lockout threshold: 0
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        no_lockout = [m for m in misconfigs if "Lockout" in m.title]
        assert len(no_lockout) >= 1

    def test_parse_smbv1_enabled(self, tmp_path: Path):
        """Test detection of SMBv1 enabled."""
        content = """Target Information: 192.168.1.100
SMBv1 enabled
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        smbv1 = [m for m in misconfigs if "SMBv1" in m.title]
        assert len(smbv1) >= 1
        assert smbv1[0].severity == "high"

    def test_parse_smb_signing_disabled(self, tmp_path: Path):
        """Test detection of SMB signing disabled."""
        content = """Target Information: 192.168.1.100
SMB signing: disabled
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        signing = [m for m in misconfigs if "Signing" in m.title]
        assert len(signing) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "enum4linux_empty.txt"
        txt_file.write_text("")

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_no_target(self, tmp_path: Path):
        """Test handling of file without target info."""
        content = """enum4linux output
No target found
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_extracts_ip_from_content(self, tmp_path: Path):
        """Test extracting IP from content when Target missing."""
        content = """192.168.1.100 - SMB enumeration
Session Check on 192.168.1.100
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_enum4linux(self, tmp_path: Path):
        """Test that source is set to enum4linux."""
        content = """Target Information: 192.168.1.100
user:[admin] rid:[0x1f4]
"""
        txt_file = tmp_path / "enum4linux.txt"
        txt_file.write_text(content)

        parser = Enum4linuxParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "enum4linux"
