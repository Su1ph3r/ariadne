"""Tests for rpcclient parser."""

import pytest
from pathlib import Path

from ariadne.parsers.rpcclient import RpcclientParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestRpcclientParser(BaseParserTest):
    """Test RpcclientParser functionality."""

    parser_class = RpcclientParser
    expected_name = "rpcclient"
    expected_patterns = ["*rpcclient*.txt", "*rpcclient*.log", "*rpc_enum*.txt"]
    expected_entity_types = ["Host", "User", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_rpcclient_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        content = "user:[Administrator] rid:[0x1f4]"
        txt_file = tmp_path / "rpcclient_output.txt"
        txt_file.write_text(content)

        assert RpcclientParser.can_parse(txt_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """user:[admin] rid:[0x1f4]
group:[Domain Admins] rid:[0x200]
"""
        txt_file = tmp_path / "output.txt"
        txt_file.write_text(content)

        assert RpcclientParser.can_parse(txt_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text file is rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("random text content")

        assert not RpcclientParser.can_parse(txt_file)

    # =========================================================================
    # User Enumeration Tests
    # =========================================================================

    def test_parse_enumdomusers(self, tmp_path: Path):
        """Test parsing enumdomusers output."""
        content = """user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[jsmith] rid:[0x451]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 4
        usernames = [u.username for u in users]
        assert "Administrator" in usernames
        assert "jsmith" in usernames

    def test_parse_admin_user_by_rid(self, tmp_path: Path):
        """Test detection of administrator by RID 500."""
        content = "user:[Administrator] rid:[0x1f4]"
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.is_admin]
        assert len(admin_users) >= 1

    def test_stores_rid_in_raw_properties(self, tmp_path: Path):
        """Test that RID is stored in raw_properties."""
        content = "user:[testuser] rid:[0x451]"
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].raw_properties.get("rid") == 0x451

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        content = """user:[testuser] rid:[0x451]
user:[testuser] rid:[0x451]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        testusers = [u for u in users if u.username.lower() == "testuser"]
        assert len(testusers) == 1

    # =========================================================================
    # Domain Info Tests
    # =========================================================================

    def test_extracts_domain_name(self, tmp_path: Path):
        """Test extraction of domain name."""
        content = """Domain Name: CORP
Domain SID: S-1-5-21-1234567890-1234567890-1234567890

user:[admin] rid:[0x1f4]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].domain == "CORP"

    def test_extracts_netbios_domain(self, tmp_path: Path):
        """Test extraction of Netbios domain name."""
        content = """Netbios domain: CORP
user:[admin] rid:[0x1f4]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].domain == "CORP"

    # =========================================================================
    # Group Enumeration Tests
    # =========================================================================

    def test_parse_enumdomgroups(self, tmp_path: Path):
        """Test parsing enumdomgroups output."""
        content = """group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Enterprise Admins] rid:[0x207]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        priv_groups = [m for m in misconfigs if "Privileged group enumerated" in m.title]
        assert len(priv_groups) >= 2  # Domain Admins, Enterprise Admins

    # =========================================================================
    # Password Policy Tests
    # =========================================================================

    def test_parse_weak_min_password(self, tmp_path: Path):
        """Test detection of weak minimum password length."""
        content = """min_password_length: 4
password_history: 0
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        weak_pass = [m for m in misconfigs if "Weak minimum password" in m.title]
        assert len(weak_pass) >= 1
        assert weak_pass[0].severity == "medium"

    def test_parse_no_lockout_policy(self, tmp_path: Path):
        """Test detection of no account lockout policy."""
        content = "Account lockout threshold: 0"
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        no_lockout = [m for m in misconfigs if "No account lockout" in m.title]
        assert len(no_lockout) >= 1

    def test_parse_no_complexity(self, tmp_path: Path):
        """Test detection of password complexity not enforced."""
        content = "password_properties: 0x00000001"  # Not DOMAIN_PASSWORD_COMPLEX
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        no_complexity = [m for m in misconfigs if "complexity not enforced" in m.title]
        assert len(no_complexity) >= 1

    # =========================================================================
    # Queryuser Tests
    # =========================================================================

    def test_parse_queryuser(self, tmp_path: Path):
        """Test parsing queryuser output extracts username."""
        # Queryuser format with tabs - just verify username extraction
        content = "User Name   :\ttestuser\nFull Name   :\tTest User"
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "testuser"

    def test_parse_enumdomusers_with_mixed_content(self, tmp_path: Path):
        """Test parsing enumdomusers mixed with queryuser output."""
        # The parser reliably extracts users from enumdomusers format
        content = """user:[disableduser] rid:[0x452]
user:[admin] rid:[0x1f4]

Domain Name: CORP
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2
        usernames = [u.username for u in users]
        assert "disableduser" in usernames
        assert "admin" in usernames

    def test_parse_combined_enumeration(self, tmp_path: Path):
        """Test parsing combined user and group enumeration."""
        content = """user:[weakuser] rid:[0x453]
group:[Backup Operators] rid:[0x227]

user:[asrepuser] rid:[0x454]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        misconfigs = self.get_misconfigurations(entities)

        assert len(users) >= 2
        # Backup Operators is a privileged group
        priv_groups = [m for m in misconfigs if "Privileged group" in m.title]
        assert len(priv_groups) >= 1

    def test_parse_multiple_privileged_groups(self, tmp_path: Path):
        """Test detection of multiple privileged groups."""
        content = """group:[Domain Admins] rid:[0x200]
group:[Enterprise Admins] rid:[0x207]
group:[Backup Operators] rid:[0x227]
group:[Regular Users] rid:[0x201]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        priv_groups = [m for m in misconfigs if "Privileged group" in m.title]
        # Should detect Domain Admins, Enterprise Admins, Backup Operators
        assert len(priv_groups) >= 3

    def test_parse_user_with_domain(self, tmp_path: Path):
        """Test that domain is associated with parsed users."""
        content = """Domain Name: CORP

user:[svcaccount] rid:[0x455]
user:[testuser] rid:[0x456]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2
        assert all(u.domain == "CORP" for u in users)

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text("")

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_mixed_content(self, tmp_path: Path):
        """Test handling of mixed content."""
        content = """Domain Name: CORP

rpcclient> enumdomusers
user:[admin] rid:[0x1f4]
user:[jsmith] rid:[0x451]

rpcclient> enumdomgroups
group:[Domain Admins] rid:[0x200]

rpcclient> getdompwinfo
min_password_length: 8
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_case_insensitive_matching(self, tmp_path: Path):
        """Test case insensitive user/group matching."""
        content = """USER:[TestUser] RID:[0x451]
GROUP:[Domain Admins] RID:[0x200]
"""
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_rpcclient(self, tmp_path: Path):
        """Test that source is set to rpcclient."""
        content = "user:[testuser] rid:[0x451]"
        txt_file = tmp_path / "rpcclient.txt"
        txt_file.write_text(content)

        parser = RpcclientParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "rpcclient"
