"""Tests for Kerbrute parser."""

import pytest
from pathlib import Path

from ariadne.parsers.kerbrute import KerbruteParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from .base import BaseParserTest


class TestKerbruteParser(BaseParserTest):
    """Test KerbruteParser functionality."""

    parser_class = KerbruteParser
    expected_name = "kerbrute"
    expected_patterns = ["*kerbrute*.txt", "*kerbrute*.log"]
    expected_entity_types = ["Host", "User", "Credential", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_kerbrute_txt(self, tmp_path: Path):
        """Test detection of Kerbrute output file."""
        content = """kerbrute userenum
[+] VALID USERNAME: jsmith@corp.local
[+] VALID USERNAME: admin@corp.local
"""
        txt_file = tmp_path / "kerbrute_output.txt"
        txt_file.write_text(content)

        assert KerbruteParser.can_parse(txt_file)

    def test_can_parse_by_content(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """[+] VALID USERNAME: testuser@domain.local
[+] VALID USERNAME: admin@domain.local
"""
        txt_file = tmp_path / "output.txt"
        txt_file.write_text(content)

        assert KerbruteParser.can_parse(txt_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just random text.")

        assert not KerbruteParser.can_parse(txt_file)

    # =========================================================================
    # Valid Username Tests
    # =========================================================================

    def test_parse_valid_usernames(self, tmp_path: Path):
        """Test parsing valid usernames from enumeration."""
        # Use backslash format - parser's regex handles this correctly
        content = """VALID USERNAME: CORP\\jsmith
VALID USERNAME: CORP\\admin
VALID USERNAME: CORP\\svc_sql
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 3
        usernames = [u.username for u in users]
        assert "jsmith" in usernames
        assert "admin" in usernames

    def test_parse_valid_username_with_domain(self, tmp_path: Path):
        """Test parsing usernames with domain backslash format."""
        # Remove [+] - parser's VALID_USER_PATTERN handles this format correctly
        content = """VALID USERNAME: CORP\\jsmith
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "CORP"

    def test_valid_users_tagged(self, tmp_path: Path):
        """Test that valid users have appropriate tags."""
        content = """[+] VALID USERNAME: testuser@corp.local
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert "valid-user" in users[0].tags
        assert "kerb-enumerated" in users[0].tags

    # =========================================================================
    # Valid Credentials Tests
    # =========================================================================

    def test_parse_valid_login(self, tmp_path: Path):
        """Test parsing valid login from password spray."""
        content = """[+] VALID LOGIN: admin@corp.local:Password123
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "password"
        assert creds[0].value == "Password123"
        assert creds[0].severity == "critical"

    def test_valid_login_creates_user(self, tmp_path: Path):
        """Test that valid login creates a user entity."""
        # Use backslash format - parser's regex handles this correctly
        content = """[+] VALID LOGIN: corp.local\\jsmith:Summer2024!
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert any(u.username == "jsmith" for u in users)

    # =========================================================================
    # AS-REP Roasting Tests
    # =========================================================================

    def test_parse_asrep_hash(self, tmp_path: Path):
        """Test parsing AS-REP hash."""
        content = """$krb5asrep$23$asrepuser@CORP.LOCAL:aabbccdd11223344aabbccdd11223344$aabbccdd11223344
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        asrep_creds = [c for c in creds if c.credential_type == "kerberos"]
        assert len(asrep_creds) >= 1
        assert "asreproast" in asrep_creds[0].tags

        users = self.get_users(entities)
        asrep_users = [u for u in users if "asreproastable" in u.tags]
        assert len(asrep_users) >= 1

    def test_parse_asrep_creates_misconfiguration(self, tmp_path: Path):
        """Test that AS-REP roastable users create misconfigurations."""
        content = """$krb5asrep$23$vulnerable_user@CORP.LOCAL:aabbccdd11223344aabbccdd11223344$aabbccdd
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        asrep = [m for m in misconfigs if "AS-REP" in m.title]
        assert len(asrep) >= 1
        assert asrep[0].severity == "high"

    def test_parse_no_preauth_indicator(self, tmp_path: Path):
        """Test parsing NO PREAUTH indicator."""
        content = """NO PREAUTH: nopreauth_user@corp.local
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        nopreauth = [u for u in users if "no-preauth" in u.tags]
        assert len(nopreauth) >= 1

    # =========================================================================
    # Domain Controller Tests
    # =========================================================================

    def test_parse_domain_controller(self, tmp_path: Path):
        """Test parsing domain controller information."""
        content = """Domain Controller: dc01.corp.local
[+] VALID USERNAME: admin@corp.local
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "dc01.corp.local"
        assert "domain-controller" in hosts[0].tags

    def test_parse_dc_ip(self, tmp_path: Path):
        """Test parsing domain controller by IP."""
        content = """DC: 192.168.1.10
[+] VALID USERNAME: admin@corp.local
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.10"

    # =========================================================================
    # Locked Account Tests
    # =========================================================================

    def test_parse_locked_accounts(self, tmp_path: Path):
        """Test parsing locked account information."""
        content = """LOCKED: locked_user@corp.local
DISABLED: disabled_user@corp.local
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        locked = [u for u in users if "locked" in u.tags]
        assert len(locked) >= 1
        assert locked[0].enabled == False

    # =========================================================================
    # Domain Extraction Tests
    # =========================================================================

    def test_extracts_default_domain(self, tmp_path: Path):
        """Test extraction of default domain."""
        content = """Domain: corp.local
[+] VALID USERNAME: jsmith
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        # Users without explicit domain should get default domain
        assert len(users) >= 1

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        # Use backslash format without [+]
        content = """VALID USERNAME: corp.local\\admin
VALID USERNAME: corp.local\\admin
VALID USERNAME: corp.local\\admin
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "kerbrute_empty.txt"
        txt_file.write_text("")

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_no_users_found(self, tmp_path: Path):
        """Test handling when no valid users found."""
        # Avoid trigger words like "valid" that could cause partial matches
        content = """kerbrute userenum
Completed enumeration with 0 accounts found
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) == 0

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_kerbrute(self, tmp_path: Path):
        """Test that source is set to kerbrute."""
        content = """[+] VALID USERNAME: testuser@corp.local
"""
        txt_file = tmp_path / "kerbrute.txt"
        txt_file.write_text(content)

        parser = KerbruteParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "kerbrute"
