"""Tests for Responder parser."""

import pytest
from pathlib import Path

from ariadne.parsers.responder import ResponderParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential
from .base import BaseParserTest


class TestResponderParser(BaseParserTest):
    """Test ResponderParser functionality."""

    parser_class = ResponderParser
    expected_name = "responder"
    expected_patterns = [
        "*Responder*.txt",
        "*responder*.log",
        "*NTLM*.txt",
        "*SMB-NTLMv*.txt",
        "*HTTP-NTLMv*.txt",
        "*MSSQL-NTLMv*.txt",
    ]
    expected_entity_types = ["Host", "User", "Credential"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_responder_log(self, tmp_path: Path):
        """Test detection of Responder log file."""
        content = "[*] Responder is running\n[+] NTLMv2 captured"
        log_file = tmp_path / "Responder-Session.log"
        log_file.write_text(content)

        assert ResponderParser.can_parse(log_file)

    def test_can_parse_ntlmv2_file(self, tmp_path: Path):
        """Test detection of NTLMv2 hash file."""
        content = "admin::CORP:1122334455667788:aabbccdd:0011223344556677"
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text(content)

        assert ResponderParser.can_parse(hash_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just random text.")

        assert not ResponderParser.can_parse(txt_file)

    # =========================================================================
    # Hash File Parsing Tests
    # =========================================================================

    def test_parse_ntlmv2_hash(self, tmp_path: Path):
        """Test parsing NTLMv2 hash."""
        # NTLMv2 format: user::domain:challenge:response:blob
        content = "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122334455"
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text(content)

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        creds = self.get_credentials(entities)
        users = self.get_users(entities)

        assert len(creds) >= 1
        assert creds[0].username == "admin"
        assert creds[0].domain == "CORP"
        assert "captured" in creds[0].tags

        assert len(users) >= 1
        assert users[0].username == "admin"
        assert "ntlm-captured" in users[0].tags

    def test_parse_multiple_hashes(self, tmp_path: Path):
        """Test parsing multiple hashes."""
        lines = [
            "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122",
            "jsmith::CORP:8877665544332211:ffeeddccbbaa99887766554433221100:998877",
        ]
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text("\n".join(lines))

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 2

    def test_parse_hash_extracts_protocol(self, tmp_path: Path):
        """Test that protocol is extracted from filename."""
        content = "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122"
        hash_file = tmp_path / "HTTP-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text(content)

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert "http" in creds[0].tags

    # =========================================================================
    # Log File Parsing Tests
    # =========================================================================

    def test_parse_log_extracts_hosts(self, tmp_path: Path):
        """Test parsing log file extracts victim hosts."""
        lines = [
            "Responder Session Log",
            "[*] NTLMv2 Client: 192.168.1.100",
            "[*] NTLMv2 Client: 192.168.1.101",
        ]
        log_file = tmp_path / "Responder-Session.log"
        log_file.write_text("\n".join(lines))

        parser = ResponderParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2
        assert any(h.ip == "192.168.1.100" for h in hosts)
        assert any(h.ip == "192.168.1.101" for h in hosts)

    def test_parse_log_cleartext_password(self, tmp_path: Path):
        """Test parsing cleartext passwords from log."""
        lines = [
            "Responder Session Log",
            "Username: testuser",
            "[HTTP] Cleartext-Password: SecretPass123",
        ]
        log_file = tmp_path / "Responder-Session.log"
        log_file.write_text("\n".join(lines))

        parser = ResponderParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        cleartext = [c for c in creds if c.credential_type == "password"]
        assert len(cleartext) >= 1
        assert cleartext[0].severity == "critical"

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hashes(self, tmp_path: Path):
        """Test that duplicate hashes are not created."""
        # Same hash repeated
        content = "\n".join([
            "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122",
            "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122",
        ])
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text(content)

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        creds = self.get_credentials(entities)
        assert len(creds) == 1

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        lines = [
            "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122",
            "admin::CORP:9988776655443322:ffeeddccbbaa99887766554433221100:665544",
        ]
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text("\n".join(lines))

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        log_file = tmp_path / "Responder-Session.log"
        log_file.write_text("")

        parser = ResponderParser()
        entities = list(parser.parse(log_file))

        assert isinstance(entities, list)

    def test_handles_empty_domain(self, tmp_path: Path):
        """Test handling of hashes with empty domain."""
        content = "localuser:::1122334455667788:aabbccddeeff00112233445566778899:001122"
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text(content)

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].username == "localuser"

    def test_skips_comments(self, tmp_path: Path):
        """Test that comments are skipped."""
        lines = [
            "# This is a comment",
            "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122",
        ]
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text("\n".join(lines))

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        creds = self.get_credentials(entities)
        assert len(creds) == 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_responder(self, tmp_path: Path):
        """Test that source is set to responder."""
        content = "admin::CORP:1122334455667788:aabbccddeeff00112233445566778899:001122"
        hash_file = tmp_path / "SMB-NTLMv2-SSP-192.168.1.100.txt"
        hash_file.write_text(content)

        parser = ResponderParser()
        entities = list(parser.parse(hash_file))

        for entity in entities:
            assert entity.source == "responder"
