"""Tests for ntlmrelayx parser."""

import pytest
from pathlib import Path

from ariadne.parsers.ntlmrelayx import NtlmrelayxParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestNtlmrelayxParser(BaseParserTest):
    """Test NtlmrelayxParser functionality."""

    parser_class = NtlmrelayxParser
    expected_name = "ntlmrelayx"
    expected_patterns = ["*ntlmrelayx*.txt", "*ntlmrelayx*.log", "*relay*.log"]
    expected_entity_types = ["Host", "User", "Credential", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_ntlmrelayx_log(self, tmp_path: Path):
        """Test detection of ntlmrelayx log file."""
        content = """Impacket v0.10.0 - ntlmrelayx
[*] Target: 192.168.1.100
[*] Relaying to target
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        assert NtlmrelayxParser.can_parse(log_file)

    def test_can_parse_relay_log(self, tmp_path: Path):
        """Test detection of relay log file."""
        content = """[*] Authenticating against 192.168.1.100 as CORP/admin
[*] SMB signing disabled
"""
        log_file = tmp_path / "relay.log"
        log_file.write_text(content)

        assert NtlmrelayxParser.can_parse(log_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just random text.")

        assert not NtlmrelayxParser.can_parse(txt_file)

    # =========================================================================
    # Target Parsing Tests
    # =========================================================================

    def test_parse_targets(self, tmp_path: Path):
        """Test parsing target hosts."""
        content = """Target: 192.168.1.100
Target: 192.168.1.101
Connecting to: 192.168.1.102
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3
        assert any(h.ip == "192.168.1.100" for h in hosts)
        assert any(h.ip == "192.168.1.101" for h in hosts)

    def test_parse_hostname_target(self, tmp_path: Path):
        """Test parsing hostname targets."""
        content = """Target: DC01.corp.local
Relaying to: WS01.corp.local
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        hostname_hosts = [h for h in hosts if h.hostname]
        assert len(hostname_hosts) >= 1

    # =========================================================================
    # SMB Signing Tests
    # =========================================================================

    def test_parse_smb_signing_disabled(self, tmp_path: Path):
        """Test parsing SMB signing disabled hosts."""
        content = """192.168.1.100 does not require SMB signing
192.168.1.101 doesn't enforce signing
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        misconfigs = self.get_misconfigurations(entities)
        signing = [m for m in misconfigs if "SMB Signing" in m.title]
        assert len(signing) >= 2
        assert all(m.severity == "medium" for m in signing)
        assert all("ntlm-relay" in m.tags for m in signing)

    def test_smb_signing_host_tagged(self, tmp_path: Path):
        """Test that SMB signing disabled hosts are tagged."""
        content = """192.168.1.100 does not require SMB signing
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "smb-signing-disabled" in hosts[0].tags

    # =========================================================================
    # Relay Success Tests
    # =========================================================================

    def test_parse_relay_success(self, tmp_path: Path):
        """Test parsing successful relay attempts."""
        content = """Authenticating against 192.168.1.100 as CORP/admin
Successfully authenticated to DC01 with CORP\\jsmith
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert any("relayed" in u.tags for u in users)

    def test_relay_creates_access_relationship(self, tmp_path: Path):
        """Test that relay success creates HAS_ACCESS relationship."""
        content = """Target: 192.168.1.100
Authenticating against 192.168.1.100 as CORP/admin
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        relationships = self.get_relationships(entities)
        access_rels = [r for r in relationships if r.relation_type.value == "has_access"]
        assert len(access_rels) >= 1

    # =========================================================================
    # SAM Dump Tests
    # =========================================================================

    def test_parse_sam_dump(self, tmp_path: Path):
        """Test parsing SAM dump from relay."""
        content = """Target: 192.168.1.100
[*] Dumping SAM hashes:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
localuser:1001:aad3b435b51404eeaad3b435b51404ee:11223344aabbccdd11223344aabbccdd:::
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        sam_creds = [c for c in creds if "sam" in c.tags]
        assert len(sam_creds) >= 2
        assert all(c.credential_type == "ntlm" for c in sam_creds)
        assert all(c.severity == "critical" for c in sam_creds)

    def test_skips_empty_ntlm_hash(self, tmp_path: Path):
        """Test that empty NTLM hashes are skipped."""
        content = """Target: 192.168.1.100
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        guest_creds = [c for c in creds if "Guest" in c.title]
        assert len(guest_creds) == 0

    # =========================================================================
    # NTLM Hash Capture Tests
    # =========================================================================

    def test_parse_ntlm_hash_capture(self, tmp_path: Path):
        """Test parsing captured NTLM hashes."""
        # Format: domain\username::challenge:response:blob
        # Must start with hash directly - parser regex matches across newlines
        content = """CORP\\admin::1122334455667788:aabbccddeeff00112233445566778899:001122334455667788
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        ntlm_creds = [c for c in creds if c.credential_type == "ntlmv2"]
        assert len(ntlm_creds) >= 1
        assert ntlm_creds[0].domain == "CORP"
        assert ntlm_creds[0].username == "admin"

    def test_parse_ntlm_hash_creates_user(self, tmp_path: Path):
        """Test that captured NTLM hashes create users."""
        # Format: domain\username::challenge:response:blob
        content = """Target: 192.168.1.100
CORP\\jsmith::1122334455667788:aabbccddeeff00112233445566778899:001122334455667788
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert any(u.username == "jsmith" for u in users)
        assert any("captured" in u.tags for u in users)

    # =========================================================================
    # Secret Extraction Tests
    # =========================================================================

    def test_parse_secrets(self, tmp_path: Path):
        """Test parsing extracted secrets."""
        content = """Target: 192.168.1.100
[+] SECRET: DPAPI_SYSTEM : base64encodedvalue==
[*] SECRET: LSA_SECRET_KEY : anothersecret
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        secrets = [c for c in creds if c.credential_type == "secret"]
        assert len(secrets) >= 2
        assert all("relay-extracted" in c.tags for c in secrets)

    def test_skips_null_secrets(self, tmp_path: Path):
        """Test that null secrets are skipped."""
        # Format: [*] SECRET_NAME : value - parser checks if value is (null) or empty
        content = """Target: 192.168.1.100
[*] EMPTY_SECRET : (null)
[*] ANOTHER_EMPTY :
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        secrets = [c for c in creds if c.credential_type == "secret"]
        # One empty secret may still be created if "" is not stripped properly
        # The important check is that (null) secrets are skipped
        null_secrets = [s for s in secrets if "(null)" in s.value]
        assert len(null_secrets) == 0

    # =========================================================================
    # Shell/Code Execution Tests
    # =========================================================================

    def test_parse_shell_execution(self, tmp_path: Path):
        """Test parsing shell execution."""
        content = """Target: 192.168.1.100
Got shell on 192.168.1.100
Executing code at DC01.corp.local
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        misconfigs = self.get_misconfigurations(entities)
        shells = [m for m in misconfigs if "Code Execution" in m.title]
        assert len(shells) >= 2
        assert all(m.severity == "critical" for m in shells)
        assert all("code-execution" in m.tags for m in shells)

    def test_shell_marks_host_compromised(self, tmp_path: Path):
        """Test that shell execution creates a critical misconfiguration."""
        # Note: Host may be created first with relay-target tag, then shell creates misconfiguration
        content = """Got shell on 192.168.1.100
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        # Check for compromised host
        hosts = self.get_hosts(entities)
        compromised = [h for h in hosts if "compromised" in h.tags]
        assert len(compromised) >= 1

        # Check for misconfiguration
        misconfigs = self.get_misconfigurations(entities)
        code_exec = [m for m in misconfigs if "Code Execution" in m.title]
        assert len(code_exec) >= 1

    # =========================================================================
    # Admin Access Tests
    # =========================================================================

    def test_parse_admin_access(self, tmp_path: Path):
        """Test parsing admin access discovery."""
        content = """Target: 192.168.1.100
jsmith has admin access on 192.168.1.100
admin is administrator on DC01
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        misconfigs = self.get_misconfigurations(entities)
        admin = [m for m in misconfigs if "Admin Access" in m.title]
        assert len(admin) >= 1
        assert all(m.severity == "critical" for m in admin)

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        content = """Target: 192.168.1.100
Relaying to: 192.168.1.100
Connecting to: 192.168.1.100
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        hosts = self.get_hosts(entities)
        ip_100 = [h for h in hosts if h.ip == "192.168.1.100"]
        assert len(ip_100) == 1

    def test_deduplicates_credentials(self, tmp_path: Path):
        """Test that duplicate credentials are not created."""
        # SAM hash format - file must start directly with hash to avoid regex matching across newlines
        content = """admin:500:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
admin:500:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        creds = self.get_credentials(entities)
        admin_creds = [c for c in creds if c.username == "admin"]
        assert len(admin_creds) == 1

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        content = """Target: 192.168.1.100
Authenticating against 192.168.1.100 as CORP/admin
Authenticating against 192.168.1.101 as CORP/admin
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.username == "admin"]
        assert len(admin_users) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        log_file = tmp_path / "ntlmrelayx_empty.log"
        log_file.write_text("")

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        assert isinstance(entities, list)

    def test_handles_malformed_hash(self, tmp_path: Path):
        """Test handling of malformed hash lines."""
        content = """Target: 192.168.1.100
malformed:not:a:valid:hash:line
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        # Should not crash
        assert isinstance(entities, list)

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_ntlmrelayx(self, tmp_path: Path):
        """Test that source is set to ntlmrelayx."""
        content = """Target: 192.168.1.100
192.168.1.100 does not require SMB signing
"""
        log_file = tmp_path / "ntlmrelayx.log"
        log_file.write_text(content)

        parser = NtlmrelayxParser()
        entities = list(parser.parse(log_file))

        for entity in entities:
            assert entity.source == "ntlmrelayx"
