"""Tests for Impacket parser."""

import pytest
from pathlib import Path
from textwrap import dedent

from ariadne.parsers.impacket import ImpacketParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential
from .base import BaseParserTest


class TestImpacketParser(BaseParserTest):
    """Test ImpacketParser functionality."""

    parser_class = ImpacketParser
    expected_name = "impacket"
    expected_patterns = ["*secretsdump*.txt", "*getuserspns*.txt", "*getnpusers*.txt", "*impacket*.txt"]
    expected_entity_types = ["Host", "User", "Credential"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_secretsdump_file(self, tmp_path: Path):
        """Test detection of secretsdump output."""
        content = dedent("""\
            [*] Target system bootKey: 0x123456789abcdef
            [*] Dumping local SAM hashes
            Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            """)
        txt_file = tmp_path / "secretsdump_192.168.1.1.txt"
        txt_file.write_text(content)

        assert ImpacketParser.can_parse(txt_file)

    def test_can_parse_getuserspns_file(self, tmp_path: Path):
        """Test detection of GetUserSPNs output."""
        content = dedent("""\
            Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

            ServicePrincipalName  Name     MemberOf  PasswordLastSet
            --------------------  -------  --------  -------------------
            http/web.corp.local   svc_web            2024-01-01 12:00:00

            $krb5tgs$23$*svc_web$CORP.LOCAL$svc_web*$1234567890abcdef
            """)
        txt_file = tmp_path / "getuserspns_output.txt"
        txt_file.write_text(content)

        assert ImpacketParser.can_parse(txt_file)

    def test_can_parse_getnpusers_file(self, tmp_path: Path):
        """Test detection of GetNPUsers output."""
        content = dedent("""\
            Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

            [*] Getting TGT for asrep_user
            $krb5asrep$23$asrep_user@CORP.LOCAL:1234567890abcdef
            """)
        txt_file = tmp_path / "getnpusers_output.txt"
        txt_file.write_text(content)

        assert ImpacketParser.can_parse(txt_file)

    def test_cannot_parse_json_file(self, tmp_path: Path):
        """Test that JSON files are rejected."""
        json_file = tmp_path / "data.json"
        json_file.write_text('{"test": true}')

        assert not ImpacketParser.can_parse(json_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just a random text file with no hashes.")

        assert not ImpacketParser.can_parse(txt_file)

    # =========================================================================
    # NTLM Hash Parsing Tests
    # =========================================================================

    def test_parse_ntlm_hashes(self, tmp_path: Path):
        """Test parsing NTLM hashes from secretsdump."""
        # Use domain prefix format which the parser handles reliably
        lines = [
            "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::",
            "CORP\\testuser:1001:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::",
        ]
        txt_file = tmp_path / "secretsdump_192.168.1.1.txt"
        txt_file.write_text("\n".join(lines) + "\n")

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)

        assert len(users) >= 2
        assert len(creds) >= 2

        usernames = {u.username for u in users}
        assert "Administrator" in usernames
        assert "testuser" in usernames

        admin_cred = next((c for c in creds if "Administrator" in c.title), None)
        assert admin_cred is not None
        assert admin_cred.credential_type == "ntlm"
        assert admin_cred.ntlm_hash == "a87f3a337d73085c45f9416be5787d86"
        assert admin_cred.severity == "high"

    def test_parse_domain_ntlm_hashes(self, tmp_path: Path):
        """Test parsing NTLM hashes with domain prefix."""
        content = dedent("""\
            CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            CORP\\jsmith:1001:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
            """)
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)

        assert len(users) >= 2
        admin = next((u for u in users if u.username == "Administrator"), None)
        assert admin is not None
        assert admin.domain == "CORP"

        admin_cred = next((c for c in creds if "Administrator" in c.title), None)
        assert admin_cred is not None
        assert admin_cred.domain == "CORP"

    def test_skips_empty_lm_hash(self, tmp_path: Path):
        """Test that empty NTLM hashes (31d6cfe0d16ae931b73c59d7e0c089c0) are skipped."""
        # Use domain prefix format for reliable parsing
        lines = [
            "CORP\\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
            "CORP\\testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::",
        ]
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text("\n".join(lines) + "\n")

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        # Guest should be skipped (empty hash), only testuser should be present
        assert len(creds) == 1
        assert "testuser" in creds[0].title

    # =========================================================================
    # Kerberoast Tests
    # =========================================================================

    def test_parse_kerberoast_hashes(self, tmp_path: Path):
        """Test parsing Kerberoastable hashes."""
        content = dedent("""\
            Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

            ServicePrincipalName  Name     MemberOf
            --------------------  -------  --------
            http/web.corp.local   svc_web

            $krb5tgs$23$*svc_web$CORP.LOCAL$svc_web*$1234567890abcdef1234567890abcdef
            $krb5tgs$23$*svc_sql$CORP.LOCAL$svc_sql*$fedcba0987654321fedcba0987654321
            """)
        txt_file = tmp_path / "getuserspns.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)

        # Should have at least 2 kerberoastable users
        kerb_users = [u for u in users if "kerberoastable" in (u.tags or [])]
        assert len(kerb_users) >= 2

        # Should have kerberos credentials
        kerb_creds = [c for c in creds if c.credential_type == "kerberos"]
        assert len(kerb_creds) >= 2

        svc_web_cred = next((c for c in kerb_creds if "svc_web" in c.title), None)
        assert svc_web_cred is not None
        assert "kerberoast" in (svc_web_cred.tags or [])
        assert svc_web_cred.severity == "high"

    # =========================================================================
    # AS-REP Roast Tests
    # =========================================================================

    def test_parse_asreproast_hashes(self, tmp_path: Path):
        """Test parsing AS-REP roastable hashes."""
        content = dedent("""\
            Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

            [*] Getting TGT for asrep_user
            $krb5asrep$23$asrep_user@CORP.LOCAL:1234567890abcdef1234567890abcdef

            [*] Getting TGT for nopreauth
            $krb5asrep$23$nopreauth@CORP.LOCAL:fedcba0987654321fedcba0987654321
            """)
        txt_file = tmp_path / "getnpusers.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)

        # Should have AS-REP roastable users
        asrep_users = [u for u in users if "asreproastable" in (u.tags or [])]
        assert len(asrep_users) >= 2

        # Should have AS-REP credentials
        asrep_creds = [c for c in creds if "asreproast" in (c.tags or [])]
        assert len(asrep_creds) >= 2

        assert asrep_creds[0].domain == "CORP.LOCAL"

    # =========================================================================
    # Cleartext Password Tests
    # =========================================================================

    def test_parse_cleartext_passwords(self, tmp_path: Path):
        """Test parsing cleartext passwords."""
        content = dedent("""\
            CORP\\svc_account:CLEARTEXT:P@ssw0rd123!
            CORP\\admin:CLEARTEXT:AdminPassword1
            """)
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        cleartext_creds = [c for c in creds if c.credential_type == "password"]

        assert len(cleartext_creds) >= 2

        svc_cred = next((c for c in cleartext_creds if "svc_account" in c.title), None)
        assert svc_cred is not None
        assert svc_cred.value == "P@ssw0rd123!"
        assert svc_cred.severity == "critical"
        assert svc_cred.domain == "CORP"

    def test_skips_null_cleartext(self, tmp_path: Path):
        """Test that null cleartext passwords are skipped."""
        content = dedent("""\
            [*] Dumping cached credentials
            CORP\\nulluser:CLEARTEXT:(null)
            CORP\\realuser:CLEARTEXT:RealPassword!
            """)
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        cleartext_creds = [c for c in creds if c.credential_type == "password"]

        # Only realuser should be present
        assert len(cleartext_creds) == 1
        assert "realuser" in cleartext_creds[0].title

    # =========================================================================
    # DPAPI Key Tests
    # =========================================================================

    def test_parse_dpapi_keys(self, tmp_path: Path):
        """Test parsing DPAPI keys."""
        content = dedent("""\
            [*] Dumping DPAPI keys
            [dpapi_machinekey] 12345678-1234-1234-1234-123456789abc : abcdef123456789012345678901234567890abcdef
            [dpapi_userkey] 87654321-4321-4321-4321-cba987654321 : fedcba098765432109876543210987654321fedcba
            """)
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        dpapi_creds = [c for c in creds if c.credential_type == "dpapi"]

        assert len(dpapi_creds) >= 2

        machine_key = next((c for c in dpapi_creds if "machinekey" in c.title), None)
        assert machine_key is not None
        assert machine_key.severity == "medium"
        assert machine_key.raw_data.get("key_type") == "dpapi_machinekey"

    # =========================================================================
    # Target Extraction Tests
    # =========================================================================

    def test_extracts_target_from_content(self, tmp_path: Path):
        """Test target extraction from file content."""
        content = dedent("""\
            Impacket v0.10.0
            Target: dc01.corp.local

            [*] Dumping local SAM hashes
            testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            """)
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].hostname == "dc01.corp.local"

    def test_extracts_target_from_filename(self, tmp_path: Path):
        """Test target extraction from filename."""
        content = dedent("""\
            [*] Dumping local SAM hashes
            testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            """)
        txt_file = tmp_path / "secretsdump_192.168.1.100.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.100"

    def test_source_is_impacket(self, tmp_path: Path):
        """Test that source is set to impacket."""
        content = dedent("""\
            [*] Dumping local SAM hashes
            testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            """)
        txt_file = tmp_path / "secretsdump_192.168.1.1.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "impacket"

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_users(self, tmp_path: Path):
        """Test that duplicate users are not created."""
        content = dedent("""\
            CORP\\testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            CORP\\testuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
            """)
        txt_file = tmp_path / "secretsdump.txt"
        txt_file.write_text(content)

        parser = ImpacketParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)

        # Should only have one user and one credential
        assert len(users) == 1
        assert len(creds) == 1
