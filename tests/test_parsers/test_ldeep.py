"""Tests for ldeep parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.ldeep import LdeepParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestLdeepParser(BaseParserTest):
    """Test LdeepParser functionality."""

    parser_class = LdeepParser
    expected_name = "ldeep"
    expected_patterns = ["*ldeep*.json", "*ldeep*.txt", "ldeep_*"]
    expected_entity_types = ["Host", "User", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_ldeep_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        data = {"sAMAccountName": "testuser", "distinguishedName": "CN=testuser,DC=corp,DC=local"}
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        assert LdeepParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        data = {
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=jsmith,OU=Users,DC=corp,DC=local",
            "userAccountControl": 512
        }
        json_file = tmp_path / "output.json"
        json_file.write_text(json.dumps(data))

        assert LdeepParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not LdeepParser.can_parse(json_file)

    # =========================================================================
    # User Parsing Tests
    # =========================================================================

    def test_parse_user(self, tmp_path: Path):
        """Test parsing user from JSON."""
        data = {
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=jsmith,OU=Users,DC=corp,DC=local",
            "displayName": "John Smith",
            "mail": "jsmith@corp.local",
            "userAccountControl": 512
        }
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "corp.local"

    def test_parse_disabled_user(self, tmp_path: Path):
        """Test parsing disabled user (UAC 0x0002)."""
        data = {
            "sAMAccountName": "disabled",
            "distinguishedName": "CN=disabled,DC=corp,DC=local",
            "userAccountControl": 514  # 512 + 2 (ACCOUNTDISABLE)
        }
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].enabled == False

    def test_parse_admin_user_by_group(self, tmp_path: Path):
        """Test detection of admin user by group membership."""
        data = {
            "sAMAccountName": "admin",
            "distinguishedName": "CN=admin,DC=corp,DC=local",
            "userAccountControl": 512,
            "memberOf": ["CN=Domain Admins,OU=Groups,DC=corp,DC=local"]
        }
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].is_admin == True

    def test_parse_asreproastable_user(self, tmp_path: Path):
        """Test detection of AS-REP roastable users."""
        data = {
            "sAMAccountName": "asrepuser",
            "distinguishedName": "CN=asrepuser,DC=corp,DC=local",
            "userAccountControl": 4194816  # 512 + 0x400000 (DONT_REQ_PREAUTH)
        }
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        asrep = [m for m in misconfigs if "AS-REP" in m.title]
        assert len(asrep) >= 1
        assert asrep[0].severity == "high"

    def test_parse_kerberoastable_user(self, tmp_path: Path):
        """Test detection of Kerberoastable users."""
        data = {
            "sAMAccountName": "svc_account",
            "distinguishedName": "CN=svc_account,DC=corp,DC=local",
            "userAccountControl": 512,
            "servicePrincipalName": ["MSSQLSvc/server.corp.local:1433"]
        }
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        kerb = [m for m in misconfigs if "Kerberoastable" in m.title]
        assert len(kerb) >= 1

    def test_parse_password_not_required(self, tmp_path: Path):
        """Test detection of users with PASSWD_NOTREQD flag."""
        data = {
            "sAMAccountName": "nopass",
            "distinguishedName": "CN=nopass,DC=corp,DC=local",
            "userAccountControl": 544  # 512 + 0x0020 (PASSWD_NOTREQD)
        }
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        passwd = [m for m in misconfigs if "Password not required" in m.title]
        assert len(passwd) >= 1
        assert passwd[0].severity == "high"

    # =========================================================================
    # Computer Parsing Tests
    # =========================================================================

    def test_parse_computer(self, tmp_path: Path):
        """Test parsing computer from JSON."""
        data = {
            "sAMAccountName": "WKS01$",
            "distinguishedName": "CN=WKS01,OU=Computers,DC=corp,DC=local",
            "operatingSystem": "Windows 10 Enterprise",
            "operatingSystemVersion": "10.0 (19041)",
            "userAccountControl": 4096,
            "objectClass": ["computer"]
        }
        json_file = tmp_path / "ldeep_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WKS01"
        assert "Windows 10" in (hosts[0].os or "")

    def test_parse_domain_controller(self, tmp_path: Path):
        """Test parsing domain controller."""
        data = {
            "sAMAccountName": "DC01$",
            "distinguishedName": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
            "operatingSystem": "Windows Server 2019",
            "userAccountControl": 532480,
            "objectClass": ["computer"]
        }
        json_file = tmp_path / "ldeep_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        dc_hosts = [h for h in hosts if h.is_dc]
        assert len(dc_hosts) >= 1

    def test_parse_unconstrained_delegation(self, tmp_path: Path):
        """Test detection of unconstrained delegation."""
        data = {
            "sAMAccountName": "SRV01$",
            "distinguishedName": "CN=SRV01,OU=Computers,DC=corp,DC=local",
            "userAccountControl": 528384,  # 4096 + 0x80000 (TRUSTED_FOR_DELEGATION)
            "objectClass": ["computer"]
        }
        json_file = tmp_path / "ldeep_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = [m for m in misconfigs if "Unconstrained Delegation" in m.title]
        assert len(delegation) >= 1
        assert delegation[0].severity == "critical"

    def test_parse_constrained_delegation(self, tmp_path: Path):
        """Test detection of constrained delegation."""
        data = {
            "sAMAccountName": "SRV02$",
            "distinguishedName": "CN=SRV02,OU=Computers,DC=corp,DC=local",
            "userAccountControl": 16781312,  # 4096 + 0x1000000 (TRUSTED_TO_AUTH_FOR_DELEGATION)
            "msDS-AllowedToDelegateTo": ["cifs/dc01.corp.local"],
            "objectClass": ["computer"]
        }
        json_file = tmp_path / "ldeep_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = [m for m in misconfigs if "Constrained Delegation" in m.title]
        assert len(delegation) >= 1
        assert delegation[0].severity == "high"

    def test_parse_rbcd(self, tmp_path: Path):
        """Test detection of RBCD configuration."""
        data = {
            "sAMAccountName": "SRV03$",
            "distinguishedName": "CN=SRV03,OU=Computers,DC=corp,DC=local",
            "userAccountControl": 4096,
            "msDS-AllowedToActOnBehalfOfOtherIdentity": "O:SYD:...",
            "objectClass": ["computer"]
        }
        json_file = tmp_path / "ldeep_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        rbcd = [m for m in misconfigs if "RBCD" in m.title]
        assert len(rbcd) >= 1

    # =========================================================================
    # Delegation File Tests
    # =========================================================================

    def test_parse_delegation_file(self, tmp_path: Path):
        """Test parsing delegation-specific file."""
        data = {
            "sAMAccountName": "WEB01$",
            "userAccountControl": 528384  # Unconstrained delegation
        }
        json_file = tmp_path / "ldeep_delegation.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        misconfigs = self.get_misconfigurations(entities)
        # Should detect delegation
        assert len(hosts) >= 1
        delegation_findings = [m for m in misconfigs if "Delegation" in m.title]
        assert len(delegation_findings) >= 1

    # =========================================================================
    # Trust Parsing Tests
    # =========================================================================

    def test_parse_trusts(self, tmp_path: Path):
        """Test parsing domain trusts."""
        data = {
            "trustPartner": "PARTNER.LOCAL",
            "trustDirection": "Bidirectional"
        }
        json_file = tmp_path / "ldeep_trusts.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        trusted = [h for h in hosts if "trusted-domain" in h.tags]
        assert len(trusted) >= 1

    # =========================================================================
    # gMSA Parsing Tests
    # =========================================================================

    def test_parse_gmsa(self, tmp_path: Path):
        """Test parsing gMSA account."""
        data = {
            "sAMAccountName": "gmsa_account$",
            "PrincipalsAllowedToRetrieveManagedPassword": ["CN=Web Servers,DC=corp,DC=local"]
        }
        json_file = tmp_path / "ldeep_gmsa.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        gmsa_users = [u for u in users if "gmsa" in u.tags]
        assert len(gmsa_users) >= 1

        misconfigs = self.get_misconfigurations(entities)
        gmsa_readable = [m for m in misconfigs if "gMSA Password Readable" in m.title]
        assert len(gmsa_readable) >= 1

    # =========================================================================
    # LAPS Parsing Tests
    # =========================================================================

    def test_parse_laps(self, tmp_path: Path):
        """Test parsing LAPS password readable finding."""
        data = {
            "sAMAccountName": "WKS01$",
            "ms-Mcs-AdmPwd": "RandomP@ssword123"
        }
        json_file = tmp_path / "ldeep_laps.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        laps = [m for m in misconfigs if "LAPS Password Readable" in m.title]
        assert len(laps) >= 1
        assert laps[0].severity == "high"

    # =========================================================================
    # Format Variations Tests
    # =========================================================================

    def test_parse_array_format(self, tmp_path: Path):
        """Test parsing array of entries."""
        data = [
            {"sAMAccountName": "user1", "userAccountControl": 512},
            {"sAMAccountName": "user2", "userAccountControl": 512}
        ]
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_parse_jsonlines_format(self, tmp_path: Path):
        """Test parsing JSON lines format."""
        content = '{"sAMAccountName": "user1"}\n{"sAMAccountName": "user2"}'
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(content)

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_parse_text_format(self, tmp_path: Path):
        """Test parsing text output format."""
        content = """sAMAccountName: testuser
distinguishedName: CN=testuser,DC=corp,DC=local

sAMAccountName: anotheruser
distinguishedName: CN=anotheruser,DC=corp,DC=local
"""
        txt_file = tmp_path / "ldeep_output.txt"
        txt_file.write_text(content)

        parser = LdeepParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_json(self, tmp_path: Path):
        """Test handling of empty JSON."""
        json_file = tmp_path / "ldeep_empty.json"
        json_file.write_text("[]")

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_sam(self, tmp_path: Path):
        """Test handling of entry without sAMAccountName."""
        data = {"distinguishedName": "CN=unknown,DC=corp,DC=local"}
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_skips_computer_accounts_as_users(self, tmp_path: Path):
        """Test that computer accounts (ending with $) are not parsed as users."""
        data = {"sAMAccountName": "COMPUTER$", "userAccountControl": 4096}
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        # Computer accounts should be parsed as hosts, not users
        user_names = [u.username for u in users]
        assert "COMPUTER$" not in user_names

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_ldeep(self, tmp_path: Path):
        """Test that source is set to ldeep."""
        data = {"sAMAccountName": "testuser", "userAccountControl": 512}
        json_file = tmp_path / "ldeep_users.json"
        json_file.write_text(json.dumps(data))

        parser = LdeepParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "ldeep"
