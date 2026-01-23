"""Tests for PowerView parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.powerview import PowerViewParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from .base import BaseParserTest


class TestPowerViewParser(BaseParserTest):
    """Test PowerViewParser functionality."""

    parser_class = PowerViewParser
    expected_name = "powerview"
    expected_patterns = ["*powerview*.txt", "*powerview*.json", "*sharpview*.txt", "*Get-Domain*.txt"]
    expected_entity_types = ["Host", "User", "Misconfiguration", "Relationship"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_powerview_json(self, tmp_path: Path):
        """Test detection of PowerView JSON output."""
        data = {
            "samaccountname": "admin",
            "distinguishedname": "CN=admin,CN=Users,DC=corp,DC=local"
        }
        json_file = tmp_path / "powerview_users.json"
        json_file.write_text(json.dumps(data))

        assert PowerViewParser.can_parse(json_file)

    def test_can_parse_powerview_txt(self, tmp_path: Path):
        """Test detection of PowerView text output."""
        lines = [
            "samaccountname: admin",
            "distinguishedname: CN=admin,CN=Users,DC=corp,DC=local",
        ]
        txt_file = tmp_path / "Get-DomainUser.txt"
        txt_file.write_text("\n".join(lines))

        assert PowerViewParser.can_parse(txt_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not PowerViewParser.can_parse(json_file)

    # =========================================================================
    # User Parsing Tests
    # =========================================================================

    def test_parse_json_user(self, tmp_path: Path):
        """Test parsing user object from JSON."""
        data = {
            "samaccountname": "jsmith",
            "distinguishedname": "CN=John Smith,CN=Users,DC=corp,DC=local",
            "displayname": "John Smith",
            "useraccountcontrol": 512
        }
        json_file = tmp_path / "powerview_user.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "corp.local"

    def test_parse_json_disabled_user(self, tmp_path: Path):
        """Test parsing disabled user."""
        data = {
            "samaccountname": "disabled_user",
            "distinguishedname": "CN=Disabled,CN=Users,DC=corp,DC=local",
            "useraccountcontrol": 514  # 512 + 2 (ACCOUNTDISABLE)
        }
        json_file = tmp_path / "powerview_user.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].enabled == False

    def test_parse_json_asreproastable_user(self, tmp_path: Path):
        """Test parsing AS-REP roastable user."""
        data = {
            "samaccountname": "asrep_user",
            "distinguishedname": "CN=asrep_user,CN=Users,DC=corp,DC=local",
            "useraccountcontrol": 4194816  # 512 + 4194304 (DONT_REQ_PREAUTH)
        }
        json_file = tmp_path / "powerview_user.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        asrep = [m for m in misconfigs if "AS-REP" in m.title]
        assert len(asrep) >= 1
        assert asrep[0].severity == "high"

    def test_parse_json_kerberoastable_user(self, tmp_path: Path):
        """Test parsing Kerberoastable user."""
        data = {
            "samaccountname": "svc_sql",
            "distinguishedname": "CN=svc_sql,CN=Users,DC=corp,DC=local",
            "useraccountcontrol": 512,
            "serviceprincipalname": ["MSSQLSvc/sql01.corp.local:1433"]
        }
        json_file = tmp_path / "powerview_user.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        kerb = [m for m in misconfigs if "Kerberoastable" in m.title]
        assert len(kerb) >= 1
        assert "kerberoast" in kerb[0].tags

    def test_parse_json_unconstrained_delegation_user(self, tmp_path: Path):
        """Test parsing user with unconstrained delegation."""
        data = {
            "samaccountname": "deleg_user",
            "distinguishedname": "CN=deleg_user,CN=Users,DC=corp,DC=local",
            "useraccountcontrol": 524800  # 512 + 524288 (TRUSTED_FOR_DELEGATION)
        }
        json_file = tmp_path / "powerview_user.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        deleg = [m for m in misconfigs if "Unconstrained Delegation" in m.title]
        assert len(deleg) >= 1
        assert deleg[0].severity == "critical"

    # =========================================================================
    # Computer Parsing Tests
    # =========================================================================

    def test_parse_json_computer(self, tmp_path: Path):
        """Test parsing computer object from JSON."""
        data = {
            "samaccountname": "WS01$",
            "dnshostname": "WS01.corp.local",
            "distinguishedname": "CN=WS01,CN=Computers,DC=corp,DC=local",
            "operatingsystem": "Windows 10 Enterprise",
            "operatingsystemversion": "10.0 (19041)"
        }
        json_file = tmp_path / "powerview_computer.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WS01.corp.local"
        assert "Windows 10" in hosts[0].os

    def test_parse_json_computer_unconstrained_delegation(self, tmp_path: Path):
        """Test parsing computer with unconstrained delegation."""
        data = {
            "samaccountname": "DC01$",
            "dnshostname": "DC01.corp.local",
            "distinguishedname": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
            "useraccountcontrol": 532480  # includes TRUSTED_FOR_DELEGATION
        }
        json_file = tmp_path / "powerview_computer.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        deleg = [m for m in misconfigs if "Unconstrained" in m.title]
        assert len(deleg) >= 1

    # =========================================================================
    # Session Parsing Tests
    # =========================================================================

    def test_parse_json_session(self, tmp_path: Path):
        """Test parsing session information."""
        data = {
            "ComputerName": "WS01.corp.local",
            "UserName": "jsmith"
        }
        json_file = tmp_path / "powerview_netsession.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        session = [m for m in misconfigs if "Session" in m.title]
        assert len(session) >= 1

    # =========================================================================
    # Local Admin Parsing Tests
    # =========================================================================

    def test_parse_json_local_admin(self, tmp_path: Path):
        """Test parsing local admin membership."""
        data = {
            "ComputerName": "WS01.corp.local",
            "GroupName": "Administrators",
            "MemberName": "CORP\\Domain Admins"
        }
        json_file = tmp_path / "powerview_localadmin.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        admin = [m for m in misconfigs if "Local Admin" in m.title]
        assert len(admin) >= 1

    # =========================================================================
    # ACL Parsing Tests
    # =========================================================================

    def test_parse_json_dangerous_acl(self, tmp_path: Path):
        """Test parsing dangerous ACL."""
        data = {
            "ObjectDN": "CN=admin,CN=Users,DC=corp,DC=local",
            "ActiveDirectoryRights": "GenericAll",
            "IdentityReference": "CORP\\helpdesk"
        }
        json_file = tmp_path / "powerview_objectacl.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        acl = [m for m in misconfigs if "ACL" in m.title]
        assert len(acl) >= 1
        assert acl[0].severity == "high"

    # =========================================================================
    # Text Parsing Tests
    # =========================================================================

    def test_parse_text_user(self, tmp_path: Path):
        """Test parsing user from text output."""
        content = """samaccountname: jsmith
distinguishedname: CN=jsmith,CN=Users,DC=corp,DC=local
useraccountcontrol: 512"""
        txt_file = tmp_path / "powerview_user.txt"
        txt_file.write_text(content)

        parser = PowerViewParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "powerview_empty.json"
        json_file.write_text("")

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "powerview.json"
        json_file.write_text("{invalid json}")

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_skips_computer_accounts_in_user_parsing(self, tmp_path: Path):
        """Test that computer accounts are not parsed as users."""
        data = {
            "samaccountname": "WS01$",
            "distinguishedname": "CN=WS01,CN=Computers,DC=corp,DC=local"
        }
        json_file = tmp_path / "powerview_user.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        # Computer accounts (ending with $) should not be parsed as users
        user_sams = [u.username for u in users]
        assert "WS01$" not in user_sams

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_powerview(self, tmp_path: Path):
        """Test that source is set to powerview."""
        data = {
            "samaccountname": "jsmith",
            "distinguishedname": "CN=jsmith,CN=Users,DC=corp,DC=local"
        }
        json_file = tmp_path / "powerview.json"
        json_file.write_text(json.dumps(data))

        parser = PowerViewParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "powerview"
