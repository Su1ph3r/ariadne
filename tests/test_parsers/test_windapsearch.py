"""Tests for windapsearch parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.windapsearch import WindapsearchParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestWindapsearchParser(BaseParserTest):
    """Test WindapsearchParser functionality."""

    parser_class = WindapsearchParser
    expected_name = "windapsearch"
    expected_patterns = ["*windapsearch*.txt", "*windapsearch*.json", "*ldap_enum*.txt"]
    expected_entity_types = ["Host", "User", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_windapsearch_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        data = {"sAMAccountName": "testuser", "distinguishedName": "CN=testuser,DC=corp,DC=local"}
        json_file = tmp_path / "windapsearch_users.json"
        json_file.write_text(json.dumps(data))

        assert WindapsearchParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        data = {
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=jsmith,OU=Users,DC=corp,DC=local",
            "userAccountControl": 512
        }
        json_file = tmp_path / "output.json"
        json_file.write_text(json.dumps(data))

        assert WindapsearchParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not WindapsearchParser.can_parse(json_file)

    # =========================================================================
    # JSON User Parsing Tests
    # =========================================================================

    def test_parse_json_user(self, tmp_path: Path):
        """Test parsing user from JSON."""
        data = {
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=jsmith,OU=Users,DC=corp,DC=local",
            "displayName": "John Smith",
            "mail": "jsmith@corp.local",
            "userAccountControl": 512,
            "objectClass": ["user", "person"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
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
            "userAccountControl": 514,  # 512 + 2 (ACCOUNTDISABLE)
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
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
            "memberOf": ["CN=Domain Admins,OU=Groups,DC=corp,DC=local"],
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].is_admin == True

    def test_parse_asreproastable_user(self, tmp_path: Path):
        """Test detection of AS-REP roastable users."""
        data = {
            "sAMAccountName": "asrepuser",
            "distinguishedName": "CN=asrepuser,DC=corp,DC=local",
            "userAccountControl": 4194816,  # 512 + 0x400000 (DONT_REQ_PREAUTH)
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
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
            "servicePrincipalName": ["MSSQLSvc/server.corp.local:1433"],
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        kerb = [m for m in misconfigs if "Kerberoastable" in m.title]
        assert len(kerb) >= 1

    def test_parse_password_not_required(self, tmp_path: Path):
        """Test detection of users with PASSWD_NOTREQD flag."""
        data = {
            "sAMAccountName": "nopass",
            "distinguishedName": "CN=nopass,DC=corp,DC=local",
            "userAccountControl": 544,  # 512 + 0x0020 (PASSWD_NOTREQD)
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        passwd = [m for m in misconfigs if "Password not required" in m.title]
        assert len(passwd) >= 1
        assert passwd[0].severity == "high"

    # =========================================================================
    # JSON Computer Parsing Tests
    # =========================================================================

    def test_parse_json_computer(self, tmp_path: Path):
        """Test parsing computer from JSON."""
        data = {
            "sAMAccountName": "WKS01$",
            "distinguishedName": "CN=WKS01,OU=Computers,DC=corp,DC=local",
            "operatingSystem": "Windows 10 Enterprise",
            "operatingSystemVersion": "10.0 (19041)",
            "userAccountControl": 4096,
            "objectClass": ["computer"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
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
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
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
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = [m for m in misconfigs if "Unconstrained Delegation" in m.title]
        assert len(delegation) >= 1
        assert delegation[0].severity == "critical"

    # =========================================================================
    # Text Format Parsing Tests
    # =========================================================================

    def test_parse_text_user(self, tmp_path: Path):
        """Test parsing user from text output."""
        content = """dn: CN=testuser,OU=Users,DC=corp,DC=local
sAMAccountName: testuser
displayName: Test User

dn: CN=anotheruser,OU=Users,DC=corp,DC=local
sAMAccountName: anotheruser
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_parse_text_computer(self, tmp_path: Path):
        """Test parsing computer from text output."""
        content = """dn: CN=WKS01,OU=Computers,DC=corp,DC=local
sAMAccountName: WKS01$
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WKS01"

    def test_parse_text_domain_controller(self, tmp_path: Path):
        """Test parsing DC from text output."""
        content = """dn: CN=DC01,OU=Domain Controllers,DC=corp,DC=local
sAMAccountName: DC01$
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        dc_hosts = [h for h in hosts if h.is_dc]
        assert len(dc_hosts) >= 1

    def test_parse_text_kerberoastable(self, tmp_path: Path):
        """Test parsing Kerberoastable user from text."""
        content = """dn: CN=svc_sql,OU=Users,DC=corp,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql.corp.local:1433
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        kerb = [m for m in misconfigs if "Kerberoastable" in m.title]
        assert len(kerb) >= 1

    def test_parse_text_asreproastable(self, tmp_path: Path):
        """Test parsing AS-REP roastable user from text."""
        content = """dn: CN=asrepuser,OU=Users,DC=corp,DC=local
sAMAccountName: asrepuser
userAccountControl: 4194816
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        asrep = [m for m in misconfigs if "AS-REP" in m.title]
        assert len(asrep) >= 1

    def test_parse_text_unconstrained_delegation(self, tmp_path: Path):
        """Test parsing unconstrained delegation from text."""
        # The parser checks for TRUSTED_FOR_DELEGATION string or UAC 524288
        content = """dn: CN=SRV01,OU=Computers,DC=corp,DC=local
sAMAccountName: SRV01$
TRUSTED_FOR_DELEGATION
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = [m for m in misconfigs if "Unconstrained Delegation" in m.title]
        assert len(delegation) >= 1

    def test_parse_text_admin_user(self, tmp_path: Path):
        """Test parsing admin user from text."""
        content = """dn: CN=admin,OU=Users,DC=corp,DC=local
sAMAccountName: admin
memberOf: CN=Domain Admins,OU=Groups,DC=corp,DC=local
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        admin_users = [u for u in users if u.is_admin]
        assert len(admin_users) >= 1

    # =========================================================================
    # Format Variations Tests
    # =========================================================================

    def test_parse_json_array(self, tmp_path: Path):
        """Test parsing array of entries."""
        data = [
            {"sAMAccountName": "user1", "userAccountControl": 512, "objectClass": ["user"]},
            {"sAMAccountName": "user2", "userAccountControl": 512, "objectClass": ["user"]}
        ]
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_extracts_groups_from_memberof(self, tmp_path: Path):
        """Test extraction of groups from memberOf."""
        data = {
            "sAMAccountName": "testuser",
            "distinguishedName": "CN=testuser,DC=corp,DC=local",
            "userAccountControl": 512,
            "memberOf": [
                "CN=IT Staff,OU=Groups,DC=corp,DC=local",
                "CN=VPN Users,OU=Groups,DC=corp,DC=local"
            ],
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert "IT Staff" in users[0].groups
        assert "VPN Users" in users[0].groups

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_json(self, tmp_path: Path):
        """Test handling of empty JSON."""
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text("[]")

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_empty_text(self, tmp_path: Path):
        """Test handling of empty text file."""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text("")

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_sam(self, tmp_path: Path):
        """Test handling of entry without sAMAccountName."""
        data = {
            "distinguishedName": "CN=unknown,DC=corp,DC=local",
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_deduplicates_users_in_text(self, tmp_path: Path):
        """Test that duplicate users are not created in text parsing."""
        content = """dn: CN=testuser,OU=Users,DC=corp,DC=local
sAMAccountName: testuser

dn: CN=testuser,OU=Users,DC=corp,DC=local
sAMAccountName: testuser
"""
        txt_file = tmp_path / "windapsearch.txt"
        txt_file.write_text(content)

        parser = WindapsearchParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        testusers = [u for u in users if u.username.lower() == "testuser"]
        assert len(testusers) == 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_windapsearch(self, tmp_path: Path):
        """Test that source is set to windapsearch."""
        data = {
            "sAMAccountName": "testuser",
            "userAccountControl": 512,
            "objectClass": ["user"]
        }
        json_file = tmp_path / "windapsearch.json"
        json_file.write_text(json.dumps(data))

        parser = WindapsearchParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "windapsearch"
