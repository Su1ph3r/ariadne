"""Tests for LDAPDomainDump parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.ldapdomaindump import LDAPDomainDumpParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from .base import BaseParserTest


class TestLDAPDomainDumpParser(BaseParserTest):
    """Test LDAPDomainDumpParser functionality."""

    parser_class = LDAPDomainDumpParser
    expected_name = "ldapdomaindump"
    expected_patterns = [
        "domain_users*.json",
        "domain_groups*.json",
        "domain_computers*.json",
        "domain_trusts*.json",
        "*ldapdomaindump*.json",
    ]
    expected_entity_types = ["Host", "User", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_domain_users_json(self, tmp_path: Path):
        """Test detection of domain users JSON file."""
        data = [{
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=jsmith,CN=Users,DC=corp,DC=local",
            "userAccountControl": 512
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        assert LDAPDomainDumpParser.can_parse(json_file)

    def test_can_parse_domain_computers_json(self, tmp_path: Path):
        """Test detection of domain computers JSON file."""
        data = [{
            "sAMAccountName": "WS01$",
            "distinguishedName": "CN=WS01,CN=Computers,DC=corp,DC=local",
            "operatingSystem": "Windows 10"
        }]
        json_file = tmp_path / "domain_computers.json"
        json_file.write_text(json.dumps(data))

        assert LDAPDomainDumpParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not LDAPDomainDumpParser.can_parse(json_file)

    # =========================================================================
    # User Parsing Tests
    # =========================================================================

    def test_parse_user(self, tmp_path: Path):
        """Test parsing user from JSON."""
        data = [{
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=John Smith,CN=Users,DC=corp,DC=local",
            "displayName": "John Smith",
            "mail": "jsmith@corp.local",
            "userAccountControl": 512
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "corp.local"
        assert users[0].display_name == "John Smith"
        assert users[0].email == "jsmith@corp.local"

    def test_parse_disabled_user(self, tmp_path: Path):
        """Test parsing disabled user."""
        data = [{
            "sAMAccountName": "disabled_user",
            "distinguishedName": "CN=disabled,CN=Users,DC=corp,DC=local",
            "userAccountControl": 514  # 512 + 2 (ACCOUNTDISABLE)
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].enabled == False

    def test_parse_admin_user(self, tmp_path: Path):
        """Test parsing admin user (member of privileged group)."""
        data = [{
            "sAMAccountName": "admin",
            "distinguishedName": "CN=admin,CN=Users,DC=corp,DC=local",
            "userAccountControl": 512,
            "memberOf": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"]
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].is_admin == True

    def test_parse_password_not_required(self, tmp_path: Path):
        """Test detection of PASSWD_NOTREQD flag."""
        data = [{
            "sAMAccountName": "pwdnotreq_user",
            "distinguishedName": "CN=pwdnotreq,CN=Users,DC=corp,DC=local",
            "userAccountControl": 544  # 512 + 32 (PASSWD_NOTREQD)
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        passwd_notreq = [m for m in misconfigs if "Password not required" in m.title]
        assert len(passwd_notreq) >= 1
        assert passwd_notreq[0].severity == "high"

    def test_parse_asreproastable_user(self, tmp_path: Path):
        """Test detection of AS-REP roastable user."""
        data = [{
            "sAMAccountName": "asrep_user",
            "distinguishedName": "CN=asrep,CN=Users,DC=corp,DC=local",
            "userAccountControl": 4194816  # 512 + 4194304 (DONT_REQ_PREAUTH)
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        asrep = [m for m in misconfigs if "pre-auth disabled" in m.title]
        assert len(asrep) >= 1
        assert "asreproast" in asrep[0].tags

    def test_parse_kerberoastable_user(self, tmp_path: Path):
        """Test detection of Kerberoastable service account."""
        data = [{
            "sAMAccountName": "svc_sql",
            "distinguishedName": "CN=svc_sql,CN=Users,DC=corp,DC=local",
            "userAccountControl": 512,
            "servicePrincipalName": ["MSSQLSvc/sql01.corp.local:1433"]
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        kerb = [m for m in misconfigs if "Kerberoastable" in m.title]
        assert len(kerb) >= 1
        assert "kerberoast" in kerb[0].tags

    # =========================================================================
    # Computer Parsing Tests
    # =========================================================================

    def test_parse_computer(self, tmp_path: Path):
        """Test parsing computer from JSON."""
        data = [{
            "sAMAccountName": "WS01$",
            "dNSHostName": "WS01.corp.local",
            "distinguishedName": "CN=WS01,CN=Computers,DC=corp,DC=local",
            "operatingSystem": "Windows 10 Enterprise",
            "operatingSystemServicePack": "Build 19041",
            "userAccountControl": 4096
        }]
        json_file = tmp_path / "domain_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "WS01" in hosts[0].hostname
        assert "Windows 10" in hosts[0].os

    def test_parse_outdated_os(self, tmp_path: Path):
        """Test detection of outdated operating systems."""
        data = [{
            "sAMAccountName": "OLD_SERVER$",
            "distinguishedName": "CN=OLD_SERVER,CN=Computers,DC=corp,DC=local",
            "operatingSystem": "Windows Server 2003",
            "userAccountControl": 4096
        }]
        json_file = tmp_path / "domain_computers.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        outdated = [m for m in misconfigs if "Outdated OS" in m.title]
        assert len(outdated) >= 1

    # =========================================================================
    # Group Parsing Tests
    # =========================================================================

    def test_parse_large_privileged_group(self, tmp_path: Path):
        """Test detection of large privileged groups."""
        members = [f"CN=user{i},CN=Users,DC=corp,DC=local" for i in range(25)]
        data = [{
            "sAMAccountName": "Domain Admins",
            "distinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
            "member": members
        }]
        json_file = tmp_path / "domain_groups.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        large_group = [m for m in misconfigs if "Large privileged group" in m.title]
        assert len(large_group) >= 1

    # =========================================================================
    # Trust Parsing Tests
    # =========================================================================

    def test_parse_domain_trust(self, tmp_path: Path):
        """Test parsing domain trust."""
        data = [{
            "trustPartner": "partner.local",
            "trustDirection": "3",
            "trustType": "2"
        }]
        json_file = tmp_path / "domain_trusts.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "trusted-domain" in hosts[0].tags

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty JSON array."""
        json_file = tmp_path / "domain_users.json"
        json_file.write_text("[]")

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_attributes(self, tmp_path: Path):
        """Test handling of entries with missing attributes."""
        data = [{
            "sAMAccountName": "minimal_user"
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "minimal_user"

    def test_handles_list_attributes(self, tmp_path: Path):
        """Test handling of attributes that are lists."""
        data = [{
            "sAMAccountName": ["jsmith"],  # Sometimes LDAP returns as list
            "distinguishedName": ["CN=jsmith,CN=Users,DC=corp,DC=local"],
            "userAccountControl": ["512"]
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"

    def test_extracts_domain_from_dn(self, tmp_path: Path):
        """Test domain extraction from distinguished name."""
        data = [{
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=John Smith,OU=Employees,DC=sub,DC=corp,DC=local"
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].domain == "sub.corp.local"

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_ldapdomaindump(self, tmp_path: Path):
        """Test that source is set to ldapdomaindump."""
        data = [{
            "sAMAccountName": "jsmith",
            "distinguishedName": "CN=jsmith,CN=Users,DC=corp,DC=local"
        }]
        json_file = tmp_path / "domain_users.json"
        json_file.write_text(json.dumps(data))

        parser = LDAPDomainDumpParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "ldapdomaindump"
