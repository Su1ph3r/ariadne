"""Tests for BloodHound parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.bloodhound import BloodHoundParser
from ariadne.models.asset import Host, User
from ariadne.models.relationship import Relationship, RelationType
from .base import BaseParserTest


class TestBloodHoundParser(BaseParserTest):
    """Test BloodHoundParser functionality."""

    parser_class = BloodHoundParser
    expected_name = "bloodhound"
    expected_patterns = ["*.json"]
    expected_entity_types = ["Host", "User", "Relationship"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_users_json(self, tmp_path: Path):
        """Test detection of BloodHound users JSON."""
        data = {
            "meta": {"count": 1, "type": "users", "version": 5},
            "data": [{"Properties": {"name": "ADMIN@CORP.LOCAL"}, "ObjectIdentifier": "S-1-5-21-1"}]
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        assert BloodHoundParser.can_parse(json_file)

    def test_can_parse_computers_json(self, tmp_path: Path):
        """Test detection of BloodHound computers JSON."""
        data = {
            "meta": {"count": 1, "type": "computers", "version": 5},
            "data": [{"Properties": {"name": "DC01.CORP.LOCAL"}, "ObjectIdentifier": "S-1-5-21-1"}]
        }
        json_file = tmp_path / "computers.json"
        json_file.write_text(json.dumps(data))

        assert BloodHoundParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is not parsed as BloodHound."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"not": "bloodhound"}')

        assert not BloodHoundParser.can_parse(json_file)

    def test_cannot_parse_nessus_json(self, tmp_path: Path):
        """Test that other security tool JSON is rejected."""
        json_file = tmp_path / "nessus.json"
        json_file.write_text('{"findings": []}')

        assert not BloodHoundParser.can_parse(json_file)

    # =========================================================================
    # User Parsing Tests
    # =========================================================================

    def test_parse_users(self, tmp_path: Path):
        """Test parsing BloodHound users."""
        data = {
            "meta": {"count": 2, "type": "users", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "ADMIN@CORP.LOCAL",
                        "samaccountname": "admin",
                        "domain": "CORP.LOCAL",
                        "enabled": True,
                        "admincount": True,
                        "displayname": "Administrator",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-500",
                    "Aces": [],
                    "MemberOf": [],
                },
                {
                    "Properties": {
                        "name": "JSMITH@CORP.LOCAL",
                        "samaccountname": "jsmith",
                        "domain": "CORP.LOCAL",
                        "enabled": True,
                        "admincount": False,
                        "displayname": "John Smith",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1001",
                    "Aces": [],
                    "MemberOf": [],
                },
            ],
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) == 2

        admin = next((u for u in users if u.username == "admin"), None)
        assert admin is not None
        assert admin.domain == "CORP.LOCAL"
        assert admin.is_admin is True
        assert admin.enabled is True
        assert admin.source == "bloodhound"

        jsmith = next((u for u in users if u.username == "jsmith"), None)
        assert jsmith is not None
        assert jsmith.is_admin is False

    def test_parse_user_with_password_settings(self, tmp_path: Path):
        """Test parsing user with password-related properties."""
        data = {
            "meta": {"count": 1, "type": "users", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "SVC_SQL@CORP.LOCAL",
                        "samaccountname": "svc_sql",
                        "domain": "CORP.LOCAL",
                        "enabled": True,
                        "pwdneverexpires": True,
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1100",
                    "Aces": [],
                    "MemberOf": [],
                },
            ],
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) == 1
        assert users[0].password_never_expires is True

    # =========================================================================
    # Computer Parsing Tests
    # =========================================================================

    def test_parse_computers(self, tmp_path: Path):
        """Test parsing BloodHound computers."""
        data = {
            "meta": {"count": 2, "type": "computers", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "DC01.CORP.LOCAL",
                        "domain": "CORP.LOCAL",
                        "operatingsystem": "Windows Server 2019",
                        "isdc": True,
                        "enabled": True,
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1000",
                    "Aces": [],
                },
                {
                    "Properties": {
                        "name": "WS01.CORP.LOCAL",
                        "domain": "CORP.LOCAL",
                        "operatingsystem": "Windows 10",
                        "isdc": False,
                        "enabled": True,
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1001",
                    "Aces": [],
                },
            ],
        }
        json_file = tmp_path / "computers.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 2

        dc = next((h for h in hosts if h.is_dc), None)
        assert dc is not None
        assert "dc01" in dc.hostname.lower()
        assert dc.os == "Windows Server 2019"
        assert dc.source == "bloodhound"

        ws = next((h for h in hosts if not h.is_dc), None)
        assert ws is not None
        assert ws.os == "Windows 10"

    # =========================================================================
    # ACE/Relationship Parsing Tests
    # =========================================================================

    def test_parse_generic_all_ace(self, tmp_path: Path):
        """Test parsing GenericAll ACE into relationship."""
        data = {
            "meta": {"count": 1, "type": "users", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "JSMITH@CORP.LOCAL",
                        "samaccountname": "jsmith",
                        "domain": "CORP.LOCAL",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1001",
                    "Aces": [
                        {
                            "RightName": "GenericAll",
                            "PrincipalSID": "S-1-5-21-123-1100",
                            "PrincipalType": "User",
                            "IsInherited": False,
                        }
                    ],
                    "MemberOf": [],
                },
            ],
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        generic_all = [r for r in relationships if r.relation_type == RelationType.HAS_GENERIC_ALL]
        assert len(generic_all) >= 1
        assert generic_all[0].source_id == "S-1-5-21-123-1100"

    def test_parse_force_change_password_ace(self, tmp_path: Path):
        """Test parsing ForceChangePassword ACE."""
        data = {
            "meta": {"count": 1, "type": "users", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "TARGET@CORP.LOCAL",
                        "samaccountname": "target",
                        "domain": "CORP.LOCAL",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1001",
                    "Aces": [
                        {
                            "RightName": "ForceChangePassword",
                            "PrincipalSID": "S-1-5-21-123-1100",
                            "PrincipalType": "User",
                        }
                    ],
                    "MemberOf": [],
                },
            ],
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        force_pw = [r for r in relationships if r.relation_type == RelationType.CAN_FORCE_CHANGE_PASSWORD]
        assert len(force_pw) >= 1

    def test_parse_read_laps_ace(self, tmp_path: Path):
        """Test parsing ReadLAPSPassword ACE."""
        data = {
            "meta": {"count": 1, "type": "computers", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "WS01.CORP.LOCAL",
                        "domain": "CORP.LOCAL",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-1000",
                    "Aces": [
                        {
                            "RightName": "ReadLAPSPassword",
                            "PrincipalSID": "S-1-5-21-123-512",
                            "PrincipalType": "Group",
                        }
                    ],
                },
            ],
        }
        json_file = tmp_path / "computers.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        laps = [r for r in relationships if r.relation_type == RelationType.CAN_READ_LAPS]
        assert len(laps) >= 1

    # =========================================================================
    # Membership Parsing Tests
    # =========================================================================

    def test_parse_membership_relationships(self, tmp_path: Path):
        """Test parsing MemberOf relationships from users."""
        data = {
            "meta": {"count": 1, "type": "users", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "ADMIN@CORP.LOCAL",
                        "samaccountname": "admin",
                        "domain": "CORP.LOCAL",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-500",
                    "Aces": [],
                    "MemberOf": [
                        {"ObjectIdentifier": "S-1-5-21-123-512"},
                        {"ObjectIdentifier": "S-1-5-21-123-519"},
                    ],
                },
            ],
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        member_of = [r for r in relationships if r.relation_type == RelationType.MEMBER_OF]
        assert len(member_of) >= 2

    # =========================================================================
    # Groups Parsing Tests
    # =========================================================================

    def test_parse_group_members(self, tmp_path: Path):
        """Test parsing group members into relationships."""
        data = {
            "meta": {"count": 1, "type": "groups", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "DOMAIN ADMINS@CORP.LOCAL",
                        "domain": "CORP.LOCAL",
                    },
                    "ObjectIdentifier": "S-1-5-21-123-512",
                    "Members": [
                        {"ObjectIdentifier": "S-1-5-21-123-500", "ObjectType": "User"},
                        {"ObjectIdentifier": "S-1-5-21-123-501", "ObjectType": "User"},
                    ],
                    "Aces": [],
                },
            ],
        }
        json_file = tmp_path / "groups.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        assert len(relationships) >= 2
        for r in relationships:
            assert r.target_id == "S-1-5-21-123-512"

    # =========================================================================
    # Domain Trust Parsing Tests
    # =========================================================================

    def test_parse_domain_trusts(self, tmp_path: Path):
        """Test parsing domain trust relationships."""
        data = {
            "meta": {"count": 1, "type": "domains", "version": 5},
            "data": [
                {
                    "Properties": {
                        "name": "CORP.LOCAL",
                    },
                    "ObjectIdentifier": "S-1-5-21-123",
                    "Trusts": [
                        {
                            "TargetDomainSid": "S-1-5-21-456",
                            "TargetDomainName": "PARTNER.LOCAL",
                            "TrustType": "External",
                            "TrustDirection": "Bidirectional",
                            "IsTransitive": False,
                        }
                    ],
                },
            ],
        }
        json_file = tmp_path / "domains.json"
        json_file.write_text(json.dumps(data))

        parser = BloodHoundParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        trusts = [r for r in relationships if r.relation_type == RelationType.TRUSTS]
        assert len(trusts) >= 1
        assert trusts[0].properties.get("trust_type") == "External"
