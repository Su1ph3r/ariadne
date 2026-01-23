"""Tests for ADRecon parser."""

import pytest
from pathlib import Path

from ariadne.parsers.adrecon import ADReconParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestADReconParser(BaseParserTest):
    """Test ADReconParser functionality."""

    parser_class = ADReconParser
    expected_name = "adrecon"
    expected_patterns = [
        "*ADRecon*.csv",
        "*-Users.csv",
        "*-Computers.csv",
        "*-Groups.csv",
        "*-DomainControllers.csv",
        "*-GPOs.csv",
        "*-Trusts.csv",
    ]
    expected_entity_types = ["Host", "User", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_adrecon_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        content = """"Name","SamAccountName","Enabled"
"admin","admin","True"
"""
        csv_file = tmp_path / "ADRecon-Users.csv"
        csv_file.write_text(content)

        assert ADReconParser.can_parse(csv_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """"SamAccountName","DistinguishedName","UserPrincipalName","MemberOf"
"jsmith","CN=jsmith,OU=Users","jsmith@corp.local",""
"""
        csv_file = tmp_path / "users.csv"
        csv_file.write_text(content)

        assert ADReconParser.can_parse(csv_file)

    def test_cannot_parse_random_csv(self, tmp_path: Path):
        """Test that random CSV is rejected."""
        content = """"Column1","Column2"
"data1","data2"
"""
        csv_file = tmp_path / "random.csv"
        csv_file.write_text(content)

        assert not ADReconParser.can_parse(csv_file)

    # =========================================================================
    # Users Parsing Tests
    # =========================================================================

    def test_parse_users(self, tmp_path: Path):
        """Test parsing users from CSV."""
        content = """"Name","SamAccountName","Domain","Enabled","PasswordNeverExpires"
"John Smith","jsmith","CORP","True","False"
"""
        csv_file = tmp_path / "CORP-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "John Smith"
        assert users[0].enabled == True

    def test_parse_admin_user_by_group(self, tmp_path: Path):
        """Test detection of admin user by group membership."""
        content = """"Name","SamAccountName","Enabled","MemberOf"
"Admin User","admin","True","CN=Domain Admins,OU=Groups"
"""
        csv_file = tmp_path / "CORP-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].is_admin == True

    def test_parse_user_asreproast(self, tmp_path: Path):
        """Test detection of AS-REP roastable users."""
        content = """"Name","SamAccountName","Enabled","DoesNotRequirePreAuth"
"Weak User","weakuser","True","True"
"""
        csv_file = tmp_path / "CORP-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        asrep = [m for m in misconfigs if "AS-REP" in m.title]
        assert len(asrep) >= 1
        assert asrep[0].severity == "high"

    def test_parse_user_kerberoast(self, tmp_path: Path):
        """Test detection of Kerberoastable users."""
        content = """"Name","SamAccountName","Enabled","ServicePrincipalName"
"SVC Account","svc_account","True","MSSQLSvc/server.corp.local:1433"
"""
        csv_file = tmp_path / "CORP-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        kerb = [m for m in misconfigs if "Kerberoastable" in m.title]
        assert len(kerb) >= 1

    def test_parse_user_password_not_required(self, tmp_path: Path):
        """Test detection of users with PASSWD_NOTREQD flag."""
        content = """"Name","SamAccountName","Enabled","PasswordNotRequired"
"No Password","nopass","True","True"
"""
        csv_file = tmp_path / "CORP-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        passwd = [m for m in misconfigs if "Password not required" in m.title]
        assert len(passwd) >= 1
        assert passwd[0].severity == "high"

    # =========================================================================
    # Computers Parsing Tests
    # =========================================================================

    def test_parse_computers(self, tmp_path: Path):
        """Test parsing computers from CSV."""
        content = """"Name","DNSHostName","Domain","OperatingSystem","OperatingSystemVersion","Enabled"
"WKS01","wks01.corp.local","CORP","Windows 10 Enterprise","10.0 (19041)","True"
"""
        csv_file = tmp_path / "CORP-Computers.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WKS01"
        assert "Windows 10" in hosts[0].os

    def test_parse_computer_legacy_os(self, tmp_path: Path):
        """Test detection of legacy operating systems."""
        content = """"Name","DNSHostName","OperatingSystem","Enabled"
"OLD01","old01.corp.local","Windows Server 2003","True"
"""
        csv_file = tmp_path / "CORP-Computers.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        legacy = [m for m in misconfigs if "Legacy OS" in m.title]
        assert len(legacy) >= 1

    def test_parse_computer_unconstrained_delegation(self, tmp_path: Path):
        """Test detection of unconstrained delegation."""
        content = """"Name","DNSHostName","Enabled","TrustedForDelegation"
"SRV01","srv01.corp.local","True","True"
"""
        csv_file = tmp_path / "CORP-Computers.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = [m for m in misconfigs if "Unconstrained Delegation" in m.title]
        assert len(delegation) >= 1
        assert delegation[0].severity == "critical"

    # =========================================================================
    # Domain Controllers Parsing Tests
    # =========================================================================

    def test_parse_domain_controllers(self, tmp_path: Path):
        """Test parsing domain controllers from CSV."""
        content = """"Name","HostName","IPAddress","Domain","OperatingSystem"
"DC01","dc01.corp.local","192.168.1.10","CORP","Windows Server 2019"
"""
        csv_file = tmp_path / "CORP-DomainControllers.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].is_dc == True
        assert hosts[0].ip == "192.168.1.10"

    # =========================================================================
    # Groups Parsing Tests
    # =========================================================================

    def test_parse_large_privileged_group(self, tmp_path: Path):
        """Test detection of large privileged groups."""
        members = ";".join([f"user{i}" for i in range(25)])
        content = f""""Name","SamAccountName","Members"
"Domain Admins","Domain Admins","{members}"
"""
        csv_file = tmp_path / "CORP-Groups.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        large_group = [m for m in misconfigs if "Large privileged group" in m.title]
        assert len(large_group) >= 1

    # =========================================================================
    # Trusts Parsing Tests
    # =========================================================================

    def test_parse_trusts(self, tmp_path: Path):
        """Test parsing domain trusts from CSV."""
        content = """"TrustPartner","TrustDirection","SIDFiltering"
"PARTNER.LOCAL","Bidirectional","true"
"""
        csv_file = tmp_path / "CORP-Trusts.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        trusted = [h for h in hosts if "trusted-domain" in h.tags]
        assert len(trusted) >= 1

    def test_parse_trust_sid_filtering_disabled(self, tmp_path: Path):
        """Test detection of SID filtering disabled."""
        content = """"TrustPartner","TrustDirection","SIDFiltering"
"RISKY.LOCAL","Bidirectional","false"
"""
        csv_file = tmp_path / "CORP-Trusts.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        sid_filtering = [m for m in misconfigs if "SID filtering" in m.title]
        assert len(sid_filtering) >= 1

    # =========================================================================
    # Password Policy Parsing Tests
    # =========================================================================

    def test_parse_weak_password_policy(self, tmp_path: Path):
        """Test detection of weak password policy."""
        content = """"MinPasswordLength","PasswordComplexity"
"4","false"
"""
        csv_file = tmp_path / "CORP-PasswordPolicy.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        weak_pw = [m for m in misconfigs if "password" in m.title.lower()]
        assert len(weak_pw) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_csv(self, tmp_path: Path):
        """Test handling of empty CSV."""
        content = """"Name","SamAccountName"
"""
        csv_file = tmp_path / "ADRecon-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        assert isinstance(entities, list)

    def test_handles_missing_columns(self, tmp_path: Path):
        """Test handling of CSV with missing columns."""
        content = """"Name"
"testuser"
"""
        csv_file = tmp_path / "ADRecon-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_extracts_cn_from_dn(self, tmp_path: Path):
        """Test extraction of CN from distinguished name."""
        content = """"Name","SamAccountName","Enabled","MemberOf"
"testuser","testuser","True","CN=Test Group,OU=Groups,DC=corp,DC=local"
"""
        csv_file = tmp_path / "ADRecon-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert "Test Group" in users[0].groups

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_adrecon(self, tmp_path: Path):
        """Test that source is set to adrecon."""
        content = """"Name","SamAccountName","Enabled"
"testuser","testuser","True"
"""
        csv_file = tmp_path / "ADRecon-Users.csv"
        csv_file.write_text(content)

        parser = ADReconParser()
        entities = list(parser.parse(csv_file))

        for entity in entities:
            assert entity.source == "adrecon"
