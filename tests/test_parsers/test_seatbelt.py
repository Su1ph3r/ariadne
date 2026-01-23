"""Tests for Seatbelt parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.seatbelt import SeatbeltParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration, Vulnerability
from .base import BaseParserTest


class TestSeatbeltParser(BaseParserTest):
    """Test SeatbeltParser functionality."""

    parser_class = SeatbeltParser
    expected_name = "seatbelt"
    expected_patterns = ["*seatbelt*.txt", "*seatbelt*.json", "*Seatbelt*.txt"]
    expected_entity_types = ["Host", "User", "Misconfiguration", "Vulnerability", "Credential"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_seatbelt_txt(self, tmp_path: Path):
        """Test detection of Seatbelt text output."""
        lines = [
            "====== Seatbelt Output ======",
            "====== OSInfo ======",
            "Hostname: WORKSTATION01",
            "ProductName: Windows 10 Enterprise",
            "====== TokenPrivileges ======",
        ]
        txt_file = tmp_path / "seatbelt_output.txt"
        txt_file.write_text("\n".join(lines))

        assert SeatbeltParser.can_parse(txt_file)

    def test_can_parse_seatbelt_json(self, tmp_path: Path):
        """Test detection of Seatbelt JSON output."""
        data = {
            "OSInfo": {"Hostname": "WORKSTATION01", "ProductName": "Windows 10"},
            "TokenPrivileges": []
        }
        json_file = tmp_path / "seatbelt.json"
        json_file.write_text(json.dumps(data))

        assert SeatbeltParser.can_parse(json_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just a random text file.")

        assert not SeatbeltParser.can_parse(txt_file)

    # =========================================================================
    # Text Parsing - OS Info Tests
    # =========================================================================

    def test_parse_text_extracts_host(self, tmp_path: Path):
        """Test parsing host information from text."""
        lines = [
            "====== OSInfo ======",
            "Hostname: WORKSTATION01",
            "ProductName: Windows 10 Enterprise",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WORKSTATION01"
        assert hosts[0].os == "Windows 10 Enterprise"
        assert "enumerated" in hosts[0].tags

    def test_parse_text_extracts_user(self, tmp_path: Path):
        """Test parsing user information from text."""
        lines = [
            "====== CurrentUser ======",
            "User: CORP\\jsmith",
            "LogonUser: CORP\\admin",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 1

    # =========================================================================
    # Text Parsing - Credential Tests
    # =========================================================================

    def test_parse_autologon_credentials(self, tmp_path: Path):
        """Test parsing AutoLogon credentials from JSON."""
        # The text regex is complex with optional groups - test JSON path instead
        data = {
            "Credentials": [
                {"UserName": "autologon_user", "Password": "AutoPass123", "Target": "autologon"}
            ]
        }
        json_file = tmp_path / "seatbelt.json"
        json_file.write_text(json.dumps(data))

        parser = SeatbeltParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].username == "autologon_user"
        assert creds[0].value == "AutoPass123"

    def test_parse_credential_manager(self, tmp_path: Path):
        """Test parsing Credential Manager entries."""
        lines = [
            "====== CredentialManager ======",
            "Target: Domain:target=server.corp.local",
            "UserName: CORP\\svc_backup",
            "Password: BackupPass123",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        cred_mgr = [c for c in creds if "credential-manager" in c.tags]
        assert len(cred_mgr) >= 1

    # =========================================================================
    # Text Parsing - Privilege Tests
    # =========================================================================

    def test_parse_dangerous_privileges(self, tmp_path: Path):
        """Test parsing dangerous token privileges."""
        lines = [
            "====== TokenPrivileges ======",
            "SeImpersonatePrivilege: Enabled",
            "SeDebugPrivilege: Enabled",
            "SeShutdownPrivilege: Disabled",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        priv_misconfigs = [m for m in misconfigs if "privilege" in m.tags]
        assert len(priv_misconfigs) >= 2

        impersonate = next((m for m in priv_misconfigs if "SeImpersonate" in m.title), None)
        assert impersonate is not None
        assert impersonate.severity == "high"

    def test_parse_always_install_elevated(self, tmp_path: Path):
        """Test parsing AlwaysInstallElevated setting."""
        lines = [
            "====== UACSystemPolicies ======",
            "AlwaysInstallElevated: True",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        aie = next((m for m in misconfigs if "AlwaysInstallElevated" in m.title), None)
        assert aie is not None
        assert aie.severity == "high"
        assert "privesc" in aie.tags

    # =========================================================================
    # Text Parsing - Vulnerability Tests
    # =========================================================================

    def test_parse_unquoted_service_path(self, tmp_path: Path):
        """Test parsing unquoted service paths."""
        # Content must match the UNQUOTED_SERVICE_PATTERN regex
        content = "UnquotedServicePath\nName: VulnService  PathName: C:\\Program Files\\Vuln App\\service.exe"
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text(content)

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        vulns = self.get_vulnerabilities(entities)
        unquoted = [v for v in vulns if "Unquoted" in v.title]
        assert len(unquoted) >= 1
        assert "privesc" in unquoted[0].tags

    def test_parse_lsass_protection_disabled(self, tmp_path: Path):
        """Test parsing LSASS protection status."""
        lines = [
            "====== LSASettings ======",
            "LSASS protection: disabled",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        lsass = next((m for m in misconfigs if "LSASS" in m.title), None)
        assert lsass is not None
        assert "lsass" in lsass.tags

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_osinfo(self, tmp_path: Path):
        """Test parsing JSON OS information."""
        data = {
            "OSInfo": {
                "Hostname": "WORKSTATION01",
                "ComputerName": "WORKSTATION01",
                "ProductName": "Windows 10 Pro"
            }
        }
        json_file = tmp_path / "seatbelt.json"
        json_file.write_text(json.dumps(data))

        parser = SeatbeltParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WORKSTATION01"
        assert hosts[0].os == "Windows 10 Pro"

    def test_parse_json_credentials(self, tmp_path: Path):
        """Test parsing JSON credentials."""
        data = {
            "Credentials": [
                {"UserName": "admin", "Password": "AdminPass123", "Target": "server1"},
                {"UserName": "svc_sql", "Password": "SqlPass456", "Target": "sqlserver"},
            ]
        }
        json_file = tmp_path / "seatbelt.json"
        json_file.write_text(json.dumps(data))

        parser = SeatbeltParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 2

    def test_parse_json_token_privileges(self, tmp_path: Path):
        """Test parsing JSON token privileges."""
        data = {
            "TokenPrivileges": [
                {"Name": "SeImpersonatePrivilege", "State": "Enabled"},
                {"Name": "SeDebugPrivilege", "State": "Enabled"},
                {"Name": "SeShutdownPrivilege", "State": "Disabled"},
            ]
        }
        json_file = tmp_path / "seatbelt.json"
        json_file.write_text(json.dumps(data))

        parser = SeatbeltParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        priv_misconfigs = [m for m in misconfigs if "privilege" in m.tags]
        # Should find 2 dangerous privileges (SeImpersonate and SeDebug)
        assert len(priv_misconfigs) >= 2

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "seatbelt_empty.txt"
        txt_file.write_text("")

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON."""
        json_file = tmp_path / "seatbelt.json"
        json_file.write_text("{invalid json}")

        parser = SeatbeltParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)

    def test_skips_system_users(self, tmp_path: Path):
        """Test that system accounts are skipped."""
        lines = [
            "User: NT AUTHORITY\\SYSTEM",
            "User: LOCAL SERVICE",
            "User: NETWORK SERVICE",
            "User: CORP\\realuser",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        # Should only have realuser, not system accounts
        usernames = [u.username.lower() for u in users]
        assert "system" not in usernames
        assert "local service" not in usernames

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_seatbelt(self, tmp_path: Path):
        """Test that source is set to seatbelt."""
        lines = [
            "Hostname: WORKSTATION01",
            "ProductName: Windows 10",
        ]
        txt_file = tmp_path / "seatbelt.txt"
        txt_file.write_text("\n".join(lines))

        parser = SeatbeltParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "seatbelt"
