"""Tests for CrackMapExec parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.crackmapexec import CrackMapExecParser
from ariadne.models.asset import Host, Service, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from .base import BaseParserTest


class TestCrackMapExecParser(BaseParserTest):
    """Test CrackMapExecParser functionality."""

    parser_class = CrackMapExecParser
    expected_name = "crackmapexec"
    expected_patterns = ["*cme*.json", "*nxc*.json", "*crackmapexec*.json", "*netexec*.json"]
    expected_entity_types = ["Host", "Service", "User", "Credential", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_cme_json(self, tmp_path: Path):
        """Test detection of CrackMapExec JSON output."""
        data = {
            "host": "192.168.1.1",
            "hostname": "DC01",
            "domain": "CORP.LOCAL",
            "protocol": "smb",
            "signing": False
        }
        json_file = tmp_path / "cme_output.json"
        json_file.write_text(json.dumps(data))

        assert CrackMapExecParser.can_parse(json_file)

    def test_can_parse_nxc_json(self, tmp_path: Path):
        """Test detection of NetExec JSON output."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "pwned": True
        }
        json_file = tmp_path / "nxc_scan.json"
        json_file.write_text(json.dumps(data))

        assert CrackMapExecParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is not parsed as CME."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not CrackMapExecParser.can_parse(json_file)

    def test_cannot_parse_txt_file(self, tmp_path: Path):
        """Test that text files are rejected."""
        txt_file = tmp_path / "cme_output.txt"
        txt_file.write_text("SMB 192.168.1.1 445 DC01 [+] CORP.LOCAL\\admin")

        assert not CrackMapExecParser.can_parse(txt_file)

    # =========================================================================
    # Host Parsing Tests
    # =========================================================================

    def test_parse_single_host(self, tmp_path: Path):
        """Test parsing single host."""
        data = {
            "host": "192.168.1.1",
            "hostname": "DC01",
            "domain": "CORP.LOCAL",
            "os": "Windows Server 2019",
            "protocol": "smb"
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].hostname == "DC01"
        assert hosts[0].domain == "CORP.LOCAL"
        assert hosts[0].os == "Windows Server 2019"
        assert hosts[0].source == "crackmapexec"

    def test_parse_multiple_hosts(self, tmp_path: Path):
        """Test parsing multiple hosts from array."""
        data = [
            {"host": "192.168.1.1", "hostname": "DC01", "protocol": "smb"},
            {"host": "192.168.1.2", "hostname": "WS01", "protocol": "smb"},
            {"host": "192.168.1.3", "hostname": "WS02", "protocol": "smb"},
        ]
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 3
        host_ips = {h.ip for h in hosts}
        assert host_ips == {"192.168.1.1", "192.168.1.2", "192.168.1.3"}

    def test_parse_host_with_ip_key(self, tmp_path: Path):
        """Test parsing host with 'ip' key instead of 'host'."""
        data = {"ip": "10.0.0.1", "hostname": "SERVER01", "protocol": "smb"}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"

    # =========================================================================
    # Service Parsing Tests
    # =========================================================================

    def test_creates_smb_service(self, tmp_path: Path):
        """Test that SMB service is created."""
        data = {"host": "192.168.1.1", "protocol": "smb"}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].port == 445
        assert services[0].name == "smb"
        assert services[0].protocol == "tcp"

    def test_creates_winrm_service(self, tmp_path: Path):
        """Test that WinRM service is created."""
        data = {"host": "192.168.1.1", "protocol": "winrm"}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].port == 5985
        assert services[0].name == "winrm"

    def test_creates_ldap_service(self, tmp_path: Path):
        """Test that LDAP service is created."""
        data = {"host": "192.168.1.1", "protocol": "ldap"}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) == 1
        assert services[0].port == 389
        assert services[0].name == "ldap"

    def test_creates_service_to_host_relationship(self, tmp_path: Path):
        """Test that RUNS_ON relationship is created."""
        data = {"host": "192.168.1.1", "protocol": "smb"}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type == RelationType.RUNS_ON]
        assert len(runs_on) >= 1

    # =========================================================================
    # SMB Signing Tests
    # =========================================================================

    def test_detects_smb_signing_disabled(self, tmp_path: Path):
        """Test detection of SMB signing disabled."""
        data = {"host": "192.168.1.1", "protocol": "smb", "signing": False}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        signing_issue = next((m for m in misconfigs if "SMB Signing" in m.title), None)
        assert signing_issue is not None
        assert signing_issue.severity == "medium"
        assert "relay" in signing_issue.description.lower()

    def test_no_misconfig_when_signing_enabled(self, tmp_path: Path):
        """Test no misconfiguration when SMB signing is enabled."""
        data = {"host": "192.168.1.1", "protocol": "smb", "signing": True}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        signing_issues = [m for m in misconfigs if "SMB Signing" in m.title]
        assert len(signing_issues) == 0

    # =========================================================================
    # SMBv1 Tests
    # =========================================================================

    def test_detects_smbv1_enabled(self, tmp_path: Path):
        """Test detection of SMBv1 enabled."""
        data = {"host": "192.168.1.1", "protocol": "smb", "smbv1": True}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        smbv1_issue = next((m for m in misconfigs if "SMBv1" in m.title), None)
        assert smbv1_issue is not None
        assert smbv1_issue.severity == "high"
        assert "EternalBlue" in smbv1_issue.description

    # =========================================================================
    # Share Access Tests
    # =========================================================================

    def test_detects_accessible_shares(self, tmp_path: Path):
        """Test detection of accessible shares."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "shares": [
                {"name": "C$", "read": True, "write": True},
                {"name": "ADMIN$", "read": True, "write": False},
                {"name": "IPC$", "read": True, "write": False},
            ]
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        share_issues = [m for m in misconfigs if "Share" in m.title]
        assert len(share_issues) >= 3

        c_share = next((m for m in share_issues if "C$" in m.title), None)
        assert c_share is not None
        assert c_share.severity == "medium"

        ipc_share = next((m for m in share_issues if "IPC$" in m.title), None)
        assert ipc_share is not None
        assert ipc_share.severity == "low"  # IPC$ is low severity

    # =========================================================================
    # Session Tests
    # =========================================================================

    def test_parses_sessions(self, tmp_path: Path):
        """Test parsing logged-in sessions."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "domain": "CORP.LOCAL",
            "sessions": [
                {"user": "admin", "domain": "CORP.LOCAL"},
                {"user": "jsmith", "domain": "CORP.LOCAL"},
            ]
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        session_users = [u for u in users if u.username in ["admin", "jsmith"]]
        assert len(session_users) >= 2

        relationships = self.get_relationships(entities)
        has_session = [r for r in relationships if r.relation_type == RelationType.HAS_SESSION]
        assert len(has_session) >= 2

    # =========================================================================
    # Admin Access Tests
    # =========================================================================

    def test_detects_admin_access(self, tmp_path: Path):
        """Test detection of admin access (pwned flag)."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "domain": "CORP.LOCAL",
            "username": "adminuser",
            "admin": True
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        admin_user = next((u for u in users if u.username == "adminuser"), None)
        assert admin_user is not None
        assert admin_user.is_admin is True

        relationships = self.get_relationships(entities)
        admin_to = [r for r in relationships if r.relation_type == RelationType.ADMIN_TO]
        assert len(admin_to) >= 1

    def test_detects_pwned_flag(self, tmp_path: Path):
        """Test detection of pwned flag."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "domain": "CORP.LOCAL",
            "username": "pwned_user",
            "pwned": True
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        pwned_user = next((u for u in users if u.username == "pwned_user"), None)
        assert pwned_user is not None
        assert pwned_user.is_admin is True

    # =========================================================================
    # Credential Parsing Tests
    # =========================================================================

    def test_parses_password_credentials(self, tmp_path: Path):
        """Test parsing password credentials."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "domain": "CORP.LOCAL",
            "credentials": [
                {"username": "svc_account", "password": "SecretPass123!", "domain": "CORP.LOCAL"},
            ]
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        password_creds = [c for c in creds if c.credential_type == "password"]
        assert len(password_creds) >= 1

        svc_cred = next((c for c in password_creds if "svc_account" in c.title), None)
        assert svc_cred is not None
        assert svc_cred.value == "SecretPass123!"
        assert svc_cred.severity == "critical"
        assert svc_cred.domain == "CORP.LOCAL"

    def test_parses_ntlm_hash_credentials(self, tmp_path: Path):
        """Test parsing NTLM hash credentials."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "domain": "CORP.LOCAL",
            "credentials": [
                {"username": "admin", "hash": "aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86"},
            ]
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        ntlm_creds = [c for c in creds if c.credential_type == "ntlm"]
        assert len(ntlm_creds) >= 1

        admin_cred = next((c for c in ntlm_creds if "admin" in c.title), None)
        assert admin_cred is not None
        assert admin_cred.severity == "high"

    def test_parses_inline_hash_credential(self, tmp_path: Path):
        """Test parsing inline hash credential."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "domain": "CORP.LOCAL",
            "username": "user1",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0"
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "ntlm"

    def test_skips_null_passwords(self, tmp_path: Path):
        """Test that null/empty passwords are skipped."""
        data = {
            "host": "192.168.1.1",
            "protocol": "smb",
            "credentials": [
                {"username": "user1", "password": "(null)"},
                {"username": "user2", "password": "*"},
                {"username": "user3", "password": ""},
                {"username": "user4", "password": "RealPassword!"},
            ]
        }
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        password_creds = [c for c in creds if c.credential_type == "password"]
        # Only user4 should have a password credential
        assert len(password_creds) == 1
        assert "user4" in password_creds[0].title

    # =========================================================================
    # Protocol Port Mapping Tests
    # =========================================================================

    def test_protocol_port_mapping(self, tmp_path: Path):
        """Test that protocols map to correct ports."""
        protocols = [
            ("smb", 445),
            ("winrm", 5985),
            ("ldap", 389),
            ("ldaps", 636),
            ("mssql", 1433),
            ("ssh", 22),
            ("rdp", 3389),
        ]

        for protocol, expected_port in protocols:
            data = {"host": "192.168.1.1", "protocol": protocol}
            json_file = tmp_path / f"cme_{protocol}.json"
            json_file.write_text(json.dumps(data))

            parser = CrackMapExecParser()
            entities = list(parser.parse(json_file))

            services = self.get_services(entities)
            assert len(services) == 1, f"Expected 1 service for {protocol}"
            assert services[0].port == expected_port, f"Expected port {expected_port} for {protocol}"

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_missing_host(self, tmp_path: Path):
        """Test handling of entry without host."""
        data = {"protocol": "smb", "signing": False}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 0

    def test_source_is_crackmapexec(self, tmp_path: Path):
        """Test that source is set to crackmapexec."""
        data = {"host": "192.168.1.1", "protocol": "smb"}
        json_file = tmp_path / "cme.json"
        json_file.write_text(json.dumps(data))

        parser = CrackMapExecParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "crackmapexec"
