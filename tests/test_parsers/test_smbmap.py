"""Tests for SMBMap parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.smbmap import SMBMapParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration, Credential
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestSMBMapParser(BaseParserTest):
    """Test SMBMapParser functionality."""

    parser_class = SMBMapParser
    expected_name = "smbmap"
    expected_patterns = ["*smbmap*.txt", "*smbmap*.json", "*smbmap*.csv"]
    expected_entity_types = ["Host", "Service", "Misconfiguration", "Credential"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_smbmap_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        content = "[+] IP: 192.168.1.100"
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        assert SMBMapParser.can_parse(txt_file)

    def test_can_parse_smbmap_json(self, tmp_path: Path):
        """Test detection of SMBMap JSON file."""
        data = {"192.168.1.100": {"share": "READ"}}
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        assert SMBMapParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """[+] IP: 192.168.1.100:445
Disk Permissions
Share	READ ONLY
"""
        txt_file = tmp_path / "results.txt"
        txt_file.write_text(content)

        assert SMBMapParser.can_parse(txt_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text is rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("random text content")

        assert not SMBMapParser.can_parse(txt_file)

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_host(self, tmp_path: Path):
        """Test parsing host from JSON format."""
        data = {
            "192.168.1.100": {
                "Public": "READ ONLY",
                "C$": "READ, WRITE"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    def test_parse_json_creates_service(self, tmp_path: Path):
        """Test that JSON parsing creates SMB service."""
        data = {"192.168.1.100": {"share": "READ"}}
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 445
        assert services[0].name == "microsoft-ds"

    def test_parse_json_creates_relationship(self, tmp_path: Path):
        """Test that JSON parsing creates service-host relationship."""
        data = {"192.168.1.100": {"share": "READ"}}
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    def test_parse_json_shares(self, tmp_path: Path):
        """Test parsing shares from JSON format."""
        data = {
            "192.168.1.100": {
                "Public": "READ ONLY",
                "Shared": "READ, WRITE"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        share_misconfigs = [m for m in misconfigs if "SMB Share" in m.title]
        assert len(share_misconfigs) >= 2

    def test_parse_json_skips_no_access(self, tmp_path: Path):
        """Test that shares with NO ACCESS are skipped."""
        data = {
            "192.168.1.100": {
                "Public": "NO ACCESS",
                "IPC$": "NO ACCESS"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        share_misconfigs = [m for m in misconfigs if "SMB Share" in m.title]
        assert len(share_misconfigs) == 0

    def test_parse_json_admin_shares_severity(self, tmp_path: Path):
        """Test that admin shares have higher severity."""
        data = {
            "192.168.1.100": {
                "C$": "READ, WRITE",
                "ADMIN$": "READ"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        c_share = [m for m in misconfigs if "C$" in m.title]
        assert len(c_share) >= 1
        assert c_share[0].severity == "high"  # writable admin share

    # =========================================================================
    # Text Parsing Tests
    # =========================================================================

    def test_parse_text_host(self, tmp_path: Path):
        """Test parsing host from text format."""
        content = """[+] IP: 192.168.1.100:445	Name: SERVER01
    Disk                                                  	Permissions	Comment
    ----                                                  	-----------	-------
    Public                                                	READ ONLY	Public Files
"""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    def test_parse_text_shares(self, tmp_path: Path):
        """Test parsing shares from text format."""
        content = """[+] IP: 192.168.1.100
    Disk                                                  	Permissions	Comment
    ----                                                  	-----------	-------
    Public                                                	READ ONLY	Public Files
    Shared                                                	READ, WRITE	Shared Files
"""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        share_misconfigs = [m for m in misconfigs if "SMB Share" in m.title]
        assert len(share_misconfigs) >= 2

    def test_parse_text_alternative_format(self, tmp_path: Path):
        """Test parsing alternative text format."""
        content = """[*] IP: 192.168.1.100
Public	Disk	Public files	READ
Private	Disk	Private data	READ, WRITE
"""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    def test_parse_text_multiple_hosts(self, tmp_path: Path):
        """Test parsing multiple hosts from text."""
        content = """[+] IP: 192.168.1.100
    Share1	READ ONLY
[+] IP: 192.168.1.101
    Share2	READ, WRITE
"""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        content = """[+] IP: 192.168.1.100
    Share1	READ ONLY
[+] IP: 192.168.1.100
    Share2	READ, WRITE
"""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1

    # =========================================================================
    # Interesting File Detection Tests
    # =========================================================================

    def test_detects_password_file(self, tmp_path: Path):
        """Test detection of password file."""
        data = {
            "192.168.1.100": {
                "Public": {
                    "permissions": "READ",
                    "files": ["passwords.txt"]
                }
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "file"

    def test_detects_kdbx_file(self, tmp_path: Path):
        """Test detection of KeePass database file."""
        data = {
            "192.168.1.100": {
                "Public": {
                    "permissions": "READ",
                    "files": ["secrets.kdbx"]
                }
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    def test_detects_config_file(self, tmp_path: Path):
        """Test detection of sensitive config file via JSON."""
        data = {
            "192.168.1.100": {
                "wwwroot": {
                    "permissions": "READ",
                    "files": ["web.config"]
                }
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        sensitive = [m for m in misconfigs if "Sensitive file" in m.title]
        assert len(sensitive) >= 1

    def test_detects_ntds_dit(self, tmp_path: Path):
        """Test detection of NTDS.dit file via JSON."""
        data = {
            "192.168.1.100": {
                "SYSVOL": {
                    "permissions": "READ",
                    "files": ["NTDS.dit"]
                }
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        sensitive = [m for m in misconfigs if "Sensitive file" in m.title]
        assert len(sensitive) >= 1

    # =========================================================================
    # Permission Analysis Tests
    # =========================================================================

    def test_writable_share_medium_severity(self, tmp_path: Path):
        """Test that writable non-admin shares are medium severity."""
        data = {
            "192.168.1.100": {
                "Public": "READ, WRITE"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        public = [m for m in misconfigs if "Public" in m.title]
        assert len(public) >= 1
        assert public[0].severity == "medium"

    def test_readable_share_low_severity(self, tmp_path: Path):
        """Test that read-only non-admin shares are low severity."""
        data = {
            "192.168.1.100": {
                "Public": "READ"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        public = [m for m in misconfigs if "Public" in m.title]
        assert len(public) >= 1
        assert public[0].severity == "low"

    def test_stores_raw_data(self, tmp_path: Path):
        """Test that share info is stored in raw_data."""
        data = {
            "192.168.1.100": {
                "Public": "READ, WRITE"
            }
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        public = [m for m in misconfigs if "Public" in m.title]
        assert len(public) >= 1
        assert public[0].raw_data.get("readable") == True
        assert public[0].raw_data.get("writable") == True

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_json(self, tmp_path: Path):
        """Test handling of empty JSON."""
        json_file = tmp_path / "smbmap.json"
        json_file.write_text("{}")

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_empty_text(self, tmp_path: Path):
        """Test handling of empty text file."""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text("")

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_ip(self, tmp_path: Path):
        """Test handling of invalid IP in JSON key."""
        data = {
            "not_an_ip": {"share": "READ"},
            "192.168.1.100": {"share": "READ"}
        }
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.100"

    def test_skips_header_rows(self, tmp_path: Path):
        """Test that header rows are skipped."""
        content = """[+] IP: 192.168.1.100
    Disk                                                  	Permissions	Comment
    ----                                                  	-----------	-------
    Public                                                	READ ONLY	Files
"""
        txt_file = tmp_path / "smbmap.txt"
        txt_file.write_text(content)

        parser = SMBMapParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        # Should only have Public share, not "Disk" or "----"
        share_names = [m.title for m in misconfigs if "SMB Share" in m.title]
        assert not any("----" in name for name in share_names)
        assert not any("Disk" in name for name in share_names)

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_smbmap(self, tmp_path: Path):
        """Test that source is set to smbmap."""
        data = {"192.168.1.100": {"Public": "READ"}}
        json_file = tmp_path / "smbmap.json"
        json_file.write_text(json.dumps(data))

        parser = SMBMapParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "smbmap"
