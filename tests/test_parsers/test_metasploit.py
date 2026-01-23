"""Tests for Metasploit parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.metasploit import MetasploitParser
from ariadne.models.asset import Host, Service, User
from ariadne.models.finding import Vulnerability, Credential
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestMetasploitParser(BaseParserTest):
    """Test MetasploitParser functionality."""

    parser_class = MetasploitParser
    expected_name = "metasploit"
    expected_patterns = ["*metasploit*.xml", "*metasploit*.json", "*msf*.xml", "*msf*.json", "*.msf"]
    expected_entity_types = ["Host", "Service", "User", "Vulnerability", "Credential"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_metasploit_xml(self, tmp_path: Path):
        """Test detection of Metasploit XML file."""
        content = """<?xml version="1.0"?>
<MetasploitV4>
  <hosts>
    <host>
      <address>192.168.1.100</address>
    </host>
  </hosts>
</MetasploitV4>
"""
        xml_file = tmp_path / "metasploit_export.xml"
        xml_file.write_text(content)

        assert MetasploitParser.can_parse(xml_file)

    def test_can_parse_metasploit_json(self, tmp_path: Path):
        """Test detection of Metasploit JSON file."""
        data = {
            "hosts": [
                {"address": "192.168.1.100"}
            ]
        }
        json_file = tmp_path / "metasploit.json"
        json_file.write_text(json.dumps(data))

        assert MetasploitParser.can_parse(json_file)

    def test_cannot_parse_random_xml(self, tmp_path: Path):
        """Test that random XML is rejected."""
        content = """<?xml version="1.0"?>
<root><random>data</random></root>
"""
        xml_file = tmp_path / "random.xml"
        xml_file.write_text(content)

        assert not MetasploitParser.can_parse(xml_file)

    # =========================================================================
    # XML Host Parsing Tests
    # =========================================================================

    def test_parse_xml_host(self, tmp_path: Path):
        """Test parsing host from XML."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
    <name>server.corp.local</name>
    <os_name>Windows Server 2019</os_name>
    <arch>x86_64</arch>
  </host>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"
        assert hosts[0].hostname == "server.corp.local"
        assert "Windows" in hosts[0].os

    def test_parse_xml_service(self, tmp_path: Path):
        """Test parsing service from XML."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
    <service>
      <port>22</port>
      <proto>tcp</proto>
      <name>ssh</name>
      <info>OpenSSH 7.9</info>
    </service>
    <service>
      <port>80</port>
      <proto>tcp</proto>
      <name>http</name>
    </service>
  </host>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        services = self.get_services(entities)
        assert len(services) >= 2
        assert any(s.port == 22 and s.name == "ssh" for s in services)
        assert any(s.port == 80 and s.name == "http" for s in services)

    def test_parse_xml_creates_relationships(self, tmp_path: Path):
        """Test that XML parsing creates service-host relationships."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
    <service><port>22</port><proto>tcp</proto></service>
  </host>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    # =========================================================================
    # XML Vulnerability Parsing Tests
    # =========================================================================

    def test_parse_xml_vuln(self, tmp_path: Path):
        """Test parsing vulnerability from XML."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
  </host>
  <vuln>
    <name>MS17-010 EternalBlue</name>
    <info>SMB Remote Code Execution</info>
    <host>192.168.1.100</host>
    <ref>CVE-2017-0144</ref>
  </vuln>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert "EternalBlue" in vulns[0].title
        assert vulns[0].cve_id == "CVE-2017-0144"

    def test_parse_xml_vuln_exploited(self, tmp_path: Path):
        """Test that exploited vulnerabilities are marked."""
        content = """<?xml version="1.0"?>
<root>
  <vuln>
    <name>MS08-067</name>
    <exploited_at>2024-01-01</exploited_at>
  </vuln>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].severity == "high"
        assert "exploited" in vulns[0].tags

    # =========================================================================
    # XML Credential Parsing Tests
    # =========================================================================

    def test_parse_xml_cred(self, tmp_path: Path):
        """Test parsing credential from XML."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
  </host>
  <cred>
    <user>admin</user>
    <pass>Password123</pass>
    <ptype>password</ptype>
    <host>192.168.1.100</host>
  </cred>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].username == "admin"
        assert creds[0].credential_type == "password"
        assert creds[0].severity == "critical"

    def test_parse_xml_cred_hash(self, tmp_path: Path):
        """Test parsing hash credential from XML."""
        content = """<?xml version="1.0"?>
<root>
  <cred>
    <user>admin</user>
    <pass>aabbccdd11223344aabbccdd11223344</pass>
    <ptype>smb_hash</ptype>
  </cred>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].credential_type == "ntlm"

    def test_parse_xml_cred_creates_user(self, tmp_path: Path):
        """Test that credential parsing creates user entity."""
        content = """<?xml version="1.0"?>
<root>
  <cred>
    <user>jsmith</user>
    <pass>secret</pass>
    <ptype>password</ptype>
  </cred>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"

    # =========================================================================
    # XML Loot Parsing Tests
    # =========================================================================

    def test_parse_xml_loot_hash(self, tmp_path: Path):
        """Test parsing hash loot from XML."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
  </host>
  <loot>
    <ltype>windows.hashes</ltype>
    <name>NTLM Hashes</name>
    <data>admin:500:aad3b435...:aabbccdd...:::</data>
    <host>192.168.1.100</host>
  </loot>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        creds = self.get_credentials(entities)
        loot_creds = [c for c in creds if c.credential_type == "loot"]
        assert len(loot_creds) >= 1

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_host(self, tmp_path: Path):
        """Test parsing host from JSON."""
        data = {
            "hosts": [{
                "address": "192.168.1.100",
                "name": "server.corp.local",
                "os_name": "Linux"
            }]
        }
        json_file = tmp_path / "metasploit.json"
        json_file.write_text(json.dumps(data))

        parser = MetasploitParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    def test_parse_json_services(self, tmp_path: Path):
        """Test parsing services from JSON."""
        data = {
            "hosts": [{
                "address": "192.168.1.100",
                "services": [
                    {"port": 22, "proto": "tcp", "name": "ssh"},
                    {"port": 80, "proto": "tcp", "name": "http"}
                ]
            }]
        }
        json_file = tmp_path / "metasploit.json"
        json_file.write_text(json.dumps(data))

        parser = MetasploitParser()
        entities = list(parser.parse(json_file))

        services = self.get_services(entities)
        assert len(services) >= 2

    def test_parse_json_vulns(self, tmp_path: Path):
        """Test parsing vulnerabilities from JSON."""
        data = {
            "hosts": [{"address": "192.168.1.100"}],
            "vulns": [{
                "name": "MS17-010",
                "info": "EternalBlue",
                "host": "192.168.1.100",
                "refs": ["CVE-2017-0144"]
            }]
        }
        json_file = tmp_path / "metasploit.json"
        json_file.write_text(json.dumps(data))

        parser = MetasploitParser()
        entities = list(parser.parse(json_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].cve_id == "CVE-2017-0144"

    def test_parse_json_creds(self, tmp_path: Path):
        """Test parsing credentials from JSON."""
        data = {
            "hosts": [{"address": "192.168.1.100"}],
            "creds": [{
                "user": "admin",
                "pass": "secret",
                "ptype": "password",
                "host": "192.168.1.100"
            }]
        }
        json_file = tmp_path / "metasploit.json"
        json_file.write_text(json.dumps(data))

        parser = MetasploitParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].username == "admin"

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_xml(self, tmp_path: Path):
        """Test handling of empty XML."""
        content = """<?xml version="1.0"?><root></root>"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        assert isinstance(entities, list)

    def test_handles_empty_json(self, tmp_path: Path):
        """Test handling of empty JSON."""
        json_file = tmp_path / "metasploit.json"
        json_file.write_text("{}")

        parser = MetasploitParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_address(self, tmp_path: Path):
        """Test handling of host without address."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <name>server.local</name>
  </host>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_handles_invalid_port(self, tmp_path: Path):
        """Test handling of invalid port value."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
    <service>
      <port>invalid</port>
      <proto>tcp</proto>
    </service>
  </host>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        # Should not crash, service should be skipped
        services = self.get_services(entities)
        assert len(services) == 0

    def test_handles_cred_without_user(self, tmp_path: Path):
        """Test handling of credential without username."""
        content = """<?xml version="1.0"?>
<root>
  <cred>
    <pass>orphan_password</pass>
    <ptype>password</ptype>
  </cred>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        # Should still create credential with value
        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_metasploit(self, tmp_path: Path):
        """Test that source is set to metasploit."""
        content = """<?xml version="1.0"?>
<root>
  <host>
    <address>192.168.1.100</address>
  </host>
</root>
"""
        xml_file = tmp_path / "metasploit.xml"
        xml_file.write_text(content)

        parser = MetasploitParser()
        entities = list(parser.parse(xml_file))

        for entity in entities:
            assert entity.source == "metasploit"
