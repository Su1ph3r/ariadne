"""Tests for Nessus parser."""

import pytest
from pathlib import Path

from ariadne.parsers.nessus import NessusParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from .base import BaseParserTest


class TestNessusParser(BaseParserTest):
    """Test NessusParser functionality."""

    parser_class = NessusParser
    expected_name = "nessus"
    expected_patterns = ["*.nessus", "nessus_*.xml"]
    expected_entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_nessus_file(self, tmp_path: Path):
        """Test detection of .nessus file."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        assert NessusParser.can_parse(nessus_file)

    def test_cannot_parse_nmap_xml(self, tmp_path: Path):
        """Test that nmap XML is not parsed as nessus."""
        xml_content = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host></host></nmaprun>"""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(xml_content)

        assert not NessusParser.can_parse(xml_file)

    def test_cannot_parse_json(self, tmp_path: Path):
        """Test that JSON files are rejected."""
        json_file = tmp_path / "scan.json"
        json_file.write_text('{"test": true}')

        assert not NessusParser.can_parse(json_file)

    # =========================================================================
    # Host Parsing Tests
    # =========================================================================

    def test_parse_single_host(self, tmp_path: Path):
        """Test parsing single host."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties>
        <tag name="host-ip">192.168.1.1</tag>
        <tag name="host-fqdn">server.corp.local</tag>
        <tag name="operating-system">Windows Server 2019</tag>
      </HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].hostname == "server.corp.local"
        assert hosts[0].os == "Windows Server 2019"
        assert hosts[0].source == "nessus"

    def test_parse_multiple_hosts(self, tmp_path: Path):
        """Test parsing multiple hosts."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
    </ReportHost>
    <ReportHost name="192.168.1.2">
      <HostProperties><tag name="host-ip">192.168.1.2</tag></HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 2

    # =========================================================================
    # Service Parsing Tests
    # =========================================================================

    def test_parse_services(self, tmp_path: Path):
        """Test parsing services from report items."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10267" pluginName="SSH Detection" severity="0">
        <description>SSH is running</description>
      </ReportItem>
      <ReportItem port="80" protocol="tcp" svc_name="www" pluginID="10287" pluginName="Web Server" severity="0">
        <description>HTTP server detected</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        services = self.get_services(entities)
        assert len(services) == 2
        ports = {s.port for s in services}
        assert ports == {22, 80}

    def test_deduplicates_services(self, tmp_path: Path):
        """Test that duplicate services are not created."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10267" severity="0"/>
      <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10268" severity="0"/>
      <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10269" severity="1"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        services = self.get_services(entities)
        assert len(services) == 1

    # =========================================================================
    # Vulnerability Parsing Tests
    # =========================================================================

    def test_parse_vulnerability_with_cve(self, tmp_path: Path):
        """Test parsing vulnerability with CVE."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="445" protocol="tcp" svc_name="cifs" pluginID="97833" pluginName="MS17-010 EternalBlue" severity="4" pluginFamily="Windows">
        <description>The remote Windows host is affected by EternalBlue</description>
        <cve>CVE-2017-0144</cve>
        <cvss3_base_score>9.8</cvss3_base_score>
        <exploit_available>true</exploit_available>
        <exploit_framework_metasploit>true</exploit_framework_metasploit>
        <metasploit_name>MS17-010 EternalBlue SMB</metasploit_name>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1

        eternalblue = next((v for v in vulns if "EternalBlue" in v.title), None)
        assert eternalblue is not None
        assert eternalblue.cve_id == "CVE-2017-0144"
        assert eternalblue.cvss_score == 9.8
        assert eternalblue.exploit_available is True
        assert "MS17-010" in eternalblue.metasploit_module

    def test_parse_vulnerability_severity_mapping(self, tmp_path: Path):
        """Test that Nessus severity numbers map correctly."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="0" protocol="tcp" svc_name="general" pluginID="1" pluginName="Info" severity="0"/>
      <ReportItem port="0" protocol="tcp" svc_name="general" pluginID="2" pluginName="Low" severity="1"/>
      <ReportItem port="0" protocol="tcp" svc_name="general" pluginID="3" pluginName="Medium" severity="2"/>
      <ReportItem port="0" protocol="tcp" svc_name="general" pluginID="4" pluginName="High" severity="3"/>
      <ReportItem port="0" protocol="tcp" svc_name="general" pluginID="5" pluginName="Critical" severity="4"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        vulns = self.get_vulnerabilities(entities)
        severity_map = {v.title: v.severity for v in vulns}

        assert severity_map.get("Info") == "info"
        assert severity_map.get("Low") == "low"
        assert severity_map.get("Medium") == "medium"
        assert severity_map.get("High") == "high"
        assert severity_map.get("Critical") == "critical"

    def test_parse_vulnerability_with_cvss2_fallback(self, tmp_path: Path):
        """Test CVSS3 is preferred, CVSS2 is fallback."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="0" protocol="tcp" pluginID="1" pluginName="Test" severity="3">
        <cvss_base_score>7.5</cvss_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].cvss_score == 7.5

    # =========================================================================
    # Misconfiguration Parsing Tests
    # =========================================================================

    def test_parse_misconfiguration(self, tmp_path: Path):
        """Test parsing compliance/misconfiguration findings."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="0" protocol="tcp" pluginID="12345" pluginName="SMB Signing Misconfiguration" severity="2" pluginFamily="Compliance">
        <description>SMB signing is not required</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert "SMB Signing" in misconfigs[0].title

    # =========================================================================
    # Affected Asset ID Tests
    # =========================================================================

    def test_vuln_affected_asset_is_service_when_port(self, tmp_path: Path):
        """Test vulnerability affected_asset_id points to service when port > 0."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="445" protocol="tcp" svc_name="cifs" pluginID="1" pluginName="Test" severity="3"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert "445" in vulns[0].affected_asset_id

    def test_vuln_affected_asset_is_host_when_no_port(self, tmp_path: Path):
        """Test vulnerability affected_asset_id points to host when port is 0."""
        xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <HostProperties><tag name="host-ip">192.168.1.1</tag></HostProperties>
      <ReportItem port="0" protocol="tcp" svc_name="general" pluginID="1" pluginName="Test" severity="3"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        nessus_file = tmp_path / "scan.nessus"
        nessus_file.write_text(xml_content)

        parser = NessusParser()
        entities = list(parser.parse(nessus_file))

        vulns = self.get_vulnerabilities(entities)
        hosts = self.get_hosts(entities)
        assert len(vulns) >= 1
        assert vulns[0].affected_asset_id == hosts[0].id
