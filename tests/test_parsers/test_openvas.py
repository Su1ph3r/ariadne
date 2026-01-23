"""Tests for OpenVAS parser."""

import pytest
from pathlib import Path

from ariadne.parsers.openvas import OpenVASParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestOpenVASParser(BaseParserTest):
    """Test OpenVASParser functionality."""

    parser_class = OpenVASParser
    expected_name = "openvas"
    expected_patterns = ["*openvas*.xml", "*gvm*.xml", "*greenbone*.xml"]
    expected_entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_openvas_xml(self, tmp_path: Path):
        """Test detection of OpenVAS XML file."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <nvt oid="1.2.3.4"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas_report.xml"
        xml_file.write_text(content)

        assert OpenVASParser.can_parse(xml_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """<?xml version="1.0"?>
<report>
  <host>192.168.1.100</host>
  <nvt oid="1.2.3">
    <name>Test Vuln</name>
    <cvss_base>7.5</cvss_base>
  </nvt>
</report>
"""
        xml_file = tmp_path / "report.xml"
        xml_file.write_text(content)

        assert OpenVASParser.can_parse(xml_file)

    def test_cannot_parse_random_xml(self, tmp_path: Path):
        """Test that random XML is rejected."""
        content = """<?xml version="1.0"?>
<random><data>test</data></random>
"""
        xml_file = tmp_path / "random.xml"
        xml_file.write_text(content)

        assert not OpenVASParser.can_parse(xml_file)

    def test_cannot_parse_non_xml(self, tmp_path: Path):
        """Test that non-XML files are rejected."""
        txt_file = tmp_path / "openvas.txt"
        txt_file.write_text("openvas results")

        assert not OpenVASParser.can_parse(txt_file)

    # =========================================================================
    # Host Parsing Tests
    # =========================================================================

    def test_parse_host(self, tmp_path: Path):
        """Test parsing host from OpenVAS result."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100
      <hostname>server.local</hostname>
    </host>
    <port>general/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3"><name>Vuln1</name></nvt>
  </result>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="4.5.6"><name>Vuln2</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1

    # =========================================================================
    # Service Parsing Tests
    # =========================================================================

    def test_parse_service(self, tmp_path: Path):
        """Test parsing service from port information."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>443/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 443
        assert services[0].protocol == "tcp"

    def test_service_creates_relationship(self, tmp_path: Path):
        """Test that service creates RUNS_ON relationship."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>22/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    def test_guesses_service_name(self, tmp_path: Path):
        """Test service name guessing from port."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>22/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].name == "ssh"

    def test_skips_general_port(self, tmp_path: Path):
        """Test that general/tcp doesn't create service."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        services = self.get_services(entities)
        assert len(services) == 0

    # =========================================================================
    # Vulnerability Parsing Tests
    # =========================================================================

    def test_parse_vulnerability(self, tmp_path: Path):
        """Test parsing vulnerability from NVT."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>443/tcp</port>
    <nvt oid="1.2.3.4.5">
      <name>Test Vulnerability</name>
      <family>Web Servers</family>
      <cvss_base>7.5</cvss_base>
    </nvt>
    <description>This is a test vulnerability</description>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].title == "Test Vulnerability"

    def test_parse_vulnerability_with_cve(self, tmp_path: Path):
        """Test parsing vulnerability with CVE reference."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3">
      <name>CVE Test</name>
      <cve>CVE-2021-44228</cve>
    </nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].cve_id == "CVE-2021-44228"

    def test_parse_vulnerability_with_ref_cve(self, tmp_path: Path):
        """Test parsing vulnerability with CVE in ref element."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3">
      <name>CVE Test</name>
      <refs>
        <ref type="cve" id="CVE-2020-1234"/>
      </refs>
    </nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].cve_id == "CVE-2020-1234"

    def test_severity_from_cvss(self, tmp_path: Path):
        """Test severity calculation from CVSS score."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3">
      <name>Critical Vuln</name>
      <cvss_base>9.8</cvss_base>
    </nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].severity == "critical"

    def test_severity_from_threat(self, tmp_path: Path):
        """Test severity calculation from threat level."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <threat>High</threat>
    <nvt oid="1.2.3"><name>High Vuln</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].severity == "high"

    # =========================================================================
    # Misconfiguration Tests
    # =========================================================================

    def test_parse_compliance_as_misconfiguration(self, tmp_path: Path):
        """Test that compliance findings are misconfigurations."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3">
      <name>Compliance Check Failed</name>
      <family>Policy Compliance</family>
      <solution>Fix the configuration</solution>
    </nvt>
    <description>Configuration is not compliant</description>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert "Compliance" in misconfigs[0].title

    # =========================================================================
    # Alternative Format Tests
    # =========================================================================

    def test_parse_results_wrapper(self, tmp_path: Path):
        """Test parsing results inside results wrapper."""
        content = """<?xml version="1.0"?>
<report>
  <results>
    <result>
      <host>192.168.1.100</host>
      <port>general/tcp</port>
      <nvt oid="1.2.3"><name>Test</name></nvt>
    </result>
  </results>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_report(self, tmp_path: Path):
        """Test handling of empty report."""
        content = """<?xml version="1.0"?>
<report></report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_host(self, tmp_path: Path):
        """Test handling of result without host."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <port>443/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        # Should not crash
        assert isinstance(entities, list)

    def test_handles_missing_nvt(self, tmp_path: Path):
        """Test handling of result without NVT."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>443/tcp</port>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        # Should create host but no vulnerability
        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_openvas(self, tmp_path: Path):
        """Test that source is set to openvas."""
        content = """<?xml version="1.0"?>
<report>
  <result>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <nvt oid="1.2.3"><name>Test</name></nvt>
  </result>
</report>
"""
        xml_file = tmp_path / "openvas.xml"
        xml_file.write_text(content)

        parser = OpenVASParser()
        entities = list(parser.parse(xml_file))

        for entity in entities:
            assert entity.source == "openvas"
