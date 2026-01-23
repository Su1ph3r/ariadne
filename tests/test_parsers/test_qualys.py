"""Tests for Qualys parser."""

import pytest
from pathlib import Path

from ariadne.parsers.qualys import QualysParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestQualysParser(BaseParserTest):
    """Test QualysParser functionality."""

    parser_class = QualysParser
    expected_name = "qualys"
    expected_patterns = ["*qualys*.xml", "*qualys*.csv", "qualys_*.xml", "qualys_*.csv"]
    expected_entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_qualys_xml(self, tmp_path: Path):
        """Test detection of Qualys XML file."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="4">
      <TITLE>Test Vulnerability</TITLE>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys_report.xml"
        xml_file.write_text(content)

        assert QualysParser.can_parse(xml_file)

    def test_can_parse_qualys_csv(self, tmp_path: Path):
        """Test detection of Qualys CSV file."""
        content = """"IP","QID","Title","Severity"
"192.168.1.100","12345","Test Vuln","4"
"""
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text(content)

        assert QualysParser.can_parse(csv_file)

    def test_cannot_parse_random_xml(self, tmp_path: Path):
        """Test that random XML is rejected."""
        content = """<?xml version="1.0"?>
<random><data>test</data></random>
"""
        xml_file = tmp_path / "random.xml"
        xml_file.write_text(content)

        assert not QualysParser.can_parse(xml_file)

    # =========================================================================
    # XML Host Parsing Tests
    # =========================================================================

    def test_parse_xml_host(self, tmp_path: Path):
        """Test parsing host from XML."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <DNS>server.local</DNS>
    <OS>Windows Server 2019</OS>
    <VULN number="12345" severity="3">
      <TITLE>Test</TITLE>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"
        assert hosts[0].hostname == "server.local"
        assert "Windows" in hosts[0].os

    def test_parse_xml_host_alternative_format(self, tmp_path: Path):
        """Test parsing host from alternative XML format."""
        content = """<?xml version="1.0"?>
<REPORT>
  <IP value="192.168.1.100">
    <VULN number="12345" severity="3">
      <TITLE>Test</TITLE>
    </VULN>
  </IP>
</REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="1" severity="3"><TITLE>Vuln1</TITLE></VULN>
    <VULN number="2" severity="4"><TITLE>Vuln2</TITLE></VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1

    # =========================================================================
    # XML Service Parsing Tests
    # =========================================================================

    def test_parse_xml_service(self, tmp_path: Path):
        """Test parsing service from XML."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="3">
      <TITLE>Test</TITLE>
      <PORT>443</PORT>
      <PROTOCOL>tcp</PROTOCOL>
      <SERVICE>https</SERVICE>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 443
        assert services[0].name == "https"

    def test_service_creates_relationship(self, tmp_path: Path):
        """Test that service creates RUNS_ON relationship."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="3">
      <TITLE>Test</TITLE>
      <PORT>22</PORT>
      <PROTOCOL>tcp</PROTOCOL>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        relationships = self.get_relationships(entities)
        runs_on = [r for r in relationships if r.relation_type.value == "runs_on"]
        assert len(runs_on) >= 1

    # =========================================================================
    # XML Vulnerability Parsing Tests
    # =========================================================================

    def test_parse_xml_vulnerability(self, tmp_path: Path):
        """Test parsing vulnerability from XML."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="5">
      <TITLE>Critical Vulnerability</TITLE>
      <DIAGNOSIS>This is a critical vulnerability</DIAGNOSIS>
      <SOLUTION>Patch the system</SOLUTION>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].title == "Critical Vulnerability"
        assert vulns[0].severity == "critical"

    def test_parse_xml_vulnerability_with_cve(self, tmp_path: Path):
        """Test parsing vulnerability with CVE."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="4">
      <TITLE>CVE Test</TITLE>
      <CVE_ID>CVE-2021-44228</CVE_ID>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].cve_id == "CVE-2021-44228"

    def test_parse_xml_vulnerability_with_cvss(self, tmp_path: Path):
        """Test parsing vulnerability with CVSS score."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="4">
      <TITLE>CVSS Test</TITLE>
      <CVSS_BASE>7.5</CVSS_BASE>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].cvss_score == 7.5

    def test_severity_mapping(self, tmp_path: Path):
        """Test severity level mapping."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="1" severity="1"><TITLE>Info</TITLE></VULN>
    <VULN number="2" severity="2"><TITLE>Low</TITLE></VULN>
    <VULN number="3" severity="3"><TITLE>Medium</TITLE></VULN>
    <VULN number="4" severity="4"><TITLE>High</TITLE></VULN>
    <VULN number="5" severity="5"><TITLE>Critical</TITLE></VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        vulns = self.get_vulnerabilities(entities)
        severities = {v.title: v.severity for v in vulns}
        assert severities.get("Info") == "info"
        assert severities.get("Low") == "low"
        assert severities.get("Medium") == "medium"
        assert severities.get("High") == "high"
        assert severities.get("Critical") == "critical"

    # =========================================================================
    # XML Misconfiguration Tests
    # =========================================================================

    def test_parse_xml_compliance_as_misconfiguration(self, tmp_path: Path):
        """Test that compliance findings are misconfigurations."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="3">
      <TITLE>Policy Check Failed</TITLE>
      <CATEGORY>Policy Compliance</CATEGORY>
    </VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1

    # =========================================================================
    # CSV Parsing Tests
    # =========================================================================

    def test_parse_csv_host(self, tmp_path: Path):
        """Test parsing host from CSV."""
        content = """"IP","DNS","OS","QID","Title","Severity"
"192.168.1.100","server.local","Windows","12345","Test Vuln","4"
"""
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].ip == "192.168.1.100"

    def test_parse_csv_vulnerability(self, tmp_path: Path):
        """Test parsing vulnerability from CSV."""
        content = """"IP","QID","Title","Severity","CVE ID","CVSS Base"
"192.168.1.100","12345","Critical Vuln","5","CVE-2021-44228","10.0"
"""
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(csv_file))

        vulns = self.get_vulnerabilities(entities)
        assert len(vulns) >= 1
        assert vulns[0].title == "Critical Vuln"
        assert vulns[0].severity == "critical"
        assert vulns[0].cve_id == "CVE-2021-44228"
        assert vulns[0].cvss_score == 10.0

    def test_parse_csv_with_port(self, tmp_path: Path):
        """Test parsing CSV with port information."""
        content = """"IP","Port","Protocol","QID","Title","Severity"
"192.168.1.100","443","tcp","12345","HTTPS Vuln","3"
"""
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(csv_file))

        services = self.get_services(entities)
        assert len(services) >= 1
        assert services[0].port == 443

    def test_parse_csv_skips_header_rows(self, tmp_path: Path):
        """Test that CSV parsing skips header/metadata rows."""
        content = """Qualys Report
Generated: 2024-01-01
====================

"IP","QID","Title","Severity"
"192.168.1.100","12345","Test","3"
"""
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_xml(self, tmp_path: Path):
        """Test handling of empty XML."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT></QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_empty_csv(self, tmp_path: Path):
        """Test handling of empty CSV."""
        content = """"IP","QID","Title","Severity"
"""
        csv_file = tmp_path / "qualys.csv"
        csv_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(csv_file))

        assert isinstance(entities, list)

    def test_handles_invalid_ip(self, tmp_path: Path):
        """Test handling of invalid IP."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>not_an_ip</IP>
    <VULN number="12345" severity="3"><TITLE>Test</TITLE></VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 0

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_qualys(self, tmp_path: Path):
        """Test that source is set to qualys."""
        content = """<?xml version="1.0"?>
<QUALYS_REPORT>
  <HOST>
    <IP>192.168.1.100</IP>
    <VULN number="12345" severity="3"><TITLE>Test</TITLE></VULN>
  </HOST>
</QUALYS_REPORT>
"""
        xml_file = tmp_path / "qualys.xml"
        xml_file.write_text(content)

        parser = QualysParser()
        entities = list(parser.parse(xml_file))

        for entity in entities:
            assert entity.source == "qualys"
