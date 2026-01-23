"""Tests for PingCastle parser."""

import pytest
from pathlib import Path

from ariadne.parsers.pingcastle import PingCastleParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestPingCastleParser(BaseParserTest):
    """Test PingCastleParser functionality."""

    parser_class = PingCastleParser
    expected_name = "pingcastle"
    expected_patterns = ["*pingcastle*.xml", "ad_hc_*.xml", "*_pingcastle_report.xml"]
    expected_entity_types = ["Host", "User", "Vulnerability", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_pingcastle_xml(self, tmp_path: Path):
        """Test detection of PingCastle XML file."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainName>CORP.LOCAL</DomainName>
  <GlobalScore>50</GlobalScore>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle_report.xml"
        xml_file.write_text(content)

        assert PingCastleParser.can_parse(xml_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = """<?xml version="1.0"?>
<Report>
  <DomainController>
    <DCName>DC01</DCName>
  </DomainController>
  <RiskRule>
    <RuleId>S-Test</RuleId>
  </RiskRule>
</Report>
"""
        xml_file = tmp_path / "report.xml"
        xml_file.write_text(content)

        assert PingCastleParser.can_parse(xml_file)

    def test_cannot_parse_random_xml(self, tmp_path: Path):
        """Test that random XML is rejected."""
        content = """<?xml version="1.0"?>
<random><data>test</data></random>
"""
        xml_file = tmp_path / "random.xml"
        xml_file.write_text(content)

        assert not PingCastleParser.can_parse(xml_file)

    # =========================================================================
    # Domain Info Parsing Tests
    # =========================================================================

    def test_parse_domain_info(self, tmp_path: Path):
        """Test parsing domain information."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainName>CORP.LOCAL</DomainName>
  <ForestFunctionalLevel>2016</ForestFunctionalLevel>
  <DomainFunctionalLevel>2016</DomainFunctionalLevel>
  <GlobalScore>45</GlobalScore>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "CORP.LOCAL"
        assert "domain" in hosts[0].tags

    def test_stores_scores_in_raw_properties(self, tmp_path: Path):
        """Test that scores are stored in raw_properties."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainName>CORP.LOCAL</DomainName>
  <GlobalScore>50</GlobalScore>
  <StaleObjectsScore>20</StaleObjectsScore>
  <PrivilegiedGroupScore>15</PrivilegiedGroupScore>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].raw_properties.get("global_score") == "50"

    # =========================================================================
    # Domain Controller Parsing Tests
    # =========================================================================

    def test_parse_domain_controller(self, tmp_path: Path):
        """Test parsing domain controller information."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainController>
    <DCName>DC01</DCName>
    <IP>192.168.1.10</IP>
    <OperatingSystem>Windows Server 2019</OperatingSystem>
  </DomainController>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        dc_hosts = [h for h in hosts if h.is_dc]
        assert len(dc_hosts) >= 1
        assert dc_hosts[0].hostname == "DC01"
        assert dc_hosts[0].ip == "192.168.1.10"

    def test_parse_dc_ldap_signing_disabled(self, tmp_path: Path):
        """Test detection of LDAP signing disabled."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainController>
    <DCName>DC01</DCName>
    <LDAPSigning>false</LDAPSigning>
  </DomainController>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        ldap_signing = [m for m in misconfigs if "LDAP Signing" in m.title]
        assert len(ldap_signing) >= 1

    def test_parse_dc_smbv1_enabled(self, tmp_path: Path):
        """Test detection of SMBv1 enabled."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainController>
    <DCName>DC01</DCName>
    <SMBv1>true</SMBv1>
  </DomainController>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        smbv1 = [m for m in misconfigs if "SMBv1" in m.title]
        assert len(smbv1) >= 1
        assert smbv1[0].severity == "high"

    # =========================================================================
    # Risk Rule Parsing Tests
    # =========================================================================

    def test_parse_risk_rules(self, tmp_path: Path):
        """Test parsing risk rules."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <RiskRule>
    <RuleId>S-DomainAdmin</RuleId>
    <Category>Stale Objects</Category>
    <Rationale>There are stale admin accounts</Rationale>
    <Points>25</Points>
  </RiskRule>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert "S-DomainAdmin" in misconfigs[0].title

    def test_risk_rule_severity_from_points(self, tmp_path: Path):
        """Test severity calculation from risk rule points."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <RiskRule>
    <RuleId>Critical-Rule</RuleId>
    <Category>Test</Category>
    <Points>35</Points>
  </RiskRule>
  <RiskRule>
    <RuleId>High-Rule</RuleId>
    <Category>Test</Category>
    <Points>25</Points>
  </RiskRule>
  <RiskRule>
    <RuleId>Medium-Rule</RuleId>
    <Category>Test</Category>
    <Points>15</Points>
  </RiskRule>
  <RiskRule>
    <RuleId>Low-Rule</RuleId>
    <Category>Test</Category>
    <Points>5</Points>
  </RiskRule>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        severities = {m.check_id: m.severity for m in misconfigs}
        assert severities.get("Critical-Rule") == "critical"
        assert severities.get("High-Rule") == "high"
        assert severities.get("Medium-Rule") == "medium"
        assert severities.get("Low-Rule") == "low"

    # =========================================================================
    # Privileged Group Parsing Tests
    # =========================================================================

    def test_parse_privileged_group_members(self, tmp_path: Path):
        """Test parsing privileged group members."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <PrivilegedGroup>
    <GroupName>Domain Admins</GroupName>
    <NumberOfMember>5</NumberOfMember>
    <Member>
      <Name>CORP\\admin1</Name>
    </Member>
    <Member>
      <Name>CORP\\admin2</Name>
    </Member>
  </PrivilegedGroup>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        users = self.get_users(entities)
        assert len(users) >= 2
        assert all(u.is_admin for u in users)

    def test_parse_excessive_group_members(self, tmp_path: Path):
        """Test detection of excessive group members."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <PrivilegedGroup>
    <GroupName>Domain Admins</GroupName>
    <NumberOfMember>60</NumberOfMember>
  </PrivilegedGroup>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        excessive = [m for m in misconfigs if "Excessive" in m.title]
        assert len(excessive) >= 1

    # =========================================================================
    # Trust Parsing Tests
    # =========================================================================

    def test_parse_trusts(self, tmp_path: Path):
        """Test parsing domain trusts."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <Trust>
    <TrustPartner>PARTNER.LOCAL</TrustPartner>
    <TrustDirection>Bidirectional</TrustDirection>
    <TrustType>Forest</TrustType>
    <SIDFilteringEnabled>true</SIDFilteringEnabled>
  </Trust>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        hosts = self.get_hosts(entities)
        trusted = [h for h in hosts if "trusted-domain" in h.tags]
        assert len(trusted) >= 1
        assert trusted[0].hostname == "PARTNER.LOCAL"

    def test_parse_trust_sid_filtering_disabled(self, tmp_path: Path):
        """Test detection of SID filtering disabled."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <Trust>
    <TrustPartner>RISKY.LOCAL</TrustPartner>
    <SIDFilteringEnabled>false</SIDFilteringEnabled>
  </Trust>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        sid_filtering = [m for m in misconfigs if "SID filtering" in m.title]
        assert len(sid_filtering) >= 1
        assert sid_filtering[0].severity == "high"

    # =========================================================================
    # GPO Parsing Tests
    # =========================================================================

    def test_parse_gpo_issues(self, tmp_path: Path):
        """Test parsing GPO issues."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <GPOInfo>
    <GPOName>Default Domain Policy</GPOName>
    <Issue>
      <Description>Weak password policy settings</Description>
    </Issue>
  </GPOInfo>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        misconfigs = self.get_misconfigurations(entities)
        gpo_issues = [m for m in misconfigs if "GPO Issue" in m.title]
        assert len(gpo_issues) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_report(self, tmp_path: Path):
        """Test handling of empty report."""
        content = """<?xml version="1.0"?>
<HealthcheckData></HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        assert isinstance(entities, list)

    def test_handles_missing_dc_name(self, tmp_path: Path):
        """Test handling of DC without name."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainController>
    <IP>192.168.1.10</IP>
  </DomainController>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        # Should not crash
        assert isinstance(entities, list)

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_pingcastle(self, tmp_path: Path):
        """Test that source is set to pingcastle."""
        content = """<?xml version="1.0"?>
<HealthcheckData>
  <DomainName>CORP.LOCAL</DomainName>
</HealthcheckData>
"""
        xml_file = tmp_path / "pingcastle.xml"
        xml_file.write_text(content)

        parser = PingCastleParser()
        entities = list(parser.parse(xml_file))

        for entity in entities:
            assert entity.source == "pingcastle"
