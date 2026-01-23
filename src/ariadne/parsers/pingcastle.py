"""PingCastle XML/HTML report parser for AD security assessment."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class PingCastleParser(BaseParser):
    """Parser for PingCastle AD health assessment XML reports."""

    name = "pingcastle"
    description = "Parse PingCastle Active Directory security assessment reports"
    file_patterns = ["*pingcastle*.xml", "ad_hc_*.xml", "*_pingcastle_report.xml"]
    entity_types = ["Host", "User", "Vulnerability", "Misconfiguration"]

    SEVERITY_MAP = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a PingCastle XML file and yield entities."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        domain_info = self._parse_domain_info(root)
        if domain_info:
            yield domain_info

        yield from self._parse_domain_controllers(root)
        yield from self._parse_risk_rules(root)
        yield from self._parse_privileged_groups(root)
        yield from self._parse_trusts(root)
        yield from self._parse_gpo_issues(root)

    def _parse_domain_info(self, root: ET.Element) -> Host | None:
        """Parse domain information."""
        domain_name = self._get_text(root, ".//DomainName") or self._get_text(root, ".//Domain")
        if not domain_name:
            return None

        forest_level = self._get_text(root, ".//ForestFunctionalLevel")
        domain_level = self._get_text(root, ".//DomainFunctionalLevel")

        return Host(
            ip="",
            hostname=domain_name,
            domain=domain_name,
            source="pingcastle",
            tags=["domain", "active-directory"],
            raw_properties={
                "forest_level": forest_level,
                "domain_level": domain_level,
                "global_score": self._get_text(root, ".//GlobalScore"),
                "stale_objects_score": self._get_text(root, ".//StaleObjectsScore"),
                "privileged_score": self._get_text(root, ".//PrivilegiedGroupScore"),
                "trust_score": self._get_text(root, ".//TrustScore"),
                "anomaly_score": self._get_text(root, ".//AnomalyScore"),
            },
        )

    def _parse_domain_controllers(self, root: ET.Element) -> Generator[Entity, None, None]:
        """Parse domain controller information."""
        for dc_elem in root.findall(".//DomainController"):
            dc_name = self._get_text(dc_elem, "DCName") or self._get_text(dc_elem, "Name")
            if not dc_name:
                continue

            ip = self._get_text(dc_elem, "IP") or ""
            os_version = self._get_text(dc_elem, "OperatingSystem")

            host = Host(
                ip=ip,
                hostname=dc_name,
                os=os_version,
                is_dc=True,
                source="pingcastle",
                tags=["domain-controller"],
            )
            yield host

            if self._get_text(dc_elem, "LDAPSigning") == "false":
                yield Misconfiguration(
                    title=f"LDAP Signing not required on {dc_name}",
                    description="LDAP signing is not required, enabling relay attacks",
                    severity="medium",
                    affected_asset_id=host.id,
                    source="pingcastle",
                    check_id="ldap_signing",
                )

            if self._get_text(dc_elem, "SMBv1") == "true":
                yield Misconfiguration(
                    title=f"SMBv1 enabled on {dc_name}",
                    description="SMBv1 is enabled, which is vulnerable to multiple exploits",
                    severity="high",
                    affected_asset_id=host.id,
                    source="pingcastle",
                    check_id="smbv1",
                )

    def _parse_risk_rules(self, root: ET.Element) -> Generator[Entity, None, None]:
        """Parse risk rule findings."""
        for rule_elem in root.findall(".//RiskRule"):
            rule_id = self._get_text(rule_elem, "RuleId") or self._get_text(rule_elem, "RiskId")
            if not rule_id:
                continue

            category = self._get_text(rule_elem, "Category", "Unknown")
            rationale = self._get_text(rule_elem, "Rationale", "")
            documentation = self._get_text(rule_elem, "Documentation", "")
            points = self._get_text(rule_elem, "Points", "0")

            try:
                point_value = int(points)
            except ValueError:
                point_value = 0

            if point_value >= 30:
                severity = "critical"
            elif point_value >= 20:
                severity = "high"
            elif point_value >= 10:
                severity = "medium"
            elif point_value > 0:
                severity = "low"
            else:
                severity = "info"

            yield Misconfiguration(
                title=f"{category}: {rule_id}",
                description=rationale,
                severity=severity,
                source="pingcastle",
                check_id=rule_id,
                rationale=rationale,
                remediation=documentation,
                raw_data={"points": point_value, "category": category},
            )

    def _parse_privileged_groups(self, root: ET.Element) -> Generator[Entity, None, None]:
        """Parse privileged group membership."""
        for group_elem in root.findall(".//PrivilegedGroup"):
            group_name = self._get_text(group_elem, "GroupName")
            if not group_name:
                continue

            member_count = self._get_text(group_elem, "NumberOfMember", "0")
            try:
                count = int(member_count)
            except ValueError:
                count = 0

            if count > 50:
                yield Misconfiguration(
                    title=f"Excessive members in {group_name}",
                    description=f"The group {group_name} has {count} members, which may indicate over-privileged accounts",
                    severity="medium",
                    source="pingcastle",
                    check_id=f"excessive_members_{group_name}",
                )

            for member_elem in group_elem.findall(".//Member"):
                member_name = self._get_text(member_elem, "Name") or member_elem.text
                if member_name:
                    domain_part = None
                    username = member_name
                    if "\\" in member_name:
                        domain_part, username = member_name.split("\\", 1)

                    user = User(
                        username=username,
                        domain=domain_part,
                        is_admin=True,
                        groups=[group_name],
                        source="pingcastle",
                    )
                    yield user

    def _parse_trusts(self, root: ET.Element) -> Generator[Entity, None, None]:
        """Parse domain trust relationships."""
        for trust_elem in root.findall(".//Trust"):
            trust_partner = self._get_text(trust_elem, "TrustPartner")
            if not trust_partner:
                continue

            trust_direction = self._get_text(trust_elem, "TrustDirection", "")
            trust_type = self._get_text(trust_elem, "TrustType", "")
            sid_filtering = self._get_text(trust_elem, "SIDFilteringEnabled", "true")

            trusted_domain = Host(
                ip="",
                hostname=trust_partner,
                domain=trust_partner,
                source="pingcastle",
                tags=["trusted-domain"],
            )
            yield trusted_domain

            if sid_filtering.lower() == "false":
                yield Misconfiguration(
                    title=f"SID filtering disabled for trust with {trust_partner}",
                    description=f"SID filtering is disabled on the trust with {trust_partner}, potentially enabling SID history attacks",
                    severity="high",
                    affected_asset_id=trusted_domain.id,
                    source="pingcastle",
                    check_id="sid_filtering_disabled",
                )

    def _parse_gpo_issues(self, root: ET.Element) -> Generator[Entity, None, None]:
        """Parse GPO-related security issues."""
        for gpo_elem in root.findall(".//GPOInfo"):
            gpo_name = self._get_text(gpo_elem, "GPOName")
            if not gpo_name:
                continue

            for issue_elem in gpo_elem.findall(".//Issue"):
                issue_text = issue_elem.text or self._get_text(issue_elem, "Description", "")
                if issue_text:
                    yield Misconfiguration(
                        title=f"GPO Issue: {gpo_name}",
                        description=issue_text,
                        severity="medium",
                        source="pingcastle",
                        check_id=f"gpo_{gpo_name}",
                    )

    def _get_text(self, elem: ET.Element, path: str, default: str = "") -> str:
        """Safely get text from an XML element."""
        found = elem.find(path)
        if found is not None and found.text:
            return found.text.strip()
        return default

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a PingCastle XML file."""
        if file_path.suffix.lower() != ".xml":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"PingCastle",
                    b"<HealthcheckData",
                    b"<DomainController",
                    b"<RiskRule",
                    b"GlobalScore",
                    b"PrivilegiedGroupScore",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
