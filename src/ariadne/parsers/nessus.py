"""Nessus .nessus XML output parser."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class NessusParser(BaseParser):
    """Parser for Nessus .nessus XML files."""

    name = "nessus"
    description = "Parse Nessus vulnerability scanner XML output"
    file_patterns = ["*.nessus", "nessus_*.xml"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    SEVERITY_MAP = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Nessus XML file and yield entities."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        for report_host in root.findall(".//ReportHost"):
            host = self._parse_host(report_host)
            if host:
                yield host

                seen_services: set[tuple[int, str]] = set()

                for item in report_host.findall(".//ReportItem"):
                    port = int(item.get("port", 0))
                    protocol = item.get("protocol", "tcp")
                    svc_name = item.get("svc_name", "unknown")

                    if port > 0 and (port, protocol) not in seen_services:
                        seen_services.add((port, protocol))
                        service = Service(
                            port=port,
                            protocol=protocol,
                            name=svc_name,
                            host_id=host.id,
                            source="nessus",
                        )
                        yield service
                        yield Relationship(
                            source_id=service.id,
                            target_id=host.id,
                            relation_type=RelationType.RUNS_ON,
                            source="nessus",
                        )

                    finding = self._parse_finding(item, host.id)
                    if finding:
                        yield finding

    def _parse_host(self, report_host: ET.Element) -> Host | None:
        """Parse a ReportHost element."""
        name = report_host.get("name", "")
        if not name:
            return None

        properties = {}
        for tag in report_host.findall(".//tag"):
            tag_name = tag.get("name", "")
            if tag_name and tag.text:
                properties[tag_name] = tag.text

        ip = properties.get("host-ip", name)
        hostname = properties.get("host-fqdn") or properties.get("netbios-name")
        os_name = properties.get("operating-system")

        return Host(
            ip=ip,
            hostname=hostname,
            os=os_name,
            source="nessus",
            raw_properties=properties,
        )

    def _parse_finding(self, item: ET.Element, host_id: str) -> Vulnerability | Misconfiguration | None:
        """Parse a ReportItem element into a finding."""
        plugin_id = item.get("pluginID", "")
        plugin_name = item.get("pluginName", "Unknown")
        severity_num = item.get("severity", "0")
        severity = self.SEVERITY_MAP.get(severity_num, "info")

        port = int(item.get("port", 0))
        protocol = item.get("protocol", "tcp")

        affected_id = host_id
        if port > 0:
            affected_id = f"service:{host_id}:{port}/{protocol}"

        description = ""
        desc_elem = item.find("description")
        if desc_elem is not None and desc_elem.text:
            description = desc_elem.text

        cve_id = None
        cve_elem = item.find("cve")
        if cve_elem is not None and cve_elem.text:
            cve_id = cve_elem.text

        cvss_score = None
        cvss_elem = item.find("cvss3_base_score")
        if cvss_elem is None:
            cvss_elem = item.find("cvss_base_score")
        if cvss_elem is not None and cvss_elem.text:
            try:
                cvss_score = float(cvss_elem.text)
            except ValueError:
                pass

        exploit_available = False
        exploit_elem = item.find("exploit_available")
        if exploit_elem is not None and exploit_elem.text:
            exploit_available = exploit_elem.text.lower() == "true"

        metasploit = None
        msf_elem = item.find("exploit_framework_metasploit")
        if msf_elem is not None and msf_elem.text and msf_elem.text.lower() == "true":
            msf_name = item.find("metasploit_name")
            if msf_name is not None and msf_name.text:
                metasploit = msf_name.text

        references = []
        for ref in item.findall(".//see_also"):
            if ref.text:
                references.extend(ref.text.strip().split("\n"))

        plugin_family = item.get("pluginFamily", "")
        if "compliance" in plugin_family.lower() or "misconfig" in plugin_name.lower():
            return Misconfiguration(
                title=plugin_name,
                description=description,
                severity=severity,
                affected_asset_id=affected_id,
                source="nessus",
                check_id=plugin_id,
                references=references,
            )

        return Vulnerability(
            title=plugin_name,
            description=description,
            severity=severity,
            affected_asset_id=affected_id,
            cve_id=cve_id,
            cvss_score=cvss_score,
            exploit_available=exploit_available,
            metasploit_module=metasploit,
            source="nessus",
            references=references,
            raw_data={"plugin_id": plugin_id, "plugin_family": plugin_family},
        )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Nessus XML file."""
        if file_path.suffix.lower() not in [".nessus", ".xml"]:
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(1000)
                return b"NessusClientData" in header or b"<Policy>" in header
        except Exception:
            return False
