"""Nmap XML output parser."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class NmapParser(BaseParser):
    """Parser for Nmap XML output files."""

    name = "nmap"
    description = "Parse Nmap XML scan results"
    file_patterns = ["*.xml", "nmap_*.xml", "*nmap*.xml"]
    entity_types = ["Host", "Service", "Vulnerability"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an Nmap XML file and yield entities."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        if root.tag != "nmaprun":
            return

        for host_elem in root.findall(".//host"):
            host = self._parse_host(host_elem)
            if host:
                yield host

                for port_elem in host_elem.findall(".//port"):
                    service = self._parse_service(port_elem, host.id)
                    if service:
                        yield service

                        yield Relationship(
                            source_id=service.id,
                            target_id=host.id,
                            relation_type=RelationType.RUNS_ON,
                        )

                        for vuln in self._parse_vulns(port_elem, service.id):
                            yield vuln

    def _parse_host(self, host_elem: ET.Element) -> Host | None:
        """Parse a host element."""
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            return None

        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host_elem.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            return None

        ip = addr_elem.get("addr", "")

        hostname = None
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name")

        os_name = None
        os_elem = host_elem.find(".//osmatch")
        if os_elem is not None:
            os_name = os_elem.get("name")

        return Host(
            ip=ip,
            hostname=hostname,
            os=os_name,
            source="nmap",
        )

    def _parse_service(self, port_elem: ET.Element, host_id: str) -> Service | None:
        """Parse a port/service element."""
        state = port_elem.find("state")
        if state is None or state.get("state") != "open":
            return None

        port = int(port_elem.get("portid", 0))
        protocol = port_elem.get("protocol", "tcp")

        service_elem = port_elem.find("service")
        name = "unknown"
        product = None
        version = None

        if service_elem is not None:
            name = service_elem.get("name", "unknown")
            product = service_elem.get("product")
            version = service_elem.get("version")

        return Service(
            port=port,
            protocol=protocol,
            name=name,
            product=product,
            version=version,
            host_id=host_id,
            source="nmap",
        )

    def _parse_vulns(self, port_elem: ET.Element, service_id: str) -> Generator[Vulnerability, None, None]:
        """Parse vulnerability information from NSE scripts."""
        for script in port_elem.findall(".//script"):
            script_id = script.get("id", "")

            if "vuln" in script_id.lower() or "cve" in script_id.lower():
                output = script.get("output", "")

                cves = self._extract_cves(output)
                for cve in cves:
                    yield Vulnerability(
                        cve_id=cve,
                        title=f"{script_id}: {cve}",
                        description=output[:500],
                        affected_asset_id=service_id,
                        source="nmap",
                    )

                if not cves and output:
                    yield Vulnerability(
                        title=script_id,
                        description=output[:500],
                        affected_asset_id=service_id,
                        source="nmap",
                    )

    def _extract_cves(self, text: str) -> list[str]:
        """Extract CVE IDs from text."""
        import re
        pattern = r"CVE-\d{4}-\d{4,}"
        return list(set(re.findall(pattern, text, re.IGNORECASE)))

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an Nmap XML file."""
        if not file_path.suffix.lower() == ".xml":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(500)
                return b"nmaprun" in header or b"nmap" in header.lower()
        except Exception:
            return False
