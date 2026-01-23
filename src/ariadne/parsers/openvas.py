"""OpenVAS/GVM XML report parser."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class OpenVASParser(BaseParser):
    """Parser for OpenVAS/GVM XML report files."""

    name = "openvas"
    description = "Parse OpenVAS/Greenbone Vulnerability Manager reports"
    file_patterns = ["*openvas*.xml", "*gvm*.xml", "*greenbone*.xml"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    SEVERITY_MAP = {
        "Log": "info",
        "Low": "low",
        "Medium": "medium",
        "High": "high",
        "Critical": "critical",
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an OpenVAS XML file and yield entities."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        seen_hosts: dict[str, Host] = {}
        seen_services: dict[str, Service] = {}

        for result in root.findall(".//result"):
            yield from self._parse_result(result, seen_hosts, seen_services)

        for result in root.findall(".//results/result"):
            yield from self._parse_result(result, seen_hosts, seen_services)

    def _parse_result(
        self,
        result: ET.Element,
        seen_hosts: dict[str, Host],
        seen_services: dict[str, Service]
    ) -> Generator[Entity, None, None]:
        """Parse a single result element."""
        host_elem = result.find("host")
        if host_elem is None or not host_elem.text:
            return

        host_ip = host_elem.text.strip()

        if host_ip not in seen_hosts:
            hostname = None
            hostname_elem = host_elem.find("hostname")
            if hostname_elem is not None and hostname_elem.text:
                hostname = hostname_elem.text.strip()

            host = Host(
                ip=host_ip,
                hostname=hostname,
                source="openvas",
            )
            seen_hosts[host_ip] = host
            yield host
        else:
            host = seen_hosts[host_ip]

        port_str = self._get_text(result, "port", "general/tcp")
        port, protocol = self._parse_port(port_str)

        service_key = f"{host_ip}:{port}/{protocol}"
        if port > 0 and service_key not in seen_services:
            service = Service(
                port=port,
                protocol=protocol,
                name=self._guess_service(port),
                host_id=host.id,
                source="openvas",
            )
            seen_services[service_key] = service
            yield service
            yield Relationship(
                source_id=service.id,
                target_id=host.id,
                relation_type=RelationType.RUNS_ON,
                source="openvas",
            )

        affected_id = seen_services[service_key].id if service_key in seen_services else host.id

        nvt = result.find("nvt")
        if nvt is None:
            return

        oid = nvt.get("oid", "")
        name = self._get_text(nvt, "name", "Unknown")
        family = self._get_text(nvt, "family", "")

        cvss_str = self._get_text(nvt, "cvss_base", "")
        cvss_score = None
        if cvss_str:
            try:
                cvss_score = float(cvss_str)
            except ValueError:
                pass

        severity_text = self._get_text(result, "severity", "")
        threat = self._get_text(result, "threat", "")

        severity = self._determine_severity(severity_text, threat, cvss_score)

        description = self._get_text(result, "description", "")

        cve_id = None
        refs = []
        for ref in nvt.findall(".//ref"):
            ref_type = ref.get("type", "")
            ref_id = ref.get("id", "")
            if ref_type.lower() == "cve" and ref_id:
                if cve_id is None:
                    cve_id = ref_id
                refs.append(ref_id)
            elif ref_id:
                refs.append(ref_id)

        cve_elem = nvt.find("cve")
        if cve_elem is not None and cve_elem.text and cve_elem.text != "NOCVE":
            if cve_id is None:
                cve_id = cve_elem.text.strip()

        solution = self._get_text(nvt, "solution", "")
        tags_text = self._get_text(nvt, "tags", "")

        if "compliance" in family.lower() or "policy" in family.lower():
            yield Misconfiguration(
                title=name,
                description=description,
                severity=severity,
                affected_asset_id=affected_id,
                source="openvas",
                check_id=oid,
                remediation=solution,
                references=refs,
                raw_data={
                    "family": family,
                    "oid": oid,
                    "qod": self._get_text(result, "qod/value", ""),
                },
            )
        else:
            yield Vulnerability(
                title=name,
                description=description,
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_asset_id=affected_id,
                source="openvas",
                references=refs,
                raw_data={
                    "family": family,
                    "oid": oid,
                    "solution": solution,
                    "tags": tags_text,
                    "qod": self._get_text(result, "qod/value", ""),
                },
            )

    def _parse_port(self, port_str: str) -> tuple[int, str]:
        """Parse port string like '443/tcp' or 'general/tcp'."""
        parts = port_str.split("/")
        protocol = parts[1] if len(parts) > 1 else "tcp"

        port_part = parts[0]
        if port_part.isdigit():
            return int(port_part), protocol

        if port_part == "general":
            return 0, protocol

        port_match = port_part.split()
        if port_match and port_match[0].isdigit():
            return int(port_match[0]), protocol

        return 0, protocol

    def _determine_severity(self, severity_text: str, threat: str, cvss: float | None) -> str:
        """Determine severity from various sources."""
        if cvss is not None:
            if cvss >= 9.0:
                return "critical"
            elif cvss >= 7.0:
                return "high"
            elif cvss >= 4.0:
                return "medium"
            elif cvss > 0:
                return "low"
            return "info"

        if threat:
            return self.SEVERITY_MAP.get(threat, "medium")

        try:
            sev_float = float(severity_text)
            if sev_float >= 9.0:
                return "critical"
            elif sev_float >= 7.0:
                return "high"
            elif sev_float >= 4.0:
                return "medium"
            elif sev_float > 0:
                return "low"
            return "info"
        except ValueError:
            return "medium"

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 8080: "http-proxy",
        }
        return port_map.get(port, "unknown")

    def _get_text(self, elem: ET.Element, path: str, default: str = "") -> str:
        """Get text content from element or child."""
        if "/" in path:
            found = elem.find(path)
        else:
            found = elem.find(path)

        if found is not None and found.text:
            return found.text.strip()
        return default

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an OpenVAS XML file."""
        if file_path.suffix.lower() != ".xml":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"openvas",
                    b"<report",
                    b"<result",
                    b"<nvt",
                    b"Greenbone",
                    b"GVM",
                    b"gvmd",
                    b"<host>",
                    b"cvss_base",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
