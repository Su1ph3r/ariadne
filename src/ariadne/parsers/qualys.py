"""Qualys vulnerability scan XML/CSV report parser."""

import csv
import io
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class QualysParser(BaseParser):
    """Parser for Qualys vulnerability scan report files (XML/CSV)."""

    name = "qualys"
    description = "Parse Qualys vulnerability scanner reports"
    file_patterns = ["*qualys*.xml", "*qualys*.csv", "qualys_*.xml", "qualys_*.csv"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    SEVERITY_MAP = {
        "1": "info",
        "2": "low",
        "3": "medium",
        "4": "high",
        "5": "critical",
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Qualys report file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".csv":
            yield from self._parse_csv(file_path)
        else:
            yield from self._parse_xml(file_path)

    def _parse_xml(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Qualys XML report."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        seen_hosts: dict[str, Host] = {}
        seen_services: dict[str, Service] = {}

        for host_elem in root.findall(".//HOST"):
            yield from self._parse_host_xml(host_elem, seen_hosts, seen_services)

        for host_elem in root.findall(".//IP"):
            yield from self._parse_host_xml(host_elem, seen_hosts, seen_services)

    def _parse_host_xml(
        self,
        host_elem: ET.Element,
        seen_hosts: dict[str, Host],
        seen_services: dict[str, Service]
    ) -> Generator[Entity, None, None]:
        """Parse a host element from XML."""
        ip = (
            self._get_text(host_elem, "IP") or
            host_elem.get("value") or
            host_elem.text or ""
        ).strip()

        if not ip or not self._is_valid_ip(ip):
            ip_elem = host_elem.find(".//IP")
            if ip_elem is not None:
                ip = ip_elem.get("value") or ip_elem.text or ""

        if not ip or not self._is_valid_ip(ip):
            return

        if ip not in seen_hosts:
            hostname = self._get_text(host_elem, "DNS") or self._get_text(host_elem, "NETBIOS")
            os_info = self._get_text(host_elem, "OS") or self._get_text(host_elem, "OPERATING_SYSTEM")

            host = Host(
                ip=ip,
                hostname=hostname if hostname else None,
                os=os_info if os_info else None,
                source="qualys",
            )
            seen_hosts[ip] = host
            yield host
        else:
            host = seen_hosts[ip]

        for vuln_elem in host_elem.findall(".//VULN"):
            yield from self._parse_vuln_xml(vuln_elem, host, seen_services)

        for vuln_elem in host_elem.findall(".//CAT"):
            for v in vuln_elem.findall(".//VULN"):
                yield from self._parse_vuln_xml(v, host, seen_services)

        for det_elem in host_elem.findall(".//DETECTION"):
            yield from self._parse_detection_xml(det_elem, host, seen_services)

    def _parse_vuln_xml(
        self,
        vuln_elem: ET.Element,
        host: Host,
        seen_services: dict[str, Service]
    ) -> Generator[Entity, None, None]:
        """Parse a vulnerability element."""
        qid = vuln_elem.get("number") or self._get_text(vuln_elem, "QID")
        title = self._get_text(vuln_elem, "TITLE") or f"QID {qid}"

        severity_num = (
            vuln_elem.get("severity") or
            self._get_text(vuln_elem, "SEVERITY") or
            "3"
        )
        severity = self.SEVERITY_MAP.get(severity_num, "medium")

        port_str = self._get_text(vuln_elem, "PORT") or "0"
        protocol = self._get_text(vuln_elem, "PROTOCOL") or "tcp"

        try:
            port = int(port_str)
        except ValueError:
            port = 0

        affected_id = host.id
        if port > 0:
            service_key = f"{host.ip}:{port}/{protocol}"
            if service_key not in seen_services:
                service = Service(
                    port=port,
                    protocol=protocol.lower(),
                    name=self._get_text(vuln_elem, "SERVICE") or self._guess_service(port),
                    host_id=host.id,
                    source="qualys",
                )
                seen_services[service_key] = service
                yield service
                yield Relationship(
                    source_id=service.id,
                    target_id=host.id,
                    relation_type=RelationType.RUNS_ON,
                    source="qualys",
                )
            affected_id = seen_services[service_key].id

        cvss_str = self._get_text(vuln_elem, "CVSS_BASE") or self._get_text(vuln_elem, "CVSS3_BASE")
        cvss_score = None
        if cvss_str:
            try:
                cvss_score = float(cvss_str)
            except ValueError:
                pass

        cve_text = self._get_text(vuln_elem, "CVE_ID") or self._get_text(vuln_elem, "CVE")
        cve_id = None
        refs = []
        if cve_text:
            cves = [c.strip() for c in cve_text.replace(",", " ").split() if c.strip().startswith("CVE-")]
            if cves:
                cve_id = cves[0]
                refs = cves

        description = (
            self._get_text(vuln_elem, "DIAGNOSIS") or
            self._get_text(vuln_elem, "CONSEQUENCE") or
            ""
        )
        solution = self._get_text(vuln_elem, "SOLUTION")

        vuln_type = self._get_text(vuln_elem, "VULN_TYPE") or self._get_text(vuln_elem, "TYPE")
        category = self._get_text(vuln_elem, "CATEGORY")

        if vuln_type and "info" in vuln_type.lower():
            severity = "info"

        if category and ("compliance" in category.lower() or "policy" in category.lower()):
            yield Misconfiguration(
                title=title,
                description=description,
                severity=severity,
                affected_asset_id=affected_id,
                source="qualys",
                check_id=qid,
                remediation=solution,
                references=refs,
            )
        else:
            yield Vulnerability(
                title=title,
                description=description,
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_asset_id=affected_id,
                source="qualys",
                references=refs,
                raw_data={
                    "qid": qid,
                    "solution": solution,
                    "category": category,
                },
            )

    def _parse_detection_xml(
        self,
        det_elem: ET.Element,
        host: Host,
        seen_services: dict[str, Service]
    ) -> Generator[Entity, None, None]:
        """Parse a detection element (alternative format)."""
        qid = self._get_text(det_elem, "QID")
        if not qid:
            return

        port_str = self._get_text(det_elem, "PORT") or "0"
        protocol = self._get_text(det_elem, "PROTOCOL") or "tcp"

        try:
            port = int(port_str)
        except ValueError:
            port = 0

        affected_id = host.id
        if port > 0:
            service_key = f"{host.ip}:{port}/{protocol}"
            if service_key not in seen_services:
                service = Service(
                    port=port,
                    protocol=protocol.lower(),
                    name=self._guess_service(port),
                    host_id=host.id,
                    source="qualys",
                )
                seen_services[service_key] = service
                yield service
                yield Relationship(
                    source_id=service.id,
                    target_id=host.id,
                    relation_type=RelationType.RUNS_ON,
                    source="qualys",
                )
            affected_id = seen_services[service_key].id

        severity_num = self._get_text(det_elem, "SEVERITY") or "3"
        severity = self.SEVERITY_MAP.get(severity_num, "medium")

        yield Vulnerability(
            title=f"QID {qid}",
            description=self._get_text(det_elem, "RESULTS", ""),
            severity=severity,
            affected_asset_id=affected_id,
            source="qualys",
            raw_data={"qid": qid},
        )

    def _parse_csv(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Qualys CSV report."""
        content = file_path.read_text(errors="ignore")

        start_idx = 0
        for i, line in enumerate(content.split("\n")):
            if line.startswith('"IP"') or line.startswith("IP,") or "QID" in line:
                start_idx = i
                break

        lines = content.split("\n")[start_idx:]
        csv_content = "\n".join(lines)

        reader = csv.DictReader(io.StringIO(csv_content))

        seen_hosts: dict[str, Host] = {}
        seen_services: dict[str, Service] = {}

        for row in reader:
            ip = row.get("IP") or row.get("ip") or row.get("Host IP") or ""
            if not ip or not self._is_valid_ip(ip):
                continue

            if ip not in seen_hosts:
                host = Host(
                    ip=ip,
                    hostname=row.get("DNS") or row.get("NetBIOS") or None,
                    os=row.get("OS") or None,
                    source="qualys",
                )
                seen_hosts[ip] = host
                yield host
            else:
                host = seen_hosts[ip]

            port_str = row.get("Port") or row.get("port") or "0"
            protocol = row.get("Protocol") or row.get("protocol") or "tcp"

            try:
                port = int(port_str)
            except ValueError:
                port = 0

            affected_id = host.id
            if port > 0:
                service_key = f"{ip}:{port}/{protocol}"
                if service_key not in seen_services:
                    service = Service(
                        port=port,
                        protocol=protocol.lower(),
                        name=self._guess_service(port),
                        host_id=host.id,
                        source="qualys",
                    )
                    seen_services[service_key] = service
                    yield service
                    yield Relationship(
                        source_id=service.id,
                        target_id=host.id,
                        relation_type=RelationType.RUNS_ON,
                        source="qualys",
                    )
                affected_id = seen_services[service_key].id

            qid = row.get("QID") or row.get("qid") or ""
            title = row.get("Title") or row.get("Vulnerability") or f"QID {qid}"

            severity_num = row.get("Severity") or row.get("severity") or "3"
            severity = self.SEVERITY_MAP.get(str(severity_num), "medium")

            cvss_str = row.get("CVSS Base") or row.get("CVSS") or ""
            cvss_score = None
            if cvss_str:
                try:
                    cvss_score = float(cvss_str)
                except ValueError:
                    pass

            cve = row.get("CVE ID") or row.get("CVE") or ""
            cve_id = cve if cve.startswith("CVE-") else None

            yield Vulnerability(
                title=title,
                description=row.get("Threat") or row.get("Results") or "",
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_asset_id=affected_id,
                source="qualys",
                raw_data={"qid": qid},
            )

    def _guess_service(self, port: int) -> str:
        """Guess service name from port."""
        port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
        }
        return port_map.get(port, "unknown")

    def _get_text(self, elem: ET.Element, tag: str, default: str = "") -> str:
        """Get text from child element."""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    def _is_valid_ip(self, value: str) -> bool:
        """Check if string is valid IP."""
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Qualys report."""
        suffix = file_path.suffix.lower()
        if suffix not in [".xml", ".csv"]:
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"qualys",
                    b"Qualys",
                    b"QUALYS",
                    b"<HOST>",
                    b"<VULN",
                    b"<QID>",
                    b"QID,",
                    b'"QID"',
                    b"CVSS Base",
                    b"<DETECTION",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
