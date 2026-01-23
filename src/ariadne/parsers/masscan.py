"""Masscan JSON/XML output parser."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class MasscanParser(BaseParser):
    """Parser for Masscan JSON and XML output files."""

    name = "masscan"
    description = "Parse Masscan fast port scanner output (JSON/XML)"
    file_patterns = ["*masscan*.json", "*masscan*.xml", "masscan_*"]
    entity_types = ["Host", "Service"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Masscan output file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".json" or self._is_json(file_path):
            yield from self._parse_json(file_path)
        elif suffix == ".xml":
            yield from self._parse_xml(file_path)
        else:
            content = file_path.read_text(errors="ignore")
            if content.strip().startswith("{") or content.strip().startswith("["):
                yield from self._parse_json(file_path)
            elif content.strip().startswith("<"):
                yield from self._parse_xml(file_path)

    def _is_json(self, file_path: Path) -> bool:
        """Check if file contains JSON."""
        try:
            with open(file_path, "rb") as f:
                first_char = f.read(1).decode(errors="ignore").strip()
                return first_char in ["{", "["]
        except Exception:
            return False

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Masscan JSON output."""
        content = file_path.read_text(errors="ignore")

        content = content.strip()
        if content.endswith(","):
            content = content[:-1]
        if not content.startswith("["):
            content = "[" + content
        if not content.endswith("]"):
            content = content + "]"

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            lines = file_path.read_text(errors="ignore").strip().split("\n")
            data = []
            for line in lines:
                line = line.strip().rstrip(",")
                if line and line.startswith("{"):
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        seen_hosts: dict[str, Host] = {}

        for entry in data:
            ip = entry.get("ip")
            if not ip:
                continue

            if ip not in seen_hosts:
                host = Host(
                    ip=ip,
                    source="masscan",
                )
                seen_hosts[ip] = host
                yield host

            host = seen_hosts[ip]

            for port_info in entry.get("ports", []):
                port = port_info.get("port")
                protocol = port_info.get("proto", "tcp")
                status = port_info.get("status", "open")

                if port and status == "open":
                    service_name = self._guess_service(port)

                    service = Service(
                        port=port,
                        protocol=protocol,
                        name=service_name,
                        host_id=host.id,
                        source="masscan",
                    )
                    yield service
                    yield Relationship(
                        source_id=service.id,
                        target_id=host.id,
                        relation_type=RelationType.RUNS_ON,
                        source="masscan",
                    )

    def _parse_xml(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Masscan XML output."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        seen_hosts: dict[str, Host] = {}

        for host_elem in root.findall(".//host"):
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                continue

            ip = addr_elem.get("addr", "")
            if not ip:
                continue

            if ip not in seen_hosts:
                host = Host(
                    ip=ip,
                    source="masscan",
                )
                seen_hosts[ip] = host
                yield host

            host = seen_hosts[ip]

            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = "unknown"
                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                else:
                    service_name = self._guess_service(port)

                service = Service(
                    port=port,
                    protocol=protocol,
                    name=service_name,
                    host_id=host.id,
                    source="masscan",
                )
                yield service
                yield Relationship(
                    source_id=service.id,
                    target_id=host.id,
                    relation_type=RelationType.RUNS_ON,
                    source="masscan",
                )

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            465: "smtps",
            587: "submission",
            636: "ldaps",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            5985: "winrm",
            5986: "winrm-ssl",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
        }
        return common_ports.get(port, "unknown")

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Masscan output file."""
        if file_path.suffix.lower() not in [".json", ".xml", ""]:
            if "masscan" not in file_path.name.lower():
                return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(1000)
                header_lower = header.lower()
                # Check for masscan specifically - either in filename or content
                # For XML: look for scanner="masscan"
                # For JSON: look for masscan identifier or specific format
                if b"masscan" in header_lower:
                    return True
                # Check for masscan-specific JSON format with "ports" array
                if file_path.suffix.lower() == ".json" and b'"ports"' in header:
                    return True
                return False
        except Exception:
            return False
