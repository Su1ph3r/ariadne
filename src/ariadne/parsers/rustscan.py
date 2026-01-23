"""RustScan fast port scanner output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class RustScanParser(BaseParser):
    """Parser for RustScan port scanner output (JSON and greppable formats)."""

    name = "rustscan"
    description = "Parse RustScan fast port scanner output"
    file_patterns = ["*rustscan*.json", "*rustscan*.txt", "*rustscan*.greppable"]
    entity_types = ["Host", "Service"]

    GREPPABLE_PATTERN = re.compile(
        r"^Host:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s*.*?Ports:\s*(?P<ports>.+)$",
        re.MULTILINE
    )

    SIMPLE_PATTERN = re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s*->\s*\[(?P<ports>[\d,\s]+)\]"
    )

    PORT_PATTERN = re.compile(
        r"(\d+)/(?:open|filtered)?/?(\w+)?/?/?([^,/]*)?/?([^,]*)?"
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a RustScan output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse RustScan JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        if isinstance(data, list):
            for entry in data:
                yield from self._parse_json_entry(entry)
        elif isinstance(data, dict):
            yield from self._parse_json_entry(data)

    def _parse_json_entry(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a single JSON entry."""
        ip = entry.get("ip") or entry.get("host") or entry.get("address")
        if not ip:
            return

        host = Host(
            ip=ip,
            hostname=entry.get("hostname"),
            source="rustscan",
        )
        yield host

        ports = entry.get("ports", [])
        if isinstance(ports, list):
            for port_info in ports:
                if isinstance(port_info, dict):
                    port = port_info.get("port") or port_info.get("portid")
                    protocol = port_info.get("protocol", "tcp")
                    service_name = port_info.get("service", {}).get("name", "unknown") if isinstance(port_info.get("service"), dict) else "unknown"
                elif isinstance(port_info, int):
                    port = port_info
                    protocol = "tcp"
                    service_name = self._guess_service(port)
                else:
                    continue

                if port:
                    service = Service(
                        port=int(port),
                        protocol=protocol,
                        name=service_name,
                        host_id=host.id,
                        source="rustscan",
                    )
                    yield service
                    yield Relationship(
                        source_id=service.id,
                        target_id=host.id,
                        relation_type=RelationType.RUNS_ON,
                        source="rustscan",
                    )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse RustScan text/greppable output."""
        seen_hosts: dict[str, Host] = {}

        for match in self.GREPPABLE_PATTERN.finditer(content):
            ip = match.group("ip")
            ports_str = match.group("ports")

            if ip not in seen_hosts:
                host = Host(ip=ip, source="rustscan")
                seen_hosts[ip] = host
                yield host

            host = seen_hosts[ip]
            yield from self._parse_ports_string(ports_str, host)

        for match in self.SIMPLE_PATTERN.finditer(content):
            ip = match.group("ip")
            ports_str = match.group("ports")

            if ip not in seen_hosts:
                host = Host(ip=ip, source="rustscan")
                seen_hosts[ip] = host
                yield host

            host = seen_hosts[ip]

            for port_str in ports_str.split(","):
                port_str = port_str.strip()
                if port_str.isdigit():
                    port = int(port_str)
                    service = Service(
                        port=port,
                        protocol="tcp",
                        name=self._guess_service(port),
                        host_id=host.id,
                        source="rustscan",
                    )
                    yield service
                    yield Relationship(
                        source_id=service.id,
                        target_id=host.id,
                        relation_type=RelationType.RUNS_ON,
                        source="rustscan",
                    )

        if not seen_hosts:
            yield from self._parse_simple_port_list(content)

    def _parse_ports_string(self, ports_str: str, host: Host) -> Generator[Entity, None, None]:
        """Parse a greppable ports string."""
        for port_match in self.PORT_PATTERN.finditer(ports_str):
            port = int(port_match.group(1))
            protocol = port_match.group(2) or "tcp"
            service_name = port_match.group(3) or self._guess_service(port)

            service = Service(
                port=port,
                protocol=protocol.lower(),
                name=service_name if service_name else "unknown",
                host_id=host.id,
                source="rustscan",
            )
            yield service
            yield Relationship(
                source_id=service.id,
                target_id=host.id,
                relation_type=RelationType.RUNS_ON,
                source="rustscan",
            )

    def _parse_simple_port_list(self, content: str) -> Generator[Entity, None, None]:
        """Parse simple RustScan output with IP and port list."""
        current_ip = None
        current_host = None

        for line in content.split("\n"):
            line = line.strip()

            ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                current_ip = ip_match.group(1)
                current_host = Host(ip=current_ip, source="rustscan")
                yield current_host
                continue

            if current_host and line:
                ports = re.findall(r"\b(\d+)\b", line)
                for port_str in ports:
                    port = int(port_str)
                    if 1 <= port <= 65535:
                        service = Service(
                            port=port,
                            protocol="tcp",
                            name=self._guess_service(port),
                            host_id=current_host.id,
                            source="rustscan",
                        )
                        yield service
                        yield Relationship(
                            source_id=service.id,
                            target_id=current_host.id,
                            relation_type=RelationType.RUNS_ON,
                            source="rustscan",
                        )

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
            993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
            5985: "winrm", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
            27017: "mongodb",
        }
        return port_map.get(port, "unknown")

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a RustScan output file."""
        if "rustscan" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"rustscan",
                    b"RustScan",
                    b"Open ",
                    b"-> [",
                    b'"ports"',
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
