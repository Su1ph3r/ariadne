"""Amass subdomain enumeration output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class AmassParser(BaseParser):
    """Parser for Amass subdomain enumeration output."""

    name = "amass"
    description = "Parse Amass subdomain enumeration and DNS discovery results"
    file_patterns = ["*amass*.json", "*amass*.txt", "amass_*.txt"]
    entity_types = ["Host", "Relationship"]

    SUBDOMAIN_PATTERN = re.compile(
        r"^(?P<subdomain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$",
        re.MULTILINE
    )

    DNS_RECORD_PATTERN = re.compile(
        r"(?P<name>[^\s]+)\s+(?P<type>A|AAAA|CNAME|MX|NS|TXT|PTR)\s+(?P<value>[^\s]+)",
        re.IGNORECASE
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    IPV6_PATTERN = re.compile(r"([a-fA-F0-9:]+:+[a-fA-F0-9:]+)")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an Amass output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Amass JSON output."""
        seen_hosts: dict[str, Host] = {}

        for line in content.strip().split("\n"):
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            yield from self._parse_json_entry(entry, seen_hosts)

        try:
            data = json.loads(content)
            if isinstance(data, list):
                for entry in data:
                    yield from self._parse_json_entry(entry, seen_hosts)
            elif isinstance(data, dict):
                yield from self._parse_json_entry(data, seen_hosts)
        except json.JSONDecodeError:
            pass

    def _parse_json_entry(self, entry: dict, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse a single Amass JSON entry."""
        name = entry.get("name") or entry.get("hostname") or entry.get("domain") or ""
        addresses = entry.get("addresses") or []
        sources = entry.get("sources") or entry.get("source") or []
        tag = entry.get("tag") or ""

        if isinstance(sources, str):
            sources = [sources]
        if isinstance(addresses, str):
            addresses = [{"ip": addresses}]

        if name and name.lower() not in seen_hosts:
            ips = []
            for addr in addresses:
                if isinstance(addr, dict):
                    ip = addr.get("ip") or addr.get("address") or ""
                    if ip:
                        ips.append(ip)
                elif isinstance(addr, str):
                    ips.append(addr)

            primary_ip = ""
            for ip in ips:
                if self.IPV4_PATTERN.match(ip):
                    primary_ip = ip
                    break

            tags = ["subdomain", "recon"]
            if tag:
                tags.append(tag.lower())

            host = Host(
                ip=primary_ip,
                hostname=name,
                source="amass",
                tags=tags,
                raw_properties={
                    "all_ips": ips,
                    "sources": sources,
                },
            )
            seen_hosts[name.lower()] = host
            yield host

            for ip in ips:
                if ip != primary_ip and self.IPV4_PATTERN.match(ip):
                    ip_host_key = f"ip:{ip}"
                    if ip_host_key not in seen_hosts:
                        ip_host = Host(
                            ip=ip,
                            hostname="",
                            source="amass",
                            tags=["discovered"],
                        )
                        seen_hosts[ip_host_key] = ip_host
                        yield ip_host

                        yield Relationship(
                            source_id=host.id,
                            target_id=ip_host.id,
                            relation_type=RelationType.RESOLVES_TO,
                        )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse Amass text output."""
        seen_hosts: dict[str, Host] = {}
        seen_ips: set[str] = set()

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            dns_match = self.DNS_RECORD_PATTERN.search(line)
            if dns_match:
                name = dns_match.group("name")
                record_type = dns_match.group("type").upper()
                value = dns_match.group("value")

                if name.lower() not in seen_hosts:
                    ip = ""
                    if record_type == "A":
                        ip = value

                    host = Host(
                        ip=ip,
                        hostname=name,
                        source="amass",
                        tags=["subdomain", "recon"],
                    )
                    seen_hosts[name.lower()] = host
                    yield host

                if record_type == "A" and value not in seen_ips:
                    seen_ips.add(value)
                    if f"ip:{value}" not in seen_hosts:
                        ip_host = Host(
                            ip=value,
                            hostname="",
                            source="amass",
                            tags=["discovered"],
                        )
                        seen_hosts[f"ip:{value}"] = ip_host
                        yield ip_host

                continue

            subdomain_match = self.SUBDOMAIN_PATTERN.match(line)
            if subdomain_match:
                subdomain = subdomain_match.group("subdomain")

                if subdomain.lower() not in seen_hosts:
                    ip_in_line = self.IPV4_PATTERN.search(line)
                    ip = ip_in_line.group(1) if ip_in_line else ""

                    host = Host(
                        ip=ip,
                        hostname=subdomain,
                        source="amass",
                        tags=["subdomain", "recon"],
                    )
                    seen_hosts[subdomain.lower()] = host
                    yield host

                continue

            parts = line.split()
            if len(parts) >= 1:
                potential_domain = parts[0]
                if "." in potential_domain and not potential_domain.startswith("."):
                    domain_pattern = re.match(
                        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
                        potential_domain
                    )
                    if domain_pattern and potential_domain.lower() not in seen_hosts:
                        ip = ""
                        if len(parts) >= 2:
                            ip_match = self.IPV4_PATTERN.match(parts[1])
                            if ip_match:
                                ip = parts[1]

                        host = Host(
                            ip=ip,
                            hostname=potential_domain,
                            source="amass",
                            tags=["subdomain", "recon"],
                        )
                        seen_hosts[potential_domain.lower()] = host
                        yield host

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an Amass output file."""
        name_lower = file_path.name.lower()
        if "amass" in name_lower:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"amass",
                    b"Amass",
                    b'"name"',
                    b'"addresses"',
                    b'"sources"',
                    b'"tag"',
                    b"OWASP",
                    b"subdomain",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
