"""Subfinder subdomain discovery output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class SubfinderParser(BaseParser):
    """Parser for Subfinder subdomain discovery output."""

    name = "subfinder"
    description = "Parse Subfinder subdomain discovery and enumeration results"
    file_patterns = ["*subfinder*.json", "*subfinder*.txt", "subfinder_*.txt", "*subdomains*.txt"]
    entity_types = ["Host"]

    SUBDOMAIN_PATTERN = re.compile(
        r"^(?P<subdomain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$"
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Subfinder output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Subfinder JSON output."""
        seen_hosts: set[str] = set()

        for line in content.strip().split("\n"):
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
                if isinstance(entry, dict):
                    yield from self._parse_json_entry(entry, seen_hosts)
                elif isinstance(entry, str):
                    if entry.lower() not in seen_hosts:
                        seen_hosts.add(entry.lower())
                        yield Host(
                            ip="",
                            hostname=entry,
                            source="subfinder",
                            tags=["subdomain", "recon"],
                        )
            except json.JSONDecodeError:
                continue

        try:
            data = json.loads(content)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        yield from self._parse_json_entry(entry, seen_hosts)
                    elif isinstance(entry, str):
                        if entry.lower() not in seen_hosts:
                            seen_hosts.add(entry.lower())
                            yield Host(
                                ip="",
                                hostname=entry,
                                source="subfinder",
                                tags=["subdomain", "recon"],
                            )
        except json.JSONDecodeError:
            pass

    def _parse_json_entry(self, entry: dict, seen_hosts: set) -> Generator[Entity, None, None]:
        """Parse a single Subfinder JSON entry."""
        host = entry.get("host") or entry.get("subdomain") or entry.get("domain") or ""
        source = entry.get("source") or entry.get("sources") or ""
        ip = entry.get("ip") or entry.get("a") or ""

        if isinstance(source, list):
            source = ", ".join(source)
        if isinstance(ip, list):
            ip = ip[0] if ip else ""

        if host and host.lower() not in seen_hosts:
            seen_hosts.add(host.lower())

            tags = ["subdomain", "recon"]
            if source:
                tags.append(f"source:{source[:20]}")

            yield Host(
                ip=ip if self.IPV4_PATTERN.match(str(ip)) else "",
                hostname=host,
                source="subfinder",
                tags=tags,
                raw_properties={"discovery_source": source} if source else {},
            )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse Subfinder text output (one subdomain per line)."""
        seen_hosts: set[str] = set()

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            parts = line.split(",")
            subdomain = parts[0].strip()

            ip = ""
            source = ""
            if len(parts) >= 2:
                second = parts[1].strip()
                if self.IPV4_PATTERN.match(second):
                    ip = second
                else:
                    source = second
            if len(parts) >= 3:
                source = parts[2].strip()

            if not self.SUBDOMAIN_PATTERN.match(subdomain):
                if "." in subdomain and not subdomain[0].isdigit():
                    pass
                else:
                    continue

            if subdomain.lower() in seen_hosts:
                continue
            seen_hosts.add(subdomain.lower())

            tags = ["subdomain", "recon"]
            if source:
                tags.append(f"source:{source[:20]}")

            raw_props = {"discovery_source": source} if source else {}
            yield Host(
                ip=ip,
                hostname=subdomain,
                source="subfinder",
                tags=tags,
                raw_properties=raw_props,
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Subfinder output file."""
        name_lower = file_path.name.lower()
        if "subfinder" in name_lower:
            return True

        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".json", ""]:
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)

                if b"subfinder" in header.lower():
                    return True

                if b'"host"' in header and (b'"source"' in header or b'"sources"' in header):
                    return True

                lines = header.decode("utf-8", errors="ignore").split("\n")[:20]
                domain_count = 0
                for line in lines:
                    line = line.strip()
                    if line and cls.SUBDOMAIN_PATTERN.match(line.split(",")[0].strip()):
                        domain_count += 1

                return domain_count >= 5

        except Exception:
            return False
