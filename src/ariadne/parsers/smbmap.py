"""SMBMap output parser for share enumeration."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration, Credential
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class SMBMapParser(BaseParser):
    """Parser for SMBMap share enumeration output."""

    name = "smbmap"
    description = "Parse SMBMap SMB share enumeration output"
    file_patterns = ["*smbmap*.txt", "*smbmap*.json", "*smbmap*.csv"]
    entity_types = ["Host", "Service", "Misconfiguration", "Credential"]

    HOST_PATTERN = re.compile(r"^\[[\+\*!]\]\s+IP:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)", re.MULTILINE)

    SHARE_PATTERN = re.compile(
        r"^\s*(?P<share_name>\S+)\s+(?P<permissions>READ(?:,\s*WRITE)?|WRITE|NO ACCESS|READ ONLY)\s*(?P<comment>.*)?$",
        re.MULTILINE
    )

    SHARE_LINE_PATTERN = re.compile(
        r"(?P<share_name>[^\t]+)\t+(?P<type>[^\t]*)\t+(?P<comment>[^\t]*)\t+(?P<permissions>READ|WRITE|READ, WRITE|NO ACCESS)",
        re.MULTILINE
    )

    FILE_PATTERN = re.compile(
        r"^\s+(?P<perms>[drwx-]+)\s+(?P<size>\d+)\s+(?P<date>\S+\s+\S+)\s+(?P<filename>.+)$",
        re.MULTILINE
    )

    INTERESTING_FILES = [
        r".*\.kdbx?$",
        r".*password.*",
        r".*credential.*",
        r".*secret.*",
        r".*\.pfx$",
        r".*\.p12$",
        r".*\.pem$",
        r".*\.key$",
        r".*id_rsa.*",
        r".*\.ssh.*",
        r"web\.config",
        r".*\.config$",
        r".*unattend.*\.xml$",
        r".*sysprep.*\.xml$",
        r".*\.rdp$",
        r".*\.vmdk$",
        r"NTDS\.dit",
        r"SAM",
        r"SYSTEM",
        r"SECURITY",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an SMBMap output file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            yield from self._parse_json(file_path)
        else:
            yield from self._parse_text(file_path)

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse SMBMap JSON output."""
        with open(file_path) as f:
            data = json.load(f)

        for host_ip, host_data in data.items():
            if not self._is_valid_ip(host_ip):
                continue

            host = Host(
                ip=host_ip,
                source="smbmap",
            )
            yield host

            service = Service(
                port=445,
                protocol="tcp",
                name="microsoft-ds",
                host_id=host.id,
                source="smbmap",
            )
            yield service
            yield Relationship(
                source_id=service.id,
                target_id=host.id,
                relation_type=RelationType.RUNS_ON,
                source="smbmap",
            )

            shares = host_data if isinstance(host_data, dict) else {}

            for share_name, share_info in shares.items():
                yield from self._process_share(host.id, host_ip, share_name, share_info)

    def _parse_text(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse SMBMap text output."""
        content = file_path.read_text(errors="ignore")

        current_host: Host | None = None
        current_ip: str = ""
        seen_hosts: dict[str, Host] = {}

        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]

            host_match = self.HOST_PATTERN.search(line)
            if host_match:
                current_ip = host_match.group("ip")

                if current_ip not in seen_hosts:
                    current_host = Host(
                        ip=current_ip,
                        source="smbmap",
                    )
                    seen_hosts[current_ip] = current_host
                    yield current_host

                    service = Service(
                        port=445,
                        protocol="tcp",
                        name="microsoft-ds",
                        host_id=current_host.id,
                        source="smbmap",
                    )
                    yield service
                    yield Relationship(
                        source_id=service.id,
                        target_id=current_host.id,
                        relation_type=RelationType.RUNS_ON,
                        source="smbmap",
                    )
                else:
                    current_host = seen_hosts[current_ip]

                i += 1
                continue

            if current_host:
                share_match = self.SHARE_PATTERN.search(line) or self.SHARE_LINE_PATTERN.search(line)
                if share_match:
                    groups = share_match.groupdict()
                    share_name = groups.get("share_name", "").strip()
                    permissions = groups.get("permissions", "").strip().upper()

                    if share_name and share_name not in ["Disk", "Share", "----"]:
                        yield from self._process_share_text(
                            current_host.id,
                            current_ip,
                            share_name,
                            permissions
                        )

            file_match = self.FILE_PATTERN.search(line)
            if file_match and current_host:
                filename = file_match.group("filename").strip()
                yield from self._check_interesting_file(current_host.id, filename)

            i += 1

    def _process_share(self, host_id: str, host_ip: str, share_name: str, share_info: dict | str) -> Generator[Entity, None, None]:
        """Process a share entry from JSON format."""
        if isinstance(share_info, str):
            permissions = share_info.upper()
        else:
            permissions = share_info.get("permissions", "").upper()

        if "NO ACCESS" in permissions:
            return

        readable = "READ" in permissions
        writable = "WRITE" in permissions

        severity = "low"
        if share_name.upper() in ["C$", "ADMIN$", "IPC$"]:
            severity = "high" if writable else "medium"
        elif writable:
            severity = "medium"

        yield Misconfiguration(
            title=f"Accessible SMB Share: {share_name}",
            description=f"Share \\\\{host_ip}\\{share_name} is accessible with permissions: {permissions}",
            severity=severity,
            affected_asset_id=host_id,
            source="smbmap",
            check_id=f"smb_share_{share_name}",
            raw_data={
                "share_name": share_name,
                "readable": readable,
                "writable": writable,
                "permissions": permissions,
            },
        )

        if isinstance(share_info, dict) and "files" in share_info:
            for file_entry in share_info.get("files", []):
                filename = file_entry if isinstance(file_entry, str) else file_entry.get("name", "")
                yield from self._check_interesting_file(host_id, filename, share_name)

    def _process_share_text(self, host_id: str, host_ip: str, share_name: str, permissions: str) -> Generator[Entity, None, None]:
        """Process a share from text output."""
        if "NO ACCESS" in permissions:
            return

        readable = "READ" in permissions
        writable = "WRITE" in permissions

        severity = "low"
        if share_name.upper() in ["C$", "ADMIN$"]:
            severity = "high" if writable else "medium"
        elif writable:
            severity = "medium"

        yield Misconfiguration(
            title=f"Accessible SMB Share: {share_name}",
            description=f"Share \\\\{host_ip}\\{share_name} is accessible with permissions: {permissions}",
            severity=severity,
            affected_asset_id=host_id,
            source="smbmap",
            check_id=f"smb_share_{share_name}",
            raw_data={
                "share_name": share_name,
                "readable": readable,
                "writable": writable,
            },
        )

    def _check_interesting_file(self, host_id: str, filename: str, share_name: str = "") -> Generator[Entity, None, None]:
        """Check if a file is potentially sensitive."""
        filename_lower = filename.lower()

        for pattern in self.INTERESTING_FILES:
            if re.match(pattern, filename_lower, re.IGNORECASE):
                location = f"in share {share_name}" if share_name else ""

                if any(x in filename_lower for x in ["password", "credential", "secret", ".kdbx"]):
                    yield Credential(
                        title=f"Potential credential file: {filename}",
                        credential_type="file",
                        value=filename,
                        severity="high",
                        affected_asset_id=host_id,
                        source="smbmap",
                        tags=["sensitive-file"],
                        raw_data={"share": share_name, "filename": filename},
                    )
                else:
                    yield Misconfiguration(
                        title=f"Sensitive file found: {filename}",
                        description=f"Potentially sensitive file '{filename}' found {location}",
                        severity="medium",
                        affected_asset_id=host_id,
                        source="smbmap",
                        check_id="sensitive_file",
                        raw_data={"filename": filename, "share": share_name},
                    )
                break

    def _is_valid_ip(self, value: str) -> bool:
        """Check if string is a valid IP address."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an SMBMap output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".json", ".csv", ""]:
            return False

        if "smbmap" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"smbmap",
                    b"SMBMap",
                    b"[+] IP:",
                    b"[*] IP:",
                    b"Disk Permissions",
                    b"READ ONLY",
                    b"READ, WRITE",
                    b"NO ACCESS",
                    b"\\\\",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
