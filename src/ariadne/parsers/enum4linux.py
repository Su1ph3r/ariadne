"""Enum4linux output parser for SMB/NetBIOS enumeration."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class Enum4linuxParser(BaseParser):
    """Parser for enum4linux SMB enumeration output."""

    name = "enum4linux"
    description = "Parse enum4linux SMB/NetBIOS enumeration output"
    file_patterns = ["*enum4linux*.txt", "*enum4linux*.log"]
    entity_types = ["Host", "Service", "User", "Misconfiguration"]

    TARGET_PATTERN = re.compile(r"Target\s*(?:Information)?\s*[:=]\s*(\S+)", re.IGNORECASE)
    IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    WORKGROUP_PATTERN = re.compile(r"Workgroup\s*[:=]\s*(\S+)", re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r"Domain\s*(?:Name)?\s*[:=]\s*(\S+)", re.IGNORECASE)
    OS_PATTERN = re.compile(r"OS\s*[:=]\s*(.+?)(?:\n|$)", re.IGNORECASE)
    NETBIOS_PATTERN = re.compile(r"NetBIOS\s+computer\s+name\s*[:=]\s*(\S+)", re.IGNORECASE)

    USER_RID_PATTERN = re.compile(
        r"user:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]",
        re.IGNORECASE
    )
    USER_SIMPLE_PATTERN = re.compile(
        r"^\s*S-\d+-\d+.*\\([^\s]+)\s+\(.*User.*\)",
        re.MULTILINE | re.IGNORECASE
    )

    GROUP_PATTERN = re.compile(
        r"group:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]",
        re.IGNORECASE
    )

    SHARE_PATTERN = re.compile(
        r"^\s*([^\s]+)\s+(?:Disk|IPC|Printer|Print)\s+(.*)$",
        re.MULTILINE
    )

    SHARE_MAPPING_PATTERN = re.compile(
        r"//([^/]+)/([^\s]+)\s+Mapping:\s*(\w+)",
        re.IGNORECASE
    )

    ANONYMOUS_PATTERN = re.compile(
        r"(?:anonymous|null)\s+(?:session|login|access)\s+(?:allowed|permitted|successful|enabled)",
        re.IGNORECASE
    )

    PASSWORD_POLICY_PATTERN = re.compile(
        r"(?:Minimum|Maximum)\s+password\s+(?:length|age)\s*[:=]\s*(\d+)",
        re.IGNORECASE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an enum4linux output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        host = self._parse_target_info(content)
        if host:
            yield host

            service = Service(
                port=445,
                protocol="tcp",
                name="microsoft-ds",
                host_id=host.id,
                source="enum4linux",
            )
            yield service
            yield Relationship(
                source_id=service.id,
                target_id=host.id,
                relation_type=RelationType.RUNS_ON,
                source="enum4linux",
            )

            yield from self._parse_users(content, host)
            yield from self._parse_shares(content, host)
            yield from self._parse_misconfigs(content, host)

    def _parse_target_info(self, content: str) -> Host | None:
        """Extract target host information."""
        target_match = self.TARGET_PATTERN.search(content)
        if target_match:
            target = target_match.group(1)
        else:
            ip_match = self.IP_PATTERN.search(content[:500])
            if ip_match:
                target = ip_match.group(1)
            else:
                return None

        is_ip = bool(self.IP_PATTERN.match(target))

        domain = None
        domain_match = self.DOMAIN_PATTERN.search(content) or self.WORKGROUP_PATTERN.search(content)
        if domain_match:
            domain = domain_match.group(1)

        os_info = None
        os_match = self.OS_PATTERN.search(content)
        if os_match:
            os_info = os_match.group(1).strip()

        hostname = None
        netbios_match = self.NETBIOS_PATTERN.search(content)
        if netbios_match:
            hostname = netbios_match.group(1)
        elif not is_ip:
            hostname = target

        return Host(
            ip=target if is_ip else "",
            hostname=hostname,
            domain=domain,
            os=os_info,
            source="enum4linux",
            tags=["smb-enumerated"],
        )

    def _parse_users(self, content: str, host: Host) -> Generator[Entity, None, None]:
        """Extract user accounts."""
        seen_users: set[str] = set()

        for match in self.USER_RID_PATTERN.finditer(content):
            username = match.group(1)
            rid = match.group(2)

            if username.lower() in seen_users:
                continue
            seen_users.add(username.lower())

            rid_int = int(rid, 16)
            is_admin = rid_int == 500

            user = User(
                username=username,
                domain=host.domain,
                is_admin=is_admin,
                source="enum4linux",
                raw_properties={"rid": rid_int},
            )
            yield user

        for match in self.USER_SIMPLE_PATTERN.finditer(content):
            username = match.group(1)
            if username.lower() not in seen_users:
                seen_users.add(username.lower())
                yield User(
                    username=username,
                    domain=host.domain,
                    source="enum4linux",
                )

    def _parse_shares(self, content: str, host: Host) -> Generator[Entity, None, None]:
        """Extract share information."""
        seen_shares: set[str] = set()

        for match in self.SHARE_PATTERN.finditer(content):
            share_name = match.group(1).strip()
            comment = match.group(2).strip() if match.group(2) else ""

            if share_name.lower() in seen_shares or share_name in ["----", "Sharename", "Share"]:
                continue
            seen_shares.add(share_name.lower())

            severity = "low"
            if share_name.upper() in ["C$", "ADMIN$"]:
                severity = "high"
            elif share_name.upper() not in ["IPC$", "PRINT$"]:
                severity = "medium"

            yield Misconfiguration(
                title=f"SMB Share Discovered: {share_name}",
                description=f"Share {share_name} found on {host.ip or host.hostname}. Comment: {comment}",
                severity=severity,
                affected_asset_id=host.id,
                source="enum4linux",
                check_id=f"share_{share_name}",
            )

        for match in self.SHARE_MAPPING_PATTERN.finditer(content):
            share_name = match.group(2)
            mapping_status = match.group(3)

            if share_name.lower() in seen_shares:
                continue
            seen_shares.add(share_name.lower())

            if mapping_status.upper() == "OK":
                yield Misconfiguration(
                    title=f"Accessible SMB Share: {share_name}",
                    description=f"Share {share_name} is accessible (mapping successful)",
                    severity="medium",
                    affected_asset_id=host.id,
                    source="enum4linux",
                    check_id=f"accessible_share_{share_name}",
                )

    def _parse_misconfigs(self, content: str, host: Host) -> Generator[Entity, None, None]:
        """Extract security misconfigurations."""
        if self.ANONYMOUS_PATTERN.search(content):
            yield Misconfiguration(
                title="Anonymous/Null Session Allowed",
                description="The target allows anonymous or null SMB sessions, enabling unauthenticated enumeration",
                severity="medium",
                affected_asset_id=host.id,
                source="enum4linux",
                check_id="anonymous_session",
                tags=["null-session"],
            )

        if re.search(r"Minimum password length\s*[:=]\s*0", content, re.IGNORECASE):
            yield Misconfiguration(
                title="No Minimum Password Length",
                description="Password policy allows empty passwords (minimum length = 0)",
                severity="high",
                affected_asset_id=host.id,
                source="enum4linux",
                check_id="no_min_password",
            )

        if re.search(r"Password Complexity\s*[:=]\s*(?:Disabled|0|No)", content, re.IGNORECASE):
            yield Misconfiguration(
                title="Password Complexity Disabled",
                description="Password complexity requirements are not enforced",
                severity="medium",
                affected_asset_id=host.id,
                source="enum4linux",
                check_id="no_password_complexity",
            )

        if re.search(r"Account lockout threshold\s*[:=]\s*(?:0|None|Disabled)", content, re.IGNORECASE):
            yield Misconfiguration(
                title="No Account Lockout Policy",
                description="Account lockout is disabled, allowing unlimited password attempts",
                severity="medium",
                affected_asset_id=host.id,
                source="enum4linux",
                check_id="no_lockout",
            )

        if re.search(r"SMBv1\s+(?:enabled|supported|available)", content, re.IGNORECASE):
            yield Misconfiguration(
                title="SMBv1 Enabled",
                description="SMBv1 is enabled, which is vulnerable to multiple attacks",
                severity="high",
                affected_asset_id=host.id,
                source="enum4linux",
                check_id="smbv1_enabled",
            )

        if re.search(r"(?:Message signing|SMB signing)\s*[:=]?\s*(?:disabled|not required|false)", content, re.IGNORECASE):
            yield Misconfiguration(
                title="SMB Signing Not Required",
                description="SMB signing is not required, enabling relay attacks",
                severity="medium",
                affected_asset_id=host.id,
                source="enum4linux",
                check_id="smb_signing_disabled",
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an enum4linux output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if "enum4linux" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"enum4linux",
                    b"Starting enum4linux",
                    b"Target Information",
                    b"Nbtstat Information",
                    b"Session Check on",
                    b"Getting domain SID",
                    b"Users on",
                    b"Share Enumeration",
                    b"user:[",
                    b"group:[",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
