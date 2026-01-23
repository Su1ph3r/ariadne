"""Cobalt Strike beacon logs and team server export parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class CobaltStrikeParser(BaseParser):
    """Parser for Cobalt Strike beacon logs and team server exports."""

    name = "cobaltstrike"
    description = "Parse Cobalt Strike beacon logs, team server exports, and session data"
    file_patterns = ["*beacon*.log", "*cobaltstrike*.json", "*cs_*.log", "*teamserver*.log"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    BEACON_CHECKIN_PATTERN = re.compile(
        r"\[(?P<timestamp>[^\]]+)\]\s+(?:beacon|metadata)\s+(?:from|:)\s+"
        r"(?P<user>[^@\s]+)@(?P<hostname>[^\s]+)\s+\((?P<ip>[^)]+)\)",
        re.IGNORECASE
    )

    BEACON_ID_PATTERN = re.compile(
        r"beacon\s+(?:id|ID)[:\s]+(?P<bid>[a-f0-9]+)",
        re.IGNORECASE
    )

    BEACON_METADATA_PATTERN = re.compile(
        r"(?:computer|host)[:\s]+(?P<hostname>[^\s,;]+).*?"
        r"(?:user|username)[:\s]+(?P<user>[^\s,;]+).*?"
        r"(?:process|pid)[:\s]+(?P<process>[^\s,;]+)",
        re.IGNORECASE | re.DOTALL
    )

    CREDENTIAL_PATTERN = re.compile(
        r"(?:credentials?|creds?|hash(?:es)?)[:\s]+"
        r"(?P<domain>[^\\\/\s]+)?[\\\/]?(?P<username>[^:\s]+)[:\s]+"
        r"(?P<hash_or_pass>[a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?|[^\s]+)",
        re.IGNORECASE
    )

    MIMIKATZ_PATTERN = re.compile(
        r"(?:Username|User)\s*:\s*(?P<username>[^\r\n]+).*?"
        r"(?:Domain)\s*:\s*(?P<domain>[^\r\n]+).*?"
        r"(?:NTLM|Password|LM)\s*:\s*(?P<secret>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    KEYLOG_PATTERN = re.compile(
        r"\[keystrokes\]|\[keystroke\]|keylog",
        re.IGNORECASE
    )

    SCREENSHOT_PATTERN = re.compile(
        r"screenshot|printscreen|screen\s*capture",
        re.IGNORECASE
    )

    LATERAL_PATTERN = re.compile(
        r"(?:jump|remote-exec|psexec|wmi|winrm|ssh)\s+(?P<target>[^\s]+)",
        re.IGNORECASE
    )

    SPAWN_PATTERN = re.compile(
        r"(?:spawn|spawned|spawning)\s+(?:to\s+)?(?P<target>[^\s]+)",
        re.IGNORECASE
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Cobalt Strike log file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_log(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Cobalt Strike JSON export."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        for entry in entries:
            if isinstance(entry, dict):
                yield from self._parse_beacon_entry(entry, seen_hosts, seen_users)

    def _parse_beacon_entry(self, entry: dict, seen_hosts: dict, seen_users: set) -> Generator[Entity, None, None]:
        """Parse a single beacon entry from JSON."""
        hostname = entry.get("computer") or entry.get("hostname") or entry.get("host") or ""
        ip = entry.get("internal") or entry.get("ip") or entry.get("external") or ""
        user = entry.get("user") or entry.get("username") or ""
        pid = entry.get("pid") or entry.get("process")
        arch = entry.get("arch") or entry.get("architecture")
        os_info = entry.get("os") or entry.get("version")
        beacon_id = entry.get("id") or entry.get("bid") or entry.get("beacon_id")

        if hostname or ip:
            host_key = (hostname or ip).lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(str(ip)) else "",
                    hostname=hostname if hostname else None,
                    os=os_info,
                    source="cobaltstrike",
                    tags=["beacon", "compromised"],
                    raw_properties={
                        "beacon_id": beacon_id,
                        "arch": arch,
                        "pid": pid,
                    },
                )
                seen_hosts[host_key] = host
                yield host

                yield Misconfiguration(
                    title=f"Cobalt Strike Beacon: {hostname or ip}",
                    description=f"Active beacon on {hostname or ip} (PID: {pid}, User: {user})",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="cobaltstrike",
                    check_id="active_beacon",
                    tags=["beacon", "compromised", "c2"],
                )

        if user and user.lower() not in seen_users:
            seen_users.add(user.lower())
            domain = None
            username = user
            if "\\" in user:
                domain, username = user.split("\\", 1)
            elif "@" in user:
                username, domain = user.split("@", 1)

            user_obj = User(
                username=username,
                domain=domain,
                source="cobaltstrike",
                tags=["compromised", "beacon-user"],
            )
            yield user_obj

            if hostname and hostname.lower() in seen_hosts:
                yield Relationship(
                    source_id=user_obj.id,
                    target_id=seen_hosts[hostname.lower()].id,
                    relation_type=RelationType.HAS_SESSION,
                    properties={"beacon_id": beacon_id},
                )

        creds = entry.get("credentials") or entry.get("creds") or []
        if isinstance(creds, list):
            for cred in creds:
                if isinstance(cred, dict):
                    yield from self._parse_credential_dict(cred)

    def _parse_credential_dict(self, cred: dict) -> Generator[Entity, None, None]:
        """Parse a credential dictionary."""
        username = cred.get("user") or cred.get("username") or ""
        domain = cred.get("domain") or cred.get("realm") or ""
        password = cred.get("password") or cred.get("plaintext") or ""
        ntlm = cred.get("ntlm") or cred.get("hash") or ""
        cred_type = cred.get("type") or ("password" if password else "ntlm")

        if username and (password or ntlm):
            yield Credential(
                title=f"CS Credential: {domain}\\{username}" if domain else f"CS Credential: {username}",
                credential_type=cred_type,
                username=username,
                domain=domain if domain else None,
                value=password or ntlm,
                severity="critical",
                source="cobaltstrike",
                tags=["beacon", "harvested"],
            )

    def _parse_log(self, content: str) -> Generator[Entity, None, None]:
        """Parse Cobalt Strike text logs."""
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()
        seen_creds: set[str] = set()

        for match in self.BEACON_CHECKIN_PATTERN.finditer(content):
            user = match.group("user")
            hostname = match.group("hostname")
            ip = match.group("ip")

            host_key = hostname.lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(ip) else "",
                    hostname=hostname,
                    source="cobaltstrike",
                    tags=["beacon", "compromised"],
                )
                seen_hosts[host_key] = host
                yield host

                yield Misconfiguration(
                    title=f"Cobalt Strike Beacon: {hostname}",
                    description=f"Beacon check-in from {user}@{hostname} ({ip})",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="cobaltstrike",
                    check_id="beacon_checkin",
                    tags=["beacon", "c2"],
                )

            if user.lower() not in seen_users:
                seen_users.add(user.lower())
                user_obj = User(
                    username=user,
                    source="cobaltstrike",
                    tags=["compromised"],
                )
                yield user_obj

        for match in self.MIMIKATZ_PATTERN.finditer(content):
            username = match.group("username").strip()
            domain = match.group("domain").strip()
            secret = match.group("secret").strip()

            if not username or username == "(null)" or not secret or secret == "(null)":
                continue

            cred_key = f"{domain}\\{username}:{secret[:16]}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            is_ntlm = bool(re.match(r"^[a-fA-F0-9]{32}$", secret))
            yield Credential(
                title=f"Mimikatz: {domain}\\{username}" if domain else f"Mimikatz: {username}",
                credential_type="ntlm" if is_ntlm else "password",
                username=username,
                domain=domain if domain and domain != "(null)" else None,
                value=secret,
                severity="critical",
                source="cobaltstrike",
                tags=["mimikatz", "harvested"],
            )

        for match in self.CREDENTIAL_PATTERN.finditer(content):
            domain = match.group("domain") or ""
            username = match.group("username")
            hash_or_pass = match.group("hash_or_pass")

            cred_key = f"{domain}\\{username}:{hash_or_pass[:16]}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            is_ntlm = bool(re.match(r"^[a-fA-F0-9]{32}(:[a-fA-F0-9]{32})?$", hash_or_pass))
            yield Credential(
                title=f"CS Cred: {domain}\\{username}" if domain else f"CS Cred: {username}",
                credential_type="ntlm" if is_ntlm else "password",
                username=username,
                domain=domain if domain else None,
                value=hash_or_pass,
                severity="critical",
                source="cobaltstrike",
                tags=["harvested"],
            )

        for match in self.LATERAL_PATTERN.finditer(content):
            target = match.group("target")
            if target.lower() not in seen_hosts:
                is_ip = bool(self.IPV4_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="cobaltstrike",
                    tags=["lateral-target"],
                )
                seen_hosts[target.lower()] = host
                yield host

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Cobalt Strike log file."""
        name_lower = file_path.name.lower()
        if any(x in name_lower for x in ["beacon", "cobaltstrike", "cs_", "teamserver"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(4000)
                indicators = [
                    b"beacon",
                    b"Beacon",
                    b"cobalt",
                    b"Cobalt",
                    b"teamserver",
                    b"sleeptime",
                    b"metadata",
                    b"[task]",
                    b"[input]",
                    b"[output]",
                    b"[indicator]",
                    b"psexec",
                    b"jump",
                    b"mimikatz",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
