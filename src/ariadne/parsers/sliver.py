"""Sliver C2 implant logs and session data parser."""

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
class SliverParser(BaseParser):
    """Parser for Sliver C2 implant logs and session exports."""

    name = "sliver"
    description = "Parse Sliver C2 implant logs, session data, and operator commands"
    file_patterns = ["*sliver*.json", "*sliver*.log", "*implant*.json", "*beacon*.json"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    SESSION_PATTERN = re.compile(
        r"(?:session|implant|beacon)\s+(?:opened|connected|established)\s+"
        r"(?:for\s+)?(?P<user>[^@\s]+)?@?(?P<hostname>[^\s(]+)\s*\((?P<ip>[^)]+)\)",
        re.IGNORECASE
    )

    WHOAMI_PATTERN = re.compile(
        r"(?:whoami|getuid)[:\s]+(?P<domain>[^\\\/]+)?[\\\/]?(?P<username>[^\s\r\n]+)",
        re.IGNORECASE
    )

    CREDENTIAL_PATTERN = re.compile(
        r"(?P<domain>[^\\\/\s]+)?[\\\/](?P<username>[^:\s]+)[:\s]+"
        r"(?P<secret>[a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?)",
        re.IGNORECASE
    )

    HASHDUMP_PATTERN = re.compile(
        r"(?P<username>[^:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<ntlm>[a-fA-F0-9]{32}):::"
    )

    SEATBELT_USER_PATTERN = re.compile(
        r"(?:User|Username)[:\s]+(?P<user>[^\r\n]+)",
        re.IGNORECASE
    )

    PIVOT_PATTERN = re.compile(
        r"(?:pivot|tunnel|portfwd|socks)\s+(?:to|through|via)\s+(?P<target>[^\s]+)",
        re.IGNORECASE
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Sliver log file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_log(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Sliver JSON export."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        for entry in entries:
            if isinstance(entry, dict):
                yield from self._parse_session_entry(entry, seen_hosts, seen_users)

    def _parse_session_entry(self, entry: dict, seen_hosts: dict, seen_users: set) -> Generator[Entity, None, None]:
        """Parse a single session entry from JSON."""
        session_id = entry.get("ID") or entry.get("id") or entry.get("session_id") or ""
        hostname = entry.get("Hostname") or entry.get("hostname") or entry.get("Name") or ""
        remote_addr = entry.get("RemoteAddress") or entry.get("remote_address") or entry.get("ip") or ""
        username = entry.get("Username") or entry.get("username") or entry.get("user") or ""
        os_info = entry.get("OS") or entry.get("os") or ""
        arch = entry.get("Arch") or entry.get("arch") or ""
        pid = entry.get("PID") or entry.get("pid")
        filename = entry.get("Filename") or entry.get("filename") or ""
        transport = entry.get("Transport") or entry.get("transport") or ""

        ip = ""
        if remote_addr:
            ip_match = self.IPV4_PATTERN.search(remote_addr)
            if ip_match:
                ip = ip_match.group(1)

        if hostname or ip:
            host_key = (hostname or ip).lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip,
                    hostname=hostname if hostname else None,
                    os=f"{os_info} {arch}".strip() if os_info else None,
                    source="sliver",
                    tags=["implant", "compromised"],
                    raw_properties={
                        "session_id": session_id,
                        "pid": pid,
                        "filename": filename,
                        "transport": transport,
                    },
                )
                seen_hosts[host_key] = host
                yield host

                yield Misconfiguration(
                    title=f"Sliver Implant: {hostname or ip}",
                    description=f"Active Sliver implant on {hostname or ip} (User: {username}, PID: {pid})",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="sliver",
                    check_id="active_implant",
                    tags=["implant", "compromised", "c2"],
                )

        if username and username.lower() not in seen_users:
            seen_users.add(username.lower())
            domain = None
            user = username
            if "\\" in username:
                domain, user = username.split("\\", 1)
            elif "@" in username:
                user, domain = username.split("@", 1)

            user_obj = User(
                username=user,
                domain=domain,
                source="sliver",
                tags=["compromised", "implant-user"],
            )
            yield user_obj

            if hostname and hostname.lower() in seen_hosts:
                yield Relationship(
                    source_id=user_obj.id,
                    target_id=seen_hosts[hostname.lower()].id,
                    relation_type=RelationType.HAS_SESSION,
                    source="sliver",
                    properties={"session_id": session_id},
                )

        creds = entry.get("Credentials") or entry.get("credentials") or []
        if isinstance(creds, list):
            for cred in creds:
                if isinstance(cred, dict):
                    cred_user = cred.get("Username") or cred.get("username") or ""
                    cred_domain = cred.get("Domain") or cred.get("domain") or ""
                    cred_hash = cred.get("Hash") or cred.get("hash") or ""
                    cred_pass = cred.get("Password") or cred.get("password") or ""

                    if cred_user and (cred_hash or cred_pass):
                        yield Credential(
                            title=f"Sliver Cred: {cred_domain}\\{cred_user}" if cred_domain else f"Sliver Cred: {cred_user}",
                            credential_type="ntlm" if cred_hash else "password",
                            username=cred_user,
                            domain=cred_domain if cred_domain else None,
                            value=cred_hash or cred_pass,
                            severity="critical",
                            source="sliver",
                            tags=["harvested"],
                        )

    def _parse_log(self, content: str) -> Generator[Entity, None, None]:
        """Parse Sliver text logs."""
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()
        seen_creds: set[str] = set()

        for match in self.SESSION_PATTERN.finditer(content):
            user = match.group("user") or ""
            hostname = match.group("hostname")
            ip = match.group("ip")

            host_key = hostname.lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(ip) else "",
                    hostname=hostname,
                    source="sliver",
                    tags=["implant", "compromised"],
                )
                seen_hosts[host_key] = host
                yield host

                yield Misconfiguration(
                    title=f"Sliver Implant: {hostname}",
                    description=f"Session established: {user}@{hostname} ({ip})",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="sliver",
                    check_id="session_established",
                    tags=["implant", "c2"],
                )

            if user and user.lower() not in seen_users:
                seen_users.add(user.lower())
                user_obj = User(
                    username=user,
                    source="sliver",
                    tags=["compromised"],
                )
                yield user_obj

        for match in self.HASHDUMP_PATTERN.finditer(content):
            username = match.group("username")
            ntlm = match.group("ntlm")
            lm = match.group("lm")

            if ntlm == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            cred_key = f"{username}:{ntlm}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            yield Credential(
                title=f"Sliver Hash: {username}",
                credential_type="ntlm",
                username=username,
                value=f"{lm}:{ntlm}",
                severity="critical",
                source="sliver",
                tags=["hashdump"],
            )

        for match in self.CREDENTIAL_PATTERN.finditer(content):
            domain = match.group("domain") or ""
            username = match.group("username")
            secret = match.group("secret")

            cred_key = f"{domain}\\{username}:{secret[:16]}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            yield Credential(
                title=f"Sliver Cred: {domain}\\{username}" if domain else f"Sliver Cred: {username}",
                credential_type="ntlm",
                username=username,
                domain=domain if domain else None,
                value=secret,
                severity="critical",
                source="sliver",
                tags=["harvested"],
            )

        for match in self.PIVOT_PATTERN.finditer(content):
            target = match.group("target")
            if target.lower() not in seen_hosts:
                is_ip = bool(self.IPV4_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="sliver",
                    tags=["pivot-target"],
                )
                seen_hosts[target.lower()] = host
                yield host

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Sliver log file."""
        name_lower = file_path.name.lower()
        if "sliver" in name_lower:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(4000)
                indicators = [
                    b"sliver",
                    b"Sliver",
                    b"implant",
                    b"Implant",
                    b"Session",
                    b"RemoteAddress",
                    b"Transport",
                    b"mtls",
                    b"wg",
                    b"dns",
                    b"http",
                    b"[*] Session",
                    b"[*] Beacon",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
