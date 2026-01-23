"""Havoc C2 demon logs and teamserver data parser."""

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
class HavocParser(BaseParser):
    """Parser for Havoc C2 demon logs and teamserver exports."""

    name = "havoc"
    description = "Parse Havoc C2 demon logs, teamserver data, and operator commands"
    file_patterns = ["*havoc*.json", "*havoc*.log", "*demon*.log", "*demon*.json"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    DEMON_PATTERN = re.compile(
        r"(?:demon|agent)\s+(?:registered|connected|checkin)\s+"
        r"(?:from\s+)?(?P<user>[^@\s]+)?@?(?P<hostname>[^\s(]+)\s*\((?P<ip>[^)]+)\)",
        re.IGNORECASE
    )

    DEMON_METADATA_PATTERN = re.compile(
        r"(?:Computer|Host)[:\s]+(?P<hostname>[^\r\n,]+).*?"
        r"(?:User|Username)[:\s]+(?P<user>[^\r\n,]+).*?"
        r"(?:Process|PID)[:\s]+(?P<process>[^\r\n,]+)",
        re.IGNORECASE | re.DOTALL
    )

    CREDENTIAL_PATTERN = re.compile(
        r"(?P<domain>[^\\\/\s]+)?[\\\/](?P<username>[^:\s]+)[:\s]+"
        r"(?P<hash>[a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?)",
        re.IGNORECASE
    )

    MIMIKATZ_PATTERN = re.compile(
        r"(?:Username|User)\s*:\s*(?P<username>[^\r\n]+).*?"
        r"(?:Domain)\s*:\s*(?P<domain>[^\r\n]+).*?"
        r"(?:NTLM|Password|Hash)\s*:\s*(?P<secret>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    TOKEN_PATTERN = re.compile(
        r"(?:token|impersonate|steal_token)\s+(?P<domain>[^\\\/]+)?[\\\/]?(?P<user>[^\s]+)",
        re.IGNORECASE
    )

    INJECT_PATTERN = re.compile(
        r"(?:inject|shellcode|execute-assembly)\s+(?:into\s+)?(?:pid\s+)?(?P<pid>\d+)",
        re.IGNORECASE
    )

    LATERAL_PATTERN = re.compile(
        r"(?:jump|psexec|wmi|winrm|dcom|ssh)\s+(?:to\s+)?(?P<target>[^\s]+)",
        re.IGNORECASE
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Havoc log file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_log(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Havoc JSON export."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        for entry in entries:
            if isinstance(entry, dict):
                yield from self._parse_demon_entry(entry, seen_hosts, seen_users)

    def _parse_demon_entry(self, entry: dict, seen_hosts: dict, seen_users: set) -> Generator[Entity, None, None]:
        """Parse a single demon entry from JSON."""
        demon_id = entry.get("DemonID") or entry.get("demon_id") or entry.get("AgentID") or ""
        hostname = entry.get("Computer") or entry.get("Hostname") or entry.get("hostname") or ""
        ip = entry.get("Internal") or entry.get("External") or entry.get("ip") or ""
        username = entry.get("User") or entry.get("Username") or entry.get("user") or ""
        domain = entry.get("Domain") or entry.get("domain") or ""
        os_info = entry.get("OS") or entry.get("os") or ""
        arch = entry.get("Arch") or entry.get("arch") or ""
        pid = entry.get("PID") or entry.get("pid")
        process = entry.get("Process") or entry.get("process") or ""
        elevated = entry.get("Elevated") or entry.get("elevated") or False

        if hostname or ip:
            host_key = (hostname or ip).lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(str(ip)) else "",
                    hostname=hostname if hostname else None,
                    os=f"{os_info} {arch}".strip() if os_info else None,
                    domain=domain if domain else None,
                    source="havoc",
                    tags=["demon", "compromised"],
                    raw_properties={
                        "demon_id": demon_id,
                        "pid": pid,
                        "process": process,
                        "elevated": elevated,
                    },
                )
                seen_hosts[host_key] = host
                yield host

                severity = "critical" if elevated else "high"
                yield Misconfiguration(
                    title=f"Havoc Demon: {hostname or ip}",
                    description=f"Active demon on {hostname or ip} (User: {username}, PID: {pid}, Elevated: {elevated})",
                    severity=severity,
                    affected_asset_id=host.id,
                    source="havoc",
                    check_id="active_demon",
                    tags=["demon", "compromised", "c2"],
                )

        if username and username.lower() not in seen_users:
            seen_users.add(username.lower())
            user_obj = User(
                username=username,
                domain=domain if domain else None,
                is_admin=elevated,
                source="havoc",
                tags=["compromised", "demon-user"],
            )
            yield user_obj

            if hostname and hostname.lower() in seen_hosts:
                yield Relationship(
                    source_id=user_obj.id,
                    target_id=seen_hosts[hostname.lower()].id,
                    relation_type=RelationType.HAS_SESSION,
                    source="havoc",
                    properties={"demon_id": demon_id, "elevated": elevated},
                )

        creds = entry.get("Credentials") or entry.get("credentials") or []
        if isinstance(creds, list):
            for cred in creds:
                if isinstance(cred, dict):
                    cred_user = cred.get("Username") or cred.get("username") or ""
                    cred_domain = cred.get("Domain") or cred.get("domain") or ""
                    cred_hash = cred.get("Hash") or cred.get("hash") or cred.get("NTLM") or ""
                    cred_pass = cred.get("Password") or cred.get("password") or ""

                    if cred_user and (cred_hash or cred_pass):
                        yield Credential(
                            title=f"Havoc Cred: {cred_domain}\\{cred_user}" if cred_domain else f"Havoc Cred: {cred_user}",
                            credential_type="ntlm" if cred_hash else "password",
                            username=cred_user,
                            domain=cred_domain if cred_domain else None,
                            value=cred_hash or cred_pass,
                            severity="critical",
                            source="havoc",
                            tags=["harvested"],
                        )

    def _parse_log(self, content: str) -> Generator[Entity, None, None]:
        """Parse Havoc text logs."""
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()
        seen_creds: set[str] = set()

        for match in self.DEMON_PATTERN.finditer(content):
            user = match.group("user") or ""
            hostname = match.group("hostname")
            ip = match.group("ip")

            host_key = hostname.lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(ip) else "",
                    hostname=hostname,
                    source="havoc",
                    tags=["demon", "compromised"],
                )
                seen_hosts[host_key] = host
                yield host

                yield Misconfiguration(
                    title=f"Havoc Demon: {hostname}",
                    description=f"Demon registered: {user}@{hostname} ({ip})",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="havoc",
                    check_id="demon_registered",
                    tags=["demon", "c2"],
                )

            if user and user.lower() not in seen_users:
                seen_users.add(user.lower())
                user_obj = User(
                    username=user,
                    source="havoc",
                    tags=["compromised"],
                )
                yield user_obj

        for match in self.DEMON_METADATA_PATTERN.finditer(content):
            hostname = match.group("hostname").strip()
            user = match.group("user").strip()

            if hostname and hostname.lower() not in seen_hosts:
                host = Host(
                    ip="",
                    hostname=hostname,
                    source="havoc",
                    tags=["demon", "compromised"],
                )
                seen_hosts[hostname.lower()] = host
                yield host

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
                title=f"Havoc Mimikatz: {domain}\\{username}" if domain else f"Havoc Mimikatz: {username}",
                credential_type="ntlm" if is_ntlm else "password",
                username=username,
                domain=domain if domain and domain != "(null)" else None,
                value=secret,
                severity="critical",
                source="havoc",
                tags=["mimikatz", "harvested"],
            )

        for match in self.CREDENTIAL_PATTERN.finditer(content):
            domain = match.group("domain") or ""
            username = match.group("username")
            hash_val = match.group("hash")

            cred_key = f"{domain}\\{username}:{hash_val[:16]}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            yield Credential(
                title=f"Havoc Hash: {domain}\\{username}" if domain else f"Havoc Hash: {username}",
                credential_type="ntlm",
                username=username,
                domain=domain if domain else None,
                value=hash_val,
                severity="critical",
                source="havoc",
                tags=["harvested"],
            )

        for match in self.LATERAL_PATTERN.finditer(content):
            target = match.group("target")
            if target.lower() not in seen_hosts:
                is_ip = bool(self.IPV4_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="havoc",
                    tags=["lateral-target"],
                )
                seen_hosts[target.lower()] = host
                yield host

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Havoc log file."""
        name_lower = file_path.name.lower()
        if any(x in name_lower for x in ["havoc", "demon"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(4000)
                indicators = [
                    b"havoc",
                    b"Havoc",
                    b"demon",
                    b"Demon",
                    b"DemonID",
                    b"teamserver",
                    b"Elevated",
                    b"[*] Demon",
                    b"[+] Agent",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
