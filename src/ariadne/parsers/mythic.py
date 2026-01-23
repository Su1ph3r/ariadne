"""Mythic C2 callback logs and task data parser."""

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
class MythicParser(BaseParser):
    """Parser for Mythic C2 callback logs and task exports."""

    name = "mythic"
    description = "Parse Mythic C2 callback logs, task data, and credential harvesting"
    file_patterns = ["*mythic*.json", "*mythic*.log", "*callback*.json", "*apfell*.json"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration", "Relationship"]

    CALLBACK_PATTERN = re.compile(
        r"(?:callback|agent|payload)\s+(?:registered|connected|checkin).*?"
        r"(?:host|hostname)[:\s]+(?P<hostname>[^\s,]+).*?"
        r"(?:ip|address)[:\s]+(?P<ip>[^\s,]+)",
        re.IGNORECASE | re.DOTALL
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Mythic log file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_log(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Mythic JSON export."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        for entry in entries:
            if isinstance(entry, dict):
                if "callbacks" in entry:
                    for cb in entry["callbacks"]:
                        yield from self._parse_callback_entry(cb, seen_hosts, seen_users)
                elif "tasks" in entry:
                    for task in entry["tasks"]:
                        yield from self._parse_task_entry(task, seen_hosts, seen_users)
                else:
                    yield from self._parse_callback_entry(entry, seen_hosts, seen_users)

    def _parse_callback_entry(self, entry: dict, seen_hosts: dict, seen_users: set) -> Generator[Entity, None, None]:
        """Parse a single callback entry from JSON."""
        callback_id = entry.get("id") or entry.get("agent_callback_id") or entry.get("display_id") or ""
        hostname = entry.get("host") or entry.get("hostname") or ""
        ip = entry.get("ip") or entry.get("external_ip") or entry.get("internal_ip") or ""
        username = entry.get("user") or entry.get("username") or ""
        domain = entry.get("domain") or ""
        os_info = entry.get("os") or ""
        arch = entry.get("architecture") or ""
        pid = entry.get("pid")
        process_name = entry.get("process_name") or ""
        integrity = entry.get("integrity_level") or entry.get("integrity") or ""
        payload_type = entry.get("payload_type") or entry.get("payload") or ""

        is_elevated = bool(integrity and ("high" in integrity.lower() or "system" in integrity.lower()))

        if hostname or ip:
            host_key = (hostname or ip).lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(str(ip)) else "",
                    hostname=hostname if hostname else None,
                    os=f"{os_info} {arch}".strip() if os_info else None,
                    domain=domain if domain else None,
                    source="mythic",
                    tags=["callback", "compromised"],
                    raw_properties={
                        "callback_id": callback_id,
                        "pid": pid,
                        "process_name": process_name,
                        "integrity_level": integrity,
                        "payload_type": payload_type,
                    },
                )
                seen_hosts[host_key] = host
                yield host

                severity = "critical" if is_elevated else "high"
                yield Misconfiguration(
                    title=f"Mythic Callback: {hostname or ip}",
                    description=f"Active {payload_type} callback on {hostname or ip} (User: {username}, Integrity: {integrity})",
                    severity=severity,
                    affected_asset_id=host.id,
                    source="mythic",
                    check_id="active_callback",
                    tags=["callback", "compromised", "c2"],
                )

        if username and username.lower() not in seen_users:
            seen_users.add(username.lower())
            user_obj = User(
                username=username,
                domain=domain if domain else None,
                is_admin=is_elevated,
                source="mythic",
                tags=["compromised", "callback-user"],
            )
            yield user_obj

            if hostname and hostname.lower() in seen_hosts:
                yield Relationship(
                    source_id=user_obj.id,
                    target_id=seen_hosts[hostname.lower()].id,
                    relation_type=RelationType.HAS_SESSION,
                    source="mythic",
                    properties={"callback_id": callback_id, "integrity": integrity},
                )

    def _parse_task_entry(self, task: dict, seen_hosts: dict, seen_users: set) -> Generator[Entity, None, None]:
        """Parse a task entry for credentials and other findings."""
        command = task.get("command") or task.get("command_name") or ""
        params = task.get("params") or task.get("parameters") or ""
        output = task.get("response") or task.get("output") or task.get("result") or ""
        status = task.get("status") or ""

        if status.lower() not in ["completed", "success", "processed"]:
            return

        full_output = f"{params}\n{output}".lower()

        if any(x in command.lower() for x in ["mimikatz", "logonpasswords", "sekurlsa", "credentials"]):
            yield from self._parse_mimikatz_output(output)

        if any(x in command.lower() for x in ["hashdump", "sam", "secretsdump"]):
            yield from self._parse_hashdump_output(output)

        if "shell" in command.lower() or "execute" in command.lower():
            yield from self._parse_shell_output(output, seen_hosts)

    def _parse_mimikatz_output(self, output: str) -> Generator[Entity, None, None]:
        """Parse mimikatz-style output for credentials."""
        pattern = re.compile(
            r"(?:Username|User)\s*:\s*(?P<username>[^\r\n]+).*?"
            r"(?:Domain)\s*:\s*(?P<domain>[^\r\n]+).*?"
            r"(?:NTLM|Password|Hash)\s*:\s*(?P<secret>[^\r\n]+)",
            re.IGNORECASE | re.DOTALL
        )

        seen_creds: set[str] = set()
        for match in pattern.finditer(output):
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
                title=f"Mythic Cred: {domain}\\{username}" if domain else f"Mythic Cred: {username}",
                credential_type="ntlm" if is_ntlm else "password",
                username=username,
                domain=domain if domain and domain != "(null)" else None,
                value=secret,
                severity="critical",
                source="mythic",
                tags=["mimikatz", "harvested"],
            )

    def _parse_hashdump_output(self, output: str) -> Generator[Entity, None, None]:
        """Parse hashdump output for NTLM hashes."""
        pattern = re.compile(
            r"(?P<username>[^:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<ntlm>[a-fA-F0-9]{32}):::"
        )

        seen_creds: set[str] = set()
        for match in pattern.finditer(output):
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
                title=f"Mythic Hash: {username}",
                credential_type="ntlm",
                username=username,
                value=f"{lm}:{ntlm}",
                severity="critical",
                source="mythic",
                tags=["hashdump"],
            )

    def _parse_shell_output(self, output: str, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse shell command output for additional hosts."""
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

        for match in ip_pattern.finditer(output):
            ip = match.group(1)
            if ip.startswith("127.") or ip.startswith("0."):
                continue
            if ip not in seen_hosts:
                seen_hosts[ip] = True

    def _parse_log(self, content: str) -> Generator[Entity, None, None]:
        """Parse Mythic text logs."""
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        for match in self.CALLBACK_PATTERN.finditer(content):
            hostname = match.group("hostname")
            ip = match.group("ip")

            host_key = (hostname or ip).lower()
            if host_key not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(ip) else "",
                    hostname=hostname if hostname else None,
                    source="mythic",
                    tags=["callback", "compromised"],
                )
                seen_hosts[host_key] = host
                yield host

                yield Misconfiguration(
                    title=f"Mythic Callback: {hostname or ip}",
                    description=f"Callback registered from {hostname or ip}",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="mythic",
                    check_id="callback_registered",
                    tags=["callback", "c2"],
                )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Mythic log file."""
        name_lower = file_path.name.lower()
        if any(x in name_lower for x in ["mythic", "callback", "apfell"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(4000)
                indicators = [
                    b"mythic",
                    b"Mythic",
                    b"callback",
                    b"Callback",
                    b"agent_callback_id",
                    b"payload_type",
                    b"integrity_level",
                    b"apfell",
                    b"Apfell",
                    b"apollo",
                    b"poseidon",
                    b"medusa",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
