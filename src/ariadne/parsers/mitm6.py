"""mitm6 IPv6 DNS takeover and relay attack log parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class Mitm6Parser(BaseParser):
    """Parser for mitm6 IPv6 DNS takeover attack logs."""

    name = "mitm6"
    description = "Parse mitm6 IPv6 DNS takeover and relay attack logs"
    file_patterns = ["*mitm6*.txt", "*mitm6*.log"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration"]

    VICTIM_PATTERN = re.compile(
        r"(?:Received|Got|Spoofing)\s+(?:DHCPv6|DNS)\s+(?:request|query)\s+(?:from|for)\s+"
        r"(?P<hostname>[^\s(]+)\s*(?:\((?P<ip>[^)]+)\))?",
        re.IGNORECASE
    )

    RELAY_PATTERN = re.compile(
        r"(?:Relaying|Forwarding|Authenticating)\s+(?:NTLM|credentials?)\s+"
        r"(?:from|for)\s+(?P<user>[^\s]+)\s+(?:to|against)\s+(?P<target>\S+)",
        re.IGNORECASE
    )

    HASH_PATTERN = re.compile(
        r"(?P<domain>[^\\:]+)?\\?(?P<username>[^:]+)::(?P<challenge>[a-fA-F0-9]+):"
        r"(?P<response>[a-fA-F0-9]+):(?P<blob>[a-fA-F0-9]+)"
    )

    AUTH_SUCCESS_PATTERN = re.compile(
        r"(?:Successfully|Authentication)\s+(?:authenticated|succeeded|successful)\s+"
        r"(?:as|for)\s+(?P<user>\S+)\s+(?:on|to|against)\s+(?P<target>\S+)",
        re.IGNORECASE
    )

    WPAD_PATTERN = re.compile(
        r"(?:Serving|Sent)\s+WPAD\s+(?:file|proxy)\s+to\s+(?P<victim>\S+)",
        re.IGNORECASE
    )

    IPV6_PATTERN = re.compile(r"([a-fA-F0-9:]+:+[a-fA-F0-9:]+)")
    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a mitm6 log file and yield entities."""
        content = file_path.read_text(errors="ignore")

        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        yield from self._parse_victims(content, seen_hosts)
        yield from self._parse_relays(content, seen_hosts, seen_users)
        yield from self._parse_hashes(content, seen_hosts, seen_users)
        yield from self._parse_auth_success(content, seen_hosts, seen_users)
        yield from self._parse_wpad(content, seen_hosts)

    def _parse_victims(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse victim hosts from DHCPv6/DNS requests."""
        for match in self.VICTIM_PATTERN.finditer(content):
            hostname = match.group("hostname")
            ip = match.group("ip") or ""

            if hostname and hostname.lower() not in seen_hosts:
                host = Host(
                    ip=ip if self.IPV4_PATTERN.match(ip) else "",
                    hostname=hostname,
                    source="mitm6",
                    tags=["mitm6-victim", "ipv6-vulnerable"],
                )
                seen_hosts[hostname.lower()] = host
                yield host

                yield Misconfiguration(
                    title=f"IPv6 DNS Takeover Victim: {hostname}",
                    description=f"Host {hostname} responded to malicious DHCPv6/DNS, indicating IPv6 is enabled without proper security",
                    severity="medium",
                    affected_asset_id=host.id,
                    source="mitm6",
                    check_id="ipv6_vulnerable",
                    tags=["ipv6", "dns-takeover"],
                )

    def _parse_relays(self, content: str, seen_hosts: dict[str, Host], seen_users: set[str]) -> Generator[Entity, None, None]:
        """Parse relay attempts."""
        for match in self.RELAY_PATTERN.finditer(content):
            user_str = match.group("user")
            target = match.group("target")

            domain = None
            username = user_str
            if "\\" in user_str:
                domain, username = user_str.split("\\", 1)
            elif "@" in user_str:
                username, domain = user_str.split("@", 1)

            user_key = f"{domain}\\{username}".lower() if domain else username.lower()
            if user_key not in seen_users:
                seen_users.add(user_key)
                user = User(
                    username=username,
                    domain=domain,
                    source="mitm6",
                    tags=["relayed"],
                )
                yield user

            if target and target.lower() not in seen_hosts:
                is_ip = bool(self.IPV4_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="mitm6",
                    tags=["relay-target"],
                )
                seen_hosts[target.lower()] = host
                yield host

    def _parse_hashes(self, content: str, seen_hosts: dict[str, Host], seen_users: set[str]) -> Generator[Entity, None, None]:
        """Parse captured NTLM hashes."""
        seen_hashes: set[str] = set()

        for match in self.HASH_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain") or ""
            hash_value = match.group(0)

            hash_key = f"{domain}\\{username}:{hash_value[:32]}"
            if hash_key in seen_hashes:
                continue
            seen_hashes.add(hash_key)

            user_key = f"{domain}\\{username}".lower() if domain else username.lower()
            if user_key not in seen_users:
                seen_users.add(user_key)
                user = User(
                    username=username,
                    domain=domain if domain else None,
                    source="mitm6",
                    tags=["ntlm-captured"],
                )
                yield user

            yield Credential(
                title=f"Net-NTLMv2 hash: {domain}\\{username}" if domain else f"Net-NTLMv2 hash: {username}",
                credential_type="ntlmv2",
                username=username,
                domain=domain if domain else None,
                value=hash_value,
                severity="high",
                source="mitm6",
                tags=["captured", "relay"],
            )

    def _parse_auth_success(self, content: str, seen_hosts: dict[str, Host], seen_users: set[str]) -> Generator[Entity, None, None]:
        """Parse successful authentications."""
        for match in self.AUTH_SUCCESS_PATTERN.finditer(content):
            user_str = match.group("user")
            target = match.group("target")

            domain = None
            username = user_str
            if "\\" in user_str:
                domain, username = user_str.split("\\", 1)

            if target.lower() in seen_hosts:
                host = seen_hosts[target.lower()]

                yield Misconfiguration(
                    title=f"Relay Attack Success: {target}",
                    description=f"Successfully relayed {user_str} credentials to {target}",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="mitm6",
                    check_id="relay_success",
                    tags=["compromised", "relay"],
                )

    def _parse_wpad(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse WPAD proxy attacks."""
        for match in self.WPAD_PATTERN.finditer(content):
            victim = match.group("victim")

            if victim.lower() not in seen_hosts:
                is_ip = bool(self.IPV4_PATTERN.match(victim))
                host = Host(
                    ip=victim if is_ip else "",
                    hostname=victim if not is_ip else None,
                    source="mitm6",
                    tags=["wpad-victim"],
                )
                seen_hosts[victim.lower()] = host
                yield host
            else:
                host = seen_hosts[victim.lower()]

            yield Misconfiguration(
                title=f"WPAD Attack Victim: {victim}",
                description=f"Host {victim} requested and received malicious WPAD configuration",
                severity="high",
                affected_asset_id=host.id,
                source="mitm6",
                check_id="wpad_attack",
                tags=["wpad", "proxy"],
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a mitm6 log file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if "mitm6" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"mitm6",
                    b"DHCPv6",
                    b"IPv6",
                    b"WPAD",
                    b"Spoofing",
                    b"DNS takeover",
                    b"Relaying NTLM",
                    b"fe80::",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
