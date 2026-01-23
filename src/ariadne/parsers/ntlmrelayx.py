"""ntlmrelayx NTLM relay attack log parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class NtlmrelayxParser(BaseParser):
    """Parser for ntlmrelayx NTLM relay attack logs and captured credentials."""

    name = "ntlmrelayx"
    description = "Parse ntlmrelayx NTLM relay attack logs and captured credentials"
    file_patterns = ["*ntlmrelayx*.txt", "*ntlmrelayx*.log", "*relay*.log"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration"]

    RELAY_SUCCESS_PATTERN = re.compile(
        r"(?:Authenticating|Relaying|Successfully)\s+(?:against|to|authenticated)\s+(?P<target>\S+)\s+"
        r"(?:as|with)\s+(?:(?P<domain>[^\\@/\s]+)[\\@/])?(?P<username>\S+)",
        re.IGNORECASE
    )

    SAM_DUMP_PATTERN = re.compile(
        r"(?P<username>[^:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<ntlm>[a-fA-F0-9]{32}):::"
    )

    NTLM_HASH_PATTERN = re.compile(
        r"(?P<domain>[^\\:]+)?\\?(?P<username>[^:]+)::(?P<challenge>[a-fA-F0-9]+):(?P<response>[a-fA-F0-9]+):(?P<blob>[a-fA-F0-9]+)"
    )

    SECRET_PATTERN = re.compile(
        r"(?:\[[\*\+]\]|SECRET)\s*:?\s*(?P<name>[^:]+)\s*:\s*(?P<value>.+)",
        re.IGNORECASE
    )

    TARGET_PATTERN = re.compile(
        r"(?:Target|Relaying to|Connecting to)\s*[:=]?\s*(?P<target>\S+)",
        re.IGNORECASE
    )

    SMB_SIGNING_PATTERN = re.compile(
        r"(?P<host>\S+)\s+(?:does not|doesn't)\s+(?:require|enforce)\s+(?:SMB\s*)?signing",
        re.IGNORECASE
    )

    SHELL_PATTERN = re.compile(
        r"(?:Got|Obtained|Executing)\s+(?:shell|command|code)\s+(?:on|at)\s+(?P<target>\S+)",
        re.IGNORECASE
    )

    ADMIN_PATTERN = re.compile(
        r"(?P<username>\S+)\s+(?:has|is)\s+(?:admin|administrator)\s+(?:access|rights)\s+(?:on|to)\s+(?P<target>\S+)",
        re.IGNORECASE
    )

    IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an ntlmrelayx log file and yield entities."""
        content = file_path.read_text(errors="ignore")

        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()

        yield from self._parse_targets(content, seen_hosts)
        yield from self._parse_smb_signing(content, seen_hosts)
        yield from self._parse_relay_success(content, seen_hosts, seen_users)
        yield from self._parse_sam_dump(content, seen_hosts)
        yield from self._parse_ntlm_hashes(content, seen_hosts)
        yield from self._parse_secrets(content, seen_hosts)
        yield from self._parse_shells(content, seen_hosts, seen_users)

    def _parse_targets(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Extract target hosts."""
        for match in self.TARGET_PATTERN.finditer(content):
            target = match.group("target")
            if target and target not in seen_hosts:
                is_ip = bool(self.IP_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="ntlmrelayx",
                    tags=["relay-target"],
                )
                seen_hosts[target] = host
                yield host

    def _parse_smb_signing(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse SMB signing disabled hosts."""
        for match in self.SMB_SIGNING_PATTERN.finditer(content):
            host_str = match.group("host")

            if host_str not in seen_hosts:
                is_ip = bool(self.IP_PATTERN.match(host_str))
                host = Host(
                    ip=host_str if is_ip else "",
                    hostname=host_str if not is_ip else None,
                    source="ntlmrelayx",
                    tags=["smb-signing-disabled"],
                )
                seen_hosts[host_str] = host
                yield host
            else:
                host = seen_hosts[host_str]

            yield Misconfiguration(
                title=f"SMB Signing Not Required: {host_str}",
                description=f"Host {host_str} does not require SMB signing, enabling NTLM relay attacks",
                severity="medium",
                affected_asset_id=host.id,
                source="ntlmrelayx",
                check_id="smb_signing_disabled",
                tags=["ntlm-relay"],
            )

    def _parse_relay_success(self, content: str, seen_hosts: dict[str, Host], seen_users: set[str]) -> Generator[Entity, None, None]:
        """Parse successful relay attempts."""
        for match in self.RELAY_SUCCESS_PATTERN.finditer(content):
            target = match.group("target")
            username = match.group("username")
            domain = match.groupdict().get("domain")

            if target and target not in seen_hosts:
                is_ip = bool(self.IP_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="ntlmrelayx",
                )
                seen_hosts[target] = host
                yield host

            if username:
                user_key = f"{domain}\\{username}".lower() if domain else username.lower()
                if user_key not in seen_users:
                    seen_users.add(user_key)
                    user = User(
                        username=username,
                        domain=domain,
                        source="ntlmrelayx",
                        tags=["relayed"],
                    )
                    yield user

                    if target and target in seen_hosts:
                        yield Relationship(
                            source_id=user.id,
                            target_id=seen_hosts[target].id,
                            relation_type=RelationType.HAS_ACCESS,
                            source="ntlmrelayx",
                            properties={"via": "ntlm_relay"},
                        )

    def _parse_sam_dump(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse dumped SAM hashes."""
        seen_creds: set[str] = set()

        for match in self.SAM_DUMP_PATTERN.finditer(content):
            username = match.group("username")
            ntlm = match.group("ntlm")

            if ntlm == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            cred_key = f"sam:{username}:{ntlm}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            host = next(iter(seen_hosts.values()), None)

            yield Credential(
                title=f"SAM hash for {username}",
                credential_type="ntlm",
                username=username,
                value=ntlm,
                ntlm_hash=ntlm,
                severity="critical",
                affected_asset_id=host.id if host else None,
                source="ntlmrelayx",
                tags=["relay-dumped", "sam"],
            )

    def _parse_ntlm_hashes(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse captured NTLM hashes."""
        seen_creds: set[str] = set()

        for match in self.NTLM_HASH_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain") or ""
            hash_value = match.group(0)

            cred_key = f"ntlm:{domain}\\{username}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            user = User(
                username=username,
                domain=domain if domain else None,
                source="ntlmrelayx",
                tags=["captured"],
            )
            yield user

            yield Credential(
                title=f"Net-NTLM hash for {domain}\\{username}" if domain else f"Net-NTLM hash for {username}",
                credential_type="ntlmv2",
                username=username,
                domain=domain if domain else None,
                value=hash_value[:200] + "...",
                severity="high",
                source="ntlmrelayx",
                tags=["captured", "relay"],
            )

    def _parse_secrets(self, content: str, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse extracted secrets (LSA, DPAPI, etc.)."""
        for match in self.SECRET_PATTERN.finditer(content):
            name = match.group("name").strip()
            value = match.group("value").strip()

            if not value or value in ["(null)", ""]:
                continue

            host = next(iter(seen_hosts.values()), None)

            yield Credential(
                title=f"Secret: {name}",
                credential_type="secret",
                value=value[:500] if len(value) > 500 else value,
                severity="high",
                affected_asset_id=host.id if host else None,
                source="ntlmrelayx",
                tags=["relay-extracted"],
                raw_data={"secret_name": name},
            )

    def _parse_shells(self, content: str, seen_hosts: dict[str, Host], seen_users: set[str]) -> Generator[Entity, None, None]:
        """Parse shell/code execution achievements."""
        for match in self.SHELL_PATTERN.finditer(content):
            target = match.group("target")

            if target not in seen_hosts:
                is_ip = bool(self.IP_PATTERN.match(target))
                host = Host(
                    ip=target if is_ip else "",
                    hostname=target if not is_ip else None,
                    source="ntlmrelayx",
                    tags=["compromised"],
                )
                seen_hosts[target] = host
                yield host
            else:
                host = seen_hosts[target]

            yield Misconfiguration(
                title=f"Code Execution Achieved: {target}",
                description=f"Successfully executed code on {target} via NTLM relay",
                severity="critical",
                affected_asset_id=host.id,
                source="ntlmrelayx",
                check_id="relay_shell",
                tags=["compromised", "code-execution"],
            )

        for match in self.ADMIN_PATTERN.finditer(content):
            username = match.group("username")
            target = match.group("target")

            if target in seen_hosts:
                host = seen_hosts[target]

                yield Misconfiguration(
                    title=f"Admin Access via Relay: {username} -> {target}",
                    description=f"User {username} has admin access to {target} confirmed via relay",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="ntlmrelayx",
                    check_id="relay_admin",
                    tags=["admin-access"],
                )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an ntlmrelayx log file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if any(x in file_path.name.lower() for x in ["ntlmrelayx", "relay"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"ntlmrelayx",
                    b"Impacket",
                    b"NTLM Relay",
                    b"Relaying",
                    b"SMB signing",
                    b"Authenticating against",
                    b"dumping SAM",
                    b"secretsdump",
                    b"[*] Target",
                    b"[+] Relayed",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
