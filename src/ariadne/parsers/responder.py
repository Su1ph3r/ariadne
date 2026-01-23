"""Responder log and hash parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class ResponderParser(BaseParser):
    """Parser for Responder captured hashes and logs."""

    name = "responder"
    description = "Parse Responder LLMNR/NBT-NS/MDNS poisoning captured hashes"
    file_patterns = [
        "*Responder*.txt",
        "*responder*.log",
        "*NTLM*.txt",
        "*SMB-NTLMv*.txt",
        "*HTTP-NTLMv*.txt",
        "*MSSQL-NTLMv*.txt",
    ]
    entity_types = ["Host", "User", "Credential"]

    NTLMV2_PATTERN = re.compile(
        r"(?P<username>[^:]+)::(?P<domain>[^:]*):(?P<challenge>[a-fA-F0-9]+):(?P<response>[a-fA-F0-9]+):(?P<blob>[a-fA-F0-9]+)"
    )

    NTLMV1_PATTERN = re.compile(
        r"(?P<username>[^:]+)::(?P<domain>[^:]*):(?P<lm_response>[a-fA-F0-9]+):(?P<nt_response>[a-fA-F0-9]+):(?P<challenge>[a-fA-F0-9]+)"
    )

    NETNTLMV2_FULL = re.compile(
        r"(?P<username>[^:]+)::(?P<domain>[^:]*):(?P<server_challenge>[a-fA-F0-9]{16}):(?P<ntproof>[a-fA-F0-9]{32}):(?P<blob>[a-fA-F0-9]+)"
    )

    LOG_ENTRY_PATTERN = re.compile(
        r"\[(?P<protocol>[^\]]+)\]\s+(?:NTLMv[12](?:-SSP)?(?:\s+Client)?\s*:\s*(?P<client_ip>\d+\.\d+\.\d+\.\d+)|"
        r"Hash\s*:\s*(?P<hash>[^\n]+)|"
        r"(?:User(?:name)?|Client)\s*:\s*(?P<username>[^\n]+)|"
        r"Domain\s*:\s*(?P<domain>[^\n]+))"
    )

    CLEARTEXT_PATTERN = re.compile(
        r"\[(?P<protocol>[^\]]+)\]\s+Cleartext-Password\s*:\s*(?P<password>[^\n]+)"
    )

    IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Responder log/hash file and yield entities."""
        content = file_path.read_text(errors="ignore")
        filename = file_path.name.lower()

        if "ntlmv" in filename or "smb-" in filename or "http-" in filename:
            yield from self._parse_hash_file(content, filename)
        else:
            yield from self._parse_log_file(content)

    def _parse_hash_file(self, content: str, filename: str) -> Generator[Entity, None, None]:
        """Parse a Responder hash dump file."""
        seen_hashes: set[str] = set()
        seen_users: set[str] = set()
        seen_hosts: set[str] = set()

        protocol = self._extract_protocol(filename)

        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = self.NETNTLMV2_FULL.match(line) or self.NTLMV2_PATTERN.match(line) or self.NTLMV1_PATTERN.match(line)

            if match:
                groups = match.groupdict()
                username = groups.get("username", "")
                domain = groups.get("domain", "")
                hash_value = line

                if hash_value in seen_hashes:
                    continue
                seen_hashes.add(hash_value)

                user_key = f"{domain}\\{username}".lower()
                if user_key not in seen_users:
                    seen_users.add(user_key)
                    user = User(
                        username=username,
                        domain=domain if domain else None,
                        source="responder",
                        tags=["ntlm-captured"],
                    )
                    yield user

                hash_type = "ntlmv2" if "ntlmv2" in filename or len(groups.get("blob", "")) > 32 else "ntlmv1"

                yield Credential(
                    title=f"Net-NTLMv2 hash for {domain}\\{username}" if domain else f"Net-NTLMv2 hash for {username}",
                    credential_type=hash_type,
                    username=username,
                    domain=domain if domain else None,
                    value=hash_value,
                    severity="high",
                    source="responder",
                    tags=["captured", protocol] if protocol else ["captured"],
                )

    def _parse_log_file(self, content: str) -> Generator[Entity, None, None]:
        """Parse a Responder session log file."""
        seen_hosts: dict[str, Host] = {}
        seen_users: set[str] = set()
        current_entry: dict[str, str] = {}

        for line in content.split("\n"):
            line = line.strip()

            ip_match = self.IP_PATTERN.search(line)
            if ip_match:
                ip = ip_match.group(1)
                if ip not in seen_hosts and not ip.startswith("127."):
                    host = Host(
                        ip=ip,
                        source="responder",
                        tags=["poisoning-victim"],
                    )
                    seen_hosts[ip] = host
                    yield host
                current_entry["client_ip"] = ip

            if "[*]" in line or "[-]" in line or "[+]" in line:
                if "NTLMv" in line or "Hash" in line:
                    if "client" in line.lower():
                        pass

            match = self.LOG_ENTRY_PATTERN.search(line)
            if match:
                groups = match.groupdict()
                if groups.get("protocol"):
                    current_entry["protocol"] = groups["protocol"]
                if groups.get("client_ip"):
                    current_entry["client_ip"] = groups["client_ip"]
                if groups.get("username"):
                    current_entry["username"] = groups["username"].strip()
                if groups.get("domain"):
                    current_entry["domain"] = groups["domain"].strip()
                if groups.get("hash"):
                    current_entry["hash"] = groups["hash"].strip()

            cleartext_match = self.CLEARTEXT_PATTERN.search(line)
            if cleartext_match:
                protocol = cleartext_match.group("protocol")
                password = cleartext_match.group("password").strip()

                username = current_entry.get("username", "unknown")
                domain = current_entry.get("domain", "")

                yield Credential(
                    title=f"Cleartext password for {domain}\\{username}" if domain else f"Cleartext password for {username}",
                    credential_type="password",
                    username=username,
                    domain=domain if domain else None,
                    value=password,
                    severity="critical",
                    source="responder",
                    tags=["cleartext", protocol],
                )
                current_entry = {}
                continue

            if current_entry.get("hash") and current_entry.get("username"):
                username = current_entry["username"]
                domain = current_entry.get("domain", "")
                hash_value = current_entry["hash"]

                user_key = f"{domain}\\{username}".lower()
                if user_key not in seen_users:
                    seen_users.add(user_key)
                    user = User(
                        username=username,
                        domain=domain if domain else None,
                        source="responder",
                        tags=["ntlm-captured"],
                    )
                    yield user

                yield Credential(
                    title=f"Net-NTLM hash for {domain}\\{username}" if domain else f"Net-NTLM hash for {username}",
                    credential_type="ntlmv2",
                    username=username,
                    domain=domain if domain else None,
                    value=hash_value,
                    severity="high",
                    source="responder",
                    tags=["captured"],
                )

                if current_entry.get("client_ip") and current_entry["client_ip"] in seen_hosts:
                    host = seen_hosts[current_entry["client_ip"]]
                    yield Relationship(
                        source_id=f"user:{domain}\\{username}" if domain else f"user:{username}",
                        target_id=host.id,
                        relation_type=RelationType.HAS_SESSION,
                        source="responder",
                    )

                current_entry = {}

    def _extract_protocol(self, filename: str) -> str:
        """Extract protocol from filename."""
        protocols = ["smb", "http", "ldap", "mssql", "ftp", "imap", "pop3", "smtp"]
        filename_lower = filename.lower()
        for proto in protocols:
            if proto in filename_lower:
                return proto
        return ""

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Responder log/hash file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        filename_lower = file_path.name.lower()
        if any(x in filename_lower for x in ["responder", "ntlmv", "smb-ntlm", "http-ntlm"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"Responder",
                    b"NTLMv1",
                    b"NTLMv2",
                    b"LLMNR",
                    b"NBT-NS",
                    b"MDNS",
                    b"Poisoner",
                    rb"::[^:]*:[a-fA-F0-9]{16}:",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
