"""Mimikatz credential extraction output parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class MimikatzParser(BaseParser):
    """Parser for Mimikatz credential extraction output."""

    name = "mimikatz"
    description = "Parse Mimikatz credential dump output (sekurlsa, lsadump, etc.)"
    file_patterns = ["*mimikatz*.txt", "*mimikatz*.log", "*sekurlsa*.txt", "*lsadump*.txt"]
    entity_types = ["Host", "User", "Credential"]

    AUTH_PACKAGE_PATTERN = re.compile(
        r"Authentication Id\s*:\s*\d+\s*;\s*\d+.*?"
        r"Session\s*:\s*(?P<session>\S+).*?"
        r"User Name\s*:\s*(?P<username>\S+).*?"
        r"Domain\s*:\s*(?P<domain>\S+)",
        re.DOTALL | re.IGNORECASE
    )

    CRED_BLOCK_PATTERN = re.compile(
        r"(?:msv|tspkg|wdigest|kerberos|ssp|credman|cloudap)\s*:"
        r".*?(?=(?:msv|tspkg|wdigest|kerberos|ssp|credman|cloudap|Authentication Id)\s*:|$)",
        re.DOTALL | re.IGNORECASE
    )

    USERNAME_PATTERN = re.compile(r"(?:User(?:name|Name)?|User)\s*:\s*(\S+)", re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r"Domain\s*:\s*(\S+)", re.IGNORECASE)
    PASSWORD_PATTERN = re.compile(r"Password\s*:\s*(.+?)(?:\n|$)", re.IGNORECASE)
    NTLM_PATTERN = re.compile(r"(?:NTLM|NT)\s*:\s*([a-fA-F0-9]{32})", re.IGNORECASE)
    SHA1_PATTERN = re.compile(r"SHA1\s*:\s*([a-fA-F0-9]{40})", re.IGNORECASE)
    LM_PATTERN = re.compile(r"LM\s*:\s*([a-fA-F0-9]{32})", re.IGNORECASE)

    DCSYNC_PATTERN = re.compile(
        r"SAM Username\s*:\s*(?P<username>\S+).*?"
        r"Hash NTLM\s*:\s*(?P<ntlm>[a-fA-F0-9]{32})",
        re.DOTALL | re.IGNORECASE
    )

    SAM_PATTERN = re.compile(
        r"(?:User|RID)\s*:\s*(?P<username>\S+).*?"
        r"(?:Hash NTLM|NTLM)\s*:\s*(?P<ntlm>[a-fA-F0-9]{32})",
        re.DOTALL | re.IGNORECASE
    )

    DPAPI_MASTERKEY_PATTERN = re.compile(
        r"(?:GUID|guidMasterKey)\s*:\s*\{?(?P<guid>[a-fA-F0-9-]+)\}?.*?"
        r"(?:key|masterkey)\s*:\s*(?P<key>[a-fA-F0-9]+)",
        re.DOTALL | re.IGNORECASE
    )

    TICKET_PATTERN = re.compile(
        r"(?:Service Name|Server Name)\s*:\s*(?P<service>\S+).*?"
        r"(?:Client Name|Client)\s*:\s*(?P<client>\S+)",
        re.DOTALL | re.IGNORECASE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Mimikatz output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        hostname = self._extract_hostname(content)
        host = None
        if hostname:
            host = Host(
                ip="",
                hostname=hostname,
                source="mimikatz",
            )
            yield host

        yield from self._parse_sekurlsa(content, host)
        yield from self._parse_lsadump(content, host)
        yield from self._parse_dcsync(content, host)
        yield from self._parse_dpapi(content, host)
        yield from self._parse_simple_creds(content, host)

    def _extract_hostname(self, content: str) -> str | None:
        """Extract hostname from Mimikatz output."""
        hostname_match = re.search(r"Hostname:\s*(\S+)", content, re.IGNORECASE)
        if hostname_match:
            return hostname_match.group(1)

        computer_match = re.search(r"(?:Computer|Machine)\s*(?:Name)?\s*:\s*(\S+)", content, re.IGNORECASE)
        if computer_match:
            return computer_match.group(1)

        return None

    def _parse_sekurlsa(self, content: str, host: Host | None) -> Generator[Entity, None, None]:
        """Parse sekurlsa::logonpasswords output."""
        seen_creds: set[str] = set()
        seen_users: set[str] = set()

        sections = re.split(r"Authentication Id\s*:", content)

        for section in sections[1:]:
            username = None
            domain = None
            password = None
            ntlm = None

            user_match = self.USERNAME_PATTERN.search(section)
            if user_match:
                username = user_match.group(1)
                if username.lower() in ["(null)", ""]:
                    continue

            domain_match = self.DOMAIN_PATTERN.search(section)
            if domain_match:
                domain = domain_match.group(1)
                if domain.lower() in ["(null)", ""]:
                    domain = None

            password_match = self.PASSWORD_PATTERN.search(section)
            if password_match:
                password = password_match.group(1).strip()
                if password.lower() in ["(null)", "(null))", ""]:
                    password = None

            ntlm_match = self.NTLM_PATTERN.search(section)
            if ntlm_match:
                ntlm = ntlm_match.group(1)

            if not username:
                continue

            user_key = f"{domain}\\{username}".lower() if domain else username.lower()
            if user_key not in seen_users:
                seen_users.add(user_key)
                user = User(
                    username=username,
                    domain=domain,
                    source="mimikatz",
                )
                yield user

            if password and len(password) > 1:
                cred_key = f"password:{user_key}"
                if cred_key not in seen_creds:
                    seen_creds.add(cred_key)
                    yield Credential(
                        title=f"Password for {domain}\\{username}" if domain else f"Password for {username}",
                        credential_type="password",
                        username=username,
                        domain=domain,
                        value=password,
                        severity="critical",
                        affected_asset_id=host.id if host else None,
                        source="mimikatz",
                        tags=["cleartext", "sekurlsa"],
                    )

            if ntlm and ntlm != "31d6cfe0d16ae931b73c59d7e0c089c0":
                cred_key = f"ntlm:{user_key}:{ntlm}"
                if cred_key not in seen_creds:
                    seen_creds.add(cred_key)
                    yield Credential(
                        title=f"NTLM hash for {domain}\\{username}" if domain else f"NTLM hash for {username}",
                        credential_type="ntlm",
                        username=username,
                        domain=domain,
                        value=ntlm,
                        ntlm_hash=ntlm,
                        severity="high",
                        affected_asset_id=host.id if host else None,
                        source="mimikatz",
                        tags=["sekurlsa"],
                    )

    def _parse_lsadump(self, content: str, host: Host | None) -> Generator[Entity, None, None]:
        """Parse lsadump::sam output."""
        seen_creds: set[str] = set()

        for match in self.SAM_PATTERN.finditer(content):
            username = match.group("username")
            ntlm = match.group("ntlm")

            if ntlm == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            cred_key = f"sam:{username}:{ntlm}"
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)

                user = User(
                    username=username,
                    source="mimikatz",
                    tags=["local-account"],
                )
                yield user

                yield Credential(
                    title=f"SAM hash for {username}",
                    credential_type="ntlm",
                    username=username,
                    value=ntlm,
                    ntlm_hash=ntlm,
                    severity="high",
                    affected_asset_id=host.id if host else None,
                    source="mimikatz",
                    tags=["lsadump", "sam"],
                )

    def _parse_dcsync(self, content: str, host: Host | None) -> Generator[Entity, None, None]:
        """Parse lsadump::dcsync output."""
        seen_creds: set[str] = set()

        for match in self.DCSYNC_PATTERN.finditer(content):
            username = match.group("username")
            ntlm = match.group("ntlm")

            if ntlm == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            cred_key = f"dcsync:{username}:{ntlm}"
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)

                user = User(
                    username=username,
                    source="mimikatz",
                    tags=["dcsync"],
                )
                yield user

                yield Credential(
                    title=f"DCSync hash for {username}",
                    credential_type="ntlm",
                    username=username,
                    value=ntlm,
                    ntlm_hash=ntlm,
                    severity="critical",
                    affected_asset_id=host.id if host else None,
                    source="mimikatz",
                    tags=["dcsync"],
                )

    def _parse_dpapi(self, content: str, host: Host | None) -> Generator[Entity, None, None]:
        """Parse DPAPI masterkey output."""
        for match in self.DPAPI_MASTERKEY_PATTERN.finditer(content):
            guid = match.group("guid")
            key = match.group("key")

            yield Credential(
                title=f"DPAPI MasterKey: {guid}",
                credential_type="dpapi",
                value=key[:64] + "..." if len(key) > 64 else key,
                severity="high",
                affected_asset_id=host.id if host else None,
                source="mimikatz",
                tags=["dpapi"],
                raw_data={"guid": guid},
            )

    def _parse_simple_creds(self, content: str, host: Host | None) -> Generator[Entity, None, None]:
        """Parse simple credential patterns that might be missed."""
        lines = content.split("\n")
        seen_creds: set[str] = set()

        i = 0
        while i < len(lines):
            line = lines[i]

            if "* Username :" in line or "User Name :" in line:
                username = line.split(":", 1)[1].strip()
                domain = None
                ntlm = None
                password = None

                for j in range(i+1, min(i+10, len(lines))):
                    next_line = lines[j]
                    if "Domain :" in next_line:
                        domain = next_line.split(":", 1)[1].strip()
                    elif "NTLM :" in next_line or "* NTLM :" in next_line:
                        ntlm_match = re.search(r"([a-fA-F0-9]{32})", next_line)
                        if ntlm_match:
                            ntlm = ntlm_match.group(1)
                    elif "Password :" in next_line or "* Password :" in next_line:
                        password = next_line.split(":", 1)[1].strip()
                        if password.lower() in ["(null)", ""]:
                            password = None
                    elif "* Username :" in next_line or "Authentication Id" in next_line:
                        break

                if username and username.lower() not in ["(null)", ""]:
                    user_key = f"{domain}\\{username}".lower() if domain else username.lower()

                    if ntlm and ntlm != "31d6cfe0d16ae931b73c59d7e0c089c0":
                        cred_key = f"simple_ntlm:{user_key}:{ntlm}"
                        if cred_key not in seen_creds:
                            seen_creds.add(cred_key)
                            yield Credential(
                                title=f"NTLM for {domain}\\{username}" if domain else f"NTLM for {username}",
                                credential_type="ntlm",
                                username=username,
                                domain=domain if domain and domain.lower() != "(null)" else None,
                                value=ntlm,
                                ntlm_hash=ntlm,
                                severity="high",
                                affected_asset_id=host.id if host else None,
                                source="mimikatz",
                            )

                    if password:
                        cred_key = f"simple_pass:{user_key}"
                        if cred_key not in seen_creds:
                            seen_creds.add(cred_key)
                            yield Credential(
                                title=f"Password for {domain}\\{username}" if domain else f"Password for {username}",
                                credential_type="password",
                                username=username,
                                domain=domain if domain and domain.lower() != "(null)" else None,
                                value=password,
                                severity="critical",
                                affected_asset_id=host.id if host else None,
                                source="mimikatz",
                            )

            i += 1

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Mimikatz output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if any(x in file_path.name.lower() for x in ["mimikatz", "sekurlsa", "lsadump"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"mimikatz",
                    b"sekurlsa",
                    b"lsadump",
                    b"Authentication Id",
                    b"Session           :",
                    b"User Name         :",
                    b"* Username :",
                    b"* NTLM     :",
                    b"* Password :",
                    b"wdigest :",
                    b"kerberos :",
                    b"credman :",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
