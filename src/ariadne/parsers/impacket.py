"""Impacket tool output parser (secretsdump, GetUserSPNs, etc.)."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class ImpacketParser(BaseParser):
    """Parser for Impacket tool text output files."""

    name = "impacket"
    description = "Parse Impacket secretsdump/GetUserSPNs/GetNPUsers output"
    file_patterns = ["*secretsdump*.txt", "*getuserspns*.txt", "*getnpusers*.txt", "*impacket*.txt"]
    entity_types = ["Host", "User", "Credential"]

    NTLM_PATTERN = re.compile(
        r"^(?P<domain>[^\\:]+)?\\?(?P<username>[^:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<ntlm>[a-fA-F0-9]{32}):::",
        re.MULTILINE
    )

    KERBEROAST_PATTERN = re.compile(
        r"\$krb5tgs\$\d+\$\*?(?P<username>[^$*]+)\$(?P<domain>[^$]+)\$[^$]+\$(?P<hash>[a-fA-F0-9$]+)",
        re.MULTILINE
    )

    ASREPROAST_PATTERN = re.compile(
        r"\$krb5asrep\$\d+\$(?P<username>[^@$]+)@(?P<domain>[^$:]+):(?P<hash>[a-fA-F0-9$]+)",
        re.MULTILINE
    )

    DPAPI_PATTERN = re.compile(
        r"\[(?P<keytype>dpapi_machinekey|dpapi_userkey)\]\s*(?P<guid>[a-fA-F0-9-]+)\s*:\s*(?P<key>[a-fA-F0-9]+)",
        re.MULTILINE | re.IGNORECASE
    )

    CLEARTEXT_PATTERN = re.compile(
        r"(?P<domain>[^\\:]+)?\\?(?P<username>[^:]+):CLEARTEXT:(?P<password>.+)",
        re.MULTILINE
    )

    LSA_SECRET_PATTERN = re.compile(
        r"\[(?P<secret_name>[^\]]+)\]\s*(?P<domain>[^\\:]+)?\\?(?P<username>[^:]+)?:(?P<value>.+)",
        re.MULTILINE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an Impacket output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        target_host = self._extract_target(content, file_path.name)
        host = None
        if target_host:
            host = Host(
                ip=target_host if self._is_ip(target_host) else "",
                hostname=target_host if not self._is_ip(target_host) else None,
                source="impacket",
            )
            yield host

        yield from self._parse_ntlm_hashes(content, host.id if host else None)
        yield from self._parse_kerberoast(content, host.id if host else None)
        yield from self._parse_asreproast(content, host.id if host else None)
        yield from self._parse_cleartext(content, host.id if host else None)
        yield from self._parse_dpapi(content, host.id if host else None)

    def _extract_target(self, content: str, filename: str) -> str | None:
        """Extract target host from content or filename."""
        target_pattern = re.search(r"Target:\s*([^\s\n]+)", content)
        if target_pattern:
            return target_pattern.group(1)

        connect_pattern = re.search(r"Connecting to\s+([^\s\n:]+)", content)
        if connect_pattern:
            return connect_pattern.group(1)

        ip_pattern = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", filename)
        if ip_pattern:
            return ip_pattern.group(1)

        return None

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))

    def _parse_ntlm_hashes(self, content: str, host_id: str | None) -> Generator[Entity, None, None]:
        """Parse NTLM hash dumps from secretsdump."""
        seen_users: set[str] = set()

        for match in self.NTLM_PATTERN.finditer(content):
            domain = match.group("domain") or ""
            username = match.group("username")
            ntlm_hash = match.group("ntlm")
            lm_hash = match.group("lm")

            user_key = f"{domain}\\{username}".lower()
            if user_key in seen_users:
                continue
            seen_users.add(user_key)

            if ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            user = User(
                username=username,
                domain=domain if domain else None,
                source="impacket",
            )
            yield user

            yield Credential(
                title=f"NTLM hash for {domain}\\{username}" if domain else f"NTLM hash for {username}",
                credential_type="ntlm",
                username=username,
                domain=domain if domain else None,
                value=ntlm_hash,
                ntlm_hash=ntlm_hash,
                severity="high",
                affected_asset_id=host_id,
                source="impacket",
                raw_data={"lm_hash": lm_hash, "rid": match.group("rid")},
            )

    def _parse_kerberoast(self, content: str, host_id: str | None) -> Generator[Entity, None, None]:
        """Parse Kerberoastable service account hashes."""
        for match in self.KERBEROAST_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain")
            hash_value = match.group("hash")

            user = User(
                username=username,
                domain=domain,
                source="impacket",
                tags=["kerberoastable", "service-account"],
            )
            yield user

            yield Credential(
                title=f"Kerberos TGS hash for {domain}\\{username}",
                credential_type="kerberos",
                username=username,
                domain=domain,
                value=f"$krb5tgs${username}${domain}${hash_value[:50]}...",
                severity="high",
                affected_asset_id=host_id,
                source="impacket",
                tags=["kerberoast"],
            )

    def _parse_asreproast(self, content: str, host_id: str | None) -> Generator[Entity, None, None]:
        """Parse AS-REP roastable account hashes."""
        for match in self.ASREPROAST_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain")
            hash_value = match.group("hash")

            user = User(
                username=username,
                domain=domain,
                source="impacket",
                tags=["asreproastable", "no-preauth"],
            )
            yield user

            yield Credential(
                title=f"AS-REP hash for {username}@{domain}",
                credential_type="kerberos",
                username=username,
                domain=domain,
                value=f"$krb5asrep${username}@{domain}:{hash_value[:50]}...",
                severity="high",
                affected_asset_id=host_id,
                source="impacket",
                tags=["asreproast"],
            )

    def _parse_cleartext(self, content: str, host_id: str | None) -> Generator[Entity, None, None]:
        """Parse cleartext passwords."""
        for match in self.CLEARTEXT_PATTERN.finditer(content):
            domain = match.group("domain") or ""
            username = match.group("username")
            password = match.group("password").strip()

            if not password or password in ["(null)", ""]:
                continue

            user = User(
                username=username,
                domain=domain if domain else None,
                source="impacket",
            )
            yield user

            yield Credential(
                title=f"Cleartext password for {domain}\\{username}" if domain else f"Cleartext password for {username}",
                credential_type="password",
                username=username,
                domain=domain if domain else None,
                value=password,
                severity="critical",
                affected_asset_id=host_id,
                source="impacket",
            )

    def _parse_dpapi(self, content: str, host_id: str | None) -> Generator[Entity, None, None]:
        """Parse DPAPI keys."""
        for match in self.DPAPI_PATTERN.finditer(content):
            key_type = match.group("keytype")
            guid = match.group("guid")
            key = match.group("key")

            yield Credential(
                title=f"DPAPI {key_type}: {guid}",
                credential_type="dpapi",
                value=key,
                severity="medium",
                affected_asset_id=host_id,
                source="impacket",
                raw_data={"guid": guid, "key_type": key_type},
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an Impacket output file."""
        if file_path.suffix.lower() != ".txt":
            return False

        try:
            with open(file_path, "rb") as f:
                content = f.read(5000)
                indicators = [
                    b"Impacket",
                    b"secretsdump",
                    b"GetUserSPNs",
                    b"GetNPUsers",
                    b"[*] Dumping",
                    b"[*] Service",
                    b"$krb5tgs$",
                    b"$krb5asrep$",
                    rb":\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::",
                ]
                content_str = content.decode(errors="ignore")
                if re.search(r":\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", content_str):
                    return True
                return any(ind in content for ind in indicators[:-1])
        except Exception:
            return False
