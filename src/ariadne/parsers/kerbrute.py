"""Kerbrute Kerberos enumeration output parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class KerbruteParser(BaseParser):
    """Parser for Kerbrute Kerberos user enumeration and password spraying output."""

    name = "kerbrute"
    description = "Parse Kerbrute Kerberos enumeration and password spray output"
    file_patterns = ["*kerbrute*.txt", "*kerbrute*.log"]
    entity_types = ["Host", "User", "Credential", "Misconfiguration"]

    VALID_USER_PATTERN = re.compile(
        r"(?:\[\+\]|VALID\s*(?:USERNAME|USER)?)\s*[:>]?\s*(?:(?P<domain>[^\\@\s]+)[\\@])?(?P<username>\S+)",
        re.IGNORECASE
    )

    VALID_CRED_PATTERN = re.compile(
        r"(?:\[\+\]|VALID\s*(?:LOGIN|CRED(?:ENTIAL)?)?|SUCCESS)\s*[:>]?\s*"
        r"(?:(?P<domain>[^\\@\s]+)[\\@])?(?P<username>[^:@\s]+)"
        r"(?:[:@](?P<password>\S+))?",
        re.IGNORECASE
    )

    ASREP_PATTERN = re.compile(
        r"(?:\[\+\]|NO\s*PREAUTH|ASREP)\s*[:>]?\s*(?:(?P<domain>[^\\@\s]+)[\\@])?(?P<username>\S+)",
        re.IGNORECASE
    )

    HASH_PATTERN = re.compile(
        r"\$krb5asrep\$(?P<etype>\d+)?\$?(?P<username>[^@$]+)@(?P<domain>[^$:]+):(?P<hash>[a-fA-F0-9$]+)"
    )

    DC_PATTERN = re.compile(
        r"(?:Domain\s*Controller|DC|Target|KDC)\s*[:=]\s*(?P<dc>\S+)",
        re.IGNORECASE
    )

    DOMAIN_PATTERN = re.compile(
        r"(?:Domain|Realm)\s*[:=]\s*(?P<domain>\S+)",
        re.IGNORECASE
    )

    LOCKED_PATTERN = re.compile(
        r"(?:LOCKED|DISABLED|ACCOUNT.*LOCKED)\s*[:>]?\s*(?:(?P<domain>[^\\@\s]+)[\\@])?(?P<username>\S+)",
        re.IGNORECASE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Kerbrute output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        host = self._parse_target_dc(content)
        if host:
            yield host

        default_domain = self._extract_default_domain(content)

        yield from self._parse_valid_users(content, default_domain, host)
        yield from self._parse_valid_creds(content, default_domain, host)
        yield from self._parse_asrep_users(content, default_domain, host)
        yield from self._parse_locked_accounts(content, default_domain, host)

    def _parse_target_dc(self, content: str) -> Host | None:
        """Extract domain controller information."""
        dc_match = self.DC_PATTERN.search(content)
        if dc_match:
            dc = dc_match.group("dc")
            is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", dc))

            return Host(
                ip=dc if is_ip else "",
                hostname=dc if not is_ip else None,
                source="kerbrute",
                tags=["domain-controller", "kdc"],
            )
        return None

    def _extract_default_domain(self, content: str) -> str | None:
        """Extract default domain from output."""
        domain_match = self.DOMAIN_PATTERN.search(content)
        if domain_match:
            return domain_match.group("domain")

        for line in content.split("\n")[:20]:
            if "@" in line:
                parts = re.findall(r"@([^\s:@]+)", line)
                if parts:
                    return parts[0]
        return None

    def _parse_valid_users(self, content: str, default_domain: str | None, host: Host | None) -> Generator[Entity, None, None]:
        """Parse valid usernames from enumeration."""
        seen_users: set[str] = set()

        for match in self.VALID_USER_PATTERN.finditer(content):
            if "LOGIN" in content[max(0, match.start()-20):match.start()].upper():
                continue

            username = match.group("username")
            domain = match.group("domain") or default_domain

            if not username or username.lower() in ["username", "user"]:
                continue

            user_key = f"{domain}\\{username}".lower() if domain else username.lower()
            if user_key in seen_users:
                continue
            seen_users.add(user_key)

            user = User(
                username=username,
                domain=domain,
                source="kerbrute",
                tags=["valid-user", "kerb-enumerated"],
            )
            yield user

    def _parse_valid_creds(self, content: str, default_domain: str | None, host: Host | None) -> Generator[Entity, None, None]:
        """Parse valid credentials from password spraying."""
        seen_creds: set[str] = set()

        patterns = [
            re.compile(r"\[\+\]\s*VALID\s*LOGIN\s*:\s*(?P<domain>[^\\@]+)?[\\@]?(?P<username>[^:@\s]+)(?:[:@](?P<password>\S+))?", re.IGNORECASE),
            re.compile(r"SUCCESS\s*[:>]\s*(?P<username>\S+)@(?P<domain>\S+)\s*[:with]*\s*(?P<password>\S+)?", re.IGNORECASE),
        ]

        for pattern in patterns:
            for match in pattern.finditer(content):
                username = match.group("username")
                domain = match.groupdict().get("domain") or default_domain
                password = match.groupdict().get("password")

                if not username:
                    continue

                user_key = f"{domain}\\{username}".lower() if domain else username.lower()
                cred_key = f"{user_key}:{password}" if password else user_key

                if cred_key in seen_creds:
                    continue
                seen_creds.add(cred_key)

                user = User(
                    username=username,
                    domain=domain,
                    source="kerbrute",
                    tags=["valid-creds"],
                )
                yield user

                if password:
                    yield Credential(
                        title=f"Valid credential for {domain}\\{username}" if domain else f"Valid credential for {username}",
                        credential_type="password",
                        username=username,
                        domain=domain,
                        value=password,
                        severity="critical",
                        affected_asset_id=host.id if host else None,
                        source="kerbrute",
                        tags=["password-spray"],
                    )

    def _parse_asrep_users(self, content: str, default_domain: str | None, host: Host | None) -> Generator[Entity, None, None]:
        """Parse AS-REP roastable users."""
        seen_users: set[str] = set()

        for match in self.HASH_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain") or default_domain
            hash_value = match.group(0)

            user_key = f"{domain}\\{username}".lower()
            if user_key in seen_users:
                continue
            seen_users.add(user_key)

            user = User(
                username=username,
                domain=domain,
                source="kerbrute",
                tags=["asreproastable", "no-preauth"],
            )
            yield user

            yield Misconfiguration(
                title=f"AS-REP Roastable: {domain}\\{username}",
                description=f"User {username}@{domain} does not require Kerberos pre-authentication",
                severity="high",
                affected_asset_id=host.id if host else None,
                source="kerbrute",
                check_id="asreproast",
            )

            yield Credential(
                title=f"AS-REP hash for {domain}\\{username}",
                credential_type="kerberos",
                username=username,
                domain=domain,
                value=hash_value,
                severity="high",
                affected_asset_id=host.id if host else None,
                source="kerbrute",
                tags=["asreproast"],
            )

        for match in self.ASREP_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain") or default_domain

            user_key = f"{domain}\\{username}".lower() if domain else username.lower()
            if user_key in seen_users:
                continue
            seen_users.add(user_key)

            user = User(
                username=username,
                domain=domain,
                source="kerbrute",
                tags=["asreproastable", "no-preauth"],
            )
            yield user

            yield Misconfiguration(
                title=f"AS-REP Roastable: {domain}\\{username}" if domain else f"AS-REP Roastable: {username}",
                description=f"User does not require Kerberos pre-authentication",
                severity="high",
                source="kerbrute",
                check_id="asreproast",
            )

    def _parse_locked_accounts(self, content: str, default_domain: str | None, host: Host | None) -> Generator[Entity, None, None]:
        """Parse locked out accounts (useful for avoiding in future sprays)."""
        for match in self.LOCKED_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain") or default_domain

            user = User(
                username=username,
                domain=domain,
                enabled=False,
                source="kerbrute",
                tags=["locked", "disabled"],
            )
            yield user

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Kerbrute output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if "kerbrute" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"kerbrute",
                    b"Kerbrute",
                    b"VALID USERNAME",
                    b"VALID LOGIN",
                    b"userenum",
                    b"passwordspray",
                    b"bruteuser",
                    b"[+] VALID",
                    b"NO PREAUTH",
                    b"$krb5asrep$",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
