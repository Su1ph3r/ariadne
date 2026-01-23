"""Rubeus Kerberos attack tool output parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class RubeusParser(BaseParser):
    """Parser for Rubeus Kerberos attack tool output."""

    name = "rubeus"
    description = "Parse Rubeus Kerberos attack tool output (AS-REP, Kerberoast, tickets)"
    file_patterns = ["*rubeus*.txt", "*rubeus*.log", "*asreproast*.txt", "*kerberoast*.txt"]
    entity_types = ["User", "Credential", "Misconfiguration"]

    ASREP_HASH_PATTERN = re.compile(
        r"\$krb5asrep\$(?P<etype>\d+)?\$?(?P<username>[^@$]+)@(?P<domain>[^$:]+):(?P<hash>[a-fA-F0-9$]+)",
        re.MULTILINE
    )

    TGS_HASH_PATTERN = re.compile(
        r"\$krb5tgs\$(?P<etype>\d+)?\$\*?(?P<username>[^$*]+)\$(?P<domain>[^$]+)\$[^$]*\$(?P<hash>[a-fA-F0-9$]+)",
        re.MULTILINE
    )

    USER_SPN_PATTERN = re.compile(
        r"User\s*:\s*(?P<username>[^\s@]+)(?:@(?P<domain>\S+))?",
        re.IGNORECASE
    )

    SPN_PATTERN = re.compile(
        r"ServicePrincipalName\s*:\s*(?P<spn>\S+)",
        re.IGNORECASE
    )

    TICKET_PATTERN = re.compile(
        r"(?:Base64|base64)(?:EncodedTicket|Ticket)?\s*:\s*(?P<ticket>[A-Za-z0-9+/=]+)",
        re.IGNORECASE
    )

    DELEGATION_PATTERN = re.compile(
        r"(?P<account>[^\s]+)\s+(?:has|is)\s+(?:unconstrained|constrained)\s+delegation",
        re.IGNORECASE
    )

    S4U_PATTERN = re.compile(
        r"S4U2(?:self|proxy)\s+(?:for|to)\s+(?P<target>\S+)",
        re.IGNORECASE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Rubeus output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        yield from self._parse_asrep_hashes(content)
        yield from self._parse_tgs_hashes(content)
        yield from self._parse_kerberoast_section(content)
        yield from self._parse_delegation(content)
        yield from self._parse_tickets(content)

    def _parse_asrep_hashes(self, content: str) -> Generator[Entity, None, None]:
        """Parse AS-REP roastable hashes."""
        seen_users: set[str] = set()

        for match in self.ASREP_HASH_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain")
            hash_value = match.group(0)
            etype = match.group("etype") or "23"

            user_key = f"{domain}\\{username}".lower()
            if user_key in seen_users:
                continue
            seen_users.add(user_key)

            user = User(
                username=username,
                domain=domain,
                source="rubeus",
                tags=["asreproastable", "no-preauth"],
            )
            yield user

            yield Misconfiguration(
                title=f"AS-REP Roastable: {domain}\\{username}",
                description=f"User {username}@{domain} does not require Kerberos pre-authentication",
                severity="high",
                affected_asset_id=user.id,
                source="rubeus",
                check_id="asreproast",
                tags=["asreproast"],
            )

            yield Credential(
                title=f"AS-REP hash for {domain}\\{username}",
                credential_type="kerberos",
                username=username,
                domain=domain,
                value=hash_value,
                hash_type=f"krb5asrep_etype{etype}",
                severity="high",
                source="rubeus",
                tags=["asreproast"],
            )

    def _parse_tgs_hashes(self, content: str) -> Generator[Entity, None, None]:
        """Parse Kerberoast TGS hashes."""
        seen_users: set[str] = set()

        for match in self.TGS_HASH_PATTERN.finditer(content):
            username = match.group("username")
            domain = match.group("domain")
            hash_value = match.group(0)
            etype = match.group("etype") or "23"

            user_key = f"{domain}\\{username}".lower()
            if user_key in seen_users:
                continue
            seen_users.add(user_key)

            user = User(
                username=username,
                domain=domain,
                source="rubeus",
                tags=["kerberoastable", "service-account"],
            )
            yield user

            yield Misconfiguration(
                title=f"Kerberoastable: {domain}\\{username}",
                description=f"Service account {username}@{domain} has an SPN set and can be Kerberoasted",
                severity="medium",
                affected_asset_id=user.id,
                source="rubeus",
                check_id="kerberoast",
                tags=["kerberoast"],
            )

            yield Credential(
                title=f"TGS hash for {domain}\\{username}",
                credential_type="kerberos",
                username=username,
                domain=domain,
                value=hash_value[:200] + "...",
                hash_type=f"krb5tgs_etype{etype}",
                severity="high",
                source="rubeus",
                tags=["kerberoast"],
            )

    def _parse_kerberoast_section(self, content: str) -> Generator[Entity, None, None]:
        """Parse structured Kerberoast output sections."""
        current_user: dict[str, str] = {}
        seen_users: set[str] = set()

        for line in content.split("\n"):
            user_match = self.USER_SPN_PATTERN.search(line)
            if user_match:
                current_user = {
                    "username": user_match.group("username"),
                    "domain": user_match.group("domain") or "",
                }

            spn_match = self.SPN_PATTERN.search(line)
            if spn_match and current_user.get("username"):
                current_user["spn"] = spn_match.group("spn")

            if current_user.get("username") and current_user.get("spn"):
                user_key = f"{current_user.get('domain', '')}\\{current_user['username']}".lower()
                if user_key not in seen_users:
                    seen_users.add(user_key)

                    user = User(
                        username=current_user["username"],
                        domain=current_user.get("domain") or None,
                        source="rubeus",
                        tags=["has-spn"],
                        raw_properties={"spn": current_user["spn"]},
                    )
                    yield user

    def _parse_delegation(self, content: str) -> Generator[Entity, None, None]:
        """Parse delegation findings."""
        for match in self.DELEGATION_PATTERN.finditer(content):
            account = match.group("account")
            delegation_type = "unconstrained" if "unconstrained" in match.group(0).lower() else "constrained"

            severity = "critical" if delegation_type == "unconstrained" else "high"

            yield Misconfiguration(
                title=f"{delegation_type.title()} Delegation: {account}",
                description=f"Account {account} has {delegation_type} delegation enabled",
                severity=severity,
                source="rubeus",
                check_id=f"{delegation_type}_delegation",
                tags=["delegation", delegation_type],
            )

        if re.search(r"unconstrained delegation", content, re.IGNORECASE):
            for match in re.finditer(r"(?:samaccountname|account)\s*[:=]\s*(\S+)", content, re.IGNORECASE):
                account = match.group(1)
                if "$" in account:
                    yield Misconfiguration(
                        title=f"Unconstrained Delegation: {account}",
                        description=f"Computer account {account} has unconstrained delegation",
                        severity="critical",
                        source="rubeus",
                        check_id="unconstrained_delegation",
                        tags=["delegation", "unconstrained"],
                    )

    def _parse_tickets(self, content: str) -> Generator[Entity, None, None]:
        """Parse extracted tickets."""
        ticket_count = 0
        for match in self.TICKET_PATTERN.finditer(content):
            ticket_count += 1
            ticket_preview = match.group("ticket")[:100]

            yield Credential(
                title=f"Kerberos Ticket #{ticket_count}",
                credential_type="kerberos_ticket",
                value=ticket_preview + "...",
                severity="high",
                source="rubeus",
                tags=["ticket"],
            )

        for match in self.S4U_PATTERN.finditer(content):
            target = match.group("target")
            yield Misconfiguration(
                title=f"S4U Delegation to {target}",
                description=f"S4U2self/S4U2proxy delegation attack possible to {target}",
                severity="high",
                source="rubeus",
                check_id="s4u_attack",
                tags=["s4u", "delegation"],
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Rubeus output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if any(x in file_path.name.lower() for x in ["rubeus", "asrep", "kerberoast"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"Rubeus",
                    b"$krb5asrep$",
                    b"$krb5tgs$",
                    b"ServicePrincipalName",
                    b"[*] Action:",
                    b"[*] Target User",
                    b"[*] Building AS-REQ",
                    b"[*] Building TGS-REQ",
                    b"Base64EncodedTicket",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
