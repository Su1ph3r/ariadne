"""rpcclient RPC enumeration output parser."""

import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class RpcclientParser(BaseParser):
    """Parser for rpcclient RPC enumeration output."""

    name = "rpcclient"
    description = "Parse rpcclient RPC/SMB enumeration output"
    file_patterns = ["*rpcclient*.txt", "*rpcclient*.log", "*rpc_enum*.txt"]
    entity_types = ["Host", "User", "Misconfiguration"]

    USER_PATTERN = re.compile(
        r"user:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]",
        re.IGNORECASE
    )

    GROUP_PATTERN = re.compile(
        r"group:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]",
        re.IGNORECASE
    )

    DOMAIN_PATTERN = re.compile(
        r"Domain Name:\s*(\S+)|"
        r"Domain:\s*(\S+)|"
        r"Netbios domain:\s*(\S+)",
        re.IGNORECASE
    )

    SID_PATTERN = re.compile(
        r"Domain SID:\s*(S-\d+-\d+(?:-\d+)+)",
        re.IGNORECASE
    )

    QUERYUSER_PATTERN = re.compile(
        r"User Name\s*:\s*(?P<username>\S+).*?"
        r"(?:Full Name\s*:\s*(?P<fullname>[^\n]*))?.*?"
        r"(?:Description\s*:\s*(?P<desc>[^\n]*))?.*?"
        r"(?:Acct Flags\s*:\s*(?P<flags>[^\n]*))?",
        re.DOTALL | re.IGNORECASE
    )

    PRIV_GROUPS = [
        "domain admins", "enterprise admins", "administrators",
        "schema admins", "account operators", "backup operators",
    ]

    PASSWORD_POLICY_PATTERN = re.compile(
        r"(?:min_password_length|Minimum password length):\s*(\d+)|"
        r"(?:password_history|Password history length):\s*(\d+)|"
        r"(?:lockout_threshold|Account lockout threshold):\s*(\d+)",
        re.IGNORECASE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an rpcclient output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        domain = self._extract_domain(content)

        yield from self._parse_users(content, domain)
        yield from self._parse_groups(content, domain)
        yield from self._parse_password_policy(content)
        yield from self._parse_queryuser(content, domain)

    def _extract_domain(self, content: str) -> str | None:
        """Extract domain name from output."""
        match = self.DOMAIN_PATTERN.search(content)
        if match:
            return match.group(1) or match.group(2) or match.group(3)
        return None

    def _parse_users(self, content: str, domain: str | None) -> Generator[Entity, None, None]:
        """Parse enumerated users."""
        seen_users: set[str] = set()

        for match in self.USER_PATTERN.finditer(content):
            username = match.group(1)
            rid = match.group(2)

            if username.lower() in seen_users:
                continue
            seen_users.add(username.lower())

            rid_int = int(rid, 16)
            is_admin = rid_int == 500

            user = User(
                username=username,
                domain=domain,
                is_admin=is_admin,
                source="rpcclient",
                raw_properties={"rid": rid_int},
            )
            yield user

    def _parse_groups(self, content: str, domain: str | None) -> Generator[Entity, None, None]:
        """Parse enumerated groups and check for interesting memberships."""
        for match in self.GROUP_PATTERN.finditer(content):
            group_name = match.group(1)

            if group_name.lower() in self.PRIV_GROUPS:
                yield Misconfiguration(
                    title=f"Privileged group enumerated: {group_name}",
                    description=f"Privileged group {group_name} was successfully enumerated via RPC",
                    severity="info",
                    source="rpcclient",
                    check_id=f"group_enum_{group_name}",
                    tags=["enumeration"],
                )

    def _parse_password_policy(self, content: str) -> Generator[Entity, None, None]:
        """Parse password policy information."""
        min_length_match = re.search(r"(?:min_password_length|Minimum password length):\s*(\d+)", content, re.IGNORECASE)
        if min_length_match:
            min_length = int(min_length_match.group(1))
            if min_length < 8:
                yield Misconfiguration(
                    title=f"Weak minimum password length: {min_length}",
                    description=f"Domain password policy requires only {min_length} characters",
                    severity="medium",
                    source="rpcclient",
                    check_id="weak_min_password",
                )

        lockout_match = re.search(r"(?:lockout_threshold|Account lockout threshold):\s*(\d+)", content, re.IGNORECASE)
        if lockout_match:
            threshold = int(lockout_match.group(1))
            if threshold == 0:
                yield Misconfiguration(
                    title="No account lockout policy",
                    description="Account lockout is disabled, allowing unlimited password attempts",
                    severity="medium",
                    source="rpcclient",
                    check_id="no_lockout",
                )

        complexity_match = re.search(r"(?:password_properties|Password properties):\s*(\S+)", content, re.IGNORECASE)
        if complexity_match:
            props = complexity_match.group(1)
            if "DOMAIN_PASSWORD_COMPLEX" not in props.upper():
                yield Misconfiguration(
                    title="Password complexity not enforced",
                    description="Domain password policy does not require complexity",
                    severity="medium",
                    source="rpcclient",
                    check_id="no_complexity",
                )

    def _parse_queryuser(self, content: str, domain: str | None) -> Generator[Entity, None, None]:
        """Parse detailed user query results."""
        seen_users: set[str] = set()

        for match in self.QUERYUSER_PATTERN.finditer(content):
            username = match.group("username")
            if not username or username.lower() in seen_users:
                continue
            seen_users.add(username.lower())

            fullname = match.group("fullname") or ""
            description = match.group("desc") or ""
            flags = match.group("flags") or ""

            is_admin = "500" in flags or "Administrator" in fullname

            enabled = "ACCOUNTDISABLE" not in flags.upper() if flags else True
            pwd_never_expires = "DONT_EXPIRE_PASSWORD" in flags.upper() if flags else False

            user = User(
                username=username,
                domain=domain,
                display_name=fullname.strip() if fullname else None,
                enabled=enabled,
                is_admin=is_admin,
                password_never_expires=pwd_never_expires,
                source="rpcclient",
            )
            yield user

            if "PASSWD_NOTREQD" in flags.upper():
                yield Misconfiguration(
                    title=f"Password not required: {username}",
                    description=f"User {username} has PASSWD_NOTREQD flag",
                    severity="high",
                    affected_asset_id=user.id,
                    source="rpcclient",
                    check_id="passwd_notreqd",
                )

            if "DONT_REQ_PREAUTH" in flags.upper():
                yield Misconfiguration(
                    title=f"AS-REP Roastable: {username}",
                    description=f"User {username} does not require pre-authentication",
                    severity="high",
                    affected_asset_id=user.id,
                    source="rpcclient",
                    check_id="asreproast",
                    tags=["asreproast"],
                )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an rpcclient output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ""]:
            return False

        if "rpcclient" in file_path.name.lower() or "rpc_enum" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"rpcclient",
                    b"user:[",
                    b"group:[",
                    b"rid:[0x",
                    b"Domain Name:",
                    b"Domain SID:",
                    b"queryuser",
                    b"enumdomusers",
                    b"enumdomgroups",
                    b"Acct Flags",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
