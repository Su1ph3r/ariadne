"""windapsearch LDAP enumeration output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class WindapsearchParser(BaseParser):
    """Parser for windapsearch LDAP enumeration output."""

    name = "windapsearch"
    description = "Parse windapsearch LDAP enumeration output"
    file_patterns = ["*windapsearch*.txt", "*windapsearch*.json", "*ldap_enum*.txt"]
    entity_types = ["Host", "User", "Misconfiguration"]

    PRIVILEGED_GROUPS = [
        "domain admins", "enterprise admins", "schema admins",
        "administrators", "account operators", "backup operators",
        "dnsadmins", "server operators",
    ]

    USER_PATTERN = re.compile(
        r"(?:dn|DN):\s*(?:CN=)?(?P<name>[^,]+),.*?"
        r"(?:sAMAccountName|samaccountname):\s*(?P<sam>[^\n]+)",
        re.DOTALL | re.IGNORECASE
    )

    COMPUTER_PATTERN = re.compile(
        r"(?:dn|DN):\s*CN=(?P<name>[^,]+),.*?OU=(?:Computers|Domain Controllers)",
        re.IGNORECASE
    )

    SPN_PATTERN = re.compile(
        r"servicePrincipalName:\s*(?P<spn>[^\n]+)",
        re.IGNORECASE
    )

    ADMIN_PATTERN = re.compile(
        r"(?:memberOf|member):\s*CN=(?P<group>[^,]+)",
        re.IGNORECASE
    )

    UAC_PATTERN = re.compile(
        r"userAccountControl:\s*(?P<uac>\d+)",
        re.IGNORECASE
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a windapsearch output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse windapsearch JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]

        for entry in entries:
            yield from self._parse_ldap_entry(entry)

    def _parse_ldap_entry(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a single LDAP entry from JSON."""
        dn = entry.get("dn") or entry.get("distinguishedName") or ""
        object_class = entry.get("objectClass", [])

        if isinstance(object_class, str):
            object_class = [object_class]

        sam = entry.get("sAMAccountName") or entry.get("samaccountname") or ""

        if "user" in [oc.lower() for oc in object_class] or "person" in [oc.lower() for oc in object_class]:
            yield from self._parse_user_entry(entry, sam)
        elif "computer" in [oc.lower() for oc in object_class]:
            yield from self._parse_computer_entry(entry, sam)

    def _parse_user_entry(self, entry: dict, sam: str) -> Generator[Entity, None, None]:
        """Parse a user LDAP entry."""
        if not sam:
            return

        domain = self._extract_domain(entry.get("distinguishedName", ""))

        uac = int(entry.get("userAccountControl", 0))
        enabled = not (uac & 0x0002)
        pwd_never_expires = bool(uac & 0x10000)
        pwd_not_required = bool(uac & 0x0020)
        dont_req_preauth = bool(uac & 0x400000)

        member_of = entry.get("memberOf", [])
        if isinstance(member_of, str):
            member_of = [member_of]

        is_admin = any(
            priv in group.lower()
            for group in member_of
            for priv in self.PRIVILEGED_GROUPS
        )

        user = User(
            username=sam,
            domain=domain,
            display_name=entry.get("displayName") or entry.get("cn"),
            email=entry.get("mail"),
            enabled=enabled,
            is_admin=is_admin,
            password_never_expires=pwd_never_expires,
            groups=[self._extract_cn(g) for g in member_of],
            source="windapsearch",
        )
        yield user

        if pwd_not_required:
            yield Misconfiguration(
                title=f"Password not required: {sam}",
                description=f"User {sam} has PASSWD_NOTREQD flag",
                severity="high",
                affected_asset_id=user.id,
                source="windapsearch",
                check_id="passwd_notreqd",
            )

        if dont_req_preauth:
            yield Misconfiguration(
                title=f"AS-REP Roastable: {sam}",
                description=f"User {sam} does not require Kerberos pre-authentication",
                severity="high",
                affected_asset_id=user.id,
                source="windapsearch",
                check_id="asreproast",
                tags=["asreproast"],
            )

        spns = entry.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        if spns and enabled:
            yield Misconfiguration(
                title=f"Kerberoastable: {sam}",
                description=f"User {sam} has SPNs: {', '.join(spns[:3])}",
                severity="medium",
                affected_asset_id=user.id,
                source="windapsearch",
                check_id="kerberoast",
                tags=["kerberoast"],
            )

    def _parse_computer_entry(self, entry: dict, sam: str) -> Generator[Entity, None, None]:
        """Parse a computer LDAP entry."""
        hostname = (sam or entry.get("cn", "")).rstrip("$")
        if not hostname:
            return

        domain = self._extract_domain(entry.get("distinguishedName", ""))
        os_info = entry.get("operatingSystem")
        os_version = entry.get("operatingSystemVersion")
        if os_info and os_version:
            os_info = f"{os_info} {os_version}"

        uac = int(entry.get("userAccountControl", 0))
        enabled = not (uac & 0x0002)
        trusted_for_delegation = bool(uac & 0x80000)

        is_dc = "Domain Controllers" in entry.get("distinguishedName", "")

        host = Host(
            ip="",
            hostname=hostname,
            domain=domain,
            os=os_info,
            enabled=enabled,
            is_dc=is_dc,
            source="windapsearch",
        )
        yield host

        if trusted_for_delegation:
            yield Misconfiguration(
                title=f"Unconstrained Delegation: {hostname}",
                description=f"Computer {hostname} is trusted for unconstrained delegation",
                severity="critical",
                affected_asset_id=host.id,
                source="windapsearch",
                check_id="unconstrained_delegation",
                tags=["delegation"],
            )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse windapsearch text output."""
        entries = re.split(r"\n\s*\n", content)
        seen_users: set[str] = set()
        seen_hosts: set[str] = set()

        for entry in entries:
            if not entry.strip():
                continue

            dn_match = re.search(r"(?:dn|DN):\s*(.+)", entry)
            sam_match = re.search(r"(?:sAMAccountName|samaccountname):\s*(\S+)", entry)

            if sam_match:
                sam = sam_match.group(1)

                if "OU=Domain Controllers" in entry or sam.endswith("$"):
                    hostname = sam.rstrip("$")
                    if hostname.lower() not in seen_hosts:
                        seen_hosts.add(hostname.lower())

                        host = Host(
                            ip="",
                            hostname=hostname,
                            is_dc="Domain Controllers" in entry,
                            source="windapsearch",
                        )
                        yield host

                        if "TRUSTED_FOR_DELEGATION" in entry or re.search(r"userAccountControl.*524288", entry):
                            yield Misconfiguration(
                                title=f"Unconstrained Delegation: {hostname}",
                                description=f"Computer {hostname} is trusted for unconstrained delegation",
                                severity="critical",
                                affected_asset_id=host.id,
                                source="windapsearch",
                                check_id="unconstrained_delegation",
                            )
                else:
                    if sam.lower() not in seen_users:
                        seen_users.add(sam.lower())

                        is_admin = bool(self.ADMIN_PATTERN.search(entry) and
                                       any(priv in entry.lower() for priv in self.PRIVILEGED_GROUPS))

                        user = User(
                            username=sam,
                            is_admin=is_admin,
                            source="windapsearch",
                        )
                        yield user

                        spn_match = self.SPN_PATTERN.search(entry)
                        if spn_match:
                            yield Misconfiguration(
                                title=f"Kerberoastable: {sam}",
                                description=f"User has SPN: {spn_match.group('spn')}",
                                severity="medium",
                                affected_asset_id=user.id,
                                source="windapsearch",
                                check_id="kerberoast",
                            )

                        uac_match = self.UAC_PATTERN.search(entry)
                        if uac_match:
                            uac = int(uac_match.group("uac"))
                            if uac & 0x400000:
                                yield Misconfiguration(
                                    title=f"AS-REP Roastable: {sam}",
                                    description=f"User does not require pre-authentication",
                                    severity="high",
                                    affected_asset_id=user.id,
                                    source="windapsearch",
                                    check_id="asreproast",
                                )

    def _extract_domain(self, dn: str) -> str | None:
        """Extract domain from DN."""
        dc_parts = re.findall(r"DC=([^,]+)", dn, re.IGNORECASE)
        return ".".join(dc_parts) if dc_parts else None

    def _extract_cn(self, dn: str) -> str:
        """Extract CN from DN."""
        match = re.search(r"CN=([^,]+)", dn, re.IGNORECASE)
        return match.group(1) if match else dn

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a windapsearch output file."""
        if "windapsearch" in file_path.name.lower() or "ldap_enum" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"windapsearch",
                    b"sAMAccountName",
                    b"distinguishedName",
                    b"userAccountControl",
                    b"servicePrincipalName",
                    b"memberOf",
                    b"dn: CN=",
                    b"dn:CN=",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
