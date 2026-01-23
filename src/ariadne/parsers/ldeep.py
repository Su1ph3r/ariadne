"""ldeep LDAP enumeration tool output parser."""

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
class LdeepParser(BaseParser):
    """Parser for ldeep LDAP enumeration tool output."""

    name = "ldeep"
    description = "Parse ldeep LDAP deep enumeration output"
    file_patterns = ["*ldeep*.json", "*ldeep*.txt", "ldeep_*"]
    entity_types = ["Host", "User", "Misconfiguration"]

    PRIVILEGED_GROUPS = [
        "domain admins", "enterprise admins", "schema admins",
        "administrators", "account operators", "backup operators",
        "dnsadmins", "server operators",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an ldeep output file and yield entities."""
        content = file_path.read_text(errors="ignore")
        filename = file_path.name.lower()

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content, filename)
        else:
            yield from self._parse_text(content, filename)

    def _parse_json(self, content: str, filename: str) -> Generator[Entity, None, None]:
        """Parse ldeep JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            for line in content.strip().split("\n"):
                if line.strip():
                    try:
                        entry = json.loads(line)
                        yield from self._parse_entry(entry, filename)
                    except json.JSONDecodeError:
                        continue
            return

        if isinstance(data, list):
            for entry in data:
                yield from self._parse_entry(entry, filename)
        elif isinstance(data, dict):
            yield from self._parse_entry(data, filename)

    def _parse_entry(self, entry: dict, filename: str) -> Generator[Entity, None, None]:
        """Parse a single ldeep entry based on content."""
        sam = entry.get("sAMAccountName") or entry.get("samaccountname") or ""
        dn = entry.get("distinguishedName") or entry.get("dn") or ""
        object_class = entry.get("objectClass", [])

        if isinstance(object_class, str):
            object_class = [object_class]

        is_computer = (
            "computer" in [oc.lower() for oc in object_class] or
            sam.endswith("$") or
            "delegation" in filename or
            "computers" in filename
        )

        is_user = (
            "user" in [oc.lower() for oc in object_class] or
            "person" in [oc.lower() for oc in object_class] or
            "users" in filename
        )

        if is_computer:
            yield from self._parse_computer(entry)
        elif is_user or sam:
            yield from self._parse_user(entry)

        if "trusts" in filename:
            yield from self._parse_trust(entry)

        if "delegation" in filename:
            yield from self._parse_delegation(entry)

        if "gmsa" in filename or "gMSA" in str(entry):
            yield from self._parse_gmsa(entry)

        if "laps" in filename or "ms-Mcs-AdmPwd" in str(entry):
            yield from self._parse_laps(entry)

    def _parse_user(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse user entry."""
        sam = entry.get("sAMAccountName") or entry.get("samaccountname")
        if not sam or sam.endswith("$"):
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
            source="ldeep",
        )
        yield user

        if pwd_not_required:
            yield Misconfiguration(
                title=f"Password not required: {sam}",
                description=f"User {sam} has PASSWD_NOTREQD flag",
                severity="high",
                affected_asset_id=user.id,
                source="ldeep",
                check_id="passwd_notreqd",
            )

        if dont_req_preauth:
            yield Misconfiguration(
                title=f"AS-REP Roastable: {sam}",
                description=f"User {sam} does not require Kerberos pre-authentication",
                severity="high",
                affected_asset_id=user.id,
                source="ldeep",
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
                source="ldeep",
                check_id="kerberoast",
                tags=["kerberoast"],
            )

    def _parse_computer(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse computer entry."""
        sam = entry.get("sAMAccountName") or entry.get("samaccountname") or entry.get("cn", "")
        hostname = sam.rstrip("$")
        if not hostname:
            return

        domain = self._extract_domain(entry.get("distinguishedName", ""))
        os_info = entry.get("operatingSystem")
        os_version = entry.get("operatingSystemVersion")
        if os_info and os_version:
            os_info = f"{os_info} {os_version}"

        uac = int(entry.get("userAccountControl", 0))
        trusted_for_delegation = bool(uac & 0x80000)
        trusted_to_auth = bool(uac & 0x1000000)

        is_dc = "Domain Controllers" in entry.get("distinguishedName", "")

        host = Host(
            ip="",
            hostname=hostname,
            domain=domain,
            os=os_info,
            is_dc=is_dc,
            source="ldeep",
        )
        yield host

        if trusted_for_delegation:
            yield Misconfiguration(
                title=f"Unconstrained Delegation: {hostname}",
                description=f"Computer {hostname} is trusted for unconstrained delegation",
                severity="critical",
                affected_asset_id=host.id,
                source="ldeep",
                check_id="unconstrained_delegation",
                tags=["delegation", "unconstrained"],
            )

        if trusted_to_auth:
            allowed_to = entry.get("msDS-AllowedToDelegateTo", [])
            if isinstance(allowed_to, str):
                allowed_to = [allowed_to]

            yield Misconfiguration(
                title=f"Constrained Delegation: {hostname}",
                description=f"Computer {hostname} has constrained delegation to: {', '.join(allowed_to[:5])}",
                severity="high",
                affected_asset_id=host.id,
                source="ldeep",
                check_id="constrained_delegation",
                tags=["delegation", "constrained"],
            )

        rbcd = entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if rbcd:
            yield Misconfiguration(
                title=f"RBCD Configured: {hostname}",
                description=f"Computer {hostname} has Resource-Based Constrained Delegation configured",
                severity="high",
                affected_asset_id=host.id,
                source="ldeep",
                check_id="rbcd",
                tags=["delegation", "rbcd"],
            )

    def _parse_delegation(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse delegation-specific findings."""
        sam = entry.get("sAMAccountName") or entry.get("samaccountname") or ""
        hostname = sam.rstrip("$")

        if not hostname:
            return

        host = Host(
            ip="",
            hostname=hostname,
            source="ldeep",
            tags=["delegation"],
        )
        yield host

        delegation_type = "unknown"
        uac = int(entry.get("userAccountControl", 0))

        if uac & 0x80000:
            delegation_type = "unconstrained"
            severity = "critical"
        elif uac & 0x1000000:
            delegation_type = "constrained"
            severity = "high"
        elif entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            delegation_type = "rbcd"
            severity = "high"
        else:
            return

        yield Misconfiguration(
            title=f"{delegation_type.title()} Delegation: {hostname}",
            description=f"Account {hostname} has {delegation_type} delegation configured",
            severity=severity,
            affected_asset_id=host.id,
            source="ldeep",
            check_id=f"{delegation_type}_delegation",
            tags=["delegation", delegation_type],
        )

    def _parse_trust(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse trust relationship."""
        trust_partner = entry.get("trustPartner") or entry.get("name") or entry.get("cn")
        if not trust_partner:
            return

        host = Host(
            ip="",
            hostname=trust_partner,
            domain=trust_partner,
            source="ldeep",
            tags=["trusted-domain"],
        )
        yield host

    def _parse_gmsa(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse gMSA (Group Managed Service Account)."""
        sam = entry.get("sAMAccountName") or entry.get("samaccountname")
        if not sam:
            return

        principals = entry.get("msDS-GroupMSAMembership") or entry.get("PrincipalsAllowedToRetrieveManagedPassword", [])
        if isinstance(principals, str):
            principals = [principals]

        user = User(
            username=sam,
            source="ldeep",
            tags=["gmsa", "service-account"],
        )
        yield user

        if principals:
            yield Misconfiguration(
                title=f"gMSA Password Readable: {sam}",
                description=f"gMSA {sam} password can be read by: {', '.join(str(p)[:50] for p in principals[:3])}",
                severity="medium",
                affected_asset_id=user.id,
                source="ldeep",
                check_id="gmsa_readable",
                tags=["gmsa"],
            )

    def _parse_laps(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse LAPS (Local Administrator Password Solution) findings."""
        hostname = (entry.get("sAMAccountName") or entry.get("cn", "")).rstrip("$")
        if not hostname:
            return

        laps_password = entry.get("ms-Mcs-AdmPwd") or entry.get("ms-mcs-admpwd")

        if laps_password:
            yield Misconfiguration(
                title=f"LAPS Password Readable: {hostname}",
                description=f"LAPS password for {hostname} is readable",
                severity="high",
                source="ldeep",
                check_id="laps_readable",
                tags=["laps"],
                raw_data={"hostname": hostname},
            )

    def _parse_text(self, content: str, filename: str) -> Generator[Entity, None, None]:
        """Parse ldeep text output."""
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "\t" in line or ":" in line:
                parts = re.split(r"[\t:]", line, 1)
                if len(parts) == 2:
                    key, value = parts[0].strip(), parts[1].strip()

                    if key.lower() in ["samaccountname", "user", "account"]:
                        user = User(
                            username=value.rstrip("$"),
                            source="ldeep",
                        )
                        yield user

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
        """Check if this file is an ldeep output file."""
        if "ldeep" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"ldeep",
                    b"sAMAccountName",
                    b"distinguishedName",
                    b"msDS-AllowedToDelegateTo",
                    b"msDS-AllowedToActOnBehalfOfOtherIdentity",
                    b"userAccountControl",
                    b"servicePrincipalName",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
