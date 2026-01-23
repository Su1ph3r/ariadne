"""PowerView Active Directory enumeration output parser."""

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
class PowerViewParser(BaseParser):
    """Parser for PowerView AD enumeration output."""

    name = "powerview"
    description = "Parse PowerView/SharpView Active Directory enumeration output"
    file_patterns = ["*powerview*.txt", "*powerview*.json", "*sharpview*.txt", "*Get-Domain*.txt"]
    entity_types = ["Host", "User", "Misconfiguration", "Relationship"]

    PRIVILEGED_GROUPS = [
        "domain admins", "enterprise admins", "schema admins",
        "administrators", "account operators", "backup operators",
        "dnsadmins", "server operators",
    ]

    USER_OBJECT_PATTERN = re.compile(
        r"(?:samaccountname|SAMAccountName)[:\s]+(?P<sam>[^\r\n]+).*?"
        r"(?:distinguishedname|DistinguishedName)[:\s]+(?P<dn>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    COMPUTER_OBJECT_PATTERN = re.compile(
        r"(?:dnshostname|DNSHostName|name)[:\s]+(?P<hostname>[^\r\n$]+)\$?.*?"
        r"(?:operatingsystem|OperatingSystem)[:\s]+(?P<os>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    GROUP_MEMBER_PATTERN = re.compile(
        r"(?:GroupName|Group)[:\s]+(?P<group>[^\r\n]+).*?"
        r"(?:MemberName|Member)[:\s]+(?P<member>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    SPN_PATTERN = re.compile(
        r"(?:serviceprincipalname|ServicePrincipalName)[:\s]+(?P<spn>[^\r\n]+)",
        re.IGNORECASE
    )

    DELEGATION_PATTERN = re.compile(
        r"(?:msds-allowedtodelegateto|AllowedToDelegateTo)[:\s]+(?P<targets>[^\r\n]+)",
        re.IGNORECASE
    )

    UAC_PATTERN = re.compile(
        r"(?:useraccountcontrol|UserAccountControl)[:\s]+(?P<uac>\d+)",
        re.IGNORECASE
    )

    ACL_PATTERN = re.compile(
        r"(?:ObjectDN|IdentityReference)[:\s]+(?P<target>[^\r\n]+).*?"
        r"(?:ActiveDirectoryRights|Rights)[:\s]+(?P<rights>[^\r\n]+).*?"
        r"(?:IdentityReference|Principal)[:\s]+(?P<principal>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    TRUST_PATTERN = re.compile(
        r"(?:TargetDomain|TrustPartner|SourceName)[:\s]+(?P<domain>[^\r\n]+).*?"
        r"(?:TrustDirection|Direction)[:\s]+(?P<direction>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    SESSION_PATTERN = re.compile(
        r"(?:ComputerName|CName)[:\s]+(?P<computer>[^\r\n]+).*?"
        r"(?:UserName|User)[:\s]+(?P<user>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    LOCALGROUP_PATTERN = re.compile(
        r"(?:ComputerName|Server)[:\s]+(?P<computer>[^\r\n]+).*?"
        r"(?:GroupName|Group)[:\s]+(?P<group>[^\r\n]+).*?"
        r"(?:MemberName|Member)[:\s]+(?P<member>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a PowerView output file and yield entities."""
        content = file_path.read_text(errors="ignore")
        filename = file_path.name.lower()

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content, filename)
        else:
            yield from self._parse_text(content, filename)

    def _parse_json(self, content: str, filename: str) -> Generator[Entity, None, None]:
        """Parse PowerView JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]

        for entry in entries:
            if isinstance(entry, dict):
                yield from self._parse_object(entry, filename)

    def _parse_object(self, entry: dict, filename: str) -> Generator[Entity, None, None]:
        """Parse a single PowerView object."""
        sam = entry.get("samaccountname") or entry.get("SamAccountName") or ""
        dn = entry.get("distinguishedname") or entry.get("DistinguishedName") or ""
        object_class = entry.get("objectclass") or entry.get("ObjectClass") or []

        if isinstance(object_class, str):
            object_class = [object_class]

        is_computer = (
            "computer" in [oc.lower() for oc in object_class] or
            sam.endswith("$") or
            "computer" in filename
        )

        is_user = (
            "user" in [oc.lower() for oc in object_class] or
            "person" in [oc.lower() for oc in object_class] or
            "user" in filename
        )

        if is_computer:
            yield from self._parse_computer(entry)
        elif is_user or sam:
            yield from self._parse_user(entry)

        if "session" in filename or "netsession" in filename:
            yield from self._parse_session(entry)

        if "localgroup" in filename or "localadmin" in filename:
            yield from self._parse_localgroup(entry)

        if "acl" in filename or "objectacl" in filename:
            yield from self._parse_acl(entry)

    def _parse_user(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a user object."""
        sam = entry.get("samaccountname") or entry.get("SamAccountName") or ""
        if not sam or sam.endswith("$"):
            return

        domain = self._extract_domain(entry.get("distinguishedname", "") or entry.get("DistinguishedName", ""))

        uac = int(entry.get("useraccountcontrol") or entry.get("UserAccountControl") or 0)
        enabled = not (uac & 0x0002)
        pwd_never_expires = bool(uac & 0x10000)
        pwd_not_required = bool(uac & 0x0020)
        dont_req_preauth = bool(uac & 0x400000)
        trusted_for_delegation = bool(uac & 0x80000)

        member_of = entry.get("memberof") or entry.get("MemberOf") or []
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
            display_name=entry.get("displayname") or entry.get("DisplayName") or entry.get("cn"),
            enabled=enabled,
            is_admin=is_admin,
            password_never_expires=pwd_never_expires,
            groups=[self._extract_cn(g) for g in member_of],
            source="powerview",
        )
        yield user

        if pwd_not_required:
            yield Misconfiguration(
                title=f"Password not required: {sam}",
                description=f"User {sam} has PASSWD_NOTREQD flag",
                severity="high",
                affected_asset_id=user.id,
                source="powerview",
                check_id="passwd_notreqd",
            )

        if dont_req_preauth:
            yield Misconfiguration(
                title=f"AS-REP Roastable: {sam}",
                description=f"User {sam} does not require Kerberos pre-authentication",
                severity="high",
                affected_asset_id=user.id,
                source="powerview",
                check_id="asreproast",
                tags=["asreproast"],
            )

        spns = entry.get("serviceprincipalname") or entry.get("ServicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        if spns and enabled:
            yield Misconfiguration(
                title=f"Kerberoastable: {sam}",
                description=f"User {sam} has SPNs: {', '.join(spns[:3])}",
                severity="medium",
                affected_asset_id=user.id,
                source="powerview",
                check_id="kerberoast",
                tags=["kerberoast"],
            )

        if trusted_for_delegation:
            yield Misconfiguration(
                title=f"Unconstrained Delegation: {sam}",
                description=f"User {sam} is trusted for unconstrained delegation",
                severity="critical",
                affected_asset_id=user.id,
                source="powerview",
                check_id="unconstrained_delegation",
                tags=["delegation"],
            )

    def _parse_computer(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a computer object."""
        hostname = (
            entry.get("dnshostname") or entry.get("DNSHostName") or
            entry.get("name") or entry.get("Name") or
            entry.get("samaccountname") or entry.get("SamAccountName") or ""
        ).rstrip("$")

        if not hostname:
            return

        domain = self._extract_domain(entry.get("distinguishedname", "") or entry.get("DistinguishedName", ""))
        os_info = entry.get("operatingsystem") or entry.get("OperatingSystem") or ""
        os_version = entry.get("operatingsystemversion") or entry.get("OperatingSystemVersion") or ""
        if os_version:
            os_info = f"{os_info} {os_version}"

        uac = int(entry.get("useraccountcontrol") or entry.get("UserAccountControl") or 0)
        trusted_for_delegation = bool(uac & 0x80000)
        trusted_to_auth = bool(uac & 0x1000000)

        is_dc = "Domain Controllers" in (entry.get("distinguishedname") or entry.get("DistinguishedName") or "")

        host = Host(
            ip="",
            hostname=hostname,
            domain=domain,
            os=os_info,
            is_dc=is_dc,
            source="powerview",
        )
        yield host

        if trusted_for_delegation:
            yield Misconfiguration(
                title=f"Unconstrained Delegation: {hostname}",
                description=f"Computer {hostname} is trusted for unconstrained delegation",
                severity="critical",
                affected_asset_id=host.id,
                source="powerview",
                check_id="unconstrained_delegation",
                tags=["delegation", "unconstrained"],
            )

        if trusted_to_auth:
            allowed_to = entry.get("msds-allowedtodelegateto") or entry.get("msDS-AllowedToDelegateTo") or []
            if isinstance(allowed_to, str):
                allowed_to = [allowed_to]

            yield Misconfiguration(
                title=f"Constrained Delegation: {hostname}",
                description=f"Computer {hostname} can delegate to: {', '.join(allowed_to[:5])}",
                severity="high",
                affected_asset_id=host.id,
                source="powerview",
                check_id="constrained_delegation",
                tags=["delegation", "constrained"],
            )

    def _parse_session(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse session information."""
        computer = entry.get("ComputerName") or entry.get("computername") or entry.get("CName") or ""
        user = entry.get("UserName") or entry.get("username") or entry.get("User") or ""

        if computer and user:
            yield Misconfiguration(
                title=f"Active Session: {user} on {computer}",
                description=f"User {user} has an active session on {computer}",
                severity="info",
                source="powerview",
                check_id=f"session_{computer}_{user}",
                tags=["session"],
            )

    def _parse_localgroup(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse local group membership."""
        computer = entry.get("ComputerName") or entry.get("computername") or entry.get("Server") or ""
        group = entry.get("GroupName") or entry.get("groupname") or entry.get("Group") or ""
        member = entry.get("MemberName") or entry.get("membername") or entry.get("Member") or ""

        if computer and member and "admin" in group.lower():
            yield Misconfiguration(
                title=f"Local Admin: {member} on {computer}",
                description=f"{member} is a member of {group} on {computer}",
                severity="medium",
                source="powerview",
                check_id=f"localadmin_{computer}_{member}",
                tags=["local-admin"],
            )

    def _parse_acl(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse ACL information."""
        target = entry.get("ObjectDN") or entry.get("objectdn") or ""
        rights = entry.get("ActiveDirectoryRights") or entry.get("activedirectoryrights") or ""
        principal = entry.get("IdentityReference") or entry.get("identityreference") or ""

        dangerous_rights = ["GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "AllExtendedRights"]

        if any(r in rights for r in dangerous_rights):
            yield Misconfiguration(
                title=f"Dangerous ACL: {principal} -> {self._extract_cn(target)}",
                description=f"{principal} has {rights} on {target}",
                severity="high",
                source="powerview",
                check_id=f"acl_{hash(f'{principal}{target}') % 10000}",
                tags=["acl", "misconfiguration"],
            )

    def _parse_text(self, content: str, filename: str) -> Generator[Entity, None, None]:
        """Parse PowerView text output."""
        blocks = re.split(r"\n\s*\n", content)
        seen_users: set[str] = set()
        seen_hosts: set[str] = set()

        for block in blocks:
            if not block.strip():
                continue

            props = {}
            for line in block.split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    props[key.strip().lower()] = value.strip()

            if props:
                sam = props.get("samaccountname", "")

                if sam.endswith("$") or "computer" in filename:
                    hostname = sam.rstrip("$") or props.get("dnshostname", "") or props.get("name", "")
                    if hostname and hostname.lower() not in seen_hosts:
                        seen_hosts.add(hostname.lower())
                        yield from self._parse_computer(props)
                elif sam and sam.lower() not in seen_users:
                    seen_users.add(sam.lower())
                    yield from self._parse_user(props)

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
        """Check if this file is a PowerView output file."""
        name_lower = file_path.name.lower()
        if any(x in name_lower for x in ["powerview", "sharpview", "get-domain", "get-net"]):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"PowerView",
                    b"powerview",
                    b"SharpView",
                    b"samaccountname",
                    b"SamAccountName",
                    b"distinguishedname",
                    b"DistinguishedName",
                    b"serviceprincipalname",
                    b"useraccountcontrol",
                    b"memberof",
                    b"MemberOf",
                    b"Get-Domain",
                    b"Get-Net",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
