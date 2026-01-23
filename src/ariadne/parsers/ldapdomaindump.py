"""LDAPDomainDump JSON output parser for AD enumeration."""

import json
from datetime import datetime
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class LDAPDomainDumpParser(BaseParser):
    """Parser for LDAPDomainDump JSON output files."""

    name = "ldapdomaindump"
    description = "Parse LDAPDomainDump AD enumeration JSON output"
    file_patterns = [
        "domain_users*.json",
        "domain_groups*.json",
        "domain_computers*.json",
        "domain_trusts*.json",
        "*ldapdomaindump*.json",
    ]
    entity_types = ["Host", "User", "Misconfiguration"]

    PRIVILEGED_GROUPS = [
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "backup operators",
        "print operators",
        "server operators",
        "dnsadmins",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an LDAPDomainDump JSON file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        filename = file_path.name.lower()

        if "users" in filename:
            yield from self._parse_users(data)
        elif "groups" in filename:
            yield from self._parse_groups(data)
        elif "computers" in filename:
            yield from self._parse_computers(data)
        elif "trusts" in filename:
            yield from self._parse_trusts(data)
        else:
            if isinstance(data, list) and data:
                first_item = data[0]
                if "sAMAccountName" in first_item:
                    if "userAccountControl" in first_item:
                        yield from self._parse_users(data)
                    elif "operatingSystem" in first_item:
                        yield from self._parse_computers(data)
                elif "member" in first_item:
                    yield from self._parse_groups(data)

    def _parse_users(self, data: list) -> Generator[Entity, None, None]:
        """Parse domain users."""
        for entry in data:
            sam_name = self._get_attr(entry, "sAMAccountName")
            if not sam_name:
                continue

            dn = self._get_attr(entry, "distinguishedName", "")
            domain = self._extract_domain_from_dn(dn)

            uac = self._get_attr(entry, "userAccountControl", "0")
            try:
                uac_int = int(uac)
            except ValueError:
                uac_int = 0

            enabled = not (uac_int & 0x0002)
            pwd_never_expires = bool(uac_int & 0x10000)
            pwd_not_required = bool(uac_int & 0x0020)
            dont_req_preauth = bool(uac_int & 0x400000)

            member_of = self._get_attr_list(entry, "memberOf")
            is_admin = any(
                priv_group in group.lower()
                for group in member_of
                for priv_group in self.PRIVILEGED_GROUPS
            )

            last_logon = None
            last_logon_ts = self._get_attr(entry, "lastLogonTimestamp")
            if last_logon_ts:
                last_logon = self._parse_ad_timestamp(last_logon_ts)

            user = User(
                username=sam_name,
                domain=domain,
                display_name=self._get_attr(entry, "displayName"),
                email=self._get_attr(entry, "mail"),
                enabled=enabled,
                is_admin=is_admin,
                password_never_expires=pwd_never_expires,
                last_logon=last_logon,
                groups=[self._extract_cn(g) for g in member_of],
                object_id=self._get_attr(entry, "objectSid"),
                source="ldapdomaindump",
                raw_properties={
                    "dn": dn,
                    "uac": uac_int,
                    "description": self._get_attr(entry, "description"),
                },
            )
            yield user

            if pwd_not_required:
                yield Misconfiguration(
                    title=f"Password not required for {sam_name}",
                    description=f"User {sam_name} has PASSWD_NOTREQD flag set",
                    severity="high",
                    affected_asset_id=user.id,
                    source="ldapdomaindump",
                    check_id="passwd_notreqd",
                )

            if dont_req_preauth:
                yield Misconfiguration(
                    title=f"Kerberos pre-auth disabled for {sam_name}",
                    description=f"User {sam_name} does not require Kerberos pre-authentication (AS-REP Roastable)",
                    severity="high",
                    affected_asset_id=user.id,
                    source="ldapdomaindump",
                    check_id="no_preauth",
                    tags=["asreproast"],
                )

            spns = self._get_attr_list(entry, "servicePrincipalName")
            if spns and enabled:
                yield Misconfiguration(
                    title=f"Service account {sam_name} is Kerberoastable",
                    description=f"User {sam_name} has SPNs set: {', '.join(spns[:3])}{'...' if len(spns) > 3 else ''}",
                    severity="medium",
                    affected_asset_id=user.id,
                    source="ldapdomaindump",
                    check_id="kerberoastable",
                    tags=["kerberoast"],
                )

    def _parse_computers(self, data: list) -> Generator[Entity, None, None]:
        """Parse domain computers."""
        for entry in data:
            sam_name = self._get_attr(entry, "sAMAccountName", "")
            hostname = sam_name.rstrip("$") if sam_name else self._get_attr(entry, "dNSHostName", "")
            if not hostname:
                continue

            dn = self._get_attr(entry, "distinguishedName", "")
            domain = self._extract_domain_from_dn(dn)
            os_version = self._get_attr(entry, "operatingSystem")
            os_sp = self._get_attr(entry, "operatingSystemServicePack")

            if os_version and os_sp:
                os_version = f"{os_version} {os_sp}"

            uac = self._get_attr(entry, "userAccountControl", "0")
            try:
                uac_int = int(uac)
            except ValueError:
                uac_int = 0

            enabled = not (uac_int & 0x0002)

            host = Host(
                ip="",
                hostname=hostname,
                domain=domain,
                os=os_version,
                enabled=enabled,
                source="ldapdomaindump",
                raw_properties={
                    "dn": dn,
                    "sam_account_name": sam_name,
                    "object_sid": self._get_attr(entry, "objectSid"),
                },
            )
            yield host

            if os_version and any(old_os in os_version.lower() for old_os in ["2003", "2008", "xp", "vista", "windows 7"]):
                yield Misconfiguration(
                    title=f"Outdated OS on {hostname}",
                    description=f"Computer {hostname} is running {os_version}, which may be unsupported",
                    severity="medium",
                    affected_asset_id=host.id,
                    source="ldapdomaindump",
                    check_id="outdated_os",
                )

    def _parse_groups(self, data: list) -> Generator[Entity, None, None]:
        """Parse domain groups and their memberships."""
        for entry in data:
            group_name = self._get_attr(entry, "sAMAccountName") or self._get_attr(entry, "cn")
            if not group_name:
                continue

            members = self._get_attr_list(entry, "member")
            dn = self._get_attr(entry, "distinguishedName", "")
            domain = self._extract_domain_from_dn(dn)

            is_privileged = group_name.lower() in self.PRIVILEGED_GROUPS

            if is_privileged and len(members) > 20:
                yield Misconfiguration(
                    title=f"Large privileged group: {group_name}",
                    description=f"Privileged group {group_name} has {len(members)} members",
                    severity="medium",
                    source="ldapdomaindump",
                    check_id=f"large_priv_group_{group_name}",
                )

    def _parse_trusts(self, data: list) -> Generator[Entity, None, None]:
        """Parse domain trusts."""
        for entry in data:
            trust_partner = self._get_attr(entry, "trustPartner") or self._get_attr(entry, "cn")
            if not trust_partner:
                continue

            trust_direction = self._get_attr(entry, "trustDirection", "0")
            trust_type = self._get_attr(entry, "trustType", "0")

            host = Host(
                ip="",
                hostname=trust_partner,
                domain=trust_partner,
                source="ldapdomaindump",
                tags=["trusted-domain"],
                raw_properties={
                    "trust_direction": trust_direction,
                    "trust_type": trust_type,
                },
            )
            yield host

    def _get_attr(self, entry: dict, attr: str, default: str = "") -> str:
        """Get attribute value from entry."""
        val = entry.get(attr)
        if val is None:
            lower_attr = attr.lower()
            for key in entry:
                if key.lower() == lower_attr:
                    val = entry[key]
                    break

        if val is None:
            return default

        if isinstance(val, list):
            return val[0] if val else default
        return str(val)

    def _get_attr_list(self, entry: dict, attr: str) -> list[str]:
        """Get attribute as list."""
        val = entry.get(attr)
        if val is None:
            lower_attr = attr.lower()
            for key in entry:
                if key.lower() == lower_attr:
                    val = entry[key]
                    break

        if val is None:
            return []

        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)]

    def _extract_domain_from_dn(self, dn: str) -> str | None:
        """Extract domain name from distinguished name."""
        import re
        dc_parts = re.findall(r"DC=([^,]+)", dn, re.IGNORECASE)
        if dc_parts:
            return ".".join(dc_parts)
        return None

    def _extract_cn(self, dn: str) -> str:
        """Extract CN from distinguished name."""
        import re
        match = re.search(r"CN=([^,]+)", dn, re.IGNORECASE)
        if match:
            return match.group(1)
        return dn

    def _parse_ad_timestamp(self, timestamp: str) -> datetime | None:
        """Parse AD timestamp (Windows FILETIME)."""
        try:
            ts = int(timestamp)
            if ts == 0 or ts == 9223372036854775807:
                return None
            epoch_diff = 116444736000000000
            unix_ts = (ts - epoch_diff) / 10000000
            return datetime.fromtimestamp(unix_ts)
        except (ValueError, OSError):
            return None

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an LDAPDomainDump JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"sAMAccountName",
                    b"distinguishedName",
                    b"userAccountControl",
                    b"memberOf",
                    b"servicePrincipalName",
                    b"objectSid",
                    b"ldapdomaindump",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
