"""ADRecon Active Directory enumeration report parser."""

import csv
import io
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class ADReconParser(BaseParser):
    """Parser for ADRecon Active Directory enumeration CSV/Excel reports."""

    name = "adrecon"
    description = "Parse ADRecon Active Directory enumeration reports"
    file_patterns = [
        "*ADRecon*.csv",
        "*-Users.csv",
        "*-Computers.csv",
        "*-Groups.csv",
        "*-DomainControllers.csv",
        "*-GPOs.csv",
        "*-Trusts.csv",
    ]
    entity_types = ["Host", "User", "Misconfiguration"]

    PRIVILEGED_GROUPS = [
        "domain admins", "enterprise admins", "schema admins",
        "administrators", "account operators", "backup operators",
        "print operators", "server operators", "dnsadmins",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an ADRecon CSV file and yield entities."""
        filename = file_path.name.lower()

        if "users" in filename:
            yield from self._parse_users(file_path)
        elif "computers" in filename:
            yield from self._parse_computers(file_path)
        elif "domaincontrollers" in filename or "dc" in filename:
            yield from self._parse_domain_controllers(file_path)
        elif "groups" in filename:
            yield from self._parse_groups(file_path)
        elif "gpos" in filename or "gpo" in filename:
            yield from self._parse_gpos(file_path)
        elif "trusts" in filename:
            yield from self._parse_trusts(file_path)
        elif "passwordpolicy" in filename:
            yield from self._parse_password_policy(file_path)
        else:
            yield from self._parse_generic(file_path)

    def _parse_users(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon Users CSV."""
        for row in self._read_csv(file_path):
            username = row.get("Name") or row.get("SamAccountName") or row.get("UserName")
            if not username:
                continue

            enabled = self._parse_bool(row.get("Enabled", "True"))
            pwd_never_expires = self._parse_bool(row.get("PasswordNeverExpires", "False"))
            pwd_not_required = self._parse_bool(row.get("PasswordNotRequired", "False"))
            no_preauth = self._parse_bool(row.get("DoesNotRequirePreAuth", "False"))

            member_of = row.get("MemberOf", "").split(";") if row.get("MemberOf") else []
            is_admin = any(
                priv in group.lower()
                for group in member_of
                for priv in self.PRIVILEGED_GROUPS
            )

            user = User(
                username=username,
                domain=row.get("Domain"),
                display_name=row.get("DisplayName"),
                email=row.get("EmailAddress") or row.get("Mail"),
                enabled=enabled,
                is_admin=is_admin,
                password_never_expires=pwd_never_expires,
                groups=[self._extract_cn(g) for g in member_of if g],
                source="adrecon",
                raw_properties={
                    "dn": row.get("DistinguishedName"),
                    "description": row.get("Description"),
                    "sid": row.get("SID"),
                    "spn": row.get("ServicePrincipalName"),
                },
            )
            yield user

            if pwd_not_required:
                yield Misconfiguration(
                    title=f"Password not required: {username}",
                    description=f"User {username} has PASSWD_NOTREQD flag set",
                    severity="high",
                    affected_asset_id=user.id,
                    source="adrecon",
                    check_id="passwd_notreqd",
                )

            if no_preauth:
                yield Misconfiguration(
                    title=f"AS-REP Roastable: {username}",
                    description=f"User {username} does not require Kerberos pre-authentication",
                    severity="high",
                    affected_asset_id=user.id,
                    source="adrecon",
                    check_id="asreproast",
                    tags=["asreproast"],
                )

            spn = row.get("ServicePrincipalName")
            if spn and enabled:
                yield Misconfiguration(
                    title=f"Kerberoastable: {username}",
                    description=f"User {username} has SPN: {spn[:100]}",
                    severity="medium",
                    affected_asset_id=user.id,
                    source="adrecon",
                    check_id="kerberoast",
                    tags=["kerberoast"],
                )

    def _parse_computers(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon Computers CSV."""
        for row in self._read_csv(file_path):
            name = row.get("Name") or row.get("DNSHostName") or row.get("SamAccountName")
            if not name:
                continue

            name = name.rstrip("$")
            os_info = row.get("OperatingSystem")
            os_version = row.get("OperatingSystemVersion")
            if os_info and os_version:
                os_info = f"{os_info} {os_version}"

            enabled = self._parse_bool(row.get("Enabled", "True"))

            host = Host(
                ip="",
                hostname=name,
                domain=row.get("Domain"),
                os=os_info,
                enabled=enabled,
                source="adrecon",
                raw_properties={
                    "dn": row.get("DistinguishedName"),
                    "sid": row.get("SID"),
                    "description": row.get("Description"),
                },
            )
            yield host

            if os_info and any(old in os_info.lower() for old in ["2003", "2008", "xp", "vista", "windows 7"]):
                yield Misconfiguration(
                    title=f"Legacy OS: {name}",
                    description=f"Computer {name} runs {os_info}",
                    severity="medium",
                    affected_asset_id=host.id,
                    source="adrecon",
                    check_id="legacy_os",
                )

            if self._parse_bool(row.get("TrustedForDelegation", "False")):
                yield Misconfiguration(
                    title=f"Unconstrained Delegation: {name}",
                    description=f"Computer {name} is trusted for unconstrained delegation",
                    severity="critical",
                    affected_asset_id=host.id,
                    source="adrecon",
                    check_id="unconstrained_delegation",
                    tags=["delegation"],
                )

    def _parse_domain_controllers(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon Domain Controllers CSV."""
        for row in self._read_csv(file_path):
            name = row.get("Name") or row.get("HostName")
            if not name:
                continue

            host = Host(
                ip=row.get("IPAddress", ""),
                hostname=name,
                domain=row.get("Domain"),
                os=row.get("OperatingSystem"),
                is_dc=True,
                source="adrecon",
                tags=["domain-controller"],
            )
            yield host

    def _parse_groups(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon Groups CSV."""
        for row in self._read_csv(file_path):
            group_name = row.get("Name") or row.get("SamAccountName")
            if not group_name:
                continue

            members = row.get("Members", "").split(";") if row.get("Members") else []
            member_count = len([m for m in members if m])

            if group_name.lower() in self.PRIVILEGED_GROUPS and member_count > 20:
                yield Misconfiguration(
                    title=f"Large privileged group: {group_name}",
                    description=f"Group {group_name} has {member_count} members",
                    severity="medium",
                    source="adrecon",
                    check_id=f"large_group_{group_name}",
                )

    def _parse_gpos(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon GPO CSV."""
        for row in self._read_csv(file_path):
            gpo_name = row.get("DisplayName") or row.get("Name")
            if not gpo_name:
                continue

            if self._parse_bool(row.get("GPOStatus", "")) == "AllSettingsDisabled":
                yield Misconfiguration(
                    title=f"Disabled GPO: {gpo_name}",
                    description=f"GPO {gpo_name} has all settings disabled",
                    severity="info",
                    source="adrecon",
                    check_id=f"disabled_gpo_{gpo_name}",
                )

    def _parse_trusts(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon Trusts CSV."""
        for row in self._read_csv(file_path):
            trust_partner = row.get("TrustPartner") or row.get("Name")
            if not trust_partner:
                continue

            host = Host(
                ip="",
                hostname=trust_partner,
                domain=trust_partner,
                source="adrecon",
                tags=["trusted-domain"],
            )
            yield host

            sid_filtering = row.get("SIDFilteringForestAware") or row.get("SIDFiltering")
            if sid_filtering and sid_filtering.lower() == "false":
                yield Misconfiguration(
                    title=f"SID filtering disabled: {trust_partner}",
                    description=f"Trust with {trust_partner} has SID filtering disabled",
                    severity="high",
                    affected_asset_id=host.id,
                    source="adrecon",
                    check_id="sid_filtering_disabled",
                )

    def _parse_password_policy(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ADRecon Password Policy CSV."""
        for row in self._read_csv(file_path):
            min_length = row.get("MinPasswordLength") or row.get("MinPwdLength")
            if min_length and int(min_length) < 8:
                yield Misconfiguration(
                    title="Weak minimum password length",
                    description=f"Minimum password length is only {min_length} characters",
                    severity="medium",
                    source="adrecon",
                    check_id="weak_min_password",
                )

            complexity = row.get("PasswordComplexity")
            if complexity and complexity.lower() == "false":
                yield Misconfiguration(
                    title="Password complexity disabled",
                    description="Password complexity requirements are not enforced",
                    severity="medium",
                    source="adrecon",
                    check_id="no_complexity",
                )

    def _parse_generic(self, file_path: Path) -> Generator[Entity, None, None]:
        """Generic CSV parser for unknown ADRecon files."""
        for row in self._read_csv(file_path):
            if "SamAccountName" in row and "UserPrincipalName" in row:
                yield from self._parse_users(file_path)
                return
            elif "DNSHostName" in row or "OperatingSystem" in row:
                yield from self._parse_computers(file_path)
                return

    def _read_csv(self, file_path: Path) -> Generator[dict, None, None]:
        """Read CSV file and yield rows as dictionaries."""
        content = file_path.read_text(errors="ignore")

        for encoding in ["utf-8", "utf-16", "latin-1"]:
            try:
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    yield row
                return
            except Exception:
                continue

    def _parse_bool(self, value: str) -> bool:
        """Parse boolean value from string."""
        if not value:
            return False
        return value.lower() in ["true", "yes", "1", "enabled"]

    def _extract_cn(self, dn: str) -> str:
        """Extract CN from distinguished name."""
        match = re.search(r"CN=([^,]+)", dn, re.IGNORECASE)
        return match.group(1) if match else dn

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an ADRecon CSV file."""
        if file_path.suffix.lower() != ".csv":
            return False

        if "adrecon" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(1000)
                indicators = [
                    b"SamAccountName",
                    b"DistinguishedName",
                    b"UserPrincipalName",
                    b"OperatingSystem",
                    b"DNSHostName",
                    b"MemberOf",
                    b"ServicePrincipalName",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
