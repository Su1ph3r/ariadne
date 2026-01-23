"""Seatbelt host enumeration output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration, Vulnerability, Credential
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class SeatbeltParser(BaseParser):
    """Parser for Seatbelt host enumeration output."""

    name = "seatbelt"
    description = "Parse Seatbelt Windows host enumeration and security checks"
    file_patterns = ["*seatbelt*.txt", "*seatbelt*.json", "*Seatbelt*.txt"]
    entity_types = ["Host", "User", "Misconfiguration", "Vulnerability", "Credential"]

    SECTION_PATTERN = re.compile(
        r"====+\s*(?P<section>[^=]+?)\s*====+",
        re.IGNORECASE
    )

    OS_INFO_PATTERN = re.compile(
        r"(?:Hostname|ComputerName)[:\s]+(?P<hostname>[^\r\n]+).*?"
        r"(?:ProductName|OS)[:\s]+(?P<os>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    USER_PATTERN = re.compile(
        r"(?:User|Username|LogonUser)[:\s]+(?P<domain>[^\\\/]+)?[\\\/]?(?P<username>[^\r\n\s]+)",
        re.IGNORECASE
    )

    CREDENTIAL_PATTERN = re.compile(
        r"(?:Target|Resource)[:\s]+(?P<target>[^\r\n]+).*?"
        r"(?:UserName|User)[:\s]+(?P<username>[^\r\n]+).*?"
        r"(?:Password|Credential)[:\s]+(?P<password>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    AUTOLOGON_PATTERN = re.compile(
        r"DefaultUserName[:\s]+(?P<username>[^\r\n]+).*?"
        r"(?:DefaultPassword[:\s]+(?P<password>[^\r\n]+))?.*?"
        r"(?:DefaultDomainName[:\s]+(?P<domain>[^\r\n]+))?",
        re.IGNORECASE | re.DOTALL
    )

    DPAPI_PATTERN = re.compile(
        r"(?:DPAPI|MasterKey|Credential)[:\s]*(?P<value>[a-fA-F0-9-]{36,})",
        re.IGNORECASE
    )

    AV_PATTERN = re.compile(
        r"(?:AntiVirus|AV|Defender|EDR|Security)[^\r\n]*[:\s]+(?P<product>[^\r\n]+)",
        re.IGNORECASE
    )

    UNQUOTED_SERVICE_PATTERN = re.compile(
        r"(?:Name|ServiceName)[:\s]+(?P<name>[^\r\n]+).*?"
        r"(?:PathName|BinaryPath)[:\s]+(?P<path>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    VULNERABLE_DRIVER_PATTERN = re.compile(
        r"(?:Driver|Service)[:\s]+(?P<driver>[^\r\n]+).*?(?:vulnerable|exploit)",
        re.IGNORECASE | re.DOTALL
    )

    TOKEN_PRIV_PATTERN = re.compile(
        r"(?P<privilege>Se\w+Privilege)[:\s]+(?P<state>Enabled|Disabled)",
        re.IGNORECASE
    )

    DANGEROUS_PRIVS = [
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
        "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Seatbelt output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Seatbelt JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        if isinstance(data, dict):
            yield from self._parse_json_sections(data)

    def _parse_json_sections(self, data: dict) -> Generator[Entity, None, None]:
        """Parse JSON sections from Seatbelt."""
        hostname = ""
        os_info = ""

        if "OSInfo" in data or "osinfo" in data:
            os_section = data.get("OSInfo") or data.get("osinfo") or {}
            hostname = os_section.get("Hostname") or os_section.get("ComputerName") or ""
            os_info = os_section.get("ProductName") or os_section.get("OS") or ""

            if hostname:
                host = Host(
                    ip="",
                    hostname=hostname,
                    os=os_info,
                    source="seatbelt",
                    tags=["enumerated"],
                )
                yield host

        if "Credentials" in data or "credentials" in data:
            creds = data.get("Credentials") or data.get("credentials") or []
            for cred in creds:
                if isinstance(cred, dict):
                    target = cred.get("Target") or cred.get("Resource") or ""
                    username = cred.get("UserName") or cred.get("Username") or ""
                    password = cred.get("Password") or cred.get("Credential") or ""

                    if username and password:
                        yield Credential(
                            title=f"Seatbelt Cred: {username}",
                            credential_type="password",
                            username=username,
                            value=password,
                            severity="high",
                            source="seatbelt",
                            tags=["credential-manager"],
                            raw_data={"target": target},
                        )

        if "TokenPrivileges" in data or "tokenprivileges" in data:
            privs = data.get("TokenPrivileges") or data.get("tokenprivileges") or []
            for priv in privs:
                if isinstance(priv, dict):
                    name = priv.get("Name") or priv.get("Privilege") or ""
                    state = priv.get("State") or priv.get("Enabled") or ""

                    if name in self.DANGEROUS_PRIVS and "enabled" in str(state).lower():
                        yield Misconfiguration(
                            title=f"Dangerous Privilege: {name}",
                            description=f"Token has {name} enabled - potential privilege escalation",
                            severity="high",
                            source="seatbelt",
                            check_id=f"priv_{name.lower()}",
                            tags=["privilege", "privesc"],
                        )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse Seatbelt text output."""
        host = None
        seen_creds: set[str] = set()
        seen_users: set[str] = set()

        os_match = self.OS_INFO_PATTERN.search(content)
        if os_match:
            hostname = os_match.group("hostname").strip()
            os_info = os_match.group("os").strip()

            host = Host(
                ip="",
                hostname=hostname,
                os=os_info,
                source="seatbelt",
                tags=["enumerated"],
            )
            yield host

        for match in self.USER_PATTERN.finditer(content):
            domain = match.group("domain") or ""
            username = match.group("username").strip()

            if not username or username.lower() in seen_users:
                continue
            if username.lower() in ["nt authority", "system", "local service", "network service"]:
                continue

            seen_users.add(username.lower())
            user = User(
                username=username,
                domain=domain.strip() if domain else None,
                source="seatbelt",
            )
            yield user

        autologon = self.AUTOLOGON_PATTERN.search(content)
        if autologon:
            username = autologon.group("username")
            password = autologon.group("password")
            domain = autologon.group("domain")

            if username and password:
                yield Credential(
                    title=f"AutoLogon: {username}",
                    credential_type="password",
                    username=username.strip(),
                    domain=domain.strip() if domain else None,
                    value=password.strip(),
                    severity="critical",
                    source="seatbelt",
                    tags=["autologon"],
                )

                yield Misconfiguration(
                    title="AutoLogon Credentials Stored",
                    description=f"AutoLogon configured with cleartext password for {username}",
                    severity="high",
                    source="seatbelt",
                    check_id="autologon_creds",
                    tags=["autologon", "credential"],
                )

        for match in self.CREDENTIAL_PATTERN.finditer(content):
            target = match.group("target").strip()
            username = match.group("username").strip()
            password = match.group("password").strip()

            cred_key = f"{username}:{password[:16]}"
            if cred_key in seen_creds:
                continue
            seen_creds.add(cred_key)

            yield Credential(
                title=f"Credential Manager: {username}",
                credential_type="password",
                username=username,
                value=password,
                severity="high",
                source="seatbelt",
                tags=["credential-manager"],
                raw_data={"target": target},
            )

        for match in self.TOKEN_PRIV_PATTERN.finditer(content):
            privilege = match.group("privilege")
            state = match.group("state")

            if privilege in self.DANGEROUS_PRIVS and state.lower() == "enabled":
                yield Misconfiguration(
                    title=f"Dangerous Privilege: {privilege}",
                    description=f"Token has {privilege} enabled - potential privilege escalation",
                    severity="high",
                    source="seatbelt",
                    check_id=f"priv_{privilege.lower()}",
                    tags=["privilege", "privesc"],
                )

        if "UnquotedServicePath" in content or "Unquoted" in content:
            unquoted_section = re.search(
                r"Unquoted.*?(?:====|$)",
                content,
                re.IGNORECASE | re.DOTALL
            )
            if unquoted_section:
                for match in self.UNQUOTED_SERVICE_PATTERN.finditer(unquoted_section.group(0)):
                    name = match.group("name").strip()
                    path = match.group("path").strip()

                    if " " in path and not path.startswith('"'):
                        yield Vulnerability(
                            title=f"Unquoted Service Path: {name}",
                            description=f"Service {name} has unquoted path: {path}",
                            severity="medium",
                            source="seatbelt",
                            tags=["privesc", "unquoted-path"],
                        )

        if "AlwaysInstallElevated" in content:
            if re.search(r"AlwaysInstallElevated.*?:\s*(?:True|1|Enabled)", content, re.IGNORECASE):
                yield Misconfiguration(
                    title="AlwaysInstallElevated Enabled",
                    description="MSI packages will install with elevated privileges",
                    severity="high",
                    source="seatbelt",
                    check_id="always_install_elevated",
                    tags=["privesc"],
                )

        if "LSASS" in content.upper():
            if re.search(r"LSASS.*?protection.*?(?:disabled|not|none)", content, re.IGNORECASE):
                yield Misconfiguration(
                    title="LSASS Protection Disabled",
                    description="LSA protection is not enabled - credentials can be dumped",
                    severity="medium",
                    source="seatbelt",
                    check_id="lsass_protection",
                    tags=["credential", "lsass"],
                )

        if "Credential Guard" in content:
            if re.search(r"Credential Guard.*?(?:disabled|not|none)", content, re.IGNORECASE):
                yield Misconfiguration(
                    title="Credential Guard Disabled",
                    description="Windows Credential Guard is not enabled",
                    severity="medium",
                    source="seatbelt",
                    check_id="credential_guard",
                    tags=["credential"],
                )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Seatbelt output file."""
        name_lower = file_path.name.lower()
        if "seatbelt" in name_lower:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(4000)
                indicators = [
                    b"Seatbelt",
                    b"seatbelt",
                    b"====",
                    b"OSInfo",
                    b"TokenPrivileges",
                    b"CredentialManager",
                    b"AutoLogon",
                    b"InterestingProcesses",
                    b"AntiVirus",
                    b"UACSystemPolicies",
                ]
                return sum(1 for ind in indicators if ind in header) >= 3
        except Exception:
            return False
