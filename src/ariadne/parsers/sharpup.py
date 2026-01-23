"""SharpUp privilege escalation checks output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class SharpUpParser(BaseParser):
    """Parser for SharpUp privilege escalation enumeration output."""

    name = "sharpup"
    description = "Parse SharpUp Windows privilege escalation checks"
    file_patterns = ["*sharpup*.txt", "*sharpup*.json", "*SharpUp*.txt", "*privesc*.txt"]
    entity_types = ["Host", "Vulnerability", "Misconfiguration"]

    VULN_SECTION_PATTERN = re.compile(
        r"\[(?:\*|\+|!)\]\s*(?P<finding>[^\r\n]+)",
        re.IGNORECASE
    )

    MODIFIABLE_SERVICE_PATTERN = re.compile(
        r"(?:Modifiable\s+Service|Service\s+Binary)[:\s]*(?P<service>[^\r\n]+).*?"
        r"(?:Path|Binary)[:\s]*(?P<path>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    UNQUOTED_SERVICE_PATTERN = re.compile(
        r"Unquoted\s+Service\s+Path[:\s]*(?P<service>[^\r\n]+).*?"
        r"(?:Path|Binary)[:\s]*(?P<path>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    MODIFIABLE_REG_PATTERN = re.compile(
        r"Modifiable\s+(?:Service\s+)?Registry[:\s]*(?P<service>[^\r\n]+)",
        re.IGNORECASE
    )

    ALWAYS_ELEVATED_PATTERN = re.compile(
        r"AlwaysInstallElevated",
        re.IGNORECASE
    )

    AUTOLOGON_PATTERN = re.compile(
        r"AutoLogon.*?(?:DefaultUserName|User)[:\s]*(?P<username>[^\r\n]+).*?"
        r"(?:DefaultPassword|Password)[:\s]*(?P<password>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    SCHEDULED_TASK_PATTERN = re.compile(
        r"(?:Modifiable\s+)?Scheduled\s+Task[:\s]*(?P<task>[^\r\n]+).*?"
        r"(?:Path|Action)[:\s]*(?P<path>[^\r\n]+)",
        re.IGNORECASE | re.DOTALL
    )

    WRITABLE_PATH_PATTERN = re.compile(
        r"(?:Writable|Modifiable)\s+(?:PATH|Path\s+Directory)[:\s]*(?P<path>[^\r\n]+)",
        re.IGNORECASE
    )

    CACHED_CREDS_PATTERN = re.compile(
        r"Cached\s+(?:GPP\s+)?(?:Credentials?|Password)[:\s]*(?P<creds>[^\r\n]+)",
        re.IGNORECASE
    )

    TOKEN_PRIV_PATTERN = re.compile(
        r"(?P<privilege>Se\w+Privilege)\s+(?:is\s+)?(?:enabled|available)",
        re.IGNORECASE
    )

    DANGEROUS_PRIVS = [
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
        "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a SharpUp output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse SharpUp JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        if isinstance(data, list):
            for finding in data:
                yield from self._parse_json_finding(finding)
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list):
                    for finding in value:
                        yield from self._parse_json_finding(finding)
                elif isinstance(value, dict):
                    value["type"] = key
                    yield from self._parse_json_finding(value)

    def _parse_json_finding(self, finding: dict) -> Generator[Entity, None, None]:
        """Parse a single JSON finding."""
        finding_type = finding.get("Type") or finding.get("type") or finding.get("Check") or ""
        description = finding.get("Description") or finding.get("description") or ""
        service = finding.get("Service") or finding.get("Name") or ""
        path = finding.get("Path") or finding.get("Binary") or ""
        severity = finding.get("Severity") or "medium"

        title = finding_type or "SharpUp Finding"
        desc = description or f"{service}: {path}"

        if any(x in finding_type.lower() for x in ["modifiable", "writable", "unquoted"]):
            yield Vulnerability(
                title=f"PrivEsc: {title}",
                description=desc,
                severity=severity if severity in ["critical", "high", "medium", "low"] else "medium",
                source="sharpup",
                tags=["privesc"],
                raw_data=finding,
            )
        else:
            yield Misconfiguration(
                title=title,
                description=desc,
                severity=severity if severity in ["critical", "high", "medium", "low"] else "medium",
                source="sharpup",
                check_id=f"sharpup_{finding_type.lower().replace(' ', '_')[:30]}",
                tags=["privesc"],
                raw_data=finding,
            )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse SharpUp text output."""
        seen_findings: set[str] = set()

        for match in self.MODIFIABLE_SERVICE_PATTERN.finditer(content):
            service = match.group("service").strip()
            path = match.group("path").strip()

            finding_key = f"modifiable_service:{service}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            yield Vulnerability(
                title=f"Modifiable Service: {service}",
                description=f"Service {service} binary/config is modifiable: {path}",
                severity="high",
                source="sharpup",
                tags=["privesc", "service"],
            )

        for match in self.UNQUOTED_SERVICE_PATTERN.finditer(content):
            service = match.group("service").strip()
            path = match.group("path").strip()

            finding_key = f"unquoted_service:{service}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            yield Vulnerability(
                title=f"Unquoted Service Path: {service}",
                description=f"Service {service} has unquoted path: {path}",
                severity="medium",
                source="sharpup",
                tags=["privesc", "unquoted-path"],
            )

        for match in self.MODIFIABLE_REG_PATTERN.finditer(content):
            service = match.group("service").strip()

            finding_key = f"modifiable_reg:{service}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            yield Vulnerability(
                title=f"Modifiable Service Registry: {service}",
                description=f"Registry key for service {service} is modifiable",
                severity="high",
                source="sharpup",
                tags=["privesc", "registry"],
            )

        if self.ALWAYS_ELEVATED_PATTERN.search(content):
            yield Misconfiguration(
                title="AlwaysInstallElevated Enabled",
                description="MSI packages will install with SYSTEM privileges",
                severity="high",
                source="sharpup",
                check_id="always_install_elevated",
                tags=["privesc"],
            )

        for match in self.SCHEDULED_TASK_PATTERN.finditer(content):
            task = match.group("task").strip()
            path = match.group("path").strip()

            finding_key = f"scheduled_task:{task}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            yield Vulnerability(
                title=f"Modifiable Scheduled Task: {task}",
                description=f"Scheduled task {task} is modifiable: {path}",
                severity="high",
                source="sharpup",
                tags=["privesc", "scheduled-task"],
            )

        for match in self.WRITABLE_PATH_PATTERN.finditer(content):
            path = match.group("path").strip()

            finding_key = f"writable_path:{path}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            yield Vulnerability(
                title=f"Writable PATH Directory",
                description=f"PATH directory is writable: {path}",
                severity="medium",
                source="sharpup",
                tags=["privesc", "path-hijack"],
            )

        for match in self.TOKEN_PRIV_PATTERN.finditer(content):
            privilege = match.group("privilege")

            if privilege in self.DANGEROUS_PRIVS:
                finding_key = f"token_priv:{privilege}"
                if finding_key in seen_findings:
                    continue
                seen_findings.add(finding_key)

                yield Misconfiguration(
                    title=f"Dangerous Privilege: {privilege}",
                    description=f"Token has {privilege} - potential for privilege escalation",
                    severity="high",
                    source="sharpup",
                    check_id=f"priv_{privilege.lower()}",
                    tags=["privesc", "token"],
                )

        for match in self.VULN_SECTION_PATTERN.finditer(content):
            finding = match.group("finding").strip()

            if any(x in finding.lower() for x in ["not vulnerable", "no issues", "secure", "disabled"]):
                continue

            finding_key = f"generic:{finding[:50]}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            severity = "medium"
            if any(x in finding.lower() for x in ["credential", "password", "admin", "system"]):
                severity = "high"

            yield Misconfiguration(
                title=f"SharpUp: {finding[:60]}",
                description=finding,
                severity=severity,
                source="sharpup",
                check_id=f"sharpup_{hash(finding) % 10000}",
                tags=["privesc"],
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a SharpUp output file."""
        name_lower = file_path.name.lower()
        if "sharpup" in name_lower:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"SharpUp",
                    b"sharpup",
                    b"Modifiable Service",
                    b"Unquoted Service",
                    b"AlwaysInstallElevated",
                    b"TokenPrivileges",
                    b"Cached GPP",
                    b"[*] Checking",
                    b"[+] Found",
                    b"Hijackable",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
