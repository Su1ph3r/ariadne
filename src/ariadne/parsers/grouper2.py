"""Grouper2 GPO vulnerability analysis parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Vulnerability, Misconfiguration, Credential
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class Grouper2Parser(BaseParser):
    """Parser for Grouper2 GPO vulnerability analysis output."""

    name = "grouper2"
    description = "Parse Grouper2 Group Policy vulnerability analysis"
    file_patterns = ["*grouper2*.json", "*grouper2*.html", "*grouper*.json", "*gpo_audit*.json"]
    entity_types = ["Host", "User", "Vulnerability", "Misconfiguration", "Credential"]

    SEVERITY_MAP = {
        "black": "critical",
        "red": "high",
        "orange": "high",
        "yellow": "medium",
        "green": "low",
        "1": "critical",
        "2": "high",
        "3": "medium",
        "4": "low",
        "5": "info",
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Grouper2 output file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            yield from self._parse_json(file_path)
        elif suffix == ".html":
            yield from self._parse_html(file_path)

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Grouper2 JSON output."""
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            for entry in data:
                yield from self._parse_finding(entry)
        elif isinstance(data, dict):
            if "findings" in data:
                for entry in data["findings"]:
                    yield from self._parse_finding(entry)
            elif "GPOName" in data or "GpoName" in data:
                yield from self._parse_finding(data)
            else:
                for gpo_name, gpo_data in data.items():
                    if isinstance(gpo_data, dict):
                        gpo_data["GPOName"] = gpo_name
                        yield from self._parse_finding(gpo_data)
                    elif isinstance(gpo_data, list):
                        for item in gpo_data:
                            if isinstance(item, dict):
                                item["GPOName"] = gpo_name
                                yield from self._parse_finding(item)

    def _parse_finding(self, finding: dict) -> Generator[Entity, None, None]:
        """Parse a single Grouper2 finding."""
        gpo_name = finding.get("GPOName") or finding.get("GpoName") or finding.get("Name") or "Unknown GPO"
        finding_type = finding.get("FindingType") or finding.get("Type") or finding.get("Category") or ""
        description = finding.get("FindingDetail") or finding.get("Detail") or finding.get("Description") or ""
        severity_raw = str(finding.get("Severity") or finding.get("Interest") or finding.get("Triage") or "3")
        severity = self.SEVERITY_MAP.get(severity_raw.lower(), "medium")

        setting = finding.get("Setting") or finding.get("SettingName") or ""
        value = finding.get("Value") or finding.get("SettingValue") or ""

        finding_lower = finding_type.lower() if finding_type else ""
        desc_lower = description.lower()

        if any(cred_indicator in desc_lower or cred_indicator in finding_lower
               for cred_indicator in ["password", "credential", "cpassword", "gpp"]):

            cpassword = finding.get("cpassword") or finding.get("CPassword")
            password = finding.get("password") or finding.get("Password") or finding.get("DecryptedPassword")
            username = finding.get("username") or finding.get("UserName") or finding.get("User")

            if cpassword or password:
                yield Credential(
                    title=f"GPP Password in {gpo_name}",
                    description=f"Group Policy Preferences password found: {description[:200]}",
                    credential_type="password" if password else "gpp_cpassword",
                    username=username,
                    value=password or cpassword or "",
                    severity="critical",
                    source="grouper2",
                    tags=["gpp", "cpassword"],
                    raw_data=finding,
                )
            else:
                yield Misconfiguration(
                    title=f"Credential exposure in GPO: {gpo_name}",
                    description=f"{description}\nSetting: {setting}\nValue: {value}",
                    severity=severity,
                    source="grouper2",
                    check_id=f"gpo_cred_{gpo_name}",
                    tags=["gpp", "credential"],
                    raw_data=finding,
                )
            return

        if any(x in finding_lower for x in ["script", "scheduled task", "immediate task"]):
            yield Misconfiguration(
                title=f"GPO Script/Task in {gpo_name}",
                description=f"{finding_type}: {description}\nSetting: {setting}",
                severity=severity,
                source="grouper2",
                check_id=f"gpo_script_{gpo_name}",
                tags=["gpo", "script"],
                raw_data=finding,
            )
            return

        if any(x in finding_lower for x in ["privilege", "user right", "sepriv"]):
            yield Misconfiguration(
                title=f"Privilege Assignment in {gpo_name}",
                description=f"{finding_type}: {description}\n{setting}: {value}",
                severity=severity,
                source="grouper2",
                check_id=f"gpo_priv_{gpo_name}",
                tags=["gpo", "privilege"],
                raw_data=finding,
            )
            return

        if any(x in finding_lower for x in ["registry", "reg "]):
            yield Misconfiguration(
                title=f"Registry Setting in {gpo_name}",
                description=f"{finding_type}: {description}\n{setting}: {value}",
                severity=severity,
                source="grouper2",
                check_id=f"gpo_reg_{gpo_name}",
                tags=["gpo", "registry"],
                raw_data=finding,
            )
            return

        if any(x in finding_lower for x in ["file", "folder", "share", "path"]):
            yield Misconfiguration(
                title=f"File/Share Config in {gpo_name}",
                description=f"{finding_type}: {description}\n{setting}: {value}",
                severity=severity,
                source="grouper2",
                check_id=f"gpo_file_{gpo_name}",
                tags=["gpo", "file"],
                raw_data=finding,
            )
            return

        if any(x in desc_lower for x in ["interesting", "vuln", "attack", "abuse"]):
            yield Vulnerability(
                title=f"GPO Vulnerability: {gpo_name}",
                description=f"{finding_type}: {description}",
                severity=severity,
                source="grouper2",
                tags=["gpo"],
                raw_data=finding,
            )
            return

        yield Misconfiguration(
            title=f"GPO Finding: {gpo_name}",
            description=f"{finding_type}: {description}\n{setting}: {value}".strip(),
            severity=severity,
            source="grouper2",
            check_id=f"gpo_{gpo_name}",
            tags=["gpo"],
            raw_data=finding,
        )

    def _parse_html(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Grouper2 HTML output (basic extraction)."""
        content = file_path.read_text(errors="ignore")

        gpo_pattern = re.compile(
            r"<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?</tr>",
            re.DOTALL | re.IGNORECASE
        )

        for match in gpo_pattern.finditer(content):
            gpo_name = match.group(1).strip()
            finding_type = match.group(2).strip()
            detail = match.group(3).strip()

            if gpo_name and finding_type and gpo_name != "GPO Name":
                yield Misconfiguration(
                    title=f"GPO Finding: {gpo_name}",
                    description=f"{finding_type}: {detail}",
                    severity="medium",
                    source="grouper2",
                    check_id=f"gpo_{gpo_name}",
                    tags=["gpo"],
                )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Grouper2 output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".json", ".html"]:
            return False

        if "grouper" in file_path.name.lower() or "gpo_audit" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"Grouper",
                    b"grouper",
                    b"GPOName",
                    b"GpoName",
                    b"FindingType",
                    b"FindingDetail",
                    b"cpassword",
                    b"CPassword",
                    b"ScheduledTask",
                    b"ImmediateTask",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
