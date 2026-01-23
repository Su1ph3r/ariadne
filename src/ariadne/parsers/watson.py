"""Watson missing patch enumeration output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host
from ariadne.models.finding import Vulnerability
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class WatsonParser(BaseParser):
    """Parser for Watson missing Windows patches enumeration."""

    name = "watson"
    description = "Parse Watson Windows missing patch enumeration for privilege escalation"
    file_patterns = ["*watson*.txt", "*watson*.json", "*Watson*.txt"]
    entity_types = ["Host", "Vulnerability"]

    OS_PATTERN = re.compile(
        r"(?:OS|Operating\s+System)[:\s]+(?P<os>[^\r\n]+)",
        re.IGNORECASE
    )

    BUILD_PATTERN = re.compile(
        r"(?:Build|Version)[:\s]+(?P<build>\d+)",
        re.IGNORECASE
    )

    VULN_PATTERN = re.compile(
        r"\[(?:\*|\+|!)\]\s*(?P<cve>(?:CVE-\d{4}-\d+|MS\d{2}-\d{3}|KB\d+))[:\s]*(?P<desc>[^\r\n]+)?",
        re.IGNORECASE
    )

    KB_PATTERN = re.compile(
        r"(?:Missing|Vulnerable|Not\s+Installed)[:\s]*(?P<kb>KB\d+)",
        re.IGNORECASE
    )

    EXPLOIT_PATTERN = re.compile(
        r"(?:Exploit|PoC|Reference)[:\s]*(?P<url>https?://[^\s\r\n]+)",
        re.IGNORECASE
    )

    KNOWN_PRIVESC_CVES = {
        "CVE-2019-0836": ("high", "Windows Kernel Elevation of Privilege"),
        "CVE-2019-0841": ("high", "Windows AppX Deployment Service Elevation of Privilege"),
        "CVE-2019-1064": ("high", "Windows AppX Deployment Service Elevation of Privilege"),
        "CVE-2019-1130": ("high", "Windows AppX Deployment Service Elevation of Privilege"),
        "CVE-2019-1253": ("high", "Windows AppX Deployment Service Elevation of Privilege"),
        "CVE-2019-1315": ("high", "Windows Error Reporting Elevation of Privilege"),
        "CVE-2019-1322": ("high", "Windows Services Elevation of Privilege"),
        "CVE-2019-1385": ("high", "Windows AppX Deployment Extensions Elevation of Privilege"),
        "CVE-2019-1388": ("high", "Windows Certificate Dialog Elevation of Privilege"),
        "CVE-2019-1405": ("high", "Windows UPnP Service Elevation of Privilege"),
        "CVE-2019-1129": ("high", "Windows AppX Deployment Service Elevation of Privilege"),
        "CVE-2020-0668": ("high", "Windows Kernel Elevation of Privilege"),
        "CVE-2020-0683": ("high", "Windows Installer Elevation of Privilege"),
        "CVE-2020-0787": ("high", "Windows BITS Elevation of Privilege - BitsArbitrary"),
        "CVE-2020-0796": ("critical", "SMBGhost - Windows SMBv3 Remote Code Execution"),
        "CVE-2020-1472": ("critical", "Zerologon - Netlogon Elevation of Privilege"),
        "CVE-2020-1048": ("high", "Windows Print Spooler Elevation of Privilege"),
        "CVE-2021-1675": ("critical", "PrintNightmare - Windows Print Spooler RCE"),
        "CVE-2021-34527": ("critical", "PrintNightmare - Windows Print Spooler RCE"),
        "CVE-2021-36934": ("high", "HiveNightmare/SeriousSAM - SAM/SYSTEM ACL"),
        "CVE-2021-1732": ("high", "Windows Win32k Elevation of Privilege"),
        "CVE-2021-33739": ("high", "Windows DWM Core Library Elevation of Privilege"),
        "CVE-2021-40449": ("high", "Win32k Elevation of Privilege"),
        "CVE-2022-21882": ("high", "Win32k Elevation of Privilege"),
        "CVE-2022-21919": ("high", "Windows User Profile Service Elevation of Privilege"),
        "CVE-2022-26904": ("high", "Windows User Profile Service Elevation of Privilege"),
        "MS14-058": ("high", "Win32k.sys Elevation of Privilege"),
        "MS15-051": ("high", "Win32k.sys Elevation of Privilege"),
        "MS16-032": ("high", "Secondary Logon Handle Elevation of Privilege"),
        "MS16-034": ("high", "Windows Kernel-Mode Drivers Elevation of Privilege"),
        "MS16-135": ("high", "Win32k.sys Elevation of Privilege"),
        "MS17-010": ("critical", "EternalBlue - SMBv1 Remote Code Execution"),
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Watson output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse Watson JSON output."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        host = None
        if isinstance(data, dict):
            os_info = data.get("OS") or data.get("OperatingSystem") or ""
            build = data.get("Build") or data.get("BuildNumber") or ""
            hostname = data.get("Hostname") or data.get("ComputerName") or ""

            if hostname or os_info:
                host = Host(
                    ip="",
                    hostname=hostname if hostname else None,
                    os=f"{os_info} Build {build}" if build else os_info,
                    source="watson",
                    tags=["enumerated"],
                )
                yield host

            vulns = data.get("Vulnerabilities") or data.get("vulnerabilities") or data.get("CVEs") or []
            if isinstance(vulns, list):
                for vuln in vulns:
                    yield from self._parse_vuln_entry(vuln, host)

    def _parse_vuln_entry(self, vuln: dict, host: Host | None) -> Generator[Entity, None, None]:
        """Parse a single vulnerability entry."""
        cve = vuln.get("CVE") or vuln.get("cve") or vuln.get("ID") or ""
        description = vuln.get("Description") or vuln.get("description") or ""
        exploit_url = vuln.get("Exploit") or vuln.get("exploit") or vuln.get("URL") or ""
        kb = vuln.get("KB") or vuln.get("kb") or ""

        if cve in self.KNOWN_PRIVESC_CVES:
            severity, desc = self.KNOWN_PRIVESC_CVES[cve]
            description = description or desc
        else:
            severity = "high"

        yield Vulnerability(
            title=f"Missing Patch: {cve}",
            description=f"{description}\nMissing KB: {kb}" if kb else description,
            cve=cve if cve.startswith("CVE-") else None,
            severity=severity,
            affected_asset_id=host.id if host else None,
            source="watson",
            tags=["privesc", "missing-patch"],
            raw_data={
                "exploit_url": exploit_url,
                "kb": kb,
            },
        )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse Watson text output."""
        host = None
        seen_vulns: set[str] = set()

        os_match = self.OS_PATTERN.search(content)
        build_match = self.BUILD_PATTERN.search(content)

        if os_match:
            os_info = os_match.group("os").strip()
            build = build_match.group("build") if build_match else ""

            host = Host(
                ip="",
                hostname="",
                os=f"{os_info} Build {build}" if build else os_info,
                source="watson",
                tags=["enumerated"],
            )
            yield host

        for match in self.VULN_PATTERN.finditer(content):
            cve = match.group("cve").upper()
            desc = match.group("desc") or ""

            if cve in seen_vulns:
                continue
            seen_vulns.add(cve)

            if cve in self.KNOWN_PRIVESC_CVES:
                severity, known_desc = self.KNOWN_PRIVESC_CVES[cve]
                desc = desc or known_desc
            else:
                severity = "high"

            following_text = content[match.end():match.end() + 500]
            exploit_match = self.EXPLOIT_PATTERN.search(following_text)
            exploit_url = exploit_match.group("url") if exploit_match else ""

            yield Vulnerability(
                title=f"Missing Patch: {cve}",
                description=desc.strip(),
                cve=cve if cve.startswith("CVE-") else None,
                severity=severity,
                affected_asset_id=host.id if host else None,
                source="watson",
                tags=["privesc", "missing-patch"],
                raw_data={"exploit_url": exploit_url},
            )

        for match in self.KB_PATTERN.finditer(content):
            kb = match.group("kb").upper()

            if kb in seen_vulns:
                continue
            seen_vulns.add(kb)

            yield Vulnerability(
                title=f"Missing Patch: {kb}",
                description=f"Security update {kb} is not installed",
                severity="medium",
                affected_asset_id=host.id if host else None,
                source="watson",
                tags=["missing-patch"],
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Watson output file."""
        name_lower = file_path.name.lower()
        if "watson" in name_lower:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"Watson",
                    b"watson",
                    b"CVE-",
                    b"MS1",
                    b"[*] OS",
                    b"[*] Build",
                    b"Vulnerabilities",
                    b"Missing Patch",
                    b"Elevation of Privilege",
                    b"PrintNightmare",
                    b"EternalBlue",
                    b"Zerologon",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
