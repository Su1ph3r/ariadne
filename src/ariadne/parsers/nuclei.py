"""Nuclei JSON output parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class NucleiParser(BaseParser):
    """Parser for Nuclei JSON/JSONL output files."""

    name = "nuclei"
    description = "Parse Nuclei vulnerability scanner output"
    file_patterns = ["*.json", "*.jsonl", "nuclei_*.json", "*nuclei*.json"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Nuclei JSON/JSONL file and yield entities."""
        content = file_path.read_text()

        findings = []
        if content.strip().startswith("["):
            findings = json.loads(content)
        else:
            for line in content.strip().split("\n"):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        seen_hosts: dict[str, Host] = {}

        for finding in findings:
            host = self._extract_host(finding, seen_hosts)
            if host and host.id not in seen_hosts:
                seen_hosts[host.id] = host
                yield host

            vuln = self._parse_finding(finding, host.id if host else None)
            if vuln:
                yield vuln

    def _extract_host(self, finding: dict, seen: dict[str, Host]) -> Host | None:
        """Extract host information from a finding."""
        host_str = finding.get("host", "")
        if not host_str:
            return None

        from urllib.parse import urlparse

        try:
            parsed = urlparse(host_str)
            hostname = parsed.hostname or host_str
        except Exception:
            hostname = host_str

        if hostname in seen:
            return seen[hostname]

        ip = finding.get("ip", "")

        return Host(
            ip=ip or hostname,
            hostname=hostname if hostname != ip else None,
            source="nuclei",
        )

    def _parse_finding(self, finding: dict, host_id: str | None) -> Vulnerability | Misconfiguration | None:
        """Parse a single Nuclei finding."""
        template_id = finding.get("template-id", finding.get("templateID", ""))
        info = finding.get("info", {})

        name = info.get("name", template_id)
        severity = info.get("severity", "info").lower()
        description = info.get("description", "")
        matched_at = finding.get("matched-at", finding.get("matched", ""))

        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        cve_ids = [t for t in tags if t.upper().startswith("CVE-")]
        cve_id = cve_ids[0] if cve_ids else None

        cvss_score = None
        classification = info.get("classification", {})
        if classification:
            cvss_score = classification.get("cvss-score")

        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]

        is_misconfig = "misconfig" in tags or severity == "info"

        if is_misconfig and not cve_id:
            return Misconfiguration(
                title=name,
                description=description or f"Found at: {matched_at}",
                severity=severity,
                affected_asset_id=host_id,
                template_id=template_id,
                tags=tags,
                source="nuclei",
            )

        return Vulnerability(
            cve_id=cve_id,
            title=name,
            description=description or f"Found at: {matched_at}",
            severity=severity,
            cvss_score=cvss_score,
            affected_asset_id=host_id,
            references=references,
            template_id=template_id,
            tags=tags,
            source="nuclei",
        )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Nuclei output file."""
        if file_path.suffix.lower() not in [".json", ".jsonl"]:
            return False

        try:
            with open(file_path) as f:
                first_line = f.readline()
                if not first_line.strip():
                    return False

                if first_line.strip().startswith("["):
                    data = json.loads(f.read())
                    if data and isinstance(data, list) and len(data) > 0:
                        return "template-id" in data[0] or "templateID" in data[0]
                else:
                    data = json.loads(first_line)
                    return "template-id" in data or "templateID" in data
        except Exception:
            return False

        return False
