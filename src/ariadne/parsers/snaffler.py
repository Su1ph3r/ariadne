"""Snaffler file share secret hunter output parser."""

import csv
import io
import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class SnafflerParser(BaseParser):
    """Parser for Snaffler share enumeration and secret finding output."""

    name = "snaffler"
    description = "Parse Snaffler file share secret hunting output"
    file_patterns = ["*snaffler*.txt", "*snaffler*.log", "*snaffler*.json", "*snaffler*.csv"]
    entity_types = ["Host", "Credential", "Misconfiguration"]

    SEVERITY_MAP = {
        "black": "critical",
        "red": "critical",
        "orange": "high",
        "yellow": "medium",
        "green": "low",
        "blue": "info",
        "white": "info",
    }

    FILE_PATTERN = re.compile(
        r"\[(?P<severity>\w+)\]\s*"
        r"(?:\[(?P<rule>\w+)\])?\s*"
        r"(?P<path>\\\\[^\s]+)",
        re.IGNORECASE
    )

    UNC_PATTERN = re.compile(r"\\\\([^\\]+)\\([^\\]+)")

    CRED_INDICATORS = [
        "password", "passwd", "pwd", "secret", "credential", "cred",
        "api_key", "apikey", "token", "auth", "private", "id_rsa",
        ".kdbx", ".pfx", ".p12", ".pem", ".key", "web.config",
        "appsettings", "connectionstring", "unattend", "sysprep",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Snaffler output file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            yield from self._parse_json(file_path)
        elif suffix == ".csv":
            yield from self._parse_csv(file_path)
        else:
            yield from self._parse_text(file_path)

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Snaffler JSON output."""
        with open(file_path) as f:
            data = json.load(f)

        entries = data if isinstance(data, list) else [data]
        seen_hosts: dict[str, Host] = {}

        for entry in entries:
            yield from self._process_entry(entry, seen_hosts)

    def _parse_csv(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Snaffler CSV output."""
        content = file_path.read_text(errors="ignore")
        reader = csv.DictReader(io.StringIO(content))

        seen_hosts: dict[str, Host] = {}

        for row in reader:
            entry = {
                "path": row.get("Path") or row.get("FilePath") or row.get("FullPath", ""),
                "severity": row.get("Triage") or row.get("Severity") or row.get("Color", "yellow"),
                "rule": row.get("Rule") or row.get("MatchedRule", ""),
                "context": row.get("MatchContext") or row.get("Context", ""),
            }
            yield from self._process_entry(entry, seen_hosts)

    def _parse_text(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Snaffler text output."""
        content = file_path.read_text(errors="ignore")
        seen_hosts: dict[str, Host] = {}

        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            match = self.FILE_PATTERN.search(line)
            if match:
                entry = {
                    "severity": match.group("severity"),
                    "rule": match.group("rule") or "",
                    "path": match.group("path"),
                }
                yield from self._process_entry(entry, seen_hosts)

            elif line.startswith("\\\\"):
                parts = line.split()
                if parts:
                    entry = {
                        "path": parts[0],
                        "severity": "yellow",
                        "rule": "",
                    }
                    yield from self._process_entry(entry, seen_hosts)

    def _process_entry(self, entry: dict, seen_hosts: dict[str, Host]) -> Generator[Entity, None, None]:
        """Process a single Snaffler finding entry."""
        path = entry.get("path", "") or entry.get("Path", "") or entry.get("FilePath", "")
        if not path:
            return

        severity_color = (entry.get("severity", "") or entry.get("Triage", "") or "yellow").lower()
        severity = self.SEVERITY_MAP.get(severity_color, "medium")

        rule = entry.get("rule", "") or entry.get("Rule", "") or entry.get("MatchedRule", "")
        context = entry.get("context", "") or entry.get("MatchContext", "") or entry.get("Content", "")

        unc_match = self.UNC_PATTERN.search(path)
        if unc_match:
            hostname = unc_match.group(1)
            share = unc_match.group(2)

            if hostname not in seen_hosts:
                host = Host(
                    ip="",
                    hostname=hostname,
                    source="snaffler",
                    tags=["file-share"],
                )
                seen_hosts[hostname] = host
                yield host
            host = seen_hosts[hostname]
        else:
            host = None
            hostname = "unknown"
            share = ""

        filename = path.split("\\")[-1].lower() if "\\" in path else path.lower()

        is_credential_file = any(ind in filename or ind in path.lower() for ind in self.CRED_INDICATORS)

        if is_credential_file or severity_color in ["black", "red"]:
            yield Credential(
                title=f"Sensitive file: {filename}",
                description=f"Found at: {path}",
                credential_type="file",
                value=path,
                severity=severity,
                affected_asset_id=host.id if host else None,
                source="snaffler",
                tags=["file-share", rule] if rule else ["file-share"],
                raw_data={
                    "full_path": path,
                    "rule": rule,
                    "context": context[:500] if context else "",
                    "share": share,
                },
            )
        else:
            yield Misconfiguration(
                title=f"Interesting file found: {filename}",
                description=f"Path: {path}\nRule: {rule}" + (f"\nContext: {context[:200]}" if context else ""),
                severity=severity,
                affected_asset_id=host.id if host else None,
                source="snaffler",
                check_id=rule or "snaffler_finding",
                raw_data={
                    "full_path": path,
                    "rule": rule,
                    "share": share,
                },
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Snaffler output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".txt", ".log", ".json", ".csv", ""]:
            return False

        if "snaffler" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"Snaffler",
                    b"[Black]",
                    b"[Red]",
                    b"[Yellow]",
                    b"[Green]",
                    b"KeepExtExact",
                    b"KeepRegex",
                    b"DiscardRegex",
                    b"MatchedRule",
                    b"FilePath",
                    b"MatchContext",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
