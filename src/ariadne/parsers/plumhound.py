"""PlumHound BloodHound query results parser."""

import csv
import io
import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration, Vulnerability
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class PlumHoundParser(BaseParser):
    """Parser for PlumHound BloodHound query results (CSV/JSON)."""

    name = "plumhound"
    description = "Parse PlumHound BloodHound automated query results"
    file_patterns = ["*plumhound*.csv", "*plumhound*.json", "*PlumHound*.csv", "*PlumHound*.json"]
    entity_types = ["Host", "User", "Misconfiguration", "Vulnerability"]

    CRITICAL_QUERIES = [
        "domain admins",
        "dcsync",
        "unconstrained",
        "kerberoastable",
        "asreproast",
        "gpo abuse",
        "high value",
        "shortest path",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a PlumHound output file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            yield from self._parse_json(file_path)
        else:
            yield from self._parse_csv(file_path)

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse PlumHound JSON output."""
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            for entry in data:
                yield from self._parse_entry(entry)
        elif isinstance(data, dict):
            if "results" in data:
                for entry in data["results"]:
                    yield from self._parse_entry(entry)
            else:
                yield from self._parse_entry(data)

    def _parse_csv(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse PlumHound CSV output."""
        content = file_path.read_text(errors="ignore")
        reader = csv.DictReader(io.StringIO(content))

        filename = file_path.stem.lower()

        for row in reader:
            yield from self._parse_csv_row(row, filename)

    def _parse_entry(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a single JSON entry."""
        query_name = entry.get("query") or entry.get("title") or entry.get("name", "")
        results = entry.get("results") or entry.get("data", [])

        if isinstance(results, list):
            for result in results:
                yield from self._parse_result(result, query_name)
        elif isinstance(results, dict):
            yield from self._parse_result(results, query_name)

    def _parse_result(self, result: dict, query_name: str) -> Generator[Entity, None, None]:
        """Parse a query result entry."""
        node_type = result.get("type") or result.get("label") or ""
        name = result.get("name") or result.get("Name") or ""

        if not name:
            for key in result:
                if "name" in key.lower():
                    name = result[key]
                    break

        if not name:
            return

        is_critical = any(crit in query_name.lower() for crit in self.CRITICAL_QUERIES)
        severity = "critical" if is_critical else "high"

        if node_type.lower() in ["user", "azureuser"] or "@" in name:
            domain = None
            username = name
            if "@" in name:
                username, domain = name.split("@", 1)
            elif "\\" in name:
                domain, username = name.split("\\", 1)

            user = User(
                username=username,
                domain=domain,
                source="plumhound",
                tags=["bloodhound-finding"],
            )
            yield user

            yield Misconfiguration(
                title=f"{query_name}: {name}",
                description=f"User {name} identified by PlumHound query: {query_name}",
                severity=severity,
                affected_asset_id=user.id,
                source="plumhound",
                check_id=query_name.replace(" ", "_").lower(),
            )

        elif node_type.lower() in ["computer", "host"]:
            hostname = name.rstrip("$")

            host = Host(
                ip="",
                hostname=hostname,
                source="plumhound",
                tags=["bloodhound-finding"],
            )
            yield host

            yield Misconfiguration(
                title=f"{query_name}: {hostname}",
                description=f"Computer {hostname} identified by PlumHound query: {query_name}",
                severity=severity,
                affected_asset_id=host.id,
                source="plumhound",
                check_id=query_name.replace(" ", "_").lower(),
            )

        elif node_type.lower() in ["group", "azuregroup"]:
            yield Misconfiguration(
                title=f"{query_name}: {name}",
                description=f"Group {name} identified in attack path",
                severity=severity,
                source="plumhound",
                check_id=query_name.replace(" ", "_").lower(),
                raw_data=result,
            )

    def _parse_csv_row(self, row: dict, filename: str) -> Generator[Entity, None, None]:
        """Parse a CSV row based on column headers."""
        user_cols = ["UserName", "User", "SamAccountName", "name"]
        computer_cols = ["ComputerName", "Computer", "HostName", "DNSHostName"]

        for col in user_cols:
            if col in row and row[col]:
                name = row[col]
                domain = row.get("Domain") or row.get("domain")

                user = User(
                    username=name.split("@")[0] if "@" in name else name,
                    domain=domain or (name.split("@")[1] if "@" in name else None),
                    source="plumhound",
                    tags=["bloodhound-finding"],
                )
                yield user

                query_name = self._query_from_filename(filename)
                is_critical = any(crit in filename for crit in self.CRITICAL_QUERIES)

                yield Misconfiguration(
                    title=f"{query_name}: {name}",
                    description=f"User identified by PlumHound: {query_name}",
                    severity="critical" if is_critical else "high",
                    affected_asset_id=user.id,
                    source="plumhound",
                    check_id=query_name,
                )
                break

        for col in computer_cols:
            if col in row and row[col]:
                hostname = row[col].rstrip("$")

                host = Host(
                    ip="",
                    hostname=hostname,
                    domain=row.get("Domain"),
                    source="plumhound",
                    tags=["bloodhound-finding"],
                )
                yield host

                query_name = self._query_from_filename(filename)
                is_critical = any(crit in filename for crit in self.CRITICAL_QUERIES)

                yield Misconfiguration(
                    title=f"{query_name}: {hostname}",
                    description=f"Computer identified by PlumHound: {query_name}",
                    severity="critical" if is_critical else "high",
                    affected_asset_id=host.id,
                    source="plumhound",
                    check_id=query_name,
                )
                break

        if "Path" in row or "path" in row or "relationship" in str(row).lower():
            path_desc = row.get("Path") or row.get("path") or str(row)
            yield Misconfiguration(
                title=f"Attack Path: {self._query_from_filename(filename)}",
                description=path_desc[:500],
                severity="high",
                source="plumhound",
                check_id="attack_path",
                raw_data=row,
            )

    def _query_from_filename(self, filename: str) -> str:
        """Extract query name from filename."""
        name = filename.replace("plumhound", "").replace("_", " ").replace("-", " ")
        return name.strip().title() or "BloodHound Query"

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a PlumHound output file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".csv", ".json"]:
            return False

        if "plumhound" in file_path.name.lower():
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"PlumHound",
                    b"plumhound",
                    b"BloodHound",
                    b"bloodhound",
                    b"DomainAdmins",
                    b"Kerberoast",
                    b"ASREPRoast",
                    b"ShortestPath",
                    b"HighValue",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
