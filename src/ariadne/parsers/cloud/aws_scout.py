"""AWS ScoutSuite output parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import CloudResource
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class AWSScoutParser(BaseParser):
    """Parser for ScoutSuite AWS scan results."""

    name = "aws_scout"
    description = "Parse ScoutSuite AWS security audit results"
    file_patterns = ["scoutsuite_results_*.json", "scoutsuite-results/*.json"]
    entity_types = ["CloudResource", "Misconfiguration", "Relationship"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse ScoutSuite results and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        account_id = data.get("account_id", "unknown")

        services = data.get("services", {})

        for service_name, service_data in services.items():
            yield from self._parse_service(service_name, service_data, account_id)

    def _parse_service(
        self, service_name: str, service_data: dict, account_id: str
    ) -> Generator[Entity, None, None]:
        """Parse a single AWS service."""
        findings = service_data.get("findings", {})

        for finding_key, finding_data in findings.items():
            if finding_data.get("flagged_items", 0) > 0:
                items = finding_data.get("items", [])

                for item in items:
                    resource = CloudResource(
                        resource_id=item,
                        resource_type=service_name,
                        provider="aws",
                        account_id=account_id,
                        region=self._extract_region(item),
                        source="scoutsuite",
                    )
                    yield resource

                    yield Misconfiguration(
                        title=finding_key.replace("_", " ").title(),
                        description=finding_data.get("description", ""),
                        severity=self._map_severity(finding_data.get("level", "warning")),
                        affected_asset_id=resource.id,
                        check_id=finding_key,
                        rationale=finding_data.get("rationale", ""),
                        remediation=finding_data.get("remediation", ""),
                        source="scoutsuite",
                    )

    def _extract_region(self, arn_or_id: str) -> str | None:
        """Extract AWS region from ARN or resource ID."""
        if arn_or_id.startswith("arn:aws:"):
            parts = arn_or_id.split(":")
            if len(parts) >= 4:
                return parts[3] if parts[3] else None
        return None

    def _map_severity(self, level: str) -> str:
        """Map ScoutSuite level to standard severity."""
        mapping = {
            "danger": "critical",
            "warning": "medium",
            "info": "info",
        }
        return mapping.get(level.lower(), "info")

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a ScoutSuite results file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path) as f:
                data = json.load(f)
                return (
                    isinstance(data, dict)
                    and "services" in data
                    and ("account_id" in data or "provider_name" in data)
                )
        except Exception:
            return False
