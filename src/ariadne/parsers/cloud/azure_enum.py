"""Azure enumeration tool parsers (AzureHound, ROADtools, etc.)."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import CloudResource, User
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class AzureEnumParser(BaseParser):
    """Parser for Azure enumeration tool outputs (AzureHound, ROADtools)."""

    name = "azure_enum"
    description = "Parse Azure enumeration results (AzureHound, ROADtools)"
    file_patterns = ["*azurehound*.json", "*roadtools*.json", "azure_*.json"]
    entity_types = ["CloudResource", "User", "Relationship"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Azure enumeration results."""
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            for item in data:
                yield from self._parse_item(item)
        elif isinstance(data, dict):
            if "value" in data:
                for item in data["value"]:
                    yield from self._parse_item(item)
            else:
                yield from self._parse_item(data)

    def _parse_item(self, item: dict) -> Generator[Entity, None, None]:
        """Parse a single Azure object."""
        odata_type = item.get("@odata.type", "").lower()
        object_type = item.get("ObjectType", item.get("objectType", "")).lower()

        if "user" in odata_type or object_type == "user":
            yield from self._parse_user(item)
        elif "serviceprincipal" in odata_type or object_type == "serviceprincipal":
            yield from self._parse_service_principal(item)
        elif "application" in odata_type or object_type == "application":
            yield from self._parse_application(item)
        elif "group" in odata_type or object_type == "group":
            yield from self._parse_group(item)
        elif "subscription" in object_type or "resourcegroup" in object_type:
            yield from self._parse_azure_resource(item)

    def _parse_user(self, item: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD user."""
        user = User(
            username=item.get("userPrincipalName", item.get("mail", "")),
            display_name=item.get("displayName"),
            enabled=item.get("accountEnabled", True),
            domain=self._extract_tenant(item),
            object_id=item.get("id", item.get("objectId")),
            source="azure",
            raw_properties=item,
        )
        yield user

    def _parse_service_principal(self, item: dict) -> Generator[Entity, None, None]:
        """Parse an Azure service principal."""
        resource = CloudResource(
            resource_id=item.get("id", item.get("objectId", "")),
            resource_type="ServicePrincipal",
            name=item.get("displayName"),
            provider="azure",
            tenant_id=item.get("appOwnerTenantId"),
            app_id=item.get("appId"),
            source="azure",
            raw_properties=item,
        )
        yield resource

    def _parse_application(self, item: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD application."""
        resource = CloudResource(
            resource_id=item.get("id", item.get("objectId", "")),
            resource_type="Application",
            name=item.get("displayName"),
            provider="azure",
            app_id=item.get("appId"),
            source="azure",
            raw_properties=item,
        )
        yield resource

    def _parse_group(self, item: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD group."""
        resource = CloudResource(
            resource_id=item.get("id", item.get("objectId", "")),
            resource_type="Group",
            name=item.get("displayName"),
            provider="azure",
            source="azure",
            raw_properties=item,
        )
        yield resource

        for member in item.get("members", []):
            member_id = member.get("id", member.get("objectId", member)) if isinstance(member, dict) else member
            yield Relationship(
                source_id=str(member_id),
                target_id=resource.id,
                relation_type=RelationType.MEMBER_OF,
            )

    def _parse_azure_resource(self, item: dict) -> Generator[Entity, None, None]:
        """Parse a generic Azure resource."""
        resource = CloudResource(
            resource_id=item.get("id", item.get("resourceId", "")),
            resource_type=item.get("type", item.get("ObjectType", "Unknown")),
            name=item.get("name", item.get("displayName")),
            provider="azure",
            region=item.get("location"),
            subscription_id=item.get("subscriptionId"),
            source="azure",
            raw_properties=item,
        )
        yield resource

    def _extract_tenant(self, item: dict) -> str | None:
        """Extract tenant ID or domain from Azure object."""
        upn = item.get("userPrincipalName", "")
        if "@" in upn:
            return upn.split("@")[1]
        return item.get("tenantId")

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an Azure enumeration file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path) as f:
                data = json.load(f)

                if isinstance(data, list) and len(data) > 0:
                    sample = data[0]
                elif isinstance(data, dict) and "value" in data and len(data["value"]) > 0:
                    sample = data["value"][0]
                elif isinstance(data, dict):
                    sample = data
                else:
                    return False

                azure_indicators = [
                    "@odata.type",
                    "userPrincipalName",
                    "appOwnerTenantId",
                    "tenantId",
                    "subscriptionId",
                ]
                return any(indicator in sample for indicator in azure_indicators)
        except Exception:
            return False
