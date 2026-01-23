"""AzureHound JSON output parser for Azure AD enumeration."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User, CloudResource
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class AzureHoundParser(BaseParser):
    """Parser for AzureHound Azure AD enumeration JSON files."""

    name = "azurehound"
    description = "Parse AzureHound Azure AD BloodHound data"
    file_patterns = [
        "*azurehound*.json",
        "*azure_*.json",
        "*_azusers.json",
        "*_azgroups.json",
        "*_azapps.json",
        "*_azdevices.json",
    ]
    entity_types = ["User", "CloudResource", "Host", "Misconfiguration"]

    PRIVILEGED_ROLES = [
        "global administrator",
        "privileged role administrator",
        "privileged authentication administrator",
        "application administrator",
        "cloud application administrator",
        "authentication administrator",
        "exchange administrator",
        "intune administrator",
        "azure ad joined device local administrator",
        "password administrator",
        "user administrator",
        "helpdesk administrator",
    ]

    DANGEROUS_PERMISSIONS = [
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Group.ReadWrite.All",
        "GroupMember.ReadWrite.All",
        "User.ReadWrite.All",
        "RoleAssignmentSchedule.ReadWrite.Directory",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an AzureHound JSON file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, dict):
            if "data" in data:
                entries = data["data"]
            elif "value" in data:
                entries = data["value"]
            else:
                entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            return

        for entry in entries:
            kind = entry.get("kind", "").lower()
            props = entry.get("Properties", entry.get("properties", entry))

            if kind == "azuser" or self._is_user(props):
                yield from self._parse_user(props)
            elif kind == "azgroup" or self._is_group(props):
                yield from self._parse_group(props)
            elif kind == "azapp" or kind == "azserviceprincipal" or self._is_app(props):
                yield from self._parse_app(props)
            elif kind == "azdevice" or self._is_device(props):
                yield from self._parse_device(props)
            elif kind == "azrole" or self._is_role(props):
                yield from self._parse_role(props)
            elif kind == "azvm" or self._is_vm(props):
                yield from self._parse_vm(props)
            elif kind == "azsubscription" or self._is_subscription(props):
                yield from self._parse_subscription(props)

    def _parse_user(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD user."""
        upn = props.get("userPrincipalName") or props.get("name") or props.get("displayname")
        if not upn:
            return

        object_id = props.get("objectid") or props.get("id")
        enabled = props.get("enabled", True)
        if isinstance(enabled, str):
            enabled = enabled.lower() == "true"

        is_admin = False
        admin_roles = props.get("adminroles", []) or props.get("roles", [])
        if admin_roles:
            is_admin = any(
                role.lower() in self.PRIVILEGED_ROLES
                for role in admin_roles
            )

        user = User(
            username=upn.split("@")[0] if "@" in upn else upn,
            domain=upn.split("@")[1] if "@" in upn else None,
            display_name=props.get("displayname"),
            email=props.get("mail") or props.get("userPrincipalName"),
            enabled=enabled,
            is_admin=is_admin,
            object_id=object_id,
            source="azurehound",
            tags=["azure-ad"],
            raw_properties={
                "upn": upn,
                "tenant_id": props.get("tenantid"),
                "on_premises_sync": props.get("onpremisessyncenabled"),
            },
        )
        yield user

        if props.get("passwordpolicies") and "DisablePasswordExpiration" in str(props.get("passwordpolicies")):
            yield Misconfiguration(
                title=f"Password never expires for {upn}",
                description=f"Azure AD user {upn} has password expiration disabled",
                severity="low",
                affected_asset_id=user.id,
                source="azurehound",
                check_id="password_never_expires",
            )

        if props.get("onpremisessyncenabled") is False and is_admin:
            yield Misconfiguration(
                title=f"Cloud-only privileged account: {upn}",
                description=f"Privileged Azure AD account {upn} is cloud-only (not synced from on-prem)",
                severity="info",
                affected_asset_id=user.id,
                source="azurehound",
                check_id="cloud_only_admin",
            )

    def _parse_group(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD group."""
        display_name = props.get("displayname") or props.get("name")
        if not display_name:
            return

        object_id = props.get("objectid") or props.get("id")

        resource = CloudResource(
            resource_id=object_id or display_name,
            resource_type="AzureADGroup",
            name=display_name,
            provider="azure",
            source="azurehound",
            tags=["azure-ad", "group"],
            raw_properties={
                "security_enabled": props.get("securityenabled"),
                "is_assignable_to_role": props.get("isassignabletorole"),
                "membership_rule": props.get("membershiprule"),
            },
        )
        yield resource

        if props.get("isassignabletorole"):
            yield Misconfiguration(
                title=f"Role-assignable group: {display_name}",
                description=f"Group {display_name} can be assigned Azure AD roles",
                severity="info",
                affected_asset_id=resource.id,
                source="azurehound",
                check_id="role_assignable_group",
            )

    def _parse_app(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD application or service principal."""
        display_name = props.get("displayname") or props.get("name")
        app_id = props.get("appid") or props.get("applicationId")
        object_id = props.get("objectid") or props.get("id")

        if not display_name and not app_id:
            return

        permissions = props.get("apppermissions", []) or props.get("permissions", [])

        resource = CloudResource(
            resource_id=object_id or app_id or display_name,
            resource_type="AzureADApp",
            name=display_name,
            provider="azure",
            app_id=app_id,
            permissions=permissions if isinstance(permissions, list) else [],
            source="azurehound",
            tags=["azure-ad", "application"],
        )
        yield resource

        dangerous_perms = [p for p in permissions if any(d in str(p) for d in self.DANGEROUS_PERMISSIONS)]
        if dangerous_perms:
            yield Misconfiguration(
                title=f"High-privilege app permissions: {display_name}",
                description=f"Application {display_name} has dangerous permissions: {', '.join(dangerous_perms[:5])}",
                severity="high",
                affected_asset_id=resource.id,
                source="azurehound",
                check_id="dangerous_app_permissions",
            )

        if props.get("passwordcredentials"):
            for cred in props.get("passwordcredentials", []):
                if cred.get("endDateTime"):
                    yield Misconfiguration(
                        title=f"App with client secret: {display_name}",
                        description=f"Application {display_name} uses client secret authentication",
                        severity="info",
                        affected_asset_id=resource.id,
                        source="azurehound",
                        check_id="app_client_secret",
                    )
                    break

    def _parse_device(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD device."""
        display_name = props.get("displayname") or props.get("name")
        device_id = props.get("deviceid") or props.get("id")

        if not display_name:
            return

        os_info = props.get("operatingsystem")
        os_version = props.get("operatingsystemversion")
        if os_info and os_version:
            os_info = f"{os_info} {os_version}"

        host = Host(
            ip="",
            hostname=display_name,
            os=os_info,
            source="azurehound",
            tags=["azure-ad", "device"],
            raw_properties={
                "device_id": device_id,
                "trust_type": props.get("trusttype"),
                "is_compliant": props.get("iscompliant"),
                "is_managed": props.get("ismanaged"),
            },
        )
        yield host

    def _parse_role(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure AD role."""
        display_name = props.get("displayname") or props.get("name")
        if not display_name:
            return

        resource = CloudResource(
            resource_id=props.get("objectid") or display_name,
            resource_type="AzureADRole",
            name=display_name,
            provider="azure",
            source="azurehound",
            tags=["azure-ad", "role"],
        )
        yield resource

    def _parse_vm(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure Virtual Machine."""
        name = props.get("name") or props.get("displayname")
        if not name:
            return

        host = Host(
            ip="",
            hostname=name,
            os=props.get("ostype"),
            source="azurehound",
            tags=["azure", "vm"],
            raw_properties={
                "resource_id": props.get("id"),
                "subscription": props.get("subscriptionid"),
                "resource_group": props.get("resourcegroup"),
            },
        )
        yield host

    def _parse_subscription(self, props: dict) -> Generator[Entity, None, None]:
        """Parse an Azure subscription."""
        display_name = props.get("displayname") or props.get("name")
        subscription_id = props.get("subscriptionid") or props.get("id")

        if not subscription_id:
            return

        resource = CloudResource(
            resource_id=subscription_id,
            resource_type="AzureSubscription",
            name=display_name,
            provider="azure",
            subscription_id=subscription_id,
            source="azurehound",
            tags=["azure", "subscription"],
        )
        yield resource

    def _is_user(self, props: dict) -> bool:
        return "userPrincipalName" in props or props.get("@odata.type") == "#microsoft.graph.user"

    def _is_group(self, props: dict) -> bool:
        return props.get("@odata.type") == "#microsoft.graph.group" or (
            "securityenabled" in props and "displayname" in props
        )

    def _is_app(self, props: dict) -> bool:
        return "appid" in props or props.get("@odata.type") in [
            "#microsoft.graph.application",
            "#microsoft.graph.servicePrincipal"
        ]

    def _is_device(self, props: dict) -> bool:
        return "deviceid" in props or props.get("@odata.type") == "#microsoft.graph.device"

    def _is_role(self, props: dict) -> bool:
        return props.get("@odata.type") == "#microsoft.graph.directoryRole"

    def _is_vm(self, props: dict) -> bool:
        return props.get("type") == "Microsoft.Compute/virtualMachines"

    def _is_subscription(self, props: dict) -> bool:
        return "subscriptionid" in props or props.get("type") == "Microsoft.Subscription"

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an AzureHound JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"azurehound",
                    b"AZUser",
                    b"AZGroup",
                    b"AZApp",
                    b"userPrincipalName",
                    b"tenantid",
                    b"@odata.type",
                    b"microsoft.graph",
                    b'"kind"',
                    b"AZDevice",
                    b"AZServicePrincipal",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
