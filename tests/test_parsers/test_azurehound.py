"""Tests for AzureHound parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.azurehound import AzureHoundParser
from ariadne.models.asset import Host, User, CloudResource
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestAzureHoundParser(BaseParserTest):
    """Test AzureHoundParser functionality."""

    parser_class = AzureHoundParser
    expected_name = "azurehound"
    expected_patterns = [
        "*azurehound*.json",
        "*azure_*.json",
        "*_azusers.json",
        "*_azgroups.json",
        "*_azapps.json",
        "*_azdevices.json",
    ]
    expected_entity_types = ["User", "CloudResource", "Host", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_azurehound_json(self, tmp_path: Path):
        """Test detection of AzureHound JSON file by filename."""
        data = {
            "kind": "AZUser",
            "Properties": {"userPrincipalName": "user@domain.com"}
        }
        json_file = tmp_path / "azurehound_export.json"
        json_file.write_text(json.dumps(data))

        assert AzureHoundParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        data = {
            "userPrincipalName": "admin@tenant.onmicrosoft.com",
            "tenantid": "12345-67890"
        }
        json_file = tmp_path / "users.json"
        json_file.write_text(json.dumps(data))

        assert AzureHoundParser.can_parse(json_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not AzureHoundParser.can_parse(json_file)

    # =========================================================================
    # User Parsing Tests
    # =========================================================================

    def test_parse_user(self, tmp_path: Path):
        """Test parsing Azure AD user."""
        data = {
            "kind": "AZUser",
            "Properties": {
                "userPrincipalName": "jsmith@contoso.com",
                "displayname": "John Smith",
                "mail": "jsmith@contoso.com",
                "objectid": "12345-67890",
                "enabled": True
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"
        assert users[0].domain == "contoso.com"
        assert "azure-ad" in users[0].tags

    def test_parse_user_by_upn_detection(self, tmp_path: Path):
        """Test user detection by userPrincipalName field."""
        data = {
            "userPrincipalName": "admin@tenant.onmicrosoft.com",
            "displayname": "Admin User"
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"

    def test_parse_admin_user(self, tmp_path: Path):
        """Test parsing user with admin roles."""
        data = {
            "kind": "AZUser",
            "Properties": {
                "userPrincipalName": "admin@contoso.com",
                "adminroles": ["Global Administrator"]
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].is_admin == True

    def test_parse_user_password_never_expires(self, tmp_path: Path):
        """Test misconfiguration for password never expires."""
        data = {
            "kind": "AZUser",
            "Properties": {
                "userPrincipalName": "user@contoso.com",
                "passwordpolicies": "DisablePasswordExpiration"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        pw_misconfig = [m for m in misconfigs if "never expires" in m.title.lower()]
        assert len(pw_misconfig) >= 1

    # =========================================================================
    # Group Parsing Tests
    # =========================================================================

    def test_parse_group(self, tmp_path: Path):
        """Test parsing Azure AD group."""
        data = {
            "kind": "AZGroup",
            "Properties": {
                "displayname": "IT Admins",
                "objectid": "group-12345",
                "securityenabled": True
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        resources = self.get_cloud_resources(entities)
        groups = [r for r in resources if r.resource_type == "AzureADGroup"]
        assert len(groups) >= 1
        assert groups[0].name == "IT Admins"

    def test_parse_role_assignable_group(self, tmp_path: Path):
        """Test misconfiguration for role-assignable group."""
        data = {
            "kind": "AZGroup",
            "Properties": {
                "displayname": "Privileged Group",
                "isassignabletorole": True
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        role_misconfig = [m for m in misconfigs if "Role-assignable" in m.title]
        assert len(role_misconfig) >= 1

    # =========================================================================
    # Application Parsing Tests
    # =========================================================================

    def test_parse_app(self, tmp_path: Path):
        """Test parsing Azure AD application."""
        data = {
            "kind": "AZApp",
            "Properties": {
                "displayname": "My App",
                "appid": "app-12345",
                "objectid": "obj-67890"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        resources = self.get_cloud_resources(entities)
        apps = [r for r in resources if r.resource_type == "AzureADApp"]
        assert len(apps) >= 1
        assert apps[0].name == "My App"

    def test_parse_app_with_dangerous_permissions(self, tmp_path: Path):
        """Test misconfiguration for app with dangerous permissions."""
        data = {
            "kind": "AZApp",
            "Properties": {
                "displayname": "Dangerous App",
                "appid": "app-12345",
                "apppermissions": [
                    "RoleManagement.ReadWrite.Directory",
                    "Application.ReadWrite.All"
                ]
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        perm_misconfig = [m for m in misconfigs if "High-privilege" in m.title]
        assert len(perm_misconfig) >= 1
        assert perm_misconfig[0].severity == "high"

    def test_parse_service_principal(self, tmp_path: Path):
        """Test parsing service principal."""
        data = {
            "kind": "AZServicePrincipal",
            "Properties": {
                "displayname": "Service Principal",
                "appid": "sp-12345"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        resources = self.get_cloud_resources(entities)
        assert len(resources) >= 1

    # =========================================================================
    # Device Parsing Tests
    # =========================================================================

    def test_parse_device(self, tmp_path: Path):
        """Test parsing Azure AD device."""
        data = {
            "kind": "AZDevice",
            "Properties": {
                "displayname": "WORKSTATION01",
                "deviceid": "device-12345",
                "operatingsystem": "Windows",
                "operatingsystemversion": "10.0.19043"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "WORKSTATION01"
        assert "Windows" in hosts[0].os
        assert "azure-ad" in hosts[0].tags

    # =========================================================================
    # VM Parsing Tests
    # =========================================================================

    def test_parse_vm(self, tmp_path: Path):
        """Test parsing Azure Virtual Machine."""
        data = {
            "kind": "AZVM",
            "Properties": {
                "name": "prod-web-01",
                "ostype": "Linux",
                "subscriptionid": "sub-12345"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "prod-web-01"
        assert "vm" in hosts[0].tags

    # =========================================================================
    # Subscription Parsing Tests
    # =========================================================================

    def test_parse_subscription(self, tmp_path: Path):
        """Test parsing Azure subscription."""
        data = {
            "kind": "AZSubscription",
            "Properties": {
                "displayname": "Production",
                "subscriptionid": "sub-12345-67890"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        resources = self.get_cloud_resources(entities)
        subs = [r for r in resources if r.resource_type == "AzureSubscription"]
        assert len(subs) >= 1
        assert subs[0].name == "Production"

    # =========================================================================
    # Multiple Entry Tests
    # =========================================================================

    def test_parse_data_wrapper(self, tmp_path: Path):
        """Test parsing entries inside data wrapper."""
        data = {
            "data": [
                {"kind": "AZUser", "Properties": {"userPrincipalName": "user1@contoso.com"}},
                {"kind": "AZUser", "Properties": {"userPrincipalName": "user2@contoso.com"}}
            ]
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_parse_value_wrapper(self, tmp_path: Path):
        """Test parsing entries inside value wrapper."""
        data = {
            "value": [
                {"userPrincipalName": "user@contoso.com", "@odata.type": "#microsoft.graph.user"}
            ]
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1

    def test_parse_array_format(self, tmp_path: Path):
        """Test parsing array of entries."""
        data = [
            {"kind": "AZUser", "Properties": {"userPrincipalName": "user@contoso.com"}},
            {"kind": "AZGroup", "Properties": {"displayname": "Group1"}}
        ]
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        resources = self.get_cloud_resources(entities)
        assert len(users) >= 1
        assert len(resources) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        json_file = tmp_path / "azurehound_empty.json"
        json_file.write_text("[]")

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_missing_upn(self, tmp_path: Path):
        """Test handling of user without UPN."""
        data = {
            "kind": "AZUser",
            "Properties": {"objectid": "12345"}
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        # Should not crash, may not produce user
        assert isinstance(entities, list)

    def test_handles_enabled_as_string(self, tmp_path: Path):
        """Test handling of enabled field as string."""
        data = {
            "kind": "AZUser",
            "Properties": {
                "userPrincipalName": "user@contoso.com",
                "enabled": "true"
            }
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].enabled == True

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_azurehound(self, tmp_path: Path):
        """Test that source is set to azurehound."""
        data = {
            "kind": "AZUser",
            "Properties": {"userPrincipalName": "user@contoso.com"}
        }
        json_file = tmp_path / "azurehound.json"
        json_file.write_text(json.dumps(data))

        parser = AzureHoundParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "azurehound"
