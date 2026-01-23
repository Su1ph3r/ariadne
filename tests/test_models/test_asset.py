"""Tests for asset models (Host, Service, User, CloudResource)."""

import pytest
from datetime import datetime

from ariadne.models.asset import Asset, Host, Service, User, CloudResource


class TestAssetBase:
    """Test base Asset class."""

    def test_asset_has_id(self):
        """Test Asset has auto-generated ID."""
        asset = Asset()
        assert asset.id is not None
        assert len(asset.id) > 0

    def test_asset_has_source(self):
        """Test Asset has default source."""
        asset = Asset()
        assert asset.source == "unknown"

    def test_asset_custom_source(self):
        """Test Asset with custom source."""
        asset = Asset(source="nmap")
        assert asset.source == "nmap"

    def test_asset_has_discovered_at(self):
        """Test Asset has discovered_at timestamp."""
        asset = Asset()
        assert asset.discovered_at is not None
        assert isinstance(asset.discovered_at, datetime)

    def test_asset_has_tags(self):
        """Test Asset has tags list."""
        asset = Asset()
        assert asset.tags == []

    def test_asset_custom_tags(self):
        """Test Asset with custom tags."""
        asset = Asset(tags=["critical", "external"])
        assert asset.tags == ["critical", "external"]

    def test_asset_has_raw_properties(self):
        """Test Asset has raw_properties dict."""
        asset = Asset()
        assert asset.raw_properties == {}

    def test_asset_custom_raw_properties(self):
        """Test Asset with custom raw_properties."""
        asset = Asset(raw_properties={"custom": "value"})
        assert asset.raw_properties == {"custom": "value"}

    def test_asset_allows_extra_fields(self):
        """Test Asset allows extra fields (model_config extra='allow')."""
        asset = Asset(custom_field="test")
        assert asset.custom_field == "test"


class TestHost:
    """Test Host model."""

    def test_host_id_generation_from_ip(self):
        """Test Host ID is generated from IP."""
        host = Host(ip="192.168.1.1")
        assert host.id == "host:192.168.1.1"

    def test_host_id_generation_from_hostname(self):
        """Test Host ID is generated from hostname when no IP."""
        host = Host(hostname="server.local")
        assert host.id == "host:server.local"

    def test_host_id_prefers_ip(self):
        """Test Host ID prefers IP over hostname."""
        host = Host(ip="192.168.1.1", hostname="server.local")
        assert host.id == "host:192.168.1.1"

    def test_host_with_all_fields(self):
        """Test Host with all fields populated."""
        host = Host(
            ip="192.168.1.100",
            hostname="dc01.corp.local",
            os="Windows Server 2019",
            domain="CORP",
            mac_address="00:11:22:33:44:55",
            is_dc=True,
            enabled=True,
            ports=[88, 389, 445],
            source="nmap",
        )
        assert host.ip == "192.168.1.100"
        assert host.hostname == "dc01.corp.local"
        assert host.os == "Windows Server 2019"
        assert host.domain == "CORP"
        assert host.mac_address == "00:11:22:33:44:55"
        assert host.is_dc is True
        assert host.enabled is True
        assert host.ports == [88, 389, 445]

    def test_host_defaults(self):
        """Test Host default values."""
        host = Host(ip="192.168.1.1")
        assert host.hostname is None
        assert host.os is None
        assert host.domain is None
        assert host.mac_address is None
        assert host.is_dc is False
        assert host.enabled is True
        assert host.ports == []

    def test_host_fqdn_with_hostname_and_domain(self):
        """Test Host FQDN property with hostname and domain."""
        host = Host(ip="192.168.1.1", hostname="dc01", domain="corp.local")
        assert host.fqdn == "dc01.corp.local"

    def test_host_fqdn_hostname_already_has_domain(self):
        """Test Host FQDN when hostname already includes domain."""
        host = Host(ip="192.168.1.1", hostname="dc01.corp.local", domain="corp.local")
        assert host.fqdn == "dc01.corp.local"

    def test_host_fqdn_no_domain(self):
        """Test Host FQDN falls back to hostname when no domain."""
        host = Host(ip="192.168.1.1", hostname="server")
        assert host.fqdn == "server"

    def test_host_fqdn_no_hostname_falls_back_to_ip(self):
        """Test Host FQDN falls back to IP when no hostname."""
        host = Host(ip="192.168.1.1")
        assert host.fqdn == "192.168.1.1"


class TestService:
    """Test Service model."""

    def test_service_id_generation(self):
        """Test Service ID is generated from host_id, port, and protocol."""
        service = Service(port=22, host_id="host:192.168.1.1")
        assert service.id == "service:host:192.168.1.1:22/tcp"

    def test_service_id_with_udp(self):
        """Test Service ID with UDP protocol."""
        service = Service(port=53, protocol="udp", host_id="host:192.168.1.1")
        assert service.id == "service:host:192.168.1.1:53/udp"

    def test_service_required_port(self):
        """Test Service requires port."""
        service = Service(port=80)
        assert service.port == 80

    def test_service_defaults(self):
        """Test Service default values."""
        service = Service(port=80)
        assert service.protocol == "tcp"
        assert service.name == "unknown"
        assert service.product is None
        assert service.version is None
        assert service.host_id is None
        assert service.banner is None
        assert service.ssl is False

    def test_service_with_all_fields(self):
        """Test Service with all fields populated."""
        service = Service(
            port=443,
            protocol="tcp",
            name="https",
            product="nginx",
            version="1.18.0",
            host_id="host:192.168.1.1",
            banner="nginx/1.18.0",
            ssl=True,
            source="nmap",
        )
        assert service.port == 443
        assert service.protocol == "tcp"
        assert service.name == "https"
        assert service.product == "nginx"
        assert service.version == "1.18.0"
        assert service.ssl is True

    def test_service_display_name_with_product_and_version(self):
        """Test Service display_name with product and version."""
        service = Service(port=22, name="ssh", product="OpenSSH", version="8.9")
        assert service.display_name == "ssh (OpenSSH 8.9)"

    def test_service_display_name_with_product_only(self):
        """Test Service display_name with product only."""
        service = Service(port=80, name="http", product="nginx")
        assert service.display_name == "http (nginx)"

    def test_service_display_name_without_product(self):
        """Test Service display_name without product."""
        service = Service(port=80, name="http")
        assert service.display_name == "http"


class TestUser:
    """Test User model."""

    def test_user_id_generation_with_domain(self):
        """Test User ID is generated with domain prefix."""
        user = User(username="jsmith", domain="CORP")
        assert user.id == "user:CORP\\jsmith"

    def test_user_id_generation_without_domain(self):
        """Test User ID is generated without domain."""
        user = User(username="jsmith")
        assert user.id == "user:jsmith"

    def test_user_required_username(self):
        """Test User requires username."""
        user = User(username="admin")
        assert user.username == "admin"

    def test_user_defaults(self):
        """Test User default values."""
        user = User(username="test")
        assert user.domain is None
        assert user.display_name is None
        assert user.email is None
        assert user.enabled is True
        assert user.is_admin is False
        assert user.password_never_expires is False
        assert user.last_logon is None
        assert user.groups == []
        assert user.object_id is None

    def test_user_with_all_fields(self):
        """Test User with all fields populated."""
        user = User(
            username="jsmith",
            domain="CORP",
            display_name="John Smith",
            email="jsmith@corp.local",
            enabled=True,
            is_admin=False,
            password_never_expires=False,
            groups=["Domain Users", "IT Support"],
            object_id="S-1-5-21-1234",
            source="bloodhound",
        )
        assert user.username == "jsmith"
        assert user.domain == "CORP"
        assert user.display_name == "John Smith"
        assert user.email == "jsmith@corp.local"
        assert user.groups == ["Domain Users", "IT Support"]

    def test_user_principal_name_with_domain(self):
        """Test User principal_name property with domain."""
        user = User(username="jsmith", domain="CORP")
        assert user.principal_name == "CORP\\jsmith"

    def test_user_principal_name_without_domain(self):
        """Test User principal_name property without domain."""
        user = User(username="jsmith")
        assert user.principal_name == "jsmith"

    def test_user_admin_flag(self):
        """Test User is_admin flag."""
        admin = User(username="admin", is_admin=True)
        assert admin.is_admin is True

        regular = User(username="user", is_admin=False)
        assert regular.is_admin is False


class TestCloudResource:
    """Test CloudResource model."""

    def test_cloud_resource_id_generation(self):
        """Test CloudResource ID is generated from provider, type, and resource_id."""
        resource = CloudResource(
            resource_id="i-0123456789",
            resource_type="EC2",
            provider="aws",
        )
        assert resource.id == "cloud:aws:EC2:i-0123456789"

    def test_cloud_resource_required_fields(self):
        """Test CloudResource required fields."""
        resource = CloudResource(resource_id="test-id", resource_type="VM")
        assert resource.resource_id == "test-id"
        assert resource.resource_type == "VM"

    def test_cloud_resource_defaults(self):
        """Test CloudResource default values."""
        resource = CloudResource(resource_id="test", resource_type="VM")
        assert resource.name is None
        assert resource.provider == "unknown"
        assert resource.account_id is None
        assert resource.tenant_id is None
        assert resource.subscription_id is None
        assert resource.region is None
        assert resource.app_id is None
        assert resource.arn is None
        assert resource.permissions == []

    def test_cloud_resource_aws(self):
        """Test CloudResource for AWS."""
        resource = CloudResource(
            resource_id="i-0123456789abcdef0",
            resource_type="EC2",
            name="web-server",
            provider="aws",
            account_id="123456789012",
            region="us-east-1",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
            permissions=["ec2:DescribeInstances"],
            source="aws_scout",
        )
        assert resource.provider == "aws"
        assert resource.account_id == "123456789012"
        assert resource.region == "us-east-1"
        assert resource.arn is not None

    def test_cloud_resource_azure(self):
        """Test CloudResource for Azure."""
        resource = CloudResource(
            resource_id="00000000-0000-0000-0000-000000000001",
            resource_type="VirtualMachine",
            name="vm-prod",
            provider="azure",
            tenant_id="11111111-1111-1111-1111-111111111111",
            subscription_id="22222222-2222-2222-2222-222222222222",
            region="eastus",
            source="azurehound",
        )
        assert resource.provider == "azure"
        assert resource.tenant_id is not None
        assert resource.subscription_id is not None

    def test_cloud_resource_display_name_with_name(self):
        """Test CloudResource display_name property with name."""
        resource = CloudResource(
            resource_id="i-0123456789",
            resource_type="EC2",
            name="web-server",
        )
        assert resource.display_name == "web-server"

    def test_cloud_resource_display_name_without_name(self):
        """Test CloudResource display_name property without name."""
        resource = CloudResource(
            resource_id="i-0123456789",
            resource_type="EC2",
        )
        assert resource.display_name == "i-0123456789"
