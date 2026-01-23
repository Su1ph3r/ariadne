"""Tests for GraphBuilder."""

import pytest
import networkx as nx

from ariadne.graph.builder import GraphBuilder
from ariadne.models.asset import Host, Service, User, CloudResource
from ariadne.models.finding import Vulnerability, Misconfiguration, Credential
from ariadne.models.relationship import Relationship, RelationType


class TestGraphBuilder:
    """Test GraphBuilder functionality."""

    # =========================================================================
    # Initialization Tests
    # =========================================================================

    def test_initialization(self):
        """Test that builder initializes with empty graph."""
        builder = GraphBuilder()
        assert isinstance(builder.graph, nx.DiGraph)
        assert builder.graph.number_of_nodes() == 0
        assert builder.graph.number_of_edges() == 0

    # =========================================================================
    # Host Node Tests
    # =========================================================================

    def test_add_host(self):
        """Test adding a host to the graph."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")

        builder.add_entity(host)

        assert host.id in builder.graph
        node_data = builder.graph.nodes[host.id]
        assert node_data["type"] == "host"
        assert node_data["ip"] == "192.168.1.1"
        assert node_data["hostname"] == "server01"

    def test_add_host_with_domain_controller_flag(self):
        """Test adding a domain controller host."""
        builder = GraphBuilder()
        dc = Host(ip="192.168.1.10", hostname="DC01", is_dc=True)

        builder.add_entity(dc)

        node_data = builder.graph.nodes[dc.id]
        assert node_data["is_dc"] is True

    def test_add_host_with_os(self):
        """Test adding a host with OS information."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01", os="Windows Server 2019")

        builder.add_entity(host)

        node_data = builder.graph.nodes[host.id]
        assert node_data["os"] == "Windows Server 2019"

    def test_add_host_label_is_fqdn(self):
        """Test that host label uses FQDN."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01", domain="corp.local")

        builder.add_entity(host)

        node_data = builder.graph.nodes[host.id]
        assert node_data["label"] == "server01.corp.local"

    def test_add_multiple_hosts(self):
        """Test adding multiple hosts."""
        builder = GraphBuilder()
        host1 = Host(ip="192.168.1.1", hostname="server01")
        host2 = Host(ip="192.168.1.2", hostname="server02")

        builder.add_entity(host1)
        builder.add_entity(host2)

        assert builder.graph.number_of_nodes() == 2
        assert host1.id in builder.graph
        assert host2.id in builder.graph

    # =========================================================================
    # Service Node Tests
    # =========================================================================

    def test_add_service(self):
        """Test adding a service to the graph."""
        builder = GraphBuilder()
        service = Service(name="ssh", port=22, protocol="tcp")

        builder.add_entity(service)

        assert service.id in builder.graph
        node_data = builder.graph.nodes[service.id]
        assert node_data["type"] == "service"
        assert node_data["port"] == 22

    def test_add_service_with_product_version(self):
        """Test adding a service with product and version."""
        builder = GraphBuilder()
        service = Service(
            name="http", port=80, protocol="tcp",
            product="Apache httpd", version="2.4.41"
        )

        builder.add_entity(service)

        node_data = builder.graph.nodes[service.id]
        assert node_data["product"] == "Apache httpd"
        assert node_data["version"] == "2.4.41"

    def test_add_service_connected_to_host(self):
        """Test that service is connected to host when host exists."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        service = Service(name="ssh", port=22, protocol="tcp", host_id=host.id)

        builder.add_entity(host)
        builder.add_entity(service)

        assert builder.graph.has_edge(service.id, host.id)
        edge_data = builder.graph.edges[service.id, host.id]
        assert edge_data["type"] == "runs_on"

    def test_add_service_without_host_no_edge(self):
        """Test that service without host creates no edge."""
        builder = GraphBuilder()
        service = Service(name="ssh", port=22, protocol="tcp", host_id="nonexistent")

        builder.add_entity(service)

        assert builder.graph.number_of_edges() == 0

    def test_service_label_format(self):
        """Test service label is name:port format."""
        builder = GraphBuilder()
        service = Service(name="http", port=80, protocol="tcp")

        builder.add_entity(service)

        node_data = builder.graph.nodes[service.id]
        assert node_data["label"] == "http:80"

    # =========================================================================
    # User Node Tests
    # =========================================================================

    def test_add_user(self):
        """Test adding a user to the graph."""
        builder = GraphBuilder()
        user = User(username="admin", domain="CORP")

        builder.add_entity(user)

        assert user.id in builder.graph
        node_data = builder.graph.nodes[user.id]
        assert node_data["type"] == "user"
        assert node_data["username"] == "admin"

    def test_add_admin_user(self):
        """Test adding an admin user."""
        builder = GraphBuilder()
        user = User(username="admin", domain="CORP", is_admin=True)

        builder.add_entity(user)

        node_data = builder.graph.nodes[user.id]
        assert node_data["is_admin"] is True

    def test_add_disabled_user(self):
        """Test adding a disabled user."""
        builder = GraphBuilder()
        user = User(username="olduser", domain="CORP", enabled=False)

        builder.add_entity(user)

        node_data = builder.graph.nodes[user.id]
        assert node_data["enabled"] is False

    def test_user_label_is_principal_name(self):
        """Test that user label uses principal name (domain\\username format)."""
        builder = GraphBuilder()
        user = User(username="jsmith", domain="corp.local")

        builder.add_entity(user)

        node_data = builder.graph.nodes[user.id]
        assert node_data["label"] == "corp.local\\jsmith"

    # =========================================================================
    # CloudResource Node Tests
    # =========================================================================

    def test_add_cloud_resource(self):
        """Test adding a cloud resource to the graph."""
        builder = GraphBuilder()
        resource = CloudResource(
            resource_id="12345",
            resource_type="VM",
            name="webserver",
            provider="azure"
        )

        builder.add_entity(resource)

        assert resource.id in builder.graph
        node_data = builder.graph.nodes[resource.id]
        assert node_data["type"] == "cloud_resource"
        assert node_data["resource_type"] == "VM"
        assert node_data["provider"] == "azure"

    def test_add_cloud_resource_with_region(self):
        """Test adding a cloud resource with region."""
        builder = GraphBuilder()
        resource = CloudResource(
            resource_id="12345",
            resource_type="VM",
            name="webserver",
            provider="aws",
            region="us-east-1"
        )

        builder.add_entity(resource)

        node_data = builder.graph.nodes[resource.id]
        assert node_data["region"] == "us-east-1"

    # =========================================================================
    # Vulnerability Finding Tests
    # =========================================================================

    def test_add_vulnerability(self):
        """Test adding a vulnerability to the graph."""
        builder = GraphBuilder()
        vuln = Vulnerability(
            title="SQL Injection",
            severity="critical",
            cve="CVE-2021-12345"
        )

        builder.add_entity(vuln)

        assert vuln.id in builder.graph
        node_data = builder.graph.nodes[vuln.id]
        assert node_data["type"] == "vulnerability"
        assert node_data["severity"] == "critical"

    def test_vulnerability_connected_to_affected_asset(self):
        """Test that vulnerability is connected to affected asset."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        vuln = Vulnerability(
            title="SQL Injection",
            severity="critical",
            affected_asset_id=host.id
        )

        builder.add_entity(host)
        builder.add_entity(vuln)

        assert builder.graph.has_edge(host.id, vuln.id)
        edge_data = builder.graph.edges[host.id, vuln.id]
        assert edge_data["type"] == "has_vulnerability"

    def test_vulnerability_severity_score_as_weight(self):
        """Test that vulnerability severity score is used as edge weight."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        vuln = Vulnerability(
            title="Critical Vuln",
            severity="critical",
            affected_asset_id=host.id
        )

        builder.add_entity(host)
        builder.add_entity(vuln)

        edge_data = builder.graph.edges[host.id, vuln.id]
        assert edge_data["weight"] == vuln.severity_score

    # =========================================================================
    # Misconfiguration Finding Tests
    # =========================================================================

    def test_add_misconfiguration(self):
        """Test adding a misconfiguration to the graph."""
        builder = GraphBuilder()
        misconfig = Misconfiguration(
            title="Weak Password Policy",
            severity="medium"
        )

        builder.add_entity(misconfig)

        assert misconfig.id in builder.graph
        node_data = builder.graph.nodes[misconfig.id]
        assert node_data["type"] == "misconfiguration"

    def test_misconfiguration_connected_to_affected_asset(self):
        """Test that misconfiguration is connected to affected asset."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="DC01")
        misconfig = Misconfiguration(
            title="Unconstrained Delegation",
            severity="high",
            affected_asset_id=host.id
        )

        builder.add_entity(host)
        builder.add_entity(misconfig)

        assert builder.graph.has_edge(host.id, misconfig.id)
        edge_data = builder.graph.edges[host.id, misconfig.id]
        assert edge_data["type"] == "has_misconfiguration"

    # =========================================================================
    # Credential Finding Tests
    # =========================================================================

    def test_add_credential(self):
        """Test adding a credential to the graph."""
        builder = GraphBuilder()
        cred = Credential(
            title="Extracted credential",
            severity="critical",
            credential_type="password",
            username="admin"
        )

        builder.add_entity(cred)

        assert cred.id in builder.graph
        node_data = builder.graph.nodes[cred.id]
        assert node_data["type"] == "credential"

    # =========================================================================
    # Relationship Edge Tests
    # =========================================================================

    def test_add_relationship(self):
        """Test adding a relationship to the graph."""
        builder = GraphBuilder()
        host1 = Host(ip="192.168.1.1", hostname="server01")
        host2 = Host(ip="192.168.1.2", hostname="server02")
        rel = Relationship(
            source_id=host1.id,
            target_id=host2.id,
            relation_type=RelationType.CAN_REACH
        )

        builder.add_entity(host1)
        builder.add_entity(host2)
        builder.add_entity(rel)

        assert builder.graph.has_edge(host1.id, host2.id)
        edge_data = builder.graph.edges[host1.id, host2.id]
        assert edge_data["type"] == "can_reach"

    def test_add_bidirectional_relationship(self):
        """Test adding a bidirectional relationship."""
        builder = GraphBuilder()
        host1 = Host(ip="192.168.1.1", hostname="server01")
        host2 = Host(ip="192.168.1.2", hostname="server02")
        rel = Relationship(
            source_id=host1.id,
            target_id=host2.id,
            relation_type=RelationType.CAN_REACH,
            bidirectional=True
        )

        builder.add_entity(host1)
        builder.add_entity(host2)
        builder.add_entity(rel)

        assert builder.graph.has_edge(host1.id, host2.id)
        assert builder.graph.has_edge(host2.id, host1.id)

    def test_add_relationship_creates_missing_nodes(self):
        """Test that relationships create placeholder nodes if needed."""
        builder = GraphBuilder()
        rel = Relationship(
            source_id="node1",
            target_id="node2",
            relation_type=RelationType.ADMIN_TO
        )

        builder.add_entity(rel)

        assert "node1" in builder.graph
        assert "node2" in builder.graph
        assert builder.graph.nodes["node1"]["type"] == "unknown"

    def test_relationship_edge_properties(self):
        """Test that relationship properties are stored on edge."""
        builder = GraphBuilder()
        rel = Relationship(
            source_id="user1",
            target_id="dc1",
            relation_type=RelationType.ADMIN_TO,
            weight=0.9,
            confidence=0.8,
            properties={"method": "direct"}
        )

        builder.add_entity(rel)

        edge_data = builder.graph.edges["user1", "dc1"]
        assert edge_data["weight"] == 0.9
        assert edge_data["confidence"] == 0.8
        assert edge_data["properties"]["method"] == "direct"

    def test_attack_relationship_marked(self):
        """Test that attack relationships are marked as attack edges."""
        builder = GraphBuilder()
        rel = Relationship(
            source_id="user1",
            target_id="dc1",
            relation_type=RelationType.ADMIN_TO  # This is an attack relationship
        )

        builder.add_entity(rel)

        edge_data = builder.graph.edges["user1", "dc1"]
        assert edge_data["is_attack_edge"] is True

    # =========================================================================
    # Batch Add Tests
    # =========================================================================

    def test_add_entities_batch(self):
        """Test adding multiple entities at once."""
        builder = GraphBuilder()
        entities = [
            Host(ip="192.168.1.1", hostname="server01"),
            Host(ip="192.168.1.2", hostname="server02"),
            User(username="admin", domain="CORP"),
        ]

        builder.add_entities(iter(entities))

        assert builder.graph.number_of_nodes() == 3

    # =========================================================================
    # Build Tests
    # =========================================================================

    def test_build_returns_graph(self):
        """Test that build returns the graph."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        builder.add_entity(host)

        graph = builder.build()

        assert isinstance(graph, nx.DiGraph)
        assert graph.number_of_nodes() == 1

    # =========================================================================
    # Attack Graph Tests
    # =========================================================================

    def test_get_attack_graph(self):
        """Test getting attack-only subgraph."""
        builder = GraphBuilder()
        host1 = Host(ip="192.168.1.1", hostname="server01")
        host2 = Host(ip="192.168.1.2", hostname="server02")
        service = Service(name="ssh", port=22, protocol="tcp", host_id=host1.id)

        # Attack relationship
        rel = Relationship(
            source_id=host1.id,
            target_id=host2.id,
            relation_type=RelationType.ADMIN_TO
        )

        builder.add_entity(host1)
        builder.add_entity(host2)
        builder.add_entity(service)
        builder.add_entity(rel)

        attack_graph = builder.get_attack_graph()

        # Should include admin_to edge (attack), but not runs_on edge
        assert attack_graph.has_edge(host1.id, host2.id)
        # runs_on is not an attack relationship
        assert not attack_graph.has_edge(service.id, host1.id)

    def test_get_attack_graph_empty_when_no_attacks(self):
        """Test attack graph when there are no attack edges."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        service = Service(name="ssh", port=22, protocol="tcp", host_id=host.id)

        builder.add_entity(host)
        builder.add_entity(service)

        attack_graph = builder.get_attack_graph()
        # Should return empty or minimal graph
        assert attack_graph.number_of_edges() == 0

    # =========================================================================
    # Stats Tests
    # =========================================================================

    def test_stats(self):
        """Test graph statistics."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        service = Service(name="ssh", port=22, protocol="tcp", host_id=host.id)
        user = User(username="admin", domain="CORP")
        vuln = Vulnerability(title="Test Vuln", severity="high", affected_asset_id=host.id)

        builder.add_entity(host)
        builder.add_entity(service)
        builder.add_entity(user)
        builder.add_entity(vuln)

        stats = builder.stats()

        assert stats["total_nodes"] == 4
        assert stats["total_edges"] == 2  # service->host, host->vuln
        assert stats["hosts"] == 1
        assert stats["services"] == 1
        assert stats["users"] == 1
        assert stats["findings"] == 1
        assert "host" in stats["node_types"]
        assert stats["node_types"]["host"] == 1

    def test_stats_empty_graph(self):
        """Test stats on empty graph."""
        builder = GraphBuilder()

        stats = builder.stats()

        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0
        assert stats["hosts"] == 0

    def test_stats_edge_types(self):
        """Test that edge types are counted correctly."""
        builder = GraphBuilder()
        host = Host(ip="192.168.1.1", hostname="server01")
        vuln1 = Vulnerability(title="Vuln 1", severity="high", affected_asset_id=host.id)
        vuln2 = Vulnerability(title="Vuln 2", severity="medium", affected_asset_id=host.id)

        builder.add_entity(host)
        builder.add_entity(vuln1)
        builder.add_entity(vuln2)

        stats = builder.stats()

        assert "has_vulnerability" in stats["edge_types"]
        assert stats["edge_types"]["has_vulnerability"] == 2
