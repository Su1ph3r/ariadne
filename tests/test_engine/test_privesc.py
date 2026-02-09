"""Tests for privilege escalation chaining."""

import pytest

from ariadne.engine.privesc import PrivescChainer, PrivilegeLevel
from ariadne.graph.store import GraphStore
from ariadne.models.asset import Host
from ariadne.models.finding import Misconfiguration
from ariadne.models.relationship import ATTACK_RELATIONSHIPS, Relationship, RelationType


class TestPrivescChainer:
    """Test PrivescChainer functionality."""

    @pytest.fixture
    def store(self) -> GraphStore:
        """Create a fresh graph store."""
        return GraphStore()

    def _add_host(self, store: GraphStore, ip: str) -> Host:
        host = Host(ip=ip)
        store.add_entity(host)
        return host

    def _add_finding(
        self,
        store: GraphStore,
        title: str,
        host_id: str,
        tags: list[str] | None = None,
        severity: str = "high",
    ) -> Misconfiguration:
        finding = Misconfiguration(
            title=title,
            affected_asset_id=host_id,
            tags=tags or [],
            severity=severity,
        )
        store.add_entity(finding)
        return finding

    def _add_misconfiguration(
        self,
        store: GraphStore,
        title: str,
        host_id: str,
        tags: list[str] | None = None,
    ) -> Misconfiguration:
        misconfig = Misconfiguration(
            title=title,
            affected_asset_id=host_id,
            tags=tags or [],
            severity="high",
        )
        store.add_entity(misconfig)
        return misconfig

    def test_no_findings_returns_empty(self, store: GraphStore):
        """No findings should return empty report."""
        self._add_host(store, "10.0.0.1")

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.hosts_with_privesc == 0
        assert report.total_vectors == 0
        assert len(report.chains) == 0

    def test_seimpersonate_creates_vector(self, store: GraphStore):
        """SeImpersonatePrivilege finding should create UNPRIV→SYSTEM vector."""
        host = self._add_host(store, "10.0.0.1")
        self._add_finding(
            store,
            "SeImpersonatePrivilege enabled",
            host.id,
            tags=["privesc"],
        )

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.hosts_with_privesc == 1
        assert report.total_vectors == 1
        chain = report.chains[0]
        assert chain.host_id == host.id
        vector = chain.vectors[0]
        assert vector.source_level == PrivilegeLevel.UNPRIVILEGED
        assert vector.target_level == PrivilegeLevel.SYSTEM
        assert vector.technique_id == "T1134.001"
        assert vector.confidence == 0.9

    def test_modifiable_service_creates_vector(self, store: GraphStore):
        """Modifiable service finding should create UNPRIV→SYSTEM vector."""
        host = self._add_host(store, "10.0.0.1")
        self._add_misconfiguration(
            store,
            "Modifiable Service Binary",
            host.id,
            tags=["privesc", "modifiable_service"],
        )

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.hosts_with_privesc == 1
        vector = report.chains[0].vectors[0]
        assert vector.technique_id == "T1574.010"
        assert vector.confidence == 0.85

    def test_context_nodes_created(self, store: GraphStore):
        """Privilege context nodes should be created in the graph."""
        host = self._add_host(store, "10.0.0.1")
        self._add_finding(
            store,
            "SeImpersonatePrivilege enabled",
            host.id,
            tags=["privesc"],
        )

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.context_nodes_created > 0

        # Check nodes exist in graph
        graph = store.graph
        unpriv_node = f"priv:UNPRIVILEGED@{host.id}"
        system_node = f"priv:SYSTEM@{host.id}"
        assert unpriv_node in graph.nodes
        assert system_node in graph.nodes

    def test_can_privesc_edges_in_attack_subgraph(self, store: GraphStore):
        """CAN_PRIVESC edges should be in ATTACK_RELATIONSHIPS."""
        assert RelationType.CAN_PRIVESC in ATTACK_RELATIONSHIPS

        host = self._add_host(store, "10.0.0.1")
        self._add_finding(
            store,
            "AlwaysInstallElevated",
            host.id,
            tags=["privesc", "always_install_elevated"],
        )

        chainer = PrivescChainer(store)
        chainer.analyze()

        # Verify CAN_PRIVESC edges exist
        graph = store.graph
        found_privesc = False
        for u, v, data in graph.edges(data=True):
            if data.get("type") == RelationType.CAN_PRIVESC.value:
                found_privesc = True
                break
        assert found_privesc, "CAN_PRIVESC edge not found in graph"

    def test_chain_connects_lateral_to_privesc(self, store: GraphStore):
        """Lateral movement edges should connect to privesc context nodes."""
        host1 = self._add_host(store, "10.0.0.1")
        host2 = self._add_host(store, "10.0.0.2")

        # Add lateral movement edge from host1 to host2
        rel = Relationship(
            source_id=host1.id,
            target_id=host2.id,
            relation_type=RelationType.CAN_RDP,
            weight=0.8,
            confidence=0.9,
            source="test",
        )
        store.add_entity(rel)

        # Add privesc finding on host2
        self._add_finding(
            store,
            "SeImpersonatePrivilege enabled",
            host2.id,
            tags=["privesc"],
        )

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.hosts_with_privesc == 1
        assert report.edges_created > 0

        # Check that host1 can reach the UNPRIVILEGED context on host2
        graph = store.graph
        unpriv_node = f"priv:UNPRIVILEGED@{host2.id}"
        assert unpriv_node in graph.nodes

        # Should have edge from host1 → priv:UNPRIVILEGED@host2
        has_context_edge = False
        for pred in graph.predecessors(unpriv_node):
            if pred == host1.id:
                has_context_edge = True
                break
        assert has_context_edge, "Lateral movement not connected to privesc context"

    def test_non_privesc_findings_ignored(self, store: GraphStore):
        """Findings without privesc-related keywords should be ignored."""
        host = self._add_host(store, "10.0.0.1")
        self._add_finding(
            store,
            "SMB Signing Disabled",
            host.id,
            tags=["misconfig"],
        )
        self._add_finding(
            store,
            "Default Credentials Found",
            host.id,
            tags=["credential"],
        )

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.hosts_with_privesc == 0
        assert report.total_vectors == 0

    def test_watson_cve_findings(self, store: GraphStore):
        """Missing patch with privesc tag should create escalation vector."""
        host = self._add_host(store, "10.0.0.1")
        self._add_finding(
            store,
            "Missing Patch - CVE-2021-1732",
            host.id,
            tags=["privesc", "missing_patch"],
        )

        chainer = PrivescChainer(store)
        report = chainer.analyze()

        assert report.hosts_with_privesc == 1
        vector = report.chains[0].vectors[0]
        assert vector.technique_id == "T1068"
        assert vector.confidence == 0.7
        assert vector.target_level == PrivilegeLevel.SYSTEM


class TestPrivilegeLevel:
    """Test PrivilegeLevel enum ordering."""

    def test_ordering(self):
        assert PrivilegeLevel.UNPRIVILEGED < PrivilegeLevel.LOCAL_ADMIN
        assert PrivilegeLevel.LOCAL_ADMIN < PrivilegeLevel.SYSTEM
        assert PrivilegeLevel.SYSTEM < PrivilegeLevel.DOMAIN_USER_ELEVATED
        assert PrivilegeLevel.DOMAIN_USER_ELEVATED < PrivilegeLevel.DOMAIN_ADMIN
