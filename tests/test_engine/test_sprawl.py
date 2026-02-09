"""Tests for credential sprawl analysis."""

import pytest

from ariadne.engine.sprawl import CredentialCluster, SprawlAnalyzer
from ariadne.graph.store import GraphStore
from ariadne.models.asset import Host, User
from ariadne.models.finding import Credential
from ariadne.models.relationship import ATTACK_RELATIONSHIPS, RelationType

_cred_counter = 0


class TestSprawlAnalyzer:
    """Test SprawlAnalyzer functionality."""

    @pytest.fixture
    def store(self) -> GraphStore:
        """Create a fresh graph store."""
        return GraphStore()

    def _add_host(self, store: GraphStore, ip: str) -> Host:
        host = Host(ip=ip)
        store.add_entity(host)
        return host

    def _add_user(self, store: GraphStore, username: str, domain: str = "") -> User:
        user = User(username=username, domain=domain or None)
        store.add_entity(user)
        return user

    def _add_credential(
        self,
        store: GraphStore,
        username: str,
        domain: str,
        value: str,
        host_id: str,
        ntlm_hash: str | None = None,
        source: str = "test",
    ) -> Credential:
        global _cred_counter
        _cred_counter += 1
        cred_type = "ntlm" if ntlm_hash else "password"
        user_part = f"{domain}\\{username}" if domain else username
        cred = Credential(
            id=f"cred:{cred_type}:{user_part}:{host_id}:{_cred_counter}",
            credential_type=cred_type,
            username=username,
            domain=domain or None,
            value=value,
            ntlm_hash=ntlm_hash,
            affected_asset_id=host_id,
            title=f"Credential for {username}",
            source=source,
        )
        store.add_entity(cred)
        return cred

    def test_no_credentials_returns_empty_report(self, store: GraphStore):
        """No credentials in graph should return empty report."""
        self._add_host(store, "10.0.0.1")
        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        assert report.total_credentials == 0
        assert report.total_reused == 0
        assert len(report.clusters) == 0
        assert report.relationships_created == 0

    def test_single_credential_no_reuse(self, store: GraphStore):
        """A single credential on one host should not create any clusters."""
        host = self._add_host(store, "10.0.0.1")
        self._add_credential(store, "admin", "CORP", "Password1", host.id)

        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        assert report.total_credentials == 1
        assert len(report.clusters) == 0
        assert report.relationships_created >= 0  # may create CAN_AUTH_AS

    def test_matching_ntlm_creates_cluster(self, store: GraphStore):
        """Same NTLM hash on two hosts should create a cluster."""
        host1 = self._add_host(store, "10.0.0.1")
        host2 = self._add_host(store, "10.0.0.2")

        self._add_credential(
            store, "admin", "CORP", "", host1.id,
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee",
        )
        self._add_credential(
            store, "admin", "CORP", "", host2.id,
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee",
        )

        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        assert len(report.clusters) == 1
        assert report.total_reused == 2
        cluster = report.clusters[0]
        assert len(set(cluster.affected_asset_ids)) == 2

    def test_matching_value_creates_cluster(self, store: GraphStore):
        """Same password value on two hosts should create a cluster."""
        host1 = self._add_host(store, "10.0.0.1")
        host2 = self._add_host(store, "10.0.0.2")

        self._add_credential(store, "svc_backup", "CORP", "Summer2024!", host1.id)
        self._add_credential(store, "svc_backup", "CORP", "Summer2024!", host2.id)

        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        assert len(report.clusters) == 1
        assert report.total_reused == 2

    def test_different_values_no_false_positive(self, store: GraphStore):
        """Same username but different values should not cluster."""
        host1 = self._add_host(store, "10.0.0.1")
        host2 = self._add_host(store, "10.0.0.2")

        self._add_credential(store, "admin", "CORP", "Password1", host1.id)
        self._add_credential(store, "admin", "CORP", "DifferentPass", host2.id)

        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        # Should create separate sub-clusters (no reuse cluster with 2+ assets)
        reuse_clusters = [c for c in report.clusters if len(set(c.affected_asset_ids)) >= 2]
        assert len(reuse_clusters) == 0

    def test_sprawl_score_scales_with_hosts(self, store: GraphStore):
        """Sprawl score should increase with number of hosts."""
        # Create 10 hosts with same credential
        hosts = []
        for i in range(10):
            host = self._add_host(store, f"10.0.0.{i + 1}")
            hosts.append(host)
            self._add_credential(store, "admin", "CORP", "Shared!", host.id)

        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        assert len(report.clusters) == 1
        cluster = report.clusters[0]
        assert cluster.sprawl_score == 1.0  # 10 hosts → max score

    def test_reuse_edges_in_attack_subgraph(self, store: GraphStore):
        """CREDENTIAL_REUSE edges should appear in the attack subgraph."""
        host1 = self._add_host(store, "10.0.0.1")
        host2 = self._add_host(store, "10.0.0.2")

        self._add_credential(store, "admin", "CORP", "Reused!", host1.id)
        self._add_credential(store, "admin", "CORP", "Reused!", host2.id)

        analyzer = SprawlAnalyzer(store)
        analyzer.analyze()

        # Check edge exists in graph
        graph = store.graph
        found_reuse = False
        for u, v, data in graph.edges(data=True):
            if data.get("type") == RelationType.CREDENTIAL_REUSE.value:
                found_reuse = True
                break
        assert found_reuse, "CREDENTIAL_REUSE edge not found in graph"

        # Verify it's in ATTACK_RELATIONSHIPS
        assert RelationType.CREDENTIAL_REUSE in ATTACK_RELATIONSHIPS

    def test_can_auth_as_edges_created(self, store: GraphStore):
        """CAN_AUTH_AS edges should be created when credential matches a user."""
        host = self._add_host(store, "10.0.0.1")
        user = self._add_user(store, "jsmith", "CORP")
        self._add_credential(store, "jsmith", "CORP", "Password1", host.id)

        analyzer = SprawlAnalyzer(store)
        analyzer.analyze()

        # Check for CAN_AUTH_AS edge
        graph = store.graph
        found_auth = False
        for u, v, data in graph.edges(data=True):
            if data.get("type") == RelationType.CAN_AUTH_AS.value:
                found_auth = True
                assert v == user.id
                break
        assert found_auth, "CAN_AUTH_AS edge not found"

    def test_cross_parser_dedup(self, store: GraphStore):
        """Credentials from different parsers (mimikatz + secretsdump) should cluster correctly."""
        host1 = self._add_host(store, "10.0.0.1")
        host2 = self._add_host(store, "10.0.0.2")

        # Mimikatz output
        self._add_credential(
            store, "admin", "CORP", "", host1.id,
            ntlm_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
            source="mimikatz",
        )
        # Secretsdump output
        self._add_credential(
            store, "admin", "CORP", "", host2.id,
            ntlm_hash="31D6CFE0D16AE931B73C59D7E0C089C0",  # uppercase variant
            source="secretsdump",
        )

        analyzer = SprawlAnalyzer(store)
        report = analyzer.analyze()

        # Should cluster despite different sources and case
        assert len(report.clusters) == 1
        assert report.total_reused == 2


class TestCredentialCluster:
    """Test CredentialCluster properties."""

    def test_sprawl_score_one_host(self):
        cluster = CredentialCluster(
            canonical_id="test", username="a", domain="",
            affected_asset_ids=["host:1"],
        )
        assert cluster.sprawl_score == 0.0

    def test_sprawl_score_two_hosts(self):
        cluster = CredentialCluster(
            canonical_id="test", username="a", domain="",
            affected_asset_ids=["host:1", "host:2"],
        )
        assert cluster.sprawl_score == 0.3

    def test_sprawl_score_four_hosts(self):
        cluster = CredentialCluster(
            canonical_id="test", username="a", domain="",
            affected_asset_ids=["host:1", "host:2", "host:3", "host:4"],
        )
        assert cluster.sprawl_score == 0.5

    def test_sprawl_score_seven_hosts(self):
        cluster = CredentialCluster(
            canonical_id="test", username="a", domain="",
            affected_asset_ids=[f"host:{i}" for i in range(7)],
        )
        assert cluster.sprawl_score == 0.8

    def test_sprawl_score_ten_hosts(self):
        cluster = CredentialCluster(
            canonical_id="test", username="a", domain="",
            affected_asset_ids=[f"host:{i}" for i in range(10)],
        )
        assert cluster.sprawl_score == 1.0

    def test_display_name_with_domain(self):
        cluster = CredentialCluster(
            canonical_id="test", username="admin", domain="corp",
        )
        assert cluster.display_name == "corp\\admin"

    def test_display_name_without_domain(self):
        cluster = CredentialCluster(
            canonical_id="test", username="admin", domain="",
        )
        assert cluster.display_name == "admin"
