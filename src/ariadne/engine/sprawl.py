"""Credential sprawl analysis — detect credential reuse across hosts."""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.graph.store import GraphStore
from ariadne.models.finding import Credential
from ariadne.models.relationship import Relationship, RelationType


@dataclass
class CredentialCluster:
    """A group of credentials representing the same secret across hosts."""

    canonical_id: str
    username: str
    domain: str
    credential_ids: list[str] = field(default_factory=list)
    affected_asset_ids: list[str] = field(default_factory=list)

    @property
    def sprawl_score(self) -> float:
        """Compute sprawl score based on number of distinct hosts.

        1 host → 0.0, 2 → 0.3, 3-4 → 0.5, 5-9 → 0.8, 10+ → 1.0
        """
        count = len(set(self.affected_asset_ids))
        if count <= 1:
            return 0.0
        if count == 2:
            return 0.3
        if count <= 4:
            return 0.5
        if count <= 9:
            return 0.8
        return 1.0

    @property
    def display_name(self) -> str:
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username


@dataclass
class SprawlReport:
    """Results of credential sprawl analysis."""

    clusters: list[CredentialCluster] = field(default_factory=list)
    total_credentials: int = 0
    total_reused: int = 0
    relationships_created: int = 0


class SprawlAnalyzer:
    """Detect credential reuse across hosts and create graph edges."""

    def __init__(self, store: GraphStore, min_reuse_count: int = 2) -> None:
        self.store = store
        self.min_reuse_count = min_reuse_count

    def analyze(self) -> SprawlReport:
        """Run sprawl analysis and inject edges into the graph."""
        builder = self.store.builder

        # 1. Collect all Credential findings
        credentials: list[Credential] = []
        for finding in builder._findings.values():
            if isinstance(finding, Credential):
                credentials.append(finding)

        report = SprawlReport(total_credentials=len(credentials))
        if not credentials:
            return report

        # 2. Group by (username.lower(), domain.lower())
        groups: dict[tuple[str, str], list[Credential]] = {}
        for cred in credentials:
            key = (
                (cred.username or "").lower(),
                (cred.domain or "").lower(),
            )
            groups.setdefault(key, []).append(cred)

        # 3. Sub-cluster by value match
        edges_created = 0
        for (username, domain), creds in groups.items():
            if not username:
                continue

            sub_clusters = self._sub_cluster(creds)

            for cluster_creds in sub_clusters:
                # Get unique affected assets
                asset_ids = []
                for c in cluster_creds:
                    if c.affected_asset_id:
                        asset_ids.append(c.affected_asset_id)

                unique_assets = list(dict.fromkeys(asset_ids))  # preserve order, dedup

                if len(unique_assets) < self.min_reuse_count:
                    continue

                cluster = CredentialCluster(
                    canonical_id=f"sprawl:{domain}\\{username}" if domain else f"sprawl:{username}",
                    username=username,
                    domain=domain,
                    credential_ids=[c.id for c in cluster_creds],
                    affected_asset_ids=unique_assets,
                )
                report.clusters.append(cluster)
                report.total_reused += len(cluster_creds)

                # 4. Create CREDENTIAL_REUSE edges between affected assets
                for i, src_asset in enumerate(unique_assets):
                    for tgt_asset in unique_assets[i + 1 :]:
                        rel = Relationship(
                            source_id=src_asset,
                            target_id=tgt_asset,
                            relation_type=RelationType.CREDENTIAL_REUSE,
                            weight=cluster.sprawl_score,
                            confidence=1.0,
                            properties={
                                "username": username,
                                "domain": domain,
                                "sprawl_score": cluster.sprawl_score,
                                "cluster_id": cluster.canonical_id,
                            },
                            source="sprawl_analyzer",
                            bidirectional=True,
                        )
                        self.store.add_entity(rel)
                        edges_created += 1

            # 5. Create CAN_AUTH_AS edges for creds with matching users
            for cred in creds:
                if not cred.affected_asset_id:
                    continue
                user_id = self._find_matching_user(cred, builder)
                if user_id:
                    rel = Relationship(
                        source_id=cred.affected_asset_id,
                        target_id=user_id,
                        relation_type=RelationType.CAN_AUTH_AS,
                        weight=0.8,
                        confidence=0.9,
                        properties={
                            "credential_id": cred.id,
                            "credential_type": cred.credential_type,
                        },
                        source="sprawl_analyzer",
                    )
                    self.store.add_entity(rel)
                    edges_created += 1

        report.relationships_created = edges_created
        # Invalidate cached graph so new edges are picked up
        self.store._graph = None
        return report

    def _sub_cluster(self, creds: list[Credential]) -> list[list[Credential]]:
        """Sub-cluster credentials by matching value or NTLM hash."""
        if len(creds) <= 1:
            return [creds]

        # Union-Find approach: group by matching value or ntlm_hash
        parent: dict[int, int] = {i: i for i in range(len(creds))}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i in range(len(creds)):
            for j in range(i + 1, len(creds)):
                ci, cj = creds[i], creds[j]
                # Match on value
                if ci.value and cj.value and ci.value == cj.value:
                    union(i, j)
                # Match on NTLM hash
                elif ci.ntlm_hash and cj.ntlm_hash and ci.ntlm_hash.lower() == cj.ntlm_hash.lower():
                    union(i, j)

        clusters: dict[int, list[Credential]] = {}
        for i, cred in enumerate(creds):
            root = find(i)
            clusters.setdefault(root, []).append(cred)

        return list(clusters.values())

    def _find_matching_user(self, cred: Credential, builder) -> str | None:
        """Find a User node that matches this credential."""
        if not cred.username:
            return None

        # Try exact match: user:domain\username
        if cred.domain:
            user_id = f"user:{cred.domain}\\{cred.username}"
            if user_id in builder._users:
                return user_id
            # Try case-insensitive
            for uid, user in builder._users.items():
                if (
                    user.username.lower() == cred.username.lower()
                    and user.domain
                    and user.domain.lower() == cred.domain.lower()
                ):
                    return uid

        # Try without domain
        user_id = f"user:{cred.username}"
        if user_id in builder._users:
            return user_id

        # Case-insensitive username-only match
        for uid, user in builder._users.items():
            if user.username.lower() == cred.username.lower():
                return uid

        return None
