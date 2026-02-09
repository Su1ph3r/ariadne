"""Privilege escalation chaining — model local privesc as intra-host attack paths."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from ariadne.graph.store import GraphStore
from ariadne.models.finding import Finding
from ariadne.models.relationship import Relationship, RelationType


class PrivilegeLevel(IntEnum):
    """Privilege levels for escalation chaining."""

    UNPRIVILEGED = 0
    LOCAL_ADMIN = 1
    SYSTEM = 2
    DOMAIN_USER_ELEVATED = 3
    DOMAIN_ADMIN = 4


@dataclass
class PrivescVector:
    """A single privilege escalation vector from a finding."""

    finding_id: str
    finding_title: str
    source_level: PrivilegeLevel
    target_level: PrivilegeLevel
    technique_id: str
    confidence: float


@dataclass
class PrivescChain:
    """A chain of privilege escalation vectors on a single host."""

    host_id: str
    vectors: list[PrivescVector] = field(default_factory=list)
    source_level: PrivilegeLevel = PrivilegeLevel.UNPRIVILEGED
    target_level: PrivilegeLevel = PrivilegeLevel.UNPRIVILEGED

    @property
    def max_confidence(self) -> float:
        if not self.vectors:
            return 0.0
        return max(v.confidence for v in self.vectors)


@dataclass
class PrivescReport:
    """Results of privilege escalation chaining analysis."""

    chains: list[PrivescChain] = field(default_factory=list)
    hosts_with_privesc: int = 0
    total_vectors: int = 0
    context_nodes_created: int = 0
    edges_created: int = 0


# Mapping of finding tag/title keywords to escalation vectors
PRIVESC_VECTOR_MAP: list[dict] = [
    {
        "keywords": ["seimpersonateprivilege"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.SYSTEM,
        "technique": "T1134.001",
        "confidence": 0.9,
    },
    {
        "keywords": ["sedebugprivilege"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.SYSTEM,
        "technique": "T1134",
        "confidence": 0.9,
    },
    {
        "keywords": ["modifiable_service", "modifiable service"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.SYSTEM,
        "technique": "T1574.010",
        "confidence": 0.85,
    },
    {
        "keywords": ["always_install_elevated", "alwaysinstallelevated"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.SYSTEM,
        "technique": "T1548.002",
        "confidence": 0.9,
    },
    {
        "keywords": ["unquoted_path", "unquoted service path"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.SYSTEM,
        "technique": "T1574.009",
        "confidence": 0.6,
    },
    {
        "keywords": ["autologon"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.LOCAL_ADMIN,
        "technique": "T1552.001",
        "confidence": 0.95,
    },
    {
        "keywords": ["sebackupprivilege"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.LOCAL_ADMIN,
        "technique": "T1003.002",
        "confidence": 0.8,
    },
    {
        "keywords": ["seloaddriverprivilege"],
        "source": PrivilegeLevel.UNPRIVILEGED,
        "target": PrivilegeLevel.SYSTEM,
        "technique": "T1068",
        "confidence": 0.8,
    },
]

# Lateral movement relationship types that arrive at a host
_LATERAL_MOVE_TYPES = {
    RelationType.CAN_RDP.value,
    RelationType.CAN_PSREMOTE.value,
    RelationType.CAN_SSH.value,
    RelationType.ADMIN_TO.value,
    RelationType.HAS_SESSION.value,
    RelationType.CAN_REACH.value,
    RelationType.HAS_ACCESS.value,
    RelationType.CREDENTIAL_REUSE.value,
    RelationType.CAN_AUTH_AS.value,
}


class PrivescChainer:
    """Model local privilege escalation as intra-host attack path edges."""

    def __init__(self, store: GraphStore, min_confidence: float = 0.5) -> None:
        self.store = store
        self.min_confidence = min_confidence

    def analyze(self) -> PrivescReport:
        """Run privesc chaining analysis and inject edges into the graph."""
        builder = self.store.builder
        report = PrivescReport()

        # Process each host
        for host_id, host in builder._hosts.items():
            chain = self._analyze_host(host_id, builder)
            if chain and chain.vectors:
                report.chains.append(chain)
                report.total_vectors += len(chain.vectors)

        report.hosts_with_privesc = len(report.chains)

        # Create graph structures for each chain
        for chain in report.chains:
            nodes_created, edges_created = self._create_graph_structures(chain)
            report.context_nodes_created += nodes_created
            report.edges_created += edges_created

        # Invalidate cached graph
        self.store._graph = None
        return report

    def _analyze_host(self, host_id: str, builder) -> PrivescChain | None:
        """Analyze a single host for privilege escalation vectors."""
        # Find findings attached to this host
        findings: list[Finding] = []
        for finding_id, finding in builder._findings.items():
            if finding.affected_asset_id == host_id:
                findings.append(finding)

        if not findings:
            return None

        chain = PrivescChain(host_id=host_id)

        for finding in findings:
            # Check if finding has privesc tag or matches keywords
            vector = self._classify_finding(finding)
            if vector and vector.confidence >= self.min_confidence:
                chain.vectors.append(vector)

        if chain.vectors:
            chain.source_level = min(v.source_level for v in chain.vectors)
            chain.target_level = max(v.target_level for v in chain.vectors)

        return chain

    def _classify_finding(self, finding: Finding) -> PrivescVector | None:
        """Classify a finding against the PRIVESC_VECTOR_MAP."""
        search_text = finding.title.lower()
        tag_text = " ".join(t.lower() for t in finding.tags)
        combined = f"{search_text} {tag_text}"

        # Check for privesc-tagged missing patch
        is_privesc_tagged = "privesc" in tag_text or "privesc" in search_text
        is_missing_patch = "missing_patch" in combined or "missing patch" in combined

        if is_missing_patch and is_privesc_tagged:
            return PrivescVector(
                finding_id=finding.id,
                finding_title=finding.title,
                source_level=PrivilegeLevel.UNPRIVILEGED,
                target_level=PrivilegeLevel.SYSTEM,
                technique_id="T1068",
                confidence=0.7,
            )

        for entry in PRIVESC_VECTOR_MAP:
            for keyword in entry["keywords"]:
                if keyword in combined:
                    return PrivescVector(
                        finding_id=finding.id,
                        finding_title=finding.title,
                        source_level=entry["source"],
                        target_level=entry["target"],
                        technique_id=entry["technique"],
                        confidence=entry["confidence"],
                    )

        return None

    def _create_graph_structures(self, chain: PrivescChain) -> tuple[int, int]:
        """Create privilege context nodes and edges for a chain.

        Returns (nodes_created, edges_created).
        """
        graph = self.store.builder.graph
        host_id = chain.host_id
        nodes_created = 0
        edges_created = 0

        # Collect all privilege levels involved
        levels: set[PrivilegeLevel] = set()
        for vector in chain.vectors:
            levels.add(vector.source_level)
            levels.add(vector.target_level)

        # Create context nodes for each privilege level
        level_nodes: dict[PrivilegeLevel, str] = {}
        for level in levels:
            node_id = f"priv:{level.name}@{host_id}"
            level_nodes[level] = node_id
            if node_id not in graph:
                graph.add_node(
                    node_id,
                    type="priv_context",
                    label=f"{level.name} on {host_id}",
                    privilege_level=level.value,
                    host_id=host_id,
                )
                nodes_created += 1

        # Create HAS_PRIV_CONTEXT edges from host to context nodes
        for level, node_id in level_nodes.items():
            rel = Relationship(
                source_id=host_id,
                target_id=node_id,
                relation_type=RelationType.HAS_PRIV_CONTEXT,
                weight=1.0,
                confidence=1.0,
                source="privesc_chainer",
            )
            self.store.add_entity(rel)
            edges_created += 1

        # Create CAN_PRIVESC edges between privilege levels
        for vector in chain.vectors:
            src_node = level_nodes.get(vector.source_level)
            tgt_node = level_nodes.get(vector.target_level)
            if src_node and tgt_node:
                rel = Relationship(
                    source_id=src_node,
                    target_id=tgt_node,
                    relation_type=RelationType.CAN_PRIVESC,
                    weight=vector.confidence,
                    confidence=vector.confidence,
                    properties={
                        "finding_id": vector.finding_id,
                        "finding_title": vector.finding_title,
                        "technique_id": vector.technique_id,
                        "source_level": vector.source_level.name,
                        "target_level": vector.target_level.name,
                    },
                    source="privesc_chainer",
                )
                self.store.add_entity(rel)
                edges_created += 1

        # Connect incoming lateral movement edges to UNPRIVILEGED context
        unpriv_node = level_nodes.get(PrivilegeLevel.UNPRIVILEGED)
        if unpriv_node:
            for pred in list(graph.predecessors(host_id)):
                edge_data = graph.edges.get((pred, host_id), {})
                edge_type = edge_data.get("type", "")
                if edge_type in _LATERAL_MOVE_TYPES:
                    # Add edge from predecessor to UNPRIVILEGED context
                    rel = Relationship(
                        source_id=pred,
                        target_id=unpriv_node,
                        relation_type=RelationType.HAS_PRIV_CONTEXT,
                        weight=edge_data.get("weight", 1.0),
                        confidence=edge_data.get("confidence", 1.0),
                        source="privesc_chainer",
                    )
                    self.store.add_entity(rel)
                    edges_created += 1

        # Connect highest privilege context to outgoing edges
        highest_level = chain.target_level
        highest_node = level_nodes.get(highest_level)
        if highest_node:
            for succ in list(graph.successors(host_id)):
                edge_data = graph.edges.get((host_id, succ), {})
                edge_type = edge_data.get("type", "")
                if edge_type in _LATERAL_MOVE_TYPES:
                    rel = Relationship(
                        source_id=highest_node,
                        target_id=succ,
                        relation_type=RelationType.HAS_PRIV_CONTEXT,
                        weight=edge_data.get("weight", 1.0),
                        confidence=edge_data.get("confidence", 1.0),
                        source="privesc_chainer",
                    )
                    self.store.add_entity(rel)
                    edges_created += 1

        return nodes_created, edges_created
