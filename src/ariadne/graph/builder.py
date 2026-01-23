"""Graph builder for constructing the knowledge graph from parsed entities."""

from typing import Iterator, Union

import networkx as nx

from ariadne.models.asset import Asset, Host, Service, User, CloudResource
from ariadne.models.finding import Finding, Vulnerability, Misconfiguration, Credential
from ariadne.models.relationship import Relationship, RelationType, ATTACK_RELATIONSHIPS

Entity = Union[Asset, Finding, Relationship]


class GraphBuilder:
    """Builds a NetworkX graph from parsed security entities."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._hosts: dict[str, Host] = {}
        self._services: dict[str, Service] = {}
        self._users: dict[str, User] = {}
        self._cloud_resources: dict[str, CloudResource] = {}
        self._findings: dict[str, Finding] = {}

    def add_entity(self, entity: Entity) -> None:
        """Add an entity to the graph."""
        if isinstance(entity, Host):
            self._add_host(entity)
        elif isinstance(entity, Service):
            self._add_service(entity)
        elif isinstance(entity, User):
            self._add_user(entity)
        elif isinstance(entity, CloudResource):
            self._add_cloud_resource(entity)
        elif isinstance(entity, (Vulnerability, Misconfiguration, Credential)):
            self._add_finding(entity)
        elif isinstance(entity, Relationship):
            self._add_relationship(entity)

    def add_entities(self, entities: Iterator[Entity]) -> None:
        """Add multiple entities to the graph."""
        for entity in entities:
            self.add_entity(entity)

    def _add_host(self, host: Host) -> None:
        """Add a host node to the graph."""
        self._hosts[host.id] = host
        self.graph.add_node(
            host.id,
            type="host",
            label=host.fqdn,
            ip=host.ip,
            hostname=host.hostname,
            os=host.os,
            is_dc=host.is_dc,
            data=host.model_dump(),
        )

    def _add_service(self, service: Service) -> None:
        """Add a service node and connect to host."""
        self._services[service.id] = service
        self.graph.add_node(
            service.id,
            type="service",
            label=f"{service.name}:{service.port}",
            port=service.port,
            protocol=service.protocol,
            product=service.product,
            version=service.version,
            data=service.model_dump(),
        )

        if service.host_id and service.host_id in self._hosts:
            self.graph.add_edge(
                service.id,
                service.host_id,
                type=RelationType.RUNS_ON.value,
                weight=1.0,
            )

    def _add_user(self, user: User) -> None:
        """Add a user node to the graph."""
        self._users[user.id] = user
        self.graph.add_node(
            user.id,
            type="user",
            label=user.principal_name,
            username=user.username,
            domain=user.domain,
            is_admin=user.is_admin,
            enabled=user.enabled,
            data=user.model_dump(),
        )

    def _add_cloud_resource(self, resource: CloudResource) -> None:
        """Add a cloud resource node to the graph."""
        self._cloud_resources[resource.id] = resource
        self.graph.add_node(
            resource.id,
            type="cloud_resource",
            label=resource.display_name,
            resource_type=resource.resource_type,
            provider=resource.provider,
            region=resource.region,
            data=resource.model_dump(),
        )

    def _add_finding(self, finding: Finding) -> None:
        """Add a finding node and connect to affected asset."""
        self._findings[finding.id] = finding

        finding_type = "vulnerability" if isinstance(finding, Vulnerability) else "misconfiguration"
        if isinstance(finding, Credential):
            finding_type = "credential"

        self.graph.add_node(
            finding.id,
            type=finding_type,
            label=finding.title,
            severity=finding.severity,
            severity_score=finding.severity_score,
            data=finding.model_dump(),
        )

        if finding.affected_asset_id:
            rel_type = RelationType.HAS_VULNERABILITY if isinstance(finding, Vulnerability) else RelationType.HAS_MISCONFIGURATION
            self.graph.add_edge(
                finding.affected_asset_id,
                finding.id,
                type=rel_type.value,
                weight=finding.severity_score,
            )

    def _add_relationship(self, rel: Relationship) -> None:
        """Add a relationship edge to the graph."""
        if rel.source_id not in self.graph:
            self.graph.add_node(rel.source_id, type="unknown")
        if rel.target_id not in self.graph:
            self.graph.add_node(rel.target_id, type="unknown")

        self.graph.add_edge(
            rel.source_id,
            rel.target_id,
            type=rel.relation_type.value,
            weight=rel.weight,
            is_attack_edge=rel.is_attack_edge,
            confidence=rel.confidence,
            properties=rel.properties,
        )

        if rel.bidirectional:
            self.graph.add_edge(
                rel.target_id,
                rel.source_id,
                type=rel.relation_type.value,
                weight=rel.weight,
                is_attack_edge=rel.is_attack_edge,
                confidence=rel.confidence,
                properties=rel.properties,
            )

    def build(self) -> nx.DiGraph:
        """Return the built graph."""
        return self.graph

    def get_attack_graph(self) -> nx.DiGraph:
        """Return a subgraph containing only attack-relevant edges."""
        attack_edges = [
            (u, v)
            for u, v, data in self.graph.edges(data=True)
            if data.get("is_attack_edge", False)
            or data.get("type") in [r.value for r in ATTACK_RELATIONSHIPS]
        ]
        return self.graph.edge_subgraph(attack_edges).copy()

    def stats(self) -> dict:
        """Return statistics about the graph."""
        node_types = {}
        for _, data in self.graph.nodes(data=True):
            t = data.get("type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1

        edge_types = {}
        for _, _, data in self.graph.edges(data=True):
            t = data.get("type", "unknown")
            edge_types[t] = edge_types.get(t, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": node_types,
            "edge_types": edge_types,
            "hosts": len(self._hosts),
            "services": len(self._services),
            "users": len(self._users),
            "findings": len(self._findings),
        }
