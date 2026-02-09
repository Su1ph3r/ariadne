"""Graph storage abstraction for persistence and export."""

import json
from pathlib import Path
from typing import Any, Iterator, Union

import networkx as nx

from ariadne.models.asset import Asset, Service
from ariadne.models.finding import Finding
from ariadne.models.relationship import Relationship
from ariadne.graph.builder import GraphBuilder

Entity = Union[Asset, Finding, Relationship]


class GraphStore:
    """Storage abstraction for the knowledge graph."""

    def __init__(self) -> None:
        self._builder = GraphBuilder()
        self._graph: nx.DiGraph | None = None

    @property
    def graph(self) -> nx.DiGraph:
        """Get the current graph, building if necessary."""
        if self._graph is None:
            self._graph = self._builder.build()
        return self._graph

    @property
    def builder(self) -> GraphBuilder:
        """Get the underlying graph builder."""
        return self._builder

    def add_entity(self, entity: Entity) -> None:
        """Add an entity to the graph."""
        self._builder.add_entity(entity)
        self._graph = None

    def build_from_entities(self, entities: Iterator[Entity]) -> None:
        """Build the graph from an iterator of entities."""
        self._builder.add_entities(entities)
        self._graph = None

    def get_all_entities(self) -> list[Entity]:
        """Get all stored entity objects."""
        entities: list[Entity] = []
        b = self._builder
        entities.extend(b._hosts.values())
        entities.extend(b._services.values())
        entities.extend(b._users.values())
        entities.extend(b._cloud_resources.values())
        entities.extend(b._containers.values())
        entities.extend(b._mobile_apps.values())
        entities.extend(b._api_endpoints.values())
        entities.extend(b._findings.values())
        return entities

    def clear(self) -> None:
        """Clear the graph."""
        self._builder = GraphBuilder()
        self._graph = None

    def stats(self) -> dict:
        """Get graph statistics."""
        return self._builder.stats()

    def get_entity_data(self, node_id: str) -> dict[str, Any] | None:
        """Get full entity data for a node.

        Args:
            node_id: The node identifier

        Returns:
            Dictionary of entity data, or None if not found
        """
        return self._builder.get_entity_data(node_id)

    def export(self, output_path: Path, format: str = "json") -> Path:
        """Export the graph to various formats.

        Args:
            output_path: Base path for output (extension added based on format)
            format: Export format (json, graphml, neo4j-cypher, gexf)

        Returns:
            Path to the exported file
        """
        exporters = {
            "json": self._export_json,
            "graphml": self._export_graphml,
            "neo4j-cypher": self._export_neo4j_cypher,
            "gexf": self._export_gexf,
        }

        if format not in exporters:
            raise ValueError(f"Unknown export format: {format}. Available: {list(exporters.keys())}")

        return exporters[format](output_path)

    def _export_json(self, output_path: Path) -> Path:
        """Export to JSON format."""
        output_file = output_path.with_suffix(".json")

        data = nx.node_link_data(self.graph)

        # Enrich nodes with full entity data from builder
        for node in data["nodes"]:
            node_id = node.get("id")
            if node_id:
                entity_data = self._builder.get_entity_data(node_id)
                if entity_data:
                    node["data"] = entity_data

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return output_file

    def _export_graphml(self, output_path: Path) -> Path:
        """Export to GraphML format."""
        output_file = output_path.with_suffix(".graphml")

        export_graph = self.graph.copy()
        for node in export_graph.nodes():
            data = export_graph.nodes[node]
            # Add entity data for export
            entity_data = self._builder.get_entity_data(node)
            if entity_data:
                data["data_json"] = json.dumps(entity_data, default=str)
            for key, value in list(data.items()):
                if isinstance(value, (dict, list)):
                    data[key] = json.dumps(value, default=str)

        for u, v in export_graph.edges():
            data = export_graph.edges[u, v]
            if "properties" in data:
                data["properties_json"] = json.dumps(data["properties"], default=str)
                del data["properties"]

        nx.write_graphml(export_graph, output_file)
        return output_file

    def _export_neo4j_cypher(self, output_path: Path) -> Path:
        """Export to Neo4j Cypher statements."""
        output_file = output_path.with_suffix(".cypher")

        statements = []

        statements.append("// Clear existing data (optional)")
        statements.append("// MATCH (n) DETACH DELETE n;\n")

        statements.append("// Create nodes")
        for node_id, data in self.graph.nodes(data=True):
            node_type = data.get("type", "Entity").title().replace("_", "")
            label = data.get("label", node_id)

            props = {
                "id": node_id,
                "label": label,
                "type": data.get("type"),
            }

            for key in ["severity", "severity_score", "ip", "hostname", "port", "username"]:
                if key in data and data[key] is not None:
                    props[key] = data[key]

            props_str = ", ".join(
                f"{k}: {json.dumps(v)}" for k, v in props.items() if v is not None
            )

            statements.append(f"CREATE (:{node_type} {{{props_str}}});")

        statements.append("\n// Create relationships")
        for source, target, data in self.graph.edges(data=True):
            rel_type = data.get("type", "RELATED_TO").upper().replace(" ", "_")
            weight = data.get("weight", 1.0)

            statements.append(
                f"MATCH (a {{id: {json.dumps(source)}}}), (b {{id: {json.dumps(target)}}}) "
                f"CREATE (a)-[:{rel_type} {{weight: {weight}}}]->(b);"
            )

        with open(output_file, "w") as f:
            f.write("\n".join(statements))

        return output_file

    def _export_gexf(self, output_path: Path) -> Path:
        """Export to GEXF format (Gephi)."""
        output_file = output_path.with_suffix(".gexf")

        export_graph = self.graph.copy()
        for node in export_graph.nodes():
            data = export_graph.nodes[node]
            for key, value in list(data.items()):
                if isinstance(value, (dict, list)):
                    data[key] = json.dumps(value, default=str)

        for u, v in export_graph.edges():
            data = export_graph.edges[u, v]
            for key, value in list(data.items()):
                if isinstance(value, (dict, list)):
                    data[key] = json.dumps(value, default=str)

        nx.write_gexf(export_graph, output_file)
        return output_file

    def load_json(self, input_path: Path) -> None:
        """Load a graph from JSON format."""
        with open(input_path) as f:
            data = json.load(f)

        self._graph = nx.node_link_graph(data)
        self._builder = GraphBuilder()
        self._builder.graph = self._graph
