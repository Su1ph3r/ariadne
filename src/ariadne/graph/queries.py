"""Graph query utilities for path finding and analysis."""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Iterator

import networkx as nx

from ariadne.models.relationship import ATTACK_RELATIONSHIPS

logger = logging.getLogger(__name__)


class PathFindingTimeout(Exception):
    """Raised when path finding exceeds the configured timeout."""

    pass


class GraphQueries:
    """Query utilities for the knowledge graph.

    Includes timeout protection and caching for scalable path finding.
    """

    def __init__(self, graph: nx.DiGraph) -> None:
        self.graph = graph
        self._attack_subgraph_cache: nx.DiGraph | None = None
        self._cache_lock = threading.Lock()

    def invalidate_cache(self) -> None:
        """Invalidate the attack subgraph cache.

        Call this when the graph is modified.
        """
        with self._cache_lock:
            self._attack_subgraph_cache = None

    def find_entry_points(self) -> list[str]:
        """Find potential entry points (externally accessible services)."""
        entry_points = []

        for node, data in self.graph.nodes(data=True):
            if data.get("type") == "service":
                port = data.get("port", 0)
                if port in [22, 23, 80, 443, 445, 3389, 8080, 8443]:
                    entry_points.append(node)

            if data.get("type") == "host":
                if not data.get("is_internal", True):
                    entry_points.append(node)

        return entry_points

    def find_crown_jewels(self) -> list[str]:
        """Find high-value targets (domain controllers, admin users, etc.)."""
        targets = []

        for node, data in self.graph.nodes(data=True):
            if data.get("type") == "host" and data.get("is_dc"):
                targets.append(node)

            if data.get("type") == "user" and data.get("is_admin"):
                targets.append(node)

            if data.get("type") == "cloud_resource":
                resource_type = data.get("resource_type", "").lower()
                if any(t in resource_type for t in ["secret", "key", "vault", "admin"]):
                    targets.append(node)

        return targets

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        """Find the shortest path between two nodes."""
        try:
            return nx.shortest_path(self.graph, source, target)
        except nx.NetworkXNoPath:
            return None

    def all_paths(
        self,
        source: str,
        target: str,
        max_length: int = 10,
        max_paths: int | None = None,
    ) -> Iterator[list[str]]:
        """Find all simple paths between two nodes.

        Args:
            source: Source node ID
            target: Target node ID
            max_length: Maximum path length (default: 10)
            max_paths: Maximum number of paths to return (default: None for unlimited)

        Yields:
            Paths as lists of node IDs
        """
        try:
            count = 0
            for path in nx.all_simple_paths(
                self.graph, source, target, cutoff=max_length
            ):
                yield path
                count += 1
                if max_paths is not None and count >= max_paths:
                    return
        except nx.NetworkXNoPath:
            return

    def attack_paths(
        self,
        source: str,
        target: str,
        max_length: int = 10,
        max_paths: int | None = None,
        timeout_seconds: float | None = None,
    ) -> Iterator[list[str]]:
        """Find paths that only use attack-relevant edges.

        Args:
            source: Source node ID
            target: Target node ID
            max_length: Maximum path length (default: 10)
            max_paths: Maximum number of paths to return (default: None for unlimited)
            timeout_seconds: Timeout in seconds (default: None for no timeout)

        Yields:
            Paths as lists of node IDs

        Raises:
            PathFindingTimeout: If timeout is exceeded
        """
        attack_graph = self._get_attack_subgraph()

        if timeout_seconds is not None:
            yield from self._attack_paths_with_timeout(
                attack_graph, source, target, max_length, max_paths, timeout_seconds
            )
        else:
            yield from self._attack_paths_no_timeout(
                attack_graph, source, target, max_length, max_paths
            )

    def _attack_paths_no_timeout(
        self,
        attack_graph: nx.DiGraph,
        source: str,
        target: str,
        max_length: int,
        max_paths: int | None,
    ) -> Iterator[list[str]]:
        """Find attack paths without timeout."""
        try:
            count = 0
            for path in nx.all_simple_paths(
                attack_graph, source, target, cutoff=max_length
            ):
                yield path
                count += 1
                if max_paths is not None and count >= max_paths:
                    return
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return

    def _attack_paths_with_timeout(
        self,
        attack_graph: nx.DiGraph,
        source: str,
        target: str,
        max_length: int,
        max_paths: int | None,
        timeout_seconds: float,
    ) -> Iterator[list[str]]:
        """Find attack paths with timeout protection using threading."""
        paths_found: list[list[str]] = []
        stop_event = threading.Event()

        def collect_paths() -> None:
            try:
                count = 0
                for path in nx.all_simple_paths(
                    attack_graph, source, target, cutoff=max_length
                ):
                    if stop_event.is_set():
                        return
                    paths_found.append(path)
                    count += 1
                    if max_paths is not None and count >= max_paths:
                        return
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(collect_paths)
            try:
                future.result(timeout=timeout_seconds)
            except FuturesTimeoutError:
                stop_event.set()
                logger.warning(
                    "Path finding timed out after %.1f seconds (found %d paths)",
                    timeout_seconds,
                    len(paths_found),
                )

        yield from paths_found

    def find_all_attack_paths(
        self,
        entry_points: list[str] | None = None,
        targets: list[str] | None = None,
        max_length: int = 10,
        max_paths: int = 100,
        timeout_seconds: float | None = 30.0,
    ) -> list[tuple[str, str, list[str]]]:
        """Find all attack paths between entry points and targets.

        Args:
            entry_points: Source nodes (default: auto-detect)
            targets: Target nodes (default: auto-detect crown jewels)
            max_length: Maximum path length (default: 10)
            max_paths: Maximum total paths to return (default: 100)
            timeout_seconds: Timeout in seconds (default: 30.0, None for no timeout)

        Returns:
            List of (source, target, path) tuples
        """
        if entry_points is None:
            entry_points = self.find_entry_points()

        if targets is None:
            targets = self.find_crown_jewels()

        paths: list[tuple[str, str, list[str]]] = []

        # Calculate per-pair timeout to distribute time budget
        num_pairs = len(entry_points) * len(targets)
        pair_timeout = None
        if timeout_seconds is not None and num_pairs > 0:
            pair_timeout = max(1.0, timeout_seconds / num_pairs)

        for source in entry_points:
            for target in targets:
                if source == target:
                    continue

                remaining_paths = max_paths - len(paths)
                if remaining_paths <= 0:
                    return paths

                try:
                    for path in self.attack_paths(
                        source,
                        target,
                        max_length,
                        max_paths=remaining_paths,
                        timeout_seconds=pair_timeout,
                    ):
                        paths.append((source, target, path))
                        if len(paths) >= max_paths:
                            return paths
                except PathFindingTimeout:
                    logger.warning(
                        "Timeout finding paths from %s to %s", source, target
                    )
                    continue

        return paths

    def _get_attack_subgraph(self) -> nx.DiGraph:
        """Get subgraph containing only attack-relevant edges.

        Uses cached subgraph if available.
        """
        with self._cache_lock:
            if self._attack_subgraph_cache is not None:
                return self._attack_subgraph_cache

            attack_edge_types = {r.value for r in ATTACK_RELATIONSHIPS}

            attack_edges = [
                (u, v)
                for u, v, data in self.graph.edges(data=True)
                if data.get("is_attack_edge", False)
                or data.get("type") in attack_edge_types
            ]

            if not attack_edges:
                self._attack_subgraph_cache = self.graph
            else:
                self._attack_subgraph_cache = self.graph.edge_subgraph(attack_edges).copy()

            return self._attack_subgraph_cache

    def get_neighbors(self, node: str, direction: str = "both") -> list[str]:
        """Get neighbors of a node.

        Args:
            node: Node ID
            direction: "in", "out", or "both"
        """
        if direction == "in":
            return list(self.graph.predecessors(node))
        elif direction == "out":
            return list(self.graph.successors(node))
        else:
            return list(set(self.graph.predecessors(node)) | set(self.graph.successors(node)))

    def get_path_score(self, path: list[str]) -> float:
        """Calculate a score for a given path based on edge weights."""
        if len(path) < 2:
            return 0.0

        score = 1.0
        for i in range(len(path) - 1):
            edge_data = self.graph.edges.get((path[i], path[i + 1]), {})
            weight = edge_data.get("weight", 1.0)
            confidence = edge_data.get("confidence", 1.0)
            score *= weight * confidence

        return score

    def get_vulnerabilities_on_path(self, path: list[str]) -> list[str]:
        """Get all vulnerability nodes connected to nodes on a path."""
        vulns = []

        for node in path:
            for neighbor in self.graph.successors(node):
                data = self.graph.nodes.get(neighbor, {})
                if data.get("type") == "vulnerability":
                    vulns.append(neighbor)

        return vulns

    def reachability_analysis(self, source: str) -> dict[str, int]:
        """Analyze what can be reached from a source node.

        Returns:
            Dict mapping node IDs to their distance from source
        """
        try:
            return nx.single_source_shortest_path_length(self.graph, source)
        except nx.NetworkXError:
            return {}

    def centrality_analysis(self) -> dict[str, dict[str, float]]:
        """Calculate various centrality metrics for the graph."""
        return {
            "degree": dict(self.graph.degree()),
            "in_degree": dict(self.graph.in_degree()),
            "out_degree": dict(self.graph.out_degree()),
            "betweenness": nx.betweenness_centrality(self.graph),
            "pagerank": nx.pagerank(self.graph),
        }

    def find_critical_nodes(self, top_n: int = 10) -> list[tuple[str, float]]:
        """Find the most critical nodes based on betweenness centrality."""
        centrality = nx.betweenness_centrality(self.graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:top_n]
