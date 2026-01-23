"""Main synthesis engine for attack path generation."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ariadne.config import AriadneConfig
from ariadne.graph.builder import GraphBuilder
from ariadne.graph.queries import GraphQueries
from ariadne.graph.store import GraphStore
from ariadne.llm.client import LLMClient
from ariadne.llm.prompts import PromptTemplates
from ariadne.models.attack_path import AttackPath, AttackStep, AttackTechnique
from ariadne.parsers.registry import ParserRegistry
from ariadne.engine.scoring import PathScorer


@dataclass
class ValidationResult:
    """Result of input validation."""

    valid: bool = True
    file_count: int = 0
    parsers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class Synthesizer:
    """Main orchestrator for attack path synthesis.

    Workflow:
    1. Parse all input files
    2. Build knowledge graph
    3. Identify entry points and targets
    4. Find candidate paths via graph traversal
    5. Use LLM to assess feasibility and enrich paths
    6. Score and rank paths
    """

    def __init__(self, config: AriadneConfig) -> None:
        self.config = config
        self.registry = ParserRegistry()
        self.store = GraphStore()
        self.llm = LLMClient(config)
        self.scorer = PathScorer(config)
        self._queries: GraphQueries | None = None

    @property
    def queries(self) -> GraphQueries:
        """Get graph queries instance."""
        if self._queries is None:
            self._queries = GraphQueries(self.store.graph)
        return self._queries

    def validate(self, input_path: Path) -> ValidationResult:
        """Validate input files without full analysis."""
        result = ValidationResult()

        if not input_path.exists():
            result.valid = False
            result.errors.append(f"Path does not exist: {input_path}")
            return result

        if input_path.is_file():
            files = [input_path]
        else:
            files = [f for f in input_path.rglob("*") if f.is_file()]

        result.file_count = len(files)
        parsers_used = set()

        for file_path in files:
            parser = self.registry.find_parser(file_path)
            if parser:
                parsers_used.add(parser.name)
                is_valid, errors = parser.validate_file(file_path)
                if not is_valid:
                    result.warnings.extend(errors)
            else:
                result.warnings.append(f"No parser for: {file_path.name}")

        result.parsers = list(parsers_used)

        if not parsers_used:
            result.valid = False
            result.errors.append("No parsable files found")

        return result

    def analyze(
        self,
        input_path: Path,
        targets: list[str] | None = None,
        entry_points: list[str] | None = None,
    ) -> list[AttackPath]:
        """Perform full attack path synthesis.

        Args:
            input_path: Path to recon data
            targets: Optional list of target node IDs/patterns
            entry_points: Optional list of entry point node IDs/patterns

        Returns:
            List of synthesized attack paths, ranked by score
        """
        self._parse_input(input_path)

        graph_entry_points = self._resolve_entry_points(entry_points)
        graph_targets = self._resolve_targets(targets)

        candidate_paths = self.queries.find_all_attack_paths(
            entry_points=graph_entry_points,
            targets=graph_targets,
            max_length=self.config.scoring.max_path_length,
            max_paths=self.config.output.max_paths * 3,
        )

        attack_paths = []
        for source, target, path_nodes in candidate_paths:
            attack_path = self._build_attack_path(source, target, path_nodes)
            if attack_path:
                attack_paths.append(attack_path)

        if attack_paths:
            attack_paths = self._enrich_with_llm(attack_paths)

        for path in attack_paths:
            path.probability = self.scorer.score_path(path, self.store.graph)

        attack_paths.sort(key=lambda p: p.probability, reverse=True)

        return attack_paths[: self.config.output.max_paths]

    def _parse_input(self, input_path: Path) -> None:
        """Parse all input files and build the graph."""
        self.store.clear()
        entities = self.registry.parse_path(input_path)
        self.store.build_from_entities(entities)
        self._queries = None

    def _resolve_entry_points(self, patterns: list[str] | None) -> list[str]:
        """Resolve entry point patterns to node IDs."""
        if not patterns:
            return self.queries.find_entry_points()

        resolved = []
        for pattern in patterns:
            for node in self.store.graph.nodes():
                node_data = self.store.graph.nodes[node]
                if self._matches_pattern(node, node_data, pattern):
                    resolved.append(node)

        return resolved or self.queries.find_entry_points()

    def _resolve_targets(self, patterns: list[str] | None) -> list[str]:
        """Resolve target patterns to node IDs."""
        if not patterns:
            return self.queries.find_crown_jewels()

        resolved = []
        for pattern in patterns:
            for node in self.store.graph.nodes():
                node_data = self.store.graph.nodes[node]
                if self._matches_pattern(node, node_data, pattern):
                    resolved.append(node)

        return resolved or self.queries.find_crown_jewels()

    def _matches_pattern(self, node_id: str, node_data: dict, pattern: str) -> bool:
        """Check if a node matches a search pattern."""
        pattern_lower = pattern.lower()

        if pattern_lower in node_id.lower():
            return True

        label = node_data.get("label", "")
        if pattern_lower in label.lower():
            return True

        hostname = node_data.get("hostname", "")
        if hostname and pattern_lower in hostname.lower():
            return True

        ip = node_data.get("ip", "")
        if ip and pattern_lower in ip:
            return True

        return False

    def _build_attack_path(
        self, source: str, target: str, path_nodes: list[str]
    ) -> AttackPath | None:
        """Build an AttackPath from graph path nodes."""
        if len(path_nodes) < 2:
            return None

        steps = []
        for i in range(len(path_nodes) - 1):
            src = path_nodes[i]
            tgt = path_nodes[i + 1]

            edge_data = self.store.graph.edges.get((src, tgt), {})
            src_data = self.store.graph.nodes.get(src, {})
            tgt_data = self.store.graph.nodes.get(tgt, {})

            action = edge_data.get("type", "access").replace("_", " ").title()
            description = f"{action} from {src_data.get('label', src)} to {tgt_data.get('label', tgt)}"

            vulns = self.queries.get_vulnerabilities_on_path([src, tgt])

            step = AttackStep(
                order=i,
                source_asset_id=src,
                target_asset_id=tgt,
                action=action,
                description=description,
                finding_ids=vulns,
                probability=edge_data.get("weight", 0.5),
            )
            steps.append(step)

        src_label = self.store.graph.nodes.get(source, {}).get("label", source)
        tgt_label = self.store.graph.nodes.get(target, {}).get("label", target)

        path = AttackPath(
            name=f"Path: {src_label} → {tgt_label}",
            description=f"Attack path from {src_label} to {tgt_label} via {len(steps)} steps",
            steps=steps,
            entry_point_id=source,
            target_id=target,
        )
        path._recalculate_probability()

        return path

    def _enrich_with_llm(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Use LLM to enrich attack paths with analysis and techniques."""
        try:
            context = self._build_llm_context()

            for path in paths[:10]:
                try:
                    enriched = self._enrich_single_path(path, context)
                    if enriched:
                        path.llm_analysis = enriched.get("analysis", "")
                        path.llm_confidence = enriched.get("confidence", 0.0)

                        for i, step_data in enumerate(enriched.get("steps", [])):
                            if i < len(path.steps):
                                if "technique" in step_data:
                                    path.steps[i].technique = AttackTechnique(
                                        technique_id=step_data["technique"].get("id", ""),
                                        name=step_data["technique"].get("name", ""),
                                        tactic=step_data["technique"].get("tactic", ""),
                                    )
                except Exception:
                    continue

        except Exception:
            pass

        return paths

    def _enrich_single_path(self, path: AttackPath, context: str) -> dict[str, Any] | None:
        """Enrich a single path with LLM analysis."""
        path_json = json.dumps({
            "name": path.name,
            "steps": [
                {
                    "order": s.order,
                    "source": s.source_asset_id,
                    "target": s.target_asset_id,
                    "action": s.action,
                }
                for s in path.steps
            ],
        }, indent=2)

        prompt = PromptTemplates.format_path_validation(path_json, context)

        try:
            return self.llm.complete_json(prompt, PromptTemplates.SYSTEM_PROMPT)
        except Exception:
            return None

    def _build_llm_context(self) -> str:
        """Build context string for LLM prompts."""
        stats = self.store.stats()
        return f"""Environment contains:
- {stats.get('hosts', 0)} hosts
- {stats.get('services', 0)} services
- {stats.get('users', 0)} users
- {stats.get('findings', 0)} findings
- {stats.get('total_edges', 0)} relationships"""

    def export(
        self, paths: list[AttackPath], output_path: Path, format: str = "html"
    ) -> None:
        """Export attack paths to a report file."""
        if format == "json":
            from ariadne.output.json_report import JsonReporter
            reporter = JsonReporter()
        elif format == "html":
            from ariadne.output.html_report import HtmlReporter
            reporter = HtmlReporter()
        else:
            raise ValueError(f"Unknown format: {format}")

        reporter.generate(paths, output_path, self.store.stats())
