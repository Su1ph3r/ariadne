"""Attack path probability scoring."""

import networkx as nx

from ariadne.config import AriadneConfig
from ariadne.models.attack_path import AttackPath


class PathScorer:
    """Calculate probability scores for attack paths."""

    def __init__(self, config: AriadneConfig) -> None:
        self.config = config
        self.weights = config.scoring.weights

    def score_path(self, path: AttackPath, graph: nx.DiGraph) -> float:
        """Calculate overall probability score for an attack path.

        Factors considered:
        - CVSS scores of vulnerabilities used
        - Exploit availability
        - Network position (external vs internal)
        - Privilege requirements
        - Detection likelihood
        - Path length (longer = lower probability)
        """
        if not path.steps:
            return 0.0

        cvss_score = self._score_cvss(path, graph)
        exploit_score = self._score_exploit_availability(path, graph)
        position_score = self._score_network_position(path, graph)
        privilege_score = self._score_privilege_requirements(path, graph)
        detection_score = self._score_detection_likelihood(path)

        base_score = (
            cvss_score * self.weights.cvss
            + exploit_score * self.weights.exploit_available
            + position_score * self.weights.network_position
            + privilege_score * self.weights.privilege_required
            + (1 - detection_score) * self.weights.detection_likelihood
        )

        length_penalty = max(0.5, 1.0 - (len(path.steps) - 1) * 0.05)
        base_score *= length_penalty

        if path.llm_confidence > 0:
            base_score = (base_score * 0.7) + (path.llm_confidence * 0.3)

        return min(1.0, max(0.0, base_score))

    def _score_cvss(self, path: AttackPath, graph: nx.DiGraph) -> float:
        """Score based on CVSS of vulnerabilities in the path."""
        cvss_scores = []

        for step in path.steps:
            for finding_id in step.finding_ids:
                if finding_id in graph.nodes:
                    node_data = graph.nodes[finding_id]
                    score = node_data.get("severity_score", 0.5)
                    cvss_scores.append(score)

        if not cvss_scores:
            return 0.5

        return sum(cvss_scores) / len(cvss_scores)

    def _score_exploit_availability(self, path: AttackPath, graph: nx.DiGraph) -> float:
        """Score based on exploit availability for vulnerabilities."""
        exploitable_count = 0
        total_vulns = 0

        for step in path.steps:
            for finding_id in step.finding_ids:
                if finding_id in graph.nodes:
                    node_data = graph.nodes[finding_id]
                    data = node_data.get("data", {})
                    total_vulns += 1

                    if isinstance(data, dict):
                        if data.get("exploit_available") or data.get("metasploit_module"):
                            exploitable_count += 1

        if total_vulns == 0:
            return 0.3

        return exploitable_count / total_vulns

    def _score_network_position(self, path: AttackPath, graph: nx.DiGraph) -> float:
        """Score based on network positioning.

        External entry points are more valuable than internal-only paths.
        """
        entry_point = path.entry_point_id
        if entry_point not in graph.nodes:
            return 0.5

        node_data = graph.nodes[entry_point]
        node_type = node_data.get("type", "")

        if node_type == "service":
            port = node_data.get("port", 0)
            if port in [80, 443, 8080, 8443]:
                return 0.9
            elif port in [22, 3389]:
                return 0.7
            elif port in [445, 139]:
                return 0.6

        return 0.5

    def _score_privilege_requirements(self, path: AttackPath, graph: nx.DiGraph) -> float:
        """Score based on privilege requirements.

        Paths requiring lower privileges score higher.
        """
        high_priv_steps = 0

        for step in path.steps:
            edge_type = step.action.lower()

            if any(t in edge_type for t in ["admin", "root", "system", "dc"]):
                high_priv_steps += 1

        if not path.steps:
            return 0.5

        low_priv_ratio = 1 - (high_priv_steps / len(path.steps))
        return 0.3 + (low_priv_ratio * 0.7)

    def _score_detection_likelihood(self, path: AttackPath) -> float:
        """Score based on detection likelihood.

        Lower detection = higher score.
        """
        if not path.steps:
            return 0.5

        total_detection = sum(step.detection_risk for step in path.steps)
        avg_detection = total_detection / len(path.steps)

        return avg_detection

    def score_step(self, step: dict, graph: nx.DiGraph) -> float:
        """Score an individual attack step."""
        base_score = 0.5

        finding_ids = step.get("finding_ids", [])
        for finding_id in finding_ids:
            if finding_id in graph.nodes:
                node_data = graph.nodes[finding_id]
                severity_score = node_data.get("severity_score", 0.5)
                base_score = max(base_score, severity_score)

        return base_score
