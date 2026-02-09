"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ariadne.engine.privesc import PrivescReport
from ariadne.engine.sprawl import SprawlReport
from ariadne.models.attack_path import AttackPath
from ariadne.models.playbook import Playbook


class JsonReporter:
    """Generate JSON reports from attack paths."""

    def generate(
        self,
        paths: list[AttackPath],
        output_path: Path,
        stats: dict | None = None,
        playbooks: list[Playbook] | None = None,
        sprawl_report: SprawlReport | None = None,
        privesc_report: PrivescReport | None = None,
    ) -> Path:
        """Generate a JSON report.

        Args:
            paths: List of attack paths to include
            output_path: Output file path
            stats: Optional graph statistics

        Returns:
            Path to generated report
        """
        output_file = output_path.with_suffix(".json")

        # Build playbook lookup by attack_path_id
        playbook_map: dict[str, Playbook] = {}
        if playbooks:
            for pb in playbooks:
                playbook_map[pb.attack_path_id] = pb

        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "Ariadne Attack Path Synthesizer",
                "version": "0.1.0",
                "total_paths": len(paths),
            },
            "summary": self._generate_summary(paths),
            "attack_paths": [
                self._serialize_path(p, playbook_map.get(p.id)) for p in paths
            ],
        }

        if stats:
            report["environment"] = stats

        if sprawl_report and sprawl_report.clusters:
            report["credential_sprawl"] = {
                "total_credentials": sprawl_report.total_credentials,
                "total_reused": sprawl_report.total_reused,
                "relationships_created": sprawl_report.relationships_created,
                "clusters": [
                    {
                        "display_name": c.display_name,
                        "canonical_id": c.canonical_id,
                        "sprawl_score": c.sprawl_score,
                        "host_count": len(set(c.affected_asset_ids)),
                        "affected_assets": c.affected_asset_ids,
                        "credential_ids": c.credential_ids,
                    }
                    for c in sprawl_report.clusters
                ],
            }

        if privesc_report and privesc_report.chains:
            report["privesc_chains"] = {
                "hosts_with_privesc": privesc_report.hosts_with_privesc,
                "total_vectors": privesc_report.total_vectors,
                "context_nodes_created": privesc_report.context_nodes_created,
                "edges_created": privesc_report.edges_created,
                "chains": [
                    {
                        "host_id": chain.host_id,
                        "source_level": chain.source_level.name,
                        "target_level": chain.target_level.name,
                        "max_confidence": chain.max_confidence,
                        "vectors": [
                            {
                                "finding_id": v.finding_id,
                                "finding_title": v.finding_title,
                                "source_level": v.source_level.name,
                                "target_level": v.target_level.name,
                                "technique_id": v.technique_id,
                                "confidence": v.confidence,
                            }
                            for v in chain.vectors
                        ],
                    }
                    for chain in privesc_report.chains
                ],
            }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return output_file

    def _generate_summary(self, paths: list[AttackPath]) -> dict:
        """Generate summary statistics."""
        if not paths:
            return {
                "total_paths": 0,
                "avg_probability": 0,
                "avg_length": 0,
                "tactics_used": [],
            }

        tactics = set()
        for path in paths:
            tactics.update(path.tactics_used)

        return {
            "total_paths": len(paths),
            "avg_probability": sum(p.probability for p in paths) / len(paths),
            "max_probability": max(p.probability for p in paths),
            "min_probability": min(p.probability for p in paths),
            "avg_length": sum(p.length for p in paths) / len(paths),
            "tactics_used": list(tactics),
            "critical_paths": sum(1 for p in paths if p.probability >= 0.7),
            "high_risk_paths": sum(1 for p in paths if 0.5 <= p.probability < 0.7),
        }

    def _serialize_path(
        self, path: AttackPath, playbook: Playbook | None = None
    ) -> dict:
        """Serialize an attack path for JSON output."""
        result = {
            "id": path.id,
            "name": path.name,
            "description": path.description,
            "probability": path.probability,
            "impact": path.impact,
            "complexity": path.complexity,
            "entry_point": path.entry_point_id,
            "target": path.target_id,
            "length": path.length,
            "risk_score": path.risk_score,
            "tactics_used": path.tactics_used,
            "steps": [
                {
                    "order": step.order,
                    "action": step.action,
                    "description": step.description,
                    "source": step.source_asset_id,
                    "target": step.target_asset_id,
                    "probability": step.probability,
                    "detection_risk": step.detection_risk,
                    "technique": {
                        "id": step.technique.technique_id,
                        "name": step.technique.name,
                        "tactic": step.technique.tactic,
                        "url": step.technique.url,
                    }
                    if step.technique
                    else None,
                    "findings_used": step.finding_ids,
                }
                for step in path.steps
            ],
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                }
                for t in path.techniques
            ],
            "llm_analysis": path.llm_analysis,
            "llm_confidence": path.llm_confidence,
            "created_at": path.created_at.isoformat(),
        }

        if playbook:
            result["playbook"] = self._serialize_playbook(playbook)

        return result

    def _serialize_playbook(self, playbook: Playbook) -> dict:
        """Serialize a playbook for JSON output."""
        return {
            "attack_path_id": playbook.attack_path_id,
            "complexity": playbook.complexity,
            "estimated_time": playbook.estimated_time,
            "llm_enhanced": playbook.llm_enhanced,
            "global_prerequisites": playbook.global_prerequisites,
            "global_opsec_notes": playbook.global_opsec_notes,
            "steps": [
                {
                    "order": step.order,
                    "attack_step_id": step.attack_step_id,
                    "source": step.source,
                    "commands": [
                        {
                            "tool": cmd.tool,
                            "command": cmd.command,
                            "description": cmd.description,
                            "requires_root": cmd.requires_root,
                            "requires_implant": cmd.requires_implant,
                        }
                        for cmd in step.commands
                    ],
                    "prerequisites": step.prerequisites,
                    "opsec_notes": step.opsec_notes,
                    "fallback_commands": [
                        {
                            "tool": cmd.tool,
                            "command": cmd.command,
                            "description": cmd.description,
                            "requires_root": cmd.requires_root,
                            "requires_implant": cmd.requires_implant,
                        }
                        for cmd in step.fallback_commands
                    ],
                    "expected_output": step.expected_output,
                    "detection_signatures": step.detection_signatures,
                }
                for step in playbook.steps
            ],
        }
