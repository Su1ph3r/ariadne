"""PlaybookGenerator — converts attack paths into executable operator playbooks."""

from __future__ import annotations

import json
import logging
from typing import Any

from ariadne.config import AriadneConfig
from ariadne.engine.playbook_templates import (
    PlaybookStepTemplate,
    SafeFormatDict,
    lookup_template,
)
from ariadne.graph.store import GraphStore
from ariadne.models.attack_path import AttackPath, AttackStep
from ariadne.models.finding import Credential
from ariadne.models.playbook import Playbook, PlaybookCommand, PlaybookStep
from ariadne.models.relationship import RelationType

logger = logging.getLogger(__name__)


class PlaybookGenerator:
    """Generates operator playbooks from attack paths.

    Uses a two-tier approach:
    1. Deterministic templates for known RelationType → tool mappings
    2. LLM fills gaps for novel patterns and generates OPSEC context
    """

    def __init__(
        self,
        config: AriadneConfig,
        store: GraphStore,
        llm: Any | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.llm = llm

    def generate(self, paths: list[AttackPath]) -> list[Playbook]:
        """Generate playbooks for a list of attack paths."""
        playbooks = []
        for path in paths:
            playbook = self._generate_playbook(path)
            if self.llm and self.config.playbook.llm_enhance:
                playbook = self._enhance_with_llm(playbook, path)
            playbooks.append(playbook)
        return playbooks

    def _generate_playbook(self, path: AttackPath) -> Playbook:
        """Generate a playbook for a single attack path."""
        steps = []
        for step in path.steps:
            pb_step = self._generate_step(step)
            steps.append(pb_step)

        complexity = "low" if len(steps) <= 2 else "medium" if len(steps) <= 5 else "high"
        estimated_time = f"{len(steps) * 15}-{len(steps) * 30} minutes"

        return Playbook(
            attack_path_id=path.id,
            steps=steps,
            global_prerequisites=self._collect_global_prerequisites(steps),
            global_opsec_notes=self._collect_global_opsec(steps),
            estimated_time=estimated_time,
            complexity=complexity,
        )

    def _generate_step(self, step: AttackStep) -> PlaybookStep:
        """Generate a playbook step from an attack step."""
        relation_type = self._resolve_relation_type(step.action)
        technique_id = step.technique.technique_id if step.technique else None

        template = None
        if relation_type:
            template = lookup_template(relation_type, technique_id)

        if template:
            return self._step_from_template(step, template)

        if self.llm:
            return self._step_from_llm(step)

        return self._manual_fallback_step(step)

    def _resolve_relation_type(self, action: str) -> RelationType | None:
        """Reverse the display_name transform to recover the RelationType.

        Synthesizer produces action strings like "Can Rdp" or "Has Generic All"
        from edge_data['type'] via .replace("_", " ").title().
        We reverse: .lower().replace(" ", "_") to get the enum value.
        """
        normalized = action.lower().replace(" ", "_")
        try:
            return RelationType(normalized)
        except ValueError:
            return None

    def _step_from_template(
        self,
        step: AttackStep,
        template: PlaybookStepTemplate,
    ) -> PlaybookStep:
        """Build a PlaybookStep from a template, filling placeholders with entity data."""
        context = self._resolve_entity_context(step)
        fmt = SafeFormatDict(context)

        commands = []
        for cmd in template.commands:
            commands.append(
                PlaybookCommand(
                    tool=str(cmd["tool"]),
                    command=str(cmd["command"]).format_map(fmt),
                    description=str(cmd.get("description", "")).format_map(fmt),
                    requires_root=bool(cmd.get("requires_root", False)),
                    requires_implant=bool(cmd.get("requires_implant", False)),
                )
            )

        fallback_commands = []
        for cmd in template.fallback_commands[: self.config.playbook.max_fallbacks]:
            fallback_commands.append(
                PlaybookCommand(
                    tool=str(cmd["tool"]),
                    command=str(cmd["command"]).format_map(fmt),
                    description=str(cmd.get("description", "")).format_map(fmt),
                    requires_root=bool(cmd.get("requires_root", False)),
                    requires_implant=bool(cmd.get("requires_implant", False)),
                )
            )

        prerequisites = [str(p).format_map(fmt) for p in template.prerequisites]
        opsec_notes = [str(n).format_map(fmt) for n in template.opsec_notes]
        expected_output = str(template.expected_output).format_map(fmt)

        detection_sigs = []
        if self.config.playbook.include_detection_sigs:
            detection_sigs = [str(s).format_map(fmt) for s in template.detection_signatures]

        return PlaybookStep(
            order=step.order,
            attack_step_id=step.id,
            commands=commands,
            prerequisites=prerequisites,
            opsec_notes=opsec_notes,
            fallback_commands=fallback_commands,
            expected_output=expected_output,
            detection_signatures=detection_sigs,
            source="template",
        )

    def _resolve_entity_context(self, step: AttackStep) -> dict[str, str]:
        """Build placeholder context from source/target entity data and findings."""
        context: dict[str, str] = {}

        # Target entity data
        target_data = self.store.builder.get_entity_data(step.target_asset_id)
        if target_data:
            context["target_ip"] = target_data.get("ip", "")
            context["target_hostname"] = target_data.get("hostname", "")
            context["target_username"] = target_data.get("username", "")
            context["target_domain"] = target_data.get("domain", "")
            context["target_arn"] = target_data.get("arn", "")
            context["target_role"] = target_data.get("name", "")
            context["target_group"] = target_data.get("display_name", "")
            context["app_id"] = target_data.get("app_id", "")
            context["tenant_id"] = target_data.get("tenant_id", "")
            # Port from target if it's a service
            context["port"] = str(target_data.get("port", "22"))
            # Provider detection for cloud
            context["provider"] = target_data.get("provider", "")

        # Source entity data
        source_data = self.store.builder.get_entity_data(step.source_asset_id)
        if source_data:
            context.setdefault("domain", source_data.get("domain", ""))
            context["username"] = source_data.get("username", "")
            context["source_ip"] = source_data.get("ip", "")
            context["source_profile"] = source_data.get("name", "default")

        # Fallback domain from target
        if not context.get("domain") and target_data:
            context["domain"] = target_data.get("domain", "")

        # Also set target_domain from target if not set
        context.setdefault("target_domain", context.get("domain", ""))

        # Credential and vulnerability data from findings
        for finding_id in step.finding_ids:
            entity = self.store.builder.get_entity(finding_id)
            if isinstance(entity, Credential):
                context.setdefault("credential_value", entity.value or "")
                context.setdefault("hash", entity.ntlm_hash or entity.value or "")
                context.setdefault("credential_type", entity.credential_type)
                if entity.username:
                    context.setdefault("username", entity.username)
                if entity.domain:
                    context.setdefault("domain", entity.domain)
                continue

            finding_data = self.store.builder.get_entity_data(finding_id)
            if finding_data:
                context.setdefault("vuln_id", finding_data.get("cve_id", ""))
                context.setdefault(
                    "metasploit_module",
                    finding_data.get("metasploit_module", ""),
                )

        return context

    def _step_from_llm(self, step: AttackStep) -> PlaybookStep:
        """Generate a playbook step via LLM for unrecognized patterns."""
        from ariadne.llm.prompts import PromptTemplates

        context_str = json.dumps(
            {
                "action": step.action,
                "description": step.description,
                "source": step.source_asset_id,
                "target": step.target_asset_id,
                "technique": (
                    {
                        "id": step.technique.technique_id,
                        "name": step.technique.name,
                        "tactic": step.technique.tactic,
                    }
                    if step.technique
                    else None
                ),
            },
            indent=2,
        )

        prompt = PromptTemplates.format_playbook_step_generation(context_str)

        try:
            result = self.llm.complete_json(prompt, PromptTemplates.SYSTEM_PROMPT)
            if result:
                commands = [
                    PlaybookCommand(**cmd) for cmd in result.get("commands", [])
                ]
                fallbacks = [
                    PlaybookCommand(**cmd) for cmd in result.get("fallback_commands", [])
                ]
                return PlaybookStep(
                    order=step.order,
                    attack_step_id=step.id,
                    commands=commands,
                    prerequisites=result.get("prerequisites", []),
                    opsec_notes=result.get("opsec_notes", []),
                    fallback_commands=fallbacks,
                    expected_output=result.get("expected_output", ""),
                    detection_signatures=result.get("detection_signatures", []),
                    source="llm",
                )
        except Exception:
            logger.warning("LLM playbook step generation failed for step %s", step.id)

        return self._manual_fallback_step(step)

    def _manual_fallback_step(self, step: AttackStep) -> PlaybookStep:
        """Create a manual fallback step when no template or LLM is available."""
        return PlaybookStep(
            order=step.order,
            attack_step_id=step.id,
            commands=[
                PlaybookCommand(
                    tool="manual",
                    command=f"# {step.action}: {step.description}",
                    description=step.description,
                )
            ],
            source="manual",
        )

    def _enhance_with_llm(self, playbook: Playbook, path: AttackPath) -> Playbook:
        """Use LLM to add OPSEC context and refine template-generated playbooks."""
        from ariadne.llm.prompts import PromptTemplates

        context_str = json.dumps(
            {
                "path_name": path.name,
                "path_description": path.description,
                "steps": [
                    {
                        "order": s.order,
                        "commands": [c.model_dump() for c in s.commands],
                        "opsec_notes": s.opsec_notes,
                        "prerequisites": s.prerequisites,
                    }
                    for s in playbook.steps
                ],
            },
            indent=2,
        )

        prompt = PromptTemplates.format_playbook_opsec_enhancement(context_str)

        try:
            result = self.llm.complete_json(prompt, PromptTemplates.SYSTEM_PROMPT)
            if result:
                if result.get("global_opsec_notes"):
                    playbook.global_opsec_notes.extend(result["global_opsec_notes"])

                for i, step_data in enumerate(result.get("steps", [])):
                    if i < len(playbook.steps):
                        extra_opsec = step_data.get("additional_opsec_notes", [])
                        playbook.steps[i].opsec_notes.extend(extra_opsec)
                        extra_sigs = step_data.get("additional_detection_signatures", [])
                        playbook.steps[i].detection_signatures.extend(extra_sigs)

                playbook.llm_enhanced = True
        except Exception:
            logger.warning("LLM playbook enhancement failed for path %s", path.id)

        return playbook

    def _collect_global_prerequisites(self, steps: list[PlaybookStep]) -> list[str]:
        """Collect unique prerequisites across all steps."""
        seen: set[str] = set()
        result: list[str] = []
        for step in steps:
            for prereq in step.prerequisites:
                if prereq not in seen:
                    seen.add(prereq)
                    result.append(prereq)
        return result

    def _collect_global_opsec(self, steps: list[PlaybookStep]) -> list[str]:
        """Collect unique OPSEC notes across all steps."""
        seen: set[str] = set()
        result: list[str] = []
        for step in steps:
            for note in step.opsec_notes:
                if note not in seen:
                    seen.add(note)
                    result.append(note)
        return result
