"""Prompt templates for LLM-based attack path analysis."""


class PromptTemplates:
    """Collection of prompt templates for attack path synthesis."""

    SYSTEM_PROMPT = """You are an expert penetration tester and red team operator analyzing potential attack paths through a target environment. You have deep knowledge of:
- Network exploitation techniques
- Active Directory attack chains
- Web application vulnerabilities
- Cloud security misconfigurations
- MITRE ATT&CK framework

Your task is to analyze security findings and identify realistic attack paths that could be used to compromise high-value targets. Be specific, technical, and realistic in your assessments."""

    PATH_ENUMERATION = """Given the following security findings from a target environment, enumerate possible attack paths from the entry points to the crown jewels.

## Entry Points (Initial Access)
{entry_points}

## High-Value Targets (Crown Jewels)
{targets}

## Discovered Vulnerabilities
{vulnerabilities}

## Network Topology
{topology}

## User/Permission Relationships
{relationships}

For each viable attack path, provide:
1. A descriptive name for the attack chain
2. Step-by-step actions an attacker would take
3. Required vulnerabilities/misconfigurations at each step
4. Probability of success (0-100%)
5. Relevant MITRE ATT&CK techniques

Respond in JSON format:
{{
    "attack_paths": [
        {{
            "name": "Path name",
            "description": "Brief description",
            "probability": 75,
            "steps": [
                {{
                    "order": 1,
                    "action": "Action description",
                    "source": "source_id",
                    "target": "target_id",
                    "technique_id": "T1234",
                    "technique_name": "Technique Name",
                    "tactic": "initial-access",
                    "findings_used": ["finding_id"],
                    "probability": 90
                }}
            ]
        }}
    ]
}}"""

    PATH_VALIDATION = """Evaluate the feasibility of the following attack path and identify any issues or improvements.

## Proposed Attack Path
{attack_path}

## Environment Context
{context}

Analyze:
1. Is each step technically feasible?
2. Are there missing prerequisites?
3. What is the realistic probability of success?
4. What detection risks exist at each step?
5. Are there alternative approaches that would be more reliable?

Respond in JSON format:
{{
    "is_feasible": true,
    "overall_probability": 65,
    "issues": ["Issue 1", "Issue 2"],
    "improvements": ["Suggestion 1"],
    "detection_risks": ["Risk 1"],
    "alternative_steps": []
}}"""

    TECHNIQUE_MAPPING = """Map the following security finding to relevant MITRE ATT&CK techniques.

## Finding
Title: {title}
Type: {finding_type}
Description: {description}
Affected Asset: {asset}
Severity: {severity}

Identify:
1. Primary technique(s) this enables
2. Potential follow-on techniques
3. Relevant tactics
4. Required conditions for exploitation

Respond in JSON format:
{{
    "primary_techniques": [
        {{
            "id": "T1234",
            "name": "Technique Name",
            "tactic": "tactic-name",
            "applicability": "How this finding enables the technique"
        }}
    ],
    "followon_techniques": [
        {{
            "id": "T5678",
            "name": "Follow-on Technique",
            "tactic": "lateral-movement",
            "conditions": "What must be true"
        }}
    ]
}}"""

    NARRATIVE_GENERATION = """Generate a human-readable attack narrative for the following attack path.

## Attack Path
{attack_path}

## Steps
{steps}

## Findings Used
{findings}

Write a detailed narrative that:
1. Explains each step in plain English
2. Describes what an attacker would see/do
3. Notes the tools/techniques involved
4. Highlights critical decision points
5. Estimates time and complexity

Write in the style of a penetration test report finding."""

    PLAYBOOK_STEP_GENERATION = """Generate an operator playbook step for the following attack action.

## Attack Step Context
{step_context}

Generate specific, executable commands that an operator would run to perform this step. Include:
1. Primary command(s) with the exact tool and syntax
2. Fallback commands if the primary approach fails
3. Prerequisites that must be met
4. OPSEC notes for stealth
5. Expected output
6. Detection signatures that defenders would see

Respond in JSON format:
{{
    "commands": [
        {{
            "tool": "tool-name",
            "command": "exact command to run",
            "description": "What this command does",
            "requires_root": false,
            "requires_implant": false
        }}
    ],
    "fallback_commands": [
        {{
            "tool": "alt-tool",
            "command": "fallback command",
            "description": "Alternative approach",
            "requires_root": false,
            "requires_implant": false
        }}
    ],
    "prerequisites": ["Prerequisite 1"],
    "opsec_notes": ["OPSEC note 1"],
    "expected_output": "What the operator should see",
    "detection_signatures": ["Detection signature 1"]
}}"""

    PLAYBOOK_OPSEC_ENHANCEMENT = """Review the following operator playbook and enhance it with OPSEC guidance.

## Playbook
{playbook_context}

For each step, provide:
1. Additional OPSEC notes specific to the attack chain context
2. Additional detection signatures that defenders should monitor
3. Global OPSEC recommendations for the entire operation

Respond in JSON format:
{{
    "global_opsec_notes": ["Global OPSEC note 1"],
    "steps": [
        {{
            "additional_opsec_notes": ["Step-specific OPSEC note"],
            "additional_detection_signatures": ["Detection signature"]
        }}
    ]
}}"""

    REMEDIATION_SUGGESTIONS = """Provide remediation recommendations for the following attack path.

## Attack Path
{attack_path}

## Critical Vulnerabilities
{vulnerabilities}

For each step in the attack path, suggest:
1. Immediate mitigations
2. Long-term fixes
3. Detection opportunities
4. Priority (Critical/High/Medium/Low)

Respond in JSON format:
{{
    "remediations": [
        {{
            "step": 1,
            "vulnerability": "vuln_id",
            "immediate_actions": ["Action 1"],
            "long_term_fixes": ["Fix 1"],
            "detection_rules": ["Detection 1"],
            "priority": "Critical"
        }}
    ],
    "overall_recommendations": ["Recommendation 1"]
}}"""

    @classmethod
    def format_path_enumeration(
        cls,
        entry_points: str,
        targets: str,
        vulnerabilities: str,
        topology: str,
        relationships: str,
    ) -> str:
        """Format the path enumeration prompt."""
        return cls.PATH_ENUMERATION.format(
            entry_points=entry_points,
            targets=targets,
            vulnerabilities=vulnerabilities,
            topology=topology,
            relationships=relationships,
        )

    @classmethod
    def format_path_validation(cls, attack_path: str, context: str) -> str:
        """Format the path validation prompt."""
        return cls.PATH_VALIDATION.format(
            attack_path=attack_path,
            context=context,
        )

    @classmethod
    def format_technique_mapping(
        cls,
        title: str,
        finding_type: str,
        description: str,
        asset: str,
        severity: str,
    ) -> str:
        """Format the technique mapping prompt."""
        return cls.TECHNIQUE_MAPPING.format(
            title=title,
            finding_type=finding_type,
            description=description,
            asset=asset,
            severity=severity,
        )

    @classmethod
    def format_narrative(cls, attack_path: str, steps: str, findings: str) -> str:
        """Format the narrative generation prompt."""
        return cls.NARRATIVE_GENERATION.format(
            attack_path=attack_path,
            steps=steps,
            findings=findings,
        )

    @classmethod
    def format_playbook_step_generation(cls, step_context: str) -> str:
        """Format the playbook step generation prompt."""
        return cls.PLAYBOOK_STEP_GENERATION.format(step_context=step_context)

    @classmethod
    def format_playbook_opsec_enhancement(cls, playbook_context: str) -> str:
        """Format the playbook OPSEC enhancement prompt."""
        return cls.PLAYBOOK_OPSEC_ENHANCEMENT.format(playbook_context=playbook_context)
