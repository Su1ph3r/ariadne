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
