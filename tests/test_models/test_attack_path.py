"""Tests for attack path models (AttackTechnique, AttackStep, AttackPath)."""

import pytest
from datetime import datetime

from ariadne.models.attack_path import AttackTechnique, AttackStep, AttackPath


class TestAttackTechnique:
    """Test AttackTechnique model."""

    def test_technique_required_fields(self):
        """Test AttackTechnique required fields."""
        technique = AttackTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
        )
        assert technique.technique_id == "T1021"
        assert technique.name == "Remote Services"
        assert technique.tactic == "Lateral Movement"

    def test_technique_defaults(self):
        """Test AttackTechnique default values."""
        technique = AttackTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
        )
        assert technique.description is None
        assert technique.sub_technique is None

    def test_technique_url_auto_generation(self):
        """Test AttackTechnique URL is auto-generated."""
        technique = AttackTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
        )
        assert technique.url == "https://attack.mitre.org/techniques/T1021/"

    def test_technique_url_with_subtechnique(self):
        """Test AttackTechnique URL for sub-technique."""
        technique = AttackTechnique(
            technique_id="T1021.002",
            name="Remote Services: SMB/Windows Admin Shares",
            tactic="Lateral Movement",
        )
        assert technique.url == "https://attack.mitre.org/techniques/T1021/002/"

    def test_technique_url_not_overwritten(self):
        """Test AttackTechnique URL is not overwritten if provided."""
        technique = AttackTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
            url="https://custom.url/",
        )
        assert technique.url == "https://custom.url/"

    def test_technique_with_description(self):
        """Test AttackTechnique with description."""
        technique = AttackTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
            description="Adversaries may use Valid Accounts to log into a service.",
        )
        assert "Valid Accounts" in technique.description

    def test_technique_with_subtechnique_field(self):
        """Test AttackTechnique with sub_technique field."""
        technique = AttackTechnique(
            technique_id="T1021.002",
            name="SMB/Windows Admin Shares",
            tactic="Lateral Movement",
            sub_technique="002",
        )
        assert technique.sub_technique == "002"


class TestAttackStep:
    """Test AttackStep model."""

    def test_step_has_id(self):
        """Test AttackStep has auto-generated ID."""
        step = AttackStep(
            source_asset_id="host:a",
            target_asset_id="host:b",
            action="Move",
            description="Lateral movement",
        )
        assert step.id is not None
        assert len(step.id) > 0

    def test_step_required_fields(self):
        """Test AttackStep required fields."""
        step = AttackStep(
            source_asset_id="host:192.168.1.1",
            target_asset_id="host:192.168.1.2",
            action="Lateral Movement",
            description="Move via SMB",
        )
        assert step.source_asset_id == "host:192.168.1.1"
        assert step.target_asset_id == "host:192.168.1.2"
        assert step.action == "Lateral Movement"
        assert step.description == "Move via SMB"

    def test_step_defaults(self):
        """Test AttackStep default values."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
        )
        assert step.order == 0
        assert step.relationship_id is None
        assert step.technique is None
        assert step.finding_ids == []
        assert step.prerequisites == []
        assert step.probability == 1.0
        assert step.detection_risk == 0.5
        assert step.impact == "medium"
        assert step.notes is None

    def test_step_with_all_fields(self):
        """Test AttackStep with all fields populated."""
        technique = AttackTechnique(
            technique_id="T1021.002",
            name="SMB/Windows Admin Shares",
            tactic="Lateral Movement",
        )
        step = AttackStep(
            order=1,
            source_asset_id="host:ws01",
            target_asset_id="host:dc01",
            relationship_id="rel:ws01-admin_to->dc01",
            action="Lateral Movement via SMB",
            description="Use admin credentials to access DC.",
            technique=technique,
            finding_ids=["vuln:CVE-2023-1234"],
            prerequisites=["Valid credentials for target"],
            probability=0.85,
            detection_risk=0.4,
            impact="high",
            notes="Requires network access to 445/tcp",
        )
        assert step.order == 1
        assert step.technique is not None
        assert step.technique.technique_id == "T1021.002"
        assert step.probability == 0.85
        assert step.detection_risk == 0.4
        assert step.impact == "high"

    def test_step_risk_score_calculation(self):
        """Test AttackStep risk_score property."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            probability=0.8,
            detection_risk=0.5,
        )
        expected = 0.8 * (1 - 0.5 * 0.5)
        assert abs(step.risk_score - expected) < 0.001

    def test_step_risk_score_high_detection(self):
        """Test AttackStep risk_score with high detection risk."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            probability=1.0,
            detection_risk=1.0,
        )
        assert step.risk_score == 0.5

    def test_step_risk_score_low_detection(self):
        """Test AttackStep risk_score with low detection risk."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            probability=1.0,
            detection_risk=0.0,
        )
        assert step.risk_score == 1.0


class TestAttackPath:
    """Test AttackPath model."""

    def test_path_has_id(self):
        """Test AttackPath has auto-generated ID."""
        path = AttackPath(name="Test Path")
        assert path.id is not None
        assert len(path.id) > 0

    def test_path_required_name(self):
        """Test AttackPath requires name."""
        path = AttackPath(name="Domain Compromise")
        assert path.name == "Domain Compromise"

    def test_path_defaults(self):
        """Test AttackPath default values."""
        path = AttackPath(name="Test")
        assert path.description == ""
        assert path.steps == []
        assert path.entry_point_id == ""
        assert path.target_id == ""
        assert path.probability == 0.0
        assert path.impact == "high"
        assert path.complexity == "medium"
        assert path.techniques == []
        assert path.findings_used == []
        assert path.llm_analysis is None
        assert path.llm_confidence == 0.0
        assert isinstance(path.created_at, datetime)

    def test_path_with_all_fields(self):
        """Test AttackPath with all fields populated."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            probability=0.8,
        )
        path = AttackPath(
            name="Domain Compromise",
            description="Exploit EternalBlue to gain domain admin.",
            steps=[step],
            entry_point_id="host:external",
            target_id="host:dc01",
            probability=0.8,
            impact="critical",
            complexity="low",
            findings_used=["vuln:CVE-2017-0144"],
            llm_analysis="This attack path is highly viable.",
            llm_confidence=0.9,
        )
        assert path.description != ""
        assert len(path.steps) == 1
        assert path.impact == "critical"
        assert path.llm_confidence == 0.9

    def test_path_length_property(self):
        """Test AttackPath length property."""
        steps = [
            AttackStep(
                source_asset_id=f"node{i}",
                target_asset_id=f"node{i+1}",
                action="Move",
                description="Step",
            )
            for i in range(5)
        ]
        path = AttackPath(name="Long Path", steps=steps)
        assert path.length == 5

    def test_path_length_empty(self):
        """Test AttackPath length property with no steps."""
        path = AttackPath(name="Empty")
        assert path.length == 0

    def test_path_tactics_used(self):
        """Test AttackPath tactics_used property."""
        steps = [
            AttackStep(
                source_asset_id="a",
                target_asset_id="b",
                action="Initial Access",
                description="Step 1",
                technique=AttackTechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                ),
            ),
            AttackStep(
                source_asset_id="b",
                target_asset_id="c",
                action="Lateral Movement",
                description="Step 2",
                technique=AttackTechnique(
                    technique_id="T1021.002",
                    name="SMB/Windows Admin Shares",
                    tactic="Lateral Movement",
                ),
            ),
        ]
        path = AttackPath(name="Multi-tactic", steps=steps)
        assert "Initial Access" in path.tactics_used
        assert "Lateral Movement" in path.tactics_used
        assert len(path.tactics_used) == 2

    def test_path_tactics_used_no_duplicates(self):
        """Test AttackPath tactics_used doesn't have duplicates."""
        steps = [
            AttackStep(
                source_asset_id="a",
                target_asset_id="b",
                action="Move 1",
                description="Step 1",
                technique=AttackTechnique(
                    technique_id="T1021.001",
                    name="Remote Desktop Protocol",
                    tactic="Lateral Movement",
                ),
            ),
            AttackStep(
                source_asset_id="b",
                target_asset_id="c",
                action="Move 2",
                description="Step 2",
                technique=AttackTechnique(
                    technique_id="T1021.002",
                    name="SMB/Windows Admin Shares",
                    tactic="Lateral Movement",
                ),
            ),
        ]
        path = AttackPath(name="Same Tactic", steps=steps)
        assert len(path.tactics_used) == 1
        assert path.tactics_used[0] == "Lateral Movement"

    def test_path_tactics_used_empty_for_no_techniques(self):
        """Test AttackPath tactics_used is empty when no techniques."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
        )
        path = AttackPath(name="No Techniques", steps=[step])
        assert path.tactics_used == []

    def test_path_risk_score(self):
        """Test AttackPath risk_score property."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
        )
        path = AttackPath(name="Test", steps=[step], probability=0.8, impact="critical")
        assert path.risk_score == 0.8 * 1.0

    def test_path_risk_score_high_impact(self):
        """Test AttackPath risk_score with high impact."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
        )
        path = AttackPath(name="Test", steps=[step], probability=1.0, impact="high")
        assert path.risk_score == 1.0 * 0.8

    def test_path_risk_score_medium_impact(self):
        """Test AttackPath risk_score with medium impact."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
        )
        path = AttackPath(name="Test", steps=[step], probability=1.0, impact="medium")
        assert path.risk_score == 1.0 * 0.5

    def test_path_risk_score_low_impact(self):
        """Test AttackPath risk_score with low impact."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
        )
        path = AttackPath(name="Test", steps=[step], probability=1.0, impact="low")
        assert path.risk_score == 1.0 * 0.3

    def test_path_risk_score_no_steps(self):
        """Test AttackPath risk_score with no steps returns 0."""
        path = AttackPath(name="Empty", probability=0.8, impact="critical")
        assert path.risk_score == 0.0

    def test_path_add_step(self):
        """Test AttackPath add_step method."""
        path = AttackPath(name="Test")
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            probability=0.8,
        )
        path.add_step(step)

        assert len(path.steps) == 1
        assert path.steps[0].order == 0
        assert path.probability == 0.8

    def test_path_add_multiple_steps(self):
        """Test AttackPath add_step with multiple steps."""
        path = AttackPath(name="Test")
        for i in range(3):
            step = AttackStep(
                source_asset_id=f"node{i}",
                target_asset_id=f"node{i+1}",
                action="Move",
                description=f"Step {i}",
                probability=0.9,
            )
            path.add_step(step)

        assert len(path.steps) == 3
        assert path.steps[0].order == 0
        assert path.steps[1].order == 1
        assert path.steps[2].order == 2
        assert abs(path.probability - 0.9**3) < 0.001

    def test_path_recalculate_probability(self):
        """Test AttackPath probability is recalculated correctly."""
        steps = [
            AttackStep(
                source_asset_id=f"node{i}",
                target_asset_id=f"node{i+1}",
                action="Move",
                description=f"Step {i}",
                probability=0.5,
            )
            for i in range(3)
        ]
        path = AttackPath(name="Test", steps=steps)
        path._recalculate_probability()
        assert abs(path.probability - 0.125) < 0.001

    def test_path_to_narrative_empty(self):
        """Test AttackPath to_narrative with no steps."""
        path = AttackPath(name="Empty")
        narrative = path.to_narrative()
        assert "Empty attack path" in narrative

    def test_path_to_narrative_with_steps(self):
        """Test AttackPath to_narrative with steps."""
        step = AttackStep(
            source_asset_id="host:ws01",
            target_asset_id="host:dc01",
            action="Lateral Movement",
            description="Move to DC via SMB.",
            probability=0.85,
        )
        path = AttackPath(
            name="Domain Compromise",
            description="Compromise the domain controller.",
            steps=[step],
            probability=0.85,
            impact="critical",
        )
        narrative = path.to_narrative()

        assert "Domain Compromise" in narrative
        assert "85" in narrative
        assert "Critical" in narrative
        assert "Lateral Movement" in narrative
        assert "Move to DC via SMB" in narrative

    def test_path_to_narrative_with_technique(self):
        """Test AttackPath to_narrative includes technique info."""
        step = AttackStep(
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            technique=AttackTechnique(
                technique_id="T1021.002",
                name="SMB/Windows Admin Shares",
                tactic="Lateral Movement",
            ),
        )
        path = AttackPath(name="Test", steps=[step], probability=0.8)
        narrative = path.to_narrative()

        assert "T1021.002" in narrative
        assert "SMB/Windows Admin Shares" in narrative

    def test_path_to_narrative_with_llm_analysis(self):
        """Test AttackPath to_narrative includes LLM analysis."""
        path = AttackPath(
            name="Test",
            steps=[],
            llm_analysis="This is a high-risk attack path.",
        )
        path.steps.append(
            AttackStep(
                source_asset_id="a",
                target_asset_id="b",
                action="Move",
                description="Step",
            )
        )
        narrative = path.to_narrative()

        assert "AI Analysis" in narrative
        assert "high-risk" in narrative

    def test_path_to_graph_data(self):
        """Test AttackPath to_graph_data method."""
        steps = [
            AttackStep(
                source_asset_id="host:a",
                target_asset_id="host:b",
                action="Move 1",
                description="Step 1",
                probability=0.8,
            ),
            AttackStep(
                source_asset_id="host:b",
                target_asset_id="host:c",
                action="Move 2",
                description="Step 2",
                probability=0.9,
            ),
        ]
        path = AttackPath(name="Test", steps=steps, probability=0.72)
        graph_data = path.to_graph_data()

        assert "nodes" in graph_data
        assert "edges" in graph_data
        assert "metadata" in graph_data

        assert len(graph_data["nodes"]) == 3
        assert len(graph_data["edges"]) == 2

        node_ids = {n["id"] for n in graph_data["nodes"]}
        assert "host:a" in node_ids
        assert "host:b" in node_ids
        assert "host:c" in node_ids

        assert graph_data["metadata"]["name"] == "Test"
        assert graph_data["metadata"]["probability"] == 0.72

    def test_path_to_graph_data_with_technique(self):
        """Test AttackPath to_graph_data includes technique in edges."""
        step = AttackStep(
            source_asset_id="host:a",
            target_asset_id="host:b",
            action="Move",
            description="Step",
            probability=0.8,
            technique=AttackTechnique(
                technique_id="T1021.002",
                name="SMB/Windows Admin Shares",
                tactic="Lateral Movement",
            ),
        )
        path = AttackPath(name="Test", steps=[step])
        graph_data = path.to_graph_data()

        assert graph_data["edges"][0]["technique"] == "T1021.002"

    def test_path_to_graph_data_no_duplicate_nodes(self):
        """Test AttackPath to_graph_data doesn't create duplicate nodes."""
        steps = [
            AttackStep(
                source_asset_id="host:a",
                target_asset_id="host:b",
                action="Move 1",
                description="Step 1",
            ),
            AttackStep(
                source_asset_id="host:b",
                target_asset_id="host:a",
                action="Move 2",
                description="Step 2",
            ),
        ]
        path = AttackPath(name="Test", steps=steps)
        graph_data = path.to_graph_data()

        assert len(graph_data["nodes"]) == 2
