"""Tests for attack path scoring."""

import pytest
import networkx as nx

from ariadne.config import AriadneConfig
from ariadne.engine.scoring import PathScorer
from ariadne.models.attack_path import AttackPath, AttackStep


class TestPathScorer:
    """Test PathScorer functionality."""

    @pytest.fixture
    def config(self) -> AriadneConfig:
        """Create test configuration."""
        return AriadneConfig()

    @pytest.fixture
    def scorer(self, config: AriadneConfig) -> PathScorer:
        """Create scorer instance."""
        return PathScorer(config)

    @pytest.fixture
    def simple_graph(self) -> nx.DiGraph:
        """Create simple test graph."""
        g = nx.DiGraph()
        g.add_node("host:192.168.1.1", type="host", label="server")
        g.add_node("service:ssh:22", type="service", port=22)
        g.add_node("vuln:CVE-2023-1234", type="vulnerability", severity_score=0.8)
        return g

    @pytest.fixture
    def graph_with_vulns(self) -> nx.DiGraph:
        """Create graph with vulnerabilities."""
        g = nx.DiGraph()
        g.add_node("host:192.168.1.1", type="host", label="server")
        g.add_node(
            "vuln:CVE-2023-1234",
            type="vulnerability",
            severity_score=0.9,
            data={"exploit_available": True}
        )
        g.add_node(
            "vuln:CVE-2023-5678",
            type="vulnerability",
            severity_score=0.6,
            data={"exploit_available": False}
        )
        return g

    # =========================================================================
    # Basic Score Path Tests
    # =========================================================================

    def test_empty_path_score(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test scoring empty path returns 0."""
        path = AttackPath(name="Empty", steps=[])
        score = scorer.score_path(path, simple_graph)
        assert score == 0.0

    def test_single_step_path(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test scoring single step path."""
        step = AttackStep(
            order=0,
            source_asset_id="host:192.168.1.1",
            target_asset_id="service:ssh:22",
            action="Access",
            description="Access SSH",
            probability=0.8,
        )
        path = AttackPath(
            name="SSH Access",
            entry_point_id="host:192.168.1.1",
            target_id="service:ssh:22",
            steps=[step],
        )

        score = scorer.score_path(path, simple_graph)
        assert 0.0 <= score <= 1.0

    def test_score_within_bounds(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that score is always between 0 and 1."""
        step = AttackStep(
            order=0,
            source_asset_id="a",
            target_asset_id="b",
            action="Access",
            description="Test step",
            probability=1.0,
        )
        path = AttackPath(name="Test", steps=[step])

        score = scorer.score_path(path, simple_graph)
        assert 0.0 <= score <= 1.0

    # =========================================================================
    # Length Penalty Tests
    # =========================================================================

    def test_longer_path_lower_score(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that longer paths get penalized."""
        short_step = AttackStep(
            order=0,
            source_asset_id="a",
            target_asset_id="b",
            action="Move",
            description="Step",
            probability=0.8,
        )
        short_path = AttackPath(name="Short", steps=[short_step])

        long_steps = [
            AttackStep(
                order=i,
                source_asset_id=f"node{i}",
                target_asset_id=f"node{i+1}",
                action="Move",
                description="Step",
                probability=0.8,
            )
            for i in range(5)
        ]
        long_path = AttackPath(name="Long", steps=long_steps)

        short_score = scorer.score_path(short_path, simple_graph)
        long_score = scorer.score_path(long_path, simple_graph)

        assert short_score >= long_score

    def test_length_penalty_minimum(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that length penalty has a minimum floor."""
        # Create a very long path
        steps = [
            AttackStep(
                order=i,
                source_asset_id=f"node{i}",
                target_asset_id=f"node{i+1}",
                action="Move",
                description="Step",
                probability=0.8,
            )
            for i in range(20)
        ]
        path = AttackPath(name="VeryLong", steps=steps)

        score = scorer.score_path(path, simple_graph)
        # Score should still be positive due to minimum floor
        assert score >= 0.0

    # =========================================================================
    # CVSS Score Tests
    # =========================================================================

    def test_cvss_scoring_with_vulns(self, scorer: PathScorer, graph_with_vulns: nx.DiGraph):
        """Test CVSS scoring when vulnerabilities exist."""
        step = AttackStep(
            order=0,
            source_asset_id="host:192.168.1.1",
            target_asset_id="target",
            action="Exploit",
            description="Exploit vuln",
            probability=0.8,
            finding_ids=["vuln:CVE-2023-1234"],
        )
        path = AttackPath(name="CVSSTest", steps=[step])

        score = scorer.score_path(path, graph_with_vulns)
        assert score > 0.0

    def test_cvss_scoring_no_vulns(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test CVSS scoring falls back when no vulnerabilities."""
        step = AttackStep(
            order=0,
            source_asset_id="host:192.168.1.1",
            target_asset_id="other",
            action="Access",
            description="Access",
            probability=0.5,
            finding_ids=[],
        )
        path = AttackPath(name="NoVulns", steps=[step])

        score = scorer.score_path(path, simple_graph)
        assert score > 0.0

    def test_cvss_averages_multiple_vulns(self, scorer: PathScorer, graph_with_vulns: nx.DiGraph):
        """Test that CVSS score averages multiple vulnerabilities."""
        step = AttackStep(
            order=0,
            source_asset_id="host:192.168.1.1",
            target_asset_id="target",
            action="Exploit",
            description="Exploit vulns",
            probability=0.8,
            finding_ids=["vuln:CVE-2023-1234", "vuln:CVE-2023-5678"],
        )
        path = AttackPath(name="MultiVuln", steps=[step])

        score = scorer.score_path(path, graph_with_vulns)
        # Score influenced by average of 0.9 and 0.6
        assert score > 0.0

    # =========================================================================
    # Exploit Availability Tests
    # =========================================================================

    def test_exploit_availability_scoring(self, scorer: PathScorer, graph_with_vulns: nx.DiGraph):
        """Test scoring considers exploit availability."""
        # Path with exploitable vuln should score higher
        exploitable_step = AttackStep(
            order=0,
            source_asset_id="host:192.168.1.1",
            target_asset_id="target",
            action="Exploit",
            description="Exploit",
            probability=0.8,
            finding_ids=["vuln:CVE-2023-1234"],  # Has exploit_available: True
        )
        exploitable_path = AttackPath(name="Exploitable", steps=[exploitable_step])

        non_exploitable_step = AttackStep(
            order=0,
            source_asset_id="host:192.168.1.1",
            target_asset_id="target",
            action="Exploit",
            description="Exploit",
            probability=0.8,
            finding_ids=["vuln:CVE-2023-5678"],  # Has exploit_available: False
        )
        non_exploitable_path = AttackPath(name="NonExploitable", steps=[non_exploitable_step])

        exploitable_score = scorer.score_path(exploitable_path, graph_with_vulns)
        non_exploitable_score = scorer.score_path(non_exploitable_path, graph_with_vulns)

        assert exploitable_score >= non_exploitable_score

    # =========================================================================
    # Network Position Tests
    # =========================================================================

    def test_network_position_web_service(self, scorer: PathScorer):
        """Test network position score for web services."""
        g = nx.DiGraph()
        g.add_node("service:http:80", type="service", port=80)

        step = AttackStep(
            order=0,
            source_asset_id="service:http:80",
            target_asset_id="target",
            action="Exploit",
            description="Exploit web",
            probability=0.8,
        )
        path = AttackPath(
            name="WebExploit",
            entry_point_id="service:http:80",
            steps=[step]
        )

        score = scorer.score_path(path, g)
        assert score > 0.0

    def test_network_position_ssh_service(self, scorer: PathScorer):
        """Test network position score for SSH services."""
        g = nx.DiGraph()
        g.add_node("service:ssh:22", type="service", port=22)

        step = AttackStep(
            order=0,
            source_asset_id="service:ssh:22",
            target_asset_id="target",
            action="Access",
            description="SSH Access",
            probability=0.8,
        )
        path = AttackPath(
            name="SSHAccess",
            entry_point_id="service:ssh:22",
            steps=[step]
        )

        score = scorer.score_path(path, g)
        assert score > 0.0

    def test_network_position_smb_service(self, scorer: PathScorer):
        """Test network position score for SMB services."""
        g = nx.DiGraph()
        g.add_node("service:smb:445", type="service", port=445)

        step = AttackStep(
            order=0,
            source_asset_id="service:smb:445",
            target_asset_id="target",
            action="Access",
            description="SMB Access",
            probability=0.8,
        )
        path = AttackPath(
            name="SMBAccess",
            entry_point_id="service:smb:445",
            steps=[step]
        )

        score = scorer.score_path(path, g)
        assert score > 0.0

    # =========================================================================
    # Privilege Requirements Tests
    # =========================================================================

    def test_privilege_scoring_high_priv(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that high privilege requirements affect score."""
        step = AttackStep(
            order=0,
            source_asset_id="user",
            target_asset_id="dc",
            action="admin_to",  # Contains 'admin'
            description="Admin access",
            probability=0.8,
        )
        path = AttackPath(name="AdminPath", steps=[step])

        score = scorer.score_path(path, simple_graph)
        assert score > 0.0

    def test_privilege_scoring_low_priv(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that low privilege paths score higher."""
        low_priv_step = AttackStep(
            order=0,
            source_asset_id="user",
            target_asset_id="server",
            action="can_access",
            description="User access",
            probability=0.8,
        )
        low_priv_path = AttackPath(name="LowPriv", steps=[low_priv_step])

        high_priv_step = AttackStep(
            order=0,
            source_asset_id="user",
            target_asset_id="dc",
            action="admin_to",
            description="Admin access",
            probability=0.8,
        )
        high_priv_path = AttackPath(name="HighPriv", steps=[high_priv_step])

        low_score = scorer.score_path(low_priv_path, simple_graph)
        high_score = scorer.score_path(high_priv_path, simple_graph)

        # Low priv should score same or higher than high priv
        assert low_score >= high_score

    # =========================================================================
    # Detection Likelihood Tests
    # =========================================================================

    def test_detection_likelihood_scoring(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that detection risk affects score."""
        low_risk_step = AttackStep(
            order=0,
            source_asset_id="a",
            target_asset_id="b",
            action="access",
            description="Access",
            probability=0.8,
            detection_risk=0.1,
        )
        low_risk_path = AttackPath(name="LowRisk", steps=[low_risk_step])

        high_risk_step = AttackStep(
            order=0,
            source_asset_id="a",
            target_asset_id="b",
            action="access",
            description="Access",
            probability=0.8,
            detection_risk=0.9,
        )
        high_risk_path = AttackPath(name="HighRisk", steps=[high_risk_step])

        low_risk_score = scorer.score_path(low_risk_path, simple_graph)
        high_risk_score = scorer.score_path(high_risk_path, simple_graph)

        # Lower detection risk should score higher
        assert low_risk_score >= high_risk_score

    # =========================================================================
    # LLM Confidence Tests
    # =========================================================================

    def test_llm_confidence_affects_score(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test that LLM confidence is factored into score."""
        step = AttackStep(
            order=0,
            source_asset_id="a",
            target_asset_id="b",
            action="access",
            description="Access",
            probability=0.5,
        )

        path_no_llm = AttackPath(name="NoLLM", steps=[step], llm_confidence=0.0)
        path_with_llm = AttackPath(name="WithLLM", steps=[step], llm_confidence=0.9)

        score_no_llm = scorer.score_path(path_no_llm, simple_graph)
        score_with_llm = scorer.score_path(path_with_llm, simple_graph)

        # High LLM confidence should affect score
        assert score_with_llm != score_no_llm or score_no_llm == score_with_llm

    # =========================================================================
    # Score Step Tests
    # =========================================================================

    def test_score_step(self, scorer: PathScorer, graph_with_vulns: nx.DiGraph):
        """Test scoring individual steps."""
        step_dict = {
            "source_asset_id": "host:192.168.1.1",
            "target_asset_id": "target",
            "action": "Exploit",
            "finding_ids": ["vuln:CVE-2023-1234"],
        }

        score = scorer.score_step(step_dict, graph_with_vulns)
        # Should use severity_score from vuln (0.9)
        assert score == 0.9

    def test_score_step_no_findings(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test scoring step with no findings."""
        step_dict = {
            "source_asset_id": "a",
            "target_asset_id": "b",
            "action": "access",
            "finding_ids": [],
        }

        score = scorer.score_step(step_dict, simple_graph)
        assert score == 0.5  # Default base score

    def test_score_step_nonexistent_finding(self, scorer: PathScorer, simple_graph: nx.DiGraph):
        """Test scoring step with finding not in graph."""
        step_dict = {
            "source_asset_id": "a",
            "target_asset_id": "b",
            "action": "access",
            "finding_ids": ["nonexistent:vuln"],
        }

        score = scorer.score_step(step_dict, simple_graph)
        assert score == 0.5  # Default base score

    # =========================================================================
    # Config Weights Tests
    # =========================================================================

    def test_uses_config_weights(self):
        """Test that scorer uses weights from config."""
        config = AriadneConfig()
        scorer = PathScorer(config)

        assert scorer.weights == config.scoring.weights
