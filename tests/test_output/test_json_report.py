"""Tests for JSON report generator."""

import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

from ariadne.output.json_report import JsonReporter
from ariadne.models.attack_path import AttackPath, AttackStep, AttackTechnique


class TestJsonReporterGenerate:
    """Test JsonReporter generate method."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return JsonReporter()

    @pytest.fixture
    def sample_technique(self):
        """Create sample technique."""
        return AttackTechnique(
            technique_id="T1021.001",
            name="Remote Desktop Protocol",
            tactic="lateral-movement",
            description="RDP lateral movement",
        )

    @pytest.fixture
    def sample_step(self, sample_technique):
        """Create sample attack step."""
        return AttackStep(
            order=0,
            action="RDP to target",
            description="Use RDP to move laterally",
            source_asset_id="host:192.168.1.1",
            target_asset_id="host:192.168.1.2",
            technique=sample_technique,
            probability=0.8,
            detection_risk=0.3,
        )

    @pytest.fixture
    def sample_path(self, sample_step):
        """Create sample attack path."""
        path = AttackPath(
            name="Test Attack Path",
            description="A test path for unit testing",
            entry_point_id="host:192.168.1.1",
            target_id="host:192.168.1.2",
        )
        path.add_step(sample_step)
        path.probability = 0.75
        path.impact = "high"
        return path

    def test_generate_creates_file(self, reporter, sample_path, tmp_path):
        """Test generate creates output file."""
        output_path = tmp_path / "report"

        result = reporter.generate([sample_path], output_path)

        assert result.exists()
        assert result.suffix == ".json"

    def test_generate_returns_path_with_json_suffix(self, reporter, sample_path, tmp_path):
        """Test generate returns path with .json suffix."""
        output_path = tmp_path / "report.txt"

        result = reporter.generate([sample_path], output_path)

        assert result.suffix == ".json"

    def test_generate_creates_valid_json(self, reporter, sample_path, tmp_path):
        """Test generated file contains valid JSON."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.json") as f:
            data = json.load(f)

        assert isinstance(data, dict)

    def test_generate_includes_metadata(self, reporter, sample_path, tmp_path):
        """Test generated report includes metadata."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.json") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "generated_at" in data["metadata"]
        assert "generator" in data["metadata"]
        assert "version" in data["metadata"]
        assert "total_paths" in data["metadata"]

    def test_generate_includes_summary(self, reporter, sample_path, tmp_path):
        """Test generated report includes summary."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.json") as f:
            data = json.load(f)

        assert "summary" in data

    def test_generate_includes_attack_paths(self, reporter, sample_path, tmp_path):
        """Test generated report includes attack paths."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.json") as f:
            data = json.load(f)

        assert "attack_paths" in data
        assert len(data["attack_paths"]) == 1

    def test_generate_includes_stats_when_provided(self, reporter, sample_path, tmp_path):
        """Test generated report includes stats when provided."""
        output_path = tmp_path / "report"
        stats = {"nodes": 10, "edges": 15}
        reporter.generate([sample_path], output_path, stats=stats)

        with open(tmp_path / "report.json") as f:
            data = json.load(f)

        assert "environment" in data
        assert data["environment"]["nodes"] == 10

    def test_generate_empty_paths(self, reporter, tmp_path):
        """Test generate with empty paths list."""
        output_path = tmp_path / "report"
        reporter.generate([], output_path)

        with open(tmp_path / "report.json") as f:
            data = json.load(f)

        assert len(data["attack_paths"]) == 0
        assert data["metadata"]["total_paths"] == 0


class TestJsonReporterSummary:
    """Test summary generation."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return JsonReporter()

    def test_summary_empty_paths(self, reporter):
        """Test summary for empty paths."""
        summary = reporter._generate_summary([])

        assert summary["total_paths"] == 0
        assert summary["avg_probability"] == 0
        assert summary["avg_length"] == 0
        assert summary["tactics_used"] == []

    def test_summary_single_path(self, reporter):
        """Test summary for single path."""
        path = MagicMock(spec=AttackPath)
        path.probability = 0.8
        path.length = 3
        path.tactics_used = ["initial-access", "lateral-movement"]

        summary = reporter._generate_summary([path])

        assert summary["total_paths"] == 1
        assert summary["avg_probability"] == 0.8
        assert summary["avg_length"] == 3

    def test_summary_multiple_paths(self, reporter):
        """Test summary for multiple paths."""
        path1 = MagicMock(spec=AttackPath)
        path1.probability = 0.8
        path1.length = 3
        path1.tactics_used = ["initial-access"]

        path2 = MagicMock(spec=AttackPath)
        path2.probability = 0.6
        path2.length = 5
        path2.tactics_used = ["lateral-movement"]

        summary = reporter._generate_summary([path1, path2])

        assert summary["total_paths"] == 2
        assert summary["avg_probability"] == 0.7  # (0.8 + 0.6) / 2
        assert summary["avg_length"] == 4  # (3 + 5) / 2
        assert summary["max_probability"] == 0.8
        assert summary["min_probability"] == 0.6

    def test_summary_critical_paths_count(self, reporter):
        """Test summary counts critical paths correctly."""
        path1 = MagicMock(spec=AttackPath)
        path1.probability = 0.75  # Critical
        path1.length = 3
        path1.tactics_used = []

        path2 = MagicMock(spec=AttackPath)
        path2.probability = 0.5  # High risk but not critical
        path2.length = 3
        path2.tactics_used = []

        summary = reporter._generate_summary([path1, path2])

        assert summary["critical_paths"] == 1
        assert summary["high_risk_paths"] == 1

    def test_summary_collects_unique_tactics(self, reporter):
        """Test summary collects unique tactics."""
        path1 = MagicMock(spec=AttackPath)
        path1.probability = 0.5
        path1.length = 2
        path1.tactics_used = ["initial-access", "execution"]

        path2 = MagicMock(spec=AttackPath)
        path2.probability = 0.5
        path2.length = 2
        path2.tactics_used = ["execution", "lateral-movement"]

        summary = reporter._generate_summary([path1, path2])

        assert len(summary["tactics_used"]) == 3
        assert "initial-access" in summary["tactics_used"]
        assert "execution" in summary["tactics_used"]
        assert "lateral-movement" in summary["tactics_used"]


class TestJsonReporterSerializePath:
    """Test path serialization."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return JsonReporter()

    @pytest.fixture
    def sample_technique(self):
        """Create sample technique."""
        return AttackTechnique(
            technique_id="T1021.001",
            name="Remote Desktop Protocol",
            tactic="lateral-movement",
            description="RDP lateral movement",
        )

    @pytest.fixture
    def sample_step(self, sample_technique):
        """Create sample attack step."""
        return AttackStep(
            order=0,
            action="RDP to target",
            description="Use RDP to move laterally",
            source_asset_id="host:192.168.1.1",
            target_asset_id="host:192.168.1.2",
            technique=sample_technique,
            probability=0.8,
            detection_risk=0.3,
        )

    @pytest.fixture
    def sample_path(self, sample_step):
        """Create sample attack path."""
        path = AttackPath(
            name="Test Attack Path",
            description="A test path",
            entry_point_id="host:192.168.1.1",
            target_id="host:192.168.1.2",
        )
        path.add_step(sample_step)
        path.probability = 0.75
        path.impact = "high"
        return path

    def test_serialize_includes_basic_fields(self, reporter, sample_path):
        """Test serialization includes basic fields."""
        result = reporter._serialize_path(sample_path)

        assert "id" in result
        assert "name" in result
        assert "description" in result
        assert "probability" in result
        assert "impact" in result

    def test_serialize_includes_entry_and_target(self, reporter, sample_path):
        """Test serialization includes entry point and target."""
        result = reporter._serialize_path(sample_path)

        assert result["entry_point"] == "host:192.168.1.1"
        assert result["target"] == "host:192.168.1.2"

    def test_serialize_includes_steps(self, reporter, sample_path):
        """Test serialization includes steps."""
        result = reporter._serialize_path(sample_path)

        assert "steps" in result
        assert len(result["steps"]) == 1

    def test_serialize_step_includes_technique(self, reporter, sample_path):
        """Test serialized step includes technique."""
        result = reporter._serialize_path(sample_path)
        step = result["steps"][0]

        assert "technique" in step
        assert step["technique"]["id"] == "T1021.001"
        assert step["technique"]["name"] == "Remote Desktop Protocol"
        assert step["technique"]["tactic"] == "lateral-movement"

    def test_serialize_handles_step_without_technique(self, reporter):
        """Test serialization handles step without technique."""
        step = AttackStep(
            order=0,
            action="Manual action",
            description="No technique",
            source_asset_id="host:192.168.1.1",
            target_asset_id="host:192.168.1.2",
            technique=None,
            probability=0.5,
        )
        path = AttackPath(
            name="Test Path",
            description="Test",
            entry_point_id="host:192.168.1.1",
            target_id="host:192.168.1.2",
        )
        path.add_step(step)

        result = reporter._serialize_path(path)

        assert result["steps"][0]["technique"] is None

    def test_serialize_includes_timestamps(self, reporter, sample_path):
        """Test serialization includes timestamp."""
        result = reporter._serialize_path(sample_path)

        assert "created_at" in result
        # Should be ISO format string
        datetime.fromisoformat(result["created_at"])

    def test_serialize_includes_techniques_list(self, reporter, sample_path):
        """Test serialization includes techniques list."""
        result = reporter._serialize_path(sample_path)

        assert "techniques" in result
        assert len(result["techniques"]) >= 0

    def test_serialize_includes_risk_score(self, reporter, sample_path):
        """Test serialization includes risk score."""
        result = reporter._serialize_path(sample_path)

        assert "risk_score" in result
