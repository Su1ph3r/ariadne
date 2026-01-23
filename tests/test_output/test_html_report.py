"""Tests for HTML report generator."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ariadne.output.html_report import HtmlReporter
from ariadne.models.attack_path import AttackPath, AttackStep, AttackTechnique


class TestHtmlReporterInitialization:
    """Test HtmlReporter initialization."""

    def test_initialization_creates_env(self):
        """Test reporter initializes Jinja2 environment."""
        reporter = HtmlReporter()
        # env may be None if templates package not found, which is ok
        assert hasattr(reporter, "env")

    def test_initialization_handles_missing_templates(self):
        """Test reporter handles missing templates gracefully."""
        with patch("ariadne.output.html_report.PackageLoader", side_effect=Exception("No templates")):
            reporter = HtmlReporter()
            assert reporter.env is None


class TestHtmlReporterGenerate:
    """Test HtmlReporter generate method."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return HtmlReporter()

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
        assert result.suffix == ".html"

    def test_generate_returns_path_with_html_suffix(self, reporter, sample_path, tmp_path):
        """Test generate returns path with .html suffix."""
        output_path = tmp_path / "report.txt"

        result = reporter.generate([sample_path], output_path)

        assert result.suffix == ".html"

    def test_generate_creates_valid_html(self, reporter, sample_path, tmp_path):
        """Test generated file contains valid HTML."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.html") as f:
            content = f.read()

        assert "<!DOCTYPE html>" in content or "<!doctype html>" in content.lower()
        assert "<html" in content.lower()
        assert "</html>" in content.lower()

    def test_generate_includes_ariadne_branding(self, reporter, sample_path, tmp_path):
        """Test generated HTML includes Ariadne branding."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.html") as f:
            content = f.read()

        assert "Ariadne" in content

    def test_generate_includes_path_name(self, reporter, sample_path, tmp_path):
        """Test generated HTML includes path name."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.html") as f:
            content = f.read()

        assert "Test Attack Path" in content

    def test_generate_includes_path_description(self, reporter, sample_path, tmp_path):
        """Test generated HTML includes path description."""
        output_path = tmp_path / "report"
        reporter.generate([sample_path], output_path)

        with open(tmp_path / "report.html") as f:
            content = f.read()

        assert "A test path for unit testing" in content

    def test_generate_empty_paths(self, reporter, tmp_path):
        """Test generate with empty paths list."""
        output_path = tmp_path / "report"
        reporter.generate([], output_path)

        with open(tmp_path / "report.html") as f:
            content = f.read()

        assert "<!DOCTYPE html>" in content or "<!doctype html>" in content.lower()

    def test_generate_uses_fallback_when_no_env(self, sample_path, tmp_path):
        """Test generate uses fallback HTML when env is None."""
        reporter = HtmlReporter()
        reporter.env = None
        output_path = tmp_path / "report"

        result = reporter.generate([sample_path], output_path)

        assert result.exists()
        with open(result) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content


class TestHtmlReporterSummary:
    """Test summary generation."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return HtmlReporter()

    def test_summary_empty_paths(self, reporter):
        """Test summary for empty paths."""
        summary = reporter._generate_summary([])

        assert summary["total_paths"] == 0

    def test_summary_single_path(self, reporter):
        """Test summary for single path."""
        path = MagicMock(spec=AttackPath)
        path.probability = 0.8

        summary = reporter._generate_summary([path])

        assert summary["total_paths"] == 1
        assert summary["avg_probability"] == 0.8

    def test_summary_critical_count(self, reporter):
        """Test summary counts critical paths."""
        path1 = MagicMock(spec=AttackPath)
        path1.probability = 0.75  # Critical

        path2 = MagicMock(spec=AttackPath)
        path2.probability = 0.5  # High

        path3 = MagicMock(spec=AttackPath)
        path3.probability = 0.3  # Medium

        summary = reporter._generate_summary([path1, path2, path3])

        assert summary["critical_count"] == 1
        assert summary["high_count"] == 1

    def test_summary_multiple_paths_avg(self, reporter):
        """Test summary calculates correct average."""
        path1 = MagicMock(spec=AttackPath)
        path1.probability = 0.9

        path2 = MagicMock(spec=AttackPath)
        path2.probability = 0.7

        summary = reporter._generate_summary([path1, path2])

        assert summary["avg_probability"] == 0.8


class TestHtmlReporterFallbackHtml:
    """Test fallback HTML generation."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return HtmlReporter()

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

    def test_fallback_html_is_valid(self, reporter, sample_path):
        """Test fallback HTML is valid."""
        html = reporter._generate_fallback_html([sample_path], None)

        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_fallback_html_includes_styles(self, reporter, sample_path):
        """Test fallback HTML includes styles."""
        html = reporter._generate_fallback_html([sample_path], None)

        assert "<style>" in html
        assert "</style>" in html

    def test_fallback_html_includes_path_info(self, reporter, sample_path):
        """Test fallback HTML includes path info."""
        html = reporter._generate_fallback_html([sample_path], None)

        assert "Test Attack Path" in html

    def test_fallback_html_includes_steps(self, reporter, sample_path):
        """Test fallback HTML includes steps."""
        html = reporter._generate_fallback_html([sample_path], None)

        assert "RDP to target" in html

    def test_fallback_html_includes_technique_id(self, reporter, sample_path):
        """Test fallback HTML includes technique ID."""
        html = reporter._generate_fallback_html([sample_path], None)

        assert "T1021.001" in html

    def test_fallback_html_includes_probability(self, reporter, sample_path):
        """Test fallback HTML includes probability."""
        html = reporter._generate_fallback_html([sample_path], None)

        # 75% probability
        assert "75%" in html

    def test_fallback_html_critical_class(self, reporter, sample_path):
        """Test fallback HTML applies critical class for high probability."""
        sample_path.probability = 0.8
        html = reporter._generate_fallback_html([sample_path], None)

        assert 'class="attack-path critical"' in html

    def test_fallback_html_high_class(self, reporter, sample_path):
        """Test fallback HTML applies high class for medium probability."""
        sample_path.probability = 0.6
        html = reporter._generate_fallback_html([sample_path], None)

        assert 'class="attack-path high"' in html

    def test_fallback_html_medium_class(self, reporter, sample_path):
        """Test fallback HTML applies medium class for low probability."""
        sample_path.probability = 0.3
        html = reporter._generate_fallback_html([sample_path], None)

        assert 'class="attack-path medium"' in html

    def test_fallback_html_step_without_technique(self, reporter):
        """Test fallback HTML handles step without technique."""
        step = AttackStep(
            order=0,
            action="Manual action",
            description="No technique",
            source_asset_id="host:192.168.1.1",
            target_asset_id="host:192.168.1.2",
            technique=None,
            probability=0.5,
            detection_risk=0.2,
        )
        path = AttackPath(
            name="Test Path",
            description="Test",
            entry_point_id="host:192.168.1.1",
            target_id="host:192.168.1.2",
        )
        path.add_step(step)
        path.probability = 0.5

        html = reporter._generate_fallback_html([path], None)

        assert "Manual action" in html
        # Should not crash

    def test_fallback_html_includes_llm_analysis_when_present(self, reporter, sample_path):
        """Test fallback HTML includes LLM analysis when present."""
        sample_path.llm_analysis = "This is a high-risk attack path."

        html = reporter._generate_fallback_html([sample_path], None)

        assert "AI Analysis" in html
        assert "This is a high-risk attack path." in html

    def test_fallback_html_no_llm_section_when_absent(self, reporter, sample_path):
        """Test fallback HTML has no LLM section when analysis absent."""
        sample_path.llm_analysis = None

        html = reporter._generate_fallback_html([sample_path], None)

        assert "AI Analysis" not in html

    def test_fallback_html_empty_paths_message(self, reporter):
        """Test fallback HTML shows message for empty paths."""
        html = reporter._generate_fallback_html([], None)

        assert "No attack paths found" in html

    def test_fallback_html_includes_summary_stats(self, reporter, sample_path):
        """Test fallback HTML includes summary statistics."""
        html = reporter._generate_fallback_html([sample_path], None)

        # Should have stat cards
        assert "stat-card" in html
        assert "Attack Paths" in html

    def test_fallback_html_includes_footer(self, reporter, sample_path):
        """Test fallback HTML includes footer."""
        html = reporter._generate_fallback_html([sample_path], None)

        assert "<footer>" in html
        assert "Ariadne Attack Path Synthesizer" in html
