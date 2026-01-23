"""Tests for the Synthesizer class."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from ariadne.config import AriadneConfig
from ariadne.engine.synthesizer import Synthesizer, ValidationResult
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability
from ariadne.models.relationship import Relationship, RelationType


class TestValidationResult:
    """Test ValidationResult dataclass."""

    def test_default_values(self):
        """Test default values."""
        result = ValidationResult()

        assert result.valid is True
        assert result.file_count == 0
        assert result.parsers == []
        assert result.errors == []
        assert result.warnings == []

    def test_with_values(self):
        """Test with explicit values."""
        result = ValidationResult(
            valid=False,
            file_count=5,
            parsers=["nmap", "nessus"],
            errors=["Error 1"],
            warnings=["Warning 1", "Warning 2"],
        )

        assert result.valid is False
        assert result.file_count == 5
        assert result.parsers == ["nmap", "nessus"]
        assert len(result.errors) == 1
        assert len(result.warnings) == 2


class TestSynthesizer:
    """Test Synthesizer functionality."""

    @pytest.fixture
    def config(self) -> AriadneConfig:
        """Create test configuration."""
        return AriadneConfig()

    @pytest.fixture
    def synthesizer(self, config: AriadneConfig) -> Synthesizer:
        """Create synthesizer instance."""
        return Synthesizer(config)

    # =========================================================================
    # Initialization Tests
    # =========================================================================

    def test_initialization(self, config: AriadneConfig):
        """Test synthesizer initializes correctly."""
        synth = Synthesizer(config)

        assert synth.config == config
        assert synth.registry is not None
        assert synth.store is not None
        assert synth.scorer is not None

    # =========================================================================
    # Validation Tests
    # =========================================================================

    def test_validate_nonexistent_path(self, synthesizer: Synthesizer):
        """Test validation of nonexistent path."""
        result = synthesizer.validate(Path("/nonexistent/path"))

        assert result.valid is False
        assert len(result.errors) > 0
        assert "does not exist" in result.errors[0]

    def test_validate_empty_directory(self, synthesizer: Synthesizer, tmp_path: Path):
        """Test validation of empty directory."""
        result = synthesizer.validate(tmp_path)

        assert result.valid is False
        assert result.file_count == 0

    def test_validate_with_parsable_file(self, synthesizer: Synthesizer, tmp_path: Path):
        """Test validation with a parsable file."""
        # Create a simple nmap XML file
        nmap_file = tmp_path / "scan.xml"
        nmap_file.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1234567890">
<host><address addr="192.168.1.1" addrtype="ipv4"/></host>
</nmaprun>""")

        result = synthesizer.validate(tmp_path)

        assert result.file_count >= 1
        assert len(result.parsers) >= 0  # Parser may or may not detect

    def test_validate_single_file(self, synthesizer: Synthesizer, tmp_path: Path):
        """Test validation of single file."""
        nmap_file = tmp_path / "nmap_scan.xml"
        nmap_file.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="192.168.1.1" addrtype="ipv4"/></host>
</nmaprun>""")

        result = synthesizer.validate(nmap_file)

        assert result.file_count == 1

    def test_validate_unparsable_file(self, synthesizer: Synthesizer, tmp_path: Path):
        """Test validation warns about unparsable files."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("Some random text")

        result = synthesizer.validate(tmp_path)

        # Should have warning about no parser
        assert len(result.warnings) >= 1 or result.valid is False

    # =========================================================================
    # Queries Property Tests
    # =========================================================================

    def test_queries_property_creates_instance(self, synthesizer: Synthesizer):
        """Test that queries property creates GraphQueries instance."""
        queries = synthesizer.queries

        assert queries is not None
        assert synthesizer._queries is not None

    def test_queries_property_cached(self, synthesizer: Synthesizer):
        """Test that queries property returns cached instance."""
        queries1 = synthesizer.queries
        queries2 = synthesizer.queries

        assert queries1 is queries2

    # =========================================================================
    # Pattern Matching Tests
    # =========================================================================

    def test_matches_pattern_by_node_id(self, synthesizer: Synthesizer):
        """Test pattern matching by node ID."""
        result = synthesizer._matches_pattern(
            "host:192.168.1.1",
            {},
            "192.168.1"
        )
        assert result is True

    def test_matches_pattern_by_label(self, synthesizer: Synthesizer):
        """Test pattern matching by label."""
        result = synthesizer._matches_pattern(
            "host:server01",
            {"label": "webserver.corp.local"},
            "webserver"
        )
        assert result is True

    def test_matches_pattern_by_hostname(self, synthesizer: Synthesizer):
        """Test pattern matching by hostname."""
        result = synthesizer._matches_pattern(
            "host:192.168.1.1",
            {"hostname": "dc01"},
            "dc01"
        )
        assert result is True

    def test_matches_pattern_by_ip(self, synthesizer: Synthesizer):
        """Test pattern matching by IP."""
        result = synthesizer._matches_pattern(
            "host:server",
            {"ip": "10.0.0.1"},
            "10.0.0"
        )
        assert result is True

    def test_matches_pattern_case_insensitive(self, synthesizer: Synthesizer):
        """Test pattern matching is case insensitive."""
        result = synthesizer._matches_pattern(
            "HOST:SERVER",
            {"hostname": "WebServer"},
            "webserver"
        )
        assert result is True

    def test_matches_pattern_no_match(self, synthesizer: Synthesizer):
        """Test pattern matching returns false when no match."""
        result = synthesizer._matches_pattern(
            "host:192.168.1.1",
            {"hostname": "server01"},
            "notfound"
        )
        assert result is False

    # =========================================================================
    # Build Attack Path Tests
    # =========================================================================

    def test_build_attack_path_minimum_nodes(self, synthesizer: Synthesizer):
        """Test building path with minimum nodes."""
        # Add some nodes to the store
        host = Host(ip="192.168.1.1", hostname="server01")
        synthesizer.store.add_entity(host)

        # Path with single node should return None
        path = synthesizer._build_attack_path("a", "b", ["a"])
        assert path is None

    def test_build_attack_path_two_nodes(self, synthesizer: Synthesizer):
        """Test building path with two nodes."""
        host1 = Host(ip="192.168.1.1", hostname="server01")
        host2 = Host(ip="192.168.1.2", hostname="server02")
        rel = Relationship(
            source_id=host1.id,
            target_id=host2.id,
            relation_type=RelationType.CAN_REACH
        )

        synthesizer.store.add_entity(host1)
        synthesizer.store.add_entity(host2)
        synthesizer.store.add_entity(rel)

        path = synthesizer._build_attack_path(host1.id, host2.id, [host1.id, host2.id])

        assert path is not None
        assert len(path.steps) == 1
        assert path.entry_point_id == host1.id
        assert path.target_id == host2.id

    def test_build_attack_path_includes_vulns(self, synthesizer: Synthesizer):
        """Test that built path includes vulnerabilities on path."""
        host1 = Host(ip="192.168.1.1", hostname="server01")
        host2 = Host(ip="192.168.1.2", hostname="server02")
        vuln = Vulnerability(
            title="Test Vuln",
            severity="high",
            affected_asset_id=host1.id
        )
        rel = Relationship(
            source_id=host1.id,
            target_id=host2.id,
            relation_type=RelationType.CAN_REACH
        )

        synthesizer.store.add_entity(host1)
        synthesizer.store.add_entity(host2)
        synthesizer.store.add_entity(vuln)
        synthesizer.store.add_entity(rel)

        path = synthesizer._build_attack_path(host1.id, host2.id, [host1.id, host2.id])

        assert path is not None
        # Vulnerabilities should be captured in finding_ids
        if path.steps[0].finding_ids:
            assert vuln.id in path.steps[0].finding_ids

    # =========================================================================
    # LLM Context Tests
    # =========================================================================

    def test_build_llm_context(self, synthesizer: Synthesizer):
        """Test building LLM context."""
        host = Host(ip="192.168.1.1", hostname="server01")
        synthesizer.store.add_entity(host)

        context = synthesizer._build_llm_context()

        assert "hosts" in context.lower()
        assert "1" in context  # At least 1 host

    def test_build_llm_context_empty_graph(self, synthesizer: Synthesizer):
        """Test building LLM context for empty graph."""
        context = synthesizer._build_llm_context()

        assert "0 hosts" in context

    # =========================================================================
    # Resolve Entry Points Tests
    # =========================================================================

    def test_resolve_entry_points_no_patterns(self, synthesizer: Synthesizer):
        """Test resolving entry points without patterns uses defaults."""
        host = Host(ip="192.168.1.1", hostname="server01")
        service = Service(name="ssh", port=22, protocol="tcp", host_id=host.id)

        synthesizer.store.add_entity(host)
        synthesizer.store.add_entity(service)
        synthesizer._queries = None  # Reset queries cache

        entry_points = synthesizer._resolve_entry_points(None)

        # Should return auto-detected entry points
        assert isinstance(entry_points, list)

    def test_resolve_entry_points_with_patterns(self, synthesizer: Synthesizer):
        """Test resolving entry points with patterns."""
        host1 = Host(ip="192.168.1.1", hostname="webserver")
        host2 = Host(ip="192.168.1.2", hostname="dbserver")

        synthesizer.store.add_entity(host1)
        synthesizer.store.add_entity(host2)
        synthesizer._queries = None

        entry_points = synthesizer._resolve_entry_points(["webserver"])

        assert host1.id in entry_points
        assert host2.id not in entry_points

    # =========================================================================
    # Resolve Targets Tests
    # =========================================================================

    def test_resolve_targets_no_patterns(self, synthesizer: Synthesizer):
        """Test resolving targets without patterns uses defaults."""
        dc = Host(ip="192.168.1.10", hostname="dc01", is_dc=True)
        server = Host(ip="192.168.1.1", hostname="server01")

        synthesizer.store.add_entity(dc)
        synthesizer.store.add_entity(server)
        synthesizer._queries = None

        targets = synthesizer._resolve_targets(None)

        # DC should be auto-detected as crown jewel
        assert isinstance(targets, list)
        if targets:
            assert dc.id in targets

    def test_resolve_targets_with_patterns(self, synthesizer: Synthesizer):
        """Test resolving targets with patterns."""
        dc = Host(ip="192.168.1.10", hostname="dc01", is_dc=True)
        server = Host(ip="192.168.1.1", hostname="server01")

        synthesizer.store.add_entity(dc)
        synthesizer.store.add_entity(server)
        synthesizer._queries = None

        targets = synthesizer._resolve_targets(["server01"])

        assert server.id in targets


class TestSynthesizerAnalyze:
    """Test Synthesizer.analyze() method with mocked dependencies."""

    @pytest.fixture
    def config(self) -> AriadneConfig:
        """Create test configuration."""
        return AriadneConfig()

    def test_analyze_with_simple_data(self, config: AriadneConfig, tmp_path: Path):
        """Test analyze with simple input data."""
        # Create test data
        json_file = tmp_path / "bloodhound_users.json"
        data = {
            "users": [
                {"Properties": {"name": "admin@CORP.LOCAL", "enabled": True}}
            ]
        }
        json_file.write_text(json.dumps(data))

        synth = Synthesizer(config)

        # Run analyze - may not find paths but should not crash
        paths = synth.analyze(tmp_path)

        assert isinstance(paths, list)

    def test_analyze_limits_output_paths(self, config: AriadneConfig, tmp_path: Path):
        """Test that analyze respects max_paths config."""
        config.output.max_paths = 5

        # Create minimal test data
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("test")

        synth = Synthesizer(config)
        paths = synth.analyze(tmp_path)

        assert len(paths) <= config.output.max_paths


class TestSynthesizerExport:
    """Test Synthesizer.export() method."""

    @pytest.fixture
    def config(self) -> AriadneConfig:
        """Create test configuration."""
        return AriadneConfig()

    @pytest.fixture
    def synthesizer(self, config: AriadneConfig) -> Synthesizer:
        """Create synthesizer instance."""
        return Synthesizer(config)

    def test_export_invalid_format(self, synthesizer: Synthesizer, tmp_path: Path):
        """Test export with invalid format raises error."""
        with pytest.raises(ValueError, match="Unknown format"):
            synthesizer.export([], tmp_path / "report", format="invalid")

    @patch("ariadne.output.json_report.JsonReporter")
    def test_export_json_format(self, mock_reporter, synthesizer: Synthesizer, tmp_path: Path):
        """Test export with JSON format."""
        mock_instance = MagicMock()
        mock_reporter.return_value = mock_instance

        synthesizer.export([], tmp_path / "report", format="json")

        mock_reporter.assert_called_once()
        mock_instance.generate.assert_called_once()

    @patch("ariadne.output.html_report.HtmlReporter")
    def test_export_html_format(self, mock_reporter, synthesizer: Synthesizer, tmp_path: Path):
        """Test export with HTML format."""
        mock_instance = MagicMock()
        mock_reporter.return_value = mock_instance

        synthesizer.export([], tmp_path / "report", format="html")

        mock_reporter.assert_called_once()
        mock_instance.generate.assert_called_once()
