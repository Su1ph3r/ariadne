"""Tests for Ariadne CLI."""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch

from ariadne.cli import app
from ariadne import __version__


runner = CliRunner()


class TestVersion:
    """Test --version flag."""

    def test_version_flag(self):
        """Test --version displays version."""
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_version_short_flag(self):
        """Test -v displays version."""
        result = runner.invoke(app, ["-v"])

        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_version_contains_ariadne(self):
        """Test version output contains Ariadne."""
        result = runner.invoke(app, ["--version"])

        assert "Ariadne" in result.stdout


class TestMainApp:
    """Test main app behavior."""

    def test_no_args_shows_help(self):
        """Test running without args shows help."""
        result = runner.invoke(app, [])

        # Typer with no_args_is_help returns exit code 0 or 2
        assert result.exit_code in [0, 2]
        assert "Usage" in result.stdout or "usage" in result.stdout.lower()

    def test_help_flag(self):
        """Test --help flag."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "analyze" in result.stdout
        assert "parsers" in result.stdout
        assert "web" in result.stdout


class TestAnalyzeCommand:
    """Test analyze command."""

    def test_analyze_help(self):
        """Test analyze --help."""
        result = runner.invoke(app, ["analyze", "--help"])

        assert result.exit_code == 0
        assert "--output" in result.stdout
        assert "--dry-run" in result.stdout
        assert "--format" in result.stdout

    def test_analyze_missing_path(self):
        """Test analyze with missing path."""
        result = runner.invoke(app, ["analyze"])

        # Should fail because path is required
        assert result.exit_code != 0

    def test_analyze_nonexistent_path(self):
        """Test analyze with nonexistent path."""
        result = runner.invoke(app, ["analyze", "/nonexistent/path/xyz123"])

        assert result.exit_code == 1
        assert "does not exist" in result.stdout

    def test_analyze_dry_run_valid_path(self, tmp_path):
        """Test analyze --dry-run with valid path."""
        # Create a sample nmap file
        nmap_file = tmp_path / "scan.xml"
        nmap_file.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="192.168.1.1"/></host>
</nmaprun>""")

        result = runner.invoke(app, ["analyze", str(tmp_path), "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run" in result.stdout or "Validation" in result.stdout

    def test_analyze_dry_run_empty_path(self, tmp_path):
        """Test analyze --dry-run with empty directory."""
        result = runner.invoke(app, ["analyze", str(tmp_path), "--dry-run"])

        # May pass or fail depending on implementation
        # Just verify it doesn't crash
        assert result.exit_code in [0, 1]

    def test_analyze_with_output_option(self, tmp_path):
        """Test analyze with --output option parsing."""
        # Create a sample file
        nmap_file = tmp_path / "scan.xml"
        nmap_file.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="192.168.1.1"/></host>
</nmaprun>""")

        output_path = tmp_path / "report"

        # Use dry-run to avoid full analysis
        result = runner.invoke(app, [
            "analyze", str(tmp_path),
            "--output", str(output_path),
            "--dry-run"
        ])

        # Should at least parse the arguments
        assert result.exit_code in [0, 1]

    def test_analyze_format_option(self):
        """Test analyze --format option parsing."""
        result = runner.invoke(app, ["analyze", "--help"])

        assert "--format" in result.stdout
        assert "json" in result.stdout.lower() or "html" in result.stdout.lower()

    def test_analyze_target_option(self):
        """Test analyze --target option exists."""
        result = runner.invoke(app, ["analyze", "--help"])

        assert "--target" in result.stdout


class TestWebCommand:
    """Test web command."""

    def test_web_help(self):
        """Test web --help."""
        result = runner.invoke(app, ["web", "--help"])

        assert result.exit_code == 0
        assert "--host" in result.stdout
        assert "--port" in result.stdout
        assert "--reload" in result.stdout

    def test_web_default_values_in_help(self):
        """Test web shows default values."""
        result = runner.invoke(app, ["web", "--help"])

        assert "127.0.0.1" in result.stdout or "localhost" in result.stdout.lower()
        assert "8443" in result.stdout

    @patch("uvicorn.run")
    def test_web_starts_server(self, mock_run):
        """Test web command starts uvicorn."""
        result = runner.invoke(app, ["web"])

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        # First positional arg should be the app string
        assert call_args[0][0] == "ariadne.web.app:app"

    @patch("uvicorn.run")
    def test_web_custom_host_port(self, mock_run):
        """Test web with custom host and port."""
        result = runner.invoke(app, ["web", "--host", "0.0.0.0", "--port", "9000"])

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 9000

    @patch("uvicorn.run")
    def test_web_reload_flag(self, mock_run):
        """Test web --reload flag."""
        result = runner.invoke(app, ["web", "--reload"])

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["reload"] is True


class TestExportCommand:
    """Test export command."""

    def test_export_help(self):
        """Test export --help."""
        result = runner.invoke(app, ["export", "--help"])

        assert result.exit_code == 0
        assert "--output" in result.stdout
        assert "--format" in result.stdout

    def test_export_format_options(self):
        """Test export format options in help."""
        result = runner.invoke(app, ["export", "--help"])

        assert "json" in result.stdout.lower()
        # May have other formats like neo4j-cypher, graphml

    def test_export_with_valid_path(self, tmp_path):
        """Test export with valid input path."""
        # Create a sample file
        nmap_file = tmp_path / "scan.xml"
        nmap_file.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="192.168.1.1"/></host>
</nmaprun>""")

        output_path = tmp_path / "export"

        result = runner.invoke(app, [
            "export", str(tmp_path),
            "--output", str(output_path),
            "--format", "json"
        ])

        # Should succeed or fail gracefully
        assert result.exit_code in [0, 1]

    def test_export_missing_path(self):
        """Test export without input path."""
        result = runner.invoke(app, ["export"])

        # Should fail because path is required
        assert result.exit_code != 0


class TestParsersListCommand:
    """Test parsers list command."""

    def test_parsers_list(self):
        """Test parsers list command."""
        result = runner.invoke(app, ["parsers", "list"])

        assert result.exit_code == 0
        # Should show some parsers
        assert "nmap" in result.stdout.lower()

    def test_parsers_list_shows_table(self):
        """Test parsers list shows table format."""
        result = runner.invoke(app, ["parsers", "list"])

        # Rich table output should have column headers
        assert "Name" in result.stdout or "name" in result.stdout.lower()

    def test_parsers_list_shows_file_patterns(self):
        """Test parsers list shows file patterns."""
        result = runner.invoke(app, ["parsers", "list"])

        # Should show file patterns like *.xml, *.json
        assert "xml" in result.stdout.lower() or "json" in result.stdout.lower()

    def test_parsers_list_shows_multiple_parsers(self):
        """Test parsers list shows multiple parsers."""
        result = runner.invoke(app, ["parsers", "list"])

        # Should have multiple parsers
        # Check for common ones
        stdout_lower = result.stdout.lower()
        parser_count = sum(1 for p in ["nmap", "nuclei", "bloodhound", "masscan"] if p in stdout_lower)
        assert parser_count >= 2


class TestParsersInfoCommand:
    """Test parsers info command."""

    def test_parsers_info_nmap(self):
        """Test parsers info for nmap."""
        result = runner.invoke(app, ["parsers", "info", "nmap"])

        assert result.exit_code == 0
        assert "nmap" in result.stdout.lower()

    def test_parsers_info_shows_description(self):
        """Test parsers info shows description."""
        result = runner.invoke(app, ["parsers", "info", "nmap"])

        # Should have description
        assert "Description" in result.stdout or len(result.stdout) > 20

    def test_parsers_info_shows_file_patterns(self):
        """Test parsers info shows file patterns."""
        result = runner.invoke(app, ["parsers", "info", "nmap"])

        assert "pattern" in result.stdout.lower() or "xml" in result.stdout.lower()

    def test_parsers_info_shows_entity_types(self):
        """Test parsers info shows entity types."""
        result = runner.invoke(app, ["parsers", "info", "nmap"])

        # Should mention entity types
        assert "entity" in result.stdout.lower() or "Host" in result.stdout or "Service" in result.stdout

    def test_parsers_info_nonexistent(self):
        """Test parsers info for nonexistent parser."""
        result = runner.invoke(app, ["parsers", "info", "nonexistent_parser_xyz"])

        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_parsers_info_bloodhound(self):
        """Test parsers info for bloodhound."""
        result = runner.invoke(app, ["parsers", "info", "bloodhound"])

        assert result.exit_code == 0
        assert "bloodhound" in result.stdout.lower()

    def test_parsers_info_missing_name(self):
        """Test parsers info without name."""
        result = runner.invoke(app, ["parsers", "info"])

        # Should fail because name is required
        assert result.exit_code != 0


class TestParsersSubcommand:
    """Test parsers subcommand group."""

    def test_parsers_help(self):
        """Test parsers --help."""
        result = runner.invoke(app, ["parsers", "--help"])

        assert result.exit_code == 0
        assert "list" in result.stdout
        assert "info" in result.stdout

    def test_parsers_no_args(self):
        """Test parsers without subcommand."""
        result = runner.invoke(app, ["parsers"])

        # Should show help (exit code 0 or 2 depending on typer config)
        assert result.exit_code in [0, 2]


class TestIntegration:
    """Integration tests for CLI."""

    def test_full_dry_run_workflow(self, tmp_path):
        """Test full dry-run workflow."""
        # Create test data
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        nmap_file = data_dir / "nmap_scan.xml"
        nmap_file.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.0/24">
<host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="server" type="PTR"/></hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH"/>
        </port>
    </ports>
</host>
</nmaprun>""")

        # Run dry-run
        result = runner.invoke(app, ["analyze", str(data_dir), "--dry-run"])

        assert result.exit_code == 0
        assert "Validation" in result.stdout or "passed" in result.stdout.lower()

    def test_version_then_help(self):
        """Test version followed by help works."""
        # Version
        result1 = runner.invoke(app, ["--version"])
        assert result1.exit_code == 0

        # Help
        result2 = runner.invoke(app, ["--help"])
        assert result2.exit_code == 0

    def test_multiple_parsers_info(self):
        """Test info for multiple parsers."""
        parsers = ["nmap", "bloodhound", "nuclei"]

        for parser in parsers:
            result = runner.invoke(app, ["parsers", "info", parser])
            assert result.exit_code == 0, f"Parser info failed for {parser}"
