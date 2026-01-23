"""Tests for Snaffler parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.snaffler import SnafflerParser
from ariadne.models.asset import Host
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestSnafflerParser(BaseParserTest):
    """Test SnafflerParser functionality."""

    parser_class = SnafflerParser
    expected_name = "snaffler"
    expected_patterns = ["*snaffler*.txt", "*snaffler*.log", "*snaffler*.json", "*snaffler*.csv"]
    expected_entity_types = ["Host", "Credential", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_snaffler_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        content = "[Red] \\\\SERVER01\\share\\passwords.txt"
        txt_file = tmp_path / "snaffler_output.txt"
        txt_file.write_text(content)

        assert SnafflerParser.can_parse(txt_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = "[Yellow] [KeepExtExact] \\\\SERVER\\share\\config.xml"
        txt_file = tmp_path / "output.txt"
        txt_file.write_text(content)

        assert SnafflerParser.can_parse(txt_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text file is rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("random text content")

        assert not SnafflerParser.can_parse(txt_file)

    # =========================================================================
    # Text Format Parsing Tests
    # =========================================================================

    def test_parse_text_finding(self, tmp_path: Path):
        """Test parsing text format finding."""
        content = "[Yellow] [KeepExtExact] \\\\SERVER01\\share\\config.xml"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "SERVER01"
        assert "file-share" in hosts[0].tags

    def test_parse_red_finding_as_credential(self, tmp_path: Path):
        """Test that red findings are parsed as credentials."""
        content = "[Red] [KeepExtExact] \\\\SERVER01\\share\\passwords.txt"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].severity == "critical"

    def test_parse_black_finding_as_credential(self, tmp_path: Path):
        """Test that black findings are parsed as credentials."""
        content = "[Black] [KeepExtExact] \\\\SERVER01\\share\\web.config"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].severity == "critical"

    def test_parse_yellow_finding_as_misconfiguration(self, tmp_path: Path):
        """Test that yellow findings are parsed as misconfigurations."""
        content = "[Yellow] [KeepExtExact] \\\\SERVER01\\share\\readme.txt"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert misconfigs[0].severity == "medium"

    def test_parse_unc_without_brackets(self, tmp_path: Path):
        """Test parsing UNC path without severity brackets."""
        content = "\\\\SERVER01\\share\\file.txt"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "SERVER01"

    # =========================================================================
    # Credential File Detection Tests
    # =========================================================================

    def test_parse_password_file(self, tmp_path: Path):
        """Test detection of password file."""
        content = "[Yellow] \\\\SERVER01\\share\\passwords.txt"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert "Sensitive file" in creds[0].title

    def test_parse_private_key_file(self, tmp_path: Path):
        """Test detection of private key file."""
        content = "[Yellow] \\\\SERVER01\\share\\id_rsa"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    def test_parse_kdbx_file(self, tmp_path: Path):
        """Test detection of KeePass database."""
        content = "[Yellow] \\\\SERVER01\\share\\passwords.kdbx"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    def test_parse_web_config_file(self, tmp_path: Path):
        """Test detection of web.config file."""
        content = "[Yellow] \\\\SERVER01\\share\\web.config"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    def test_parse_unattend_file(self, tmp_path: Path):
        """Test detection of unattend.xml file."""
        content = "[Yellow] \\\\SERVER01\\share\\unattend.xml"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    # =========================================================================
    # JSON Format Parsing Tests
    # =========================================================================

    def test_parse_json_finding(self, tmp_path: Path):
        """Test parsing JSON format finding."""
        data = {
            "path": "\\\\SERVER01\\share\\config.xml",
            "severity": "Yellow",
            "rule": "KeepExtExact"
        }
        json_file = tmp_path / "snaffler.json"
        json_file.write_text(json.dumps(data))

        parser = SnafflerParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "SERVER01"

    def test_parse_json_array(self, tmp_path: Path):
        """Test parsing JSON array of findings."""
        data = [
            {"path": "\\\\SERVER01\\share\\file1.txt", "severity": "Yellow"},
            {"path": "\\\\SERVER02\\share\\file2.txt", "severity": "Red"}
        ]
        json_file = tmp_path / "snaffler.json"
        json_file.write_text(json.dumps(data))

        parser = SnafflerParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_json_with_context(self, tmp_path: Path):
        """Test parsing JSON with match context."""
        data = {
            "path": "\\\\SERVER01\\share\\config.xml",
            "severity": "Red",
            "rule": "KeepRegex",
            "context": "password=secretvalue123"
        }
        json_file = tmp_path / "snaffler.json"
        json_file.write_text(json.dumps(data))

        parser = SnafflerParser()
        entities = list(parser.parse(json_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    # =========================================================================
    # CSV Format Parsing Tests
    # =========================================================================

    def test_parse_csv_finding(self, tmp_path: Path):
        """Test parsing CSV format finding."""
        content = '"Path","Triage","Rule"\n"\\\\SERVER01\\share\\config.xml","Yellow","KeepExtExact"\n'
        csv_file = tmp_path / "snaffler.csv"
        csv_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1

    def test_parse_csv_with_context(self, tmp_path: Path):
        """Test parsing CSV with match context."""
        content = '"FilePath","Severity","MatchedRule","MatchContext"\n"\\\\SERVER01\\share\\web.config","Red","KeepRegex","connectionString=..."\n'
        csv_file = tmp_path / "snaffler.csv"
        csv_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(csv_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1

    # =========================================================================
    # Severity Mapping Tests
    # =========================================================================

    def test_severity_mapping(self, tmp_path: Path):
        """Test severity level mapping from colors."""
        content = """[Black] \\\\S1\\share\\f1.txt
[Red] \\\\S2\\share\\f2.txt
[Orange] \\\\S3\\share\\f3.txt
[Yellow] \\\\S4\\share\\f4.txt
[Green] \\\\S5\\share\\f5.txt
"""
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        # Check that different severities are mapped
        all_findings = self.get_credentials(entities) + self.get_misconfigurations(entities)
        severities = {f.severity for f in all_findings}
        assert "critical" in severities  # Black/Red
        assert "medium" in severities or "low" in severities  # Yellow/Green

    # =========================================================================
    # Host Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        content = """[Yellow] \\\\SERVER01\\share1\\file1.txt
[Red] \\\\SERVER01\\share2\\file2.txt
[Yellow] \\\\SERVER01\\share1\\file3.txt
"""
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        server01_hosts = [h for h in hosts if h.hostname == "SERVER01"]
        assert len(server01_hosts) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text("")

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_no_unc_path(self, tmp_path: Path):
        """Test handling of entries without UNC path."""
        content = "Some random log line without UNC path"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 0

    def test_handles_malformed_json(self, tmp_path: Path):
        """Test handling of malformed JSON."""
        json_file = tmp_path / "snaffler.json"
        json_file.write_text("{not valid json")

        parser = SnafflerParser()
        try:
            entities = list(parser.parse(json_file))
            # Should either handle gracefully or raise
        except Exception:
            pass  # Expected for malformed JSON

    def test_extracts_share_name(self, tmp_path: Path):
        """Test extraction of share name from UNC path."""
        data = {
            "path": "\\\\SERVER01\\NETLOGON\\scripts\\login.bat",
            "severity": "Yellow"
        }
        json_file = tmp_path / "snaffler.json"
        json_file.write_text(json.dumps(data))

        parser = SnafflerParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert misconfigs[0].raw_data.get("share") == "NETLOGON"

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_snaffler(self, tmp_path: Path):
        """Test that source is set to snaffler."""
        content = "[Yellow] \\\\SERVER01\\share\\file.txt"
        txt_file = tmp_path / "snaffler.txt"
        txt_file.write_text(content)

        parser = SnafflerParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "snaffler"
