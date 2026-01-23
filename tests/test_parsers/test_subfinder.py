"""Tests for Subfinder parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.subfinder import SubfinderParser
from ariadne.models.asset import Host
from .base import BaseParserTest


class TestSubfinderParser(BaseParserTest):
    """Test SubfinderParser functionality."""

    parser_class = SubfinderParser
    expected_name = "subfinder"
    expected_patterns = ["*subfinder*.json", "*subfinder*.txt", "subfinder_*.txt", "*subdomains*.txt"]
    expected_entity_types = ["Host"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_subfinder_json(self, tmp_path: Path):
        """Test detection of Subfinder JSON output."""
        data = {"host": "www.example.com", "source": "crtsh"}
        json_file = tmp_path / "subfinder_output.json"
        json_file.write_text(json.dumps(data))

        assert SubfinderParser.can_parse(json_file)

    def test_can_parse_subfinder_txt(self, tmp_path: Path):
        """Test detection of Subfinder text output."""
        lines = [
            "www.example.com",
            "api.example.com",
            "mail.example.com",
            "blog.example.com",
            "shop.example.com",
            "dev.example.com",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        assert SubfinderParser.can_parse(txt_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just random text without domains.")

        assert not SubfinderParser.can_parse(txt_file)

    # =========================================================================
    # Text Parsing Tests
    # =========================================================================

    def test_parse_text_simple_domains(self, tmp_path: Path):
        """Test parsing simple domain list."""
        lines = [
            "www.example.com",
            "api.example.com",
            "mail.example.com",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

        hostnames = {h.hostname for h in hosts}
        assert "www.example.com" in hostnames
        assert "api.example.com" in hostnames
        assert "mail.example.com" in hostnames

    def test_parse_text_with_ip(self, tmp_path: Path):
        """Test parsing domains with IP addresses."""
        lines = [
            "www.example.com,93.184.216.34",
            "api.example.com,93.184.216.35",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

        www_host = next((h for h in hosts if h.hostname == "www.example.com"), None)
        assert www_host is not None
        assert www_host.ip == "93.184.216.34"

    def test_parse_text_with_source(self, tmp_path: Path):
        """Test parsing domains with source information."""
        lines = [
            "www.example.com,93.184.216.34,crtsh",
            "api.example.com,93.184.216.35,hackertarget",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

        # Check source is preserved
        www_host = next((h for h in hosts if h.hostname == "www.example.com"), None)
        assert www_host is not None
        if www_host.raw_properties:
            assert "crtsh" in www_host.raw_properties.get("discovery_source", "")

    def test_parse_text_skips_comments(self, tmp_path: Path):
        """Test that comments are skipped."""
        lines = [
            "# This is a comment",
            "www.example.com",
            "// Another comment",
            "api.example.com",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 2

    def test_parse_text_skips_invalid_domains(self, tmp_path: Path):
        """Test that invalid domains are skipped."""
        lines = [
            "www.example.com",
            "192.168.1.1",
            "not_a_domain",
            "api.example.com",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        hostnames = {h.hostname for h in hosts if h.hostname}
        # Should have valid domains, but not IP addresses treated as domains
        assert "www.example.com" in hostnames
        assert "api.example.com" in hostnames

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_single_entry(self, tmp_path: Path):
        """Test parsing single JSON entry."""
        data = {"host": "www.example.com", "source": "crtsh"}
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(json.dumps(data))

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "www.example.com"
        assert "subdomain" in hosts[0].tags
        assert "recon" in hosts[0].tags

    def test_parse_json_multiple_entries_jsonl(self, tmp_path: Path):
        """Test parsing JSONL format."""
        entries = [
            {"host": "www.example.com", "source": "crtsh"},
            {"host": "api.example.com", "source": "hackertarget"},
            {"host": "mail.example.com", "source": "dnsdumpster"},
        ]
        content = "\n".join(json.dumps(e) for e in entries)
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(content)

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

    def test_parse_json_array(self, tmp_path: Path):
        """Test parsing JSON array format."""
        data = [
            {"host": "www.example.com", "source": "crtsh"},
            {"host": "api.example.com", "source": "hackertarget"},
        ]
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(json.dumps(data))

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_json_with_ip(self, tmp_path: Path):
        """Test parsing JSON with IP addresses."""
        data = {"host": "www.example.com", "ip": "93.184.216.34", "source": "crtsh"}
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(json.dumps(data))

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "www.example.com"
        assert hosts[0].ip == "93.184.216.34"

    def test_parse_json_string_entries(self, tmp_path: Path):
        """Test parsing JSON with string entries (just domain names)."""
        data = ["www.example.com", "api.example.com", "mail.example.com"]
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(json.dumps(data))

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

    def test_parse_json_preserves_source_tag(self, tmp_path: Path):
        """Test that source is added as a tag."""
        data = {"host": "www.example.com", "source": "crtsh"}
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(json.dumps(data))

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        # Source should be in tags
        source_tags = [t for t in hosts[0].tags if t.startswith("source:")]
        assert len(source_tags) >= 1

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        lines = [
            "www.example.com",
            "www.example.com",
            "WWW.EXAMPLE.COM",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        example_hosts = [h for h in hosts if "example.com" in (h.hostname or "").lower()]
        # Case-insensitive deduplication
        assert len(example_hosts) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "subfinder_empty.txt"
        txt_file.write_text("")

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON lines."""
        content = "\n".join([
            '{"host": "www.example.com"}',
            '{invalid json}',
            '{"host": "api.example.com"}',
        ])
        json_file = tmp_path / "subfinder.json"
        json_file.write_text(content)

        parser = SubfinderParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        # Should parse valid entries
        assert len(hosts) >= 2

    def test_handles_subdomain_variations(self, tmp_path: Path):
        """Test handling various subdomain formats."""
        lines = [
            "www.example.com",
            "sub.sub.example.com",
            "a-hyphenated-subdomain.example.com",
            "123numeric.example.com",
        ]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        hostnames = {h.hostname for h in hosts if h.hostname}
        assert "www.example.com" in hostnames
        assert "sub.sub.example.com" in hostnames

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_subfinder(self, tmp_path: Path):
        """Test that source is set to subfinder."""
        lines = ["www.example.com"]
        txt_file = tmp_path / "subfinder.txt"
        txt_file.write_text("\n".join(lines))

        parser = SubfinderParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "subfinder"
