"""Tests for Amass parser."""

import json
import pytest
from pathlib import Path
from textwrap import dedent

from ariadne.parsers.amass import AmassParser
from ariadne.models.asset import Host
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestAmassParser(BaseParserTest):
    """Test AmassParser functionality."""

    parser_class = AmassParser
    expected_name = "amass"
    expected_patterns = ["*amass*.json", "*amass*.txt", "amass_*.txt"]
    expected_entity_types = ["Host", "Relationship"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_amass_json(self, tmp_path: Path):
        """Test detection of Amass JSON output."""
        data = {
            "name": "www.example.com",
            "addresses": [{"ip": "93.184.216.34"}],
            "sources": ["DNS"]
        }
        json_file = tmp_path / "amass_output.json"
        json_file.write_text(json.dumps(data))

        assert AmassParser.can_parse(json_file)

    def test_can_parse_amass_txt(self, tmp_path: Path):
        """Test detection of Amass text output."""
        content = dedent("""\
            # Amass enumeration
            www.example.com
            api.example.com
            mail.example.com
            """)
        txt_file = tmp_path / "amass_results.txt"
        txt_file.write_text(content)

        assert AmassParser.can_parse(txt_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is not parsed as Amass."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not AmassParser.can_parse(json_file)

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_single_entry(self, tmp_path: Path):
        """Test parsing single JSON entry."""
        data = {
            "name": "www.example.com",
            "addresses": [{"ip": "93.184.216.34"}],
            "sources": ["DNS"]
        }
        json_file = tmp_path / "amass.json"
        json_file.write_text(json.dumps(data))

        parser = AmassParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "www.example.com"
        assert hosts[0].ip == "93.184.216.34"
        assert "subdomain" in hosts[0].tags
        assert "recon" in hosts[0].tags

    def test_parse_json_multiple_entries(self, tmp_path: Path):
        """Test parsing multiple JSON entries (JSONL format)."""
        entries = [
            {"name": "www.example.com", "addresses": [{"ip": "93.184.216.34"}]},
            {"name": "api.example.com", "addresses": [{"ip": "93.184.216.35"}]},
            {"name": "mail.example.com", "addresses": [{"ip": "93.184.216.36"}]},
        ]
        content = "\n".join(json.dumps(e) for e in entries)
        json_file = tmp_path / "amass.json"
        json_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

        hostnames = {h.hostname for h in hosts}
        assert "www.example.com" in hostnames
        assert "api.example.com" in hostnames
        assert "mail.example.com" in hostnames

    def test_parse_json_with_multiple_ips(self, tmp_path: Path):
        """Test parsing entry with multiple IP addresses."""
        data = {
            "name": "www.example.com",
            "addresses": [
                {"ip": "93.184.216.34"},
                {"ip": "93.184.216.35"}
            ]
        }
        json_file = tmp_path / "amass.json"
        json_file.write_text(json.dumps(data))

        parser = AmassParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        # Primary host plus additional IP hosts
        assert len(hosts) >= 2

    def test_parse_json_preserves_sources(self, tmp_path: Path):
        """Test that sources are preserved in raw_properties."""
        data = {
            "name": "www.example.com",
            "addresses": [{"ip": "93.184.216.34"}],
            "sources": ["DNS", "Certificates", "Reverse DNS"]
        }
        json_file = tmp_path / "amass.json"
        json_file.write_text(json.dumps(data))

        parser = AmassParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "sources" in hosts[0].raw_properties
        assert "DNS" in hosts[0].raw_properties["sources"]

    def test_parse_json_preserves_tag(self, tmp_path: Path):
        """Test that tag is added to host tags."""
        data = {
            "name": "www.example.com",
            "addresses": [{"ip": "93.184.216.34"}],
            "tag": "cert"
        }
        json_file = tmp_path / "amass.json"
        json_file.write_text(json.dumps(data))

        parser = AmassParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert "cert" in hosts[0].tags

    # =========================================================================
    # Text Parsing Tests
    # =========================================================================

    def test_parse_text_simple_domains(self, tmp_path: Path):
        """Test parsing simple domain list."""
        content = dedent("""\
            www.example.com
            api.example.com
            mail.example.com
            """)
        txt_file = tmp_path / "amass.txt"
        txt_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

        hostnames = {h.hostname for h in hosts if h.hostname}
        assert "www.example.com" in hostnames
        assert "api.example.com" in hostnames
        assert "mail.example.com" in hostnames

    def test_parse_text_dns_records(self, tmp_path: Path):
        """Test parsing DNS record format."""
        content = dedent("""\
            www.example.com A 93.184.216.34
            api.example.com A 93.184.216.35
            mail.example.com CNAME mail.google.com
            """)
        txt_file = tmp_path / "amass.txt"
        txt_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

        # Check that A record IPs are captured
        www_host = next((h for h in hosts if h.hostname == "www.example.com"), None)
        assert www_host is not None
        assert www_host.ip == "93.184.216.34"

    def test_parse_text_domain_with_ip(self, tmp_path: Path):
        """Test parsing domain with IP format."""
        content = dedent("""\
            www.example.com 93.184.216.34
            api.example.com 93.184.216.35
            """)
        txt_file = tmp_path / "amass.txt"
        txt_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    def test_parse_text_skips_comments(self, tmp_path: Path):
        """Test that comments are skipped."""
        content = dedent("""\
            # This is a comment
            www.example.com
            // Another comment
            api.example.com
            """)
        txt_file = tmp_path / "amass.txt"
        txt_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 2

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        content = dedent("""\
            www.example.com
            www.example.com
            WWW.EXAMPLE.COM
            """)
        txt_file = tmp_path / "amass.txt"
        txt_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        # Case-insensitive deduplication
        example_hosts = [h for h in hosts if "example.com" in (h.hostname or "").lower()]
        assert len(example_hosts) == 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "amass_empty.txt"
        txt_file.write_text("")

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json_lines(self, tmp_path: Path):
        """Test handling of invalid JSON lines."""
        content = dedent("""\
            {"name": "www.example.com", "addresses": [{"ip": "93.184.216.34"}]}
            {invalid json}
            {"name": "api.example.com", "addresses": [{"ip": "93.184.216.35"}]}
            """)
        json_file = tmp_path / "amass.json"
        json_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        # Should parse valid entries
        assert len(hosts) >= 2

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_amass(self, tmp_path: Path):
        """Test that source is set to amass."""
        content = "www.example.com"
        txt_file = tmp_path / "amass.txt"
        txt_file.write_text(content)

        parser = AmassParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "amass"
