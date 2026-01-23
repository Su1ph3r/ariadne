"""Tests for httpx parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.httpx import HttpxParser
from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration
from .base import BaseParserTest


class TestHttpxParser(BaseParserTest):
    """Test HttpxParser functionality."""

    parser_class = HttpxParser
    expected_name = "httpx"
    expected_patterns = ["*httpx*.json", "*httpx*.txt", "httpx_*.json"]
    expected_entity_types = ["Host", "Service", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_httpx_json(self, tmp_path: Path):
        """Test detection of httpx JSON output."""
        data = {
            "url": "https://www.example.com",
            "host": "www.example.com",
            "port": 443,
            "status_code": 200,
            "title": "Example Domain"
        }
        json_file = tmp_path / "httpx_output.json"
        json_file.write_text(json.dumps(data))

        assert HttpxParser.can_parse(json_file)

    def test_can_parse_httpx_txt(self, tmp_path: Path):
        """Test detection of httpx text output."""
        content = "https://www.example.com\nhttps://api.example.com"
        txt_file = tmp_path / "httpx.txt"
        txt_file.write_text(content)

        assert HttpxParser.can_parse(txt_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not HttpxParser.can_parse(json_file)

    # =========================================================================
    # JSON Parsing Tests
    # =========================================================================

    def test_parse_json_single_entry(self, tmp_path: Path):
        """Test parsing single JSON entry."""
        data = {
            "url": "https://www.example.com",
            "host": "www.example.com",
            "port": 443,
            "scheme": "https",
            "status_code": 200,
            "title": "Example Domain",
            "webserver": "nginx/1.19",
            "a": ["93.184.216.34"]
        }
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        services = self.get_services(entities)

        assert len(hosts) >= 1
        assert hosts[0].hostname == "www.example.com"
        assert hosts[0].ip == "93.184.216.34"
        assert "web" in hosts[0].tags

        assert len(services) >= 1
        assert services[0].port == 443
        assert services[0].service_name == "https"

    def test_parse_json_multiple_entries(self, tmp_path: Path):
        """Test parsing multiple JSON entries (JSONL)."""
        entries = [
            {"url": "https://www.example.com", "host": "www.example.com", "status_code": 200},
            {"url": "https://api.example.com", "host": "api.example.com", "status_code": 200},
            {"url": "http://mail.example.com", "host": "mail.example.com", "status_code": 200},
        ]
        content = "\n".join(json.dumps(e) for e in entries)
        json_file = tmp_path / "httpx.json"
        json_file.write_text(content)

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 3

    def test_parse_json_technology_detection(self, tmp_path: Path):
        """Test parsing technology detection."""
        data = {
            "url": "https://blog.example.com",
            "host": "blog.example.com",
            "status_code": 200,
            "tech": ["WordPress", "PHP", "nginx"]
        }
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        # Should detect WordPress as interesting tech
        wordpress = next((m for m in misconfigs if "WordPress" in m.title), None)
        assert wordpress is not None
        assert wordpress.severity == "info"
        assert "technology" in wordpress.tags

    def test_parse_json_missing_security_headers(self, tmp_path: Path):
        """Test detection of missing security headers."""
        data = {
            "url": "https://www.example.com",
            "host": "www.example.com",
            "status_code": 200,
            "header": {
                "Content-Type": "text/html"
            }
        }
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        headers_misconfig = next((m for m in misconfigs if "Security Headers" in m.title), None)
        assert headers_misconfig is not None
        assert "security" in headers_misconfig.tags

    def test_parse_json_admin_panel(self, tmp_path: Path):
        """Test detection of admin panels."""
        data = {
            "url": "https://admin.example.com/login",
            "host": "admin.example.com",
            "status_code": 200,
            "title": "Admin Login Panel"
        }
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        admin_panel = next((m for m in misconfigs if "Admin" in m.title or "Login" in m.title), None)
        assert admin_panel is not None

    def test_parse_json_protected_resource(self, tmp_path: Path):
        """Test detection of protected resources."""
        data = {
            "url": "https://api.example.com/admin",
            "host": "api.example.com",
            "status_code": 403
        }
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        protected = next((m for m in misconfigs if "Protected" in m.title), None)
        assert protected is not None

    def test_parse_json_cdn_detection(self, tmp_path: Path):
        """Test CDN detection."""
        data = {
            "url": "https://www.example.com",
            "host": "www.example.com",
            "status_code": 200,
            "cdn": "cloudflare"
        }
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        cdn_tags = [t for t in hosts[0].tags if "cdn" in t]
        assert len(cdn_tags) >= 1

    # =========================================================================
    # Text Parsing Tests
    # =========================================================================

    def test_parse_text_urls(self, tmp_path: Path):
        """Test parsing URL list."""
        lines = [
            "https://www.example.com",
            "https://api.example.com:8443/api",
            "http://internal.example.com",
        ]
        txt_file = tmp_path / "httpx.txt"
        txt_file.write_text("\n".join(lines))

        parser = HttpxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        services = self.get_services(entities)

        assert len(hosts) >= 3
        assert len(services) >= 3

        # Check port detection
        api_service = next((s for s in services if s.port == 8443), None)
        assert api_service is not None

    def test_parse_text_skips_comments(self, tmp_path: Path):
        """Test that comments are skipped."""
        lines = [
            "# This is a comment",
            "https://www.example.com",
        ]
        txt_file = tmp_path / "httpx.txt"
        txt_file.write_text("\n".join(lines))

        parser = HttpxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) == 1

    def test_parse_text_ip_addresses(self, tmp_path: Path):
        """Test parsing URLs with IP addresses."""
        lines = [
            "http://192.168.1.100:8080",
            "https://10.0.0.1",
        ]
        txt_file = tmp_path / "httpx.txt"
        txt_file.write_text("\n".join(lines))

        parser = HttpxParser()
        entities = list(parser.parse(txt_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

        # IP should be set, hostname should be empty
        ip_host = next((h for h in hosts if h.ip == "192.168.1.100"), None)
        assert ip_host is not None

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "httpx_empty.txt"
        txt_file.write_text("")

        parser = HttpxParser()
        entities = list(parser.parse(txt_file))

        assert isinstance(entities, list)

    def test_handles_invalid_json(self, tmp_path: Path):
        """Test handling of invalid JSON lines."""
        content = "\n".join([
            '{"url": "https://www.example.com", "host": "www.example.com", "status_code": 200}',
            '{invalid json}',
            '{"url": "https://api.example.com", "host": "api.example.com", "status_code": 200}',
        ])
        json_file = tmp_path / "httpx.json"
        json_file.write_text(content)

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 2

    # =========================================================================
    # Deduplication Tests
    # =========================================================================

    def test_deduplicates_hosts(self, tmp_path: Path):
        """Test that duplicate hosts are not created."""
        entries = [
            {"url": "https://www.example.com/page1", "host": "www.example.com"},
            {"url": "https://www.example.com/page2", "host": "www.example.com"},
        ]
        content = "\n".join(json.dumps(e) for e in entries)
        json_file = tmp_path / "httpx.json"
        json_file.write_text(content)

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        # Same host:port should be deduplicated
        example_hosts = [h for h in hosts if h.hostname == "www.example.com"]
        assert len(example_hosts) == 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_httpx(self, tmp_path: Path):
        """Test that source is set to httpx."""
        data = {"url": "https://www.example.com", "host": "www.example.com"}
        json_file = tmp_path / "httpx.json"
        json_file.write_text(json.dumps(data))

        parser = HttpxParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "httpx"
