"""Tests for Vinculum parser."""

import json

import pytest
from pathlib import Path

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration, Vulnerability
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.vinculum import VinculumParser


SAMPLE_VINCULUM_EXPORT = {
    "format": "vinculum-ariadne-export",
    "format_version": "1.0",
    "metadata": {
        "generated_at": "2025-01-15T12:00:00Z",
        "vinculum_version": "0.1.0",
    },
    "hosts": [
        {"ip": "192.168.1.10", "hostname": "web01.example.com", "os": "Ubuntu 22.04"},
        {"ip": "192.168.1.20", "hostname": "db01.example.com", "os": None},
    ],
    "services": [
        {
            "port": 443,
            "protocol": "tcp",
            "name": "https",
            "product": "nginx",
            "version": "1.18.0",
            "host_ip": "192.168.1.10",
        },
        {
            "port": 3306,
            "protocol": "tcp",
            "name": "mysql",
            "product": "MySQL",
            "version": "8.0.32",
            "host_ip": "192.168.1.20",
        },
    ],
    "vulnerabilities": [
        {
            "title": "Apache Log4j RCE",
            "severity": "critical",
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "host_ip": "192.168.1.10",
            "port": 443,
            "description": "Remote code execution via JNDI injection",
            "vinculum_metadata": {
                "correlation_id": "corr-001",
                "fingerprint": "fp-abc123",
                "source_tools": ["reticustos:nuclei"],
                "finding_count": 1,
                "epss_score": 0.975,
                "epss_percentile": 0.999,
            },
        },
        {
            "title": "MySQL Remote Access",
            "severity": "high",
            "host_ip": "192.168.1.20",
            "port": 3306,
            "description": "MySQL accessible from external network",
            "vinculum_metadata": {
                "correlation_id": "corr-002",
                "fingerprint": "fp-def456",
                "source_tools": ["reticustos:nmap"],
                "finding_count": 1,
                "epss_score": None,
                "epss_percentile": None,
            },
        },
    ],
    "misconfigurations": [
        {
            "title": "X-Frame-Options Missing",
            "severity": "info",
            "check_id": "nikto-xframe-1",
            "host_ip": "192.168.1.10",
            "port": 443,
            "remediation": "Add X-Frame-Options header",
            "description": "Missing X-Frame-Options header",
            "vinculum_metadata": {
                "correlation_id": "corr-003",
                "fingerprint": "fp-ghi789",
                "source_tools": ["reticustos:nikto"],
                "finding_count": 1,
                "epss_score": None,
                "epss_percentile": None,
            },
        },
    ],
    "relationships": [
        {
            "source_type": "service",
            "source_key": "192.168.1.10:443/tcp",
            "target_type": "host",
            "target_key": "192.168.1.10",
            "relation_type": "runs_on",
        },
    ],
}


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a sample Vinculum export file."""
    filepath = tmp_path / "vinculum_export.json"
    filepath.write_text(json.dumps(SAMPLE_VINCULUM_EXPORT, indent=2))
    return filepath


class TestVinculumParser:
    """Test VinculumParser functionality."""

    def test_parser_attributes(self):
        parser = VinculumParser()
        assert parser.name == "vinculum"
        assert "Host" in parser.entity_types
        assert "Vulnerability" in parser.entity_types
        assert "Misconfiguration" in parser.entity_types
        assert "Relationship" in parser.entity_types

    def test_can_parse_vinculum_export(self, sample_file: Path):
        assert VinculumParser.can_parse(sample_file)

    def test_cannot_parse_non_vinculum_json(self, tmp_path: Path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not VinculumParser.can_parse(other)

    def test_cannot_parse_non_json(self, tmp_path: Path):
        xml = tmp_path / "scan.xml"
        xml.write_text("<xml/>")
        assert not VinculumParser.can_parse(xml)

    def test_parse_yields_hosts(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        hosts = [e for e in entities if isinstance(e, Host)]

        assert len(hosts) == 2
        ips = {h.ip for h in hosts}
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips

        web = next(h for h in hosts if h.ip == "192.168.1.10")
        assert web.hostname == "web01.example.com"
        assert web.os == "Ubuntu 22.04"
        assert web.source == "vinculum"

    def test_parse_yields_services(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        services = [e for e in entities if isinstance(e, Service)]

        assert len(services) == 2
        ports = {s.port for s in services}
        assert ports == {443, 3306}

        https = next(s for s in services if s.port == 443)
        assert https.name == "https"
        assert https.product == "nginx"
        assert https.host_id == "host:192.168.1.10"

    def test_parse_yields_vulnerabilities(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        vulns = [e for e in entities if isinstance(e, Vulnerability)]

        assert len(vulns) == 2

        log4j = next(v for v in vulns if "Log4j" in v.title)
        assert log4j.cve_id == "CVE-2021-44228"
        assert log4j.cvss_score == 10.0
        assert log4j.severity == "critical"
        assert log4j.source == "vinculum"
        assert log4j.affected_asset_id == "service:host:192.168.1.10:443/tcp"

    def test_parse_yields_misconfigurations(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        misconfigs = [e for e in entities if isinstance(e, Misconfiguration)]

        assert len(misconfigs) == 1
        xframe = misconfigs[0]
        assert xframe.title == "X-Frame-Options Missing"
        assert xframe.check_id == "nikto-xframe-1"
        assert xframe.remediation == "Add X-Frame-Options header"
        assert xframe.source == "vinculum"

    def test_vinculum_metadata_preserved(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        vulns = [e for e in entities if isinstance(e, Vulnerability)]

        log4j = next(v for v in vulns if "Log4j" in v.title)
        assert log4j.raw_data.get("correlation_id") == "corr-001"
        assert log4j.raw_data.get("source_tools") == ["reticustos:nuclei"]

    def test_parse_yields_runs_on_relationships(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        rels = [e for e in entities if isinstance(e, Relationship)]
        runs_on = [r for r in rels if r.relation_type == RelationType.RUNS_ON]

        assert len(runs_on) == 2  # One per service

    def test_parse_yields_has_vulnerability_relationships(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        rels = [e for e in entities if isinstance(e, Relationship)]
        has_vuln = [r for r in rels if r.relation_type == RelationType.HAS_VULNERABILITY]

        assert len(has_vuln) == 2  # Two vulnerabilities

    def test_parse_yields_has_misconfiguration_relationships(self, sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(sample_file))
        rels = [e for e in entities if isinstance(e, Relationship)]
        has_misconfig = [r for r in rels if r.relation_type == RelationType.HAS_MISCONFIGURATION]

        assert len(has_misconfig) == 1

    def test_parse_file_wrapper(self, sample_file: Path):
        parser = VinculumParser()
        result = parser.parse_file(sample_file)

        assert len(result.errors) == 0
        assert len(result.hosts) == 2
        assert len(result.services) == 2
        assert len(result.vulnerabilities) == 2
        assert len(result.relationships) > 0
