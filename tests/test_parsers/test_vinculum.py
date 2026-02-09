"""Tests for Vinculum parser."""

import json

import pytest
from pathlib import Path

from ariadne.models.asset import Host, Service, CloudResource, Container, MobileApp, ApiEndpoint
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

        assert len(runs_on) == 3  # Two from services inline + one from relationships array

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


SAMPLE_V11_EXPORT = {
    "format": "vinculum-ariadne-export",
    "version": "1.1",
    "metadata": {
        "generated_at": "2025-06-01T12:00:00Z",
        "vinculum_version": "0.2.0",
    },
    "hosts": [
        {"ip": "10.0.0.1", "hostname": "api.example.com"},
    ],
    "services": [
        {
            "port": 443,
            "protocol": "tcp",
            "name": "https",
            "host_ip": "10.0.0.1",
        },
    ],
    "vulnerabilities": [],
    "misconfigurations": [],
    "cloud_resources": [
        {
            "resource_id": "arn:aws:s3:::my-bucket",
            "type": "s3-bucket",
            "name": "my-bucket",
            "provider": "aws",
            "region": "us-east-1",
            "account_id": "123456789012",
        },
        {
            "resource_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
            "type": "ec2-instance",
            "provider": "aws",
            "region": "us-east-1",
        },
    ],
    "containers": [
        {
            "id": "container-abc123",
            "image": "nginx:latest",
            "runtime": "docker",
            "namespace": "default",
            "privileged": True,
        },
        {
            "container_id": "container-def456",
            "image": "redis:7",
            "registry": "docker.io",
            "privileged": False,
        },
    ],
    "mobile_apps": [
        {
            "app_id": "com.example.app",
            "name": "Example App",
            "platform": "android",
            "version": "2.1.0",
        },
    ],
    "api_endpoints": [
        {
            "path": "/api/users",
            "method": "GET",
            "base_url": "https://api.example.com",
            "parameters": ["id", "page"],
        },
        {
            "path": "/api/users",
            "method": "POST",
            "base_url": "https://api.example.com",
            "parameters": [],
        },
    ],
    "relationships": [
        {
            "source_key": "cloud:aws:s3-bucket:arn:aws:s3:::my-bucket",
            "target_key": "vuln:s3-public",
            "relation_type": "has_cloud_vulnerability",
        },
    ],
}


@pytest.fixture
def v11_sample_file(tmp_path: Path) -> Path:
    """Create a v1.1 Vinculum export file."""
    filepath = tmp_path / "vinculum_v11_export.json"
    filepath.write_text(json.dumps(SAMPLE_V11_EXPORT, indent=2))
    return filepath


class TestVinculumParserV11:
    """Test VinculumParser v1.1 entity handling."""

    def test_parser_entity_types_include_v11(self):
        parser = VinculumParser()
        assert "CloudResource" in parser.entity_types
        assert "Container" in parser.entity_types
        assert "MobileApp" in parser.entity_types
        assert "ApiEndpoint" in parser.entity_types

    def test_parse_cloud_resources(self, v11_sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(v11_sample_file))
        cloud = [e for e in entities if isinstance(e, CloudResource)]

        assert len(cloud) == 2

        bucket = next(c for c in cloud if "s3" in c.resource_type)
        assert bucket.resource_id == "arn:aws:s3:::my-bucket"
        assert bucket.resource_type == "s3-bucket"
        assert bucket.name == "my-bucket"
        assert bucket.provider == "aws"
        assert bucket.region == "us-east-1"
        assert bucket.account_id == "123456789012"
        assert bucket.source == "vinculum"

    def test_parse_containers(self, v11_sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(v11_sample_file))
        containers = [e for e in entities if isinstance(e, Container)]

        assert len(containers) == 2

        nginx = next(c for c in containers if c.image == "nginx:latest")
        assert nginx.container_id == "container-abc123"
        assert nginx.runtime == "docker"
        assert nginx.namespace == "default"
        assert nginx.privileged is True
        assert nginx.source == "vinculum"

        redis = next(c for c in containers if c.image == "redis:7")
        assert redis.container_id == "container-def456"
        assert redis.registry == "docker.io"
        assert redis.privileged is False

    def test_parse_mobile_apps(self, v11_sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(v11_sample_file))
        apps = [e for e in entities if isinstance(e, MobileApp)]

        assert len(apps) == 1
        app = apps[0]
        assert app.app_id == "com.example.app"
        assert app.name == "Example App"
        assert app.platform == "android"
        assert app.version == "2.1.0"
        assert app.source == "vinculum"

    def test_parse_api_endpoints(self, v11_sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(v11_sample_file))
        endpoints = [e for e in entities if isinstance(e, ApiEndpoint)]

        assert len(endpoints) == 2

        get_ep = next(e for e in endpoints if e.method == "GET")
        assert get_ep.path == "/api/users"
        assert get_ep.base_url == "https://api.example.com"
        assert get_ep.parameters == ["id", "page"]
        assert get_ep.source == "vinculum"

        post_ep = next(e for e in endpoints if e.method == "POST")
        assert post_ep.path == "/api/users"
        assert post_ep.parameters == []

    def test_parse_v11_relationships(self, v11_sample_file: Path):
        parser = VinculumParser()
        entities = list(parser.parse(v11_sample_file))
        rels = [e for e in entities if isinstance(e, Relationship)]
        cloud_vuln_rels = [r for r in rels if r.relation_type == RelationType.HAS_CLOUD_VULNERABILITY]

        assert len(cloud_vuln_rels) == 1
        assert cloud_vuln_rels[0].source_id == "cloud:aws:s3-bucket:arn:aws:s3:::my-bucket"
        assert cloud_vuln_rels[0].target_id == "vuln:s3-public"

    def test_v11_backward_compatible_with_v10(self, v11_sample_file: Path):
        """v1.1 files should still yield hosts, services, and relationships."""
        parser = VinculumParser()
        entities = list(parser.parse(v11_sample_file))

        hosts = [e for e in entities if isinstance(e, Host)]
        services = [e for e in entities if isinstance(e, Service)]

        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert len(services) == 1
        assert services[0].port == 443

    def test_empty_v11_sections_ok(self, tmp_path: Path):
        """v1.1 with empty new sections should parse without errors."""
        data = {
            "format": "vinculum-ariadne-export",
            "version": "1.1",
            "hosts": [],
            "services": [],
            "vulnerabilities": [],
            "misconfigurations": [],
            "cloud_resources": [],
            "containers": [],
            "mobile_apps": [],
            "api_endpoints": [],
            "relationships": [],
        }
        filepath = tmp_path / "vinculum_empty_v11.json"
        filepath.write_text(json.dumps(data))

        parser = VinculumParser()
        entities = list(parser.parse(filepath))
        assert len(entities) == 0

    def test_missing_v11_sections_ok(self, tmp_path: Path):
        """v1.0 format without new sections should still parse fine."""
        data = {
            "format": "vinculum-ariadne-export",
            "version": "1.0",
            "hosts": [{"ip": "10.0.0.1"}],
            "services": [],
            "vulnerabilities": [],
            "misconfigurations": [],
        }
        filepath = tmp_path / "vinculum_v10.json"
        filepath.write_text(json.dumps(data))

        parser = VinculumParser()
        entities = list(parser.parse(filepath))
        hosts = [e for e in entities if isinstance(e, Host)]
        assert len(hosts) == 1

    def test_invalid_relationship_type_skipped(self, tmp_path: Path):
        """Relationships with unknown types should be skipped."""
        data = {
            "format": "vinculum-ariadne-export",
            "version": "1.1",
            "hosts": [],
            "services": [],
            "vulnerabilities": [],
            "misconfigurations": [],
            "relationships": [
                {
                    "source_key": "a",
                    "target_key": "b",
                    "relation_type": "nonexistent_type",
                },
            ],
        }
        filepath = tmp_path / "vinculum_bad_rel.json"
        filepath.write_text(json.dumps(data))

        parser = VinculumParser()
        entities = list(parser.parse(filepath))
        rels = [e for e in entities if isinstance(e, Relationship)]
        assert len(rels) == 0
