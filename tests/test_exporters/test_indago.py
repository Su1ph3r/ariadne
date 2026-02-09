"""Tests for Indago target exporter."""

import json
from pathlib import Path

import pytest

from ariadne.exporters.indago import export_indago_targets, HTTP_PORTS
from ariadne.graph.store import GraphStore
from ariadne.models.asset import Host, Service


@pytest.fixture
def store_with_http_services() -> GraphStore:
    """Create a GraphStore with HTTP services."""
    store = GraphStore()
    host = Host(ip="192.168.1.10", hostname="web01.example.com", source="test")
    svc_https = Service(
        port=443, protocol="tcp", name="https", product="nginx",
        host_id="host:192.168.1.10", ssl=True, source="test",
    )
    svc_http = Service(
        port=8080, protocol="tcp", name="http-proxy",
        host_id="host:192.168.1.10", source="test",
    )
    store.add_entity(host)
    store.add_entity(svc_https)
    store.add_entity(svc_http)
    return store


@pytest.fixture
def store_with_non_http_services() -> GraphStore:
    """Create a GraphStore with only non-HTTP services."""
    store = GraphStore()
    host = Host(ip="10.0.0.1", source="test")
    svc_mysql = Service(
        port=3306, protocol="tcp", name="mysql",
        host_id="host:10.0.0.1", source="test",
    )
    store.add_entity(host)
    store.add_entity(svc_mysql)
    return store


class TestExportIndagoTargets:
    """Test Indago target export."""

    def test_export_creates_file(self, store_with_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets.json"
        result = export_indago_targets(store_with_http_services, output)

        assert result.exists()
        assert result.suffix == ".json"

    def test_export_format(self, store_with_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets.json"
        export_indago_targets(store_with_http_services, output)

        data = json.loads(output.read_text())
        assert data["format"] == "indago-targets"
        assert data["export_source"] == "ariadne"
        assert "target_base_url" in data
        assert "total_endpoints" in data
        assert "endpoints" in data

    def test_export_finds_http_services(self, store_with_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets.json"
        export_indago_targets(store_with_http_services, output)

        data = json.loads(output.read_text())
        assert data["total_endpoints"] == 2
        assert len(data["endpoints"]) == 2

        ports = {ep["port"] for ep in data["endpoints"]}
        assert ports == {443, 8080}

    def test_export_base_url_uses_https_for_443(self, store_with_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets.json"
        export_indago_targets(store_with_http_services, output)

        data = json.loads(output.read_text())
        assert data["target_base_url"].startswith("https://")

    def test_export_no_http_services_yields_empty(self, store_with_non_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets.json"
        export_indago_targets(store_with_non_http_services, output)

        data = json.loads(output.read_text())
        assert data["total_endpoints"] == 0
        assert data["endpoints"] == []
        assert data["target_base_url"] == ""

    def test_export_adds_json_extension(self, store_with_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets"
        result = export_indago_targets(store_with_http_services, output)

        assert result.suffix == ".json"
        assert result.exists()

    def test_export_endpoint_structure(self, store_with_http_services: GraphStore, tmp_path: Path):
        output = tmp_path / "targets.json"
        export_indago_targets(store_with_http_services, output)

        data = json.loads(output.read_text())
        ep = data["endpoints"][0]

        assert "path" in ep
        assert "method" in ep
        assert "params" in ep
        assert "port" in ep
        assert "protocol" in ep
        assert "service_name" in ep
        assert ep["method"] == "GET"
        assert ep["path"] == "/"

    def test_empty_store(self, tmp_path: Path):
        store = GraphStore()
        output = tmp_path / "targets.json"
        export_indago_targets(store, output)

        data = json.loads(output.read_text())
        assert data["total_endpoints"] == 0

    def test_http_ports_constant(self):
        assert 80 in HTTP_PORTS
        assert 443 in HTTP_PORTS
        assert 8080 in HTTP_PORTS
        assert 22 not in HTTP_PORTS
        assert 3306 not in HTTP_PORTS
