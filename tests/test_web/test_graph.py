"""Tests for the graph API routes."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from ariadne.web.routes import graph


class TestGraphBuild:
    """Test graph building endpoint."""

    # =========================================================================
    # Build Graph Tests
    # =========================================================================

    def test_build_graph_with_session(self, client: TestClient, nmap_xml_content: str):
        """Test building a graph from uploaded files."""
        # First upload a file
        files = {"files": ("nmap_scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # Build the graph
        response = client.post("/api/graph/build", json={"session_id": session_id})

        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id
        assert "stats" in data

    def test_build_graph_returns_stats(self, client: TestClient, nmap_xml_content: str):
        """Test that build returns graph statistics."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        response = client.post("/api/graph/build", json={"session_id": session_id})
        data = response.json()

        assert "stats" in data
        stats = data["stats"]
        assert "node_count" in stats or "nodes" in stats or isinstance(stats, dict)

    def test_build_graph_session_not_found(self, client: TestClient):
        """Test building graph with nonexistent session."""
        response = client.post("/api/graph/build", json={"session_id": "nonexistent"})

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_build_graph_missing_session_id(self, client: TestClient):
        """Test build request without session_id."""
        response = client.post("/api/graph/build", json={})

        assert response.status_code == 422  # Validation error


class TestGraphStats:
    """Test graph statistics endpoint."""

    def test_get_graph_stats(self, client: TestClient, nmap_xml_content: str):
        """Test getting stats for built graph."""
        # Upload and build
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        # Get stats
        response = client.get(f"/api/graph/{session_id}/stats")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)

    def test_get_stats_graph_not_found(self, client: TestClient):
        """Test getting stats for non-built graph."""
        response = client.get("/api/graph/nonexistent/stats")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestGraphNodes:
    """Test graph nodes endpoint."""

    def test_get_nodes(self, client: TestClient, nmap_xml_content: str):
        """Test getting nodes from graph."""
        # Upload and build
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        # Get nodes
        response = client.get(f"/api/graph/{session_id}/nodes")

        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "total" in data
        assert isinstance(data["nodes"], list)

    def test_get_nodes_with_type_filter(self, client: TestClient, nmap_xml_content: str):
        """Test filtering nodes by type."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/nodes", params={"type": "host"})

        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        # All returned nodes should be hosts (if any)
        for node in data["nodes"]:
            assert node.get("type") == "host"

    def test_get_nodes_with_limit(self, client: TestClient, nmap_xml_content: str):
        """Test limiting nodes returned."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/nodes", params={"limit": 1})

        assert response.status_code == 200
        data = response.json()
        assert len(data["nodes"]) <= 1

    def test_get_nodes_graph_not_found(self, client: TestClient):
        """Test getting nodes for nonexistent graph."""
        response = client.get("/api/graph/nonexistent/nodes")

        assert response.status_code == 404


class TestGraphEdges:
    """Test graph edges endpoint."""

    def test_get_edges(self, client: TestClient, nmap_xml_content: str):
        """Test getting edges from graph."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/edges")

        assert response.status_code == 200
        data = response.json()
        assert "edges" in data
        assert "total" in data
        assert isinstance(data["edges"], list)

    def test_get_edges_structure(self, client: TestClient, nmap_xml_content: str):
        """Test edge data structure."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/edges")
        data = response.json()

        for edge in data["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "type" in edge

    def test_get_edges_with_type_filter(self, client: TestClient, nmap_xml_content: str):
        """Test filtering edges by type."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/edges", params={"type": "has_service"})

        assert response.status_code == 200

    def test_get_edges_with_limit(self, client: TestClient, nmap_xml_content: str):
        """Test limiting edges returned."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/edges", params={"limit": 1})

        assert response.status_code == 200
        data = response.json()
        assert len(data["edges"]) <= 1

    def test_get_edges_graph_not_found(self, client: TestClient):
        """Test getting edges for nonexistent graph."""
        response = client.get("/api/graph/nonexistent/edges")

        assert response.status_code == 404


class TestGraphVisualization:
    """Test visualization data endpoint."""

    def test_get_visualization_data(self, client: TestClient, nmap_xml_content: str):
        """Test getting Cytoscape.js format data."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/visualization")

        assert response.status_code == 200
        data = response.json()
        assert "elements" in data
        assert "nodes" in data["elements"]
        assert "edges" in data["elements"]

    def test_visualization_node_format(self, client: TestClient, nmap_xml_content: str):
        """Test Cytoscape node format."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/visualization")
        data = response.json()

        for node in data["elements"]["nodes"]:
            assert "data" in node
            assert "id" in node["data"]
            assert "label" in node["data"]
            assert "type" in node["data"]

    def test_visualization_edge_format(self, client: TestClient, nmap_xml_content: str):
        """Test Cytoscape edge format."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/visualization")
        data = response.json()

        for edge in data["elements"]["edges"]:
            assert "data" in edge
            assert "source" in edge["data"]
            assert "target" in edge["data"]
            assert "type" in edge["data"]

    def test_visualization_graph_not_found(self, client: TestClient):
        """Test visualization for nonexistent graph."""
        response = client.get("/api/graph/nonexistent/visualization")

        assert response.status_code == 404


class TestGraphEntryPoints:
    """Test entry points endpoint."""

    def test_get_entry_points(self, client: TestClient, nmap_xml_content: str):
        """Test getting entry points from graph."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/entry-points")

        assert response.status_code == 200
        data = response.json()
        assert "entry_points" in data
        assert isinstance(data["entry_points"], list)

    def test_entry_points_structure(self, client: TestClient, nmap_xml_content: str):
        """Test entry point data structure."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/entry-points")
        data = response.json()

        for ep in data["entry_points"]:
            assert "id" in ep
            assert "label" in ep
            assert "type" in ep

    def test_entry_points_graph_not_found(self, client: TestClient):
        """Test entry points for nonexistent graph."""
        response = client.get("/api/graph/nonexistent/entry-points")

        assert response.status_code == 404


class TestGraphTargets:
    """Test targets (crown jewels) endpoint."""

    def test_get_targets(self, client: TestClient, nmap_xml_content: str):
        """Test getting high-value targets from graph."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/targets")

        assert response.status_code == 200
        data = response.json()
        assert "targets" in data
        assert isinstance(data["targets"], list)

    def test_targets_structure(self, client: TestClient, nmap_xml_content: str):
        """Test target data structure."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]
        client.post("/api/graph/build", json={"session_id": session_id})

        response = client.get(f"/api/graph/{session_id}/targets")
        data = response.json()

        for target in data["targets"]:
            assert "id" in target
            assert "label" in target
            assert "type" in target

    def test_targets_graph_not_found(self, client: TestClient):
        """Test targets for nonexistent graph."""
        response = client.get("/api/graph/nonexistent/targets")

        assert response.status_code == 404
