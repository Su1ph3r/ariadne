"""Tests for the analysis API routes."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from ariadne.web.routes import analysis


class TestAnalysisValidate:
    """Test session validation endpoint."""

    # =========================================================================
    # Validate Session Tests
    # =========================================================================

    def test_validate_session(self, client: TestClient, nmap_xml_content: str):
        """Test validating an upload session."""
        # Upload a file
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # Validate the session
        response = client.post(f"/api/analysis/{session_id}/validate")

        assert response.status_code == 200
        data = response.json()
        assert "valid" in data
        assert "file_count" in data
        assert "parsers" in data

    def test_validate_session_returns_parser_info(self, client: TestClient, nmap_xml_content: str):
        """Test that validation includes parser information."""
        files = {"files": ("nmap_scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        response = client.post(f"/api/analysis/{session_id}/validate")
        data = response.json()

        assert "parsers" in data
        assert isinstance(data["parsers"], list)

    def test_validate_session_with_errors(self, client: TestClient):
        """Test validation detects issues with unsupported files."""
        files = {"files": ("random.txt", "not valid data", "text/plain")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        response = client.post(f"/api/analysis/{session_id}/validate")
        data = response.json()

        # Should still succeed but may have warnings/errors
        assert response.status_code == 200
        assert "warnings" in data or "errors" in data

    def test_validate_session_not_found(self, client: TestClient):
        """Test validating nonexistent session."""
        response = client.post("/api/analysis/nonexistent/validate")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestAnalysisSynthesize:
    """Test attack path synthesis endpoint."""

    # =========================================================================
    # Synthesize Tests
    # =========================================================================

    def test_synthesize_request_structure(self, client: TestClient, nmap_xml_content: str):
        """Test synthesize request validation."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # Patch synthesizer to avoid actual analysis
        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            response = client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

            assert response.status_code == 200

    def test_synthesize_with_max_paths(self, client: TestClient, nmap_xml_content: str):
        """Test synthesize with max_paths parameter."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            response = client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id, "max_paths": 5}
            )

            assert response.status_code == 200

    def test_synthesize_with_targets(self, client: TestClient, nmap_xml_content: str):
        """Test synthesize with specified targets."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            response = client.post(
                "/api/analysis/synthesize",
                json={
                    "session_id": session_id,
                    "targets": ["host:192.168.1.1"],
                }
            )

            assert response.status_code == 200
            # Verify targets passed to analyze
            mock_synth.analyze.assert_called_once()
            call_kwargs = mock_synth.analyze.call_args[1]
            assert call_kwargs.get("targets") == ["host:192.168.1.1"]

    def test_synthesize_with_entry_points(self, client: TestClient, nmap_xml_content: str):
        """Test synthesize with specified entry points."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            response = client.post(
                "/api/analysis/synthesize",
                json={
                    "session_id": session_id,
                    "entry_points": ["service:http:80"],
                }
            )

            assert response.status_code == 200
            call_kwargs = mock_synth.analyze.call_args[1]
            assert call_kwargs.get("entry_points") == ["service:http:80"]

    def test_synthesize_returns_summary(self, client: TestClient, nmap_xml_content: str):
        """Test that synthesize returns summary statistics."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 5, "edges": 3}
            mock_synth_cls.return_value = mock_synth

            response = client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

            data = response.json()
            assert "summary" in data
            assert "total_paths" in data["summary"]
            assert "stats" in data

    def test_synthesize_session_not_found(self, client: TestClient):
        """Test synthesize with nonexistent session."""
        response = client.post(
            "/api/analysis/synthesize",
            json={"session_id": "nonexistent"}
        )

        assert response.status_code == 404

    def test_synthesize_missing_session_id(self, client: TestClient):
        """Test synthesize without session_id."""
        response = client.post("/api/analysis/synthesize", json={})

        assert response.status_code == 422


class TestAnalysisPaths:
    """Test attack paths retrieval endpoint."""

    # =========================================================================
    # Get Paths Tests
    # =========================================================================

    def test_get_paths(self, client: TestClient, nmap_xml_content: str):
        """Test getting synthesized paths."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # First synthesize
        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

        # Then get paths
        response = client.get(f"/api/analysis/{session_id}/paths")

        assert response.status_code == 200
        data = response.json()
        assert "paths" in data

    def test_get_paths_no_analysis(self, client: TestClient):
        """Test getting paths when no analysis has been done."""
        response = client.get("/api/analysis/nonexistent/paths")

        assert response.status_code == 404
        assert "no analysis" in response.json()["detail"].lower()


class TestAnalysisPathDetail:
    """Test individual path detail endpoint."""

    # =========================================================================
    # Get Path Detail Tests
    # =========================================================================

    def test_get_path_detail_not_found(self, client: TestClient, nmap_xml_content: str):
        """Test getting detail for nonexistent path."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # First synthesize
        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

        response = client.get(f"/api/analysis/{session_id}/paths/nonexistent-path")

        assert response.status_code == 404
        assert "path not found" in response.json()["detail"].lower()

    def test_get_path_detail_no_analysis(self, client: TestClient):
        """Test getting path detail without prior analysis."""
        response = client.get("/api/analysis/nonexistent/paths/path-id")

        assert response.status_code == 404


class TestAnalysisExport:
    """Test results export endpoint."""

    # =========================================================================
    # Export Tests
    # =========================================================================

    def test_export_json(self, client: TestClient, nmap_xml_content: str):
        """Test exporting results as JSON."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # First synthesize
        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

        response = client.get(f"/api/analysis/{session_id}/export")

        assert response.status_code == 200
        data = response.json()
        assert "paths" in data

    def test_export_default_format_is_json(self, client: TestClient, nmap_xml_content: str):
        """Test that default export format is JSON."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

        # No format param
        response = client.get(f"/api/analysis/{session_id}/export")
        assert response.status_code == 200

        # Explicit json format
        response = client.get(f"/api/analysis/{session_id}/export", params={"format": "json"})
        assert response.status_code == 200

    def test_export_unsupported_format(self, client: TestClient, nmap_xml_content: str):
        """Test export with unsupported format."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        with patch.object(analysis, "Synthesizer") as mock_synth_cls:
            mock_synth = MagicMock()
            mock_synth.analyze.return_value = []
            mock_synth.store.stats.return_value = {"nodes": 0, "edges": 0}
            mock_synth_cls.return_value = mock_synth

            client.post(
                "/api/analysis/synthesize",
                json={"session_id": session_id}
            )

        response = client.get(f"/api/analysis/{session_id}/export", params={"format": "pdf"})

        assert response.status_code == 400
        assert "unsupported format" in response.json()["detail"].lower()

    def test_export_no_results(self, client: TestClient):
        """Test export without prior analysis."""
        response = client.get("/api/analysis/nonexistent/export")

        assert response.status_code == 404
