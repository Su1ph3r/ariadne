"""Tests for the ingest API routes."""

import io
import pytest
from fastapi.testclient import TestClient

from ariadne.web.routes import ingest


class TestIngestUpload:
    """Test file upload endpoints."""

    # =========================================================================
    # Upload Tests
    # =========================================================================

    def test_upload_single_file(self, client: TestClient, nmap_xml_content: str):
        """Test uploading a single file."""
        files = {"files": ("nmap_scan.xml", nmap_xml_content, "application/xml")}
        response = client.post("/api/ingest/upload", files=files)

        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "nmap_scan.xml"

    def test_upload_multiple_files(self, client: TestClient, nmap_xml_content: str, bloodhound_json_content: str):
        """Test uploading multiple files."""
        files = [
            ("files", ("nmap_scan.xml", nmap_xml_content, "application/xml")),
            ("files", ("bloodhound_users.json", bloodhound_json_content, "application/json")),
        ]
        response = client.post("/api/ingest/upload", files=files)

        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 2

    def test_upload_returns_session_id(self, client: TestClient, nmap_xml_content: str):
        """Test that upload returns a valid session ID."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        response = client.post("/api/ingest/upload", files=files)

        data = response.json()
        session_id = data["session_id"]

        # Session ID should be UUID format
        assert len(session_id) == 36
        assert session_id.count("-") == 4

    def test_upload_detects_parser(self, client: TestClient, nmap_xml_content: str):
        """Test that upload detects appropriate parser."""
        files = {"files": ("nmap_scan.xml", nmap_xml_content, "application/xml")}
        response = client.post("/api/ingest/upload", files=files)

        data = response.json()
        file_info = data["files"][0]
        assert file_info["supported"] is True
        assert file_info["parser"] == "nmap"

    def test_upload_unsupported_file(self, client: TestClient):
        """Test uploading unsupported file type."""
        files = {"files": ("random.txt", "random text content", "text/plain")}
        response = client.post("/api/ingest/upload", files=files)

        assert response.status_code == 200
        data = response.json()
        file_info = data["files"][0]
        assert file_info["supported"] is False
        assert file_info["parser"] is None

    def test_upload_counts_supported(self, client: TestClient, nmap_xml_content: str):
        """Test that upload counts supported files."""
        files = [
            ("files", ("nmap_scan.xml", nmap_xml_content, "application/xml")),
            ("files", ("random.txt", "random", "text/plain")),
        ]
        response = client.post("/api/ingest/upload", files=files)

        data = response.json()
        assert data["supported_count"] == 1

    def test_upload_records_file_size(self, client: TestClient, nmap_xml_content: str):
        """Test that upload records file sizes."""
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        response = client.post("/api/ingest/upload", files=files)

        data = response.json()
        assert data["files"][0]["size"] == len(nmap_xml_content)


class TestIngestSession:
    """Test session management endpoints."""

    # =========================================================================
    # Get Session Tests
    # =========================================================================

    def test_get_session(self, client: TestClient, nmap_xml_content: str):
        """Test getting session information."""
        # First upload a file
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # Then get session info
        response = client.get(f"/api/ingest/session/{session_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id
        assert data["file_count"] == 1
        assert "scan.xml" in data["files"]

    def test_get_session_not_found(self, client: TestClient):
        """Test getting nonexistent session."""
        response = client.get("/api/ingest/session/nonexistent-session-id")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    # =========================================================================
    # Delete Session Tests
    # =========================================================================

    def test_delete_session(self, client: TestClient, nmap_xml_content: str):
        """Test deleting a session."""
        # First upload a file
        files = {"files": ("scan.xml", nmap_xml_content, "application/xml")}
        upload_response = client.post("/api/ingest/upload", files=files)
        session_id = upload_response.json()["session_id"]

        # Delete the session
        response = client.delete(f"/api/ingest/session/{session_id}")

        assert response.status_code == 200
        assert response.json()["deleted"] is True

        # Verify session is gone
        get_response = client.get(f"/api/ingest/session/{session_id}")
        assert get_response.status_code == 404

    def test_delete_session_not_found(self, client: TestClient):
        """Test deleting nonexistent session."""
        response = client.delete("/api/ingest/session/nonexistent")

        assert response.status_code == 404


class TestIngestParsers:
    """Test parser listing endpoint."""

    def test_list_parsers(self, client: TestClient):
        """Test listing available parsers."""
        response = client.get("/api/ingest/parsers")

        assert response.status_code == 200
        data = response.json()
        assert "parsers" in data
        assert len(data["parsers"]) > 0

    def test_parser_info_structure(self, client: TestClient):
        """Test that parser info has correct structure."""
        response = client.get("/api/ingest/parsers")
        data = response.json()

        for parser in data["parsers"]:
            assert "name" in parser
            assert "description" in parser
            assert "file_patterns" in parser
            assert isinstance(parser["file_patterns"], list)

    def test_parsers_include_nmap(self, client: TestClient):
        """Test that parsers list includes nmap."""
        response = client.get("/api/ingest/parsers")
        data = response.json()

        parser_names = [p["name"] for p in data["parsers"]]
        assert "nmap" in parser_names

    def test_parsers_include_bloodhound(self, client: TestClient):
        """Test that parsers list includes bloodhound."""
        response = client.get("/api/ingest/parsers")
        data = response.json()

        parser_names = [p["name"] for p in data["parsers"]]
        assert "bloodhound" in parser_names
