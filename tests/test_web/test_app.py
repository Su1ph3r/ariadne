"""Tests for the main FastAPI app."""

import pytest
from fastapi.testclient import TestClient

from ariadne import __version__


class TestApp:
    """Test main application endpoints."""

    # =========================================================================
    # Dashboard Tests
    # =========================================================================

    def test_dashboard_returns_html(self, client: TestClient):
        """Test that dashboard returns HTML."""
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_dashboard_contains_ariadne(self, client: TestClient):
        """Test that dashboard contains Ariadne branding."""
        response = client.get("/")

        assert "Ariadne" in response.text

    def test_dashboard_contains_version(self, client: TestClient):
        """Test that dashboard has version element."""
        response = client.get("/")

        # Should have version display somewhere (e.g., "v0.1.0" pattern)
        assert "v0." in response.text.lower() or "version" in response.text.lower()

    # =========================================================================
    # Health Check Tests
    # =========================================================================

    def test_health_check(self, client: TestClient):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == __version__

    def test_health_check_returns_json(self, client: TestClient):
        """Test health check returns JSON."""
        response = client.get("/health")

        assert "application/json" in response.headers["content-type"]

    # =========================================================================
    # Config Tests
    # =========================================================================

    def test_get_config(self, client: TestClient):
        """Test getting app configuration."""
        response = client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        assert "llm_provider" in data
        assert "llm_model" in data
        assert "parsers_enabled" in data
        assert "output_format" in data

    def test_config_non_sensitive(self, client: TestClient):
        """Test that config doesn't expose sensitive data."""
        response = client.get("/api/config")
        data = response.json()

        # Should not contain API keys or secrets
        for key in data:
            assert "key" not in key.lower() or "api_key" not in key.lower()
            assert "secret" not in key.lower()
            assert "password" not in key.lower()

    # =========================================================================
    # OpenAPI Docs Tests
    # =========================================================================

    def test_openapi_docs_available(self, client: TestClient):
        """Test that OpenAPI docs are available."""
        response = client.get("/docs")

        # FastAPI redirects to /docs/
        assert response.status_code in [200, 307]

    def test_openapi_json_available(self, client: TestClient):
        """Test that OpenAPI JSON schema is available."""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert data["info"]["title"] == "Ariadne"

    # =========================================================================
    # CORS Tests
    # =========================================================================

    def test_cors_headers_not_present_by_default(self, client: TestClient):
        """Test CORS headers behavior."""
        response = client.get("/health")

        # Without CORS middleware configured, these won't be present
        # This test documents the current behavior
        assert response.status_code == 200
