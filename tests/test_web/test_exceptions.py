"""Tests for web API exceptions."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ariadne.web.exceptions import (
    AriadneAPIError,
    SessionNotFoundError,
    SessionExpiredError,
    InvalidFileError,
    NoParserFoundError,
    GraphNotBuiltError,
    AnalysisError,
    ExportError,
    ValidationError,
    StorageError,
    register_exception_handlers,
    ariadne_exception_handler,
)


class TestAriadneAPIError:
    """Test base AriadneAPIError."""

    def test_basic_error(self):
        """Test basic error creation."""
        error = AriadneAPIError("Test error")

        assert error.message == "Test error"
        assert error.status_code == 500
        assert error.error_code == "INTERNAL_ERROR"
        assert error.details == {}

    def test_error_with_all_params(self):
        """Test error with all parameters."""
        error = AriadneAPIError(
            message="Test error",
            status_code=400,
            error_code="TEST_ERROR",
            details={"key": "value"},
        )

        assert error.message == "Test error"
        assert error.status_code == 400
        assert error.error_code == "TEST_ERROR"
        assert error.details == {"key": "value"}

    def test_to_dict(self):
        """Test to_dict conversion."""
        error = AriadneAPIError(
            message="Test",
            error_code="TEST",
            details={"foo": "bar"},
        )

        result = error.to_dict()

        assert result == {
            "error": "TEST",
            "message": "Test",
            "details": {"foo": "bar"},
        }


class TestSessionNotFoundError:
    """Test SessionNotFoundError."""

    def test_error_creation(self):
        """Test error creation."""
        error = SessionNotFoundError("abc-123")

        assert "abc-123" in error.message
        assert error.status_code == 404
        assert error.error_code == "SESSION_NOT_FOUND"
        assert error.details["session_id"] == "abc-123"


class TestSessionExpiredError:
    """Test SessionExpiredError."""

    def test_error_creation(self):
        """Test error creation."""
        error = SessionExpiredError("abc-123")

        assert "abc-123" in error.message
        assert error.status_code == 410
        assert error.error_code == "SESSION_EXPIRED"


class TestInvalidFileError:
    """Test InvalidFileError."""

    def test_error_creation(self):
        """Test error creation."""
        error = InvalidFileError("test.txt", "unsupported format")

        assert "test.txt" in error.message
        assert "unsupported format" in error.message
        assert error.status_code == 400
        assert error.error_code == "INVALID_FILE"
        assert error.details["filename"] == "test.txt"
        assert error.details["reason"] == "unsupported format"


class TestNoParserFoundError:
    """Test NoParserFoundError."""

    def test_error_creation(self):
        """Test error creation."""
        error = NoParserFoundError("unknown.xyz")

        assert "unknown.xyz" in error.message
        assert error.status_code == 400
        assert error.error_code == "NO_PARSER_FOUND"


class TestGraphNotBuiltError:
    """Test GraphNotBuiltError."""

    def test_error_creation(self):
        """Test error creation."""
        error = GraphNotBuiltError("session-123")

        assert "session-123" in error.message
        assert "/api/graph/build" in error.message
        assert error.status_code == 400
        assert error.error_code == "GRAPH_NOT_BUILT"


class TestAnalysisError:
    """Test AnalysisError."""

    def test_error_creation(self):
        """Test error creation."""
        error = AnalysisError("LLM connection failed", {"provider": "openai"})

        assert "LLM connection failed" in error.message
        assert error.status_code == 500
        assert error.error_code == "ANALYSIS_ERROR"
        assert error.details["provider"] == "openai"


class TestExportError:
    """Test ExportError."""

    def test_error_creation(self):
        """Test error creation."""
        error = ExportError("pdf", "unsupported format")

        assert "pdf" in error.message
        assert error.status_code == 500
        assert error.error_code == "EXPORT_ERROR"
        assert error.details["format"] == "pdf"


class TestValidationError:
    """Test ValidationError."""

    def test_error_creation(self):
        """Test error creation."""
        errors = ["Field 'name' is required", "Field 'type' is invalid"]
        error = ValidationError(errors)

        assert error.status_code == 400
        assert error.error_code == "VALIDATION_ERROR"
        assert error.details["errors"] == errors


class TestStorageError:
    """Test StorageError."""

    def test_error_creation(self):
        """Test error creation."""
        error = StorageError("create_session", "disk full")

        assert "create_session" in error.message
        assert "disk full" in error.message
        assert error.status_code == 500
        assert error.error_code == "STORAGE_ERROR"


class TestExceptionHandler:
    """Test exception handler integration."""

    @pytest.fixture
    def app(self):
        """Create test app with exception handlers."""
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/session/{session_id}")
        async def get_session(session_id: str):
            raise SessionNotFoundError(session_id)

        @app.get("/error")
        async def get_error():
            raise AriadneAPIError("Test error", status_code=418, error_code="TEAPOT")

        return app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)

    def test_handler_returns_json(self, client):
        """Test handler returns JSON response."""
        response = client.get("/session/test-123")

        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "SESSION_NOT_FOUND"
        assert "test-123" in data["message"]

    def test_handler_custom_status_code(self, client):
        """Test handler respects custom status code."""
        response = client.get("/error")

        assert response.status_code == 418
        data = response.json()
        assert data["error"] == "TEAPOT"
