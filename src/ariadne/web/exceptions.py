"""Custom exceptions and error handlers for the web API."""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class AriadneAPIError(Exception):
    """Base exception for Ariadne API errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: str = "INTERNAL_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to JSON-serializable dict."""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
        }


class SessionNotFoundError(AriadneAPIError):
    """Raised when a session is not found."""

    def __init__(self, session_id: str) -> None:
        super().__init__(
            message=f"Session not found: {session_id}",
            status_code=404,
            error_code="SESSION_NOT_FOUND",
            details={"session_id": session_id},
        )


class SessionExpiredError(AriadneAPIError):
    """Raised when a session has expired."""

    def __init__(self, session_id: str) -> None:
        super().__init__(
            message=f"Session has expired: {session_id}",
            status_code=410,
            error_code="SESSION_EXPIRED",
            details={"session_id": session_id},
        )


class InvalidFileError(AriadneAPIError):
    """Raised when an uploaded file is invalid."""

    def __init__(self, filename: str, reason: str) -> None:
        super().__init__(
            message=f"Invalid file '{filename}': {reason}",
            status_code=400,
            error_code="INVALID_FILE",
            details={"filename": filename, "reason": reason},
        )


class NoParserFoundError(AriadneAPIError):
    """Raised when no parser can handle a file."""

    def __init__(self, filename: str) -> None:
        super().__init__(
            message=f"No parser found for file: {filename}",
            status_code=400,
            error_code="NO_PARSER_FOUND",
            details={"filename": filename},
        )


class GraphNotBuiltError(AriadneAPIError):
    """Raised when attempting operations on an unbuilt graph."""

    def __init__(self, session_id: str) -> None:
        super().__init__(
            message=f"Graph not built for session: {session_id}. Call /api/graph/build first.",
            status_code=400,
            error_code="GRAPH_NOT_BUILT",
            details={"session_id": session_id},
        )


class AnalysisError(AriadneAPIError):
    """Raised when analysis fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=f"Analysis failed: {message}",
            status_code=500,
            error_code="ANALYSIS_ERROR",
            details=details,
        )


class ExportError(AriadneAPIError):
    """Raised when export fails."""

    def __init__(self, format: str, reason: str) -> None:
        super().__init__(
            message=f"Export to {format} failed: {reason}",
            status_code=500,
            error_code="EXPORT_ERROR",
            details={"format": format, "reason": reason},
        )


class ValidationError(AriadneAPIError):
    """Raised when validation fails."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__(
            message="Validation failed",
            status_code=400,
            error_code="VALIDATION_ERROR",
            details={"errors": errors},
        )


class StorageError(AriadneAPIError):
    """Raised when storage operations fail."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(
            message=f"Storage operation '{operation}' failed: {reason}",
            status_code=500,
            error_code="STORAGE_ERROR",
            details={"operation": operation, "reason": reason},
        )


async def ariadne_exception_handler(
    request: Request, exc: AriadneAPIError
) -> JSONResponse:
    """Handle AriadneAPIError exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
            "details": {"type": type(exc).__name__},
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers with the FastAPI app."""
    app.add_exception_handler(AriadneAPIError, ariadne_exception_handler)
    # Optionally register generic handler for production
    # app.add_exception_handler(Exception, generic_exception_handler)
