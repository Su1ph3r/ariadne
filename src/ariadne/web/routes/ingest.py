"""Data ingestion API routes."""

import atexit
import logging
import shutil
import tempfile
import threading
import time
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile

from ariadne.config import get_config
from ariadne.parsers.registry import ParserRegistry

logger = logging.getLogger(__name__)

router = APIRouter()


class SessionStore:
    """Thread-safe session store with automatic TTL-based cleanup.

    Sessions are stored with their creation time and automatically
    cleaned up when they expire based on the configured TTL.
    """

    def __init__(self, ttl_hours: int = 24, cleanup_interval_seconds: int = 300) -> None:
        """Initialize the session store.

        Args:
            ttl_hours: Session time-to-live in hours (default: 24)
            cleanup_interval_seconds: Interval between cleanup runs in seconds (default: 300)
        """
        self._sessions: dict[str, tuple[Path, float]] = {}  # (path, created_at)
        self._lock = threading.Lock()
        self._ttl_seconds = ttl_hours * 3600
        self._cleanup_interval = cleanup_interval_seconds
        self._cleanup_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._start_cleanup_thread()

    def _start_cleanup_thread(self) -> None:
        """Start the background cleanup thread."""
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="session-cleanup",
        )
        self._cleanup_thread.start()

    def _cleanup_loop(self) -> None:
        """Background loop that periodically cleans up expired sessions."""
        while not self._stop_event.wait(self._cleanup_interval):
            self.cleanup_expired()

    def cleanup_expired(self) -> int:
        """Remove expired sessions and their directories.

        Returns:
            Number of sessions cleaned up
        """
        now = time.time()
        expired = []

        with self._lock:
            for session_id, (path, created_at) in self._sessions.items():
                if now - created_at > self._ttl_seconds:
                    expired.append((session_id, path))

            for session_id, path in expired:
                del self._sessions[session_id]

        # Delete directories outside the lock to avoid blocking
        cleaned = 0
        for session_id, path in expired:
            if self._safe_delete_directory(path, session_id):
                cleaned += 1

        if cleaned > 0:
            logger.info("Cleaned up %d expired sessions", cleaned)

        return cleaned

    def _safe_delete_directory(
        self, path: Path, session_id: str, max_retries: int = 3
    ) -> bool:
        """Safely delete a session directory with retries.

        Args:
            path: Directory path to delete
            session_id: Session ID for logging
            max_retries: Maximum deletion attempts

        Returns:
            True if deletion succeeded, False otherwise
        """
        for attempt in range(max_retries):
            try:
                if path.exists():
                    shutil.rmtree(path)
                return True
            except OSError as e:
                if attempt < max_retries - 1:
                    time.sleep(0.1 * (attempt + 1))  # Brief backoff
                else:
                    logger.warning(
                        "Failed to delete session directory '%s' for session '%s' after %d attempts: %s",
                        path,
                        session_id,
                        max_retries,
                        e,
                    )
        return False

    def create(self, session_id: str, path: Path) -> None:
        """Register a new session.

        Args:
            session_id: Unique session identifier
            path: Path to session directory
        """
        with self._lock:
            self._sessions[session_id] = (path, time.time())

    def get(self, session_id: str) -> Path | None:
        """Get the path for a session.

        Args:
            session_id: Session identifier

        Returns:
            Session directory path or None if not found
        """
        with self._lock:
            entry = self._sessions.get(session_id)
            return entry[0] if entry else None

    def exists(self, session_id: str) -> bool:
        """Check if a session exists.

        Args:
            session_id: Session identifier

        Returns:
            True if session exists, False otherwise
        """
        with self._lock:
            return session_id in self._sessions

    def delete(self, session_id: str) -> Path | None:
        """Remove a session and return its path.

        Args:
            session_id: Session identifier

        Returns:
            Session directory path or None if not found
        """
        with self._lock:
            entry = self._sessions.pop(session_id, None)
            return entry[0] if entry else None

    def list_sessions(self) -> list[str]:
        """List all active session IDs.

        Returns:
            List of session identifiers
        """
        with self._lock:
            return list(self._sessions.keys())

    def stop(self) -> None:
        """Stop the cleanup thread."""
        self._stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)


# Initialize global session store with config
def _get_session_store() -> SessionStore:
    """Get or create the global session store."""
    global _session_store
    if _session_store is None:
        config = get_config()
        _session_store = SessionStore(ttl_hours=config.web.session_ttl_hours)
        atexit.register(_session_store.stop)
    return _session_store


_session_store: SessionStore | None = None


@router.post("/upload")
async def upload_files(files: list[UploadFile] = File(...)) -> dict:
    """Upload scan files for analysis.

    Returns a session ID that can be used to reference the uploaded files.
    """
    session_id = str(uuid4())
    session_dir = Path(tempfile.mkdtemp(prefix=f"ariadne_{session_id}_"))

    store = _get_session_store()
    store.create(session_id, session_dir)

    uploaded = []
    registry = ParserRegistry()

    for file in files:
        if not file.filename:
            continue

        file_path = session_dir / file.filename
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        parser = registry.find_parser(file_path)
        uploaded.append({
            "filename": file.filename,
            "size": len(content),
            "parser": parser.name if parser else None,
            "supported": parser is not None,
        })

    return {
        "session_id": session_id,
        "files": uploaded,
        "supported_count": sum(1 for f in uploaded if f["supported"]),
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str) -> dict:
    """Get information about an upload session."""
    store = _get_session_store()
    session_dir = store.get(session_id)

    if session_dir is None:
        raise HTTPException(status_code=404, detail="Session not found")

    files = list(session_dir.glob("*"))

    return {
        "session_id": session_id,
        "file_count": len(files),
        "files": [f.name for f in files],
    }


@router.delete("/session/{session_id}")
async def delete_session(session_id: str) -> dict:
    """Delete an upload session and its files."""
    store = _get_session_store()
    session_dir = store.delete(session_id)

    if session_dir is None:
        raise HTTPException(status_code=404, detail="Session not found")

    store._safe_delete_directory(session_dir, session_id)

    return {"deleted": True}


@router.get("/parsers")
async def list_parsers() -> dict:
    """List available parsers."""
    registry = ParserRegistry()
    parsers = registry.list_parsers()

    return {
        "parsers": [
            {
                "name": p.name,
                "description": p.description,
                "file_patterns": p.file_patterns,
            }
            for p in parsers
        ]
    }


def get_session_path(session_id: str) -> Path | None:
    """Get the path for a session (used by other routes)."""
    store = _get_session_store()
    return store.get(session_id)
