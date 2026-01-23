"""Session storage abstraction for persistent sessions."""

import json
import shutil
import sqlite3
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from ariadne.web.exceptions import SessionNotFoundError, SessionExpiredError, StorageError


class SessionData:
    """Data container for a session."""

    def __init__(
        self,
        session_id: str,
        data_path: Path,
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.session_id = session_id
        self.data_path = data_path
        self.created_at = created_at or datetime.utcnow()
        self.expires_at = expires_at
        self.metadata = metadata or {}

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "data_path": str(self.data_path),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata,
        }


class BaseSessionStore(ABC):
    """Abstract base class for session storage."""

    @abstractmethod
    def create_session(
        self,
        ttl_hours: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SessionData:
        """Create a new session."""
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> SessionData:
        """Get a session by ID. Raises SessionNotFoundError if not found."""
        pass

    @abstractmethod
    def delete_session(self, session_id: str) -> None:
        """Delete a session and its data."""
        pass

    @abstractmethod
    def list_sessions(self) -> list[SessionData]:
        """List all active sessions."""
        pass

    @abstractmethod
    def update_metadata(self, session_id: str, metadata: dict[str, Any]) -> None:
        """Update session metadata."""
        pass

    @abstractmethod
    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count of removed sessions."""
        pass


class MemorySessionStore(BaseSessionStore):
    """In-memory session storage (default, non-persistent)."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self._sessions: dict[str, SessionData] = {}
        self._base_dir = base_dir or Path(tempfile.gettempdir()) / "ariadne_sessions"
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def create_session(
        self,
        ttl_hours: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SessionData:
        """Create a new session."""
        session_id = str(uuid4())
        data_path = self._base_dir / session_id
        data_path.mkdir(parents=True, exist_ok=True)

        expires_at = None
        if ttl_hours:
            expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)

        session = SessionData(
            session_id=session_id,
            data_path=data_path,
            expires_at=expires_at,
            metadata=metadata,
        )
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> SessionData:
        """Get a session by ID."""
        if session_id not in self._sessions:
            raise SessionNotFoundError(session_id)

        session = self._sessions[session_id]
        if session.is_expired:
            self.delete_session(session_id)
            raise SessionExpiredError(session_id)

        return session

    def delete_session(self, session_id: str) -> None:
        """Delete a session and its data."""
        if session_id not in self._sessions:
            raise SessionNotFoundError(session_id)

        session = self._sessions.pop(session_id)
        if session.data_path.exists():
            shutil.rmtree(session.data_path, ignore_errors=True)

    def list_sessions(self) -> list[SessionData]:
        """List all active sessions."""
        return [s for s in self._sessions.values() if not s.is_expired]

    def update_metadata(self, session_id: str, metadata: dict[str, Any]) -> None:
        """Update session metadata."""
        session = self.get_session(session_id)
        session.metadata.update(metadata)

    def cleanup_expired(self) -> int:
        """Remove expired sessions."""
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for session_id in expired:
            try:
                self.delete_session(session_id)
            except SessionNotFoundError:
                pass
        return len(expired)


class SQLiteSessionStore(BaseSessionStore):
    """SQLite-backed persistent session storage."""

    def __init__(self, db_path: Path | None = None, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir or Path(tempfile.gettempdir()) / "ariadne_sessions"
        self._base_dir.mkdir(parents=True, exist_ok=True)

        if db_path is None:
            db_path = self._base_dir / "sessions.db"

        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    data_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    metadata TEXT
                )
            """)
            conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        return sqlite3.connect(self._db_path)

    def create_session(
        self,
        ttl_hours: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SessionData:
        """Create a new session."""
        session_id = str(uuid4())
        data_path = self._base_dir / session_id
        data_path.mkdir(parents=True, exist_ok=True)

        created_at = datetime.utcnow()
        expires_at = None
        if ttl_hours:
            expires_at = created_at + timedelta(hours=ttl_hours)

        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO sessions (session_id, data_path, created_at, expires_at, metadata)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        str(data_path),
                        created_at.isoformat(),
                        expires_at.isoformat() if expires_at else None,
                        json.dumps(metadata or {}),
                    ),
                )
                conn.commit()
        except sqlite3.Error as e:
            shutil.rmtree(data_path, ignore_errors=True)
            raise StorageError("create_session", str(e))

        return SessionData(
            session_id=session_id,
            data_path=data_path,
            created_at=created_at,
            expires_at=expires_at,
            metadata=metadata,
        )

    def get_session(self, session_id: str) -> SessionData:
        """Get a session by ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT data_path, created_at, expires_at, metadata FROM sessions WHERE session_id = ?",
                    (session_id,),
                )
                row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageError("get_session", str(e))

        if row is None:
            raise SessionNotFoundError(session_id)

        data_path, created_at, expires_at, metadata = row

        session = SessionData(
            session_id=session_id,
            data_path=Path(data_path),
            created_at=datetime.fromisoformat(created_at),
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
            metadata=json.loads(metadata) if metadata else {},
        )

        if session.is_expired:
            self.delete_session(session_id)
            raise SessionExpiredError(session_id)

        return session

    def delete_session(self, session_id: str) -> None:
        """Delete a session and its data."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT data_path FROM sessions WHERE session_id = ?",
                    (session_id,),
                )
                row = cursor.fetchone()

                if row is None:
                    raise SessionNotFoundError(session_id)

                data_path = Path(row[0])
                if data_path.exists():
                    shutil.rmtree(data_path, ignore_errors=True)

                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
        except sqlite3.Error as e:
            raise StorageError("delete_session", str(e))

    def list_sessions(self) -> list[SessionData]:
        """List all active sessions."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT session_id, data_path, created_at, expires_at, metadata FROM sessions"
                )
                rows = cursor.fetchall()
        except sqlite3.Error as e:
            raise StorageError("list_sessions", str(e))

        sessions = []
        now = datetime.utcnow()

        for row in rows:
            session_id, data_path, created_at, expires_at, metadata = row
            exp = datetime.fromisoformat(expires_at) if expires_at else None

            if exp and now > exp:
                continue

            sessions.append(
                SessionData(
                    session_id=session_id,
                    data_path=Path(data_path),
                    created_at=datetime.fromisoformat(created_at),
                    expires_at=exp,
                    metadata=json.loads(metadata) if metadata else {},
                )
            )

        return sessions

    def update_metadata(self, session_id: str, metadata: dict[str, Any]) -> None:
        """Update session metadata."""
        session = self.get_session(session_id)
        session.metadata.update(metadata)

        try:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE sessions SET metadata = ? WHERE session_id = ?",
                    (json.dumps(session.metadata), session_id),
                )
                conn.commit()
        except sqlite3.Error as e:
            raise StorageError("update_metadata", str(e))

    def cleanup_expired(self) -> int:
        """Remove expired sessions."""
        now = datetime.utcnow().isoformat()
        count = 0

        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT session_id, data_path FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?",
                    (now,),
                )
                rows = cursor.fetchall()

                for session_id, data_path in rows:
                    path = Path(data_path)
                    if path.exists():
                        shutil.rmtree(path, ignore_errors=True)
                    count += 1

                conn.execute(
                    "DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?",
                    (now,),
                )
                conn.commit()
        except sqlite3.Error as e:
            raise StorageError("cleanup_expired", str(e))

        return count


def get_session_store(persistent: bool = False, **kwargs: Any) -> BaseSessionStore:
    """Factory function to get a session store instance.

    Args:
        persistent: If True, use SQLite storage. If False, use in-memory storage.
        **kwargs: Additional arguments passed to the store constructor.

    Returns:
        A session store instance.
    """
    if persistent:
        return SQLiteSessionStore(**kwargs)
    return MemorySessionStore(**kwargs)
