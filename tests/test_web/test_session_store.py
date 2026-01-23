"""Tests for session storage."""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ariadne.web.session_store import (
    SessionData,
    MemorySessionStore,
    SQLiteSessionStore,
    get_session_store,
)
from ariadne.web.exceptions import SessionNotFoundError, SessionExpiredError


class TestSessionData:
    """Test SessionData class."""

    def test_session_data_creation(self, tmp_path):
        """Test creating session data."""
        session = SessionData(
            session_id="test-123",
            data_path=tmp_path,
        )

        assert session.session_id == "test-123"
        assert session.data_path == tmp_path
        assert session.created_at is not None
        assert session.expires_at is None
        assert session.metadata == {}

    def test_session_not_expired_when_no_expiry(self, tmp_path):
        """Test session is not expired when no expiry set."""
        session = SessionData(
            session_id="test-123",
            data_path=tmp_path,
        )

        assert session.is_expired is False

    def test_session_not_expired_before_expiry(self, tmp_path):
        """Test session is not expired before expiry time."""
        session = SessionData(
            session_id="test-123",
            data_path=tmp_path,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )

        assert session.is_expired is False

    def test_session_expired_after_expiry(self, tmp_path):
        """Test session is expired after expiry time."""
        session = SessionData(
            session_id="test-123",
            data_path=tmp_path,
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )

        assert session.is_expired is True

    def test_session_to_dict(self, tmp_path):
        """Test session to_dict conversion."""
        session = SessionData(
            session_id="test-123",
            data_path=tmp_path,
            metadata={"key": "value"},
        )

        result = session.to_dict()

        assert result["session_id"] == "test-123"
        assert result["data_path"] == str(tmp_path)
        assert result["metadata"] == {"key": "value"}
        assert "created_at" in result


class TestMemorySessionStore:
    """Test MemorySessionStore."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create memory store."""
        return MemorySessionStore(base_dir=tmp_path)

    def test_create_session(self, store):
        """Test creating a session."""
        session = store.create_session()

        assert session.session_id is not None
        assert session.data_path.exists()

    def test_create_session_with_ttl(self, store):
        """Test creating a session with TTL."""
        session = store.create_session(ttl_hours=24)

        assert session.expires_at is not None
        assert session.expires_at > datetime.utcnow()

    def test_create_session_with_metadata(self, store):
        """Test creating a session with metadata."""
        session = store.create_session(metadata={"user": "test"})

        assert session.metadata == {"user": "test"}

    def test_get_session(self, store):
        """Test getting a session."""
        created = store.create_session()
        retrieved = store.get_session(created.session_id)

        assert retrieved.session_id == created.session_id

    def test_get_nonexistent_session_raises(self, store):
        """Test getting nonexistent session raises error."""
        with pytest.raises(SessionNotFoundError):
            store.get_session("nonexistent")

    def test_get_expired_session_raises(self, store):
        """Test getting expired session raises error."""
        session = store.create_session(ttl_hours=1)
        # Manually expire
        session.expires_at = datetime.utcnow() - timedelta(hours=1)

        with pytest.raises(SessionExpiredError):
            store.get_session(session.session_id)

    def test_delete_session(self, store):
        """Test deleting a session."""
        session = store.create_session()
        data_path = session.data_path

        store.delete_session(session.session_id)

        assert not data_path.exists()
        with pytest.raises(SessionNotFoundError):
            store.get_session(session.session_id)

    def test_delete_nonexistent_session_raises(self, store):
        """Test deleting nonexistent session raises error."""
        with pytest.raises(SessionNotFoundError):
            store.delete_session("nonexistent")

    def test_list_sessions(self, store):
        """Test listing sessions."""
        store.create_session()
        store.create_session()

        sessions = store.list_sessions()

        assert len(sessions) == 2

    def test_list_sessions_excludes_expired(self, store):
        """Test listing excludes expired sessions."""
        store.create_session()
        expired = store.create_session(ttl_hours=1)
        expired.expires_at = datetime.utcnow() - timedelta(hours=1)

        sessions = store.list_sessions()

        assert len(sessions) == 1

    def test_update_metadata(self, store):
        """Test updating session metadata."""
        session = store.create_session(metadata={"a": 1})
        store.update_metadata(session.session_id, {"b": 2})

        updated = store.get_session(session.session_id)

        assert updated.metadata == {"a": 1, "b": 2}

    def test_cleanup_expired(self, store):
        """Test cleaning up expired sessions."""
        store.create_session()
        expired = store.create_session(ttl_hours=1)
        expired.expires_at = datetime.utcnow() - timedelta(hours=1)

        count = store.cleanup_expired()

        assert count == 1
        assert len(store.list_sessions()) == 1


class TestSQLiteSessionStore:
    """Test SQLiteSessionStore."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create SQLite store."""
        return SQLiteSessionStore(
            db_path=tmp_path / "test.db",
            base_dir=tmp_path / "sessions",
        )

    def test_create_session(self, store):
        """Test creating a session."""
        session = store.create_session()

        assert session.session_id is not None
        assert session.data_path.exists()

    def test_create_session_with_ttl(self, store):
        """Test creating a session with TTL."""
        session = store.create_session(ttl_hours=24)

        assert session.expires_at is not None

    def test_create_session_with_metadata(self, store):
        """Test creating a session with metadata."""
        session = store.create_session(metadata={"user": "test"})

        assert session.metadata == {"user": "test"}

    def test_get_session(self, store):
        """Test getting a session."""
        created = store.create_session()
        retrieved = store.get_session(created.session_id)

        assert retrieved.session_id == created.session_id

    def test_get_nonexistent_session_raises(self, store):
        """Test getting nonexistent session raises error."""
        with pytest.raises(SessionNotFoundError):
            store.get_session("nonexistent")

    def test_delete_session(self, store):
        """Test deleting a session."""
        session = store.create_session()
        data_path = session.data_path

        store.delete_session(session.session_id)

        assert not data_path.exists()
        with pytest.raises(SessionNotFoundError):
            store.get_session(session.session_id)

    def test_list_sessions(self, store):
        """Test listing sessions."""
        store.create_session()
        store.create_session()

        sessions = store.list_sessions()

        assert len(sessions) == 2

    def test_update_metadata(self, store):
        """Test updating session metadata."""
        session = store.create_session(metadata={"a": 1})
        store.update_metadata(session.session_id, {"b": 2})

        updated = store.get_session(session.session_id)

        assert updated.metadata == {"a": 1, "b": 2}

    def test_cleanup_expired(self, store):
        """Test cleaning up expired sessions."""
        store.create_session()
        # Create expired session by inserting directly
        import sqlite3
        from datetime import datetime

        expired_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        with sqlite3.connect(store._db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, data_path, created_at, expires_at, metadata) VALUES (?, ?, ?, ?, ?)",
                ("expired-123", "/tmp/expired", datetime.utcnow().isoformat(), expired_time, "{}"),
            )
            conn.commit()

        count = store.cleanup_expired()

        assert count == 1

    def test_persistence(self, tmp_path):
        """Test sessions persist across store instances."""
        db_path = tmp_path / "persist.db"
        base_dir = tmp_path / "sessions"

        store1 = SQLiteSessionStore(db_path=db_path, base_dir=base_dir)
        session = store1.create_session(metadata={"test": True})
        session_id = session.session_id

        store2 = SQLiteSessionStore(db_path=db_path, base_dir=base_dir)
        retrieved = store2.get_session(session_id)

        assert retrieved.session_id == session_id
        assert retrieved.metadata == {"test": True}


class TestGetSessionStore:
    """Test get_session_store factory."""

    def test_get_memory_store(self):
        """Test getting memory store."""
        store = get_session_store(persistent=False)

        assert isinstance(store, MemorySessionStore)

    def test_get_sqlite_store(self, tmp_path):
        """Test getting SQLite store."""
        store = get_session_store(
            persistent=True,
            db_path=tmp_path / "test.db",
            base_dir=tmp_path / "sessions",
        )

        assert isinstance(store, SQLiteSessionStore)
