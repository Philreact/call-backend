from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from qapp_backend.storage.models import StoredSession

SCHEMA_VERSION = 1


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None

    def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema {version} is newer than supported {SCHEMA_VERSION}"
            )
        if version == 0:
            self._db.executescript(
                """
                CREATE TABLE sessions (
                    session_id TEXT PRIMARY KEY,
                    token_hash BLOB NOT NULL,
                    authenticated_user TEXT,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    metadata_json TEXT NOT NULL,
                    subscriptions_json TEXT NOT NULL,
                    last_application_sequence INTEGER NOT NULL
                );
                PRAGMA user_version=1;
                """
            )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.commit()
                self._db.close()
                self._db = None

    def _connection(self) -> sqlite3.Connection:
        if self._db is None:
            raise RuntimeError("database is not open")
        return self._db

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connection()
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()

    def upsert_session(self, session: StoredSession) -> None:
        with self._lock:
            self._connection().execute(
                """
                INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    token_hash=excluded.token_hash,
                    authenticated_user=excluded.authenticated_user,
                    last_seen=excluded.last_seen,
                    expires_at=excluded.expires_at,
                    metadata_json=excluded.metadata_json,
                    subscriptions_json=excluded.subscriptions_json,
                    last_application_sequence=excluded.last_application_sequence
                """,
                (
                    session.session_id,
                    session.token_hash,
                    session.authenticated_user,
                    session.created_at,
                    session.last_seen,
                    session.expires_at,
                    session.metadata_json,
                    session.subscriptions_json,
                    session.last_application_sequence,
                ),
            )
            self._connection().commit()

    def load_sessions(self, now: float) -> list[StoredSession]:
        with self._lock:
            rows = self._connection().execute(
                """
                SELECT session_id, token_hash, authenticated_user, created_at,
                       last_seen, expires_at, metadata_json, subscriptions_json,
                       last_application_sequence
                  FROM sessions
                 WHERE expires_at > ?
                """,
                (now,),
            ).fetchall()
        return [StoredSession(*row) for row in rows]

    def delete_expired_sessions(self, now: float) -> int:
        with self._lock:
            cursor = self._connection().execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (now,)
            )
            self._connection().commit()
            return cursor.rowcount

    def delete_session(self, session_id: str) -> None:
        with self._lock:
            self._connection().execute(
                "DELETE FROM sessions WHERE session_id = ?", (session_id,)
            )
            self._connection().commit()
