from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from qapp_backend.storage.database import Database
from qapp_backend.storage.models import StoredSession

if TYPE_CHECKING:
    from qapp_backend.reticulum.connection import PhysicalConnection


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


@dataclass(slots=True)
class ApplicationSession:
    session_id: str
    _token_hash: bytes
    created_at: float
    last_seen: float
    expires_at: float
    authenticated_user: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    subscriptions: set[str] = field(default_factory=set)
    last_application_sequence: int = 0
    connection: "PhysicalConnection | None" = None
    pending_transport: list[tuple[int, str, bytes, float]] = field(default_factory=list, repr=False)
    provisional: bool = False
    _dedup: OrderedDict[int, None] = field(default_factory=OrderedDict, repr=False)
    _dedup_limit: int = 512
    _last_persisted_at: float = field(default=0.0, repr=False)
    private_transport: Any = field(default=None, repr=False)

    def token_matches(self, token: str) -> bool:
        return hmac.compare_digest(self._token_hash, _token_hash(token))

    def seen_message(self, message_id: int) -> bool:
        if message_id in self._dedup:
            self._dedup.move_to_end(message_id)
            return True
        self._dedup[message_id] = None
        while len(self._dedup) > self._dedup_limit:
            self._dedup.popitem(last=False)
        return False

    def subscribe(self, topic: str) -> None:
        if not topic or len(topic) > 256:
            raise ValueError("topic must contain 1 to 256 characters")
        self.subscriptions.add(topic)

    def unsubscribe(self, topic: str) -> None:
        self.subscriptions.discard(topic)

    def send(self, payload: dict[str, Any]) -> int:
        if self.connection is None or self.connection.closed:
            raise RuntimeError("session has no active physical connection")
        connection_id = self.metadata.get("qapp_connection_id")
        if not isinstance(connection_id, str) or not connection_id:
            raise RuntimeError("session has no Q-App logical connection ID")
        return self.connection.send_application(connection_id, payload)

    def to_stored(self) -> StoredSession:
        return StoredSession(
            self.session_id, self._token_hash, self.authenticated_user,
            self.created_at, self.last_seen, self.expires_at,
            json.dumps(self.metadata, separators=(",", ":")),
            json.dumps(sorted(self.subscriptions), separators=(",", ":")),
            self.last_application_sequence,
        )


class SessionManager:
    def __init__(
        self,
        database: Database,
        ttl: float,
        dedup_limit: int = 512,
        provisional_ttl: float = 120.0,
        persist_interval: float = 60.0,
    ):
        self.database = database
        self.ttl = ttl
        self.dedup_limit = dedup_limit
        self.provisional_ttl = provisional_ttl
        self.persist_interval = persist_interval
        self._sessions: dict[str, ApplicationSession] = {}
        self._lock = threading.RLock()

    def load(self, now: float | None = None) -> None:
        timestamp = time.time() if now is None else now
        with self._lock:
            for stored in self.database.load_sessions(timestamp):
                self._sessions[stored.session_id] = ApplicationSession(
                    stored.session_id, stored.token_hash, stored.created_at,
                    stored.last_seen, stored.expires_at, stored.authenticated_user,
                    json.loads(stored.metadata_json), set(json.loads(stored.subscriptions_json)),
                    stored.last_application_sequence,
                    provisional=False,
                    _dedup_limit=self.dedup_limit,
                    _last_persisted_at=stored.last_seen,
                )

    def create(
        self,
        connection: "PhysicalConnection | None" = None,
        now: float | None = None,
        *,
        provisional: bool = False,
    ) -> tuple[ApplicationSession, str]:
        timestamp = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        session = ApplicationSession(
            secrets.token_urlsafe(18), _token_hash(token), timestamp, timestamp,
            timestamp + (self.provisional_ttl if provisional else self.ttl),
            connection=connection,
            provisional=provisional,
            _dedup_limit=self.dedup_limit,
            _last_persisted_at=timestamp,
        )
        with self._lock:
            self._sessions[session.session_id] = session
            if not provisional:
                self.database.upsert_session(session.to_stored())
        return session, token

    def promote(
        self,
        session: ApplicationSession,
        authenticated_user: str,
        now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else now
        with self._lock:
            if self._sessions.get(session.session_id) is not session:
                raise ValueError("session is no longer active")
            session.authenticated_user = authenticated_user
            session.provisional = False
            session.last_seen = timestamp
            session.expires_at = timestamp + self.ttl
            self.database.upsert_session(session.to_stored())
            session._last_persisted_at = timestamp

    def touch(self, session: ApplicationSession, now: float | None = None) -> None:
        timestamp = time.time() if now is None else now
        with self._lock:
            if self._sessions.get(session.session_id) is not session:
                return
            session.last_seen = timestamp
            if session.provisional:
                return
            session.expires_at = timestamp + self.ttl
            if timestamp - session._last_persisted_at >= self.persist_interval:
                self.database.upsert_session(session.to_stored())
                session._last_persisted_at = timestamp

    def resume(self, session_id: str, token: str, connection: "PhysicalConnection", now: float | None = None, rotate: bool = True) -> tuple[ApplicationSession | None, str | None]:
        timestamp = time.time() if now is None else now
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.expires_at <= timestamp or not session.token_matches(token):
                return None, None
            old = session.connection
            if old is not None and old is not connection and not old.closed:
                old.close("replaced_by_resumed_connection")
            session.connection = connection
            session.last_seen = timestamp
            session.expires_at = timestamp + self.ttl
            new_token = None
            if rotate:
                new_token = secrets.token_urlsafe(32)
                session._token_hash = _token_hash(new_token)
            self.database.upsert_session(session.to_stored())
            session._last_persisted_at = timestamp
            return session, new_token

    def persist(self, session: ApplicationSession) -> None:
        with self._lock:
            if session.provisional or self._sessions.get(session.session_id) is not session:
                return
            self.database.upsert_session(session.to_stored())
            session._last_persisted_at = session.last_seen

    def expire(self, now: float | None = None) -> tuple[ApplicationSession, ...]:
        timestamp = time.time() if now is None else now
        with self._lock:
            expired = tuple(
                value for value in self._sessions.values()
                if value.expires_at <= timestamp
            )
            for session in expired:
                self._sessions.pop(session.session_id, None)
            if any(not session.provisional for session in expired):
                self.database.delete_expired_sessions(timestamp)
            return expired

    def provisional_count(self) -> int:
        with self._lock:
            return sum(session.provisional for session in self._sessions.values())

    def all(self) -> tuple[ApplicationSession, ...]:
        with self._lock:
            return tuple(self._sessions.values())

    def get(self, session_id: str) -> ApplicationSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def discard(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is not None and not session.provisional:
                self.database.delete_session(session_id)
