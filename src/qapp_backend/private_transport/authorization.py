from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


@dataclass(frozen=True, slots=True)
class AttachGrant:
    token_hash: bytes
    logical_session_id: str
    logical_connection_id: str
    authenticated_user: str
    qapp_identity: tuple[str, str]
    purpose: str
    owner_binding_hash: str
    nonce: str
    expires_at: float


class AttachRejected(ValueError):
    pass


class BootstrapRateLimited(ValueError):
    pass


class AttachTokenAuthority:
    def __init__(
        self,
        *,
        ttl: float,
        per_session_per_minute: int,
        per_user_per_minute: int,
        max_unused_per_session: int,
        max_unused_global: int,
    ) -> None:
        self.ttl = ttl
        self.per_session_per_minute = per_session_per_minute
        self.per_user_per_minute = per_user_per_minute
        self.max_unused_per_session = max_unused_per_session
        self.max_unused_global = max_unused_global
        self._grants: dict[bytes, AttachGrant] = {}
        self._issued: dict[str, deque[float]] = {}
        self._issued_users: dict[str, deque[float]] = {}
        self._lock = threading.RLock()

    def issue(
        self,
        *,
        logical_session_id: str,
        logical_connection_id: str,
        authenticated_user: str,
        qapp_identity: tuple[str, str],
        purpose: str,
        owner_binding_hash: str,
        nonce: str,
        now: float | None = None,
    ) -> tuple[str, AttachGrant]:
        timestamp = time.time() if now is None else now
        with self._lock:
            self._expire_locked(timestamp)
            self._prune_rates_locked(timestamp)
            recent = self._issued.setdefault(logical_session_id, deque())
            user_recent = self._issued_users.setdefault(
                authenticated_user, deque()
            )
            unused = sum(
                grant.logical_session_id == logical_session_id
                for grant in self._grants.values()
            )
            if (
                len(recent) >= self.per_session_per_minute
                or len(user_recent) >= self.per_user_per_minute
                or unused >= self.max_unused_per_session
                or len(self._grants) >= self.max_unused_global
            ):
                raise BootstrapRateLimited("bootstrap rate limit reached")
            token = secrets.token_urlsafe(32)
            digest = token_hash(token)
            grant = AttachGrant(
                digest,
                logical_session_id,
                logical_connection_id,
                authenticated_user,
                qapp_identity,
                purpose,
                owner_binding_hash,
                nonce,
                timestamp + self.ttl,
            )
            self._grants[digest] = grant
            recent.append(timestamp)
            user_recent.append(timestamp)
            return token, grant

    def consume(
        self,
        token: str,
        *,
        logical_session_id: str,
        purpose: str,
        owner_binding_hash: str,
        nonce: str,
        session_lookup: Callable[[str], Any],
        now: float | None = None,
    ) -> tuple[AttachGrant, Any]:
        timestamp = time.time() if now is None else now
        try:
            digest = token_hash(token)
        except (UnicodeEncodeError, AttributeError) as exc:
            raise AttachRejected("attach token rejected") from exc
        with self._lock:
            self._expire_locked(timestamp)
            grant = self._grants.pop(digest, None)
        if grant is None or not hmac.compare_digest(grant.token_hash, digest):
            raise AttachRejected("attach token rejected")
        # A real token is consumed even when another attach field is wrong.
        if (
            grant.expires_at <= timestamp
            or grant.logical_session_id != logical_session_id
            or grant.purpose != purpose
            or grant.owner_binding_hash != owner_binding_hash
            or grant.nonce != nonce
        ):
            raise AttachRejected("attach token rejected")
        session = session_lookup(grant.logical_session_id)
        if (
            session is None
            or session.provisional
            or session.expires_at <= timestamp
            or session.authenticated_user != grant.authenticated_user
            or tuple(session.metadata.get("qapp_identity") or ()) != grant.qapp_identity
            or session.metadata.get("qapp_connection_id") != grant.logical_connection_id
            or session.connection is None
            or session.connection.closed
        ):
            raise AttachRejected("attach token rejected")
        return grant, session

    def invalidate_session(self, logical_session_id: str) -> None:
        with self._lock:
            for digest, grant in tuple(self._grants.items()):
                if grant.logical_session_id == logical_session_id:
                    self._grants.pop(digest, None)
            self._issued.pop(logical_session_id, None)

    def release(self, token: str) -> None:
        """Remove a credential transferred to a different attachment service."""
        try:
            digest = token_hash(token)
        except (UnicodeEncodeError, AttributeError):
            return
        with self._lock:
            self._grants.pop(digest, None)

    def outstanding(
        self, logical_session_id: str | None = None, *, now: float | None = None
    ) -> int:
        with self._lock:
            self._expire_locked(time.time() if now is None else now)
            if logical_session_id is None:
                return len(self._grants)
            return sum(
                grant.logical_session_id == logical_session_id
                for grant in self._grants.values()
            )

    def _expire_locked(self, now: float) -> None:
        for digest, grant in tuple(self._grants.items()):
            if grant.expires_at <= now:
                self._grants.pop(digest, None)

    def _prune_rates_locked(self, now: float) -> None:
        cutoff = now - 60.0
        for mapping in (self._issued, self._issued_users):
            for key, recent in tuple(mapping.items()):
                while recent and recent[0] <= cutoff:
                    recent.popleft()
                if not recent:
                    mapping.pop(key, None)
