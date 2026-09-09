from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from qapp_backend.auth.group_access import (
    GroupAccessDenied,
    GroupAccessPolicy,
    GroupAccessUnavailable,
)
from qapp_backend.auth.qortal_identity import QortalIdentityVerifier


logger = logging.getLogger(__name__)
ACCESS_CHECKED_AT = "group_access_checked_at"
ACCESS_POLICY_REVISION = "group_access_policy_revision"


class QAppAuthenticationService:
    """Signed Qortal-account authentication for an application session."""

    def __init__(self, server: Any) -> None:
        self.server = server
        self.verifier = QortalIdentityVerifier(
            server.config.allowed_qapps,
            server.config.max_auth_challenges,
            server.config.enforce_qapp_allowlist,
        )
        self.access = GroupAccessPolicy(
            server.config.access_mode,
            server.config.allowed_group_ids,
            server.config.core_url_bases,
        )
        self._workers = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="qapp-group-access"
        )
        self._pending: set[str] = set()
        self._pending_lock = threading.Lock()
        server.authentication_service = self
        server.rpc("/auth/challenge")(self.challenge)
        server.rpc("/session/info")(self.session_info)
        server.on_message("AUTHENTICATE")(self.authenticate)
        server.on_maintenance(self.maintain)
        server.on_shutdown(self.shutdown)

    def challenge(self, _ctx: Any, _payload: Any) -> dict[str, Any]:
        destination = self.server.destination_hash
        if not isinstance(destination, str):
            return {"error": {"code": "BACKEND_UNAVAILABLE"}}
        return self.verifier.issue(destination)

    def session_info(self, ctx: Any, _payload: Any) -> dict[str, Any]:
        session = ctx.session
        return {
            "authenticated": bool(
                session is not None
                and not session.provisional
                and session.authenticated_user
            ),
            "address": session.authenticated_user if session else None,
        }

    def authenticate(self, ctx: Any, message: Any) -> None:
        request_id = message.get("requestId") if isinstance(message, dict) else None
        try:
            if not isinstance(message, dict) or set(message) - {
                "type",
                "requestId",
                "payload",
            }:
                raise ValueError("authentication message is invalid")
            payload = message.get("payload")
            if not isinstance(payload, dict) or set(payload) != {"proof"}:
                raise ValueError("authentication payload is invalid")
            address, _public_key, qapp_identity = self.verifier.verify(
                payload["proof"]
            )
            checked_at = self.access.authorize(address)
            ctx.session.metadata["qapp_identity"] = list(qapp_identity)
            ctx.session.metadata[ACCESS_CHECKED_AT] = checked_at
            ctx.session.metadata[ACCESS_POLICY_REVISION] = self.access.revision
            self.server.sessions.promote(ctx.session, address)
            self.server.sessions.persist(ctx.session)
            ctx.session.send(
                {
                    "type": "AUTHENTICATED",
                    "requestId": request_id,
                    "payload": {
                        "address": address,
                        "qappName": qapp_identity[0],
                        "qappService": qapp_identity[1],
                    },
                }
            )
        except GroupAccessDenied:
            self._send_error(ctx.session, request_id, "BACKEND_ACCESS_DENIED")
        except GroupAccessUnavailable:
            self._send_error(ctx.session, request_id, "BACKEND_ACCESS_UNAVAILABLE")
        except (TypeError, ValueError):
            self._send_error(ctx.session, request_id, "IDENTITY_PROOF_INVALID")

    @staticmethod
    def _send_error(session: Any, request_id: Any, code: str) -> None:
        try:
            session.send(
                {
                    "type": "AUTHENTICATION_ERROR",
                    "requestId": request_id,
                    "payload": {"code": code},
                }
            )
        except RuntimeError:
            pass

    def require_authorized(self, session: Any, now: float | None = None) -> None:
        if self.server.config.access_mode == "public":
            return
        timestamp = time.time() if now is None else now
        checked_at = session.metadata.get(ACCESS_CHECKED_AT)
        revision = session.metadata.get(ACCESS_POLICY_REVISION)
        if (
            revision == self.access.revision
            and isinstance(checked_at, (int, float))
            and timestamp - checked_at < self.server.config.access_revalidate_interval
        ):
            return
        try:
            refreshed = self.access.authorize(session.authenticated_user, timestamp)
        except GroupAccessUnavailable:
            if (
                revision == self.access.revision
                and isinstance(checked_at, (int, float))
                and timestamp - checked_at <= self.server.config.access_outage_grace
            ):
                return
            raise
        session.metadata[ACCESS_CHECKED_AT] = refreshed
        session.metadata[ACCESS_POLICY_REVISION] = self.access.revision
        self.server.sessions.persist(session)

    def maintain(self) -> None:
        if self.server.config.access_mode == "public":
            return
        now = time.time()
        for session in self.server.sessions.all():
            if session.provisional or not session.authenticated_user:
                continue
            checked_at = session.metadata.get(ACCESS_CHECKED_AT)
            revision = session.metadata.get(ACCESS_POLICY_REVISION)
            if (
                revision == self.access.revision
                and isinstance(checked_at, (int, float))
                and now - checked_at < self.server.config.access_revalidate_interval
            ):
                continue
            with self._pending_lock:
                if session.session_id in self._pending:
                    continue
                self._pending.add(session.session_id)
            future = self._workers.submit(self._revalidate, session)
            future.add_done_callback(
                lambda _future, session_id=session.session_id: self._finished(session_id)
            )

    def _finished(self, session_id: str) -> None:
        with self._pending_lock:
            self._pending.discard(session_id)

    def _revalidate(self, session: Any) -> None:
        if self.server.sessions.get(session.session_id) is not session:
            return
        try:
            self.require_authorized(session)
            return
        except GroupAccessDenied:
            code = "BACKEND_ACCESS_DENIED"
        except GroupAccessUnavailable:
            code = "BACKEND_ACCESS_UNAVAILABLE"
        self.revoke(session, code)

    def revoke(self, session: Any, code: str) -> None:
        logger.info(
            "backend access revoked",
            extra={"event": "backend_access_revoked", "session_id": session.session_id[:12]},
        )
        try:
            session.send({"type": "BACKEND_ACCESS_REVOKED", "payload": {"code": code}})
        except RuntimeError:
            pass
        self.server.revoke_session(session)

    def shutdown(self) -> None:
        self._workers.shutdown(wait=True, cancel_futures=True)


def install_authentication_service(server: Any) -> QAppAuthenticationService:
    return QAppAuthenticationService(server)
