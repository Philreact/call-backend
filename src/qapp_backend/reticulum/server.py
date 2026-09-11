from __future__ import annotations

import asyncio
import inspect
import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, Callable

from qapp_backend.config import Config, load_config
from qapp_backend.deployment import require_deployment
from qapp_backend.readiness import write_marker
from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.errors import ProtocolError
from qapp_backend.reticulum.protocol import DataEnvelope
from qapp_backend.reticulum.realtime import MessageContext
from qapp_backend.reticulum.rpc import RpcContext, RpcRouter
from qapp_backend.reticulum.sessions import SessionManager
from qapp_backend.reticulum.writer import ReticulumWriter, schedule_teardown
from qapp_backend.storage.database import Database

logger = logging.getLogger(__name__)
DESTINATION_ASPECT = "qortal-hub-v3.qapp-backend.v1"
APP_NAME = "qortal-hub-v3"
ASPECTS = ("qapp-backend", "v1")
BUFFER_STREAM_ID = 7


def write_all_buffer(writer: Any, data: bytes, timeout: float = 10.0) -> None:
    """Compatibility helper for raw (not buffered) Channel writers."""
    ReticulumWriter(writer, timeout)(data)


class QAppServer:
    def __init__(self, config: Config | None = None):
        self.config = config or load_config()
        self.rpc_router = RpcRouter(self.config.max_rpc_payload, self.config.max_rpc_response)
        self.message_handlers: dict[str, Callable[..., Any]] = {}
        self.startup_handlers: list[Callable[[], Any]] = []
        self.shutdown_handlers: list[Callable[[], Any]] = []
        self.maintenance_handlers: list[Callable[[], Any]] = []
        self.disconnect_handlers: list[Callable[[Any], Any]] = []
        self.database = Database(self.config.database_path)
        self.sessions = SessionManager(
            self.database,
            self.config.session_ttl,
            self.config.dedup_cache_size,
            self.config.unauthenticated_session_ttl,
        )
        self.logical_sessions: dict[str, Any] = {}
        self._session_lock = threading.RLock()
        self.connections: dict[str, PhysicalConnection] = {}
        self._links: dict[bytes, PhysicalConnection] = {}
        self.reticulum: Any = None
        self.identity: Any = None
        self.destination: Any = None
        self.destination_hash: str | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop = threading.Event()
        self._announce_timer: threading.Timer | None = None
        self._maintenance_timer: threading.Timer | None = None
        self.shutting_down = False
        from qapp_backend.private_transport import PrivateTransportService
        self.private_transport: Any = PrivateTransportService(self, self.config)

    def rpc(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            self.rpc_router.register(path, handler)
            return handler
        return decorator

    def on_message(self, message_type: str | Callable[..., Any]) -> Any:
        if callable(message_type):
            self.message_handlers["*"] = message_type
            return message_type

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            if message_type in self.message_handlers:
                raise ValueError(f"handler already registered for {message_type}")
            self.message_handlers[message_type] = handler
            return handler
        return decorator

    def on_startup(self, handler: Callable[[], Any]) -> Callable[[], Any]:
        self.startup_handlers.append(handler)
        return handler

    def on_shutdown(self, handler: Callable[[], Any]) -> Callable[[], Any]:
        self.shutdown_handlers.append(handler)
        return handler

    def on_maintenance(self, handler: Callable[[], Any]) -> Callable[[], Any]:
        self.maintenance_handlers.append(handler)
        return handler

    def on_session_disconnect(self, handler: Callable[[Any], Any]) -> Callable[[Any], Any]:
        self.disconnect_handlers.append(handler)
        return handler

    def initialize(self) -> None:
        import RNS

        require_deployment(self.config)
        self.config.ensure_directories()
        self.database.open()
        self.sessions.load()
        # A logical connection ID routes messages only within the current live
        # transport. It is not an authentication credential, so persisted
        # sessions must be reclaimed through application authentication.
        self.logical_sessions = {}
        for handler in self.startup_handlers:
            handler()
        self.reticulum = RNS.Reticulum(configdir=str(self.config.rns_config_dir))
        self.identity = self._load_or_create_identity(RNS, self.config.identity_path)
        self.destination = RNS.Destination(
            self.identity, RNS.Destination.IN, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS,
        )
        self.destination_hash = self.destination.hash.hex()
        if self.private_transport is not None:
            self.private_transport.start()
        self.destination.set_link_established_callback(self._link_established)
        for path in self.rpc_router.handlers:
            self.destination.register_request_handler(
                path, response_generator=self._make_rpc_callback(path), allow=RNS.Destination.ALLOW_ALL,
            )
        logger.info(
            "server initialized",
            extra={"event": "server_startup"},
        )
        logger.info("destination %s aspect=%s protocol=1", self.destination_hash, DESTINATION_ASPECT)
        self.destination.announce()
        logger.info("destination announced", extra={"event": "destination_announce"})
        self._schedule_announce()
        self._schedule_maintenance()
        write_marker(self.config, "server", {"running": True})

    @staticmethod
    def _load_or_create_identity(RNS: Any, path: Path) -> Any:
        if path.exists():
            identity = RNS.Identity.from_file(str(path))
            if identity is None:
                raise RuntimeError(f"invalid Reticulum identity file: {path}")
            os.chmod(path, 0o600)
            return identity
        identity = RNS.Identity()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(identity.get_private_key())
        except FileExistsError:
            identity = RNS.Identity.from_file(str(path))
            if identity is None:
                raise RuntimeError(f"invalid concurrently-created Reticulum identity: {path}")
        os.chmod(path, 0o600)
        return identity

    def _make_rpc_callback(self, registered_path: str) -> Callable[..., Any]:
        def callback(path: str, data: Any, request_id: bytes, link_id: bytes, remote_identity: Any, requested_at: float) -> Any:
            connection = self._links.get(link_id)
            logical_connection_id = (
                str(data.get("logicalConnectionId"))
                if isinstance(data, dict) and data.get("logicalConnectionId")
                else None
            )
            with self._session_lock:
                session = self.logical_sessions.get(logical_connection_id)
                if session is not None and session.connection is not connection:
                    session = None
            context = RpcContext(
                self, registered_path, transport_request_id=request_id,
                connection=connection, remote_identity=remote_identity,
                session=session, logical_connection_id=logical_connection_id,
            )
            logger.info("RPC request", extra={"event": "rpc_request", "rpc_path": registered_path})
            return self.rpc_router.dispatch(registered_path, data, context)
        return callback

    def _link_established(self, link: Any) -> None:
        if self.shutting_down:
            link.teardown()
            return
        channel = link.get_channel()
        from RNS.Buffer import RawChannelWriter
        buffer_writer = RawChannelWriter(BUFFER_STREAM_ID, channel)
        write = ReticulumWriter(buffer_writer)

        connection = PhysicalConnection(
            write,
            self.config,
            self._application_message,
            self._connection_closed,
            link,
            self._logical_connection_closed,
        )
        connection.channel = channel
        connection.buffer_writer = buffer_writer

        def ready(ready_bytes: int) -> None:
            try:
                while ready_bytes > 0 and not connection.closed:
                    chunk = connection.reader.read(min(ready_bytes, 64 * 1024))
                    if not chunk:
                        break
                    connection.receive(chunk)
                    ready_bytes -= len(chunk)
            except Exception:
                logger.exception("Buffer receive failed", extra={"connection_id": connection.id})
                connection.close("buffer_receive_failed")
                try:
                    schedule_teardown(link)
                except Exception:
                    pass

        connection.reader = __import__("RNS").Buffer.create_reader(BUFFER_STREAM_ID, channel, ready)
        self.connections[connection.id] = connection
        self._links[link.link_id] = connection
        link.set_link_closed_callback(
            lambda closed_link: connection.close(
                self._reticulum_close_reason(closed_link)
            )
        )
        link.set_remote_identified_callback(lambda closed_link, identity: setattr(connection, "remote_identity", identity))
        logger.info("incoming Link", extra={"event": "incoming_link", "connection_id": connection.id})

    @staticmethod
    def _reticulum_close_reason(link: Any) -> str:
        teardown_reason = getattr(link, "teardown_reason", None)
        if teardown_reason == getattr(link, "TIMEOUT", object()):
            return "reticulum_timeout"
        initiator_closed = teardown_reason == getattr(
            link, "INITIATOR_CLOSED", object()
        )
        destination_closed = teardown_reason == getattr(
            link, "DESTINATION_CLOSED", object()
        )
        if initiator_closed or destination_closed:
            local_initiated = (
                initiator_closed and bool(getattr(link, "initiator", False))
            ) or (
                destination_closed and not bool(getattr(link, "initiator", False))
            )
            return "local_reticulum_close" if local_initiated else "remote_reticulum_close"
        return "reticulum_link_closed"

    def _application_message(self, connection: PhysicalConnection, envelope: DataEnvelope, message_id: int) -> None:
        message = envelope.decode_payload()
        message_type = message.get("type") if isinstance(message, dict) else None
        handler = self.message_handlers.get(message_type, self.message_handlers.get("*"))
        if handler is None:
            return
        logical_id = envelope.connection_id
        now = time.time()
        with self._session_lock:
            session = self.logical_sessions.get(logical_id)
            if session is not None and session.expires_at <= now:
                self._discard_session(session)
                session = None
            creating = session is None
            if creating:
                self._expire_sessions(now)
            if creating and self.sessions.provisional_count() >= self.config.max_unauthenticated_sessions:
                raise ProtocolError("unauthenticated session capacity reached")
            self._admit_logical_id(connection, logical_id, creating, now)
            if session is None:
                session, _unused_resume_token = self.sessions.create(
                    connection,
                    now,
                    provisional=True,
                )
                session.metadata["qapp_connection_id"] = logical_id
                self.logical_sessions[logical_id] = session
            else:
                old_connection = session.connection
                if (
                    old_connection is not None
                    and old_connection is not connection
                    and not old_connection.closed
                ):
                    connection.logical_connection_ids.discard(logical_id)
                    raise ProtocolError("logical connection is already active")
                session.connection = connection
        if session.pending_transport:
            connection.adopt_pending(session.pending_transport)
            session.pending_transport.clear()
        if session.seen_message(message_id):
            logger.info("duplicate DATA", extra={"event": "duplicate_data", "connection_id": connection.id, "session_id": session.session_id, "message_id": message_id})
            return
        self.sessions.touch(session, now)
        context = MessageContext(self, connection, session, message_id, logical_id)
        try:
            self.invoke_message_handler(handler, context, message)
        except Exception:
            logger.exception("application message handler failed", extra={"connection_id": connection.id, "session_id": session.session_id, "message_id": message_id})

    def invoke_message_handler(
        self, handler: Callable[..., Any], context: Any, message: Any,
    ) -> None:
        result = handler(context, message)
        if inspect.isawaitable(result):
            if self._loop is None:
                raise RuntimeError("async handler used before server event loop started")
            asyncio.run_coroutine_threadsafe(result, self._loop)

    def _admit_logical_id(
        self,
        connection: PhysicalConnection,
        logical_id: str,
        creating: bool,
        now: float,
    ) -> None:
        if logical_id in connection.logical_connection_ids:
            return
        if len(connection.logical_connection_ids) >= self.config.max_logical_sessions_per_link:
            raise ProtocolError("logical session limit reached")
        cutoff = now - 60.0
        while (
            connection.new_logical_session_times
            and connection.new_logical_session_times[0] <= cutoff
        ):
            connection.new_logical_session_times.popleft()
        if (
            creating
            and len(connection.new_logical_session_times)
            >= self.config.max_new_sessions_per_link_per_minute
        ):
            raise ProtocolError("logical session creation rate exceeded")
        connection.logical_connection_ids.add(logical_id)
        if creating:
            connection.new_logical_session_times.append(now)

    def _remove_session_indexes(self, session: Any) -> None:
        logical_id = session.metadata.get("qapp_connection_id")
        if not isinstance(logical_id, str):
            return
        if self.logical_sessions.get(logical_id) is session:
            self.logical_sessions.pop(logical_id, None)
        connection = session.connection
        logical_ids = getattr(connection, "logical_connection_ids", None)
        if logical_ids is not None:
            logical_ids.discard(logical_id)

    def _discard_session(self, session: Any) -> None:
        if self.private_transport is not None:
            self.private_transport.invalidate_session(session, close_attached=True)
        self._remove_session_indexes(session)
        session.connection = None
        session.pending_transport.clear()
        self.sessions.discard(session.session_id)

    def discard_session(self, session: Any) -> None:
        with self._session_lock:
            self._discard_session(session)

    def revoke_session(self, session: Any) -> None:
        """Remove an authorized session and apply normal call-disconnect cleanup."""
        with self._session_lock:
            if self.sessions.get(session.session_id) is not session:
                return
            for handler in self.disconnect_handlers:
                try:
                    handler(session)
                except Exception:
                    logger.exception("application revocation handler failed")
            self._discard_session(session)

    def _expire_sessions(self, now: float | None = None) -> int:
        expired = self.sessions.expire(now)
        for session in expired:
            if self.private_transport is not None:
                self.private_transport.invalidate_session(session, close_attached=True)
            self._remove_session_indexes(session)
            session.connection = None
            session.pending_transport.clear()
        return len(expired)

    def _connection_closed(self, connection: PhysicalConnection) -> None:
        self.connections.pop(connection.id, None)
        if connection.link is not None:
            self._links.pop(connection.link.link_id, None)
        with self._session_lock:
            for logical_id in tuple(connection.logical_connection_ids):
                self._disconnect_logical_session(connection, logical_id)
            connection.logical_connection_ids.clear()
            connection.new_logical_session_times.clear()

    def _logical_connection_closed(
        self, connection: PhysicalConnection, logical_id: str,
    ) -> None:
        with self._session_lock:
            self._disconnect_logical_session(connection, logical_id)
        logger.info(
            "logical connection closed",
            extra={
                "event": "logical_connection_closed",
                "connection_id": connection.id,
                "logical_connection_id": logical_id,
                "reason": "remote_logical_close",
            },
        )

    def _disconnect_logical_session(
        self, connection: PhysicalConnection, logical_id: str,
    ) -> None:
        session = self.logical_sessions.get(logical_id)
        if session is None or session.connection is not connection:
            return
        if session.provisional:
            self._discard_session(session)
            return
        if self.private_transport is not None:
            self.private_transport.invalidate_session(session, close_attached=True)
        self._remove_session_indexes(session)
        session.metadata.pop("qapp_connection_id", None)
        session.connection = None
        # Unacknowledged frames cannot be transferred to a new Link until a
        # replacement Link proves the Qortal identity again. Application state
        # recovery remains authoritative and exactly-once at the action ID.
        session.pending_transport.clear()
        self.sessions.touch(session)
        self.sessions.persist(session)
        for handler in self.disconnect_handlers:
            try:
                handler(session)
            except Exception:
                logger.exception("application disconnect handler failed")

    def publish(self, topic: str, payload: dict[str, Any]) -> int:
        sent = 0
        for session in self.sessions.all():
            if topic in session.subscriptions and session.connection is not None:
                session.send({"type": "event", "topic": topic, "payload": payload})
                sent += 1
        return sent

    def _schedule_announce(self) -> None:
        if self.shutting_down:
            return
        self._announce_timer = threading.Timer(self.config.announce_interval, self._announce)
        self._announce_timer.daemon = True
        self._announce_timer.start()

    def _announce(self) -> None:
        if not self.shutting_down and self.destination is not None:
            self.destination.announce()
            logger.info("destination announced", extra={"event": "destination_announce"})
            self._schedule_announce()

    def _schedule_maintenance(self) -> None:
        if self.shutting_down:
            return
        interval = max(1.0, min(30.0, self.config.idle_connection_timeout / 2))
        self._maintenance_timer = threading.Timer(interval, self._maintain)
        self._maintenance_timer.daemon = True
        self._maintenance_timer.start()

    def _maintain(self) -> None:
        if self.shutting_down:
            return
        cutoff = time.monotonic() - self.config.idle_connection_timeout
        for connection in list(self.connections.values()):
            if connection.last_activity < cutoff:
                connection.close("idle_timeout")
                try:
                    if connection.link is not None:
                        connection.link.teardown()
                except Exception:
                    pass
        pending_cutoff = time.monotonic() - self.config.ack_timeout
        now = time.time()
        for session in self.sessions.all():
            session.pending_transport = [
                item for item in session.pending_transport if item[3] > pending_cutoff
            ]
            if (
                not session.provisional
                and session.connection is not None
                and not session.connection.closed
            ):
                self.sessions.touch(session, now)
        with self._session_lock:
            self._expire_sessions(now)
            self.database.delete_expired_sessions(now)
        for handler in self.maintenance_handlers:
            try:
                handler()
            except Exception:
                logger.exception("application maintenance handler failed")
        self._schedule_maintenance()

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        self.initialize()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: self._stop.set())
        try:
            while not self._stop.wait(0.5):
                self._loop.run_until_complete(asyncio.sleep(0))
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        if self.shutting_down:
            return
        self.shutting_down = True
        try:
            write_marker(self.config, "server", {"running": False})
        except OSError:
            logger.exception("could not update shutdown readiness marker")
        logger.info("server shutting down", extra={"event": "shutdown"})
        if self._announce_timer is not None:
            self._announce_timer.cancel()
        if self._maintenance_timer is not None:
            self._maintenance_timer.cancel()
        for connection in list(self.connections.values()):
            connection.close("server_shutdown")
            try:
                if connection.link is not None:
                    connection.link.teardown()
            except Exception:
                pass
        for session in self.sessions.all():
            self.sessions.persist(session)
        if self.private_transport is not None:
            self.private_transport.stop()
        for handler in self.shutdown_handlers:
            try:
                handler()
            except Exception:
                logger.exception("application shutdown handler failed")
        self.database.close()
        if self._loop is not None:
            self._loop.close()
