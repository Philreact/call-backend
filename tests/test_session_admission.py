from dataclasses import replace

from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.framing import Frame, FrameType
from qapp_backend.reticulum.protocol import ControlMessage, ControlType, encode_data_envelope
from qapp_backend.reticulum.server import QAppServer


def data(logical_id: str, message_id: int, message: dict) -> bytes:
    return Frame(
        FrameType.DATA,
        message_id,
        encode_data_envelope(logical_id, message),
    ).encode()


def close(logical_id: str, message_id: int) -> bytes:
    return Frame(
        FrameType.CONTROL,
        message_id,
        ControlMessage(ControlType.CLOSE, logical_id).encode(),
    ).encode()


def server_with_handler(config, **overrides):
    server = QAppServer(replace(config, **overrides))
    server.database.open()
    server.on_message("noop")(lambda _ctx, _message: None)
    return server


def connection_for(server: QAppServer) -> PhysicalConnection:
    connection = PhysicalConnection(
        lambda _data: None,
        server.config,
        server._application_message,
        server._connection_closed,
        on_logical_close=server._logical_connection_closed,
    )
    server.connections[connection.id] = connection
    return connection


def stored_session_count(server: QAppServer) -> int:
    return server.database._connection().execute(
        "SELECT COUNT(*) FROM sessions"
    ).fetchone()[0]


def test_provisional_session_is_memory_only_and_expiration_cleans_every_index(config):
    server = server_with_handler(config, unauthenticated_session_ttl=120)
    try:
        connection = connection_for(server)
        connection.receive(data("logical-one", 1, {"type": "noop"}))

        session = server.logical_sessions["logical-one"]
        original_expiry = session.expires_at
        assert session.provisional
        assert server.sessions.provisional_count() == 1
        assert stored_session_count(server) == 0

        connection.receive(data("logical-one", 2, {"type": "noop"}))
        assert session.expires_at == original_expiry

        assert server._expire_sessions(original_expiry + 1) == 1
        assert "logical-one" not in server.logical_sessions
        assert "logical-one" not in connection.logical_connection_ids
        assert server.sessions.get(session.session_id) is None
        assert stored_session_count(server) == 0
    finally:
        server.database.close()


def test_successful_authentication_persists_but_cannot_resume_by_logical_id(config):
    server = QAppServer(config)
    server.database.open()
    received_sessions = []

    def authenticate(ctx, _message):
        received_sessions.append(ctx.session)
        if len(received_sessions) == 1:
            ctx.server.sessions.promote(ctx.session, "Q-authenticated")

    server.on_message("authenticate")(authenticate)
    try:
        connection = connection_for(server)
        connection.receive(data("logical-auth", 1, {"type": "authenticate"}))

        session = server.logical_sessions["logical-auth"]
        assert not session.provisional
        assert session.authenticated_user == "Q-authenticated"
        assert stored_session_count(server) == 1

        session.expires_at = 1
        connection.close("test")
        assert "logical-auth" not in server.logical_sessions
        assert server.sessions.get(session.session_id) is session
        assert session.connection is None
        assert "qapp_connection_id" not in session.metadata
        assert session.expires_at > session.last_seen
        assert stored_session_count(server) == 1

        replacement_connection = connection_for(server)
        replacement_connection.receive(
            data("logical-auth", 2, {"type": "authenticate"})
        )
        replacement = server.logical_sessions["logical-auth"]
        assert replacement is not session
        assert replacement.connection is replacement_connection
        assert replacement.provisional
        assert replacement.authenticated_user is None
    finally:
        server.database.close()


def test_link_close_discards_provisional_sessions(config):
    server = server_with_handler(config)
    try:
        connection = connection_for(server)
        connection.receive(data("logical-one", 1, {"type": "noop"}))
        session_id = server.logical_sessions["logical-one"].session_id

        connection.close("test")

        assert "logical-one" not in server.logical_sessions
        assert server.sessions.get(session_id) is None
        assert server.sessions.provisional_count() == 0
    finally:
        server.database.close()


def test_logical_close_disconnects_one_authenticated_session_once(config):
    server = QAppServer(config)
    server.database.open()
    disconnected = []

    def authenticate(ctx, _message):
        server.sessions.promote(ctx.session, f"Q-{ctx.qapp_connection_id}")

    server.on_message("authenticate")(authenticate)
    server.on_session_disconnect(lambda session: disconnected.append(session.session_id))
    try:
        connection = connection_for(server)
        connection.receive(data("logical-one", 1, {"type": "authenticate"}))
        connection.receive(data("logical-two", 2, {"type": "authenticate"}))
        first = server.logical_sessions["logical-one"]
        second = server.logical_sessions["logical-two"]

        connection.receive(close("logical-one", 3))
        connection.receive(close("logical-one", 4))

        assert disconnected == [first.session_id]
        assert "logical-one" not in server.logical_sessions
        assert first.connection is None
        assert "qapp_connection_id" not in first.metadata
        assert server.logical_sessions["logical-two"] is second
        assert second.connection is connection
        assert connection.logical_connection_ids == {"logical-two"}

        connection.receive(data("logical-one", 5, {"type": "authenticate"}))
        assert "logical-one" not in server.logical_sessions
        assert server.logical_sessions["logical-two"] is second
        assert not connection.closed
    finally:
        server.database.close()


def test_per_link_logical_session_limit_closes_abusive_link(config):
    server = server_with_handler(
        config,
        max_logical_sessions_per_link=2,
        max_new_sessions_per_link_per_minute=8,
    )
    try:
        connection = connection_for(server)
        connection.receive(data("logical-one", 1, {"type": "noop"}))
        connection.receive(data("logical-two", 2, {"type": "noop"}))
        connection.receive(data("logical-three", 3, {"type": "noop"}))

        assert connection.closed
        assert server.sessions.provisional_count() == 0
        assert not server.logical_sessions
    finally:
        server.database.close()


def test_per_link_creation_rate_closes_churning_link(config):
    server = server_with_handler(
        config,
        max_logical_sessions_per_link=8,
        max_new_sessions_per_link_per_minute=1,
    )
    try:
        connection = connection_for(server)
        connection.receive(data("logical-one", 1, {"type": "noop"}))
        connection.receive(data("logical-two", 2, {"type": "noop"}))

        assert connection.closed
        assert server.sessions.provisional_count() == 0
    finally:
        server.database.close()


def test_global_provisional_limit_preserves_existing_link_and_rejects_new_one(config):
    server = server_with_handler(config, max_unauthenticated_sessions=1)
    try:
        first = connection_for(server)
        second = connection_for(server)
        first.receive(data("logical-one", 1, {"type": "noop"}))
        second.receive(data("logical-two", 2, {"type": "noop"}))

        assert not first.closed
        assert second.closed
        assert server.sessions.provisional_count() == 1
        assert set(server.logical_sessions) == {"logical-one"}
    finally:
        first.close("cleanup")
        server.database.close()


def test_unknown_message_does_not_allocate_session(config):
    server = QAppServer(config)
    server.database.open()
    try:
        connection = connection_for(server)
        connection.receive(data("logical-one", 1, {"type": "unsupported"}))

        assert not server.logical_sessions
        assert server.sessions.provisional_count() == 0
        assert stored_session_count(server) == 0
    finally:
        server.database.close()
