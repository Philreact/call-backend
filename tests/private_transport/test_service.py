import base64
import json
import time
from dataclasses import replace
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives import serialization

from qapp_backend.private_transport.authorization import AttachRejected
from qapp_backend.private_transport.service import (
    BOOTSTRAP_PATH,
    PrivateTransportService,
    ensure_transport_certificate,
    owner_binding_hash,
    encode_application_payload,
)
from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.rpc import RpcContext
from qapp_backend.reticulum.server import QAppServer


class AttachedTransport:
    peer_address = ("127.0.0.1", 41000)

    def __init__(self):
        self.closed = False

    def close(self, _code, _reason):
        self.closed = True


def configured(config, **overrides):
    return replace(
        config,
        private_transport_cert_path=config.data_dir / "private-cert.pem",
        private_transport_key_path=config.data_dir / "private-key.pem",
        call_media_grants_path=config.data_dir / "call-media-grants",
        **overrides,
    )


def authenticated_server(config):
    server = QAppServer(configured(config))
    server.database.open()
    server.destination_hash = "ab" * 16
    server.private_transport.endpoint = "127.0.0.1:4444"
    server.private_transport.certificate_sha256 = "cd" * 32
    server.private_transport.media_endpoint = "127.0.0.1:4446"
    connection = PhysicalConnection(
        lambda _data: None,
        server.config,
        server._application_message,
        server._connection_closed,
        on_logical_close=server._logical_connection_closed,
    )
    server.connections[connection.id] = connection
    logical_id = "desktop-logical-connection"
    connection.logical_connection_ids.add(logical_id)
    session, _ = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = logical_id
    session.metadata["qapp_identity"] = ["qapp-ui-call", "APP"]
    server.sessions.promote(session, "Q-authenticated-user")
    server.logical_sessions[logical_id] = session
    context = RpcContext(
        server,
        BOOTSTRAP_PATH,
        connection=connection,
        session=session,
        logical_connection_id=logical_id,
    )
    return server, connection, session, context


def request(nonce="n" * 32, purpose="game"):
    return {
        "version": 1,
        "transport": "quic-masque-inner-v1",
        "nonce": nonce,
        "purpose": purpose,
    }


def attach_metadata(descriptor, **overrides):
    result = {
        "protocolVersion": 1,
        "logicalSessionId": descriptor["logicalSessionId"],
        "attachToken": descriptor["attachToken"],
        "nonce": descriptor["nonce"],
        "purpose": "game",
        "ownerBindingHash": descriptor["ownerBindingHash"],
    }
    result.update(overrides)
    return result


def test_authenticated_rpc_returns_session_bound_descriptor(config):
    server, _connection, session, context = authenticated_server(config)
    try:
        descriptor = server.private_transport.bootstrap(context, request())
        assert descriptor["logicalSessionId"] == session.session_id
        assert descriptor["backendRnsDestination"] == server.destination_hash
        assert descriptor["backendTransportEndpoint"] == "127.0.0.1:4444"
        assert descriptor["ownerBindingHash"] == owner_binding_hash(
            ("qapp-ui-call", "APP"),
            context.logical_connection_id,
            server.destination_hash,
            session.session_id,
            "n" * 32,
            "game",
        )
        assert descriptor["expiresAt"] > 0
        assert len(descriptor["attachToken"]) >= 43
    finally:
        server.database.close()


def test_realtime_bootstrap_requires_room_and_writes_one_time_media_grant(config):
    server, _connection, session, context = authenticated_server(config)
    try:
        rejected = server.private_transport.bootstrap(context, request(purpose="realtime"))
        assert rejected["error"]["code"] == "call_room_required"
        session.metadata["call_room_id"] = "proof-room"
        descriptor = server.private_transport.bootstrap(
            context, request("r" * 32, purpose="realtime")
        )
        assert descriptor["backendTransportEndpoint"] == "127.0.0.1:4446"
        assert descriptor["applicationProtocol"] == "moqt-18"
        assert descriptor["supportedFeatures"]["moqt"] is True
        digest = sha256(descriptor["attachToken"].encode("ascii")).hexdigest()
        grant_path = server.config.call_media_grants_path / f"{digest}.json"
        assert server.private_transport.tokens.outstanding(session.session_id) == 0
        grant = json.loads(grant_path.read_text("utf-8"))
        assert grant == {
            "authenticatedUser": "Q-authenticated-user",
            "expiresAt": descriptor["expiresAt"],
            "logicalSessionId": session.session_id,
            "participantId": "Q-authenticated-user",
            "purpose": "realtime",
            "qappName": "qapp-ui-call",
            "qappService": "APP",
            "roomId": "proof-room",
            "tokenSha256": digest,
            "version": 1,
        }
        server.private_transport.invalidate_session(session, close_attached=False)
        assert not grant_path.exists()
        revocation_digest = sha256(session.session_id.encode("utf-8")).hexdigest()
        revocation_path = (
            server.config.call_media_revocations_path / f"{revocation_digest}.json"
        )
        revocation = json.loads(revocation_path.read_text("utf-8"))
        assert revocation["logicalSessionId"] == session.session_id
        assert revocation["version"] == 1
        assert revocation["expiresAt"] > int(time.time() * 1000)
    finally:
        server.database.close()


def test_registered_rns_callback_resolves_the_session_on_the_same_link(config):
    server, connection, session, context = authenticated_server(config)
    link_id = b"authenticated-link"
    server._links[link_id] = connection
    payload = request()
    envelope = {
        "version": 1,
        "requestId": "bootstrap-request",
        "encoding": "json",
        "payloadBase64": base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii"),
        "logicalConnectionId": context.logical_connection_id,
    }
    try:
        response = server._make_rpc_callback(BOOTSTRAP_PATH)(
            BOOTSTRAP_PATH, envelope, b"request", link_id, object(), 0
        )
        assert response["logicalSessionId"] == session.session_id
        assert response["backendRnsDestination"] == server.destination_hash
    finally:
        server.database.close()


def test_unauthenticated_wrong_connection_and_untrusted_fields_are_rejected(config):
    server, connection, session, context = authenticated_server(config)
    try:
        session.provisional = True
        assert server.private_transport.bootstrap(context, request())["error"]["code"] == "unauthenticated"
        session.provisional = False
        connection.logical_connection_ids.clear()
        assert server.private_transport.bootstrap(context, request())["error"]["code"] == "unauthenticated"
        connection.logical_connection_ids.add(context.logical_connection_id)
        assert server.private_transport.bootstrap(
            context, {**request(), "backendTransportEndpoint": "203.0.113.1:9"}
        )["error"]["code"] == "invalid_request"
    finally:
        server.database.close()


def test_attach_succeeds_once_and_quic_disconnect_preserves_logical_session(config):
    server, _connection, session, context = authenticated_server(config)
    try:
        descriptor = server.private_transport.bootstrap(context, request())
        transport = AttachedTransport()
        assert server.private_transport.attach(
            transport, attach_metadata(descriptor)
        ) is session
        assert session.private_transport is transport
        with pytest.raises(AttachRejected):
            server.private_transport.attach(
                AttachedTransport(), attach_metadata(descriptor)
            )
        server.private_transport.detach(session, transport)
        assert session.private_transport is None
        assert server.logical_sessions[context.logical_connection_id] is session
        assert session.connection is context.connection
    finally:
        server.database.close()


def test_rns_session_close_invalidates_token_and_attached_transport(config):
    server, connection, session, context = authenticated_server(config)
    try:
        outstanding = server.private_transport.bootstrap(context, request("a" * 32))
        attached = server.private_transport.bootstrap(context, request("b" * 32))
        transport = AttachedTransport()
        server.private_transport.attach(transport, attach_metadata(attached))
        server._disconnect_logical_session(connection, context.logical_connection_id)
        assert transport.closed
        assert server.private_transport.tokens.outstanding(session.session_id) == 0
        with pytest.raises(AttachRejected):
            server.private_transport.attach(
                AttachedTransport(), attach_metadata(outstanding)
            )
    finally:
        server.database.close()


def test_wrong_qapp_or_purpose_cannot_attach(config):
    server, _connection, session, context = authenticated_server(config)
    try:
        wrong_app = server.private_transport.bootstrap(context, request("a" * 32))
        session.metadata["qapp_identity"] = ["other-app", "APP"]
        with pytest.raises(AttachRejected):
            server.private_transport.attach(
                AttachedTransport(), attach_metadata(wrong_app)
            )
        session.metadata["qapp_identity"] = ["qapp-ui-call", "APP"]
        wrong_purpose = server.private_transport.bootstrap(context, request("b" * 32))
        with pytest.raises(AttachRejected):
            server.private_transport.attach(
                AttachedTransport(),
                attach_metadata(wrong_purpose, purpose="realtime"),
            )
    finally:
        server.database.close()


def test_business_messages_are_not_migrated_to_quic_in_step_four(config):
    server, _connection, session, context = authenticated_server(config)
    try:
        descriptor = server.private_transport.bootstrap(context, request())
        transport = AttachedTransport()
        server.private_transport.attach(transport, attach_metadata(descriptor))
        with pytest.raises(ValueError, match="unsupported"):
            server.private_transport.handle_application_message(
                transport,
                session,
                "reliable",
                "business-message",
                encode_application_payload({"type": "BUSINESS_MUTATION"}),
            )
    finally:
        server.database.close()


def test_development_certificate_pin_matches_leaf_and_listener(config):
    configured_value = configured(config)
    configured_value.ensure_directories()
    certificate = ensure_transport_certificate(configured_value)
    expected = sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    server = QAppServer(configured_value)
    server.database.open()
    server.destination_hash = "ab" * 16
    try:
        server.private_transport.start()
        assert server.private_transport.certificate_sha256 == expected
        assert server.private_transport.endpoint.startswith("127.0.0.1:")
        assert configured_value.private_transport_key_path.stat().st_mode & 0o777 == 0o600
    finally:
        server.private_transport.stop()
        server.database.close()
