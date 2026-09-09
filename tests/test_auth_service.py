from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qapp_backend.auth import install_authentication_service
from qapp_backend.auth.group_access import GroupAccessDenied, GroupAccessUnavailable
from qapp_backend.auth.service import ACCESS_CHECKED_AT, ACCESS_POLICY_REVISION
from qapp_backend.auth.qortal_identity import (
    base58_encode,
    canonical_proof,
    qortal_address,
)
from qapp_backend.private_transport.service import BOOTSTRAP_PATH
from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.realtime import MessageContext
from qapp_backend.reticulum.rpc import RpcContext
from qapp_backend.reticulum.server import QAppServer


def signed_proof(challenge):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fields = {
        **challenge,
        "address": qortal_address(public_key),
        "publicKey": base58_encode(public_key),
        "qappName": "qapp-ui-call",
        "qappService": "APP",
    }
    return {
        **fields,
        "signature": base58_encode(private_key.sign(canonical_proof(fields))),
    }


def test_signed_identity_promotes_the_same_application_session(config):
    server = QAppServer(config)
    service = install_authentication_service(server)
    server.database.open()
    server.destination_hash = "ab" * 16
    connection = PhysicalConnection(lambda _data: None, config, server._application_message)
    logical_id = "authenticated-logical-session"
    connection.logical_connection_ids.add(logical_id)
    session, _token = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = logical_id
    server.logical_sessions[logical_id] = session
    context = MessageContext(server, connection, session, 1, logical_id)
    try:
        challenge = service.challenge(
            RpcContext(
                server,
                "/auth/challenge",
                connection=connection,
                session=session,
                logical_connection_id=logical_id,
            ),
            {},
        )
        proof = signed_proof(challenge)
        service.authenticate(
            context,
            {
                "type": "AUTHENTICATE",
                "requestId": "auth-1",
                "payload": {"proof": proof},
            },
        )
        assert not session.provisional
        assert session.authenticated_user == proof["address"]
        assert session.metadata["qapp_identity"] == ["qapp-ui-call", "APP"]
        assert server.logical_sessions[logical_id] is session
    finally:
        server.database.close()


def test_invalid_identity_does_not_promote_session(config):
    server = QAppServer(config)
    service = install_authentication_service(server)
    server.database.open()
    connection = PhysicalConnection(lambda _data: None, config, server._application_message)
    session, _token = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = "logical"
    context = MessageContext(server, connection, session, 1, "logical")
    try:
        service.authenticate(
            context,
            {
                "type": "AUTHENTICATE",
                "requestId": "auth-2",
                "payload": {"proof": {}},
            },
        )
        assert session.provisional
        assert session.authenticated_user is None
    finally:
        server.database.close()


def test_private_bootstrap_uses_the_newly_authenticated_session(config):
    server = QAppServer(config)
    service = install_authentication_service(server)
    server.database.open()
    server.destination_hash = "cd" * 16
    server.private_transport.endpoint = "127.0.0.1:4445"
    server.private_transport.certificate_sha256 = "ef" * 32
    connection = PhysicalConnection(
        lambda _data: None, config, server._application_message
    )
    logical_id = "private-authenticated-session"
    connection.logical_connection_ids.add(logical_id)
    session, _token = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = logical_id
    server.logical_sessions[logical_id] = session
    message_context = MessageContext(server, connection, session, 1, logical_id)
    try:
        challenge = service.challenge(
            RpcContext(server, "/auth/challenge"), {}
        )
        service.authenticate(
            message_context,
            {
                "type": "AUTHENTICATE",
                "requestId": "auth-private",
                "payload": {"proof": signed_proof(challenge)},
            },
        )
        session.metadata["call_room_id"] = "test-room"
        server.private_transport.media_endpoint = "127.0.0.1:4446"
        descriptor = server.private_transport.bootstrap(
            RpcContext(
                server,
                BOOTSTRAP_PATH,
                connection=connection,
                session=session,
                logical_connection_id=logical_id,
            ),
            {
                "version": 1,
                "transport": "quic-masque-inner-v1",
                "nonce": "n" * 32,
                "purpose": "realtime",
            },
        )
        assert descriptor["logicalSessionId"] == session.session_id
    finally:
        server.database.close()


def test_group_member_is_checked_before_session_promotion(config):
    restricted = replace(
        config,
        access_mode="groups",
        allowed_group_ids=(1144,),
        core_url_bases=("https://core.example",),
    )
    server = QAppServer(restricted)
    service = install_authentication_service(server)
    checked = []

    class Allow:
        revision = "policy-revision"

        def authorize(self, address, now=None):
            checked.append(address)
            return 1234.0

    service.access = Allow()
    server.database.open()
    server.destination_hash = "ef" * 16
    connection = PhysicalConnection(lambda _data: None, restricted, server._application_message)
    session, _token = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = "logical"
    context = MessageContext(server, connection, session, 1, "logical")
    try:
        challenge = service.challenge(RpcContext(server, "/auth/challenge"), {})
        proof = signed_proof(challenge)
        service.authenticate(context, {
            "type": "AUTHENTICATE", "requestId": "auth-groups",
            "payload": {"proof": proof},
        })
        assert checked == [proof["address"]]
        assert session.authenticated_user == proof["address"]
        assert session.metadata[ACCESS_CHECKED_AT] == 1234.0
        assert session.metadata[ACCESS_POLICY_REVISION] == "policy-revision"
    finally:
        service.shutdown()
        server.database.close()


def test_non_member_is_not_promoted(config):
    restricted = replace(
        config,
        access_mode="groups",
        allowed_group_ids=(1144,),
        core_url_bases=("https://core.example",),
    )
    server = QAppServer(restricted)
    service = install_authentication_service(server)

    class Deny:
        revision = "policy-revision"

        def authorize(self, _address, now=None):
            raise GroupAccessDenied("not a member")

    service.access = Deny()
    server.database.open()
    server.destination_hash = "12" * 16
    connection = PhysicalConnection(lambda _data: None, restricted, server._application_message)
    session, _token = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = "logical"
    context = MessageContext(server, connection, session, 1, "logical")
    try:
        challenge = service.challenge(RpcContext(server, "/auth/challenge"), {})
        service.authenticate(context, {
            "type": "AUTHENTICATE", "requestId": "auth-denied",
            "payload": {"proof": signed_proof(challenge)},
        })
        assert session.provisional
        assert session.authenticated_user is None
    finally:
        service.shutdown()
        server.database.close()


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (GroupAccessDenied("not a member"), "BACKEND_ACCESS_DENIED"),
        (GroupAccessUnavailable("offline"), "BACKEND_ACCESS_UNAVAILABLE"),
    ],
)
def test_group_access_failure_has_an_actionable_authentication_code(
    config, failure, expected_code
):
    restricted = replace(
        config,
        access_mode="groups",
        allowed_group_ids=(1144,),
        core_url_bases=("https://core.example",),
    )
    server = QAppServer(restricted)
    service = install_authentication_service(server)
    sent = []
    session = SimpleNamespace(metadata={}, send=sent.append)
    context = SimpleNamespace(session=session)

    class Verifier:
        def verify(self, _proof):
            return "Qaddress", "public-key", ("qapp-ui-call", "APP")

    class FailingAccess:
        revision = "policy-revision"

        def authorize(self, _address, now=None):
            raise failure

    service.verifier = Verifier()
    service.access = FailingAccess()
    try:
        service.authenticate(context, {
            "type": "AUTHENTICATE", "requestId": "auth-failure",
            "payload": {"proof": {}},
        })
    finally:
        service.shutdown()
    assert sent == [{
        "type": "AUTHENTICATION_ERROR",
        "requestId": "auth-failure",
        "payload": {"code": expected_code},
    }]
