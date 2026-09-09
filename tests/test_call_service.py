from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from qapp_backend.call.service import CallService, MAX_CALL_SECONDS


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


INVITE_TOKEN = bytes(range(32))


class FakeSessions:
    def __init__(self) -> None:
        self.persisted: list[Any] = []

    def persist(self, session: Any) -> None:
        self.persisted.append(session)


class FakeServer:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.disconnect_handlers: list[Any] = []
        self.sessions = FakeSessions()

    def on_message(self, message_type: str):
        def register(handler: Any) -> Any:
            self.handlers[message_type] = handler
            return handler

        return register

    def on_session_disconnect(self, handler: Any) -> Any:
        self.disconnect_handlers.append(handler)
        return handler


class FakeSession:
    def __init__(self, session_id: str, participant_id: str) -> None:
        self.session_id = session_id
        self.authenticated_user = participant_id
        self.provisional = False
        self.metadata: dict[str, Any] = {}
        self.sent: list[dict[str, Any]] = []

    def send(self, payload: dict[str, Any]) -> None:
        self.sent.append(payload)


def public_keys(seed: int) -> dict[str, str]:
    agreement_key = ec.derive_private_key(seed, ec.SECP256R1()).public_key()
    agreement_bytes = agreement_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return {
        "keyAgreementPublicKey": b64url(agreement_bytes),
        "signingPublicKey": b64url(bytes([seed]) * 32),
    }


def create_message(room: str = "room-123", seed: int = 1) -> dict[str, Any]:
    return {
        "type": "call_create",
        "requestId": f"request-{seed:04d}",
        "roomId": room,
        "inviteTokenHash": b64url(hashlib.sha256(INVITE_TOKEN).digest()),
        **public_keys(seed),
    }


def join_message(room: str = "room-123", seed: int = 2) -> dict[str, Any]:
    return {
        "type": "call_join",
        "requestId": f"request-{seed:04d}",
        "roomId": room,
        "inviteToken": b64url(INVITE_TOKEN),
        **public_keys(seed),
    }


def context(session: FakeSession) -> Any:
    return SimpleNamespace(session=session)


def create_room(server: FakeServer, alice: FakeSession) -> None:
    server.handlers["call_create"](context(alice), create_message())


def test_create_and_invited_join_bind_authenticated_membership() -> None:
    server = FakeServer()
    CallService(server)
    alice = FakeSession("session-alice", "QAlice123")
    bob = FakeSession("session-bob", "QBob456")

    create_room(server, alice)
    created = alice.sent[-1]
    assert created["type"] == "call_created"
    assert created["initiatorParticipantId"] == "QAlice123"
    assert created["revision"] == 1
    assert 0 < created["expiresAt"]

    server.handlers["call_join"](context(bob), join_message())
    joined = bob.sent[-2]
    membership = bob.sent[-1]
    assert joined["type"] == "call_joined"
    assert joined["revision"] == 2
    assert joined["expiresAt"] - created["expiresAt"] == 0
    assert membership["type"] == "call_membership"
    assert [member["participantId"] for member in membership["members"]] == [
        "QAlice123",
        "QBob456",
    ]
    assert alice.metadata["call_room_id"] == "room-123"
    assert bob.metadata["call_room_id"] == "room-123"


def test_join_requires_the_invitation_secret() -> None:
    server = FakeServer()
    CallService(server)
    alice = FakeSession("session-alice", "QAlice123")
    bob = FakeSession("session-bob", "QBob456")
    create_room(server, alice)
    invalid = join_message()
    invalid["inviteToken"] = b64url(bytes(reversed(INVITE_TOKEN)))

    with pytest.raises(ValueError, match="invalid call invitation"):
        server.handlers["call_join"](context(bob), invalid)


def test_only_initiator_can_deliver_bounded_opaque_group_key() -> None:
    server = FakeServer()
    CallService(server)
    alice = FakeSession("session-alice", "QAlice123")
    bob = FakeSession("session-bob", "QBob456")
    create_room(server, alice)
    server.handlers["call_join"](context(bob), join_message())
    bob.sent.clear()
    envelope = {
        "type": "call_group_key",
        "requestId": "envelope-0001",
        "roomId": "room-123",
        "targetParticipantId": "QBob456",
        "keyId": "ab" * 16,
        "nonce": b64url(bytes(12)),
        "ciphertext": b64url(bytes(range(48))),
        "signature": b64url(bytes(64)),
    }

    server.handlers["call_group_key"](context(alice), envelope)
    assert bob.sent == [{**envelope, "senderParticipantId": "QAlice123"}]

    with pytest.raises(ValueError, match="not authorized"):
        server.handlers["call_group_key"](
            context(bob), {**envelope, "targetParticipantId": "QAlice123"}
        )
    with pytest.raises(ValueError, match="ciphertext"):
        server.handlers["call_group_key"](
            context(alice), {**envelope, "ciphertext": b64url(bytes(47))}
        )


def test_participant_leave_keeps_call_but_initiator_leave_ends_it() -> None:
    server = FakeServer()
    service = CallService(server)
    alice = FakeSession("session-alice", "QAlice123")
    bob = FakeSession("session-bob", "QBob456")
    create_room(server, alice)
    server.handlers["call_join"](context(bob), join_message())
    alice.sent.clear()

    server.handlers["call_leave"](
        context(bob),
        {"type": "call_leave", "requestId": "leave-0001", "roomId": "room-123"},
    )
    assert alice.sent[-1]["type"] == "call_membership"
    assert "room-123" in service._rooms

    server.handlers["call_join"](context(bob), join_message())
    bob.sent.clear()
    server.handlers["call_leave"](
        context(alice),
        {"type": "call_leave", "requestId": "leave-0002", "roomId": "room-123"},
    )
    assert bob.sent[-1] == {
        "type": "call_ended",
        "roomId": "room-123",
        "reason": "INITIATOR_LEFT",
    }
    assert "room-123" not in service._rooms
    assert "call_room_id" not in bob.metadata


def test_initiator_disconnect_ends_call_and_expiry_is_three_hours() -> None:
    server = FakeServer()
    service = CallService(server)
    alice = FakeSession("session-alice", "QAlice123")
    bob = FakeSession("session-bob", "QBob456")
    create_room(server, alice)
    server.handlers["call_join"](context(bob), join_message())
    room = service._rooms["room-123"]
    assert room.expires_at_ms - int(__import__("time").time() * 1000) <= MAX_CALL_SECONDS * 1000
    bob.sent.clear()

    server.disconnect_handlers[0](alice)
    assert bob.sent[-1]["reason"] == "INITIATOR_DISCONNECTED"
    assert "room-123" not in service._rooms


def test_create_rejects_unauthenticated_and_malformed_public_keys() -> None:
    server = FakeServer()
    CallService(server)
    unauthenticated = FakeSession("session-none", "")
    with pytest.raises(ValueError, match="authenticated"):
        server.handlers["call_create"](
            context(unauthenticated), create_message(seed=1)
        )
    alice = FakeSession("session-alice", "QAlice123")
    malformed = create_message(seed=1)
    malformed["signingPublicKey"] = b64url(bytes(31))
    with pytest.raises(ValueError, match="key length"):
        server.handlers["call_create"](context(alice), malformed)
