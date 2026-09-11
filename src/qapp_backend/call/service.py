from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec


MAX_ROOMS = 1_024
MAX_PARTICIPANTS_PER_ROOM = 32
MAX_CALL_SECONDS = 3 * 60 * 60
SCREEN_LEASE_SECONDS = 45
GROUP_KEY_ENVELOPE_CIPHERTEXT_BYTES = 48

_ROOM_ID = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
_PARTICIPANT_ID = re.compile(r"^[A-Za-z0-9_-]{3,128}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_KEY_ID = re.compile(r"^[a-f0-9]{32}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def _decode_base64url(value: Any, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ValueError("invalid base64url value")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value.rstrip("=") + padding)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid base64url value") from error
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("invalid key length")
    return decoded


def _require_authenticated(session: Any) -> str:
    if (
        session is None
        or session.provisional
        or not isinstance(session.authenticated_user, str)
        or not session.authenticated_user
    ):
        raise ValueError("authenticated session required")
    return session.authenticated_user


def _validate_public_keys(agreement_key: Any, signing_key: Any) -> None:
    agreement_bytes = _decode_base64url(agreement_key, 65)
    if agreement_bytes[0] != 4:
        raise ValueError("invalid P-256 public key")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), agreement_bytes
        )
    except ValueError as error:
        raise ValueError("invalid P-256 public key") from error
    _decode_base64url(signing_key, 32)


@dataclass(frozen=True, slots=True)
class Member:
    participant_id: str
    key_agreement_public_key: str
    signing_public_key: str
    session: Any = field(compare=False, repr=False)

    def public_value(self, room_id: str) -> dict[str, Any]:
        return {
            "participantId": self.participant_id,
            "keyAgreementPublicKey": self.key_agreement_public_key,
            "signingPublicKey": self.signing_public_key,
            "track": {
                "namespace": ["qortal", "call", room_id, self.participant_id],
                "name": "audio",
            },
        }


@dataclass(slots=True)
class Room:
    room_id: str
    initiator_id: str
    invite_token_hash: bytes = field(repr=False)
    expires_at_ms: int
    revision: int = 1
    members: dict[str, Member] = field(default_factory=dict)
    expiry_timer: threading.Timer | None = field(default=None, repr=False)
    screen_owner: str = ""
    screen_id: str = ""
    screen_revision: int = 1
    screen_expires_at: float = 0
    screen_timer: threading.Timer | None = field(default=None, repr=False)
    blocked: set[str] = field(default_factory=set)
    muted: set[str] = field(default_factory=set)


class CallService:
    """Short-lived initiator-owned call membership and opaque key delivery."""

    def __init__(self, server: Any):
        self.server = server
        self._rooms: dict[str, Room] = {}
        self._session_rooms: dict[str, str] = {}
        self._lock = threading.RLock()
        # Rooms are in-memory. A restarted backend must not leave old media
        # sessions authorized by policy files from its previous process.
        config = getattr(server, "config", None)
        directory = getattr(config, "call_media_revocations_path", None)
        if directory is not None:
            policies = Path(directory) / "rooms"
            if policies.exists():
                for path in policies.iterdir():
                    if re.fullmatch(r"[a-f0-9]{64}\.json", path.name):
                        path.unlink(missing_ok=True)
        server.on_message("call_create")(self.create)
        server.on_message("call_join")(self.join)
        server.on_message("call_leave")(self.leave)
        server.on_message("call_group_key")(self.forward_group_key)
        server.on_message("call_moderate")(self.moderate)
        for kind in ("call_screen_start", "call_screen_stop", "call_screen_renew"):
            server.on_message(kind)(self.screen_control)
        server.on_session_disconnect(self.disconnected)

    def create(self, ctx: Any, message: Any) -> None:
        initiator_id = _require_authenticated(ctx.session)
        if not _PARTICIPANT_ID.fullmatch(initiator_id):
            raise ValueError("invalid authenticated participant")
        if not isinstance(message, dict) or set(message) != {
            "type",
            "requestId",
            "roomId",
            "inviteTokenHash",
            "keyAgreementPublicKey",
            "signingPublicKey",
        }:
            raise ValueError("invalid call_create message")
        request_id = self._request_id(message)
        room_id = self._room_id(message)
        invite_token_hash = _decode_base64url(message.get("inviteTokenHash"), 32)
        agreement_key = message.get("keyAgreementPublicKey")
        signing_key = message.get("signingPublicKey")
        _validate_public_keys(agreement_key, signing_key)

        with self._lock:
            if self._session_rooms.get(ctx.session.session_id) is not None:
                raise ValueError("leave the current call before creating another")
            if room_id in self._rooms:
                raise ValueError("call room already exists")
            if len(self._rooms) >= MAX_ROOMS:
                raise ValueError("call room capacity reached")
            expires_at_ms = int(time.time() * 1000) + MAX_CALL_SECONDS * 1000
            member = Member(initiator_id, agreement_key, signing_key, ctx.session)
            room = Room(room_id, initiator_id, invite_token_hash, expires_at_ms)
            room.members[initiator_id] = member
            timer = threading.Timer(MAX_CALL_SECONDS, self._expire_room, (room_id,))
            timer.daemon = True
            room.expiry_timer = timer
            self._rooms[room_id] = room
            self._bind_session(ctx.session, room_id)
            try:
                self._write_policy(room)
            except OSError:
                self._rooms.pop(room_id, None)
                self._session_rooms.pop(ctx.session.session_id, None)
                self._clear_session_metadata(ctx.session)
                raise
            snapshot = self._snapshot(room)
            timer.start()

        self._safe_send(
            ctx.session,
            {"type": "call_created", "requestId": request_id, **snapshot},
        )

    def join(self, ctx: Any, message: Any) -> None:
        participant_id = _require_authenticated(ctx.session)
        if not _PARTICIPANT_ID.fullmatch(participant_id):
            raise ValueError("invalid authenticated participant")
        if not isinstance(message, dict) or set(message) != {
            "type",
            "requestId",
            "roomId",
            "inviteToken",
            "keyAgreementPublicKey",
            "signingPublicKey",
        }:
            raise ValueError("invalid call_join message")
        request_id = self._request_id(message)
        room_id = self._room_id(message)
        invite_token = _decode_base64url(message.get("inviteToken"), 32)
        agreement_key = message.get("keyAgreementPublicKey")
        signing_key = message.get("signingPublicKey")
        _validate_public_keys(agreement_key, signing_key)

        with self._lock:
            previous_room_id = self._session_rooms.get(ctx.session.session_id)
            if previous_room_id is not None and previous_room_id != room_id:
                raise ValueError("leave the current call before joining another")
            room = self._rooms.get(room_id)
            if room is None or room.expires_at_ms <= int(time.time() * 1000):
                raise ValueError("call room is unavailable")
            if not hmac.compare_digest(
                hashlib.sha256(invite_token).digest(), room.invite_token_hash
            ):
                raise ValueError("invalid call invitation")
            if participant_id in room.blocked:
                self._safe_send(ctx.session, {"type": "call_removed", "roomId": room_id})
                return
            existing = room.members.get(participant_id)
            if existing is not None and existing.session is not ctx.session:
                raise ValueError("participant is already active")
            member = Member(participant_id, agreement_key, signing_key, ctx.session)
            changed = existing != member
            room.members[participant_id] = member
            if changed and existing is None and len(room.members) > MAX_PARTICIPANTS_PER_ROOM:
                del room.members[participant_id]
                raise ValueError("call participant capacity reached")
            self._bind_session(ctx.session, room_id)
            if changed:
                room.revision += 1
            self._write_policy(room)
            snapshot = self._snapshot(room)
            recipients = tuple(member.session for member in room.members.values())

        self._safe_send(
            ctx.session,
            {"type": "call_joined", "requestId": request_id, **snapshot},
        )
        if changed:
            self._broadcast(recipients, {"type": "call_membership", **snapshot})

    def leave(self, ctx: Any, message: Any) -> None:
        participant_id = _require_authenticated(ctx.session)
        if not isinstance(message, dict) or set(message) != {
            "type",
            "requestId",
            "roomId",
        }:
            raise ValueError("invalid call_leave message")
        request_id = self._request_id(message)
        room_id = self._room_id(message)
        with self._lock:
            if self._session_rooms.get(ctx.session.session_id) != room_id:
                raise ValueError("session is not in the call room")
            room = self._rooms.get(room_id)
            if room is None:
                raise ValueError("call room is unavailable")
            if participant_id == room.initiator_id:
                recipients = self._end_room_locked(room)
                update = None
            else:
                recipients = ()
                update = self._remove_member_locked(ctx.session, room)
            self._clear_session_metadata(ctx.session)

        self._safe_send(
            ctx.session,
            {"type": "call_left", "requestId": request_id, "roomId": room_id},
        )
        if recipients:
            self._broadcast(
                recipients,
                {"type": "call_ended", "roomId": room_id, "reason": "INITIATOR_LEFT"},
            )
        elif update is not None:
            remaining, snapshot = update
            self._broadcast(remaining, {"type": "call_membership", **snapshot})

    def forward_group_key(self, ctx: Any, message: Any) -> None:
        sender_id = _require_authenticated(ctx.session)
        if not isinstance(message, dict) or set(message) != {
            "type",
            "requestId",
            "roomId",
            "targetParticipantId",
            "keyId",
            "nonce",
            "ciphertext",
            "signature",
        }:
            raise ValueError("invalid call_group_key message")
        request_id = self._request_id(message)
        room_id = self._room_id(message)
        target_id = message.get("targetParticipantId")
        key_id = message.get("keyId")
        if (
            not isinstance(target_id, str)
            or not _PARTICIPANT_ID.fullmatch(target_id)
            or target_id == sender_id
            or not isinstance(key_id, str)
            or not _KEY_ID.fullmatch(key_id)
        ):
            raise ValueError("invalid group key metadata")
        _decode_base64url(message.get("nonce"), 12)
        ciphertext = _decode_base64url(message.get("ciphertext"))
        if len(ciphertext) != GROUP_KEY_ENVELOPE_CIPHERTEXT_BYTES:
            raise ValueError("invalid group key ciphertext")
        _decode_base64url(message.get("signature"), 64)

        with self._lock:
            room = self._rooms.get(room_id)
            target = room.members.get(target_id) if room is not None else None
            sender = room.members.get(sender_id) if room is not None else None
            if (
                room is None
                or sender_id != room.initiator_id
                or sender is None
                or sender.session is not ctx.session
                or target is None
            ):
                raise ValueError("group key delivery is not authorized")
            target_session = target.session

        self._safe_send(
            target_session,
            {
                "type": "call_group_key",
                "requestId": request_id,
                "roomId": room_id,
                "senderParticipantId": sender_id,
                "targetParticipantId": target_id,
                "keyId": key_id,
                "nonce": message["nonce"],
                "ciphertext": message["ciphertext"],
                "signature": message["signature"],
            },
        )

    def moderate(self, ctx: Any, message: Any) -> None:
        actor = _require_authenticated(ctx.session)
        if not isinstance(message, dict) or set(message) != {
            "type", "requestId", "roomId", "targetParticipantId", "operation"
        }:
            raise ValueError("invalid moderation request")
        request_id = self._request_id(message)
        room_id = self._room_id(message)
        target = message.get("targetParticipantId")
        operation = message.get("operation")
        if not isinstance(target, str) or not _PARTICIPANT_ID.fullmatch(target) or operation not in {"mute", "allow_mic", "remove", "readmit"}:
            raise ValueError("invalid moderation operation")
        with self._lock:
            room = self._rooms.get(room_id)
            host = room.members.get(actor) if room else None
            if room is None or actor != room.initiator_id or host is None or host.session is not ctx.session or room.expires_at_ms <= int(time.time() * 1000):
                raise ValueError("only the active call creator can moderate")
            if target == actor:
                raise ValueError("cannot moderate the call creator")
            if operation in {"mute", "allow_mic", "remove"} and target not in room.members and not (operation == "remove" and target in room.blocked):
                self._safe_send(ctx.session, {"type": "call_moderation_result", "requestId": request_id,
                    "roomId": room_id, "revision": room.revision, "accepted": False,
                    "code": "PARTICIPANT_LEFT", "blockedParticipantIds": sorted(room.blocked)})
                return
            removed = None
            if operation == "readmit":
                room.blocked.discard(target)
            elif operation == "remove":
                if target not in room.members and target not in room.blocked:
                    raise ValueError("participant is not in this call")
                if len(room.blocked) >= 256 and target not in room.blocked:
                    raise ValueError("removed participant limit reached")
                room.blocked.add(target)
                removed = room.members.get(target)
                if removed:
                    self._remove_member_locked(removed.session, room)
                    self._clear_session_metadata(removed.session)
                room.muted.discard(target)
            else:
                if target not in room.members:
                    raise ValueError("participant is not in this call")
                if operation == "mute":
                    if len(room.muted) >= 256 and target not in room.muted:
                        raise ValueError("muted participant limit reached")
                    room.muted.add(target)
                else:
                    room.muted.discard(target)
            room.revision += 1
            self._write_policy(room)
            snapshot = self._snapshot(room)
            recipients = tuple(member.session for member in room.members.values())
            # The removed-account list is sent only to the authenticated creator.
            result = {"type": "call_moderation_result", "requestId": request_id,
                      "roomId": room_id, "revision": room.revision,
                      "accepted": True, "code": "",
                      "blockedParticipantIds": sorted(room.blocked)}
        if removed:
            self._safe_send(removed.session, {"type": "call_removed", "roomId": room_id})
        self._broadcast(recipients, {"type": "call_membership", **snapshot})
        self._safe_send(ctx.session, result)

    def _policy_path(self, room_id: str) -> Path | None:
        config = getattr(self.server, "config", None)
        directory = getattr(config, "call_media_revocations_path", None)
        if directory is None:
            return None  # In-memory test servers have no media sidecar.
        return Path(directory) / "rooms" / (hashlib.sha256(room_id.encode()).hexdigest() + ".json")

    def _write_policy(self, room: Room) -> None:
        path = self._policy_path(room.room_id)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        try:
            with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
                json.dump({"roomId": room.room_id, "expiresAt": room.expires_at_ms,
                           "members": {key: value.session.session_id for key, value in room.members.items()},
                           "muted": sorted(room.muted.intersection(room.members))}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError:
            # Never leave an older, more permissive policy after a failed update.
            path.unlink(missing_ok=True)
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def disconnected(self, session: Any) -> None:
        with self._lock:
            room_id = self._session_rooms.get(session.session_id)
            room = self._rooms.get(room_id) if room_id is not None else None
            if room is None:
                return
            participant_id = getattr(session, "authenticated_user", None)
            if participant_id == room.initiator_id:
                recipients = self._end_room_locked(room)
                update = None
            else:
                recipients = ()
                update = self._remove_member_locked(session, room)
            self._clear_session_metadata(session)
        if recipients:
            self._broadcast(
                recipients,
                {
                    "type": "call_ended",
                    "roomId": room.room_id,
                    "reason": "INITIATOR_DISCONNECTED",
                },
            )
        elif update is not None:
            remaining, snapshot = update
            self._broadcast(remaining, {"type": "call_membership", **snapshot})

    def screen_control(self, ctx: Any, message: Any) -> None:
        participant_id = _require_authenticated(ctx.session)
        if not isinstance(message, dict) or set(message) != {
            "type", "requestId", "roomId", "shareId"
        } or message.get("type") not in {
            "call_screen_start", "call_screen_stop", "call_screen_renew"
        }:
            raise ValueError("invalid screen control message")
        request_id = self._request_id(message)
        room_id = self._room_id(message)
        share_id = message.get("shareId")
        if not isinstance(share_id, str) or not _REQUEST_ID.fullmatch(share_id):
            raise ValueError("invalid screen share id")
        with self._lock:
            room = self._rooms.get(room_id)
            member = room.members.get(participant_id) if room else None
            if room is None or member is None or member.session is not ctx.session or room.expires_at_ms <= int(time.time() * 1000):
                raise ValueError("screen sharing requires active call membership")
            previous_revision = room.screen_revision
            if room.screen_id and room.screen_expires_at <= time.monotonic():
                self._clear_screen_locked(room)
            owns = room.screen_owner == participant_id and room.screen_id == share_id
            accepted = False
            code = "SCREEN_NOT_OWNER"
            if message["type"] == "call_screen_start":
                accepted = not room.screen_id or owns
                code = "" if accepted else "SCREEN_BUSY"
                if accepted and not owns:
                    room.screen_owner = participant_id
                    room.screen_id = share_id
                    room.screen_revision += 1
            elif message["type"] == "call_screen_stop":
                accepted = owns or not room.screen_id
                code = "" if accepted else "SCREEN_NOT_OWNER"
                if owns:
                    self._clear_screen_locked(room)
            else:
                accepted = owns
                code = "" if accepted else "SCREEN_NOT_OWNER"
            if accepted and message["type"] != "call_screen_stop":
                if room.screen_timer:
                    room.screen_timer.cancel()
                room.screen_expires_at = time.monotonic() + SCREEN_LEASE_SECONDS
                timer = threading.Timer(SCREEN_LEASE_SECONDS, self._expire_screen, (room_id, share_id))
                timer.daemon = True
                room.screen_timer = timer
                timer.start()
            state = self._screen_snapshot(room)
            recipients = tuple(value.session for value in room.members.values())
            changed = room.screen_revision != previous_revision
        self._safe_send(ctx.session, {
            "type": "call_screen_result", "requestId": request_id,
            "roomId": room_id, "accepted": accepted, "code": code,
            "screenShare": state,
        })
        if changed:
            self._broadcast(recipients, {"type": "call_screen_state", "roomId": room_id, "screenShare": state})

    def _expire_screen(self, room_id: str, share_id: str) -> None:
        with self._lock:
            room = self._rooms.get(room_id)
            if room is None or room.screen_id != share_id or room.screen_expires_at > time.monotonic():
                return
            self._clear_screen_locked(room)
            state = self._screen_snapshot(room)
            recipients = tuple(value.session for value in room.members.values())
        self._broadcast(recipients, {"type": "call_screen_state", "roomId": room_id, "screenShare": state})

    @staticmethod
    def _clear_screen_locked(room: Room) -> None:
        if room.screen_timer:
            room.screen_timer.cancel()
        room.screen_timer = None
        room.screen_owner = ""
        room.screen_id = ""
        room.screen_expires_at = 0
        room.screen_revision += 1

    @staticmethod
    def _screen_snapshot(room: Room) -> dict[str, Any]:
        return {"revision": room.screen_revision, "participantId": room.screen_owner, "shareId": room.screen_id}

    def _expire_room(self, room_id: str) -> None:
        with self._lock:
            room = self._rooms.get(room_id)
            if room is None:
                return
            recipients = self._end_room_locked(room)
        self._broadcast(
            recipients,
            {"type": "call_ended", "roomId": room_id, "reason": "EXPIRED"},
        )

    @staticmethod
    def _request_id(message: dict[str, Any]) -> str:
        value = message.get("requestId")
        if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
            raise ValueError("invalid requestId")
        return value

    @staticmethod
    def _room_id(message: dict[str, Any]) -> str:
        value = message.get("roomId")
        if not isinstance(value, str) or not _ROOM_ID.fullmatch(value):
            raise ValueError("invalid roomId")
        return value

    @staticmethod
    def _snapshot(room: Room) -> dict[str, Any]:
        return {
            "roomId": room.room_id,
            "revision": room.revision,
            "initiatorParticipantId": room.initiator_id,
            "expiresAt": room.expires_at_ms,
            "screenShare": CallService._screen_snapshot(room),
            "mutedParticipantIds": sorted(room.muted.intersection(room.members)),
            "members": [
                room.members[participant_id].public_value(room.room_id)
                for participant_id in sorted(room.members)
            ],
        }

    def _bind_session(self, session: Any, room_id: str) -> None:
        self._session_rooms[session.session_id] = room_id
        session.metadata["call_room_id"] = room_id
        self.server.sessions.persist(session)

    def _clear_session_metadata(self, session: Any) -> None:
        session.metadata.pop("call_room_id", None)
        self.server.sessions.persist(session)

    def _remove_member_locked(
        self, session: Any, room: Room
    ) -> tuple[tuple[Any, ...], dict[str, Any]] | None:
        participant_id = getattr(session, "authenticated_user", None)
        member = room.members.get(participant_id)
        if member is None or member.session is not session:
            return None
        del room.members[participant_id]
        if room.screen_owner == participant_id:
            self._clear_screen_locked(room)
        self._session_rooms.pop(session.session_id, None)
        room.revision += 1
        self._write_policy(room)
        return (
            tuple(value.session for value in room.members.values()),
            self._snapshot(room),
        )

    def _end_room_locked(self, room: Room) -> tuple[Any, ...]:
        self._clear_screen_locked(room)
        self._rooms.pop(room.room_id, None)
        policy_path = self._policy_path(room.room_id)
        if policy_path is not None:
            policy_path.unlink(missing_ok=True)
        if room.expiry_timer is not None:
            room.expiry_timer.cancel()
        recipients: list[Any] = []
        for member in room.members.values():
            self._session_rooms.pop(member.session.session_id, None)
            member.session.metadata.pop("call_room_id", None)
            self.server.sessions.persist(member.session)
            if member.participant_id != room.initiator_id:
                recipients.append(member.session)
        return tuple(recipients)

    @staticmethod
    def _safe_send(session: Any, payload: dict[str, Any]) -> bool:
        try:
            session.send(payload)
            return True
        except RuntimeError:
            return False

    def _broadcast(self, sessions: tuple[Any, ...], payload: dict[str, Any]) -> None:
        for session in sessions:
            self._safe_send(session, payload)
