import json
from types import SimpleNamespace

import pytest

from qapp_backend.call.service import CallService
from test_call_service import FakeServer, FakeSession, context, create_message, join_message


@pytest.fixture
def room(tmp_path):
    server = FakeServer()
    server.config = SimpleNamespace(call_media_revocations_path=tmp_path)
    service = CallService(server)
    host = FakeSession("session-host", "QHost123")
    guest = FakeSession("session-guest", "QGuest123")
    service.create(context(host), create_message())
    service.join(context(guest), join_message())
    yield service, host, guest
    service._expire_room("room-123")


def moderate(service, actor, target, operation):
    service.moderate(context(actor), {"type": "call_moderate", "requestId": "moderate-123",
        "roomId": "room-123", "targetParticipantId": target.authenticated_user, "operation": operation})


def policy(service):
    return json.loads(service._policy_path("room-123").read_text())


def test_only_exact_creator_session_can_moderate(room):
    service, host, guest = room
    for attacker in (guest, FakeSession("spoof-session", host.authenticated_user)):
        with pytest.raises(ValueError, match="creator"):
            moderate(service, attacker, guest, "remove")
    with pytest.raises(ValueError, match="creator"):
        moderate(service, host, host, "mute")
    assert guest.authenticated_user in policy(service)["members"]


def test_mute_is_authoritative_and_does_not_turn_mic_on_when_released(room):
    service, host, guest = room
    moderate(service, host, guest, "mute")
    assert policy(service)["muted"] == [guest.authenticated_user]
    assert guest.sent[-1]["mutedParticipantIds"] == [guest.authenticated_user]
    moderate(service, host, guest, "allow_mic")
    assert policy(service)["muted"] == []
    assert guest.sent[-1]["type"] == "call_membership"


def test_removed_account_cannot_rejoin_even_with_new_session_until_readmitted(room):
    service, host, guest = room
    moderate(service, host, guest, "remove")
    assert guest.sent[-1]["type"] == "call_removed"
    assert "call_room_id" not in guest.metadata
    assert guest.authenticated_user not in policy(service)["members"]
    assert host.sent[-1]["blockedParticipantIds"] == [guest.authenticated_user]
    replacement = FakeSession("replacement-session", guest.authenticated_user)
    service.join(context(replacement), join_message(seed=3))
    assert replacement.sent[-1]["type"] == "call_removed"
    assert not replacement.metadata
    moderate(service, host, guest, "readmit")
    assert host.sent[-1]["blockedParticipantIds"] == []
    service.join(context(replacement), join_message(seed=3))
    assert policy(service)["members"][guest.authenticated_user] == replacement.session_id
    assert all("blockedParticipantIds" not in message for message in guest.sent)


def test_removal_releases_presenter_and_room_end_removes_policy(room):
    service, host, guest = room
    service.screen_control(context(guest), {"type": "call_screen_start", "requestId": "screen-123",
        "roomId": "room-123", "shareId": "share-123"})
    moderate(service, host, guest, "remove")
    assert service._rooms["room-123"].screen_owner == ""
    path = service._policy_path("room-123")
    service._expire_room("room-123")
    assert not path.exists()


def test_mute_cannot_be_evaded_by_leaving_and_rejoining(room):
    service, host, guest = room
    moderate(service, host, guest, "mute")
    service.leave(context(guest), {"type": "call_leave", "requestId": "leave-123", "roomId": "room-123"})
    service.join(context(guest), join_message())
    assert policy(service)["muted"] == [guest.authenticated_user]


def test_restart_clears_only_previous_room_policy_files(tmp_path):
    policies = tmp_path / "rooms"
    policies.mkdir()
    stale = policies / ("a" * 64 + ".json")
    stale.write_text("{}")
    unrelated = policies / "keep.txt"
    unrelated.write_text("keep")
    server = FakeServer()
    server.config = SimpleNamespace(call_media_revocations_path=tmp_path)
    CallService(server)
    assert not stale.exists()
    assert unrelated.read_text() == "keep"
