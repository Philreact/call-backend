from concurrent.futures import ThreadPoolExecutor
import threading
import time

import pytest

from qapp_backend.call.service import CallService
from test_call_service import FakeServer, FakeSession, context, create_room, join_message


@pytest.fixture
def room():
    server = FakeServer()
    service = CallService(server)
    alice = FakeSession("session-alice", "QAlice123")
    bob = FakeSession("session-bob", "QBob456")
    create_room(server, alice)
    service.join(context(bob), join_message())
    yield service, alice, bob
    service.disconnected(alice)


def control(service, session, action, share_id="share-123456"):
    service.screen_control(context(session), {
        "type": f"call_screen_{action}", "roomId": "room-123",
        "requestId": f"request-{action}", "shareId": share_id,
    })
    return [message for message in session.sent if message["type"] == "call_screen_result"][-1]


def test_only_one_presenter_even_for_simultaneous_requests(room):
    service, alice, bob = room
    barrier = threading.Barrier(2)
    def start(session):
        barrier.wait()
        return control(service, session, "start", f"share-{session.session_id}")
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(start, [alice, bob]))
    assert sum(result["accepted"] for result in results) == 1
    assert [result["code"] for result in results if not result["accepted"]] == ["SCREEN_BUSY"]


def test_non_owner_and_stale_stop_cannot_interrupt_presenter(room):
    service, alice, bob = room
    first = control(service, alice, "start")
    assert first["accepted"]
    assert not control(service, bob, "stop")["accepted"]
    assert not control(service, alice, "stop", "share-old123")["accepted"]
    assert control(service, alice, "renew")["accepted"]
    assert control(service, alice, "stop")["accepted"]
    assert control(service, bob, "start", "share-bob123")["accepted"]
    assert not control(service, alice, "stop")["accepted"]


def test_disconnect_releases_presenter_and_join_sees_current_state(room):
    service, alice, bob = room
    control(service, bob, "start")
    service.join(context(alice), {**join_message(seed=1), "requestId": "request-again"})
    assert alice.sent[-1]["screenShare"]["participantId"] == bob.authenticated_user
    service.disconnected(bob)
    assert alice.sent[-1]["screenShare"]["shareId"] == ""
    assert control(service, alice, "start")["accepted"]


def test_lease_expiry_broadcasts_and_releases_slot(room):
    service, alice, bob = room
    control(service, alice, "start")
    current = service._rooms["room-123"]
    previous = current.screen_revision
    current.screen_expires_at = time.monotonic() - 1
    service._expire_screen("room-123", "share-123456")
    assert bob.sent[-1]["type"] == "call_screen_state"
    assert bob.sent[-1]["screenShare"] == {"revision": previous + 1, "participantId": "", "shareId": ""}
    assert control(service, bob, "start")["accepted"]


def test_start_retry_is_idempotent_and_stale_timer_does_not_expire_new_lease(room):
    service, alice, _ = room
    first = control(service, alice, "start")
    second = control(service, alice, "start")
    assert first["screenShare"] == second["screenShare"]
    service._expire_screen("room-123", "share-123456")
    assert service._rooms["room-123"].screen_owner == alice.authenticated_user


def test_non_member_and_spoofed_session_cannot_present(room):
    service, alice, _ = room
    outsider = FakeSession("outsider", "QOutsider123")
    spoof = FakeSession("spoof", alice.authenticated_user)
    for session in (outsider, spoof):
        with pytest.raises(ValueError, match="membership"):
            control(service, session, "start")
