from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.framing import Frame, FrameParser, FrameType
from qapp_backend.reticulum.protocol import encode_data_envelope
from qapp_backend.reticulum.sessions import ApplicationSession

LOGICAL_ID = "rns-00000000-0000-0000-0000-000000000000"


def test_partial_bytes_discarded_with_physical_link(config):
    first = PhysicalConnection(lambda data: None, config, lambda *args: None)
    encoded = Frame(
        FrameType.DATA, 1, encode_data_envelope(LOGICAL_ID, {"type": "echo"})
    ).encode()
    first.receive(encoded[:-1])
    assert first.parser.buffered_bytes
    first.close("lost")
    assert first.parser.buffered_bytes == 0
    second = PhysicalConnection(lambda data: None, config, lambda *args: None)
    assert second.parser.buffered_bytes == 0


def test_resend_after_data_before_ack_delivers_once(config):
    delivered = []
    session = ApplicationSession("s", b"x", 0, 0, 99999999999)

    def receive(_connection, envelope, message_id):
        if not session.seen_message(message_id):
            delivered.append(envelope.decode_payload())

    frame = Frame(
        FrameType.DATA, 55, encode_data_envelope(LOGICAL_ID, {"type": "echo"})
    ).encode()
    first = PhysicalConnection(lambda data: None, config, receive)
    first.receive(frame)
    first.close("lost_before_ack")
    second = PhysicalConnection(lambda data: None, config, receive)
    second.receive(frame)
    assert delivered == [{"type": "echo"}]


def test_multiple_pending_frames_are_adopted_in_order(config):
    writes = []
    old = PhysicalConnection(lambda data: None, config, lambda *args: None)
    envelope = encode_data_envelope(LOGICAL_ID, {"type": "echo"})
    ids = [old.send_data(LOGICAL_ID, envelope) for _ in range(4)]
    carry = [
        (message_id, pending.connection_id, pending.frame, pending.created_at)
        for message_id, pending in old.pending.items()
    ]
    old.close("link_lost")
    new = PhysicalConnection(writes.append, config, lambda *args: None)
    new.adopt_pending(carry)
    assert [FrameParser().feed(raw)[0].message_id for raw in writes] == ids
    new.close()
