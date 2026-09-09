from dataclasses import replace

import pytest

from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.errors import BackpressureError
from qapp_backend.reticulum.framing import Frame, FrameParser, FrameType
from qapp_backend.reticulum.protocol import ControlMessage, ControlType, encode_data_envelope
from qapp_backend.reticulum.sessions import ApplicationSession

LOGICAL_ID = "rns-00000000-0000-0000-0000-000000000000"


def make_session(connection, dedup=512):
    return ApplicationSession(
        "s", b"x", 0, 0, 99999999999,
        metadata={"qapp_connection_id": LOGICAL_ID},
        connection=connection,
        _dedup_limit=dedup,
    )


def test_data_ack_duplicate_ack_and_dedup(config):
    writes = []
    delivered = []
    session = None

    def receive(connection, envelope, message_id):
        if not session.seen_message(message_id):
            delivered.append(envelope.decode_payload())

    connection = PhysicalConnection(writes.append, config, receive)
    session = make_session(connection)
    encoded = Frame(
        FrameType.DATA, 9, encode_data_envelope(LOGICAL_ID, {"type": "echo"})
    ).encode()
    connection.receive(encoded)
    connection.receive(encoded)
    assert delivered == [{"type": "echo"}]
    assert [
        frame.frame_type
        for raw in writes
        for frame in FrameParser().feed(raw)
    ] == [FrameType.ACK, FrameType.ACK]


def test_ack_frees_pending_and_unknown_is_harmless(config):
    connection = PhysicalConnection(lambda data: None, config, lambda *args: None)
    envelope = encode_data_envelope(LOGICAL_ID, {"type": "echo"})
    message_id = connection.send_data(LOGICAL_ID, envelope)
    assert connection.pending_bytes
    assert connection.acknowledge(message_id)
    assert connection.pending_bytes == 0
    assert not connection.acknowledge(message_id)
    assert not connection.acknowledge(123)
    connection.close()


def test_message_count_backpressure(config):
    connection = PhysicalConnection(
        lambda data: None,
        replace(config, max_unacked_messages=1),
        lambda *args: None,
    )
    envelope = encode_data_envelope(LOGICAL_ID, {"type": "echo"})
    connection.send_data(LOGICAL_ID, envelope)
    with pytest.raises(BackpressureError):
        connection.send_data(LOGICAL_ID, envelope)
    connection.close()


def test_byte_backpressure(config):
    connection = PhysicalConnection(
        lambda data: None,
        replace(config, max_queue_bytes=20),
        lambda *args: None,
    )
    with pytest.raises(BackpressureError):
        connection.send_data(LOGICAL_ID, encode_data_envelope(LOGICAL_ID, {}))


def test_ping_receives_pong_with_same_message_id(config):
    writes = []
    connection = PhysicalConnection(writes.append, config, lambda *args: None)
    connection.receive(Frame(FrameType.CONTROL, 77, b'{"type":"PING"}').encode())
    response = FrameParser().feed(writes[0])[0]
    assert response == Frame(FrameType.CONTROL, 77, b'{"type":"PONG"}')


def test_close_control_closes_only_the_named_logical_connection(config):
    closed = []
    connection = PhysicalConnection(
        lambda _data: None,
        config,
        lambda *args: None,
        on_logical_close=lambda _connection, logical_id: closed.append(logical_id),
    )
    connection.logical_connection_ids.update({"logical-one", "logical-two"})
    frame = Frame(
        FrameType.CONTROL,
        78,
        ControlMessage(ControlType.CLOSE, "logical-one").encode(),
    ).encode()

    connection.receive(frame)
    connection.receive(frame)

    assert closed == ["logical-one"]
    assert connection.logical_connection_ids == {"logical-two"}
    assert connection.closed_logical_connection_ids == {"logical-one"}
    assert not connection.closed


def test_data_after_logical_close_is_acked_but_not_delivered(config):
    writes = []
    delivered = []
    connection = PhysicalConnection(
        writes.append,
        config,
        lambda _connection, envelope, _message_id: delivered.append(
            envelope.decode_payload()
        ),
    )
    connection.logical_connection_ids.add(LOGICAL_ID)
    assert connection.close_logical(LOGICAL_ID)

    connection.receive(
        Frame(
            FrameType.DATA,
            79,
            encode_data_envelope(LOGICAL_ID, {"type": "late"}),
        ).encode()
    )

    assert delivered == []
    assert FrameParser().feed(writes[0]) == [Frame(FrameType.ACK, 79)]


def test_oversized_logical_connection_id_is_protocol_error(config):
    connection = PhysicalConnection(lambda _data: None, config, lambda *args: None)
    encoded = Frame(
        FrameType.DATA,
        1,
        encode_data_envelope("x" * 129, {"type": "echo"}),
    ).encode()

    connection.receive(encoded)

    assert connection.closed
    assert connection.close_reason == "protocol_error"


def test_connection_close_records_the_first_reason(config, caplog):
    caplog.set_level("INFO", logger="qapp_backend.reticulum.connection")
    connection = PhysicalConnection(
        lambda _data: None,
        config,
        lambda *args: None,
    )

    connection.close("idle_timeout")
    connection.close("link_closed")

    record = next(
        record for record in caplog.records
        if record.getMessage() == "physical connection closed"
    )
    assert record.reason == "idle_timeout"
    assert connection.close_reason == "idle_timeout"
