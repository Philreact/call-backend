import base64

from qapp_backend.app.service import install_reference_service
from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.framing import Frame, FrameParser, FrameType
from qapp_backend.reticulum.protocol import encode_data_envelope
from qapp_backend.reticulum.server import BUFFER_STREAM_ID, QAppServer, write_all_buffer

LOGICAL_ID = "rns-00000000-0000-0000-0000-000000000000"


class PartialWriter:
    def __init__(self):
        self.output = bytearray()
        self.flushed = False

    def write(self, data):
        amount = min(3, len(data))
        self.output.extend(data[:amount])
        return amount

    def flush(self):
        self.flushed = True


def rpc_envelope(payload, request_id="request-0001"):
    return {
        "version": 1,
        "requestId": request_id,
        "encoding": "json",
        "payloadBase64": base64.b64encode(payload).decode("ascii"),
        "logicalConnectionId": LOGICAL_ID,
    }


def test_buffer_stream_and_partial_write_are_desktop_compatible():
    writer = PartialWriter()
    write_all_buffer(writer, b"0123456789")
    assert BUFFER_STREAM_ID == 7
    assert bytes(writer.output) == b"0123456789"
    assert writer.flushed


def test_rpc_and_realtime_share_one_physical_connection(config):
    server = QAppServer(config)
    install_reference_service(server)
    server.database.open()
    writes = []
    connection = PhysicalConnection(writes.append, config, server._application_message)
    server._links[b"same-link"] = connection
    connection.logical_connection_ids.add(LOGICAL_ID)
    session, _token = server.sessions.create(connection, provisional=True)
    session.metadata["qapp_connection_id"] = LOGICAL_ID
    session.metadata["qapp_identity"] = ["qapp-ui-call", "APP"]
    server.sessions.promote(session, "Q-authenticated-user")
    server.logical_sessions[LOGICAL_ID] = session
    response = server._make_rpc_callback("/hello")(
        "/hello",
        rpc_envelope(b'{"name":"Alice"}'),
        b"transport-request",
        b"same-link",
        None,
        0.0,
    )
    assert response == {"message": "Hello, Alice", "requestId": "request-0001"}

    received = []
    server.message_handlers["echo"] = lambda ctx, message: received.append((ctx.connection, message))
    connection.receive(
        Frame(
            FrameType.DATA,
            100,
            encode_data_envelope(LOGICAL_ID, {"type": "echo", "value": 42}),
        ).encode()
    )
    assert received == [(connection, {"type": "echo", "value": 42})]
    assert FrameParser().feed(writes[-1])[0] == Frame(FrameType.ACK, 100)
    server.database.close()


def test_mid_frame_reconnect_resends_from_start_and_delivers_once(config):
    server = QAppServer(config)
    server.database.open()
    delivered = []
    server.message_handlers["echo"] = lambda ctx, message: delivered.append(message)
    complete = Frame(
        FrameType.DATA,
        101,
        encode_data_envelope(LOGICAL_ID, {"type": "echo", "blob": "x" * 100_000}),
    ).encode()

    old = PhysicalConnection(lambda data: None, config, server._application_message)
    old.receive(complete[:70_000])
    old.close("interrupted_mid_frame")
    new = PhysicalConnection(lambda data: None, config, server._application_message)
    new.receive(complete)
    new.receive(complete)
    assert delivered == [{"type": "echo", "blob": "x" * 100_000}]
    server.database.close()
