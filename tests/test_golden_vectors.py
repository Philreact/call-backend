import json
from pathlib import Path

from qapp_backend.reticulum.framing import Frame, FrameParser, FrameType
from qapp_backend.reticulum.protocol import (
    ControlMessage,
    ControlType,
    decode_data_envelope,
    decode_rpc_request,
    encode_data_envelope,
)

VECTORS = json.loads((Path(__file__).parents[1] / "protocol-v1-vectors.json").read_text())


def test_frozen_frame_vectors():
    for key, frame_type in (
        ("data_frame", FrameType.DATA),
        ("ack_frame", FrameType.ACK),
        ("control_frame", FrameType.CONTROL),
    ):
        vector = VECTORS[key]
        message_id = int(vector["message_id_hex"], 16)
        payload = bytes.fromhex(vector["payload_hex"])
        encoded = Frame(frame_type, message_id, payload).encode()
        assert encoded.hex() == vector["frame_hex"]
        assert FrameParser().feed(encoded) == [Frame(frame_type, message_id, payload)]


def test_control_and_data_codec_vectors():
    assert ControlMessage(ControlType.PING).encode().hex() == VECTORS["control_frame"]["payload_hex"]
    close = ControlMessage(ControlType.CLOSE, "logical-one")
    assert ControlMessage.decode(close.encode()) == close
    data = VECTORS["data_envelope"]
    encoded = encode_data_envelope(data["connection_id"], data["application_json"])
    assert encoded.decode("utf-8") == data["envelope_utf8"]
    assert decode_data_envelope(encoded).decode_payload() == data["application_json"]


def test_rpc_codec_vector():
    vector = VECTORS["rpc_request"]
    decoded = decode_rpc_request({
        "version": vector["version"],
        "requestId": vector["request_id"],
        "encoding": vector["encoding"],
        "payloadBase64": vector["payload_base64"],
    })
    assert decoded.request_id == vector["request_id"]
    assert decoded.decode_payload() == vector["application_json"]
