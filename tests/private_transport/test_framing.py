import pytest

from qapp_backend.private_transport.framing import (
    FRAME_RELIABLE,
    Frame,
    FrameParser,
    FramingError,
    decode_datagram,
    encode_datagram,
    encode_frame,
    encode_metadata,
)


def test_stream_frames_interoperate_with_step3_wire_format():
    encoded = encode_frame(
        Frame(FRAME_RELIABLE, encode_metadata({"messageId": "m-1"}), b"payload")
    )
    parser = FrameParser()
    assert parser.feed(encoded[:7]) == ()
    (frame,) = parser.feed(encoded[7:])
    assert frame.frame_type == FRAME_RELIABLE
    assert frame.metadata_json() == {"messageId": "m-1"}
    assert frame.payload == b"payload"


def test_datagrams_round_trip_and_reject_oversized_payloads():
    assert decode_datagram(encode_datagram("d-1", b"value")) == ("d-1", b"value")
    with pytest.raises(FramingError):
        encode_datagram("large", b"x" * 1025)


def test_stream_parser_rejects_unsupported_version():
    encoded = bytearray(encode_frame(Frame(FRAME_RELIABLE)))
    encoded[4] = 2
    with pytest.raises(FramingError):
        FrameParser().feed(encoded)
