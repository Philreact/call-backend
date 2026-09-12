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


@pytest.mark.parametrize('split', [0, 7, 12000, 65550])
def test_large_coalesced_delivery_preserves_frames_and_partial_tail(split):
    frames = tuple(Frame(FRAME_RELIABLE, encode_metadata({'messageId': str(i)}),
                         bytes([i]) * 65536) for i in range(8))
    wire = b''.join(encode_frame(frame) for frame in frames)
    parser = FrameParser()
    first = parser.feed(wire[:split])
    middle = parser.feed(wire[split:-31])
    assert len(parser._buffer) < 65536 + 4096 + 12
    last = parser.feed(wire[-31:])
    assert first + middle + last == frames
    assert not parser._buffer


def test_oversized_frame_header_is_rejected_before_buffering_body():
    import struct
    header = struct.pack('>4sBBHI', b'QP3F', 1, FRAME_RELIABLE, 0, 65537)
    parser = FrameParser()
    with pytest.raises(FramingError, match='inner frame exceeds limit'):
        parser.feed(header + b'x' * 200000)
    assert len(parser._buffer) == len(header)
