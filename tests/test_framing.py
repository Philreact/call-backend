import struct

import pytest

from qapp_backend.reticulum.errors import ProtocolError
from qapp_backend.reticulum.framing import Frame, FrameParser, FrameType, HEADER_SIZE


def test_single_complete_binary_frame():
    frame = Frame(FrameType.DATA, 42, b"\x00\xffpayload")
    assert FrameParser().feed(frame.encode()) == [frame]


def test_split_header_and_payload():
    encoded = Frame(FrameType.DATA, 7, b"abcdef").encode()
    parser = FrameParser()
    assert parser.feed(encoded[:3]) == []
    assert parser.feed(encoded[3:HEADER_SIZE + 2]) == []
    assert parser.feed(encoded[HEADER_SIZE + 2:]) == [Frame(FrameType.DATA, 7, b"abcdef")]


def test_multiple_and_zero_length_frames():
    one = Frame(FrameType.DATA, 1, b"")
    two = Frame(FrameType.CONTROL, 2, b"{}")
    assert FrameParser().feed(one.encode() + two.encode()) == [one, two]


@pytest.mark.parametrize("header", [
    struct.pack("!BBQI", 2, 1, 1, 0),
    struct.pack("!BBQI", 1, 99, 1, 0),
    struct.pack("!BBQI", 1, 1, 1, 262145),
])
def test_rejects_bad_headers_before_payload(header):
    with pytest.raises(ProtocolError):
        FrameParser().feed(header)


def test_truncated_frame_is_buffered_and_discardable():
    parser = FrameParser()
    encoded = Frame(FrameType.DATA, 5, b"payload").encode()
    assert parser.feed(encoded[:-2]) == []
    assert parser.buffered_bytes == len(encoded) - 2
    parser.reset()
    assert parser.buffered_bytes == 0


def test_receive_accumulator_limit_is_enforced():
    parser = FrameParser(max_frame_size=64, max_receive_buffer_size=128)
    with pytest.raises(ProtocolError, match="receive buffer exceeds"):
        parser.feed(b"x" * 129)


def test_ack_payload_rejected():
    with pytest.raises(ProtocolError):
        FrameParser().feed(Frame(FrameType.ACK, 4, b"x").encode())
