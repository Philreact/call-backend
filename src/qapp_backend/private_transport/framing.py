from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any


ALPN = "qortal-private/1"
PROTOCOL_VERSION = 1
FRAME_ATTACH = 1
FRAME_ATTACHED = 2
FRAME_RELIABLE = 3
MAX_METADATA_BYTES = 4 * 1024
MAX_RELIABLE_PAYLOAD_BYTES = 64 * 1024
MAX_DATAGRAM_PAYLOAD_BYTES = 1024
MAX_MESSAGE_ID_BYTES = 128
_STREAM_MAGIC = b"QP3F"
_DATAGRAM_MAGIC = b"QP3D"
_HEADER = struct.Struct(">4sBBHI")


class FramingError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Frame:
    frame_type: int
    metadata: bytes = b""
    payload: bytes = b""

    def metadata_json(self) -> Any:
        try:
            return json.loads(self.metadata.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FramingError("invalid frame metadata") from exc


def encode_metadata(value: Any) -> bytes:
    encoded = json.dumps(
        value, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(encoded) > MAX_METADATA_BYTES:
        raise FramingError("frame metadata exceeds limit")
    return encoded


def encode_frame(frame: Frame) -> bytes:
    if (
        len(frame.metadata) > MAX_METADATA_BYTES
        or len(frame.payload) > MAX_RELIABLE_PAYLOAD_BYTES
    ):
        raise FramingError("inner frame exceeds limit")
    return (
        _HEADER.pack(
            _STREAM_MAGIC,
            PROTOCOL_VERSION,
            frame.frame_type,
            len(frame.metadata),
            len(frame.payload),
        )
        + frame.metadata
        + frame.payload
    )


class FrameParser:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> tuple[Frame, ...]:
        # QUIC delivery boundaries are unrelated to application frames. Retain
        # at most one incomplete frame, even when many arrive in one event.
        incoming = memoryview(data)
        offset = 0
        frames: list[Frame] = []
        while offset < len(incoming):
            take = min(_HEADER.size - len(self._buffer), len(incoming) - offset)
            if take > 0:
                self._buffer.extend(incoming[offset:offset + take])
                offset += take
            if len(self._buffer) < _HEADER.size:
                break
            magic, version, frame_type, metadata_length, payload_length = (
                _HEADER.unpack_from(self._buffer)
            )
            if magic != _STREAM_MAGIC or version != PROTOCOL_VERSION:
                raise FramingError("unsupported inner stream protocol")
            if (
                metadata_length > MAX_METADATA_BYTES
                or payload_length > MAX_RELIABLE_PAYLOAD_BYTES
            ):
                raise FramingError("inner frame exceeds limit")
            total = _HEADER.size + metadata_length + payload_length
            take = min(total - len(self._buffer), len(incoming) - offset)
            self._buffer.extend(incoming[offset:offset + take])
            offset += take
            if len(self._buffer) < total:
                break
            metadata_start = _HEADER.size
            payload_start = metadata_start + metadata_length
            frames.append(
                Frame(
                    frame_type,
                    bytes(self._buffer[metadata_start:payload_start]),
                    bytes(self._buffer[payload_start:total]),
                )
            )
            del self._buffer[:total]
        return tuple(frames)


def decode_datagram(data: bytes) -> tuple[str, bytes]:
    if len(data) < 7 or data[:4] != _DATAGRAM_MAGIC or data[4] != PROTOCOL_VERSION:
        raise FramingError("invalid inner datagram")
    message_id_length = int.from_bytes(data[5:7], "big")
    payload_offset = 7 + message_id_length
    if (
        not 1 <= message_id_length <= MAX_MESSAGE_ID_BYTES
        or payload_offset > len(data)
        or len(data) - payload_offset > MAX_DATAGRAM_PAYLOAD_BYTES
    ):
        raise FramingError("invalid inner datagram lengths")
    try:
        message_id = data[7:payload_offset].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FramingError("invalid datagram message ID") from exc
    return message_id, data[payload_offset:]


def encode_datagram(message_id: str, payload: bytes) -> bytes:
    encoded_id = message_id.encode("utf-8")
    if (
        not 1 <= len(encoded_id) <= MAX_MESSAGE_ID_BYTES
        or len(payload) > MAX_DATAGRAM_PAYLOAD_BYTES
    ):
        raise FramingError("invalid inner datagram")
    return (
        _DATAGRAM_MAGIC
        + bytes((PROTOCOL_VERSION,))
        + len(encoded_id).to_bytes(2, "big")
        + encoded_id
        + payload
    )
