from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from qapp_backend.reticulum.errors import ProtocolError

PROTOCOL_VERSION = 1
HEADER_SIZE = 14
PROTOCOL_MAX_FRAME_SIZE = 256 * 1024
_HEADER = struct.Struct("!BBQI")


class FrameType(IntEnum):
    DATA = 1
    ACK = 2
    CONTROL = 3


@dataclass(frozen=True, slots=True)
class Frame:
    frame_type: FrameType
    message_id: int
    payload: bytes = b""

    def encode(self, max_frame_size: int = PROTOCOL_MAX_FRAME_SIZE) -> bytes:
        if not 0 <= self.message_id <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("message_id must be an unsigned 64-bit integer")
        if len(self.payload) > max_frame_size:
            raise ValueError("payload exceeds maximum frame size")
        return _HEADER.pack(PROTOCOL_VERSION, int(self.frame_type), self.message_id, len(self.payload)) + self.payload


class FrameParser:
    def __init__(
        self,
        max_frame_size: int = PROTOCOL_MAX_FRAME_SIZE,
        max_receive_buffer_size: int | None = None,
    ):
        if not 0 < max_frame_size <= PROTOCOL_MAX_FRAME_SIZE:
            raise ValueError("invalid max_frame_size")
        self.max_frame_size = max_frame_size
        self.max_receive_buffer_size = max_receive_buffer_size or max_frame_size * 2
        if self.max_receive_buffer_size < HEADER_SIZE + max_frame_size:
            raise ValueError("receive buffer must hold one maximum-sized frame")
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def reset(self) -> None:
        self._buffer.clear()

    def feed(self, data: bytes | bytearray | memoryview) -> list[Frame]:
        if len(self._buffer) + len(data) > self.max_receive_buffer_size:
            self.reset()
            raise ProtocolError("receive buffer exceeds maximum size")
        self._buffer.extend(data)
        frames: list[Frame] = []
        while len(self._buffer) >= HEADER_SIZE:
            version, raw_type, message_id, payload_length = _HEADER.unpack_from(self._buffer)
            if version != PROTOCOL_VERSION:
                self.reset()
                raise ProtocolError(f"unsupported protocol version: {version}")
            try:
                frame_type = FrameType(raw_type)
            except ValueError as exc:
                self.reset()
                raise ProtocolError(f"unknown frame type: {raw_type}") from exc
            if payload_length > self.max_frame_size:
                self.reset()
                raise ProtocolError("declared payload exceeds maximum frame size")
            total = HEADER_SIZE + payload_length
            if len(self._buffer) < total:
                break
            payload = bytes(self._buffer[HEADER_SIZE:total])
            del self._buffer[:total]
            if frame_type is FrameType.ACK and payload:
                self.reset()
                raise ProtocolError("ACK payload must be empty")
            frames.append(Frame(frame_type, message_id, payload))
        return frames
