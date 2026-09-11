from __future__ import annotations

import logging
import secrets
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Callable

from qapp_backend.config import Config
from qapp_backend.reticulum.errors import BackpressureError, ConnectionClosedError, ProtocolError
from qapp_backend.reticulum.framing import Frame, FrameParser, FrameType
from qapp_backend.reticulum.writer import schedule_teardown
from qapp_backend.reticulum.protocol import (
    ControlMessage,
    ControlType,
    DataEnvelope,
    decode_data_envelope,
    encode_data_envelope,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PendingMessage:
    connection_id: str
    frame: bytes
    created_at: float
    timer: threading.Timer | None = None


class PhysicalConnection:
    """One Link and its non-reusable Channel/Buffer byte stream."""

    def __init__(
        self,
        writer: Callable[[bytes], None],
        config: Config,
        on_application_message: Callable[["PhysicalConnection", DataEnvelope, int], None],
        on_close: Callable[["PhysicalConnection"], None] | None = None,
        link: Any = None,
        on_logical_close: Callable[["PhysicalConnection", str], None] | None = None,
    ):
        self.id = uuid.uuid4().hex
        self.link = link
        self.channel: Any = None
        self.reader: Any = None
        self.buffer_writer: Any = None
        self.writer = writer
        self.config = config
        self.parser = FrameParser(config.max_frame_size, config.max_frame_size * 2)
        self.on_application_message = on_application_message
        self.on_close = on_close
        self.on_logical_close = on_logical_close
        self.remote_identity: Any = None
        self.logical_connection_ids: set[str] = set()
        self.closed_logical_connection_ids: set[str] = set()
        self.new_logical_session_times: deque[float] = deque()
        self.pending: OrderedDict[int, PendingMessage] = OrderedDict()
        self.pending_bytes = 0
        self.last_activity = time.monotonic()
        self.closed = False
        self.close_reason: str | None = None
        self._next_message_id = secrets.randbits(63) or 1
        self._lock = threading.RLock()

    def receive(self, data: bytes) -> None:
        with self._lock:
            if self.closed:
                return
            self.last_activity = time.monotonic()
        try:
            for frame in self.parser.feed(data):
                self._dispatch(frame)
        except ProtocolError:
            logger.warning("protocol error", extra={"event": "protocol_error", "connection_id": self.id})
            self.close("protocol_error")
            if self.link is not None:
                try:
                    self.link.teardown()
                except Exception:
                    pass

    def _dispatch(self, frame: Frame) -> None:
        if frame.frame_type is FrameType.ACK:
            self.acknowledge(frame.message_id)
            return
        if frame.frame_type is FrameType.CONTROL:
            control = ControlMessage.decode(frame.payload)
            if control.kind is ControlType.PING:
                self.send_control(ControlType.PONG, frame.message_id)
            elif control.kind is ControlType.CLOSE:
                self.close_logical(control.connection_id or "")
            return
        envelope = decode_data_envelope(frame.payload)
        if envelope.connection_id in self.closed_logical_connection_ids:
            # Drain a DATA frame that raced with CLOSE without allowing it to
            # recreate the closed logical session.
            self._write(Frame(FrameType.ACK, frame.message_id).encode(self.config.max_frame_size))
            return
        self.on_application_message(self, envelope, frame.message_id)
        self._write(Frame(FrameType.ACK, frame.message_id).encode(self.config.max_frame_size))

    def close_logical(self, connection_id: str) -> bool:
        """Close one logical session without tearing down the shared Link."""
        with self._lock:
            if connection_id not in self.logical_connection_ids:
                return False
            self.logical_connection_ids.remove(connection_id)
            self.closed_logical_connection_ids.add(connection_id)
        if self.on_logical_close is not None:
            self.on_logical_close(self, connection_id)
        return True

    def send_application(self, connection_id: str, payload: Any) -> int:
        return self.send_data(connection_id, encode_data_envelope(connection_id, payload))

    def send_data(self, connection_id: str, envelope: bytes) -> int:
        with self._lock:
            if self.closed:
                raise ConnectionClosedError("physical connection is closed")
            if len(self.pending) >= self.config.max_unacked_messages:
                raise BackpressureError("maximum unacknowledged message count reached")
            message_id = self._next_message_id
            self._next_message_id = (message_id + 1) & 0xFFFFFFFFFFFFFFFF
            encoded = Frame(FrameType.DATA, message_id, envelope).encode(self.config.max_frame_size)
            if self.pending_bytes + len(encoded) > self.config.max_queue_bytes:
                raise BackpressureError("maximum queued traffic bytes reached")
            pending = PendingMessage(connection_id, encoded, time.monotonic())
            self.pending[message_id] = pending
            self.pending_bytes += len(encoded)
        try:
            self._write(encoded)
        except Exception:
            with self._lock:
                if self.pending.pop(message_id, None) is not None:
                    self.pending_bytes -= len(encoded)
            raise
        with self._lock:
            if not self.closed and self.pending.get(message_id) is pending:
                self._arm_timeout(message_id, pending)
        return message_id

    def send_control(self, kind: ControlType, message_id: int) -> None:
        payload = ControlMessage(kind).encode()
        self._write(Frame(FrameType.CONTROL, message_id, payload).encode(self.config.max_frame_size))

    def _write(self, data: bytes) -> None:
        with self._lock:
            if self.closed:
                raise ConnectionClosedError("physical connection is closed")
        try:
            self.writer(data)
        except Exception:
            self.close("buffer_write_failed")
            schedule_teardown(self.link)
            raise
        with self._lock:
            if self.closed:
                raise ConnectionClosedError("physical connection closed during write")
            self.last_activity = time.monotonic()

    def _arm_timeout(self, message_id: int, pending: PendingMessage, delay: float | None = None) -> None:
        timer = threading.Timer(
            self.config.ack_timeout if delay is None else delay,
            self._ack_timeout,
            args=(message_id,),
        )
        timer.daemon = True
        pending.timer = timer
        timer.start()

    def _ack_timeout(self, message_id: int) -> None:
        with self._lock:
            pending = self.pending.pop(message_id, None)
            if pending is None:
                return
            self.pending_bytes -= len(pending.frame)
        logger.warning("unacknowledged DATA expired", extra={"event": "ack_timeout", "connection_id": self.id, "message_id": message_id})

    def acknowledge(self, message_id: int) -> bool:
        with self._lock:
            pending = self.pending.pop(message_id, None)
            if pending is None:
                return False
            if pending.timer is not None:
                pending.timer.cancel()
            self.pending_bytes -= len(pending.frame)
            logger.info("ACK received", extra={"event": "ack_received", "connection_id": self.id, "message_id": message_id})
            return True

    def close(self, reason: str = "closed") -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
            cancel = getattr(self.writer, "cancel", None)
            if callable(cancel):
                cancel()
            self.close_reason = reason
            self.parser.reset()
            for pending in self.pending.values():
                if pending.timer is not None:
                    pending.timer.cancel()
        logger.info(
            "physical connection closed",
            extra={
                "event": "link_closed",
                "connection_id": self.id,
                "reason": reason,
            },
        )
        if self.on_close is not None:
            self.on_close(self)

    def adopt_pending(self, messages: list[tuple[int, str, bytes, float]]) -> None:
        """Resend complete logical frames after the client replaces its Link."""
        for message_id, connection_id, encoded, created_at in messages:
            with self._lock:
                if self.closed:
                    raise ConnectionClosedError("physical connection is closed")
                remaining = self.config.ack_timeout - (time.monotonic() - created_at)
                if remaining <= 0:
                    continue
                if len(self.pending) >= self.config.max_unacked_messages:
                    break
                if self.pending_bytes + len(encoded) > self.config.max_queue_bytes:
                    break
                pending = PendingMessage(connection_id, encoded, created_at)
                self.pending[message_id] = pending
                self.pending_bytes += len(encoded)
            try:
                self._write(encoded)
            except Exception:
                with self._lock:
                    if self.pending.pop(message_id, None) is not None:
                        self.pending_bytes -= len(encoded)
                raise
            with self._lock:
                if not self.closed and self.pending.get(message_id) is pending:
                    self._arm_timeout(message_id, pending, max(0, self.config.ack_timeout - (time.monotonic() - created_at)))
