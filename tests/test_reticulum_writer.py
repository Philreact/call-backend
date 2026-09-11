import threading
import time
import queue

import pytest

from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.writer import ReticulumWriter, WritePool


class RawWriter:
    def __init__(self):
        self.output = bytearray()

    def write(self, data):
        size = min(3, len(data))
        self.output.extend(data[:size])
        return size

    def flush(self):
        raise AssertionError("must not flush a buffered writer")


def test_zero_window_times_out_and_cannot_reuse_stream():
    raw = RawWriter()
    raw.write = lambda data: 0
    writer = ReticulumWriter(raw, 0.04)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        writer(b"frame")
    assert time.monotonic() - start < 1
    with pytest.raises(ConnectionError):
        writer(b"later")


def test_partial_writes_no_flush():
    raw = RawWriter()
    writer = ReticulumWriter(raw)
    writer(b"first")
    writer(b"second")
    assert raw.output == b"firstsecond"


def test_native_stall_does_not_block_close_or_replacement(config):
    entered, release = threading.Event(), threading.Event()
    old_raw = RawWriter()

    def blocked(data):
        entered.set()
        release.wait(2)
        return 1

    old_raw.write = blocked
    pool = WritePool(workers=2, capacity=2)
    old = PhysicalConnection(ReticulumWriter(old_raw, 0.08, pool), config, lambda *args: None)
    errors = []

    def send():
        try:
            old.send_application("logical", {"test": True})
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=send)
    thread.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        old.close("lost")
        assert time.monotonic() - start < 0.1
        thread.join(1)
        assert not thread.is_alive() and errors
        assert old.pending_bytes == 0 and not old.pending
        raw = RawWriter()
        new = PhysicalConnection(ReticulumWriter(raw, 0.1, pool), config, lambda *args: None)
        new.send_application("logical", {"test": "replacement"})
        assert raw.output and not new.closed
        new.close()
    finally:
        release.set()
        thread.join(1)


def test_write_failure_closes_and_releases_pending(config):
    class Broken:
        def write(self, data):
            raise OSError("lost link")
    closed = []
    connection = PhysicalConnection(ReticulumWriter(Broken()), config, lambda *args: None, closed.append)
    with pytest.raises(OSError):
        connection.send_application("logical", {"test": True})
    assert closed == [connection]
    assert connection.closed and connection.pending_bytes == 0 and not connection.pending


def test_lock_wait_bounded():
    writer = ReticulumWriter(RawWriter(), 0.03)
    writer.gate.acquire()
    try:
        with pytest.raises(TimeoutError):
            writer(b"frame")
        assert writer.cancelled.is_set()
    finally:
        writer.gate.release()


def test_expired_queued_job_never_writes():
    # A deterministic occupied pool without starting any worker threads.
    pool = WritePool(workers=0, capacity=1)
    raw = RawWriter()
    writer = ReticulumWriter(raw, 0.03, pool)
    with pytest.raises(TimeoutError):
        writer(b"stale")
    pool.jobs.get_nowait()()
    assert not raw.output


def test_full_pool_rejects_without_sending():
    pool = WritePool(workers=0, capacity=1)
    pool.submit(lambda: None)
    raw = RawWriter()
    writer = ReticulumWriter(raw, 0.03, pool)
    with pytest.raises(queue.Full):
        writer(b"frame")
    assert writer.cancelled.is_set() and not raw.output


def test_ack_during_write_does_not_leave_orphan_timer(config):
    from qapp_backend.reticulum.framing import FrameParser

    def writer(data):
        frame = FrameParser().feed(data)[0]
        # ACKs can arrive before the synchronous send returns.
        connection.acknowledge(frame.message_id)

    connection = PhysicalConnection(writer, config, lambda *args: None)
    connection.send_application("logical", {"test": True})
    assert not connection.pending and connection.pending_bytes == 0
    connection.close()
