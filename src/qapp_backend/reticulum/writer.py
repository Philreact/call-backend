"""Bounded, cancellable writes on a single non-reusable Reticulum stream."""
from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable


class WritePool:
    """Daemon workers and a bounded queue, including when native RNS stalls."""

    def __init__(self, workers: int = 8, capacity: int = 64):
        self.jobs: queue.Queue[Callable[[], None]] = queue.Queue(capacity)
        self.workers = workers
        self.started = False
        self.lock = threading.Lock()

    def submit(self, job: Callable[[], None]) -> None:
        with self.lock:
            if not self.started:
                for _ in range(self.workers):
                    threading.Thread(target=self._run, daemon=True, name="rns-write").start()
                self.started = True
        self.jobs.put_nowait(job)

    def _run(self) -> None:
        while True:
            job = self.jobs.get()
            try:
                job()
            except Exception:
                # Jobs report their own result; teardown is best effort.
                pass
            finally:
                self.jobs.task_done()


WRITE_POOL = WritePool()
TEARDOWN_POOL = WritePool(workers=2, capacity=64)


def schedule_teardown(link: Any) -> None:
    if link is not None:
        try:
            TEARDOWN_POOL.submit(link.teardown)
        except queue.Full:
            pass


class ReticulumWriter:
    def __init__(self, raw: Any, timeout: float = 10.0, pool: WritePool = WRITE_POOL):
        self.raw = raw
        self.timeout = timeout
        self.pool = pool
        self.cancelled = threading.Event()
        self.gate = threading.Lock()

    def cancel(self) -> None:
        self.cancelled.set()

    def __call__(self, data: bytes) -> None:
        deadline = time.monotonic() + self.timeout
        if not self.gate.acquire(timeout=self.timeout):
            self.cancel()
            raise TimeoutError("Reticulum write lock timed out")
        try:
            done = threading.Event()
            errors: list[Exception] = []

            def check() -> None:
                if self.cancelled.is_set():
                    raise ConnectionError("Reticulum stream cancelled")
                if time.monotonic() >= deadline:
                    raise TimeoutError("Reticulum write timed out")

            def write() -> None:
                try:
                    offset = 0
                    while offset < len(data):
                        check()
                        written = int(self.raw.write(data[offset:]) or 0)
                        if written < 0 or written > len(data) - offset:
                            raise IOError("invalid Reticulum write length")
                        if written == 0:
                            self.cancelled.wait(min(0.01, max(0, deadline - time.monotonic())))
                        offset += written
                    check()
                    # RawChannelWriter has no buffered bytes to flush.
                except Exception as exc:
                    errors.append(exc)
                finally:
                    done.set()

            check()
            self.pool.submit(write)
            while not done.wait(min(0.01, max(0, deadline - time.monotonic()))):
                check()
            check()
            if errors:
                raise errors[0]
        except Exception:
            # A possibly partial frame makes this physical stream unusable.
            self.cancel()
            raise
        finally:
            self.gate.release()
