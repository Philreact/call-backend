from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class InstanceLockError(RuntimeError):
    """Raised when the deployment lock cannot be used safely."""


class InstanceAlreadyRunningError(InstanceLockError):
    """Raised when another backend holds the deployment lock."""


@contextmanager
def acquire_instance_lock(path: Path) -> Iterator[None]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as exc:
        raise InstanceLockError(f"cannot open deployment lock {path}: {exc}") from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstanceAlreadyRunningError(
                f"another backend instance is already using deployment lock {path}"
            ) from exc
        except OSError as exc:
            raise InstanceLockError(f"cannot acquire deployment lock {path}: {exc}") from exc
        yield
    finally:
        os.close(descriptor)
