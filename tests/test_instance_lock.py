from __future__ import annotations

from pathlib import Path

import pytest

from qapp_backend.instance_lock import (
    InstanceAlreadyRunningError,
    acquire_instance_lock,
)


def test_instance_lock_rejects_a_second_backend(tmp_path: Path):
    lock_path = tmp_path / "backend.lock"

    with acquire_instance_lock(lock_path):
        with pytest.raises(InstanceAlreadyRunningError, match="another backend"):
            with acquire_instance_lock(lock_path):
                pass

    with acquire_instance_lock(lock_path):
        pass
