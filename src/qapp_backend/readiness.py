"""Read-only health checks backed by the running process's audit progress."""
from __future__ import annotations

import json
import os
from pathlib import Path

from qapp_backend.config import Config


def process_identity(pid: int) -> str:
    os.kill(pid, 0)
    # Linux start ticks and boot ID prevent a persisted marker from another
    # container lifetime becoming valid again when PID 1 is reused.
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return f"{boot}:{stat[19]}"


def write_marker(config: Config, kind: str, details: dict) -> None:
    # Docker health is Linux-specific; direct development remains portable.
    if not Path("/proc/self/stat").exists():
        return
    directory = config.data_dir / ".readiness"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{kind}.json"
    temp = path.with_suffix(".tmp")
    payload = {"pid": os.getpid(), "process": process_identity(os.getpid()), **details}
    temp.write_text(json.dumps(payload), encoding="utf-8")
    temp.replace(path)


def _marker(config: Config, kind: str) -> dict:
    value = json.loads((config.data_dir / ".readiness" / f"{kind}.json").read_text())
    if value["process"] != process_identity(value["pid"]):
        raise ValueError("startup checks belong to an earlier backend process")
    return value


def check_readiness(config: Config) -> None:
    try:
        server = _marker(config, "server")
        if not server["running"]:
            raise ValueError("backend is shutting down")
    except (KeyError, TypeError) as exc:
        raise ValueError(f"startup checks incomplete: {exc}") from exc
