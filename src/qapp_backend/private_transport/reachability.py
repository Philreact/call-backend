from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path


STATE_VERSION = 1
STATE_MAX_AGE_SECONDS = 3 * 60 * 60


class ReachabilityUnavailable(RuntimeError):
    pass


def resolve_public_host(configured_host: str, port: int, state_path: Path) -> str:
    value = configured_host.strip()
    if value.lower() != "auto":
        return ipaddress.ip_address(value).compressed

    try:
        raw = state_path.read_bytes()
    except OSError as exc:
        raise ReachabilityUnavailable(
            "automatic network state is unavailable"
        ) from exc
    if len(raw) > 4096:
        raise ReachabilityUnavailable("automatic network state is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReachabilityUnavailable("automatic network state is invalid") from exc
    if not isinstance(document, dict) or set(document) != {
        "version", "publicHost", "ports", "mode", "updatedAt"
    }:
        raise ReachabilityUnavailable("automatic network state is invalid")
    ports = document["ports"]
    updated_at = document["updatedAt"]
    if (
        document["version"] != STATE_VERSION
        or not isinstance(document["publicHost"], str)
        or not isinstance(document["mode"], str)
        or document["mode"] not in {"configured", "direct", "upnp"}
        or not isinstance(ports, list)
        or any(not isinstance(item, int) or isinstance(item, bool) for item in ports)
        or port not in ports
        or not isinstance(updated_at, int)
        or isinstance(updated_at, bool)
    ):
        raise ReachabilityUnavailable("automatic network state is invalid")
    now = time.time()
    updated_seconds = updated_at / 1000
    if updated_seconds > now + 60 or now - updated_seconds > STATE_MAX_AGE_SECONDS:
        raise ReachabilityUnavailable("automatic network state is stale")
    try:
        host = ipaddress.ip_address(document["publicHost"])
    except ValueError as exc:
        raise ReachabilityUnavailable("automatic public host is invalid") from exc
    if not host.is_global:
        raise ReachabilityUnavailable("automatic public host is not globally routable")
    return host.compressed
