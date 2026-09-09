import json
import time
from dataclasses import replace

import pytest

from qapp_backend.private_transport.reachability import (
    ReachabilityUnavailable,
    resolve_public_host,
)


def write_state(path, **overrides):
    value = {
        "version": 1,
        "publicHost": "8.8.8.8",
        "ports": [4445, 4446],
        "mode": "upnp",
        "updatedAt": int(time.time() * 1000),
    }
    value.update(overrides)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_explicit_host_does_not_require_network_state(tmp_path):
    assert resolve_public_host("127.0.0.1", 4445, tmp_path / "missing") == "127.0.0.1"


def test_auto_host_uses_fresh_state_for_the_requested_port(tmp_path):
    path = tmp_path / "reachability.json"
    write_state(path)
    assert resolve_public_host("auto", 4446, path) == "8.8.8.8"


@pytest.mark.parametrize(
    "overrides",
    [
        {"publicHost": "127.0.0.1"},
        {"ports": [4445]},
        {"updatedAt": 0},
        {"mode": "unknown"},
        {"extra": True},
    ],
)
def test_auto_host_rejects_unusable_state(tmp_path, overrides):
    path = tmp_path / "reachability.json"
    write_state(path, **overrides)
    with pytest.raises(ReachabilityUnavailable):
        resolve_public_host("auto", 4446, path)


def test_auto_configuration_requires_a_fixed_listener_port(config):
    with pytest.raises(ValueError, match="requires a fixed"):
        replace(config, private_transport_public_host="auto").validate()
