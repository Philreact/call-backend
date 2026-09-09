#!/usr/bin/env python3
"""Run a real local Reticulum Link between Desktop v1 wire code and the backend."""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time

import RNS


def free_port() -> int:
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return int(stream.getsockname()[1])


def write_config(path: Path, interface: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "config").write_text(
        "[reticulum]\n"
        "  enable_transport = No\n"
        "  share_instance = No\n"
        "[logging]\n"
        "  loglevel = 2\n"
        "[interfaces]\n"
        f"{interface}\n",
        encoding="utf-8",
    )


def load_desktop_bridge(desktop: Path):
    bridge_path = desktop / "electron" / "resources" / "presence_bridge.py"
    spec = importlib.util.spec_from_file_location("desktop_qapp_bridge", bridge_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Desktop bridge: {bridge_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_all(writer, data: bytes) -> None:
    offset = 0
    deadline = time.monotonic() + 10
    while offset < len(data):
        if time.monotonic() >= deadline:
            raise TimeoutError("Buffer write timed out")
        written = int(writer.write(data[offset:]) or 0)
        if written <= 0:
            time.sleep(0.01)
            continue
        offset += written
    writer.flush()


def wait_for(predicate, timeout: float, message: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError(message)


def run(desktop: Path) -> dict[str, object]:
    bridge = load_desktop_bridge(desktop)
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="qapp-interop-") as root_value:
        root = Path(root_value)
        backend_rns = root / "backend-rns"
        client_rns = root / "client-rns"
        backend_data = root / "backend-data"
        write_config(
            backend_rns,
            "  [[Local TCP Server]]\n"
            "    type = TCPServerInterface\n"
            "    enabled = Yes\n"
            "    listen_ip = 127.0.0.1\n"
            f"    listen_port = {port}",
        )
        write_config(
            client_rns,
            "  [[Local TCP Client]]\n"
            "    type = TCPClientInterface\n"
            "    enabled = Yes\n"
            "    target_host = 127.0.0.1\n"
            f"    target_port = {port}",
        )
        environment = os.environ.copy()
        environment.update({
            "RNS_CONFIG_DIR": str(backend_rns),
            "BACKEND_DATA_DIR": str(backend_data),
            "BACKEND_IDENTITY_PATH": str(backend_data / "identity"),
            "BACKEND_DATABASE_PATH": str(backend_data / "backend.sqlite3"),
            "ANNOUNCE_INTERVAL": "1",
            "LOG_LEVEL": "INFO",
            "REFERENCE_SERVICE_ENABLED": "true",
        })
        backend = subprocess.Popen(
            [sys.executable, "-m", "qapp_backend.main"],
            cwd=Path(__file__).parents[1],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        log_lines: list[str] = []

        def read_logs(stream):
            for line in stream:
                log_lines.append(line.rstrip())

        assert backend.stderr is not None
        log_thread = threading.Thread(target=read_logs, args=(backend.stderr,), daemon=True)
        log_thread.start()
        try:
            destination = wait_for(
                lambda: next(
                    (
                        json.loads(line)["message"].split()[1]
                        for line in list(log_lines)
                        if line.startswith("{") and "destination " in line and " aspect=" in line
                    ),
                    None,
                ),
                10,
                "backend destination was not logged",
            )
            RNS.Reticulum(configdir=str(client_rns))
            destination_hash = bytes.fromhex(destination)
            identity = wait_for(
                lambda: RNS.Identity.recall(destination_hash),
                15,
                "client did not receive backend announce",
            )
            outbound = RNS.Destination(
                identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "qortal-hub-v3",
                "qapp-backend",
                "v1",
            )
            established = threading.Event()
            link = RNS.Link(outbound, established_callback=lambda _link: established.set())
            if not established.wait(15):
                raise TimeoutError("Reticulum Link did not establish")

            rpc_result: dict[str, object] = {}
            rpc_done = threading.Event()

            def rpc_received(receipt):
                value = receipt.get_response()
                if isinstance(value, dict):
                    rpc_result.update(value)
                rpc_done.set()
            request_data = {
                "version": 1,
                "requestId": "request-0001",
                "encoding": "json",
                "payloadBase64": base64.b64encode(b'{"name":"Alice"}').decode("ascii"),
            }
            link.request(
                "/hello",
                data=request_data,
                response_callback=rpc_received,
                failed_callback=lambda _value=None: rpc_done.set(),
                timeout=10,
            )
            if not rpc_done.wait(12):
                raise TimeoutError("RPC did not complete")
            expected_rpc = {"message": "Hello, Alice", "requestId": "request-0001"}
            if rpc_result != expected_rpc:
                raise AssertionError(f"unexpected RPC result: {rpc_result!r}")

            channel = link.get_channel()
            writer = RNS.Buffer.create_writer(bridge._QAPP_RNS_STREAM_ID, channel)
            reader = RNS.Buffer.create_reader(bridge._QAPP_RNS_STREAM_ID, channel)
            received_chunks: queue.Queue[bytes] = queue.Queue()

            def read_buffer():
                while True:
                    chunk = reader.read(64 * 1024)
                    if chunk == b"":
                        return
                    if chunk:
                        received_chunks.put(bytes(chunk))

            threading.Thread(target=read_buffer, daemon=True).start()
            logical_id = "rns-00000000-0000-0000-0000-000000000000"
            app_body = b'{"type":"echo","value":42,"text":"hello"}'
            envelope = json.dumps({
                "connectionId": logical_id,
                "payloadBase64": base64.b64encode(app_body).decode("ascii"),
                "encoding": "json",
            }, separators=(",", ":")).encode("utf-8")
            inbound_id = 0x0102030405060708
            write_all(writer, bridge._qapp_rns_frame(bridge._QAPP_RNS_DATA, inbound_id, envelope))

            buffered = bytearray()
            ack_seen = False
            push_seen = False
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and not (ack_seen and push_seen):
                try:
                    buffered.extend(received_chunks.get(timeout=0.5))
                except queue.Empty:
                    continue
                while len(buffered) >= bridge._QAPP_RNS_HEADER.size:
                    version, kind, message_id, length = bridge._QAPP_RNS_HEADER.unpack_from(buffered)
                    total = bridge._QAPP_RNS_HEADER.size + length
                    if len(buffered) < total:
                        break
                    payload = bytes(buffered[bridge._QAPP_RNS_HEADER.size:total])
                    del buffered[:total]
                    if version != 1:
                        raise AssertionError("unexpected frame version")
                    if kind == bridge._QAPP_RNS_ACK and message_id == inbound_id:
                        ack_seen = True
                    elif kind == bridge._QAPP_RNS_DATA:
                        pushed = json.loads(payload.decode("utf-8"))
                        pushed_body = json.loads(base64.b64decode(pushed["payloadBase64"]))
                        if pushed["connectionId"] == logical_id and pushed_body["type"] == "echo":
                            push_seen = True
                        write_all(writer, bridge._qapp_rns_frame(bridge._QAPP_RNS_ACK, message_id))
            if not ack_seen or not push_seen:
                raise AssertionError(f"realtime incomplete: ack={ack_seen}, push={push_seen}")
            link.teardown()
            return {
                "destination": destination,
                "rpc": True,
                "ack": ack_seen,
                "server_push": push_seen,
                "buffer_stream_id": bridge._QAPP_RNS_STREAM_ID,
                "backend_logged_protocol_error": any("protocol_error" in line for line in log_lines),
            }
        finally:
            backend.terminate()
            try:
                backend.wait(timeout=8)
            except subprocess.TimeoutExpired:
                backend.kill()
                backend.wait(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--desktop",
        type=Path,
        default=Path.home() / "Desktop" / "desktop-app-official" / "qortal-desktop",
    )
    args = parser.parse_args()
    result = run(args.desktop.expanduser().resolve())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
