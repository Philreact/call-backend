"""Step 4 integration harness around the real backend bootstrap and QUIC service."""

from __future__ import annotations

import json
import os
import socket
import time
import cProfile
import pstats
import threading
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qapp_backend.app import install_reference_service
from qapp_backend.auth import install_authentication_service
from qapp_backend.auth.qortal_identity import (
    base58_encode,
    canonical_proof,
    qortal_address,
)
from qapp_backend.config import Config
from qapp_backend.private_transport.service import BOOTSTRAP_PATH
from qapp_backend.reticulum.connection import PhysicalConnection
from qapp_backend.reticulum.realtime import MessageContext
from qapp_backend.reticulum.rpc import RpcContext
from qapp_backend.reticulum.server import QAppServer


def write(value: Any) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def authenticate_session(
    server: QAppServer,
    connection: PhysicalConnection,
    session: Any,
    logical_id: str,
) -> None:
    challenge_handler = server.rpc_router.handlers["/auth/challenge"]
    context = MessageContext(server, connection, session, 1, logical_id)
    challenge = challenge_handler(
        RpcContext(
            server,
            "/auth/challenge",
            connection=connection,
            session=session,
            logical_connection_id=logical_id,
        ),
        {},
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    signed_fields = {
        **challenge,
        "address": qortal_address(public_key),
        "publicKey": base58_encode(public_key),
        "qappName": "qapp-ui-call",
        "qappService": "APP",
    }
    proof = {
        **signed_fields,
        "signature": base58_encode(private_key.sign(canonical_proof(signed_fields))),
    }
    server.invoke_message_handler(
        server.message_handlers["AUTHENTICATE"],
        context,
        {
            "type": "AUTHENTICATE",
            "requestId": "fixture-auth",
            "payload": {"proof": proof},
        },
    )
    if (
        session.provisional
        or session.authenticated_user != signed_fields["address"]
        or session.metadata.get("qapp_identity") != ["qapp-ui-call", "APP"]
    ):
        raise RuntimeError("Q-App authentication did not promote the session")


def main() -> int:
    # Historical comparison only. Production always starts the native listener.
    if os.environ.get("QORTAL_STEP4_BULK_BENCH") == "1":
        import qapp_backend.private_transport.service as service_module
        from qapp_backend.private_transport.quic_server import PrivateQuicServer
        service_module.PrivateQuicServer = PrivateQuicServer
    if os.environ.get("QORTAL_STEP4_UVLOOP") == "1":
        import asyncio
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    if os.environ.get("QORTAL_STEP4_COALESCE") == "1":
        from qapp_backend.private_transport.quic_server import PrivateQuicProtocol
        def receive_coalesced(self, data, addr):
            if self.peer_address is None:
                self.peer_address = addr
            self._quic.receive_datagram(data, addr, now=self._loop.time())
            self._process_events()
            self._transmit_soon()
        PrivateQuicProtocol.datagram_received = receive_coalesced
    temporary = tempfile.TemporaryDirectory(prefix="qapp-step4-")
    root = Path(temporary.name)
    config = replace(
        Config(),
        rns_config_dir=root / "rns",
        data_dir=root / "backend",
        identity_path=root / "backend" / "identity",
        database_path=root / "backend" / "database.sqlite3",
        private_transport_cert_path=root / "backend" / "private-cert.pem",
        private_transport_key_path=root / "backend" / "private-key.pem",
        network_state_path=root / "network" / "reachability.json",
        call_media_grants_path=root / "backend" / "call-media-grants",
        call_media_revocations_path=root / "backend" / "call-media-revocations",
        allowed_qapps=(("qapp-ui-call", "APP"),),
    )
    config.ensure_directories()
    server = QAppServer(config)
    install_authentication_service(server)
    install_reference_service(server)

    server.database.open()
    server.destination_hash = "0123456789abcdef0123456789abcdef"
    server.private_transport.start()
    # Opt-in transport benchmark: real auth, framing and aioquic; a tiny reply
    # excludes file storage so it cannot be mistaken for an end-to-end file test.
    bench = os.environ.get("QORTAL_STEP4_BULK_BENCH") == "1"
    if bench:
        server.message_handlers["file_binary"] = lambda ctx, data: ctx.reply({"receivedBytes": len(data)})
        udp = server.private_transport.quic_server._server._transport.get_extra_info("socket")
        requested = int(os.environ.get("QORTAL_STEP4_RECEIVE_BYTES", "0"))
        if requested:
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, requested)
        cpu_start = time.process_time()
        profiler = None
        if os.environ.get("QORTAL_STEP4_PROFILE") == "1":
            profiler = cProfile.Profile()
            server.private_transport.quic_server._loop.call_soon_threadsafe(profiler.enable)
    connection = PhysicalConnection(
        lambda _data: None,
        config,
        server._application_message,
        server._connection_closed,
        on_logical_close=server._logical_connection_closed,
    )
    server.connections[connection.id] = connection
    session = None
    context = None
    write(
        {
            "backendAddress": server.private_transport.endpoint,
            "backendDestination": server.destination_hash,
            "backendCertSha256": server.private_transport.certificate_sha256,
        }
    )
    try:
        for line in sys.stdin:
            command = json.loads(line)
            operation = command.get("operation")
            if operation == "bindAuthenticatedSession":
                logical_id = command["logicalConnectionId"]
                connection.logical_connection_ids.add(logical_id)
                session, _resume = server.sessions.create(
                    connection, provisional=True
                )
                session.metadata["qapp_connection_id"] = logical_id
                server.logical_sessions[logical_id] = session
                authenticate_session(server, connection, session, logical_id)
                context = RpcContext(
                    server,
                    BOOTSTRAP_PATH,
                    connection=connection,
                    session=session,
                    logical_connection_id=logical_id,
                )
                write(
                    {
                        "ok": True,
                        "logicalSessionId": session.session_id,
                        "authentication": "signed-qapp-auth",
                    }
                )
            elif operation == "bootstrap":
                if context is None:
                    write({"error": {"code": "unauthenticated"}})
                else:
                    write(server.private_transport.bootstrap(context, command["payload"]))
            elif operation == "reticulumStatus":
                write(
                    {
                        "usable": bool(
                            session is not None
                            and session.connection is connection
                            and not connection.closed
                        ),
                        "logicalSessionId": session.session_id if session else None,
                    }
                )
            elif operation == "stats":
                peer = server.private_transport.latest_peer_address
                diagnostic = {}
                if bench:
                    port = udp.getsockname()[1]
                    rows = Path("/proc/net/udp").read_text().splitlines()[1:] if Path("/proc/net/udp").exists() else []
                    drops = next((int(row.split()[-1]) for row in rows if row.split()[1].endswith(f":{port:04X}")), None)
                    diagnostic = {"receiveBytes": udp.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), "kernelDrops": drops, "cpuSeconds": time.process_time() - cpu_start}
                    if profiler is not None:
                        stopped = threading.Event()
                        def stop_profile():
                            profiler.disable()
                            stopped.set()
                        server.private_transport.quic_server._loop.call_soon_threadsafe(stop_profile)
                        stopped.wait(5)
                        profile = pstats.Stats(profiler)
                        diagnostic["profile"] = [{"function":f"{Path(k[0]).name}:{k[1]}:{k[2]}","calls":v[1],"selfSeconds":round(v[2],3),"cumulativeSeconds":round(v[3],3)} for k,v in sorted(profile.stats.items(),key=lambda row:row[1][2],reverse=True)[:18]]
                write(
                    {
                        "diagnostic": diagnostic,
                        "logicalSessionId": session.session_id if session else None,
                        "privateAttached": bool(
                            session is not None
                            and session.private_transport is not None
                        ),
                        "backendPeer": (
                            f"{peer[0]}:{peer[1]}" if peer is not None else ""
                        ),
                        "outstandingTokens": (
                            server.private_transport.tokens.outstanding(
                                session.session_id
                            )
                            if session
                            else 0
                        ),
                    }
                )
            elif operation == "disconnectReticulum":
                if session is not None:
                    server._disconnect_logical_session(
                        connection, session.metadata["qapp_connection_id"]
                    )
                write({"ok": True})
            elif operation == "shutdown":
                write({"ok": True})
                break
            else:
                write({"error": {"code": "unknown_operation"}})
    finally:
        server.private_transport.stop()
        for handler in server.shutdown_handlers:
            handler()
        server.database.close()
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
