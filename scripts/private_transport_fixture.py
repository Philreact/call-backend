"""Step 4 integration harness around the real backend bootstrap and QUIC service."""

from __future__ import annotations

import json
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
        allowed_qapps=(("qapp-ui-call", "APP"),),
    )
    config.ensure_directories()
    server = QAppServer(config)
    install_authentication_service(server)
    install_reference_service(server)

    server.database.open()
    server.destination_hash = "0123456789abcdef0123456789abcdef"
    server.private_transport.start()
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
                write(
                    {
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
        server.database.close()
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
