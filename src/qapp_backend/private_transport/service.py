from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qapp_backend.auth.qortal_identity import normalize_qapp_identity
from qapp_backend.auth.group_access import GroupAccessDenied, GroupAccessUnavailable
from qapp_backend.private_transport.authorization import (
    AttachRejected,
    AttachTokenAuthority,
    BootstrapRateLimited,
)
from qapp_backend.private_transport.framing import PROTOCOL_VERSION
from qapp_backend.private_transport.native_server import NativeQuicServer as PrivateQuicServer
from qapp_backend.private_transport.reachability import (
    ReachabilityUnavailable,
    resolve_public_host,
)
from qapp_backend.reticulum.realtime import PrivateMessageContext

if TYPE_CHECKING:
    from qapp_backend.config import Config
    from qapp_backend.reticulum.rpc import RpcContext
    from qapp_backend.reticulum.server import QAppServer


logger = logging.getLogger(__name__)
BOOTSTRAP_PATH = "/qortal/private-transport/bootstrap/v1"
BOOTSTRAP_VERSION = 1
TRANSPORT = "quic-masque-inner-v1"
PURPOSES = frozenset(("game", "file-transfer", "realtime"))
DEVELOPMENT_MESSAGE_TYPES = frozenset(("private_transport_echo", "file_request"))
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


def owner_binding_hash(
    qapp_identity: tuple[str, str],
    logical_connection_id: str,
    backend_destination: str,
    logical_session_id: str,
    nonce: str,
    purpose: str,
) -> str:
    name, service = qapp_identity
    value = (
        "qortal-private-owner-v2\0"
        f"{name}\0{service}\0{logical_connection_id}\0{backend_destination}\0"
        f"{logical_session_id}\0{nonce}\0{purpose}"
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PrivateTransportService:
    def __init__(self, server: "QAppServer", config: "Config") -> None:
        self.server = server
        self.config = config
        self.tokens = AttachTokenAuthority(
            ttl=config.private_transport_attach_ttl,
            per_session_per_minute=config.private_transport_bootstraps_per_minute,
            per_user_per_minute=config.private_transport_bootstraps_per_user_per_minute,
            max_unused_per_session=config.private_transport_max_unused_per_session,
            max_unused_global=config.private_transport_max_unused_global,
        )
        self.quic_server: PrivateQuicServer | None = None
        self._listener_port: int | None = None
        self.endpoint: str | None = None
        self.certificate_sha256: str | None = None
        self.latest_peer_address: Any = None
        self.media_endpoint: str | None = None
        self._media_grant_files: dict[str, set[Path]] = {}
        self.server.rpc_router.register(BOOTSTRAP_PATH, self.bootstrap)

    def start(self) -> None:
        if self.quic_server is not None:
            return
        certificate = ensure_transport_certificate(self.config)
        self.certificate_sha256 = hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        quic_server = PrivateQuicServer(
            self,
            host=self.config.private_transport_bind_host,
            port=self.config.private_transport_port,
            certificate_path=str(self.config.private_transport_cert_path),
            key_path=str(self.config.private_transport_key_path),
        )
        port = quic_server.start()
        self._listener_port = port
        try:
            self._refresh_endpoints()
        except ReachabilityUnavailable:
            quic_server.stop()
            self._listener_port = None
            raise
        self.quic_server = quic_server
        logger.info(
            "private transport listener started",
            extra={"event": "private_transport_started"},
        )

    def stop(self) -> None:
        for session in self.server.sessions.all():
            self.invalidate_session(session, close_attached=True)
        if self.quic_server is not None:
            self.quic_server.stop()
            self.quic_server = None
        self._listener_port = None
        self.endpoint = None
        self.media_endpoint = None

    @staticmethod
    def _endpoint(host: str, port: int) -> str:
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def _refresh_endpoints(self) -> None:
        if self._listener_port is None:
            raise ReachabilityUnavailable("private transport listener is unavailable")
        public_host = resolve_public_host(
            self.config.private_transport_public_host,
            self._listener_port,
            self.config.network_state_path,
        )
        media_host = resolve_public_host(
            self.config.call_media_public_host,
            self.config.call_media_port,
            self.config.network_state_path,
        )
        self.endpoint = self._endpoint(public_host, self._listener_port)
        self.media_endpoint = self._endpoint(media_host, self.config.call_media_port)

    def _uses_automatic_reachability(self) -> bool:
        return any(
            host.strip().lower() == "auto"
            for host in (
                self.config.private_transport_public_host,
                self.config.call_media_public_host,
            )
        )

    def bootstrap(self, ctx: "RpcContext", payload: Any) -> dict[str, Any]:
        with self.server._session_lock:
            error = self._validate_bootstrap_context(ctx, payload)
            if error is not None:
                if error in {"backend_access_denied", "backend_access_unavailable"}:
                    authentication = getattr(self.server, "authentication_service", None)
                    if authentication is not None and ctx.session is not None:
                        authentication.revoke(ctx.session, error.upper())
                return self._error(error)
            if self._uses_automatic_reachability():
                try:
                    self._refresh_endpoints()
                except ReachabilityUnavailable:
                    self.endpoint = None
                    self.media_endpoint = None
            assert isinstance(payload, dict)
            assert ctx.connection is not None
            assert ctx.logical_connection_id is not None
            session = self.server.logical_sessions[ctx.logical_connection_id]
            qapp_identity = normalize_qapp_identity(
                *(session.metadata.get("qapp_identity") or ())
            )
            nonce = payload["nonce"]
            purpose = payload["purpose"]
            destination = self.server.destination_hash
            if (
                not isinstance(destination, str)
                or self.endpoint is None
                or self.certificate_sha256 is None
                or (purpose == "realtime" and self.media_endpoint is None)
            ):
                return self._error("transport_unavailable")
            if purpose == "realtime" and not isinstance(
                session.metadata.get("call_room_id"), str
            ):
                return self._error("call_room_required")
            binding = owner_binding_hash(
                qapp_identity,
                ctx.logical_connection_id,
                destination,
                session.session_id,
                nonce,
                purpose,
            )
            try:
                token, grant = self.tokens.issue(
                    logical_session_id=session.session_id,
                    logical_connection_id=ctx.logical_connection_id,
                    authenticated_user=session.authenticated_user,
                    qapp_identity=qapp_identity,
                    purpose=purpose,
                    owner_binding_hash=binding,
                    nonce=nonce,
                )
            except BootstrapRateLimited:
                return self._error("bootstrap_rate_limited")
            if purpose == "realtime":
                self._write_media_grant(token, grant, session)
                # The MOQT process is now the sole authority for this token.
                # Keeping a second valid copy here would violate one-time use.
                self.tokens.release(token)
        logger.info(
            "private transport bootstrap issued",
            extra={
                "event": "private_transport_bootstrap",
                "session_id": session.session_id[:12],
            },
        )
        return {
            "version": BOOTSTRAP_VERSION,
            "transport": TRANSPORT,
            "logicalSessionId": session.session_id,
            "backendRnsDestination": destination,
            "backendTransportEndpoint": (
                self.media_endpoint if purpose == "realtime" else self.endpoint
            ),
            "backendTransportServerName": self.config.private_transport_server_name,
            "backendTransportCertSha256": self.certificate_sha256,
            "attachToken": token,
            "expiresAt": int(grant.expires_at * 1000),
            "nonce": nonce,
            "ownerBindingHash": binding,
            "applicationProtocol": (
                "moqt-18" if purpose == "realtime" else "qortal-private/1"
            ),
            "supportedFeatures": {
                "reliable": True,
                "datagrams": True,
                "moqt": purpose == "realtime",
            },
        }

    def _write_media_grant(self, token: str, grant: Any, session: Any) -> None:
        room_id = session.metadata["call_room_id"]
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        directory = Path(self.config.call_media_grants_path)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{digest}.json"
        temporary = directory / f".{digest}.{secrets.token_hex(8)}.tmp"
        document = {
            "version": 1,
            "tokenSha256": digest,
            "logicalSessionId": grant.logical_session_id,
            "authenticatedUser": grant.authenticated_user,
            "qappName": grant.qapp_identity[0],
            "qappService": grant.qapp_identity[1],
            "purpose": grant.purpose,
            "roomId": room_id,
            "participantId": grant.authenticated_user,
            "expiresAt": int(grant.expires_at * 1000),
        }
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, separators=(",", ":"), sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        self._media_grant_files.setdefault(grant.logical_session_id, set()).add(path)

    def _validate_bootstrap_context(
        self, ctx: "RpcContext", payload: Any
    ) -> str | None:
        if not isinstance(payload, dict) or set(payload) != {
            "version",
            "transport",
            "nonce",
            "purpose",
        }:
            return "invalid_request"
        if payload.get("version") != BOOTSTRAP_VERSION:
            return "unsupported_version"
        if payload.get("transport") != TRANSPORT:
            return "unsupported_transport"
        if payload.get("purpose") not in PURPOSES:
            return "unsupported_purpose"
        if not isinstance(payload.get("nonce"), str) or not _NONCE.fullmatch(
            payload["nonce"]
        ):
            return "invalid_nonce"
        connection = ctx.connection
        logical_id = ctx.logical_connection_id
        if (
            connection is None
            or connection.closed
            or not isinstance(logical_id, str)
            or logical_id not in connection.logical_connection_ids
        ):
            return "unauthenticated"
        session = self.server.logical_sessions.get(logical_id)
        if (
            session is None
            or ctx.session is not session
            or session.connection is not connection
            or session.provisional
            or not isinstance(session.authenticated_user, str)
            or not session.authenticated_user
            or session.expires_at <= time.time()
        ):
            return "unauthenticated"
        try:
            qapp_identity = normalize_qapp_identity(
                *(session.metadata.get("qapp_identity") or ())
            )
        except (TypeError, ValueError):
            return "unauthenticated"
        if tuple(session.metadata.get("qapp_identity") or ()) != qapp_identity:
            return "unauthenticated"
        authentication = getattr(self.server, "authentication_service", None)
        if authentication is not None:
            try:
                authentication.require_authorized(session)
            except GroupAccessDenied:
                return "backend_access_denied"
            except GroupAccessUnavailable:
                return "backend_access_unavailable"
        if session.private_transport is not None:
            return "transport_already_attached"
        return None

    def attach(self, transport: Any, metadata: Any) -> Any:
        if not isinstance(metadata, dict) or set(metadata) != {
            "protocolVersion",
            "logicalSessionId",
            "attachToken",
            "nonce",
            "purpose",
            "ownerBindingHash",
        }:
            raise AttachRejected("attach token rejected")
        if metadata.get("protocolVersion") != PROTOCOL_VERSION:
            raise AttachRejected("attach token rejected")
        for key in (
            "logicalSessionId",
            "attachToken",
            "nonce",
            "purpose",
            "ownerBindingHash",
        ):
            if not isinstance(metadata.get(key), str):
                raise AttachRejected("attach token rejected")
        with self.server._session_lock:
            _grant, session = self.tokens.consume(
                metadata["attachToken"],
                logical_session_id=metadata["logicalSessionId"],
                purpose=metadata["purpose"],
                owner_binding_hash=metadata["ownerBindingHash"],
                nonce=metadata["nonce"],
                session_lookup=self.server.sessions.get,
            )
            if session.private_transport is not None:
                raise AttachRejected("attach token rejected")
            session.private_transport = transport
            self.latest_peer_address = transport.peer_address
        logger.info(
            "private transport attached",
            extra={
                "event": "private_transport_attached",
                "session_id": session.session_id[:12],
                "transport_generation": 1,
            },
        )
        return session

    def detach(self, session: Any, transport: Any) -> None:
        with self.server._session_lock:
            if session.private_transport is not transport:
                return
            session.private_transport = None
        logger.info(
            "private transport detached",
            extra={
                "event": "private_transport_detached",
                "session_id": session.session_id[:12],
            },
        )

    def invalidate_session(self, session: Any, *, close_attached: bool) -> None:
        with self.server._session_lock:
            self.tokens.invalidate_session(session.session_id)
            transport = session.private_transport
            session.private_transport = None
            grant_files = self._media_grant_files.pop(session.session_id, set())
            revoke_media = bool(grant_files) or isinstance(
                session.metadata.get("call_room_id"), str
            )
        for path in grant_files:
            path.unlink(missing_ok=True)
        if revoke_media:
            self._write_media_revocation(session.session_id)
        if close_attached and transport is not None:
            request_close = getattr(transport, "request_close", None)
            if callable(request_close):
                request_close(0x102, "application session unavailable")
            else:
                transport.close(0x102, "application session unavailable")

    def _write_media_revocation(self, session_id: str) -> None:
        if not session_id:
            return
        directory = Path(self.config.call_media_revocations_path)
        directory.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        path = directory / f"{digest}.json"
        temporary = directory / f".{digest}.{secrets.token_hex(8)}.tmp"
        document = {
            "version": 1,
            "logicalSessionId": session_id,
            "expiresAt": int((time.time() + 10 * 60) * 1000),
        }
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, separators=(",", ":"), sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError:
            temporary.unlink(missing_ok=True)
            logger.exception("could not write media revocation marker")

    def handle_application_message(
        self,
        transport: Any,
        session: Any,
        lane: str,
        message_id: str,
        payload: bytes,
    ) -> None:
        with self.server._session_lock:
            if session.private_transport is not transport:
                raise ValueError("private transport is detached")
            value = decode_application_payload(payload)
            if not isinstance(value, (dict, bytes)):
                raise ValueError("private application payload must be an object")
            logical_id = session.metadata.get("qapp_connection_id")
            if not isinstance(logical_id, str):
                raise ValueError("logical session is unavailable")
            message_type = 'file_binary' if isinstance(value, bytes) else value.get("type")
            if message_type not in DEVELOPMENT_MESSAGE_TYPES and message_type != 'file_binary':
                raise ValueError("private application message is unsupported")
            handler = self.server.message_handlers.get(
                message_type, self.server.message_handlers.get("*")
            )
            if handler is None:
                raise ValueError("private application message is unsupported")
            context = PrivateMessageContext(
                self.server,
                session,
                message_id,
                logical_id,
                lane,
                transport,
            )
            self.server.invoke_message_handler(handler, context, value)

    @staticmethod
    def _error(code: str) -> dict[str, Any]:
        return {"error": {"code": code, "message": "Private transport bootstrap rejected"}}


def decode_application_payload(payload: bytes) -> Any:
    if not payload:
        raise ValueError("application payload is empty")
    if payload[0] == 0:
        if len(payload) > 64 * 1024:
            raise ValueError('JSON application payload exceeds limit')
        try:
            return json.loads(payload[1:].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON application payload") from exc
    if payload[0] == 1:
        return payload[1:]
    raise ValueError("unsupported application payload encoding")


def encode_application_payload(value: Any) -> bytes:
    if isinstance(value, bytes):
        return b"\x01" + value
    return b"\x00" + json.dumps(
        value, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def ensure_transport_certificate(config: "Config") -> x509.Certificate:
    certificate_path = Path(config.private_transport_cert_path)
    key_path = Path(config.private_transport_key_path)
    if certificate_path.exists() != key_path.exists():
        raise RuntimeError("private transport certificate/key pair is incomplete")
    if not certificate_path.exists():
        if config.production_deployment != "local":
            raise RuntimeError(
                "production private transport requires an operator-provisioned certificate"
            )
        _generate_development_certificate(
            certificate_path, key_path, config.private_transport_server_name
        )
    try:
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
    except (OSError, ValueError) as exc:
        raise RuntimeError("invalid private transport certificate/key") from exc
    if (
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        != certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ):
        raise RuntimeError("private transport certificate key mismatch")
    now = datetime.now(UTC)
    if (
        certificate.not_valid_before_utc > now
        or certificate.not_valid_after_utc <= now
    ):
        raise RuntimeError("private transport certificate is outside its validity period")
    try:
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound as exc:
        raise RuntimeError("private transport certificate has no DNS identity") from exc
    if config.private_transport_server_name not in names:
        raise RuntimeError("private transport certificate identity mismatch")
    os.chmod(key_path, 0o600)
    return certificate


def _generate_development_certificate(
    certificate_path: Path, key_path: Path, server_name: str
) -> None:
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(server_name)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(key_fd, "wb") as stream:
            stream.write(key_bytes)
        cert_fd = os.open(
            certificate_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
        )
        with os.fdopen(cert_fd, "wb") as stream:
            stream.write(certificate_bytes)
    except BaseException:
        key_path.unlink(missing_ok=True)
        certificate_path.unlink(missing_ok=True)
        raise
