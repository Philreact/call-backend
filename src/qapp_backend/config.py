from __future__ import annotations

import json
import math
import os
import tomllib
from urllib.parse import urlparse
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

DEFAULT_RNS_CONFIG = """\
[reticulum]
enable_transport = False
share_instance = Yes
instance_name = qapp-backend-call

[logging]
loglevel = 4

[interfaces]
  [[Local Qortal Hub]]
  type = BackboneInterface
  enabled = Yes
  remote = host.docker.internal
  target_port = 4243
  network_name = qortal-hub
  passphrase = qortal-hub-community-mesh-v1

  [[Qortal Backbone Primary]]
  type = BackboneInterface
  enabled = Yes
  remote = phantom.mobilefabrik.com
  target_port = 4400
  network_name = qortal-hub

  [[Qortal Backbone]]
  type = BackboneInterface
  enabled = Yes
  remote = reticulum.qortal.link
  target_port = 4444
  network_name = qortal-hub

  [[Qortal Backbone 2]]
  type = BackboneInterface
  enabled = Yes
  remote = reticulum2.qortal.link
  target_port = 4444
  network_name = qortal-hub

  [[Qortal Backbone 3]]
  type = BackboneInterface
  enabled = Yes
  remote = reticulum3.qortal.link
  target_port = 4444
  network_name = qortal-hub

  [[Qortal Backbone 4]]
  type = BackboneInterface
  enabled = Yes
  remote = reticulum4.qortal.link
  target_port = 4444
  network_name = qortal-hub

  [[Qortal Backbone 5]]
  type = BackboneInterface
  enabled = Yes
  remote = reticulum5.qortal.link
  target_port = 4444
  network_name = qortal-hub
"""


@dataclass(frozen=True, slots=True)
class Config:
    production_deployment: str = "local"
    instance_lock_path: Path = Path(".qapp-backend-call-instance.lock")
    rns_config_dir: Path = Path("data/reticulum")
    data_dir: Path = Path("data/backend")
    identity_path: Path = Path("data/backend/identity")
    database_path: Path = Path("data/backend/backend.sqlite3")
    backup_path: Path = Path("data/backups")
    log_level: str = "INFO"
    max_frame_size: int = 256 * 1024
    max_queue_bytes: int = 2 * 1024 * 1024
    max_unacked_messages: int = 64
    dedup_cache_size: int = 512
    ack_timeout: float = 120.0
    max_transport_retries: int = 0
    session_ttl: float = 24 * 60 * 60
    unauthenticated_session_ttl: float = 2 * 60
    max_logical_sessions_per_link: int = 8
    max_unauthenticated_sessions: int = 256
    max_auth_challenges: int = 512
    max_new_sessions_per_link_per_minute: int = 16
    idle_connection_timeout: float = 5 * 60
    announce_interval: float = 15 * 60
    max_rpc_payload: int = 256 * 1024
    max_rpc_response: int = 1024 * 1024
    private_transport_bind_host: str = "127.0.0.1"
    private_transport_public_host: str = "127.0.0.1"
    private_transport_port: int = 0
    private_transport_server_name: str = "qapp-call-private-backend"
    private_transport_cert_path: Path = Path("data/backend/private-transport-cert.pem")
    private_transport_key_path: Path = Path("data/backend/private-transport-key.pem")
    network_state_path: Path = Path("data/network/reachability.json")
    call_media_public_host: str = "127.0.0.1"
    call_media_port: int = 4446
    call_media_grants_path: Path = Path("data/backend/call-media-grants")
    call_media_revocations_path: Path = Path("data/backend/call-media-revocations")
    private_transport_attach_ttl: float = 30.0
    private_transport_bootstraps_per_minute: int = 4
    private_transport_bootstraps_per_user_per_minute: int = 8
    private_transport_max_unused_per_session: int = 4
    private_transport_max_unused_global: int = 1024
    enforce_qapp_allowlist: bool = False
    allowed_qapps: tuple[tuple[str, str], ...] = ()
    access_mode: str = "public"
    allowed_group_ids: tuple[int, ...] = ()
    core_url_bases: tuple[str, ...] = ()
    access_revalidate_interval: float = 30 * 60
    access_outage_grace: float = 60 * 60

    def validate(self) -> None:
        if self.production_deployment not in {"local", "docker"}:
            raise ValueError("production_deployment must be local or docker")
        positive = (
            "max_frame_size", "max_queue_bytes", "max_unacked_messages",
            "dedup_cache_size", "ack_timeout", "session_ttl",
            "unauthenticated_session_ttl", "max_logical_sessions_per_link",
            "max_unauthenticated_sessions", "max_auth_challenges",
            "max_new_sessions_per_link_per_minute", "idle_connection_timeout",
            "announce_interval", "max_rpc_payload", "max_rpc_response",
        )
        for name in positive:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.unauthenticated_session_ttl > self.session_ttl:
            raise ValueError("unauthenticated_session_ttl cannot exceed session_ttl")
        if self.max_transport_retries != 0:
            raise ValueError("protocol v1 requires max_transport_retries = 0")
        if self.max_frame_size > 256 * 1024:
            raise ValueError("max_frame_size cannot exceed 262144")
        import ipaddress
        try:
            ipaddress.ip_address(self.private_transport_bind_host)
            for host in (
                self.private_transport_public_host,
                self.call_media_public_host,
            ):
                if host.strip().lower() != "auto":
                    ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(
                "private transport hosts must be literal IP addresses or auto"
            ) from exc
        if not 0 <= self.private_transport_port <= 65535:
            raise ValueError("private_transport_port must be between 0 and 65535")
        if self.private_transport_public_host.strip().lower() == "auto" and self.private_transport_port == 0:
            raise ValueError("automatic reachability requires a fixed private_transport_port")
        if not 1 <= self.call_media_port <= 65535:
            raise ValueError("call_media_port must be between 1 and 65535")
        if not self.private_transport_server_name.strip():
            raise ValueError("private_transport_server_name is invalid")
        if not math.isfinite(self.private_transport_attach_ttl) or not 5 <= self.private_transport_attach_ttl <= 300:
            raise ValueError("private_transport_attach_ttl must be between 5 and 300 seconds")
        limits = (
            self.private_transport_bootstraps_per_minute,
            self.private_transport_bootstraps_per_user_per_minute,
            self.private_transport_max_unused_per_session,
            self.private_transport_max_unused_global,
        )
        if any(value <= 0 for value in limits):
            raise ValueError("private transport limits must be positive")
        if self.private_transport_max_unused_global < self.private_transport_max_unused_per_session:
            raise ValueError("private transport global token limit is too small")
        from qapp_backend.auth.qortal_identity import normalize_qapp_identity
        for identity in self.allowed_qapps:
            if normalize_qapp_identity(*identity) != identity:
                raise ValueError("allowed_qapps entries must use canonical identities")
        if self.access_mode not in {"public", "groups"}:
            raise ValueError("access_mode must be public or groups")
        if len(self.allowed_group_ids) > 16 or any(
            not isinstance(group_id, int) or isinstance(group_id, bool) or group_id <= 0
            for group_id in self.allowed_group_ids
        ) or len(set(self.allowed_group_ids)) != len(self.allowed_group_ids):
            raise ValueError("allowed_group_ids must contain up to 16 unique positive integers")
        if self.access_mode == "public" and self.allowed_group_ids:
            raise ValueError("public access cannot have group restrictions")
        if self.access_mode == "groups" and not self.allowed_group_ids:
            raise ValueError("groups access requires at least one allowed_group_id")
        if len(self.core_url_bases) > 8 or (
            self.access_mode == "groups" and not self.core_url_bases
        ):
            raise ValueError("groups access requires 1 to 8 Core URLs")
        for base in self.core_url_bases:
            parsed = urlparse(base)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("core_url_bases contains an invalid Core URL")
            local_http = parsed.hostname in {
                "127.0.0.1", "localhost", "::1", "host.docker.internal"
            }
            if parsed.scheme == "http" and not local_http:
                raise ValueError("remote Core URLs must use HTTPS")
        if not 60 <= self.access_revalidate_interval <= 12 * 60 * 60:
            raise ValueError("access_revalidate_interval must be between 60 seconds and 12 hours")
        if not self.access_revalidate_interval <= self.access_outage_grace <= 24 * 60 * 60:
            raise ValueError("access_outage_grace must be at least the revalidation interval and at most 24 hours")

    def ensure_directories(self) -> None:
        self.rns_config_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_rns_config()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.identity_path.parent.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.private_transport_cert_path.parent.mkdir(parents=True, exist_ok=True)
        self.private_transport_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.network_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.call_media_grants_path.mkdir(parents=True, exist_ok=True)
        self.call_media_revocations_path.mkdir(parents=True, exist_ok=True)

    def _ensure_rns_config(self) -> None:
        path = self.rns_config_dir / "config"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(DEFAULT_RNS_CONFIG)


_PATH_FIELDS = {
    "instance_lock_path", "rns_config_dir", "data_dir", "identity_path",
    "database_path", "backup_path", "private_transport_cert_path",
    "private_transport_key_path", "network_state_path", "call_media_grants_path",
    "call_media_revocations_path",
}
_ENV_NAMES = {
    "production_deployment": "BACKEND_PRODUCTION_DEPLOYMENT",
    "instance_lock_path": "BACKEND_INSTANCE_LOCK_PATH",
    "rns_config_dir": "RNS_CONFIG_DIR",
    "data_dir": "BACKEND_DATA_DIR",
    "identity_path": "BACKEND_IDENTITY_PATH",
    "database_path": "BACKEND_DATABASE_PATH",
    "backup_path": "BACKEND_BACKUP_PATH",
    "log_level": "LOG_LEVEL",
    "max_frame_size": "MAX_FRAME_SIZE",
    "max_queue_bytes": "MAX_QUEUE_BYTES",
    "max_unacked_messages": "MAX_UNACKED_MESSAGES",
    "dedup_cache_size": "DEDUP_CACHE_SIZE",
    "ack_timeout": "ACK_TIMEOUT",
    "max_transport_retries": "MAX_TRANSPORT_RETRIES",
    "session_ttl": "SESSION_TTL",
    "unauthenticated_session_ttl": "UNAUTHENTICATED_SESSION_TTL",
    "max_logical_sessions_per_link": "MAX_LOGICAL_SESSIONS_PER_LINK",
    "max_unauthenticated_sessions": "MAX_UNAUTHENTICATED_SESSIONS",
    "max_auth_challenges": "MAX_AUTH_CHALLENGES",
    "max_new_sessions_per_link_per_minute": "MAX_NEW_SESSIONS_PER_LINK_PER_MINUTE",
    "idle_connection_timeout": "IDLE_CONNECTION_TIMEOUT",
    "announce_interval": "ANNOUNCE_INTERVAL",
    "max_rpc_payload": "MAX_RPC_PAYLOAD",
    "max_rpc_response": "MAX_RPC_RESPONSE",
    "private_transport_bind_host": "PRIVATE_TRANSPORT_BIND_HOST",
    "private_transport_public_host": "PRIVATE_TRANSPORT_PUBLIC_HOST",
    "private_transport_port": "PRIVATE_TRANSPORT_PORT",
    "private_transport_server_name": "PRIVATE_TRANSPORT_SERVER_NAME",
    "private_transport_cert_path": "PRIVATE_TRANSPORT_CERT_PATH",
    "private_transport_key_path": "PRIVATE_TRANSPORT_KEY_PATH",
    "network_state_path": "BACKEND_NETWORK_STATE_PATH",
    "call_media_public_host": "CALL_MEDIA_PUBLIC_HOST",
    "call_media_port": "CALL_MEDIA_PORT",
    "call_media_grants_path": "CALL_MEDIA_GRANTS_PATH",
    "call_media_revocations_path": "CALL_MEDIA_REVOCATIONS_PATH",
    "private_transport_attach_ttl": "PRIVATE_TRANSPORT_ATTACH_TTL",
    "private_transport_bootstraps_per_minute": "PRIVATE_TRANSPORT_BOOTSTRAPS_PER_MINUTE",
    "private_transport_bootstraps_per_user_per_minute": "PRIVATE_TRANSPORT_BOOTSTRAPS_PER_USER_PER_MINUTE",
    "private_transport_max_unused_per_session": "PRIVATE_TRANSPORT_MAX_UNUSED_PER_SESSION",
    "private_transport_max_unused_global": "PRIVATE_TRANSPORT_MAX_UNUSED_GLOBAL",
    "enforce_qapp_allowlist": "ENFORCE_QAPP_ALLOWLIST",
    "allowed_qapps": "ALLOWED_QAPPS",
    "access_mode": "BACKEND_ACCESS_MODE",
    "allowed_group_ids": "BACKEND_ALLOWED_GROUP_IDS",
    "core_url_bases": "BACKEND_CORE_URL_BASES",
    "access_revalidate_interval": "BACKEND_ACCESS_REVALIDATE_INTERVAL",
    "access_outage_grace": "BACKEND_ACCESS_OUTAGE_GRACE",
}


def _coerce(value: Any, default: Any, name: str) -> Any:
    if name in {"allowed_group_ids", "core_url_bases"}:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{name} must be a JSON array") from exc
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"{name} must be an array")
        if name == "allowed_group_ids":
            if any(not isinstance(item, int) or isinstance(item, bool) for item in value):
                raise ValueError("allowed_group_ids must contain integers")
            return tuple(value)
        if any(not isinstance(item, str) for item in value):
            raise ValueError("core_url_bases must contain strings")
        return tuple(item.rstrip("/") for item in value)
    if name == "allowed_qapps":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("allowed_qapps must be a JSON array") from exc
        if not isinstance(value, (list, tuple)):
            raise ValueError("allowed_qapps must be an array")
        from qapp_backend.auth.qortal_identity import normalize_qapp_identity
        normalized = []
        for entry in value:
            if not isinstance(entry, dict) or set(entry) - {"name", "service"}:
                raise ValueError("allowed_qapps entries must contain only name and service")
            normalized.append(normalize_qapp_identity(entry.get("name"), entry.get("service")))
        return tuple(normalized)
    if name in _PATH_FIELDS:
        return Path(value)
    if isinstance(default, bool):
        normalized = str(value).strip().lower()
        if normalized not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
            raise ValueError(f"{name} must be a boolean")
        return normalized in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        return int(value)
    if isinstance(default, float):
        return float(value)
    return str(value)


def load_config(path: str | Path | None = None) -> Config:
    values: dict[str, Any] = {}
    if path:
        with Path(path).open("rb") as stream:
            document = tomllib.load(stream)
        section = document.get("backend", document)
        if not isinstance(section, dict):
            raise ValueError("configuration [backend] must be a table")
        values.update(section)
    defaults = Config()
    valid = {field.name for field in fields(Config)}
    unknown = values.keys() - valid
    if unknown:
        raise ValueError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    for name in valid:
        raw = os.getenv(_ENV_NAMES[name])
        if raw is not None:
            values[name] = raw
        if name in values:
            values[name] = _coerce(values[name], getattr(defaults, name), name)
    config = Config(**values)
    config.validate()
    return config
