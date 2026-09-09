from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from qapp_backend.reticulum.errors import ProtocolError

PayloadEncoding = Literal["json", "base64"]
MAX_LOGICAL_CONNECTION_ID_LENGTH = 128


class ControlType(StrEnum):
    PING = "PING"
    PONG = "PONG"
    CLOSE = "CLOSE"


@dataclass(frozen=True, slots=True)
class ControlMessage:
    kind: ControlType
    connection_id: str | None = None

    def encode(self) -> bytes:
        value = {"type": self.kind}
        if self.kind is ControlType.CLOSE:
            if (
                not isinstance(self.connection_id, str)
                or not 1 <= len(self.connection_id) <= MAX_LOGICAL_CONNECTION_ID_LENGTH
            ):
                raise ValueError("CLOSE requires a valid logical connection ID")
            value["connectionId"] = self.connection_id
        elif self.connection_id is not None:
            raise ValueError("connectionId is only valid for CLOSE")
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    @classmethod
    def decode(cls, payload: bytes) -> "ControlMessage":
        try:
            value = json.loads(payload.decode("utf-8"))
            if not isinstance(value, dict) or "type" not in value:
                raise ValueError
            kind = ControlType(value["type"])
            if kind is ControlType.CLOSE:
                connection_id = value.get("connectionId")
                if (
                    set(value) != {"type", "connectionId"}
                    or not isinstance(connection_id, str)
                    or not 1 <= len(connection_id) <= MAX_LOGICAL_CONNECTION_ID_LENGTH
                ):
                    raise ValueError
                return cls(kind, connection_id)
            if set(value) != {"type"}:
                raise ValueError
            return cls(kind)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise ProtocolError("malformed or unsupported control message") from exc


@dataclass(frozen=True, slots=True)
class DataEnvelope:
    connection_id: str
    encoding: PayloadEncoding
    payload: bytes

    def decode_payload(self) -> Any:
        if self.encoding == "base64":
            return self.payload
        try:
            return json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("DATA JSON payload is invalid") from exc


def encode_data_envelope(
    connection_id: str,
    payload: Any,
    encoding: PayloadEncoding | None = None,
) -> bytes:
    if not connection_id:
        raise ValueError("connection_id is required")
    if encoding is None:
        encoding = "base64" if isinstance(payload, (bytes, bytearray, memoryview)) else "json"
    if encoding == "base64":
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("base64 payload must be bytes-like")
        raw = bytes(payload)
    elif encoding == "json":
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    else:
        raise ValueError("unsupported payload encoding")
    envelope = {
        "connectionId": connection_id,
        "payloadBase64": base64.b64encode(raw).decode("ascii"),
        "encoding": encoding,
    }
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_data_envelope(payload: bytes) -> DataEnvelope:
    try:
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError
        connection_id = value["connectionId"]
        encoding = value["encoding"]
        encoded = value["payloadBase64"]
        if (
            not isinstance(connection_id, str)
            or not 1 <= len(connection_id) <= MAX_LOGICAL_CONNECTION_ID_LENGTH
        ):
            raise ValueError
        if encoding not in ("json", "base64") or not isinstance(encoded, str):
            raise ValueError
        raw = base64.b64decode(encoded, validate=True)
        return DataEnvelope(connection_id, encoding, raw)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise ProtocolError("malformed DATA envelope") from exc


@dataclass(frozen=True, slots=True)
class RpcRequestEnvelope:
    version: int
    request_id: str
    encoding: PayloadEncoding
    payload: bytes

    def decode_payload(self) -> Any:
        if self.encoding == "base64":
            return self.payload
        try:
            return json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("RPC JSON payload is invalid") from exc


def decode_rpc_request(value: Any) -> RpcRequestEnvelope:
    try:
        if not isinstance(value, dict) or value.get("version") != 1:
            raise ValueError
        request_id = value.get("requestId")
        encoding = value.get("encoding")
        encoded = value.get("payloadBase64")
        if not isinstance(request_id, str) or encoding not in ("json", "base64") or not isinstance(encoded, str):
            raise ValueError
        payload = base64.b64decode(encoded, validate=True)
        return RpcRequestEnvelope(1, request_id, encoding, payload)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ProtocolError("malformed RPC request envelope") from exc
