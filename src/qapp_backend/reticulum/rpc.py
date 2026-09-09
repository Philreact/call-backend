from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, replace
from typing import Any, Callable, TYPE_CHECKING

from qapp_backend.reticulum.errors import ProtocolError
from qapp_backend.reticulum.protocol import decode_rpc_request

if TYPE_CHECKING:
    from qapp_backend.reticulum.connection import PhysicalConnection
    from qapp_backend.reticulum.server import QAppServer
    from qapp_backend.reticulum.sessions import ApplicationSession


@dataclass(frozen=True, slots=True)
class RpcContext:
    server: "QAppServer"
    path: str
    request_id: str | None = None
    transport_request_id: bytes | None = None
    connection: "PhysicalConnection | None" = None
    remote_identity: Any = None
    session: "ApplicationSession | None" = None
    logical_connection_id: str | None = None


class RpcRouter:
    def __init__(self, max_payload: int, max_response: int):
        self.max_payload = max_payload
        self.max_response = max_response
        self.handlers: dict[str, Callable[[RpcContext, Any], Any]] = {}

    def register(self, path: str, handler: Callable[[RpcContext, Any], Any]) -> None:
        if not path.startswith("/") or path in self.handlers:
            raise ValueError("RPC path must be unique and start with '/'")
        if inspect.iscoroutinefunction(handler):
            raise TypeError("Reticulum RPC handlers must be synchronous")
        self.handlers[path] = handler

    def dispatch(self, path: str, wire_value: Any, context: RpcContext) -> Any:
        try:
            envelope = decode_rpc_request(wire_value)
            if len(envelope.payload) > self.max_payload:
                return self._error("payload_too_large", "RPC request exceeds size limit", envelope.request_id)
            context = replace(context, request_id=envelope.request_id)
            handler = self.handlers.get(path)
            if handler is None:
                return self._error("not_found", "Unknown RPC endpoint", envelope.request_id)
            result = handler(context, envelope.decode_payload())
            self._validate_response_size(result)
            return result
        except ProtocolError:
            return self._error("protocol_error", "Invalid RPC request envelope", None)
        except ResponseTooLarge:
            return self._error("response_too_large", "RPC response exceeds size limit", context.request_id)
        except Exception:
            return self._error("internal_error", "RPC handler failed", context.request_id)

    def _validate_response_size(self, response: Any) -> None:
        if isinstance(response, bytes):
            encoded = response
        else:
            encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > self.max_response:
            raise ResponseTooLarge

    @staticmethod
    def _error(code: str, message: str, request_id: str | None) -> dict[str, Any]:
        return {
            "error": {"code": code, "message": message},
            "requestId": request_id,
        }


class ResponseTooLarge(Exception):
    pass
