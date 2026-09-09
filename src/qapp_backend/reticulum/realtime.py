from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from qapp_backend.reticulum.connection import PhysicalConnection
    from qapp_backend.reticulum.server import QAppServer
    from qapp_backend.reticulum.sessions import ApplicationSession


@dataclass(frozen=True, slots=True)
class MessageContext:
    server: "QAppServer"
    connection: "PhysicalConnection"
    session: "ApplicationSession"
    message_id: int
    qapp_connection_id: str

    def publish(self, topic: str, payload: dict[str, Any]) -> int:
        return self.server.publish(topic, payload)


@dataclass(frozen=True, slots=True)
class PrivateMessageContext:
    server: "QAppServer"
    session: "ApplicationSession"
    message_id: str
    qapp_connection_id: str
    lane: str
    transport: Any

    def publish(self, topic: str, payload: dict[str, Any]) -> int:
        return self.server.publish(topic, payload)

    def reply(
        self,
        payload: Any,
        *,
        lane: str | None = None,
        message_id: str | None = None,
    ) -> None:
        self.transport.send_json(
            lane or self.lane, message_id or self.message_id, payload
        )
