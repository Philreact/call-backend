from __future__ import annotations

import time
from typing import Any

from qapp_backend.call import CallService
from qapp_backend.files import install_files



def _require_authenticated(session: Any) -> None:
    if (
        session is None
        or session.provisional
        or not isinstance(session.authenticated_user, str)
        or not session.authenticated_user
    ):
        raise ValueError("authenticated session required")


def install_reference_service(server: Any) -> None:
    CallService(server)
    install_files(server)

    @server.rpc("/hello")
    def hello(ctx: Any, payload: Any) -> dict[str, Any]:
        _require_authenticated(ctx.session)
        name = payload.get("name", "world") if isinstance(payload, dict) else "world"
        return {"message": f"Hello, {name}", "requestId": ctx.request_id}

    @server.rpc("/echo")
    def echo(ctx: Any, payload: Any) -> Any:
        _require_authenticated(ctx.session)
        return payload

    @server.on_message("echo")
    def realtime_echo(ctx: Any, message: Any) -> None:
        _require_authenticated(ctx.session)
        ctx.session.send({"type": "echo", "received": message})

    @server.on_message("subscribe")
    def subscribe(ctx: Any, message: Any) -> None:
        _require_authenticated(ctx.session)
        if not isinstance(message, dict) or not isinstance(message.get("topic"), str):
            raise ValueError("subscribe payload requires topic")
        ctx.session.subscribe(message["topic"])
        ctx.session.send({"type": "subscribed", "topic": message["topic"]})

    @server.on_message("unsubscribe")
    def unsubscribe(ctx: Any, message: Any) -> None:
        _require_authenticated(ctx.session)
        if not isinstance(message, dict) or not isinstance(message.get("topic"), str):
            raise ValueError("unsubscribe payload requires topic")
        ctx.session.unsubscribe(message["topic"])
        ctx.session.send({"type": "unsubscribed", "topic": message["topic"]})

    @server.on_message("server_time")
    def server_time(ctx: Any, payload: Any) -> None:
        _require_authenticated(ctx.session)
        ctx.session.send({"type": "server_time", "payload": {"unix": time.time()}})

    @server.on_message("private_transport_echo")
    def private_transport_echo(ctx: Any, payload: Any) -> None:
        _require_authenticated(ctx.session)
        if not hasattr(ctx, "reply"):
            ctx.session.send({"type": "private_transport_echo", "received": payload})
            return
        ctx.reply({"type": "private_transport_echo", "received": payload})
