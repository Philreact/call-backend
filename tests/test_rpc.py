import base64

from qapp_backend.reticulum.rpc import RpcContext, RpcRouter


def context(path="/x"):
    return RpcContext(None, path)  # type: ignore[arg-type]


def envelope(payload: bytes, request_id="request-1", encoding="json"):
    return {
        "version": 1,
        "requestId": request_id,
        "encoding": encoding,
        "payloadBase64": base64.b64encode(payload).decode("ascii"),
    }


def test_valid_unknown_exception_and_invalid_envelope():
    router = RpcRouter(100, 200)
    router.register("/x", lambda ctx, payload: {"payload": payload, "requestId": ctx.request_id})
    router.register("/boom", lambda ctx, payload: 1 / 0)
    assert router.dispatch("/x", envelope(b'{"a":1}'), context()) == {
        "payload": {"a": 1}, "requestId": "request-1"
    }
    assert router.dispatch("/missing", envelope(b"null"), context())["error"]["code"] == "not_found"
    assert router.dispatch("/boom", envelope(b"null"), context())["error"]["code"] == "internal_error"
    assert router.dispatch("/x", {"version": 9}, context())["error"]["code"] == "protocol_error"


def test_binary_payload_and_limits():
    router = RpcRouter(4, 100)
    router.register("/binary", lambda ctx, payload: payload)
    router.register("/large", lambda ctx, payload: "x" * 1000)
    assert router.dispatch("/binary", envelope(b"\x00\xff", encoding="base64"), context()) == b"\x00\xff"
    assert router.dispatch("/binary", envelope(b"12345"), context())["error"]["code"] == "payload_too_large"
    assert router.dispatch("/large", envelope(b"null"), context())["error"]["code"] == "response_too_large"

