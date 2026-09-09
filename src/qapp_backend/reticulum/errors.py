class ProtocolError(Exception):
    """The peer sent an invalid protocol frame."""


class BackpressureError(Exception):
    """The bounded transport queue cannot accept another message."""


class ConnectionClosedError(Exception):
    """The physical transport is closed."""


class RpcError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

