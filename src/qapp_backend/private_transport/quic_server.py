from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, TYPE_CHECKING

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.buffer import Buffer
from aioquic.quic.packet import pull_quic_header
from aioquic.quic.retry import QuicRetryTokenHandler
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    ProtocolNegotiated,
    QuicEvent,
    StreamDataReceived,
)

from qapp_backend.private_transport.framing import (
    ALPN,
    FRAME_ATTACH,
    FRAME_ATTACHED,
    FRAME_RELIABLE,
    Frame,
    FrameParser,
    FramingError,
    decode_datagram,
    encode_datagram,
    encode_frame,
    encode_metadata,
)

if TYPE_CHECKING:
    from qapp_backend.private_transport.service import PrivateTransportService


logger = logging.getLogger(__name__)
PROTOCOL_ERROR = 0x100
ATTACH_REJECTED = 0x101
PRIVATE_QUIC_IDLE_TIMEOUT_SECONDS = 120.0
UNAUTHENTICATED_CONNECTION_LIMIT = 256
ATTACH_DEADLINE_SECONDS = 10.0


class AdmissionQuicServer(QuicServer):
    """Bound new connection state without throttling shared relay addresses.

    aioquic has no pre-allocation admission hook. Keep this small adapter covered
    by wire-level tests when upgrading aioquic: _protocols is its CID routing map.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.pending: set[PrivateQuicProtocol] = set()
        self._admission_retry = QuicRetryTokenHandler()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        try:
            header = pull_quic_header(
                Buffer(data=data),
                host_cid_length=self._configuration.connection_id_length,
            )
        except ValueError:
            return
        if header.destination_cid not in self._protocols:
            if len(self.pending) >= UNAUTHENTICATED_CONNECTION_LIMIT:
                return
        # Also validate outstanding Retry tokens after load has subsided.
        self._retry = self._admission_retry if (
            len(self.pending) >= 64 or header.token
        ) else None
        super().datagram_received(data, addr)


class PrivateQuicProtocol(QuicConnectionProtocol):
    def __init__(self, *args: Any, service: "PrivateTransportService", admission: AdmissionQuicServer | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.service = service
        self.parser = FrameParser()
        self.stream_id: int | None = None
        self.session: Any = None
        self.peer_address: Any = None
        self._detached = False
        self._attach_attempted = False
        self._admission = admission
        if admission is not None:
            admission.pending.add(self)
        self._auth_deadline = self._loop.time() + ATTACH_DEADLINE_SECONDS
        self._auth_timer = self._loop.call_later(
            ATTACH_DEADLINE_SECONDS, self._fail, ATTACH_REJECTED,
            "authentication deadline exceeded",
        )

    def _release_admission(self) -> None:
        self._auth_timer.cancel()
        if self._admission is not None:
            self._admission.pending.discard(self)

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if self.peer_address is None:
            self.peer_address = addr
        super().datagram_received(data, addr)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol != ALPN:
                self.close(PROTOCOL_ERROR, "unsupported protocol")
            return
        if isinstance(event, StreamDataReceived):
            self._stream_data(event)
            return
        if isinstance(event, DatagramFrameReceived):
            self._datagram(event.data)
            return
        if isinstance(event, ConnectionTerminated):
            self._release_admission()
            self._detach()

    def _stream_data(self, event: StreamDataReceived) -> None:
        if self.stream_id is None:
            self.stream_id = event.stream_id
        if event.stream_id != self.stream_id or event.end_stream:
            self._fail(PROTOCOL_ERROR, "persistent stream required")
            return
        try:
            for frame in self.parser.feed(event.data):
                if self.session is None:
                    if self._attach_attempted:
                        raise FramingError("only one ATTACH attempt is allowed")
                    self._attach_attempted = True
                    self._attach(frame)
                    if self.session is None:
                        return
                elif frame.frame_type == FRAME_RELIABLE:
                    metadata = frame.metadata_json()
                    message_id = metadata.get("messageId") if isinstance(metadata, dict) else None
                    if not isinstance(message_id, str) or not message_id:
                        raise FramingError("reliable message ID is invalid")
                    self.service.handle_application_message(
                        self, self.session, "reliable", message_id, frame.payload
                    )
                else:
                    raise FramingError("unexpected reliable frame")
        except Exception:
            self._fail(PROTOCOL_ERROR, "invalid private transport frame")

    def _attach(self, frame: Frame) -> None:
        if self._loop.time() >= self._auth_deadline:
            raise FramingError("authentication deadline exceeded")
        if frame.frame_type != FRAME_ATTACH or frame.payload:
            raise FramingError("ATTACH must be the first frame")
        metadata = frame.metadata_json()
        logical_session_id = (
            metadata.get("logicalSessionId") if isinstance(metadata, dict) else ""
        )
        try:
            self.session = self.service.attach(self, metadata)
        except ValueError:
            response = {
                "ok": False,
                "logicalSessionId": logical_session_id,
                "transportGeneration": 1,
                "reliable": True,
                "datagrams": True,
                "code": "ATTACH_TOKEN_REJECTED",
            }
            self._send_frame(Frame(FRAME_ATTACHED, encode_metadata(response)))
            self._loop.call_later(
                0.05, lambda: self._fail(ATTACH_REJECTED, "attach rejected")
            )
            return
        response = {
            "ok": True,
            "logicalSessionId": self.session.session_id,
            "transportGeneration": 1,
            "reliable": True,
            "datagrams": True,
        }
        self._send_frame(Frame(FRAME_ATTACHED, encode_metadata(response)))
        self._release_admission()

    def _datagram(self, data: bytes) -> None:
        if self.session is None:
            self._fail(ATTACH_REJECTED, "attach required")
            return
        try:
            message_id, payload = decode_datagram(data)
            self.service.handle_application_message(
                self, self.session, "datagram", message_id, payload
            )
        except Exception:
            self._fail(PROTOCOL_ERROR, "invalid private transport datagram")

    def send_application(
        self, lane: str, message_id: str, payload: bytes
    ) -> None:
        if self.session is None or self.stream_id is None:
            raise RuntimeError("private transport is not attached")
        if lane == "datagram":
            self._quic.send_datagram_frame(encode_datagram(message_id, payload))
        elif lane == "reliable":
            self._send_frame(
                Frame(
                    FRAME_RELIABLE,
                    encode_metadata({"messageId": message_id}),
                    payload,
                )
            )
            return
        else:
            raise ValueError("unsupported private transport lane")
        self.transmit()

    def send_json(self, lane: str, message_id: str, value: Any) -> None:
        from qapp_backend.private_transport.service import encode_application_payload

        payload = encode_application_payload(value)
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is self._loop:
            self.send_application(lane, message_id, payload)
        else:
            self._loop.call_soon_threadsafe(
                self.send_application, lane, message_id, payload
            )

    def request_close(self, code: int, reason: str) -> None:
        self._loop.call_soon_threadsafe(self._fail, code, reason)

    def _send_frame(self, frame: Frame) -> None:
        if self.stream_id is None:
            raise RuntimeError("private transport stream is unavailable")
        self._quic.send_stream_data(self.stream_id, encode_frame(frame))
        self.transmit()

    def _fail(self, code: int, reason: str) -> None:
        self.close(code, reason)
        self._detach()

    def _detach(self) -> None:
        if self._detached:
            return
        self._detached = True
        if self.session is not None:
            self.service.detach(self.session, self)


class PrivateQuicServer:
    def __init__(
        self,
        service: "PrivateTransportService",
        *,
        host: str,
        port: int,
        certificate_path: str,
        key_path: str,
    ) -> None:
        self.service = service
        self.host = host
        self.port = port
        self.certificate_path = certificate_path
        self.key_path = key_path
        self.bound_port: int | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: Any = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        if self._thread is not None:
            if self.bound_port is None:
                raise RuntimeError("private QUIC server has not finished starting")
            return self.bound_port
        ready = threading.Event()
        failure: list[BaseException] = []

        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            try:
                configuration = QuicConfiguration(
                    alpn_protocols=[ALPN],
                    is_client=False,
                    idle_timeout=PRIVATE_QUIC_IDLE_TIMEOUT_SECONDS,
                    max_datagram_size=1200,
                    max_datagram_frame_size=1200,
                )
                configuration.load_cert_chain(
                    self.certificate_path, self.key_path
                )
                def make_server() -> AdmissionQuicServer:
                    server = AdmissionQuicServer(
                        configuration=configuration,
                        create_protocol=lambda *args, **kwargs: PrivateQuicProtocol(
                            *args, service=self.service, admission=server, **kwargs
                        ),
                    )
                    return server

                _, self._server = loop.run_until_complete(
                    loop.create_datagram_endpoint(
                        make_server, local_addr=(self.host, self.port)
                    )
                )
                transport = getattr(self._server, "_transport", None)
                socket_name = transport.get_extra_info("sockname")
                self.bound_port = int(socket_name[1])
            except BaseException as exc:
                failure.append(exc)
            finally:
                ready.set()
            if not failure:
                loop.run_forever()
            if self._server is not None:
                self._server.close()
            loop.close()

        self._thread = threading.Thread(
            target=run, name="qapp-private-quic", daemon=True
        )
        self._thread.start()
        if not ready.wait(10.0):
            raise TimeoutError("private QUIC server startup timed out")
        if failure:
            self._thread = None
            raise RuntimeError("private QUIC server failed to start") from failure[0]
        if self.bound_port is None:
            raise RuntimeError("private QUIC server did not report its port")
        return self.bound_port

    def stop(self) -> None:
        loop = self._loop
        thread = self._thread
        if loop is None or thread is None:
            return
        if self._server is not None:
            loop.call_soon_threadsafe(self._server.close)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5.0)
        self._thread = None
        self._loop = None
        self._server = None
