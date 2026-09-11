import asyncio
import ssl
from dataclasses import replace
from types import SimpleNamespace

import pytest
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from qapp_backend.private_transport import quic_server as module
from qapp_backend.private_transport.framing import (
    ALPN, FRAME_ATTACH, FRAME_RELIABLE, Frame, FrameParser, encode_frame, encode_metadata,
)
from qapp_backend.private_transport.service import ensure_transport_certificate


@pytest.fixture
async def endpoint(config, tmp_path, monkeypatch):
    monkeypatch.setattr(module, "ATTACH_DEADLINE_SECONDS", 0.3)
    config = replace(config, private_transport_cert_path=tmp_path / "cert.pem",
                     private_transport_key_path=tmp_path / "key.pem")
    ensure_transport_certificate(config)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=[ALPN])
    configuration.load_cert_chain(config.private_transport_cert_path, config.private_transport_key_path)
    messages = []
    service = SimpleNamespace(
        attach=lambda *_: SimpleNamespace(session_id="test-session"),
        detach=lambda *_: None,
        handle_application_message=lambda *args: messages.append(args),
    )
    def factory():
        server = module.AdmissionQuicServer(
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: module.PrivateQuicProtocol(
                *args, service=service, admission=server, **kwargs),
        )
        return server
    transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
        factory, local_addr=("127.0.0.1", 0))
    client_config = QuicConfiguration(is_client=True, alpn_protocols=[ALPN], verify_mode=ssl.CERT_NONE)
    yield server, transport.get_extra_info("sockname")[1], client_config, messages
    server.close()
    await asyncio.sleep(0)


async def test_unauthenticated_connection_times_out_despite_traffic(endpoint):
    server, port, configuration, _ = endpoint
    async with connect("127.0.0.1", port, configuration=configuration) as client:
        assert len(server.pending) == 1
        async def activity():
            while True:
                await client.ping()
                await asyncio.sleep(0.03)
        task = asyncio.create_task(activity())
        await asyncio.wait_for(client.wait_closed(), 2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0.1)
        assert not server.pending


async def test_authenticated_connection_survives_deadline_and_full_pending_budget(endpoint, monkeypatch):
    server, port, configuration, messages = endpoint
    async with connect("127.0.0.1", port, configuration=configuration) as client:
        reader, writer = await client.create_stream()
        writer.write(encode_frame(Frame(FRAME_ATTACH, encode_metadata({}))))
        await asyncio.wait_for(reader.read(1024), 1)
        for _ in range(50):
            if not server.pending:
                break
            await asyncio.sleep(0.01)
        assert not server.pending
        # New connections are blocked, but existing CID traffic still routes.
        monkeypatch.setattr(module, "UNAUTHENTICATED_CONNECTION_LIMIT", 0)
        await asyncio.sleep(0.4)
        await asyncio.wait_for(client.ping(), 1)
        writer.write(encode_frame(Frame(
            FRAME_RELIABLE, encode_metadata({"messageId": "test"}), b"hello")))
        client.transmit()
        await asyncio.sleep(0.05)
        assert len(messages) == 1


async def test_retry_under_load_and_capacity_recovery(endpoint, monkeypatch):
    server, port, configuration, _ = endpoint
    placeholders = {object() for _ in range(64)}
    server.pending.update(placeholders)
    try:
        async with connect("127.0.0.1", port, configuration=configuration) as client:
            assert client._quic._retry_count == 1
    finally:
        server.pending.difference_update(placeholders)
    monkeypatch.setattr(module, "UNAUTHENTICATED_CONNECTION_LIMIT", 0)
    with pytest.raises(asyncio.TimeoutError):
        async with asyncio.timeout(0.1):
            async with connect("127.0.0.1", port, configuration=configuration):
                pytest.fail("connection admitted while full")
    monkeypatch.setattr(module, "UNAUTHENTICATED_CONNECTION_LIMIT", 256)
    async with connect("127.0.0.1", port, configuration=configuration) as client:
        await asyncio.wait_for(client.ping(), 1)


async def test_independent_streams_route_replies_and_drain_fin(endpoint):
    server, port, configuration, messages = endpoint
    async with connect("127.0.0.1", port, configuration=configuration) as client:
        attach_reader, attach = await client.create_stream()
        attach.write(encode_frame(Frame(FRAME_ATTACH, encode_metadata({}))))
        response = await asyncio.wait_for(attach_reader.read(1024), 1)
        assert FrameParser().feed(response)[0].metadata_json()['reliableStreams']
        protocol = next(p for p in server._protocols.values() if p.session is not None)
        stalled_reader, stalled = await client.create_stream()
        stalled.write(b'QP')  # An incomplete bulk frame must not block controls.
        control_reader, control = await client.create_stream()
        control.write(encode_frame(Frame(FRAME_RELIABLE, encode_metadata({'messageId': 'control'}), b'data')))
        transfer_reader, transfer = await client.create_stream()
        transfer.write(encode_frame(Frame(FRAME_RELIABLE, encode_metadata({'messageId': 'transfer'}), b'data')))
        transfer.write_eof()
        client.transmit()
        for _ in range(100):
            if len(messages) == 2:
                break
            await asyncio.sleep(0.01)
        assert {m[3] for m in messages} == {'control', 'transfer'}
        protocol.send_application('reliable', 'control', b'control response')
        protocol.send_application('reliable', 'transfer', b'transfer response')
        control_data = await asyncio.wait_for(control_reader.read(1024), 1)
        transfer_data = await asyncio.wait_for(transfer_reader.read(), 1)
        assert FrameParser().feed(control_data)[0].payload == b'control response'
        assert FrameParser().feed(transfer_data)[0].payload == b'transfer response'
        assert transfer.get_extra_info('stream_id') not in protocol._parsers
        # Cancel just the stalled stream. The connection and control stream live.
        client._quic.reset_stream(stalled.get_extra_info('stream_id'), 1)
        client.transmit()
        await asyncio.wait_for(client.ping(), 1)
        control.write(encode_frame(Frame(FRAME_RELIABLE, encode_metadata({'messageId': 'again'}), b'ok')))
        client.transmit()
        for _ in range(100):
            if 'again' in protocol._replies:
                break
            await asyncio.sleep(0.01)
        protocol.send_application('reliable', 'again', b'still connected')
        assert FrameParser().feed(await asyncio.wait_for(control_reader.read(1024), 1))[0].payload == b'still connected'


async def test_additional_stream_cannot_bypass_attach(endpoint):
    server, port, configuration, messages = endpoint
    async with connect("127.0.0.1", port, configuration=configuration) as client:
        _, first = await client.create_stream()
        first.write(b'QP')
        _, other = await client.create_stream()
        other.write(encode_frame(Frame(FRAME_RELIABLE, encode_metadata({'messageId': 'unauthorized'}), b'data')))
        client.transmit()
        await asyncio.wait_for(client.wait_closed(), 1)
        assert not messages


async def test_blocked_reply_buffer_resets_only_bulk_stream(endpoint):
    server, port, configuration, messages = endpoint
    configuration.max_stream_data = 1024
    async with connect("127.0.0.1", port, configuration=configuration) as client:
        reader, attach = await client.create_stream()
        attach.write(encode_frame(Frame(FRAME_ATTACH, encode_metadata({}))))
        await asyncio.wait_for(reader.read(1024), 1)
        protocol = next(p for p in server._protocols.values() if p.session is not None)
        _, bulk = await client.create_stream()
        for i in range(5):
            bulk.write(encode_frame(Frame(FRAME_RELIABLE, encode_metadata({'messageId': f'bulk-{i}'}), b'data')))
        client.transmit()
        for _ in range(100):
            if len(messages) == 5:
                break
            await asyncio.sleep(0.01)
        assert len(messages) == 5
        for i in range(5):
            protocol.send_application('reliable', f'bulk-{i}', b'x' * (64 * 1024))
        assert bulk.get_extra_info('stream_id') not in protocol._parsers
        assert protocol.session is not None
        control_reader, control = await client.create_stream()
        control.write(encode_frame(Frame(FRAME_RELIABLE, encode_metadata({'messageId': 'control'}), b'data')))
        client.transmit()
        for _ in range(100):
            if 'control' in protocol._replies:
                break
            await asyncio.sleep(0.01)
        protocol.send_application('reliable', 'control', b'ok')
        assert FrameParser().feed(await asyncio.wait_for(control_reader.read(1024), 1))[0].payload == b'ok'
