"""Real native listener, real Python authorization/storage, existing wire format."""
import asyncio
import base64
import json
import ssl
import struct
import time

import pytest
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from qapp_backend.auth import install_authentication_service
from qapp_backend.auth.group_access import GroupAccessDenied
from qapp_backend.files import install_files, CHUNK_SIZE
from qapp_backend.private_transport.framing import Frame, encode_frame, encode_metadata
from .test_service import authenticated_server, request, attach_metadata
from test_files_binary import wire, FILE_ID


async def read_frame(reader):
    header = await asyncio.wait_for(reader.readexactly(12), 5)
    magic, version, kind, metadata_len, payload_len = struct.unpack('>4sBBHI', header)
    assert magic == b'QP3F' and version == 1
    metadata = json.loads(await reader.readexactly(metadata_len))
    payload = await reader.readexactly(payload_len)
    return kind, metadata, payload


@pytest.mark.asyncio
async def test_native_upload_resume_download_revocation(config):
    config.ensure_directories()
    server, connection, session, context = authenticated_server(config)
    install_authentication_service(server)
    install_files(server)
    server.private_transport.start()
    descriptor = server.private_transport.bootstrap(context, request())
    configuration = QuicConfiguration(is_client=True, alpn_protocols=['qortal-private/1'],
                                    max_datagram_frame_size=1200, verify_mode=ssl.CERT_NONE)
    try:
        async with connect('127.0.0.1', server.private_transport.quic_server.bound_port,
                           configuration=configuration) as client:
            reader, writer = await client.create_stream()
            writer.write(encode_frame(Frame(1, encode_metadata(attach_metadata(descriptor)))))
            assert (await read_frame(reader))[1]['ok']
            next_id = 0
            async def send(value, target=None):
                nonlocal next_id
                next_id += 1
                rr, ww = target or (reader, writer)
                payload = b'\1' + value if isinstance(value, bytes) else b'\0' + json.dumps({'type': 'file_request', **value}).encode()
                ww.write(encode_frame(Frame(3, encode_metadata({'messageId': str(next_id)}), payload)))
                kind, meta, response = await read_frame(rr)
                assert kind == 3 and meta['messageId'] == str(next_id)
                assert response[0] == 0
                return json.loads(response[1:])
            result = await send(dict(op='create', id=FILE_ID, size=2*CHUNK_SIZE, ttl=60,
                                    envelope=base64.b64encode(b'envelope').decode(),
                                    manifest=base64.b64encode(b'manifest').decode()))
            assert result['ok'], result
            bulk = await client.create_stream()
            chunks = [(i, bytes([i+1]) * (CHUNK_SIZE+28)) for i in range(2)]
            # Prove Python never reads/writes bulk bytes on this path.
            def forbidden(*args, **kwargs):
                raise AssertionError('bulk bytes reached Python')
            server.file_store.put_batch = forbidden
            server.file_store.write_chunks = forbidden
            assert (await send(wire(chunks), bulk))['result']['received'] == [0, 1]
            assert (await send(wire(chunks), bulk))['ok']
            conflict = wire([(0, b'z' * (CHUNK_SIZE+28))])
            assert (await send(conflict, bulk))['error'] == 'CHUNK_CONFLICT'
            authorize = server.authentication_service.require_authorized
            def deny(_):
                raise GroupAccessDenied('not a member')
            server.authentication_service.require_authorized = deny
            assert (await send(wire(chunks), bulk))['error'] == 'BACKEND_ACCESS_DENIED'
            server.authentication_service.require_authorized = authorize
            assert (await send(dict(op='status', id=FILE_ID)))['result']['received'] == [0, 1]
            fin_reader, fin_writer = await client.create_stream()
            fin_writer.write(encode_frame(Frame(3, encode_metadata({'messageId': 'finish-fin'}),
                b'\0' + json.dumps(dict(type='file_request', op='finish', id=FILE_ID)).encode())))
            fin_writer.write_eof()
            assert json.loads((await read_frame(fin_reader))[2][1:])['ok']
            assert await asyncio.wait_for(fin_reader.read(), 3) == b''
            for index, content in chunks:
                downloaded = await send(dict(op='get', id=FILE_ID, index=index), bulk)
                assert base64.b64decode(downloaded['result']['chunk']) == content
            server.private_transport.invalidate_session(session, close_attached=True)
            await asyncio.wait_for(client.wait_closed(), 3)
            assert session.private_transport is None
        # The old credential remains consumed even after the QUIC connection ends.
        async with connect('127.0.0.1', server.private_transport.quic_server.bound_port,
                           configuration=configuration) as client:
            reader, writer = await client.create_stream()
            writer.write(encode_frame(Frame(1, encode_metadata(attach_metadata(descriptor)))))
            assert (await read_frame(reader))[1]['ok'] is False
    finally:
        server.private_transport.stop()
        for shutdown in server.shutdown_handlers:
            shutdown()
        server.database.close()


@pytest.mark.asyncio
async def test_native_concurrent_connections_keep_ownership_isolated(config):
    from qapp_backend.reticulum.rpc import RpcContext
    from qapp_backend.private_transport.service import BOOTSTRAP_PATH
    config.ensure_directories()
    server, connection, _, _ = authenticated_server(config)
    install_authentication_service(server)
    install_files(server)
    server.private_transport.start()
    configuration = QuicConfiguration(is_client=True, alpn_protocols=['qortal-private/1'],
                                    max_datagram_frame_size=1200, verify_mode=ssl.CERT_NONE)
    async def transfer(number):
        logical_id = f'concurrent-{number}'
        connection.logical_connection_ids.add(logical_id)
        session, _ = server.sessions.create(connection, provisional=True)
        session.metadata.update(qapp_connection_id=logical_id, qapp_identity=['qapp-ui-call', 'APP'])
        server.sessions.promote(session, f'owner-{number}')
        server.logical_sessions[logical_id] = session
        ctx = RpcContext(server, BOOTSTRAP_PATH, connection=connection, session=session, logical_connection_id=logical_id)
        grant = server.private_transport.bootstrap(ctx, request())
        file_id = f'{number+1:02x}' * 16
        server.file_store.request(session.authenticated_user, dict(op='create', id=file_id,
            size=16*CHUNK_SIZE, ttl=60, envelope='eA==', manifest='eA=='))
        async with connect('127.0.0.1', server.private_transport.quic_server.bound_port,
                           configuration=configuration) as client:
            reader, writer = await client.create_stream()
            writer.write(encode_frame(Frame(1, encode_metadata(attach_metadata(grant)))))
            assert (await read_frame(reader))[1]['ok']
            content = bytes([number+1]) * (CHUNK_SIZE+28)
            batch = wire([(i, content) for i in range(16)])
            batch = batch[:4] + bytes.fromhex(file_id) + batch[20:]
            writer.write(encode_frame(Frame(3, encode_metadata({'messageId':'upload'}), b'\1'+batch)))
            assert json.loads((await read_frame(reader))[2][1:])['result']['received'] == list(range(16))
            writer.write(encode_frame(Frame(3, encode_metadata({'messageId':'other-owner'}),
                b'\0'+json.dumps(dict(type='file_request',op='status',id=f'{(number+1)%4+1:02x}'*16)).encode())))
            assert json.loads((await read_frame(reader))[2][1:])['error'] == 'ACCESS_DENIED'
    try:
        await asyncio.gather(*(transfer(n) for n in range(4)))
    finally:
        server.private_transport.stop()
        for shutdown in server.shutdown_handlers:
            shutdown()
        server.database.close()


def test_native_child_crash_stops_backend_instead_of_advertising_dead_listener(config):
    config.ensure_directories()
    server, _, _, _ = authenticated_server(config)
    install_authentication_service(server)
    install_files(server)
    server.private_transport.start()
    try:
        child = server.private_transport.quic_server.process
        child.kill()
        child.wait(timeout=3)
        assert server._stop.wait(3)
    finally:
        server.private_transport.stop()
        for shutdown in server.shutdown_handlers:
            shutdown()
        server.database.close()
