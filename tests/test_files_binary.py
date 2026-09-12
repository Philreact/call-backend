import base64
import struct
import time

import pytest

from qapp_backend.files import FileStore, FileError, CHUNK_SIZE, decode_upload_batch

FILE_ID = 'ab' * 16


def wire(chunks):
    return b'QFB1' + bytes.fromhex(FILE_ID) + struct.pack('>H', len(chunks)) + b''.join(
        struct.pack('>II', index, len(chunk)) + chunk for index, chunk in chunks)


@pytest.fixture
def store(tmp_path):
    value = FileStore(tmp_path)
    value.request('owner', dict(op='create', id=FILE_ID, size=16 * CHUNK_SIZE, ttl=60,
        envelope=base64.b64encode(b'envelope').decode(), manifest=base64.b64encode(b'manifest').decode()))
    yield value
    value.db.close()


def test_binary_batch_commits_once_and_is_compatible_with_legacy_reads(store, monkeypatch):
    import qapp_backend.files as module
    sync = module.os.fsync
    calls = []
    def synced(fd):
        calls.append(fd)
        sync(fd)
    monkeypatch.setattr(module.os, 'fsync', synced)
    chunks = [(i, bytes([i]) * (CHUNK_SIZE + 28)) for i in range(16)]
    request = decode_upload_batch(wire(chunks))
    assert store.request('owner', request) == {'received': list(range(16))}
    assert len(calls) == 1
    assert store.request('owner', request) == {'received': list(range(16))}
    assert len(calls) == 1  # Idempotent replay, no rewrites.
    store.request('owner', dict(op='finish', id=FILE_ID))
    assert base64.b64decode(store.request('recipient', dict(op='get', id=FILE_ID, index=4))['chunk']) == chunks[4][1]


def test_batch_owner_expiry_and_atomic_validation(store):
    chunks = [(0, b'x' * (CHUNK_SIZE + 28))]
    request = decode_upload_batch(wire(chunks))
    with pytest.raises(FileError, match='ACCESS_DENIED'):
        store.request('other', request)
    with pytest.raises(FileError, match='INVALID_CHUNK'):
        store.request('owner', decode_upload_batch(wire(chunks + chunks)))
    with pytest.raises(FileError, match='INVALID_CHUNK'):
        store.request('owner', decode_upload_batch(wire(chunks + [(1, b'x' * 28)])))
    assert store.request('owner', dict(op='status', id=FILE_ID))['received'] == []
    store.request('owner', request)
    with pytest.raises(FileError, match='CHUNK_CONFLICT'):
        store.request('owner', decode_upload_batch(wire([(1, b'x' * (CHUNK_SIZE + 28)), (0, b'y' * (CHUNK_SIZE + 28))])))
    assert store.request('owner', dict(op='status', id=FILE_ID))['received'] == [0]
    with store.db:
        store.db.execute('UPDATE files SET expires=?', (int(time.time()) - 1,))
    with pytest.raises(FileError, match='EXPIRED'):
        store.request('owner', request)


def test_batch_sync_failure_never_acknowledges_and_can_retry(store, monkeypatch):
    import qapp_backend.files as module
    request = decode_upload_batch(wire([(i, b'x' * (CHUNK_SIZE + 28)) for i in range(16)]))
    with monkeypatch.context() as patch:
        def failed(_):
            raise OSError('disk unavailable')
        patch.setattr(module.os, 'fsync', failed)
        with pytest.raises(OSError):
            store.request('owner', request)
    assert store.request('owner', dict(op='status', id=FILE_ID))['received'] == []
    assert len(store.request('owner', request)['received']) == 16


def test_index_commit_failure_rolls_back_entire_batch_and_can_retry(store):
    import sqlite3
    request = decode_upload_batch(wire([(i, b'x' * (CHUNK_SIZE + 28)) for i in range(16)]))
    store.db.execute("CREATE TRIGGER fail_index BEFORE INSERT ON chunks WHEN NEW.idx=5 BEGIN SELECT RAISE(ABORT, 'index unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.request('owner', request)
    assert store.request('owner', dict(op='status', id=FILE_ID))['received'] == []
    store.db.execute('DROP TRIGGER fail_index')
    assert len(store.request('owner', request)['received']) == 16


@pytest.mark.parametrize('payload', [b'', b'QFB0' + b'x' * 100, wire([]), wire([(0, b'x' * 28)])[:-1], wire([(0, b'x' * 28)]) + b'x', wire([(0, b'x' * 28)] * 17)])
def test_malformed_binary_rejected(payload):
    with pytest.raises(FileError):
        decode_upload_batch(payload)


def test_binary_handler_checks_group_access_before_parsing(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from queue import Queue
    from qapp_backend.files import install_files
    from qapp_backend.auth.group_access import GroupAccessDenied
    import qapp_backend.files as module
    handlers = {}
    shutdown = []
    def register(name):
        def decorated(fn):
            handlers[name] = fn
            return fn
        return decorated
    def denied(_):
        raise GroupAccessDenied('not a member')
    server = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path),
        on_message=register, on_shutdown=shutdown.append,
        authentication_service=SimpleNamespace(require_authorized=denied))
    install_files(server)
    def must_not_parse(_):
        pytest.fail('unauthorized binary payload was parsed')
    monkeypatch.setattr(module, 'decode_upload_batch', must_not_parse)
    replies = Queue()
    transport = object()
    ctx = SimpleNamespace(lane='reliable', transport=transport, reply=replies.put,
        session=SimpleNamespace(provisional=False, authenticated_user='other',
            expires_at=time.time() + 60, private_transport=transport))
    try:
        assert handlers['file_binary'] is handlers['file_request']
        handlers['file_binary'](ctx, b'malformed')
        assert replies.get(timeout=2) == {'ok': False, 'error': 'BACKEND_ACCESS_DENIED'}
    finally:
        shutdown[0]()
