import base64
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from qapp_backend.files import FileStore, FileError, CHUNK_SIZE, OWNER_QUOTA, MAX_FILE_SIZE, MAX_EXPIRY

ALICE = 'Q' + 'A'*33
BOB = 'Q' + 'B'*33
MALLORY = 'Q' + 'C'*33
FILE_ID = 'a'*32


@pytest.fixture
def store(tmp_path):
    value = FileStore(tmp_path)
    yield value
    value.db.close()


def create(store, **changes):
    data = dict(op='create', id=FILE_ID, size=4, ttl=60,
                envelope=base64.b64encode(b'opaque-key-envelope').decode(),
                manifest=base64.b64encode(b'opaque-metadata').decode())
    data.update(changes)
    return store.request(ALICE, data)


def put(store, index=0, chunk=b'x'*32):
    return store.request(ALICE, dict(op='put', id=FILE_ID, index=index, chunk=base64.b64encode(chunk).decode()))


def ready(store):
    create(store)
    put(store)
    store.request(ALICE, {'op': 'finish', 'id': FILE_ID})


def test_owner_list_isolated_and_link_holder_never_gets_recovery_envelope(store):
    ready(store)
    assert store.request(BOB, {'op': 'list'}) == []
    assert store.request(ALICE, {'op': 'list'})[0]['envelope']
    assert 'envelope' not in store.request(BOB, {'op': 'info', 'id': FILE_ID})
    assert store.request(BOB, {'op': 'get', 'id': FILE_ID, 'index': 0})['chunk']
    assert store.request(MALLORY, {'op': 'info', 'id': FILE_ID})
    assert store.request(MALLORY, {'op': 'get', 'id': FILE_ID, 'index': 0})['chunk']
    for op in ('delete', 'access', 'status', 'put', 'finish'):
        with pytest.raises(FileError, match='ACCESS_DENIED'):
            store.request(MALLORY, {'op': op, 'id': FILE_ID, 'index': 0})


def test_upload_resume_is_durable_and_chunks_are_immutable(store):
    create(store, size=CHUNK_SIZE+4)
    put(store, chunk=b'x'*(CHUNK_SIZE+28))
    put(store, chunk=b'x'*(CHUNK_SIZE+28))
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID}) == {'received': [0]}
    with pytest.raises(FileError, match='CHUNK_CONFLICT'):
        put(store, chunk=b'y'*(CHUNK_SIZE+28))
    with pytest.raises(FileError, match='UPLOAD_INCOMPLETE'):
        store.request(ALICE, {'op': 'finish', 'id': FILE_ID})
    reopened = FileStore(store.directory)
    try:
        assert reopened.request(ALICE, {'op': 'status', 'id': FILE_ID})['received'] == [0]
        put(reopened, index=1)
        reopened.request(ALICE, {'op': 'finish', 'id': FILE_ID})
    finally:
        reopened.db.close()


def test_expiry_and_deletion_reject_reads_and_remove_bytes(store):
    ready(store)
    with store.db:
        store.db.execute('UPDATE files SET expires=?', (int(time.time())-1,))
    with pytest.raises(FileError, match='EXPIRED'):
        store.request(BOB, {'op': 'get', 'id': FILE_ID, 'index': 0})
    store.cleanup()
    assert not (store.directory / f'{FILE_ID}.bin').exists()
    assert store.request(ALICE, {'op': 'list', 'expired': True})[0]['state'] == 'expired'
    store.request(ALICE, {'op': 'delete', 'id': FILE_ID})
    with pytest.raises(FileError, match='NOT_AVAILABLE'):
        store.request(BOB, {'op': 'info', 'id': FILE_ID})


def test_old_access_requests_fail_instead_of_implying_false_security(store):
    with pytest.raises(FileError, match='FILE_ACCESS_MODEL_CHANGED'):
        create(store, access={'groups': [1144], 'users': [BOB]})
    create(store)
    with pytest.raises(FileError, match='FILE_ACCESS_MODEL_CHANGED'):
        store.request(ALICE, {'op': 'access', 'id': FILE_ID,
                              'access': {'groups': [1144], 'users': []}})


def test_quotas_invalid_inputs_and_traversal(store):
    for changes in ({'ttl': 0}, {'ttl': 8*86400}, {'size': True}, {'id': '../bad'}, {'access': {'users': []}}):
        with pytest.raises(FileError):
            create(store, **changes)
    create(store)
    with store.db:
        store.db.execute('UPDATE files SET size=?', (OWNER_QUOTA,))
    with pytest.raises(FileError, match='STORAGE_FULL'):
        create(store, id='b'*32)
    with pytest.raises(FileError):
        store.request(ALICE, {'op': 'get', 'id': '../files.sqlite3'})


def test_three_gib_and_day_boundaries_and_bounded_resume(store):
    assert MAX_FILE_SIZE == 3 * 1024**3
    assert MAX_EXPIRY == 86400
    for changes in ({'size': MAX_FILE_SIZE+1}, {'ttl': MAX_EXPIRY+1}):
        with pytest.raises(FileError):
            create(store, **changes)
    entry = create(store, size=MAX_FILE_SIZE, ttl=MAX_EXPIRY)
    assert entry['size'] == MAX_FILE_SIZE
    # No 3 GiB allocation: exercise resume indexing separately from chunk bytes.
    with store.db:
        store.db.executemany('INSERT INTO chunks VALUES (?,?,?)',
            ((FILE_ID, i, 'test') for i in range(4098)))
    page = store.request(ALICE, {'op': 'status', 'id': FILE_ID})
    assert len(page['received']) == 4096
    assert page['nextIndex'] == 4096
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID, 'start': 4096}) == {'received': [4096,4097]}


def test_batch_syncs_once_and_acknowledges_only_after_commit(store, monkeypatch):
    import qapp_backend.files as files
    create(store, size=4*CHUNK_SIZE)
    collected = threading.Event()
    release = threading.Event()
    sync_started = threading.Event()
    sync_release = threading.Event()
    real_sync = files.os.fsync
    syncs = []
    def collect(_):
        collected.set()
        assert release.wait(3)
    def sync(fd):
        syncs.append(fd)
        sync_started.set()
        assert sync_release.wait(3)
        real_sync(fd)
    monkeypatch.setattr(files.time, 'sleep', collect)
    monkeypatch.setattr(files.os, 'fsync', sync)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(put, store, i, b'x'*(CHUNK_SIZE+28)) for i in range(4)]
        assert collected.wait(3)
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            with store.lock:
                if len(store.pending_writes.get(FILE_ID, [])) == 4:
                    break
            threading.Event().wait(0.001)
        else:
            pytest.fail('writers did not enqueue')
        release.set()
        assert sync_started.wait(3)
        assert all(not future.done() for future in futures)
        with store.lock:
            assert store.db.execute('SELECT COUNT(*) FROM chunks').fetchone()[0] == 0
        sync_release.set()
        assert [future.result(3) for future in futures] == [{}, {}, {}, {}]
    assert len(syncs) == 1
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID})['received'] == [0,1,2,3]
    assert not store.pending_writes and not store.file_locks


def test_slow_file_sync_does_not_block_another_file(store, monkeypatch):
    import qapp_backend.files as files
    create(store)
    other = 'b'*32
    create(store, id=other)
    started = threading.Event()
    release = threading.Event()
    real_sync = files.os.fsync
    def sync(fd):
        if threading.current_thread().name.startswith('slow'):
            started.set()
            assert release.wait(3)
        real_sync(fd)
    monkeypatch.setattr(files.os, 'fsync', sync)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='slow') as executor:
        future = executor.submit(put, store)
        assert started.wait(3)
        try:
            store.request(ALICE, {'op': 'put', 'id': other, 'index': 0,
                                  'chunk': base64.b64encode(b'y'*32).decode()})
            store.request(ALICE, {'op': 'finish', 'id': other})
            assert store.request(BOB, {'op': 'get', 'id': other, 'index': 0})
            assert not future.done()
        finally:
            release.set()
        future.result(3)


def test_failed_sync_does_not_advertise_chunk_and_can_retry(store, monkeypatch):
    import qapp_backend.files as files
    create(store)
    with monkeypatch.context() as patch:
        def fail(_):
            raise OSError('disk failure')
        patch.setattr(files.os, 'fsync', fail)
        with pytest.raises(OSError):
            put(store)
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID})['received'] == []
    assert not store.pending_writes and not store.file_locks
    put(store)
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID})['received'] == [0]


def test_cleanup_interval_and_expired_storage_releases_owner_quota(store):
    from qapp_backend.files import CLEANUP_INTERVAL
    assert CLEANUP_INTERVAL == 300
    create(store, size=OWNER_QUOTA)
    with store.db:
        store.db.execute('UPDATE files SET expires=?', (int(time.time())-1,))
    with pytest.raises(FileError, match='EXPIRED'):
        put(store)
    store.cleanup()
    assert create(store, id='b'*32, size=OWNER_QUOTA)


def test_index_failure_never_acknowledges_unindexed_bytes(store):
    import sqlite3
    create(store)
    with store.db:
        store.db.execute("CREATE TRIGGER fail_chunk BEFORE INSERT ON chunks BEGIN SELECT RAISE(ABORT, 'index failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match='index failure'):
        put(store)
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID})['received'] == []
    with store.db:
        store.db.execute('DROP TRIGGER fail_chunk')
    put(store)
    assert store.request(ALICE, {'op': 'status', 'id': FILE_ID})['received'] == [0]


def test_cleanup_waits_for_inflight_write_and_leaves_no_orphan(store, monkeypatch):
    import qapp_backend.files as files
    create(store)
    started = threading.Event()
    release = threading.Event()
    cleaning = threading.Event()
    real_sync = files.os.fsync
    def sync(fd):
        started.set()
        assert release.wait(3)
        real_sync(fd)
    def cleanup():
        cleaning.set()
        store.cleanup()
    monkeypatch.setattr(files.os, 'fsync', sync)
    with ThreadPoolExecutor(max_workers=2) as executor:
        writer = executor.submit(put, store)
        assert started.wait(3)
        with store.lock, store.db:
            store.db.execute('UPDATE files SET expires=?', (int(time.time())-1,))
        cleaner = executor.submit(cleanup)
        assert cleaning.wait(3)
        try:
            assert not cleaner.done()
            assert (store.directory / f'{FILE_ID}.bin').exists()
        finally:
            release.set()
        writer.result(3)
        cleaner.result(3)
    assert not (store.directory / f'{FILE_ID}.bin').exists()
    assert store.db.execute('SELECT COUNT(*) FROM chunks').fetchone()[0] == 0
    assert not store.file_locks


def test_legacy_recipient_columns_are_removed_without_losing_files(tmp_path):
    import sqlite3
    directory = tmp_path / 'legacy'
    directory.mkdir()
    db = sqlite3.connect(directory / 'files.sqlite3')
    db.executescript('''
      CREATE TABLE files (
        id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL,
        expires INTEGER NOT NULL, created INTEGER NOT NULL, state TEXT NOT NULL,
        groups_json TEXT NOT NULL, users_json TEXT NOT NULL,
        envelope TEXT NOT NULL, manifest TEXT NOT NULL);
      CREATE TABLE chunks (
        file_id TEXT NOT NULL, idx INTEGER NOT NULL, digest TEXT NOT NULL,
        PRIMARY KEY(file_id,idx));
    ''')
    db.execute('INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?)', (
        FILE_ID, ALICE, 4, int(time.time()) + 60, int(time.time()), 'ready',
        '[1144]', f'["{BOB}"]', 'opaque-envelope', 'opaque-manifest'))
    db.execute('INSERT INTO chunks VALUES (?,?,?)', (FILE_ID, 0, 'digest'))
    db.commit()
    db.close()
    (directory / f'{FILE_ID}.bin').write_bytes(b'x' * 32)

    migrated = FileStore(directory)
    try:
        columns = {row['name'] for row in migrated.db.execute(
            'PRAGMA table_info(files)')}
        assert 'groups_json' not in columns and 'users_json' not in columns
        assert migrated.request(BOB, {'op': 'info', 'id': FILE_ID})['manifest'] == 'opaque-manifest'
        assert migrated.db.execute('SELECT COUNT(*) FROM chunks').fetchone()[0] == 1
    finally:
        migrated.db.close()
