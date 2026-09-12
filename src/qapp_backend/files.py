"""Opaque, quota-bounded temporary storage. Plaintext and file keys never enter here."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import logging
import math
import os
import re
import sqlite3
import struct
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from qapp_backend.auth.group_access import GroupAccessDenied, GroupAccessUnavailable


CHUNK_SIZE = 32768
MAX_FILE_SIZE = 3 * 1024 * 1024 * 1024
MAX_EXPIRY = 86400
MAX_ACTIVE_FILES_PER_OWNER = 2
OWNER_QUOTA = MAX_FILE_SIZE
GLOBAL_QUOTA = 10 * 1024 * 1024 * 1024
CLEANUP_INTERVAL = 300
WRITE_BATCH_DELAY = 0.005
MAX_PENDING_WRITES = 16
ID = re.compile(r"^[a-f0-9]{32}$")
BATCH_CHUNKS = 16


def decode_upload_batch(payload: bytes) -> dict[str, Any]:
    if len(payload) < 22 or len(payload) > 22 + BATCH_CHUNKS * (CHUNK_SIZE + 36) or payload[:4] != b'QFB1':
        raise FileError('INVALID_REQUEST')
    count = int.from_bytes(payload[20:22], 'big')
    if not 1 <= count <= BATCH_CHUNKS:
        raise FileError('INVALID_REQUEST')
    chunks = []
    offset = 22
    for _ in range(count):
        if offset + 8 > len(payload):
            raise FileError('INVALID_REQUEST')
        index, size = struct.unpack_from('>II', payload, offset)
        offset += 8
        if not 28 <= size <= CHUNK_SIZE + 28 or offset + size > len(payload):
            raise FileError('INVALID_REQUEST')
        chunks.append((index, payload[offset:offset + size]))
        offset += size
    if offset != len(payload):
        raise FileError('INVALID_REQUEST')
    return {'op': 'put_batch', 'id': payload[4:20].hex(), 'chunks': chunks}


class FileError(ValueError):
    pass


def integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise FileError("INVALID_REQUEST")
    return value


def encoded(value: Any, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise FileError("INVALID_REQUEST")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise FileError("INVALID_REQUEST") from exc
    if not raw or len(raw) > maximum:
        raise FileError("INVALID_REQUEST")
    return raw


class FileStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        (directory / 'locks').mkdir(exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.file_locks: dict[str, list[Any]] = {}
        self.pending_writes: dict[str, list[Any]] = {}
        self.native_writes: dict[str, Any] = {}
        self.write_slots = threading.BoundedSemaphore(MAX_PENDING_WRITES)
        self.db = sqlite3.connect(directory / "files.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS files (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL,
              expires INTEGER NOT NULL, created INTEGER NOT NULL, state TEXT NOT NULL,
              envelope TEXT NOT NULL, manifest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS chunks (
              file_id TEXT NOT NULL, idx INTEGER NOT NULL, digest TEXT NOT NULL,
              PRIMARY KEY(file_id,idx));
        """)
        self._remove_legacy_access_columns()

    def _remove_legacy_access_columns(self) -> None:
        """Migrate existing uploads without retaining obsolete recipient data."""
        columns = {row['name'] for row in self.db.execute('PRAGMA table_info(files)')}
        if not {'groups_json', 'users_json'} <= columns:
            return
        with self.db:
            self.db.execute('ALTER TABLE files RENAME TO files_with_access')
            self.db.execute('''CREATE TABLE files (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL,
              expires INTEGER NOT NULL, created INTEGER NOT NULL, state TEXT NOT NULL,
              envelope TEXT NOT NULL, manifest TEXT NOT NULL)''')
            self.db.execute('''INSERT INTO files
              (id,owner,size,expires,created,state,envelope,manifest)
              SELECT id,owner,size,expires,created,state,envelope,manifest
              FROM files_with_access''')
            self.db.execute('DROP TABLE files_with_access')

    @contextmanager
    def file_lock(self, file_id: str):
        # Reference counts include waiters, so an active lock is never replaced.
        with self.lock:
            entry = self.file_locks.setdefault(file_id, [threading.RLock(), 0])
            entry[1] += 1
        try:
            with entry[0]:
                # Fixed-size, cross-process lock set shared with the native data
                # plane. Never unlink lock files: waiters must retain one inode.
                if not isinstance(file_id, str) or not ID.fullmatch(file_id):
                    raise FileError('NOT_AVAILABLE')
                with (self.directory / 'locks' / file_id[:2]).open('a+b') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            with self.lock:
                entry[1] -= 1
                if not entry[1]:
                    del self.file_locks[file_id]

    def cleanup(self) -> None:
        with self.lock:
            now = int(time.time())
            expired = self.db.execute("SELECT id FROM files WHERE expires<=? OR state IN ('expired','deleted')", (now,)).fetchall()
        for row in expired:
            file_id = row['id']
            with self.file_lock(file_id):
                (self.directory / f'{file_id}.bin').unlink(missing_ok=True)
                with self.lock, self.db:
                    self.native_writes.pop(file_id, None)
                    self.db.execute("UPDATE files SET state='expired' WHERE id=? AND state!='deleted'", (file_id,))
                    self.db.execute('DELETE FROM chunks WHERE file_id=?', (file_id,))
                    self.db.execute("DELETE FROM files WHERE id=? AND (state='deleted' OR expires<?)", (file_id, now - 7*86400))
        # Coordinate orphan removal with creation, including uncommitted files.
        for path in self.directory.glob('*.bin'):
            with self.file_lock(path.stem):
                with self.lock:
                    orphan = not self.db.execute('SELECT 1 FROM files WHERE id=?', (path.stem,)).fetchone()
                if orphan:
                    path.unlink(missing_ok=True)

    def put(self, user: str, data: dict[str, Any]) -> Any:
        if not self.write_slots.acquire(blocking=False):
            raise FileError('BUSY')
        future: Future = Future()
        file_id = data['id']
        try:
            with self.lock:
                leader = file_id not in self.pending_writes
                self.pending_writes.setdefault(file_id, []).append((user, data, future))
            if leader:
                # Coalesce the client's concurrent chunks without changing the
                # wire format or acknowledging volatile data. No extra threads.
                time.sleep(WRITE_BATCH_DELAY)
                with self.lock:
                    batch = self.pending_writes.pop(file_id)
                try:
                    with self.file_lock(file_id):
                        self.flush_batch(file_id, batch)
                except Exception as exc:
                    for _, _, waiting in batch:
                        if not waiting.done():
                            waiting.set_exception(exc)
            return future.result()
        finally:
            self.write_slots.release()

    def flush_batch(self, file_id: str, batch: list[Any]) -> None:
        writes: dict[int, tuple[bytes, str]] = {}
        accepted = []
        with self.lock:
            row = self.row(file_id)
            count = max(1, math.ceil(row['size']/CHUNK_SIZE))
            for user, data, future in batch:
                try:
                    if row['owner'] != user:
                        raise FileError('ACCESS_DENIED')
                    if row['expires'] <= time.time() or row['state'] == 'expired':
                        raise FileError('EXPIRED')
                    if row['state'] != 'uploading':
                        raise FileError('UPLOAD_CLOSED')
                    index = integer(data.get('index'), 0, count-1)
                    chunk = encoded(data.get('chunk'), CHUNK_SIZE+28)
                    if len(chunk) != min(CHUNK_SIZE, max(0, row['size']-index*CHUNK_SIZE))+28:
                        raise FileError('INVALID_CHUNK')
                    digest = hashlib.sha256(chunk).hexdigest()
                    existing = self.db.execute('SELECT digest FROM chunks WHERE file_id=? AND idx=?', (file_id,index)).fetchone()
                    previous = writes[index][1] if index in writes else existing[0] if existing else None
                    if previous is not None and previous != digest:
                        raise FileError('CHUNK_CONFLICT')
                    if previous is None:
                        writes[index] = (chunk, digest)
                    accepted.append(future)
                except FileError as exc:
                    future.set_exception(exc)
        self.write_chunks(file_id, writes)
        for future in accepted:
            future.set_result({})

    def write_chunks(self, file_id: str, writes: dict[int, tuple[bytes, str]]) -> None:
        if writes:
            # The per-file lock protects deletion/finish/read races, while other
            # files can perform disk I/O concurrently with this sync.
            with (self.directory / f'{file_id}.bin').open('r+b') as stream:
                for index, (chunk, _) in sorted(writes.items()):
                    stream.seek(index*(CHUNK_SIZE+28))
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            with self.lock, self.db:
                self.db.executemany('INSERT INTO chunks VALUES (?,?,?)',
                    ((file_id, index, value[1]) for index, value in writes.items()))
    def put_batch(self, user: str, data: dict[str, Any]) -> Any:
        if not self.write_slots.acquire(blocking=False):
            raise FileError('BUSY')
        try:
            with self.file_lock(data['id']):
                with self.lock:
                    row = self.row(data['id'])
                    if row['owner'] != user:
                        raise FileError('ACCESS_DENIED')
                    if row['expires'] <= time.time():
                        raise FileError('EXPIRED')
                    if row['state'] != 'uploading':
                        raise FileError('UPLOAD_CLOSED')
                    chunks = data.get('chunks')
                    if not isinstance(chunks, list) or not 1 <= len(chunks) <= BATCH_CHUNKS:
                        raise FileError('INVALID_REQUEST')
                    count = max(1, math.ceil(row['size'] / CHUNK_SIZE))
                    writes = {}
                    seen = set()
                    for index, chunk in chunks:
                        integer(index, 0, count - 1)
                        if index in seen or not isinstance(chunk, bytes) or len(chunk) != min(CHUNK_SIZE, max(0, row['size'] - index * CHUNK_SIZE)) + 28:
                            raise FileError('INVALID_CHUNK')
                        seen.add(index)
                        digest = hashlib.sha256(chunk).hexdigest()
                        existing = self.db.execute('SELECT digest FROM chunks WHERE file_id=? AND idx=?', (data['id'], index)).fetchone()
                        if existing and existing[0] != digest:
                            raise FileError('CHUNK_CONFLICT')
                        if not existing:
                            writes[index] = (chunk, digest)
                # Validate the complete batch before any write. A single fsync
                # and index transaction acknowledge all of its immutable chunks.
                self.write_chunks(data['id'], writes)
                return {'received': sorted(seen)}
        finally:
            self.write_slots.release()

    def row(self, file_id: str) -> sqlite3.Row:
        if not isinstance(file_id, str) or not ID.fullmatch(file_id):
            raise FileError("NOT_AVAILABLE")
        row = self.db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if row is None or row['state'] == 'deleted':
            raise FileError("NOT_AVAILABLE")
        return row

    @staticmethod
    def describe(row: sqlite3.Row, owner: bool = False) -> dict[str, Any]:
        result = {key: row[key] for key in ('id', 'size', 'expires', 'state', 'manifest')}
        if owner:
            result['envelope'] = row['envelope']
        return result

    def request(self, user: str, data: dict[str, Any]) -> Any:
        if data.get('op') == 'capabilities':
            return {'binaryUploadVersion': 1, 'batchChunks': BATCH_CHUNKS, 'maxInFlightBatches': 8}
        if data.get('op') == 'list':
            return self._request(user, data)
        file_id = data.get('id')
        if not isinstance(file_id, str) or not ID.fullmatch(file_id):
            raise FileError('INVALID_REQUEST' if data.get('op') == 'create' else 'NOT_AVAILABLE')
        if data.get('op') == 'put':
            return self.put(user, data)
        if data.get('op') == 'put_batch':
            return self.put_batch(user, data)
        with self.file_lock(file_id):
            return self._request(user, data)

    def _request(self, user: str, data: dict[str, Any]) -> Any:
        op = data.get('op')
        if op == 'list':
            offset = integer(data.get('offset', 0), 0, 1000)
            expired = data.get('expired', False)
            if type(expired) is not bool:
                raise FileError('INVALID_REQUEST')
            with self.lock:
                comparison = '<=' if expired else '>'
                rows = self.db.execute(f"SELECT * FROM files WHERE owner=? AND state!='deleted' AND expires {comparison} ? ORDER BY created DESC,id LIMIT 5 OFFSET ?", (user, int(time.time()), offset)).fetchall()
                return [self.describe(row, True) for row in rows]
        if op == 'create':
            file_id = data.get('id')
            if not isinstance(file_id, str) or not ID.fullmatch(file_id):
                raise FileError('INVALID_REQUEST')
            size = integer(data.get('size'), 0, MAX_FILE_SIZE)
            ttl = integer(data.get('ttl'), 60, MAX_EXPIRY)
            if 'access' in data:
                # Do not let an older client imply that an ignored guest list
                # provides security. It must update to the link-access model.
                raise FileError('FILE_ACCESS_MODEL_CHANGED')
            encoded(data.get('envelope'), 4096)
            encoded(data.get('manifest'), 2048)
            with self.lock, self.db:
                if self.db.execute('SELECT 1 FROM files WHERE id=?', (file_id,)).fetchone():
                    row = self.row(file_id)
                    if row['owner'] != user or row['envelope'] != data['envelope']:
                        raise FileError('UPLOAD_CONFLICT')
                    return self.describe(row, True)
                now = int(time.time())
                active = self.db.execute(
                    "SELECT COUNT(*) FROM files WHERE owner=? AND state IN ('uploading','ready') AND expires>?",
                    (user, now)).fetchone()[0]
                if active >= MAX_ACTIVE_FILES_PER_OWNER:
                    raise FileError('ACTIVE_FILE_LIMIT')
                totals = self.db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM files WHERE state IN ('uploading','ready')").fetchone()
                own = self.db.execute("SELECT COUNT(*),COALESCE(SUM(CASE WHEN state IN ('uploading','ready') THEN size ELSE 0 END),0) FROM files WHERE owner=? AND state!='deleted'", (user,)).fetchone()
                if totals[0] >= 1000 or own[0] >= 100 or totals[1]+size > GLOBAL_QUOTA or own[1]+size > OWNER_QUOTA:
                    raise FileError('STORAGE_FULL')
                self.native_writes.pop(file_id, None)
                with (self.directory / f'{file_id}.bin').open('xb'):
                    pass
                # Persist the directory entry before publishing its DB record.
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                self.db.execute('INSERT INTO files VALUES (?,?,?,?,?,?,?,?)',
                    (file_id,user,size,now+ttl,now,'uploading',data['envelope'],data['manifest']))
                return self.describe(self.row(file_id), True)
        file_id = data.get('id')
        with self.lock:
            initial = self.row(file_id)
        if op not in ('info', 'get') and initial['owner'] != user:
            raise FileError('ACCESS_DENIED')
        if op == 'access':
            # Access is now determined once, at the service boundary. Returning
            # a specific error prevents old clients from presenting a control
            # that no longer has any effect.
            raise FileError('FILE_ACCESS_MODEL_CHANGED')
        with self.lock, self.db:
            row = self.row(file_id)
            if op == 'delete':
                self.native_writes.pop(file_id, None)
                self.db.execute("UPDATE files SET state='deleted' WHERE id=?", (file_id,))
                (self.directory / f'{file_id}.bin').unlink(missing_ok=True)
                self.db.execute('DELETE FROM chunks WHERE file_id=?', (file_id,))
                return {}
            if row['expires'] <= time.time() or row['state'] == 'expired':
                raise FileError('EXPIRED')
            count = max(1, math.ceil(row['size']/CHUNK_SIZE))
            if op == 'status':
                start = integer(data.get('start', 0), 0, count)
                indices = [r[0] for r in self.db.execute(
                    'SELECT idx FROM chunks WHERE file_id=? AND idx>=? ORDER BY idx LIMIT 4097',
                    (file_id, start))]
                result = {'received': indices[:4096]}
                if len(indices) > 4096:
                    result['nextIndex'] = indices[4095] + 1
                return result
            if op == 'finish':
                received = self.db.execute('SELECT COUNT(*) FROM chunks WHERE file_id=?', (file_id,)).fetchone()[0]
                if received != count:
                    raise FileError('UPLOAD_INCOMPLETE')
                self.db.execute("UPDATE files SET state='ready' WHERE id=?", (file_id,))
                return {}
            if op == 'info':
                if row['state'] != 'ready':
                    raise FileError('UPLOAD_INCOMPLETE')
                return self.describe(row)
            index = integer(data.get('index'), 0, count-1)
            length = min(CHUNK_SIZE, max(0, row['size']-index*CHUNK_SIZE)) + 28
            if op == 'get':
                if row['state'] != 'ready':
                    raise FileError('UPLOAD_INCOMPLETE')
            else:
                raise FileError('INVALID_REQUEST')
        with (self.directory / f'{file_id}.bin').open('rb') as stream:
            stream.seek(index*(CHUNK_SIZE+28))
            chunk = stream.read(length)
        if len(chunk) != length:
            raise FileError('FILE_DAMAGED')
        return {'chunk': base64.b64encode(chunk).decode('ascii')}


def install_files(server: Any) -> None:
    store = FileStore(server.config.data_dir / 'files')
    server.file_store = store
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='file-transfer')
    control_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='file-control')
    slots = threading.BoundedSemaphore(16)
    control_slots = threading.BoundedSemaphore(8)
    stop = threading.Event()
    def cleanup_loop() -> None:
        while not stop.is_set():
            try:
                store.cleanup()
            except Exception:
                logging.getLogger(__name__).exception('File expiry cleanup failed')
            stop.wait(CLEANUP_INTERVAL)
    cleaner = threading.Thread(target=cleanup_loop, daemon=True, name='file-expiry')
    cleaner.start()
    @server.on_shutdown
    def shutdown() -> None:
        stop.set()
        cleaner.join()
        executor.shutdown(wait=True)
        control_executor.shutdown(wait=True)
        store.db.close()
    @server.on_message('file_binary')
    @server.on_message('file_request')
    def handle(ctx: Any, data: Any) -> None:
        if not hasattr(ctx, 'reply') or ctx.lane != 'reliable':
            raise ValueError('files require reliable private transport')
        bulk = isinstance(data, bytes) or (isinstance(data, dict) and data.get('op') in ('put', 'get', 'put_batch'))
        request_slots = slots if bulk else control_slots
        request_executor = executor if bulk else control_executor
        if not request_slots.acquire(blocking=False):
            ctx.reply({'ok': False, 'error': 'BUSY'})
            return
        def work() -> None:
            try:
                session = ctx.session
                if session.provisional or not session.authenticated_user or session.expires_at <= time.time() or session.private_transport is not ctx.transport:
                    raise FileError('AUTHENTICATION_REQUIRED')
                server.authentication_service.require_authorized(session)
                result = store.request(session.authenticated_user, decode_upload_batch(data) if isinstance(data, bytes) else data)
                if session.private_transport is ctx.transport:
                    ctx.reply({'ok': True, 'result': result})
            except (FileError, GroupAccessDenied, GroupAccessUnavailable) as exc:
                code = str(exc) if isinstance(exc, FileError) else 'BACKEND_ACCESS_DENIED'
                ctx.reply({'ok': False, 'error': code})
            except Exception:
                logging.getLogger(__name__).exception('File operation failed')
                ctx.reply({'ok': False, 'error': 'STORAGE_UNAVAILABLE'})
            finally:
                request_slots.release()
        request_executor.submit(work)
