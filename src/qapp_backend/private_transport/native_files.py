"""Metadata-only native storage API; ciphertext never crosses this interface.

The trusted child holds the shared stripe flock throughout prepare, disk fsync,
and commit. Python's control/cleanup paths acquire that same flock. Only this
internal API bypasses file_lock; it must never be exposed as an app handler.
"""
import math
import re
import secrets
import time

from qapp_backend.files import BATCH_CHUNKS, CHUNK_SIZE, FileError, integer


def native_file_request(store, user, request):
    op = request.get('op')
    with store.lock:
        row = store.row(request.get('id'))
        if row['expires'] <= time.time() or row['state'] == 'expired':
            raise FileError('EXPIRED')
        count = max(1, math.ceil(row['size'] / CHUNK_SIZE))
        if op == 'read':
            if row['state'] != 'ready':
                raise FileError('UPLOAD_INCOMPLETE')
            index = integer(request.get('index'), 0, count - 1)
            return {'length': min(CHUNK_SIZE, max(0, row['size'] - index * CHUNK_SIZE)) + 28}
        if op not in ('prepare', 'commit'):
            raise FileError('INVALID_REQUEST')
        if row['owner'] != user:
            raise FileError('ACCESS_DENIED')
        if row['state'] != 'uploading':
            raise FileError('UPLOAD_CLOSED')
        chunks = request.get('chunks')
        if not isinstance(chunks, list) or not 1 <= len(chunks) <= BATCH_CHUNKS:
            raise FileError('INVALID_REQUEST')
        seen, writes = set(), []
        for chunk in chunks:
            index = integer(chunk.get('index'), 0, count - 1)
            length = min(CHUNK_SIZE, max(0, row['size'] - index * CHUNK_SIZE)) + 28
            digest = chunk.get('digest')
            if index in seen or chunk.get('length') != length or not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
                raise FileError('INVALID_CHUNK')
            seen.add(index)
            existing = store.db.execute('SELECT digest FROM chunks WHERE file_id=? AND idx=?', (row['id'], index)).fetchone()
            if existing and existing[0] != digest:
                raise FileError('CHUNK_CONFLICT')
            if not existing:
                writes.append((row['id'], index, digest))
        binding = (row['owner'], row['created'], row['envelope'], row['size'],
                   tuple((c['index'], c['length'], c['digest']) for c in chunks))
        if op == 'commit':
            lease = store.native_writes.get(row['id'])
            if (lease is None or request.get('lease') != lease[0]
                    or lease[1] <= time.monotonic() or lease[2] != binding):
                raise FileError('BUSY')
            with store.db:
                store.db.executemany('INSERT INTO chunks VALUES (?,?,?)', writes)
            del store.native_writes[row['id']]
            return {'received': sorted(seen)}
        now = time.monotonic()
        for key, lease in list(store.native_writes.items()):
            if lease[1] <= now:
                del store.native_writes[key]
        if row['id'] not in store.native_writes and len(store.native_writes) >= 2048:
            raise FileError('BUSY')
        token = secrets.token_hex(16)
        # A newer prepare invalidates old queued commits. This generation check
        # complements flock: an IPC timeout must never allow a late commit to
        # index ciphertext that a subsequent, unacknowledged retry has replaced.
        store.native_writes[row['id']] = (token, now + 120, binding)
        return {'write': [r[1] for r in writes], 'received': sorted(seen), 'lease': token}
