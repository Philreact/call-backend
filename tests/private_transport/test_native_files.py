import hashlib
import os
import threading
import time

import pytest

from qapp_backend.files import FileError, CHUNK_SIZE
from qapp_backend.private_transport.native_files import native_file_request
from test_files_binary import store, FILE_ID


def descriptor(index=0, content=None):
    content = content or b'x' * (CHUNK_SIZE + 28)
    return {'index': index, 'length': len(content), 'digest': hashlib.sha256(content).hexdigest()}


def test_prepare_is_metadata_only_and_commit_is_idempotent(store):
    request = {'op': 'prepare', 'id': FILE_ID, 'chunks': [descriptor()]}
    prepared = native_file_request(store, 'owner', request)
    assert prepared['write'] == [0]
    assert store.request('owner', {'op': 'status', 'id': FILE_ID}) == {'received': []}
    request['op'] = 'commit'
    request['lease'] = prepared['lease']
    assert native_file_request(store, 'owner', request)['received'] == [0]
    request['op'] = 'prepare'
    repeated = native_file_request(store, 'owner', request)
    assert repeated['write'] == []
    native_file_request(store, 'owner', {**request, 'op': 'commit', 'lease': repeated['lease']})
    assert store.request('owner', {'op': 'status', 'id': FILE_ID}) == {'received': [0]}


def test_native_policy_and_immutable_chunk_checks(store):
    request = {'op': 'prepare', 'id': FILE_ID, 'chunks': [descriptor()]}
    with pytest.raises(FileError, match='ACCESS_DENIED'):
        native_file_request(store, 'intruder', request)
    request['lease'] = native_file_request(store, 'owner', request)['lease']
    request['op'] = 'commit'
    native_file_request(store, 'owner', request)
    request['chunks'] = [descriptor(1), descriptor(0, b'y' * (CHUNK_SIZE + 28))]
    with pytest.raises(FileError, match='CHUNK_CONFLICT'):
        native_file_request(store, 'owner', request)
    assert store.request('owner', {'op': 'status', 'id': FILE_ID}) == {'received': [0]}
    with store.db:
        store.db.execute('UPDATE files SET expires=0')
    with pytest.raises(FileError, match='EXPIRED'):
        native_file_request(store, 'owner', request)


def test_late_commit_cannot_index_a_newer_retry(store):
    first = {'op': 'prepare', 'id': FILE_ID, 'chunks': [descriptor()]}
    old = native_file_request(store, 'owner', first)
    replacement = {**first, 'chunks': [descriptor(0, b'y' * (CHUNK_SIZE + 28))]}
    current = native_file_request(store, 'owner', replacement)
    with pytest.raises(FileError, match='BUSY'):
        native_file_request(store, 'owner', {**first, 'op': 'commit', 'lease': old['lease']})
    assert store.request('owner', {'op': 'status', 'id': FILE_ID}) == {'received': []}
    native_file_request(store, 'owner', {**replacement, 'op': 'commit', 'lease': current['lease']})
    assert store.request('owner', {'op': 'status', 'id': FILE_ID}) == {'received': [0]}


def test_control_waits_for_native_flock_before_delete(store):
    import fcntl
    lock = (store.directory / 'locks' / FILE_ID[:2]).open('a+b')
    fcntl.flock(lock, fcntl.LOCK_EX)
    done = threading.Event()
    def delete():
        store.request('owner', {'op': 'delete', 'id': FILE_ID})
        done.set()
    thread = threading.Thread(target=delete)
    thread.start()
    try:
        assert not done.wait(.1)
        assert (store.directory / f'{FILE_ID}.bin').exists()
    finally:
        lock.close()
        thread.join(2)
    assert done.is_set()
    assert not (store.directory / f'{FILE_ID}.bin').exists()
