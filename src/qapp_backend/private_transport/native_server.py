"""Supervise the native QUIC data plane over a private inherited socketpair.

Only bounded JSON control/metadata crosses IPC, never encrypted file chunks.
EOF closes all attached sessions; there is no unauthenticated TCP control port.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from qapp_backend.auth.group_access import GroupAccessDenied, GroupAccessUnavailable
from qapp_backend.files import FileError
from qapp_backend.private_transport.native_files import native_file_request

logger = logging.getLogger(__name__)
MAX_IPC_LINE = 128 * 1024


class NativeTransport:
    def __init__(self, bridge, connection):
        self.bridge, self.connection = bridge, connection
        self.peer_address = None  # No address is needed for application authorization.
        self.session = None
        self.pending = {}
        self.lock = threading.Lock()

    def send_json(self, lane, message_id, value):
        with self.lock:
            request_id = self.pending.pop((lane, message_id), None)
        if request_id is not None:
            self.bridge.send({'id': request_id, 'ok': True, 'result': value})

    def request_close(self, code, reason):
        self.bridge.send({'event': 'close', 'connection': self.connection})


class NativeQuicServer:
    def __init__(self, service, *, host, port, certificate_path, key_path):
        self.service = service
        self.host, self.port = host, port
        self.certificate_path, self.key_path = certificate_path, key_path
        self.bound_port = None
        self.process = None
        self.socket = None
        self.thread = None
        self.write_lock = threading.Lock()
        self.lock = threading.RLock()
        self.connections = {}
        self.attaching = {}
        self.stopping = threading.Event()
        # Separate pools prevent control operations waiting for file locks from
        # starving metadata commits that release those locks.
        self.pools = [ThreadPoolExecutor(8, thread_name_prefix='native-control'),
                      ThreadPoolExecutor(8, thread_name_prefix='native-metadata')]
        self.slots = [threading.BoundedSemaphore(32), threading.BoundedSemaphore(32)]

    def start(self):
        binary = os.environ.get('QAPP_PRIVATE_TRANSPORT_BINARY') or shutil.which('qapp-private-transport')
        if not binary:
            local = Path(__file__).resolve().parents[3] / 'media/bin/qapp-private-transport'
            if local.is_file():
                binary = str(local)
        if not binary:
            raise RuntimeError('Native transport is missing. Run scripts/build-private-transport.sh or use Docker Compose.')
        parent, child = socket.socketpair()
        self.socket = parent
        host = f'[{self.host}]' if ':' in self.host else self.host
        try:
            self.process = subprocess.Popen([
                binary, '--listen', f'{host}:{self.port}', '--certificate', self.certificate_path,
                '--key', self.key_path, '--control-fd', str(child.fileno()),
                '--files', str(self.service.config.data_dir / 'files'),
            ], pass_fds=(child.fileno(),), stdout=subprocess.PIPE, text=True)
        except Exception:
            self.stop()
            raise
        finally:
            child.close()
        self.thread = threading.Thread(target=self._read, daemon=True, name='native-control-reader')
        self.thread.start()
        try:
            if not select.select([self.process.stdout], [], [], 10)[0]:
                raise RuntimeError('Native transport startup timed out')
            ready = json.loads(self.process.stdout.readline())
            self.bound_port = int(ready['port'])
            return self.bound_port
        except Exception:
            self.stop()
            raise

    def send(self, value):
        encoded = json.dumps(value, separators=(',', ':')).encode() + b'\n'
        if len(encoded) > MAX_IPC_LINE:
            raise ValueError('Native control response too large')
        with self.write_lock:
            if self.stopping.is_set():
                return
            self.socket.sendall(encoded)

    def _read(self):
        try:
            with self.socket.makefile('rb') as stream:
                while not self.stopping.is_set():
                    line = stream.readline(MAX_IPC_LINE + 1)
                    if not line:
                        break
                    if len(line) > MAX_IPC_LINE or not line.endswith(b'\n'):
                        raise ValueError('Native IPC framing limit exceeded')
                    request = json.loads(line)
                    if request.get('op') == 'attach':
                        with self.lock:
                            self.attaching[request['connection']] = threading.Event()
                    if request.get('op') == 'detach':
                        self._detach(request['connection'])
                        continue
                    pool = 1 if request.get('op') == 'file' else 0
                    if not self.slots[pool].acquire(blocking=False):
                        with self.lock:
                            self.attaching.pop(request.get('connection'), None)
                        self.send({'id': request['id'], 'ok': False, 'error': 'BUSY'})
                        continue
                    self.pools[pool].submit(self._dispatch, request, pool)
        except Exception:
            if not self.stopping.is_set():
                logger.exception('Native transport control connection failed')
        finally:
            unexpected = not self.stopping.is_set()
            self.stopping.set()
            with self.lock:
                identifiers = list(self.connections)
            for identifier in identifiers:
                self._detach(identifier)
            # A native crash must not leave a healthy-looking backend advertising
            # a dead listener. The container supervisor restarts the full service.
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
            if unexpected:
                self.service.server._stop.set()

    def _detach(self, identifier):
        with self.lock:
            pending = self.attaching.get(identifier)
            if pending is not None:
                pending.set()
            transport = self.connections.pop(identifier, None)
        if transport is not None and transport.session is not None:
            self.service.detach(transport.session, transport)

    def _authorized(self, transport):
        session = transport.session
        if (session is None or session.provisional or not session.authenticated_user
                or session.expires_at <= time.time() or session.private_transport is not transport):
            raise FileError('AUTHENTICATION_REQUIRED')
        self.service.server.authentication_service.require_authorized(session)
        return session

    def _dispatch(self, request, pool):
        transport = None
        delegated = False
        try:
            op, identifier = request['op'], request['connection']
            if op == 'attach':
                transport = NativeTransport(self, identifier)
                peer = request.get('peer', '')
                if peer:
                    host, port = peer.rsplit(':', 1)
                    transport.peer_address = (host.strip('[]'), int(port))
                with self.lock:
                    pending = self.attaching.get(identifier)
                    if pending is None or pending.is_set() or identifier in self.connections or len(self.connections) >= 256 or self.stopping.is_set():
                        raise ValueError('connection unavailable')
                    transport.session = self.service.attach(transport, request['metadata'])
                    self.connections[identifier] = transport
                # Recheck access at attachment, not just at bootstrap issuance.
                self._authorized(transport)
                result = {'logicalSessionId': transport.session.session_id,
                          'expiresAt': int(transport.session.expires_at * 1000)}
            else:
                with self.lock:
                    transport = self.connections.get(identifier)
                if transport is None:
                    raise FileError('AUTHENTICATION_REQUIRED')
                session = self._authorized(transport)
                if op == 'file':
                    result = native_file_request(self.service.server.file_store,
                                                 session.authenticated_user, request['metadata'])
                elif op == 'validate':
                    result = {'expiresAt': int(session.expires_at * 1000)}
                elif op == 'message':
                    message_id, lane = request['messageId'], request['lane']
                    with transport.lock:
                        if len(transport.pending) >= 128 or (lane, message_id) in transport.pending:
                            raise FileError('BUSY')
                        transport.pending[lane, message_id] = request['id']
                    from qapp_backend.private_transport.service import encode_application_payload
                    self.service.handle_application_message(transport, session, lane, message_id,
                                                            encode_application_payload(request['metadata']))
                    delegated = True
                    return  # Existing asynchronous handlers reply via transport.
                else:
                    raise ValueError('unsupported native request')
            self.send({'id': request['id'], 'ok': True, 'result': result})
        except (FileError, GroupAccessDenied, GroupAccessUnavailable, ValueError) as exc:
            if request.get('op') == 'attach':
                self._detach(request['connection'])
            code = str(exc) if isinstance(exc, FileError) else 'BACKEND_ACCESS_DENIED'
            self.send({'id': request['id'], 'ok': False, 'error': code})
        except Exception:
            logger.exception('Native control operation failed')
            self.send({'id': request['id'], 'ok': False, 'error': 'STORAGE_UNAVAILABLE'})
        finally:
            if request.get('op') == 'message' and not delegated and transport is not None:
                # A synchronous rejection must not leave a permanently pending
                # request. Asynchronous handlers retain their entry until reply.
                with transport.lock:
                    transport.pending.pop((request.get('lane'), request.get('messageId')), None)
            if request.get('op') == 'attach':
                with self.lock:
                    self.attaching.pop(request['connection'], None)
            self.slots[pool].release()

    def stop(self):
        self.stopping.set()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.socket is not None:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=5)
        for pool in self.pools:
            pool.shutdown(wait=True)
        if self.socket is not None:
            self.socket.close()
        if self.process is not None and self.process.stdout is not None:
            self.process.stdout.close()
