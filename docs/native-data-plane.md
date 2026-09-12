# Native private data plane

The backend automatically starts `qapp-private-transport`, a Go child process,
on its existing UDP private-transport port. It uses the existing certificate,
bootstrap response and `qortal-private/1` protocol. No new public port, relay
configuration, QApp change, Hub change, or stored-file migration is required.
The separately running Go MOQT media service remains unchanged.

```text
QApp → Hub → MASQUE → Go private transport → encrypted blob on disk
                             ↕ metadata only
                    Python authentication/policy/SQLite

Call media → Hub → MASQUE → separate Go MOQT media process
```

Go handles QUIC packets, congestion/flow control, reliable stream parsing,
encrypted upload writes and encrypted download reads. Python still owns
Reticulum authentication, group policy, session revocation, quotas, file
creation/listing/expiry and the SQLite chunk index. File keys and plaintext never
reach either backend process. Ciphertext never travels through Python or the
control IPC on the production upload/download path, including legacy chunk
uploads. The old Python QUIC listener is retained only for comparison tests;
there is no production fallback to it.

## Authorization and durability

- An inherited socketpair connects the child and parent. No control TCP port,
  public Unix socket, shared secret file or externally callable storage API.
  IPC documents are limited to 128 KiB; requests and worker queues are bounded.
- Attachment consumes the existing one-time, session/app/purpose/nonce-bound
  credential in Python. Successful TLS alone never grants file access.
- Every file operation requires a live attached session and the existing group
  authorization policy. Uploads additionally require file ownership. Group
  cache/revalidation/outage rules remain unchanged.
- Go takes a cross-process file lock, submits only chunk indices, lengths and
  ciphertext hashes to Python, and writes only after validation. Python checks
  size, expiry, state, ownership and immutable-chunk conflicts.
- Go fsyncs the blob before requesting the SQLite index commit. Only after that
  durable commit does it acknowledge the upload. Identical retries are safe.
  A failed write or interrupted commit can leave unindexed bytes, never a
  falsely acknowledged chunk; the normal resume status identifies missing data.
- Each prepared batch also receives an internal commit generation. A newer
  prepare invalidates older queued commits; deletion/recreation invalidates the
  generation too. This prevents a late IPC response after cancellation from
  indexing bytes replaced by a subsequent retry. Generations are bounded,
  short-lived in-memory metadata, not new client credentials.
- The lock remains held across authorization, writes and commit. Python's
  control operations and cleanup take the same lock. Locks use 256 stable stripe
  files, avoiding unlimited lock-file growth or unsafe unlink/recreation races.
  Files sharing a stripe briefly serialize writes/control operations. Native
  downloads take shared locks, allowing many recipients to read concurrently.
- Logout/revocation sends an immediate close event to Go. Session expiry is
  enforced; a legitimately renewed session can refresh its expiry at the old
  deadline. Revocation cannot recall bytes already delivered to a recipient.

## Resource isolation and failures

- 256 total private QUIC connections, including unauthenticated ones.
- QUIC Retry begins at 64 pending connections; absolute 10-second attachment
  deadline includes handshake time. No per-IP throttling that penalizes a relay's
  many legitimate users.
- One persistent primary stream and up to 32 additional active streams.
- At most eight application frames processed per connection, 32 globally.
  Payloads are at most 1 MiB each; these are frame-processing limits, **not total
  RSS limits**. QUIC receive windows grow only as needed, up to 8 MiB per connection.
  Aggregate window growth is limited to 256 MiB above the initial windows (at most
  another 256 MiB). New connections still receive their initial window when the
  growth budget is occupied. TLS, packet queues and runtime allocations add costs.
- Slow frame bodies, writes and control requests have deadlines. Disk work runs
  independently of packet processing; blocked storage cannot block the QUIC event
  loop. Control and metadata work use separate bounded Python pools so a control
  operation waiting on a file lock cannot prevent the commit releasing that lock.
- Inner packets stay at 1,200 bytes with path-MTU probing disabled, as required by
  the MASQUE tunnel. Existing keepalives and idle timeout remain in place.
- Control EOF closes Go connections. A crashed native child signals Python to
  shut down, so Docker's existing restart policy restarts the complete backend
  instead of leaving a live-looking but unusable service.

Application admission limits do not replace upstream DDoS protection. Disk,
network bandwidth and CPU remain shared physical resources, even though file
traffic and call media execute in separate processes.

## Build, deploy and verify

Docker Compose builds and bundles the child in the backend image. The usual
`docker compose up -d --build` deploys it. Existing volumes, identity and
certificates must be kept. A backend restart interrupts active sessions;
unfinished uploads can resume.

For source development on Linux/macOS, install Go 1.26+, then run:

```sh
sh scripts/build-private-transport.sh
uv run pytest
cd media
go test -race ./...
```

`QORTAL_GO_BINARY` can select the build compiler. An explicit
`QAPP_PRIVATE_TRANSPORT_BINARY` can select a prebuilt executable. Neither is a
feature flag; missing native transport fails startup with build instructions.

The tests cover real native QUIC uploads/downloads, resume, immutable conflicts,
authorization denial, logout, consumed-token replay, child failure, metadata
transactions, cross-process locks, admission bounds and tunnel configuration.

The Hub integration benchmark can additionally run real binary file writes and
reads through MASQUE with 120 ms simulated RTT:

```sh
QORTAL_NATIVE_FILE_BENCH=1 npx vitest run electron/src/private-channel-step4.test.ts
```

Run that command in the Hub repository with its Go/uv test prerequisites.
`QORTAL_BULK_BENCH_LARGE=1` increases the file from 32 MiB to 128 MiB. The test
requires successful durable upload, sampled download verification and concurrent
diagnostic delivery. Synthetic loopback results are not a VPS throughput promise;
the deployed path still needs an actual upload measurement.

### Local validation, 2026-09-12

- 167 Python tests passed, including four concurrent native connections, owner
  isolation, token replay, group denial, FIN draining, child failure and stale
  commit rejection. Go tests passed with the race detector; Electron typecheck
  and real signed-auth/MASQUE interoperability tests passed.
- The production Docker image built and started its bundled child as the
  unprivileged service user with networking isolated. It contains no aioquic
  dependency. Test services were stopped afterward; the VPS was not changed.
- Latest 128 MiB durable upload through MASQUE at simulated 120 ms RTT: 8.82 s,
  15.22 MB/s. Sampled first/last downloads matched; 172/173 concurrent diagnostic
  datagrams arrived, p95 RTT 163 ms. No reliable-stream/connection errors.
- Results vary with shared machine load: a 32 MiB run during concurrent builds
  reached 7.55 MB/s; an earlier run reached 13.09 MB/s. These tests exclude QApp
  encryption/renderer overhead and do not establish the real VPS upload rate.
