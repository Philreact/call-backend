# Temporary encrypted files

File sharing uses the existing authenticated Reticulum session to bootstrap a
`file-transfer` private channel. File requests and ciphertext then travel over
the reliable QUIC channel through MASQUE. No HTTP file endpoint, new public port,
or changes to the relay are required. Calls keep their existing media transport.

## What uploaders can choose

- An expiry between one minute and 24 hours, measured from upload creation.
- Up to 16 Qortal group IDs and/or 32 individual Qortal addresses. A match in
  either list grants access. An empty list is rejected; this is not public sharing.
- Access can be edited, or the file deleted, before expiry.

The backend's own account/group policy applies first. The uploader always has
access to their file. Other users must authenticate and pass the file policy
before metadata or any chunk is returned. Group checks use the existing bounded,
fail-closed validator and configured Core URL backups. Membership results are
cached for 30 seconds. An access-list edit applies to subsequent requests;
in-flight data and already downloaded copies cannot be revoked.

## Encryption and recovery

The QApp creates a random 256-bit AES-GCM key for each file. Each 32 KiB plaintext
chunk gets a fresh random 96-bit nonce; the file ID and chunk index are additional
authenticated data. An encrypted manifest contains the filename, MIME type,
length, and a SHA-256 digest of the ordered plaintext chunk digests. The client
verifies the manifest, every chunk, and the final digest before requesting a save.

Hub's existing `ENCRYPT_DATA` operation with no additional recipients encrypts
the `{id, secret}` recovery envelope to the uploader's own Qortal account. The
backend stores that opaque envelope and returns it only in that owner's list.
`DECRYPT_DATA` recovers it on another device signed into the same account. The
account private key never enters the QApp or backend. There is no password-based
fallback and no recovery if the account keys are lost.

Links have the form `qortal://APP/<app>/file/<id>.<key>`. The QApp extracts the key
locally; file requests contain the ID, never the clear key. The backend still
knows owners, access lists, sizes, expiry and traffic metadata. Expiry is enforced
by this server, not cryptographic erasure of recipients' copies or external backups.

## Storage and limits

- Maximum 3 GiB per file (shown as 3 GB in the UI), 3 GiB reserved per uploader,
  10 GiB globally. The expiry maximum applies to newly created links.
- Maximum 100 records per uploader and 1,000 active records globally.
- Four file workers with at most 16 queued/running file operations.
- Four chunks in flight per client, below Hub's existing message/queue limits.
- Owner lists are paged in groups of five; no unbounded list response.
- Upload-resume status is paginated at 4,096 chunk indices per response, keeping
  responses below the private channel's 64 KiB message limit even for 3 GiB files.

Storage lives in `data_dir/files` (the existing backend Docker volume): a SQLite
manifest/index and one ciphertext file per upload. Expiry rejects requests
immediately; a five-minute sweeper removes expired ciphertext and unfinished
uploads. Expired metadata/recovery envelopes remain for seven further days for
the owner's expired view. Explicit deletion invalidates the link and removes the
ciphertext; metadata is purged on the next sweep. These limits are constants in
`src/qapp_backend/files.py` in this initial version.

Chunks are immutable and acknowledged only after their bytes are synced to disk
and the SQLite index transaction is committed with full durability. Concurrent
upload requests for one file are collected for up to 5 ms and share one file
sync and index transaction. Batching is bounded to 16 pending chunks across the
store and preserves the existing chunk format and resume protocol. Sequential
uploads still work, but cannot benefit from coalescing. Per-file locks coordinate
writes, reads, deletion and cleanup; disk reads and upload syncs do not hold the
shared metadata lock, allowing independent files to progress concurrently.
Expired ciphertext can remain on disk until the next sweep (longer if disk
cleanup fails); it cannot be downloaded. Storage quotas are released after
cleanup, while retained expired metadata does not reserve file bytes.

An interrupted uploader selects the original file; its fingerprint is checked
before only missing chunks are sent. Download retries cache only ciphertext in
the browser's origin-private filesystem, scoped by account and file ID. Expired
cache folders are removed on subsequent download activity. Plaintext is streamed
into a browser-managed Blob for Hub's save operation; the browser controls that
Blob's memory/disk backing. No full-file JavaScript ArrayBuffer is constructed.

## Deployment and testing

Deploy the backend before publishing the updated QApp. The file feature uses the
existing private transport port (UDP 4445). No Hub update or relay restart is
needed. Backend restarts interrupt active calls and transfers; uploads can resume.

Run `uv run pytest tests/test_files.py` for the storage/access boundaries. Run the
QApp tests/build as usual. Before opening to users, test in Hub with two accounts:

1. Upload a file for the second account and copy the link.
2. Download there and compare its contents; an unlisted account must be denied.
3. Try an allowed group, then edit access and retry.
4. Pause/resume an upload with the original file; a different file must be rejected.
5. Sign into the uploader account on another device and copy the existing link.
6. Test a one-minute expiry and deletion; neither link should continue serving data.

Browser smoke checks use a mocked Hub bridge; real cross-device Hub authorization,
key recovery, and save permissions still require this manual end-to-end test.
