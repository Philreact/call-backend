# Temporary encrypted files

File sharing uses the existing authenticated Reticulum session to bootstrap a
`file-transfer` private channel. File requests and ciphertext then travel over
the reliable QUIC channel through MASQUE. No HTTP file endpoint, new public port,
or relay change is required. Calls keep their existing media transport.

## Access model

The uploader chooses a file and an expiry between one minute and 24 hours.
There is no per-file group or address list. A recipient needs both:

1. A Qortal account authorized by the backend's service-level access policy.
2. The unguessable private link containing that file's decryption key.

The backend runs its normal account/group authorization before dispatching every
file request. Possessing a link cannot bypass that check. After service
authorization, the link acts as the per-file invitation: any authorized account
holding it can fetch the ciphertext. The uploader can delete the file before
expiry, but forwarded links, in-flight data and downloaded copies cannot be
revoked.

This keeps uploads simple and prevents the backend from retaining per-file
recipient identities. The QApp explicitly tells uploaders that recipients must
belong to one of the service's approved groups. The backend rejects the obsolete
`access` create field instead of silently implying that an ignored guest list
still provides security.

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

Links have the form `qortal://APP/<app>/file/<id>.<key>`. The QApp extracts the
key locally; file requests contain the ID, never the clear key. The backend knows
the owner, encrypted size, timestamps, state and traffic metadata, but cannot
read the filename, MIME type, plaintext hashes, content or file key. Expiry is
enforced by this server, not cryptographic erasure of recipients' copies or
external backups.

## Storage and limits

- Maximum 3 GiB per file (shown as 3 GB in the UI), 3 GiB reserved per uploader,
  10 GiB globally. The expiry maximum applies to newly created links.
- Maximum 100 records per uploader and 1,000 active records globally.
- Four file workers with at most 16 queued/running file operations.
- Uploads start with four chunks in flight and grow to at most twelve on
  successful acknowledgements. BUSY responses reduce the window and trigger
  bounded backoff with identical ciphertext; other errors stop the upload.
  Downloads retain four chunks in flight.
- Owner lists are paged in groups of five; no unbounded list response.
- Upload-resume status is paginated at 4,096 chunk indices per response, keeping
  responses below the private channel's 64 KiB message limit even for 3 GiB files.

Storage lives in `data_dir/files` (the existing backend Docker volume): a SQLite
manifest/index and one ciphertext file per upload. On startup, databases from the
old guest-list model are migrated transactionally: existing uploads are retained
while `groups_json` and `users_json` are removed. Existing links then follow
the new service-access-plus-link rule.

Expiry rejects requests immediately; a five-minute sweeper removes expired
ciphertext and unfinished uploads. Expired metadata/recovery envelopes remain
for seven further days for the owner's expired view. Explicit deletion invalidates
the link and removes ciphertext; metadata is purged on the next sweep.

Chunks are immutable and acknowledged only after their bytes are synced to disk
and the SQLite index transaction is committed with full durability. Concurrent
upload requests for one file are collected for up to 5 ms and share one file
sync and index transaction. Batching is bounded to 16 pending chunks across the
store. Per-file locks coordinate writes, reads, deletion and cleanup; disk reads
and upload syncs do not hold the shared metadata lock.

An interrupted uploader selects the original file; its fingerprint is checked
before only missing chunks are sent. Download retries cache only ciphertext in
the browser's origin-private filesystem, scoped by account and file ID. Expired
cache folders are removed on subsequent download activity. Plaintext is streamed
into a browser-managed Blob for Hub's save operation; no full-file JavaScript
ArrayBuffer is constructed.

## Deployment and testing

Deploy the backend and updated QApp together because older QApps still send the
removed `access` field. Backend restarts interrupt active calls and transfers;
uploads can resume. The feature uses UDP 4445. No Hub or relay update is required.

Run `uv run pytest tests/test_files.py` and the QApp tests/build. Before release:

1. Upload a file and verify that the form only asks for the file and expiry.
2. Download using another account allowed by the backend service policy.
3. Verify an account outside every service-approved group is rejected during
   backend authentication, even while holding a valid link.
4. Pause/resume an upload with the original file; reject a different file.
5. Recover the uploader's link on another device signed into the same account.
6. Test expiry and deletion; neither link should continue serving data.
