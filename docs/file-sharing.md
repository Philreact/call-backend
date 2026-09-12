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
- Native QUIC and disk I/O with eight in-flight frames per connection and 32
  globally; Python receives only bounded control and chunk metadata. See
  [native data plane](native-data-plane.md) for full budgets.
- Updated Hub/QApp clients use binary batches of up to 16 encrypted chunks
  (about 512 KiB), starting with four batches and growing to eight in flight.
  Legacy clients start with four individual chunks and grow to twelve on
  successful acknowledgements. BUSY responses reduce the window and trigger
  bounded backoff with identical ciphertext; other errors stop the upload.
  Downloads retain four chunks in flight.
- Owner lists are paged in groups of five; no unbounded list response.
- Upload-resume status is paginated at 4,096 chunk indices per response, keeping
  responses below the JSON private channel's 64 KiB limit even for 3 GiB files.

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
and the SQLite index transaction is committed with full durability. Binary
batches validate all records before writing and share one sync/index transaction
per batch. Replaying identical ciphertext is idempotent; conflicting ciphertext
is rejected. Cross-process file locks coordinate writes, reads, deletion and
cleanup; native disk reads and upload syncs do not hold Python's shared metadata
lock. Legacy single-chunk requests also use the native disk path.

An interrupted uploader selects the original file; its fingerprint is checked
before only missing chunks are sent. Download retries cache only ciphertext in
the browser's origin-private filesystem, scoped by account and file ID. Expired
cache folders are removed on subsequent download activity. Plaintext is streamed
to Hub's bounded streaming-save operation; no full-file JavaScript ArrayBuffer
is constructed.

## Deployment and testing

Deploy the backend and updated QApp together because older QApps still send the
removed `access` field. Backend restarts interrupt active calls and transfers;
uploads can resume. The feature uses UDP 4445. Faster binary uploads require
updated Hub with sidecar 0.10.0, backend, and QApp; no relay update is required.
The QApp checks Hub's binary size capability and the backend's `capabilities`
operation, falling back to individual chunks when binary upload is unsupported.

The binary upload format is `QFB1`, a 16-byte file ID, a big-endian uint16 count,
then 1–16 records of big-endian uint32 index, uint32 byte length, and ciphertext.
It changes neither encryption nor the stored chunk format. Account/group checks
precede parsing and dispatch. Large frames are only admitted on authenticated
keyed streams; unauthenticated/primary frames remain capped at 64 KiB.
Retained partial frames are additionally bounded to 4 MiB per connection.

Run `uv run pytest tests/test_files.py tests/test_files_binary.py` and the QApp
tests/build. The `test_upload_storage_benchmark` tests in
`tests/private_transport/test_quic_admission.py` compare real loopback QUIC and
durable disk writes with simulated acknowledgement latency; they do not model
Hub IPC, MASQUE, encryption, or WAN performance. Before release:

1. Upload a file and verify that the form only asks for the file and expiry.
2. Download using another account allowed by the backend service policy.
3. Verify an account outside every service-approved group is rejected during
   backend authentication, even while holding a valid link.
4. Pause/resume an upload with the original file; reject a different file.
5. Recover the uploader's link on another device signed into the same account.
6. Test expiry and deletion; neither link should continue serving data.
