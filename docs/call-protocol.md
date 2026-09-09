# Initiator-owned call control and protected media protocol v1

Call control runs over the authenticated Reticulum application session. The
backend derives every participant ID from that session and never accepts a
sender ID supplied by the Q-App.

## Temporary room and invitation

The initiating Q-App creates a random room ID, a 256-bit invitation token, and
a separate random 256-bit call key. It sends `call_create` with only the
SHA-256 invitation-token hash and its ephemeral P-256/Ed25519 public keys. The
backend creates the room for no more than three hours and records that
authenticated participant as its initiator.

The shareable URL fragment contains the room ID and invitation token, never the
call key. A guest sends `call_join` with that invitation token and its own
ephemeral public keys. Rooms are limited to 32 authenticated participants.

Membership snapshots identify the initiator, expiration time, participants,
public keys, and each participant's authorized MOQT track. Their monotonically
increasing revision is only an ordering counter; it does not rotate the call
key.

## Group-key delivery

Only the initiating Q-App can send `call_group_key`. For each newly joined
participant, it derives a pairwise wrapping key using ephemeral P-256 ECDH and
HKDF-SHA-256, encrypts the single call key with AES-256-GCM, and signs the
envelope with its ephemeral Ed25519 identity. The backend validates that the
sender is the room initiator, injects the authenticated sender ID, and forwards
the opaque envelope to exactly one current participant. It cannot decrypt it.

Each Q-App derives a different AES media key for every sender from the shared
call key and the sender's room/participant/track context. Media frames remain
Ed25519-signed by their actual sender, so possession of the shared call key
does not let one participant impersonate another.

## Room lifecycle

If a guest leaves, the room continues and the membership ordering counter
advances. If the initiator leaves or its authenticated Reticulum session
disconnects, the backend deletes the room and sends `call_ended` to all other
participants. A timer performs the same cleanup at the three-hour limit.
Clients close MOQT and erase the call key on any of those events.

## Protected media frames

Media protection is implemented by `qapp-ui-call`, not Hub or the backend.
Each encoded frame contains a version, key ID, sequence, random nonce,
AES-256-GCM ciphertext, and Ed25519 signature. Room, sender, and track are
authenticated associated data. Receivers verify the signature and AEAD before
accepting a frame and retain a 64-packet replay window.

Encoded payloads are limited to 900 bytes so the protected frame remains under
the generic 1024-byte MOQT object limit. The media backend routes protected
objects without parsing or transforming them.

The current binding between a Qortal address and ephemeral public keys is
provided by the authenticated backend session. If the backend itself must be
treated as an active key-substitution adversary, a later hardening step must
add Qortal-account signatures over those keys.
# Screen sharing

Authenticated room members send `call_screen_start`, `call_screen_stop`, or
`call_screen_renew` with `requestId`, `roomId`, and a fresh `shareId` (8–128 safe
identifier characters). The backend derives the participant from the authenticated
session, never a caller-supplied participant ID. A room has at most one presenter.

The reply is `call_screen_result` with the same request/room IDs, `accepted`,
`code` (empty, `SCREEN_BUSY`, or `SCREEN_NOT_OWNER`), and
`screenShare: { revision, participantId, shareId }`. Empty IDs mean no presenter.
Changes are broadcast as `call_screen_state` with `roomId` and `screenShare`.
Membership snapshots include this state so late joiners know the current presenter.
Repeated start by the same owner/share is idempotent; stale share IDs cannot stop
or renew a newer presentation. The slot expires after 45 seconds without renewal;
clients renew every 10 seconds. Disconnect, stop, and room end also release it.

VP8 screen frames are fragmented and encrypted in the Q-App on the existing MoQ
media track. The backend and media process do not decode frames or receive keys.
The receiving Q-App checks both the signed sender and current `shareId` before
assembling a frame. The single-presenter policy therefore combines backend
reservation with receiver enforcement; it is not plaintext inspection at the relay.
Screen frames are capped at 256 KiB and 1280×720, targeting 30 fps without system audio.
QCS2 framing includes encrypted XOR repair packets; QCF2 recovery requests are
also inside authenticated encrypted media. Neither changes the backend protocol.
