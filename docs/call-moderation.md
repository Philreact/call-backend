# Call host moderation

Only the authenticated session that created a live call can moderate it. A second
session with the same account is not sufficient. Moderation never affects other
calls, account authentication, or file downloads.

The QApp sends `call_moderate` through its authenticated Reticulum connection:
`requestId`, `roomId`, `targetParticipantId`, and `operation` are required.

- `mute`: prevent this account from publishing audio in the room. Leaving and
  rejoining does not bypass the mute.
- `allow_mic`: remove the host restriction. The QApp does **not** automatically
  start the participant's microphone; they choose when to unmute.
- `remove`: remove active membership, release a screen-share slot, and block that
  Qortal account from rejoining this room, including through a new session.
- `readmit`: clear the room-specific block. The participant must use the invitation
  and satisfy ordinary authentication/access requirements to join again.

Membership updates contain `mutedParticipantIds`. Only the host receives
`call_moderation_result` with the removed-account list (`blockedParticipantIds`),
revision, requestId, accepted, and code. Removed clients receive `call_removed`.
The room ends when its host leaves; moderation lists end with it. Each list is
bounded to 256 accounts, and rooms still allow at most 32 concurrent participants.
Different Qortal accounts are different participants, not a device/IP ban.

## Media enforcement

The Python backend atomically writes each room's current account/session bindings
and mute restrictions into `call-media-revocations/rooms/<room-hash>.json` on the
existing shared backend volume. The Go media service requires this policy before
attaching and forwarding. Missing, invalid, expired or unreadable policy denies
access. Backend startup clears previous room policies because rooms do not survive
a backend restart. No key or media plaintext enters these files.

Fanout checks both publisher and recipient membership, and drops a muted account's
audio track while preserving its screen/feedback tracks. Room policy is cached
for at most 250 ms; revoked connections are also closed by the existing one-second
monitor. Already-transmitted packets cannot be recalled. QApps immediately stop
muted capture and discard affected participants' buffered audio after receiving
the control update. Moderation does not revoke recordings/keys already obtained
or prevent an allowed participant from sharing their own received content.

## Deploy and test

Rebuild **both backend and media** from this checkout (`docker compose up -d
--build`) and publish the updated QApp. Existing calls end on backend restart.
No Hub or MASQUE change is required. The old media service does not enforce these
new room policies; do not deploy only the Python portion.

With a host and another account, open **People**. Mute the other person: they
should see “Muted by host” and cannot unmute until allowed. “Allow mic” must not
turn their mic on automatically. Remove them while presenting: their screen slot
must clear and the same invitation must reject rejoining. Use **Removed → Allow
back**, then rejoin. Repeat a moderation attempt from a non-host account: it must
be rejected by the backend even if the UI is bypassed.
