# Q-App Reticulum wire protocol v1

This document freezes the wire protocol used by the local Qortal Desktop and
Python backend implementations. “MUST”, “SHOULD”, and “MAY” are normative.
Incompatible changes require a new destination aspect such as `v2`.

## Destination and shared Link

The backend MUST construct its inbound destination as:

```python
RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                "qortal-hub-v3", "qapp-backend", "v1")
```

The client constructs the corresponding outbound destination with the same
three segments. The full aspect is `qortal-hub-v3.qapp-backend.v1`.

For a Q-App isolation key and destination, Desktop pools one physical Link.
Reticulum `link.request()` RPC and realtime Channel/Buffer traffic MUST coexist
on that Link. Realtime uses `link.get_channel()` and bidirectional RNS Buffer
stream ID **7**. Writers MUST handle partial writes until the entire frame has
been accepted. The backend uses `RawChannelWriter` directly: there are no Python
buffered bytes to flush. A new Link always gets new Channel, reader, writer,
and parser objects.

Backend writes have a ten-second total deadline covering serialization-lock
wait, worker-queue wait, and partial writes. Zero-byte writes retry briefly
until that deadline. Eight daemon workers and a 64-job queue bound resource use
even if an underlying RNS call never returns; queued expired jobs cannot send.
If all workers remain stuck, new sends fail within the deadline rather than
spawning unlimited threads. A process restart may be needed in that exceptional
case, since Python cannot forcibly terminate a blocked native call.

A failed or timed-out write cancels that physical writer and closes its
connection; partial frames are never followed by new frames on that stream.
Link teardown is best effort on a separate bounded worker pool. Connection
state locks are not held during writes, so ACK processing and close remain
available. Replacement Links have independent writers and cancellation state.
These changes do not alter framing, identity proofs, group checks, or reconnect
authentication requirements.

## Frame format

All integers are unsigned and network byte order (big-endian):

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | version, exactly `1` |
| 1 | 1 | frame type |
| 2 | 8 | transport message ID |
| 10 | 4 | payload length |
| 14 | declared | payload |

The header is exactly 14 bytes (`>BBQI`). Frame types are DATA `1`, ACK `2`,
and CONTROL `3`. The maximum frame payload is 262,144 bytes and the maximum
receive accumulator is 524,288 bytes. Receivers MUST reject unsupported
versions/types and oversized declared lengths before collecting the payload.
Partial and coalesced Buffer reads are normal.

The canonical byte vectors are in `protocol-v1-vectors.json`; an identical copy
is checked into Qortal Desktop. Message IDs are hex strings there to avoid
JavaScript number precision loss.

## DATA payload

One DATA frame contains exactly one logical Q-App message. Its payload is a
compact UTF-8 JSON envelope with these fields in any JSON object order:

```json
{
  "connectionId": "rns-<UUID>",
  "payloadBase64": "...standard Base64...",
  "encoding": "json"
}
```

`connectionId` is the stable Desktop logical connection ID and multiplexes
multiple logical Q-App connections over one Link. `encoding` is exactly `json`
or `base64`. For `json`, Base64 decodes to one UTF-8 JSON value. For `base64`,
it decodes to arbitrary bytes. Standard padded Base64 is normative. JSON
whitespace and key order are not semantically significant; UTF-8, decoded
values, and envelope field meanings are normative.

Desktop `RNS_SEND` accepts a JavaScript JSON value or `Uint8Array`, but MUST
reject it if the resulting Base64 envelope exceeds the 256 KiB frame limit.
Backend server pushes use the same envelope and the target logical
`connectionId`. A backend learns that routing ID from the first DATA envelope;
transport connection IDs are routing handles, not authentication credentials.

## Message IDs, ACK, deduplication, and ordering

Each sender chooses a nonzero random 63-bit starting ID per physical/pool state,
then increments modulo `2^64`. One DATA message consumes one ID. An ACK has the
acknowledged ID in its header and a zero-length payload; it acknowledges exactly
one DATA frame. Unknown and duplicate ACKs are ignored.

Receivers retain the oldest-first 512 most recent DATA IDs in the relevant
logical/pool scope. New DATA is delivered once and ACKed. Duplicate DATA is not
delivered and is ACKed again. Channel ordering plus ordered retransmission of
complete pending frames defines transport order. No byte offset is resumed.

Each sender retains at most 64 unacknowledged complete frames and 2 MiB of
encoded queued frames. A new send crossing either bound is rejected. ACK timeout
is 120 seconds. v1 performs no timer-driven same-Link retransmission. A pending
frame is resent from its beginning, in message-ID order, when Desktop replaces a
failed Link. Timeout removes the pending frame and emits an error.

Transport deduplication does not provide business-operation idempotency. Unsafe
operations MUST carry an application `requestId`, `actionId`, or transaction ID.

## CONTROL payload

CONTROL is compact UTF-8 JSON. v1 supports:

```json
{"type":"PING"}
{"type":"PONG"}
{"type":"CLOSE","connectionId":"rns-<UUID>"}
```

PING is answered with PONG using the same header message ID. PONG requires no
response. CLOSE is idempotent and removes only a logical connection already
owned by the physical Link carrying the control. Later DATA for that closed ID
is ACKed but never delivered or allowed to recreate a session. Any other CONTROL
type or shape is a protocol error. CONTROL frames are not ACKed. v1 has no
transport HELLO, WELCOME, or RESUME messages.

Application-session authentication, resume tokens, subscriptions, and missed
event replay are application-layer concerns carried through DATA or RPC. They
MUST NOT be inferred from physical Link replacement or Q-App `connectionId`.

## RPC codec and behavior

Desktop calls `link.request(path, data=...)` on the pooled Link. `data` is this
native Reticulum dictionary:

```json
{
  "version": 1,
  "requestId": "application-operation-id",
  "encoding": "json",
  "payloadBase64": "..."
}
```

Encoding and Base64 rules match DATA. Paths MUST start with `/` and are limited
to 512 characters by Desktop. Decoded request payloads are limited to 256 KiB.
The backend returns the handler's native JSON-compatible value directly, or raw
bytes for a binary response. Desktop serializes native values as compact UTF-8
JSON and exposes them to the Q-App; bytes become `Uint8Array`. Responses are
limited to the caller-selected size, at most 1 MiB.

Backend errors are JSON objects containing `error.code`, `error.message`, and
the application `requestId` when available. Python exceptions and stack traces
MUST NOT cross the wire. Desktop does not automatically replay submitted RPCs
after timeout or ambiguous Link failure.

The reference `/hello` request with `{ "name": "Alice" }` and request ID
`request-0001` returns:

```json
{"message":"Hello, Alice","requestId":"request-0001"}
```

## Reconnect and lifecycle

Desktop owns outbound physical reconnect with exponential backoff starting at
0.5 seconds, multiplier 2, jitter 0.8–1.2, and a 30-second cap. Stable logical
connection IDs remain open while a Link is replaced. Incomplete parser bytes
are discarded. Complete unacknowledged frames are resent from their beginning.

`RNS_CLOSE` sends a logical CLOSE control before removing local ownership. If it
removes the last logical connection while reconnect is pending, the timer
observes an empty connection set and MUST NOT open or resurrect a Link. RPC
submissions are never placed in the realtime retransmit queue.

An unused pooled Desktop Link is eligible for teardown after 300 seconds when
it has no logical connections, active requests, or unacknowledged messages.

## Optional Qortal group access

After validating the signed Qortal identity proof, a restricted backend MUST
confirm that the proven address belongs to at least one configured Qortal
group before promoting the application session. It MUST NOT query group
membership for an unverified address. A confirmed non-member receives
`BACKEND_ACCESS_DENIED`; failure of every configured Core receives
`BACKEND_ACCESS_UNAVAILABLE`. Neither result creates a persistent authenticated
session or permits private-transport bootstrap.

Group authorization is independent of Q-App allowlisting and MASQUE-relay
authorization. A restricted deployment requires all configured checks to
succeed. Active authorization is periodically refreshed. A definitive removal
revokes room membership, unused attachment credentials, the private transport,
and the active MOQT media session.

## Security limits

RNS identity proves a Reticulum peer identity, not a Qortal account. Q-App
logical IDs and transport ACKs provide neither user authentication nor durable
operation deduplication. Implementations MUST bound frame accumulation, pending
queues, dedup caches, and RPC bodies, and MUST NOT log private identities,
resume/authentication secrets, or sensitive application payloads.
