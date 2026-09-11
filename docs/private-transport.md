# Private transport bootstrap

The default private transport binds an authenticated Q-App `ApplicationSession`
to an end-to-end QUIC connection carried through a MASQUE CONNECT-UDP relay.
Reticulum remains the authentication and bootstrap authority.

## Session and bootstrap

Desktop sends `/qortal/private-transport/bootstrap/v1` on the same physical RNS
Link as an owned logical Q-App connection. The RNS envelope carries the internal
logical connection ID; it is not supplied by the iframe. The JSON payload is:

```json
{
  "version": 1,
  "transport": "quic-masque-inner-v1",
  "nonce": "fresh base64url nonce",
  "purpose": "game"
}
```

The backend requires that the logical ID belongs to the requesting Link and
maps to a live, non-provisional `ApplicationSession` with a verified Qortal
address and canonical signed Q-App identity. It derives all endpoint, identity,
session, and owner fields itself. The response is:

```json
{
  "version": 1,
  "transport": "quic-masque-inner-v1",
  "logicalSessionId": "backend ApplicationSession.session_id",
  "backendRnsDestination": "32-character destination hash",
  "backendTransportEndpoint": "literal-ip:port",
  "backendTransportServerName": "qapp-private-backend",
  "backendTransportCertSha256": "64-character leaf DER hash",
  "attachToken": "single-use opaque token",
  "expiresAt": 0,
  "nonce": "request nonce",
  "ownerBindingHash": "sha256 binding",
  "supportedFeatures": {"reliable": true, "datagrams": true}
}
```

The owner binding covers canonical Q-App name/service, Desktop logical
connection ID, backend RNS destination, backend logical session ID, nonce, and
purpose. The stored grant additionally binds the verified Qortal address. A
renderer-provided owner hash is never trusted or echoed.

Attach tokens contain 256 random bits (`secrets.token_urlsafe(32)`). Only their
SHA-256 hashes are retained. They expire after 30 seconds by default, are
consumed atomically, and are consumed even if another ATTACH binding is wrong.
Session or RNS-logical-connection closure revokes unused tokens and closes the
attached private transport. A private QUIC disconnect only clears
`session.private_transport`; it does not close the Reticulum connection or the
application session.

Limits default to four bootstrap credentials per session/RNS logical connection
per minute, eight per authenticated user per minute, four outstanding per
session, and 1024 outstanding globally.

## QUIC listener

The backend uses `aioquic` with ALPN `qortal-private/1`, a 1200-byte QUIC packet
and DATAGRAM ceiling, the Step 3 `QP3F` stream framing, and native `QP3D` QUIC
DATAGRAM payloads. ATTACH must be the first application frame. No application
message is dispatched before the token is accepted.

### Independent reliable streams

The ATTACHED response advertises `reliableStreams: true`. The original attach
stream stays open for legacy clients. After authentication, clients may open
up to 32 additional bidirectional streams. Each uses the same QP3F frames and
has its own parser; replies return on the originating stream, including replies
produced asynchronously. A new stream inherits the connection's authenticated
session, never a client-supplied identity or stream name.

A stream FIN drains its outstanding replies before the backend sends FIN.
Reset, timeout or malformed framing on an additional stream resets that stream
without disconnecting the others. Incomplete final frames are rejected. Late
replies to expired/reset requests are dropped, not redirected to another stream.
There are at most 16 pending requests per stream, 128 per connection, with a
30-second reply deadline. Outgoing unacknowledged data is capped at 256 KiB per
stream and 2 MiB per connection. The send-buffer adapter reads aioquic internals
because its queue API has no drain method; test it when upgrading aioquic.

The call app uses one stream per active upload/download, one for file-management
requests, and one for reliable diagnostics. Bulk file operations and management
operations have separate bounded worker pools. Audio/screen/feedback remain
MoQ datagrams on the separate media connection; this does not change them.

Roll out this backend before Hub sidecar 0.8.0 and the updated QApp. Old clients
keep using the original stream. New clients report unsupported streams against
an older backend. No relay update or new listening port is required.

Development mode creates an ECDSA P-256 self-signed certificate and private key
under the backend data directory when neither file exists. The private key is
mode `0600`. Docker/production-shaped configurations refuse automatic creation
and require an operator-provisioned pair.

Rotation is deliberately simple: stop issuing bootstraps, allow the at-most
30-second credentials to expire, atomically replace the configured certificate
and key, and restart. Every new descriptor contains the exact current leaf DER
fingerprint. Desktop pin verification is never relaxed. A future zero-downtime
rotation can run current and next listeners during a bounded overlap.

Direct development can configure a fixed local endpoint with:

```toml
private_transport_bind_host = "127.0.0.1"
private_transport_public_host = "127.0.0.1"
private_transport_port = 0
```

The public host must be a literal IP reachable by discovered MASQUE relays.

Docker deployments default both public hosts to `auto` and use the bundled
host-network helper. It uses an explicitly configured public IP first, then a
directly attached public IPv4 address, UPnP, and finally a directly attached
public IPv6 address. The helper records its fresh result in the private
`network-data` volume; the backend validates and rereads that state when issuing
each bootstrap descriptor. UPnP maps and renews the configured diagnostic and
media UDP ports and removes them on a clean shutdown.

For a host behind provider-managed NAT or a router without UPnP, configure the
public IP explicitly and arrange forwarding for both UDP ports:

```dotenv
QAPP_BACKEND_PUBLIC_HOST=203.0.113.10
QAPP_BACKEND_UPNP=false
```
