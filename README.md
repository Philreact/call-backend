# Q-App Call Backend

An application-neutral call backend providing authenticated Qortal sessions over
Reticulum plus private MASQUE/QUIC transport. Call media uses a separate Go MOQT
process that blindly forwards encrypted media objects; it never receives media
encryption keys and cannot decode call content.

## Included

- Reticulum RPC and realtime messaging
- signed `qortal-qapp-auth-v1` identity authentication
- Q-App identity allowlisting
- persistent authenticated application sessions
- private-channel bootstrap bound to the authenticated Reticulum session
- reliable QUIC messages and QUIC datagrams through a MASQUE relay
- initiator-owned call rooms that expire after at most three hours
- invitation-gated membership with authenticated participant IDs
- bounded initiator-to-participant group-key delivery over Reticulum
- short-lived, one-time MOQT credentials bound to room, participant, track, and Q-App
- a separate MOQT media process on UDP `4446`
- narrowly scoped `private_transport_echo` diagnostics

## Simple setup guide

### 1. Requirements

Install Git, Docker Engine, and the Docker Compose plugin. Confirm Docker is
available:

```bash
docker --version
docker compose version
```

### 2. Download and configure the backend

Clone or download this repository, enter its directory, and create the local
configuration file:

```bash
cd qapp-backend-call
cp config.example.toml config.toml
```

The example accepts any Q-App, which is convenient while testing. Before a
public production deployment, edit `config.toml` and restrict access to the
Q-App names that should use this backend:

```toml
enforce_qapp_allowlist = true
allowed_qapps = [{ name = "qapp-ui-call", service = "APP" }]
```

Replace `qapp-ui-call` with the published Q-App name when it differs. Q-App
names are lowercase; the service is normally `APP`.

To restrict the backend to members of selected Qortal groups, add this policy
to `config.toml`:

```toml
access_mode = "groups"
allowed_group_ids = [1144]
core_url_bases = [
  "http://host.docker.internal:12391",
  "https://ext-node.qortal.link"
]
access_revalidate_interval = 1800
access_outage_grace = 3600
```

Replace `1144` with the group IDs intended for the deployment.
An address is accepted when it is a member of any listed group. The backend
verifies the signed Qortal identity before making a membership request. New
sessions fail closed if every Core is unavailable. Active sessions are checked
every 30 minutes; a confirmed removal is revoked immediately, while the last
successful result can survive a Core outage for at most one hour. Prefer a
local Core URL and use remote HTTPS nodes only as backups.

Use `access_mode = "public"` with empty `allowed_group_ids` and
`core_url_bases` to accept every correctly authenticated Qortal address.
`groups` mode with an empty group or Core list is rejected at startup, so a
configuration mistake cannot silently make a restricted backend public.

### 3. Choose the network setup

For a home connection, enable UPnP on the router. No `.env` file is normally
needed. The backend automatically creates and renews UDP mappings for ports
`4445` and `4446`.

For a VPS with a public IP, no `.env` file is normally needed either. The
backend detects the public address. Allow both UDP ports in the VPS provider's
firewall, and in UFW when UFW is active:

```bash
sudo ufw allow 4445/udp
sudo ufw allow 4446/udp
sudo ufw status
```

If the machine is behind NAT and automatic UPnP is unavailable, copy the
example environment file and enter the real public IP:

```bash
cp .env.example .env
```

```dotenv
QAPP_BACKEND_PUBLIC_HOST=203.0.113.10
QAPP_BACKEND_UPNP=false
```

Replace `203.0.113.10` with the actual public IP, then manually forward UDP
ports `4445` and `4446` from the router to this machine.

### 4. Start the backend

```bash
docker compose up -d --build --wait
```

The command starts three services: the Reticulum backend, the QUIC media
process, and the automatic network helper. Their state should be `running` or
`healthy`:

```bash
docker compose ps
```

### 5. Confirm the public network address

```bash
docker compose logs --tail=100 network
```

Look for either a directly detected public address or successful UPnP mappings
for UDP `4445` and `4446`. If the `network` service is unhealthy, the backend
will wait instead of advertising an unreachable address.

### 6. Get the Reticulum destination

```bash
docker compose logs backend | grep -m1 -oE 'destination [0-9a-f]{32}'
```

The 32-character value after `destination` is the stable backend destination.
It remains the same while the `backend-data` Docker volume is preserved.
Configure this value as the call backend destination in the companion Q-App.
For `qapp-ui-call`, set `DEFAULT_CALL_BACKEND_DESTINATION` in
`src/call/config.ts` before building and publishing the Q-App. A development
build may instead set `VITE_CALL_BACKEND_DESTINATION`.

### 7. Useful commands

```bash
# Follow logs
docker compose logs -f

# Restart after changing configuration
docker compose up -d --build --wait

# Stop without deleting identities or application data
docker compose down
```

Do not run `docker compose down -v` unless you intentionally want to delete the
backend identity, database, certificates, and network state.

### How automatic networking works

The bundled network helper chooses the first usable method:

1. `QAPP_BACKEND_PUBLIC_HOST` from `.env`, when explicitly configured.
2. A public IPv4 address attached directly to the host, as on most VPSs.
3. Automatic UPnP mappings for UDP `4445` and `4446`, as on many home routers.
4. A directly attached public IPv6 address when IPv4 and UPnP are unavailable.

The helper keeps UPnP leases alive and refreshes the address shared with the
backend. The backend returns the current reachable address during private
transport bootstrap. It does not publish a separate backend directory.

## Local development

```bash
cp config.example.toml config.toml
uv sync
uv run qapp-backend-call --config config.toml --check-config
uv run qapp-backend-call --config config.toml --print-destination
uv run qapp-backend-call --config config.toml
```

Set the printed destination as `VITE_CALL_BACKEND_DESTINATION` in the companion
`qapp-ui-call` project.

Private-transport diagnostics use UDP `4445`. MOQT call media uses UDP `4446`.
Clients reach these public endpoints only through a selected MASQUE relay; no
direct client fallback is used. The backend therefore sees the relay's source
address for normal client traffic.

Authentication uses `/auth/challenge` followed by an `AUTHENTICATE` realtime
message containing the proof returned by Qortal Desktop's
`SIGN_QAPP_IDENTITY` action. Private transport cannot bootstrap until that same
application session has authenticated.

An authenticated initiator sends `call_create` with a URL-safe room ID, an
invitation-token hash, and ephemeral P-256/Ed25519 public keys. Guests use the
shareable invitation to send `call_join`. The initiator's Q-App then sends the
single call key to each guest inside an opaque, per-recipient envelope. Leaving
or disconnecting the initiator ends the room. See
[docs/call-protocol.md](docs/call-protocol.md).

After joining, a client can request the private bootstrap with purpose
`realtime`. The returned credential expires after 30 seconds and can be
consumed once by the MOQT process. The token is passed inside the inner TLS
session, so the MASQUE relay cannot read it. The media process only authorizes
`qortal/call/<room>/<participant>` and the bounded `audio`, `screen`, and
`feedback` tracks. It forwards their encrypted objects without receiving the
call key. If backend access is revoked, unused media credentials are deleted
and the participant's active media connection is closed through a local-only
revocation marker.

## Verification

```bash
uv run pytest
docker run --rm -v "$PWD/network:/src" -w /src golang:1.26-bookworm go test ./...
docker run --rm -v "$PWD/media:/src" -w /src golang:1.26-bookworm go test ./...
```
