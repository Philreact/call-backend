# Local MoQT dependency

Upstream: https://github.com/mengelbart/moqtransport
Revision: 9eaf40a4dedd549b6838cba1a900f9b382d722e8
Wire profile: moqt-18, the profile implemented by that revision.

This directory contains the core, QUIC adapter, wire codec, varint package,
upstream tests and license. Examples, WebTransport adapter and development
generators are omitted. The parent module selects this copy using Go replace;
there are no module-cache edits or install-time patches.

Local change: complete IncomingSubscribeRequest.SendDatagram using the existing
draft-18 OBJECT_DATAGRAM encoder and Connection.SendDatagram. Zero object IDs
use the defined flag; explicit publisher priority is 0. Subgroup IDs are
rejected because they have no datagram wire field. Transport errors, including
oversized packets, propagate without retries or conversion to streams.

Run the parent module tests and this module's tests when updating the pin.
This patch does not complete the library's other unfinished APIs or establish
interoperability with another implementation.

Generic delivery scheduling: delivery.go adds local deadline/priority policy,
bounded per-session/per-track queues, reserved class capacity, weighted fair
service, pacing and pressure metrics. ScheduleDatagram is nonblocking;
SendScheduledDatagram / ScheduleDatagramResult provide producer backpressure.
The QUIC adapter supplies public connection stats, without modifying quic-go.
Scheduled publisher priority uses the existing draft-18 wire field; payloads
are opaque and no application track names appear in this library.

Keep this patch byte-identical in Hub and the backend's vendored module.
Run delivery_test.go (including the race detector) and the parent real-MASQUE
integration tests. No claim of cross-implementation MoQ compatibility is added.
