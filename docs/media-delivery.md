# Media delivery

Audio uses MoQ datagrams with priority 0 and a 120 ms local queue lifetime.
Feedback uses priority 0 / 500 ms. These are local queue deadlines, not maximum
participant RTT. Screen video uses complete encrypted reliable objects rather
than a stream of independently encrypted fragments.

The service accepts at most 1 MiB for a reliable object and 1 KiB for a datagram.
Each recipient/track has a two-object forwarding queue. Queue residence is
subtracted from the 1500 ms reliable delivery budget. Expired queued objects
are skipped. Each frame is forwarded on its own subgroup, preserving group and
object IDs; newer dependency groups abandon obsolete stream retransmissions.

The vendored MoQ layer implements real FIN, bounded reset leases, per-publication
and session byte limits, and stream-local failure handling. Slow recipients do
not block other recipient workers. Publisher priority cannot override backend
policy. Neither the backend nor the relay decrypts, decodes or transcodes media.
Membership, mute/removal checks and authenticated attachment remain enforced.

Deploy the rebuilt backend AND media services together. The authenticated
bootstrap advertises `moqtReliableGroups: true`, required by the matching Hub
transport. Update Hub and the QApp as well; no relay change is needed.
There is no fragmented/old-backend fallback.

Independent datagram scheduling and bounded stream queues reduce interference;
they do not guarantee bandwidth or QUIC stream priority. All tracks share the
connection and physical path. Validate concurrent audio and screen sharing over
the actual relay route before production rollout.

Verification includes opaque 150 kB reliable-object forwarding between real
authenticated local QUIC clients, track isolation, slow-recipient fanout,
cancelled-stream session survival, FIN/reset expiry and wire allocation limits.
The tests are not proof of large-group or WAN performance.
