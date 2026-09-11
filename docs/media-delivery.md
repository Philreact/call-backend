
## Media scheduling

The media service now schedules outgoing MoQ datagrams per recipient connection,
instead of forwarding every track immediately into the QUIC queue. Audio uses
priority 0 / 120 ms queue lifetime; feedback uses priority 0 / 500 ms; screen
uses priority 1 / 200 ms. These are local queue deadlines, not maximum network
latency. High-latency participants are not rejected.

The shared generic scheduler bounds track/session memory, reserves queue space
between classes, provides weighted fair service, paces bursts, and reacts to
QUIC loss/RTT pressure. Slow recipients have independent schedules. Authorization,
host mute/removal checks, encrypted payloads and relay discovery are unchanged.
Publishers cannot override backend-assigned priorities.

Deploy with the normal Docker Compose rebuild. The matching Hub 0.9.0 sidecar
adds uplink scheduling and the updated QApp adapts screen bitrate from transport
pressure as well as receiver feedback. No relay change is required. This does
not guarantee audio quality if capture, decoding or the physical link stalls.

