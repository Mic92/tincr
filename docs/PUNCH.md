# TCP simultaneous-open punch

When an `AutoShortcut` candidate exhausts every address (TCP and UDP
unreachable) but a relayed meta path exists, tincr coordinates a TCP
simultaneous open through the relay so both peers' SYN packets cross
in flight. Both firewalls see "outbound" first, so the inbound SYN
matches state. The relay hop collapses to a direct connection.

This is the same technique libp2p calls
[DCUtR](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md),
implemented natively over tinc's existing meta relay.

## Wire

Two `REQ_KEY` extension sub-types (relayed verbatim through legacy
nodes; legacy endpoints log-and-ignore unknown reqnos):

```
REQ_KEY <from> <to> 64 v1;<nonce>;<addrlist>   ; PUNCH
REQ_KEY <from> <to> 65 v1;<nonce>              ; PUNCH_SYNC
```

The payload is a single token. `v1` is the punch version. `<nonce>`
(16 hex digits) identifies one round: B picks it, A echoes it, SYNC
carries it. Messages with an unknown version or a stale nonce are
dropped. `<addrlist>`: comma-separated `addr_port` pairs, e.g.
`203.0.113.7_42012,2001:db8::7_42012`. Capped at 4.

## Sequence

```
B → A : PUNCH [B's addrs]    ; B records t0
A → B : PUNCH [A's addrs]    ; A waits for SYNC
B → A : SYNC                 ; B: rtt = now - t0, dial at +rtt/2
                             ; A: dial immediately on receipt
```

B is the side whose `AutoShortcut` slot exhausted its addr cache. B
delays because SYNC needs ~rtt/2 to reach A over the relay while B's
direct SYN takes the short path; the measured PUNCH round trip (not
the smoothed meta SRTT) times the delay. Simulation across firewall
behaviors and latency mixes: this ordering succeeds in one shot where
the reverse (B dialing immediately) systematically lands B's SYN
before A has state.

If both sides start a punch at once, the lexicographically lower name
keeps the B role and the other side folds to A.

## Sockets

Each side binds a fresh **ephemeral-port** TCP socket (one per
address family) **before** sending `PUNCH`, advertises
`(global_ip, ephemeral_port)`, and `connect()`s from that same socket
on dial. No `SO_REUSEPORT`, no listener interaction. If both SYNs
cross, the kernel completes the handshake (RFC 793 §3.4); if only one
gets through, it lands on the peer's `SYN_SENT` socket and the kernel
treats it as sim-open anyway.

Because the advertised port is the local ephemeral port, this works
when the obstacle is a **stateful ingress filter without NAT** (the
local port equals the wire port). Behind a port-translating NAT the
advertised port won't match the external one and the punch fails —
known v1 limitation.

## Triggering

- `AutoConnect = yes` (default) and a shortcut slot has exhausted its
  address cache.
- A relayed meta path to the peer exists.
- Not behind a `Proxy =` (proxies own the socket).

No new config knob. `AutoConnect = no` disables.

## Lifecycle

Pre-bound sockets and state are stored per peer. Cleared on:
- successful direct connection (any path)
- expiry (B: 2 s waiting for A's reply; A: 3 s waiting for SYNC)
- shutdown / reload

A dial killed by an inbound RST (peer's firewall answered our early
SYN) is retried up to 3 times from the same port after 50 ms — the
firewall pinhole from the first SYN outlives the socket. Fully failed
punches are throttled by the existing `shortcut_backoff` (60 s).

## Systemd hardening

Punch binds ephemeral ports — same footprint as outgoing meta
connects. No new capability. The NixOS module sets
`SocketBindDeny=any` + `SocketBindAllow` (listen port + ephemeral
range) as a tightening; the punch socket falls in the ephemeral
range.

## Test coverage

- `punch.rs::tests`: state machine transitions, dial-delay clamping,
  expiry, payload round-trip.
- `tinc-proto/src/msg/key.rs::req_key_punch_roundtrip`: wire format.
- `tinc-proto/src/msg/key.rs::req_key_unknown_reqno`: legacy peer
  graceful-ignore.
- TODO: end-to-end netns test with iptables-filtered listeners. The
  existing `tests/netns/` rig can express the topology (3 nodes, one
  shared netns, conntrack `--state NEW` filter); needs a non-loopback
  interface inside the bwrap netns so `punch_prepare` has an addr to
  advertise, plus careful iptables/startup ordering so a normal
  connect can't slip through before the rules land.

## Compatibility

- Legacy C peers: `req_key_ext_h` ignores unknown reqnos. C relays
  forward verbatim. Mixed meshes are safe.
- reqno 64/65: well above C's `LAST = 24` guard so future upstream
  growth won't collide.
