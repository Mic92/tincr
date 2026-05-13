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
REQ_KEY <from> <to> 64 <addrlist>     ; PUNCH
REQ_KEY <from> <to> 65                ; PUNCH_SYNC
```

`<addrlist>`: comma-separated `addr_port` pairs, e.g.
`203.0.113.7_42012,2001:db8::7_42012`. Capped at 4.

## Sequence

```
B → A : PUNCH [B's addrs]    ; B records t0
A → B : PUNCH [A's addrs]    ; A starts a SYNC fallback timer
B → A : SYNC                 ; B dials A's addrs immediately
   ↓ at A on SYNC: wait RTT/2 (A's meta SRTT to B's nexthop), then dial B's addrs
```

B is the side whose `AutoShortcut` slot exhausted its addr cache. RTT
on B's side is informational; A times its delay from its own SRTT
estimate.

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

Failed dials are throttled by the existing `shortcut_backoff` (60 s).

## Systemd hardening

Punch binds ephemeral ports — same footprint as outgoing meta
connects. No new capability. The NixOS module sets
`SocketBindDeny=any` + `SocketBindAllow` (listen port + ephemeral
range) as a tightening; the punch socket falls in the ephemeral
range.

## Test coverage

- `punch.rs::tests`: state machine transitions, RTT clamping,
  expiry, addrlist round-trip.
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
