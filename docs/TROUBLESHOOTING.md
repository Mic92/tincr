# Troubleshooting

Symptom → likely cause → how to confirm → fix. Commands assume
`tinc -n NET ...`; substitute your network name. See
[OPERATING.md](OPERATING.md) for the diagnostic commands referenced
here.

## Quick index

| Symptom | Jump to |
|---|---|
| `Decrease in PMTU to X detected` loops | [PMTU oscillation](#pmtu-oscillation) |
| `Ignoring unauthorized ADD_SUBNET` flood | [StrictSubnets mismatch](#ignoring-unauthorized-add_subnet-floods) |
| Traffic stuck on TCP relay, never goes UDP | [No direct UDP](#no-direct-udp-stuck-on-tcp) |
| DHT never publishes / publishes v6-only | [DHT publish gated](#dht-never-publishes--publishes-v6-only) |
| C tinc peer can't connect | [Legacy protocol](#interop-with-c-tinc-fails) |
| Wrong relay chosen / detour routing | [Edge weight](#traffic-detours-through-a-slower-relay) |
| High latency / idle CPU use / suspected daemon bug | [Event-loop strace](#reading-strace-for-event-loop-health) |

---

## PMTU oscillation

**Symptom** - log fills with

```
tincd::net: Decrease in PMTU to bob detected, restarting discovery
tincd::net: Increase in PMTU to bob detected, restarting discovery
```

and `tinc info bob` shows `PMTU:` flapping between two values.
Throughput is poor (every restart drops back to TCP for a few
seconds).

**Cause** - the path MTU genuinely changes (ECMP across links with
different MTUs, a flapping tunnel underneath), or an on-path
middlebox eats large probes inconsistently.

**Confirm** - `tinc -n NET info PEER` repeatedly; watch `PMTU:` and
the `min`/`max` columns in `tinc dump nodes`. If `min` keeps
collapsing to 0 the probes are being dropped, not just resized.

**Workaround** - pin the MTU for that peer in `hosts/PEER`:

```
PMTU = 1400
PMTUDiscovery = no
```

and/or set `ClampMSS = yes` (default) so TCP-in-tunnel never tries
to exceed it. Restart (per-host options are read at handshake
time). Pick a value at or below the lower of the two observed
PMTUs.

---

## `Ignoring unauthorized ADD_SUBNET` floods

**Symptom** - journal fills with

```
tincd::proto: Ignoring unauthorized ADD_SUBNET for carol (10.0.3.0/24) (strictsubnets)
```

(or `(tunnelserver)`), often hundreds per second after a node
joins.

**Cause** - you run with `StrictSubnets = yes` (or
`TunnelServer = yes`) and a peer is announcing a subnet that is not
in your on-disk `hosts/carol`. Usually: your `hosts/` directory is
stale, or someone added a `Subnet =` on their node without
distributing the updated host file. The message is **harmless** -
the subnet is rejected locally but still forwarded so non-strict
nodes can use it.

**Confirm** - `grep Subnet /etc/tinc/NET/hosts/carol` and compare
to what `tinc -n NET dump subnets | grep carol` on a non-strict
node shows.

**Fix** - sync `hosts/` and `tinc -n NET reload`. To silence
without syncing, drop the log level for the proto target:
`RUST_LOG=info,tincd::proto=error` (you lose other proto warnings).

---

## No direct UDP, stuck on TCP

**Symptom** - `tinc -n NET info PEER` shows

```
Reachability: directly with TCP
```

or

```
Reachability: indirectly via HUB
```

and never advances to `directly with UDP`. `Status:` lacks
`udp_confirmed`. Throughput is capped (TCP-in-TCP) or latency is
one extra hop.

**Causes & checks**, in order:

1. **Firewall drops UDP to your `Port`** on one or both ends.
   Check with `nc -u -l PORT` on the peer and `nc -u PEER PORT`
   from here (outside the tunnel).

2. **Port mapping failed** so the peer's NAT has no inbound rule.
   On the peer: no `Portmapped Tcp ...` line at INFO; at debug,
   `tincd::portmap: map V4/Tcp 655: SSDP discover: no IGD reply
   within timeout` or `PCP v4: timed out`. See
   [OPERATING.md § Port mapping](OPERATING.md#port-mapping-operations).

3. **Asymmetric UDP** - your outbound probes reach the peer but
   their UDP replies are filtered on the way back (stateless
   inbound-UDP drop, common on campus / corp networks). tincd
   handles this: the peer acks your probe over the meta connection
   (`MTU_INFO`), so *your* `udp_confirmed` should still set.
   Confirm by comparing both sides:

   ```sh
   # on A:  tinc -n NET info B   → Status: ... udp_confirmed
   # on B:  tinc -n NET info A   → Status: ...                (no udp_confirmed)
   ```

   That asymmetry is expected and traffic A→B will go UDP. If
   *neither* side gets `udp_confirmed`, UDP is blocked both ways.

4. **`TCPOnly = yes` / `IndirectData = yes`** in `tinc.conf` or the
   peer's host file. `tinc info PEER` shows `Options: tcponly` /
   `indirect` when set.

**Fix** - open UDP `Port` inbound, enable `UPnP = yes` if behind a
consumer router, or accept TCP relay for that peer. For the
asymmetric case there is nothing to fix on the tincd side.

---

## DHT never publishes / publishes v6-only

**Symptom** - at `-d2` you never see
`tincd::discovery: published seq=...`, or you only ever see
`published seq=...: tinc1 v6=[...]:655` with no `v4=` / `tcp=`. Peers
that bootstrap purely from DHT can't dial you.

**Causes**:

- **No dialable v4 address known yet.** The first publish is held
  until one of `reflexive_v4` / `portmapped_tcp` / `portmapped_tcp6`
  is set, with a 30 s grace. If you have neither a public v4 nor a
  helpful NAT gateway, the first publish lands after 30 s with
  `v6=` only - correct, but not useful to v4-only peers.
  Check for `tincd::discovery: DHT voted public v4: ...` (INFO) and
  `tincd::portmap: Portmapped Tcp ...` (INFO); if neither appears,
  that's why.

- **Publish failing.** At debug:
  `tincd::discovery: DHT publish failed (will retry in ...)`. Usually
  the host firewall drops inbound UDP on the DHT port so the
  iterative `find_node` never completes. Backoff grows from 5 s to
  the republish interval; this no longer stalls the daemon.

- **Bootstrap unreachable.** Custom `DhtBootstrap =` pointing at a
  dead host, and no `$STATE_DIRECTORY/dht_nodes` from a previous
  run. Fix the bootstrap or delete `DhtBootstrap` to use the public
  mainline seeds.

**Confirm from another host** -

```sh
tinc-dht-seed --resolve --secret-file /etc/tinc/NET/dht_secret PUBKEY_OF_NODE
# hit  → prints  tinc1 v4=... tcp=...
# miss → tinc-dht-seed: no record for pubkey (publish not landed / wrong secret?)
```

A miss with the *correct* secret means the node hasn't published; a
miss only when you omit `--secret-file` is the expected sealed
behaviour.

---

## Interop with C tinc fails

**Symptom** - a C tinc node cannot establish a meta connection;
this side logs one of

```
peer bob (203.0.113.9 port 655) had unknown identity (no Ed25519 public key)
peer bob (203.0.113.9 port 655) tries to roll back protocol version to 17.0
Got legacy REQ_KEY from bob (no SPTPS extension)
```

and drops the connection.

**Cause** - tincr is **SPTPS-only** (protocol 17.≥2). It does not
implement the legacy RSA metakey exchange. A C peer built with
`-Dcrypto=nolegacy`, or a 1.1 peer with an `Ed25519PublicKey` in
its host file and `ExperimentalProtocol` left at its default (yes),
interoperates fine. A 1.0 peer, or a 1.1 peer with
`ExperimentalProtocol = no`, does not.

**Confirm** - `tinc -n NET info PEER` on a working neighbour shows
`Protocol: 17.7` (or ≥ 17.2) for compatible peers. The C peer's
`tinc.conf` must not set `ExperimentalProtocol = no`, and
`hosts/PEER` here must contain `Ed25519PublicKey = ...`.

**Fix** - on the C peer: ensure tinc 1.1, generate an Ed25519 key
(`tinc -n NET generate-ed25519-keys`), distribute the public key,
remove `ExperimentalProtocol = no` if present.

---

## Traffic detours through a slower relay

**Symptom** - `tinc -n NET info DEST` shows `indirectly via X` or
`nexthop X` where `X` is geographically wrong; RTT to DEST through
the tunnel is much higher than the direct path.

**Cause** - edge weights are sampled at TCP-connect time; one SYN
retransmit can pin a weight at ~1000+ on a 15 ms link. tincd
re-measures via PING/PONG EWMA and re-gossips when the smoothed RTT
leaves a ±30/50 % band, so this self-heals within a few
`PingInterval`s - but only once a meta connection to the right
nexthop exists.

**Confirm** -

```sh
tinc -n NET dump edges | grep -E '^(myname|X) '
```

Compare the `weight` column to real RTT (`ping X`). A weight of
197 on a 15 ms link is the SYN-retransmit signature.

**Fix** - usually none; wait ~`PingInterval` and re-check. If a
specific link is permanently mis-weighted, set `Weight = N` in that
peer's host file. If the desired nexthop has no meta connection at
all, add `ConnectTo = NEXTHOP` or rely on AutoConnect's
demand-driven shortcut (kicks in above ~32 KiB/s relayed).

---

## Crash, but no core dump

By design. `tincd` zeroes `RLIMIT_CORE` (and `PR_SET_DUMPABLE` on
Linux) at startup so a crash can't write the Ed25519 private key and
live session keys to disk or to `systemd-coredump`. To debug a crash,
restart with `--allow-coredump` or set `TINCR_ALLOW_COREDUMP=1` in the
unit's environment; then `coredumpctl gdb tincd` works as usual. On
Linux the cleared dumpable bit also blocks same-uid `ptrace`; attach
as root or use the flag.

## Reading strace for event-loop health

When latency through the tunnel is bad and `tinc info PEER` looks
healthy (`directly with UDP`, sane `PMTU:`), or the daemon uses CPU
at idle, check whether the event loop itself is misbehaving:

```sh
# main-thread syscalls with per-call latency
strace -T -f -e trace=epoll_wait,futex,recvfrom,sendto,read,write \
    -p "$(pidof tincd)" 2>&1 | head -200
```

Healthy idle pattern: `epoll_wait(..., N, timeout_ms) = 0` with
`timeout_ms` in the 1000-5000 range, returning after roughly that
long; occasional `= 1` followed by a `read`/`recvfrom`/`write`
burst.

Red flags (all of these would be tincd bugs — capture the trace
and file an issue):

- `epoll_wait(…, 0) = 0` dozens of times in a row at idle → a
  timer is re-arming for "now" and the loop is hot-spinning.
- `futex(…) <1.0…>` or longer on the **main** TID → something is
  blocking the loop. While parked, TUN/UDP fds are not serviced;
  you'll see it as periodic ping stalls that decay (2000 → 1000 →
  100 ms) as the kernel backlog drains. Worker threads (DHT,
  portmap) are allowed to block; check the TID against
  `ls /proc/$(pidof tincd)/task`.
- `sendto` returning `EMSGSIZE` repeatedly for the same peer →
  PMTU not converging; see [PMTU oscillation](#pmtu-oscillation).
