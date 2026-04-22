# Operating tincd

Quick reference for running and debugging the daemon. See
`tinc --help` / `tincd --help` for the full flag list.

## Running

```sh
# foreground, logs to stderr (recommended under systemd)
tincd -n NETNAME -D

# detached; logs go to LOCALSTATEDIR/log/tinc.NETNAME.log
tincd -n NETNAME
```

Under systemd use `Type=notify` and run foreground (`-D`); journald
captures stderr. A sample instanced unit is in
[`contrib/tincd@.service`](../contrib/tincd@.service).

### Socket activation

tincd honours `LISTEN_FDS`/`LISTEN_PID`. Enable
[`contrib/tincd@.socket`](../contrib/tincd@.socket) to have systemd
own the TCP meta-listener: the daemon adopts the passed fd(s) and
opens the paired UDP socket on the same address itself (so the
`.socket` unit needs only `ListenStream=`, no `ListenDatagram=`).
With socket activation, `BindToAddress`/`ListenAddress`/`Port` in
`tinc.conf` are ignored — the `.socket` unit is the bind config.

## Signals

| Signal | Effect | Control-socket equivalent |
|---|---|---|
| `TERM`/`INT`/`QUIT` | clean shutdown (runs `tinc-down`) | `tinc stop` |
| `HUP` | reload config (see below) | `tinc reload` |
| `ALRM` | reset outgoing backoff, reconnect now | `tinc retry` |
| `USR1`/`USR2` | ignored — use `tinc dump …` instead | — |

## Reload scope

`tinc reload` / `SIGHUP` re-reads `tinc.conf` and `hosts/NAME` and
applies:

- `Subnet` additions/removals (with `subnet-up`/`-down` hooks)
- `ConnectTo` additions/removals
- soft settings (`PingInterval`, `MaxTimeout`, `AutoConnect`, …)
- the invitation key
- per-connection revocation: any peer whose `hosts/NAME` mtime
  changed is disconnected

It does **not** re-apply anything that requires re-binding or
re-opening:

- `Port`, `BindToAddress`, `ListenAddress`, `AddressFamily`
- `Device`, `DeviceType`, `Interface`, `Mode`
- private key paths

The daemon warns when it sees `Port`/`AddressFamily`/`Interface`
changed on reload; for the others, restart.

## Log files and rotation

`--logfile` is opened once at startup and is **not** reopened on
`SIGHUP`. Use `copytruncate` in your logrotate config:

```
/var/log/tinc.*.log {
    weekly
    rotate 4
    copytruncate
    missingok
}
```

Under systemd, prefer `-D` and let journald handle rotation.

## Debug levels

`-d[LEVEL]`, `LogLevel=` in `tinc.conf`, or `tinc debug N` at
runtime. Mapping to Rust log levels:

| tinc level | filter | adds (rough) |
|---|---|---|
| 0 | `info` | startup, connection up/down, reachability changes, port-map / DHT events |
| 1–2 | `debug` | per-connection state machine, gossip handlers, PMTU steps, port-map / DHT failures, script exits |
| 3+ | `trace` | per-packet TX/RX path (`tincd::net`), wire bodies (`tincd::proto`), event-loop turns |

`RUST_LOG` overrides all of the above and accepts per-target
filters, e.g. `RUST_LOG=info,tincd::proto=trace`.

Useful targets for `RUST_LOG` / `tinc log`:

| target | covers |
|---|---|
| `tincd::net` | data-path TX/RX, TUN read/write, PMTU probes, fragmentation — the high-volume one |
| `tincd::proto` | meta-protocol gossip (`ADD_EDGE`, `ADD_SUBNET`, `REQ_KEY`, …) parse/dispatch |
| `tincd::conn` | meta-connection lifecycle (connect/accept/handshake/close) |
| `tincd::discovery` | DHT publish/resolve, public-IP vote |
| `tincd::portmap` | PCP / UPnP-IGD attempts and results |
| `tincd::dns` | the built-in stub resolver |
| `tincd::keys` | key load / invitation key |

Example: data-path only at trace, everything else at info:

```sh
RUST_LOG=info,tincd::net=trace tincd -n NET -D
```

## Diagnostics

```sh
tinc -n NET dump nodes          # mesh members, reachability, pmtu
tinc -n NET dump edges          # meta-connection graph
tinc -n NET dump subnets        # routing table
tinc -n NET dump connections    # live TCP meta connections
tinc -n NET dump graph | dot -Tpng >mesh.png
tinc -n NET info NODE           # human summary for one node/subnet
tinc -n NET top                 # per-node traffic, live
tinc -n NET log 5               # live log stream at trace
tinc -n NET pcap | wireshark -k -i -
tinc -n NET retry               # reconnect now (after resume/NAT change)
tinc -n NET purge               # forget unreachable nodes
```

### Reading `tinc info NODE`

`tinc -n NET info PEER` prints a fixed-layout block; the interesting
fields for transport debugging:

```
Node:         bob
Node ID:      8f3…
Address:      203.0.113.7 port 655
Online since: 2025-…
Status:       validkey visited reachable sptps udp_confirmed
Options:      pmtu_discovery clamp_mss
Protocol:     17.7
Reachability: directly with UDP
PMTU:         1417
RTT:          14.327
RX:           12345 packets  6789012 bytes
TX:           …
Edges:        alice hub
Subnets:      10.0.0.2/32
```

`Reachability:` is the first thing to check; it is one of:

| value | meaning |
|---|---|
| `can reach itself` | this is the local node |
| `unreachable` | no path in the meta-graph (peer offline / partitioned) |
| `indirectly via X` | UDP traffic is relayed through node `X` |
| `unknown` | reachable but SPTPS key exchange not finished yet |
| `directly with UDP` + `PMTU:`/`RTT:` | the good case — direct UDP, PMTU discovered |
| `directly with TCP` | direct meta-connection but no working UDP; data tunnels over TCP |
| `none, forwarded via X` | nexthop is `X`'s TCP socket; should be transient |

`Status:` flags worth knowing: `udp_confirmed` = at least one UDP
probe reply seen; `validkey` = tunnel SPTPS up; `sptps` = peer
speaks the SPTPS protocol (always set for tincr peers).

### Reading `tinc dump nodes`

One line per node; the trailing fields are
`… nexthop VIA via VIA distance N pmtu PMTU (min MIN max MAX) [rtt MS]`.
During PMTU discovery `min`/`max` converge; `min 0` means no UDP
reply has ever been received from that node (data will go TCP).

### Reading `tinc dump edges`

One line per directed meta-connection with the advertised weight.
A weight in the hundreds when the real RTT is tens of ms means the
connect-time sample included a SYN retransmit; it is re-measured
from PING/PONG and re-gossiped within a few `PingInterval`s.

## Metrics / observability

There is no Prometheus / metrics endpoint. For monitoring, poll the
control socket:

```sh
# per-node byte/packet counters (parseable)
tinc -n NET dump nodes

# single peer, human-readable
tinc -n NET info PEER

# live top-style view
tinc -n NET top
```

`dump nodes` output is stable enough to scrape; the
`in_packets in_bytes out_packets out_bytes` fields are lifetime
counters (monotone until restart), so a textfile-collector can diff
them. `dump edges | wc -l` and `dump connections | wc -l` give mesh
size and local degree.

## DHT discovery operations

Enabled with `DhtDiscovery = yes` in `tinc.conf`. See the design doc
for protocol details; this is the operator view.

Startup line (INFO):

```
tincd::discovery: DHT discovery enabled (port 655, secret: yes, bootstrap: mainline)
```

`secret: yes` means `DhtSecretFile` was read; `bootstrap: mainline`
means the built-in public seed list, otherwise the `DhtBootstrap`
addresses you configured.

### Persisted routing table

The DHT routing table is snapshotted on clean shutdown to
`$STATE_DIRECTORY/dht_nodes` (one `host:port` per line; falls back
to the config dir when `STATE_DIRECTORY` is unset). On the next
start you should see, at debug:

```
tincd::discovery: loaded N persisted DHT node(s) for warm bootstrap
```

Delete the file to force a cold DNS bootstrap.

### Confirming publish / resolve

Publish success is logged at **debug** (it happens every 5 min):

```
tincd::discovery: published seq=…: tinc1 v4=203.0.113.7:655 tcp=203.0.113.7:655 v6=[…]:655
```

The first publish is held until at least one of `v4=` / `tcp=` /
`tcp6=` is known (or 30 s have passed) so peers don't cache a
v6-only record. If you only ever see `tinc1 v6=…`, port mapping and
the reflexive-v4 probe both failed — see
[TROUBLESHOOTING](TROUBLESHOOTING.md#dht-never-publishes--publishes-v6-only).

Resolve hits are INFO:

```
tincd::discovery: DHT resolved bob: [203.0.113.7:655, [2001:db8::1]:655]
```

A miss (`DHT resolve bob: no record`) is debug-only.

The BEP 42 public-address vote is also INFO:

```
tincd::discovery: DHT voted public v4: 203.0.113.7 (firewalled=false)
```

### Out-of-band resolve (`tinc-dht-seed`)

`tinc-dht-seed --resolve` looks up a peer's record from outside the
daemon — useful to confirm a node is actually publishing:

```sh
# PUBKEY is the Ed25519PublicKey line from hosts/PEER (tinc-base64)
tinc-dht-seed --resolve --secret-file /etc/tinc/NET/dht_secret PUBKEY
# → prints the inner record:  tinc1 v4=… tcp=… v6=…
```

Without `--secret-file` the same query against a mesh that uses
`DhtSecretFile` returns
`tinc-dht-seed: no record for pubkey (publish not landed / wrong secret?)`
— by design, records are sealed to mesh members.

Omit the trailing `BOOTSTRAP_HOST:PORT` to use the public mainline
seeds; pass one to query a private/test DHT.

### `DhtSecretFile` rotation

The secret is read once at startup, before privilege drop. To
rotate:

1. Distribute the new 32-byte file (raw bytes or one base64 line)
   to every node.
2. Restart `tincd` on every node (reload is **not** sufficient).

A wrong-length / unreadable file is **fatal** at startup
(`DhtSecretFile …: not 32 bytes`); a missing file when the option
is set is also fatal. This is deliberate: silently publishing under
a different key derive than the rest of the mesh is a quiet
partition.

During a staggered rollout, nodes on the old secret and nodes on
the new secret cannot DHT-resolve each other; static `Address=` /
`ConnectTo` and edge gossip still work, so keep at least one
statically-addressed path up until the rotation is complete.

## Port mapping operations

Enabled with `UPnP = yes` (TCP+UDP) or `UPnP = udponly`. The worker
tries PCP first, then falls back to UPnP-IGD (SSDP+SOAP) on the v4
path; v6 is PCP-only (firewall pinhole to your GUA).

Startup (INFO):

```
tincd::portmap: PCP/UPnP port mapping enabled (port 655, mode Yes, refresh 60s)
```

Success (INFO, once per mapping or whenever the external address
changes):

```
tincd::portmap: Portmapped Tcp 655 → 203.0.113.7:655 (via PCP)
tincd::portmap: Portmapped Udp 655 → 203.0.113.7:655 (via UPnP-IGD)
```

The `via` tag tells you which protocol the router answered. The TCP
mapping is also fed into the DHT record as `tcp=`.

Failure is **debug-only** (most hosts have no helpful gateway, so
INFO would be noise). To see why mapping isn't happening:

```sh
RUST_LOG=info,tincd::portmap=debug tincd -n NET -D
# typical lines:
#   tincd::portmap: PCP v4: timed out
#   tincd::portmap: map V4/Tcp 655: SSDP discover: no IGD reply within timeout
#   tincd::portmap: map V4/Tcp 655: rejected ext addr 127.0.0.1:655 from UPnP-IGD (loopback)
```

`Port mapping lost` (WARN) means a mapping that **had** succeeded
failed its refresh — router rebooted, UPnP toggled off, or you
roamed networks:

```
tincd::portmap: Port mapping lost (V4/Tcp 655 → 203.0.113.7:655); will retry next refresh
```

A roam is also surfaced as:

```
tincd::portmap: default route changed (… → …); re-mapping
```

Tuning / disabling:

| key | default | notes |
|---|---|---|
| `UPnP` | `no` | `yes` / `udponly` / `no` |
| `UPnPRefreshPeriod` | 60 | seconds; lease is `max(2×this, 120)` |
| `UPnPDiscoverWait` | 5 | SSDP M-SEARCH wait |

Set `UPnP = no` (or build without the `upnp` feature) to disable.
Not reload-safe; restart to apply.

## Hot redeploy under systemd

To test a locally-built `tincd` against a production config without
touching the installed package, drop an `ExecStart` override into
`/run` (tmpfs — gone on reboot) and restart the instance:

```sh
NET=retiolum
BIN=/root/tincd                # your freshly built binary

install -d /run/systemd/system/tincd@${NET}.service.d
cat >/run/systemd/system/tincd@${NET}.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=${BIN} -D -n %i
EOF
systemctl daemon-reload
systemctl restart tincd@${NET}
```

Revert:

```sh
rm -r /run/systemd/system/tincd@${NET}.service.d
systemctl daemon-reload
systemctl restart tincd@${NET}
```

Using `/run` instead of `/etc` means a forgotten override cannot
survive a reboot. The NixOS module's unit name may differ
(`tinc.${NET}.service`); adjust the drop-in path accordingly.

## Benchmarks

The `throughput` bench measures end-to-end iperf3 over a real TUN
path between two daemons (Rust↔Rust, C↔C, Rust↔C) and reports the
Rust/C ratio. Absolute Mbps is machine-local; the ratio is what you
compare across commits.

**Linux** (unprivileged, via bwrap+netns):

```sh
cargo bench --bench throughput --profile profiling
TINCD_PERF=1 cargo bench --bench throughput --profile profiling   # + perf record
```

**macOS** (real utun, requires root):

```sh
scripts/macos-bench-runner.sh                  # prompts for sudo
scripts/macos-bench-runner.sh -- rust_rust     # one pairing
TINCD_PERF=1 scripts/macos-bench-runner.sh     # + sample(1)
```

The macOS bench rewrites two host routes so traffic between the
tunnel /32s traverses the utun pair instead of `lo0`, then asserts
each daemon's `dump traffic` byte counters match iperf3's transfer
— if the kernel ever short-circuits past the utun, the bench fails
rather than reporting a loopback number.

## See also

- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom → cause → fix
- [`contrib/tincd@.service`](../contrib/tincd@.service),
  [`contrib/tincd@.socket`](../contrib/tincd@.socket)
