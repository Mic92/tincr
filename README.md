# tincr

A drop-in Rust rewrite of [tinc 1.1](https://github.com/gsliepen/tinc).
It is wire-compatible with upstream's SPTPS protocol and ships as a
single static binary. Only Ed25519 and ChaCha20-Poly1305 are supported.

Tincr is compatible with existing tinc 1.1 meshes and configuration.
It can be used as a drop-in replacement in `services.tinc.networks` in NixOS.

## Features

Differences and additions compared to upstream tinc:

- **SPTPS only.** The legacy RSA-based meta protocol is not
  implemented. `generate-rsa-keys` exists only as a no-op stub.
- **Mainline-DHT peer discovery** (`DhtDiscovery`, `DhtBootstrap`,
  `DhtSecretFile`). Each node publishes its current reflexive or
  port-mapped address as a key-blinded, AEAD-sealed BEP44 record on
  the public BitTorrent DHT. Peers resolve it using only the pubkey
  from `hosts/NAME`. This means a mesh can bootstrap without any
  `Address=` lines in the host files. The `tinc-dht-seed` binary
  runs a local seed swarm for hermetic tests.
- **Built-in port mapping** (`UPnP=yes`, same option as upstream).
  Instead of linking libminiupnpc, tincr has its own client. It tries
  PCP first and falls back to UPnP-IGD. It also adds IPv6 pinholes
  and ignores rogue-LAN SSDP responders. The mapped external
  `(ip,port)` is fed into the DHT record's `tcp=` field.
- **GSO/GRO batching** on Linux. TUN reads are drained in bursts and
  emitted as one `sendmsg` with `UDP_SEGMENT`. The receive side
  coalesces packets before writing to the TUN. This reaches 10G on a
  single thread.
- **DNS stub resolver** (`DNSAddress`, `DNSSuffix`). The daemon
  intercepts DNS queries sent to a virtual address on the TUN
  device. It answers `NODE.SUFFIX` and reverse (PTR) lookups from
  the live subnet table. No extra socket is bound for this.
- **`tinc-auth`**: an nginx `auth_request` backend. It looks up
  `$remote_addr` via the control socket and returns the matching
  node as `Tinc-Node` and `Tinc-Subnet` headers.
- **systemd integration**: readiness via `Type=notify`, watchdog
  keepalive, and socket activation (`LISTEN_FDS`) for the meta
  listener. See [`contrib/tincd@.service`](contrib/tincd@.service)
  for an example unit.
- **Routing**: nexthops stay sticky, so live flows are not rerouted
  on equal-cost churn. Edge weights are re-measured from meta `PING`
  RTT via EWMA with hysteresis. With `AutoConnect`, a node that
  relays traffic through another node opens a direct meta connection
  to the far side and holds it for a minimum interval to damp
  flapping.

## Install

```sh
# cargo
cargo install --git https://github.com/Mic92/tincr --locked tincd

# nix (provides tincd, tinc, tinc-auth, tinc-dht-seed, sptps_keypair)
nix build github:Mic92/tincr#packages.x86_64-linux.tincd
```

> **x86_64 CPU baseline:** the default `tincd` output targets
> `x86-64-v3` (Haswell/2013+, AVX2). On older or low-power chips
> such as pre-Haswell, Atom, or AMD Jaguar it will `SIGILL`. Use the
> runtime-dispatched build instead:
>
> ```sh
> nix build github:Mic92/tincr#packages.x86_64-linux.tincd-compat
> ```

## Quick start

[docs/QUICKSTART.md](docs/QUICKSTART.md) walks through setting up a
two-node mesh, adding a third node purely via DHT discovery, and a
NixOS configuration example.

[docs/OPERATING.md](docs/OPERATING.md) covers day-to-day operation:
signals, what a reload picks up, log rotation, debug levels, and a
cheatsheet for the `tinc` subcommands.

## Compatibility with tinc-c

tincr interoperates with tinc 1.1pre18 nodes on the same mesh, as
long as the C nodes set `ExperimentalProtocol=yes`. Differences:

- Only Ed25519 is supported. Peers without an `Ed25519PublicKey` are
  refused.
- There is no `tincctl` binary. The `tinc` CLI covers the same
  functionality.
- `tinc init` is non-interactive and does not probe for a free port.
- `USR1`/`USR2` signals are ignored. Use `tinc dump …` instead.
- New config keys (`DhtDiscovery`, `DNSAddress`, …) are silently
  ignored by the C daemon.

Details and the full key-by-key matrix: [docs/COMPAT.md](docs/COMPAT.md).
