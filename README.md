# tincr

A drop-in Rust rewrite of [tinc 1.1](https://github.com/gsliepen/tinc).
Wire-compatible with upstream's SPTPS protocol, ships as a single
static binary, and speaks only the modern crypto (Ed25519 +
ChaCha20-Poly1305 — no RSA, no OpenSSL). Existing tinc 1.1 meshes,
config trees, and the NixOS `services.tinc.networks` module work
unchanged.

## Features

Beyond upstream wire compat:

- **SPTPS-only.** Legacy RSA/metaauth is compiled out
  (`generate-rsa-keys` is a no-op stub). One handshake, one cipher
  suite.
- **Mainline-DHT peer discovery** (`DhtDiscovery`, `DhtBootstrap`,
  `DhtSecretFile`). Nodes publish their current reflexive/port-mapped
  address as a key-blinded, AEAD-sealed BEP44 record on the public
  BitTorrent DHT; peers resolve it from `hosts/NAME`'s pubkey alone.
  A mesh can bootstrap with **no `Address=` lines anywhere**. The
  `tinc-dht-seed` binary runs a local seed swarm for hermetic tests.
- **Built-in port mapping** (`UPnP=yes`, same knob as upstream): a
  dependency-free PCP-first client (falls back to UPnP-IGD, adds
  IPv6 pinholes, hardened against rogue-LAN SSDP responders) instead
  of linking libminiupnpc. The mapped external `(ip,port)` is fed
  into the DHT record's `tcp=` field.
- **GSO/GRO batching** on Linux. TUN reads are drained in bursts and
  emitted as one `sendmsg` with `UDP_SEGMENT`; the receive side
  coalesces into the TUN write. Single-thread 10G on commodity
  hardware.
- **DNS stub resolver** (`DNSAddress`, `DNSSuffix`). The daemon
  intercepts UDP/53 to a virtual address on the TUN and answers
  `NODE.SUFFIX → Subnet` and PTR from the live subnet table — no
  bind, no extra socket.
- **`tinc-auth`**: a tiny nginx `auth_request` backend that maps
  `$remote_addr` → `Tinc-Node` / `Tinc-Subnet` headers via the
  control socket.
- **systemd-native**: `Type=notify` readiness, `WATCHDOG=1`
  keepalive, and `LISTEN_FDS` socket activation for the meta
  listener. See [`contrib/tincd@.service`](contrib/tincd@.service).
- **Smarter routing**: SSSP nexthop stickiness (don't reroute live
  flows on equal-cost churn), edge weights re-measured from meta
  `PING` RTT via EWMA with hysteresis, and `AutoConnect`
  auto-shortcut — when a relay is hot, open a direct meta connection
  to the far side and hold it for a minimum interval to damp flap.

## Install

```sh
# cargo
cargo install --git https://github.com/Mic92/tincr --locked tincd

# nix (provides tincd, tinc, tinc-auth, tinc-dht-seed, sptps_keypair)
nix build github:Mic92/tincr#packages.x86_64-linux.tincd
```

## Quick start

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the two-node
walkthrough, a third node joining purely via DHT discovery, and a
NixOS snippet. See [docs/OPERATING.md](docs/OPERATING.md) for
signals, reload scope, log rotation, debug levels, and a `tinc`
subcommand cheatsheet.

## Compatibility with tinc-c

tincr interoperates with tinc 1.1pre18 nodes on the same mesh
(`ExperimentalProtocol=yes` on the C side). Differences:

- Ed25519 only — peers without an `Ed25519PublicKey` are refused.
- No `tincctl` binary; the `tinc` CLI covers the same surface.
- `tinc init` is non-interactive and does not probe for a free port.
- `USR1`/`USR2` are ignored; use `tinc dump …`.
- New config keys (`DhtDiscovery`, `DNSAddress`, …) are silently
  ignored by the C daemon.

Details and the full key-by-key matrix: [docs/COMPAT.md](docs/COMPAT.md).
