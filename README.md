# tincr

tincr connects your machines into one private network (a mesh VPN),
even when they sit behind home routers or firewalls. Nodes talk to
each other directly where possible. There is no central server that
all traffic passes through.

It is a rewrite of [tinc 1.1](https://github.com/gsliepen/tinc) in
Rust: same configuration files, same wire protocol (SPTPS), same
`tinc` command line, shipped as a single static binary. It works as
a drop-in replacement for an existing tinc 1.1 mesh, including
`services.tinc.networks` on NixOS.

## Install

```sh
# cargo
cargo install --git https://github.com/Mic92/tincr --locked tincd

# nix (provides tincd, tinc, tinc-auth, tinc-dht-seed, sptps_keypair)
nix build github:Mic92/tincr#packages.x86_64-linux.tincd
```

> **Older x86_64 CPUs:** the default build targets `x86-64-v3`
> (Haswell/2013+, AVX2) and crashes with `SIGILL` on older or
> low-power chips (pre-Haswell, Atom, AMD Jaguar). Use the
> runtime-dispatched build instead:
>
> ```sh
> nix build github:Mic92/tincr#packages.x86_64-linux.tincd-compat
> ```

## Getting started

[docs/QUICKSTART.md](docs/QUICKSTART.md) sets up a two-node mesh,
then adds a third node behind NAT that finds the others via DHT
discovery alone. It also has a NixOS example.

Adding a machine to an existing mesh takes two commands:

```sh
# on an existing node
tinc -n myvpn invite laptop

# on the new machine, paste the printed URL
tinc -n myvpn join <URL>
```

## Features

Everything tinc 1.1 does, plus:

- **Nodes find each other on their own.** Each node publishes its
  current address as an encrypted record on the public BitTorrent
  DHT. Peers look it up using only the public key they already
  have, so host files need no `Address=` lines at all. Config keys:
  `DhtDiscovery`, `DhtBootstrap`, `DhtSecretFile`.
- **Invitations.** `tinc invite` prints a one-time URL, `tinc join`
  uses it to enroll a new node. No copying key files around.
- **Asks your router to open a port** (`UPnP=yes`). Uses its own
  client (PCP, falling back to UPnP-IGD) instead of libminiupnpc,
  and also opens IPv6 pinholes. The mapped address is published via
  the DHT.
- **Fast.** Multi-gigabit on a single thread on Linux (measured:
  ~5 Gbit/s on a Ryzen 9 3900) by batching packets (GSO/GRO:
  bursts of TUN reads become one `sendmsg` with `UDP_SEGMENT`, and
  vice versa on receive).
- **Call nodes by name.** With `DNSAddress` and `DNSSuffix` set,
  `ssh laptop.vpn` just works: the daemon answers DNS queries for
  `NODE.SUFFIX` (and reverse lookups) straight from its routing
  table. See [docs/DNS.md](docs/DNS.md).
- **Sandboxing.** With `Sandbox = normal` or `high`, the daemon
  locks itself out of everything on disk it does not need
  (Landlock on Linux, pledge/unveil-style). See
  [docs/SECURITY.md](docs/SECURITY.md).
- **nginx integration.** `tinc-auth` is an `auth_request` backend:
  it tells nginx which mesh node a request came from, via
  `Tinc-Node` and `Tinc-Subnet` headers.
- **systemd integration.** Readiness via `Type=notify`, watchdog
  keepalive, socket activation. Example unit:
  [`contrib/tincd@.service`](contrib/tincd@.service).
- **Stable routing.** Live connections keep their path instead of
  being rerouted whenever an equally good one appears. Link quality
  is measured from real round-trip times. With `AutoConnect`, nodes
  that relay traffic for each other connect directly.
- **AES encryption as an option** (`SPTPSCipher = aes-256-gcm`).
  The default is ChaCha20-Poly1305. On CPUs with AES hardware,
  AES-256-GCM raises tunnel throughput by 43–44% (measured: 3.4 →
  4.9 Gbit/s on a Ryzen 9 3900, 2.1 → 3.0 Gbit/s on Apple
  M-series). Both ends must be tincr and agree.
- **Post-quantum key exchange** (`SPTPSKex = x25519-mlkem768`).
  Adds ML-KEM-768 on top of X25519, so recorded traffic stays
  secret even against a future quantum computer. Both ends must be
  tincr and agree.

## Documentation

| Topic | Read |
|---|---|
| First mesh setup | [docs/QUICKSTART.md](docs/QUICKSTART.md) |
| Day-to-day operation: reloads, logs, `tinc` cheatsheet | [docs/OPERATING.md](docs/OPERATING.md) |
| Debugging a broken mesh | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| Firewall configuration | [docs/FIREWALL.md](docs/FIREWALL.md) |
| NixOS | [docs/NIXOS.md](docs/NIXOS.md) |
| DNS over the VPN | [docs/DNS.md](docs/DNS.md) |
| Security model | [docs/SECURITY.md](docs/SECURITY.md) |
| Mixing tincr and tinc-c nodes | [docs/COMPAT.md](docs/COMPAT.md) |
| Internals | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md) |

Man pages: `tincd(8)`, `tinc(8)`, `tinc.conf(5)`, `tinc-auth(8)`,
`tinc-dht-seed(8)`.

## Compatibility with tinc-c

tincr interoperates with tinc 1.1pre18 nodes on the same mesh, as
long as the C nodes set `ExperimentalProtocol=yes`. Differences:

- Only Ed25519 node keys are supported. Peers without an
  `Ed25519PublicKey` are refused. The legacy RSA-based meta
  protocol is not implemented (`generate-rsa-keys` is a no-op
  stub).
- `SPTPSCipher` and `SPTPSKex` are tincr extensions. Leave them at
  their defaults (ChaCha20-Poly1305, X25519) on any edge that
  involves a C node.
- There is no `tincctl` binary. The `tinc` CLI covers the same
  functionality.
- `tinc init` is non-interactive and does not probe for a free port.
- `USR1`/`USR2` signals are ignored. Use `tinc dump …` instead.
- New config keys (`DhtDiscovery`, `DNSAddress`, …) are silently
  ignored by the C daemon.

Details and the full key-by-key matrix: [docs/COMPAT.md](docs/COMPAT.md).
