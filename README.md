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

# nix (provides tincd, tinc, tinc-auth, sptps_keypair)
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

[docs/QUICKSTART.md](docs/QUICKSTART.md) sets up a two-node mesh.
It also has a NixOS example.

Adding a machine to an existing mesh takes two commands:

```sh
# on an existing node
tinc -n myvpn invite laptop

# on the new machine, paste the printed URL
tinc -n myvpn join <URL>
```

## Features

Everything tinc 1.1 does, plus:

- **Invitations.** `tinc invite` prints a one-time URL, `tinc join`
  uses it to enroll a new node. No copying key files around.
- **Asks your router to open a port** (`UPnP=yes`). Uses its own
  client (PCP, falling back to UPnP-IGD) instead of libminiupnpc,
  and also opens IPv6 pinholes.
- **Fast.** Multi-gigabit per flow on Linux by batching packets
  (GSO/GRO: bursts of TUN reads become one `sendmsg` with
  `UDP_SEGMENT`, and vice versa on receive) and using the AVX-512
  AEAD kernels via OpenSSL. Measured on a Ryzen AI 7 350 against
  C tinc's ~1 Gbit/s: 3.2 Gbit/s single flow (5.7 with AES), and
  with the sharded data plane (`Shards`, on by default) traffic
  from multiple peers spreads across cores: 8.6 Gbit/s aggregate
  from 4 peers.
- **Call nodes by name.** With `DNSAddress` and `DNSSuffix` set,
  `ssh laptop.vpn` just works: the daemon answers DNS queries for
  `NODE.SUFFIX` (and reverse lookups) straight from its routing
  table. See [docs/DNS.md](docs/DNS.md).
- **Sandboxing.** With `Sandbox = normal` or `high`, the daemon
  locks itself out of everything on disk it does not need
  (Landlock on Linux, pledge/unveil-style). See
  [docs/SECURITY.md](docs/SECURITY.md).
- **Web auth from mesh identity.** `tinc-auth` is an nginx
  `auth_request` backend (`Tinc-Node`/`Tinc-Subnet` headers) and an
  OIDC provider for apps like Gitea and Grafana: being on the mesh
  is the login. See [docs/AUTH.md](docs/AUTH.md).
- **systemd integration.** Readiness via `Type=notify`, watchdog
  keepalive, socket activation. Example unit:
  [`contrib/tincd@.service`](contrib/tincd@.service).
- **Stable routing.** Live connections keep their path instead of
  being rerouted whenever an equally good one appears. Link quality
  is measured from real round-trip times. With `AutoConnect`, nodes
  that relay traffic for each other connect directly.
- **AES encryption as an option** (`SPTPSCipher = aes-256-gcm`).
  The default is ChaCha20-Poly1305. On CPUs with AES hardware,
  AES-256-GCM roughly doubles single-flow throughput (measured:
  3.2 → 5.7 Gbit/s on Zen 5). Both ends must be tincr and agree.
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

Man pages: `tincd(8)`, `tinc(8)`, `tinc.conf(5)`, `tinc-auth(8)`.

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
- New config keys are silently ignored by the C daemon.

Details and the full key-by-key matrix: [docs/COMPAT.md](docs/COMPAT.md).
