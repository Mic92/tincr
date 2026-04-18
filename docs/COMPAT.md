# Compatibility with tinc 1.1

What an operator running a mixed C/Rust mesh, or migrating from one
to the other, needs to know. Internal implementation differences that
don't change observable behaviour are out of scope; see
[ARCHITECTURE.md](ARCHITECTURE.md) for those.

## Interoperability

tincr speaks meta-protocol 17.7 with SPTPS, i.e. what tinc 1.1
calls `ExperimentalProtocol = yes` (the default in every 1.1pre
release). A mesh can mix C and Rust nodes freely.

It does **not** speak the legacy RSA/CBC protocol. That means:

- tinc **1.0.x** nodes cannot connect.
- tinc 1.1 nodes with `ExperimentalProtocol = no` cannot connect.
- Nodes that have only an RSA key pair and no Ed25519 key cannot
  connect.

Before introducing a tincr node, make sure every peer it will talk
to has an Ed25519 key (`tinc generate-ed25519-keys` on the C side)
and that the corresponding `Ed25519PublicKey` line is present in its
host file here.

All tincr protocol extensions are encoded as optional trailing
fields that C tinc's parser ignores, or happen entirely out of band,
so a C node in the mesh is simply oblivious to them.

## Dropped

- **Legacy crypto.** No RSA meta-key exchange, no Blowfish/AES-CBC,
  no configurable `Cipher`/`Digest`/`MACLength`. These keys are
  recognised and warned about, then ignored. Delete them.
- **`--bypass-security`.** The C debug flag that skipped signature
  checks is not ported.
- **OpenSSL/libgcrypt.** One built-in crypto stack; nothing to link
  against or choose at build time.
- **TAP on macOS.** macOS builds are utun (L3) only, so
  `Mode = switch`/`hub` is Linux/BSD only.

## Added

These have no equivalent in C tinc. All are off-mesh or
backwards-compatible on the wire; a C node simply doesn't
participate.

- **DHT discovery.** A node can publish its current dialable address
  to the BitTorrent Mainline DHT and resolve peers from it, removing
  the need for at least one statically-addressed relay. Records are
  encrypted and published under a key only mesh members can derive;
  setting `DhtSecretFile` additionally gates resolution to nodes
  holding the secret. New keys: `DhtDiscovery`, `DhtSecretFile`,
  `DhtBootstrapAddress`. New tool: `tinc-dht-seed`.
- **IPv6 firewall pinhole.** Port mapping speaks PCP in addition to
  UPnP-IGD, and uses it over IPv6 to open inbound through consumer
  router firewalls — so a node with only a global v6 address can
  still accept direct connections.
- **`tinc-auth`.** Small HTTP `auth_request` backend that answers
  "which mesh node owns this source IP", for putting per-node ACLs
  in front of internal web services.
- **In-mesh DNS.** The daemon answers `name.NETNAME` A/AAAA/PTR
  queries for mesh subnets by intercepting them on the TUN device.
  No socket bound, nothing to configure on the peer.
- **Landlock sandbox.** On Linux the daemon confines itself after
  setup. `Sandbox = normal`/`high` tightens further. Relevant if you
  run hook scripts: under `high`, scripts that touch paths outside
  the config/state directories will fail.
- **systemd integration.** `Type=notify` readiness, watchdog pings
  from the event loop, and socket activation. See
  [OPERATING.md](OPERATING.md) for unit files.
- **`LogLevel` config key.** Sets verbosity from `tinc.conf` so the
  unit file doesn't need `-d` flags.

## Changed behaviour

Things that work in both daemons but not identically.

- **Socket activation takes TCP only.** Put `ListenStream=` in the
  `.socket` unit; the daemon opens the matching UDP socket itself on
  the same address. Don't pass `ListenDatagram=`.
- **More `ADD_EDGE` traffic.** Edge weights are re-measured from
  meta-connection ping RTT and re-advertised when they drift
  meaningfully, instead of being fixed at connect time. Gossip
  volume stays bounded (at most one update per edge per few ping
  intervals), but packet captures will show `ADD_EDGE` lines during
  steady state that C tinc would not send. The payoff is that route
  selection tracks real latency instead of whatever the TCP
  handshake happened to measure.
- **AutoConnect is less eager to drop.** A meta-connection that is
  currently the next hop for active traffic is never reaped by the
  "more than 3 connections" rule, and connections opened as a
  shortcut to a hot relay target are held for a grace period.
- **`StrictSubnets` reload is incomplete.** Authorised subnets are
  loaded at startup, but SIGHUP does not yet re-diff `hosts/*` and
  broadcast the deltas the way C does. Restart the daemon after
  editing host files under `StrictSubnets = yes`.
- **Unknown or restart-only config keys are warned about.** C
  ignores them silently; tincr logs a warning at startup, and on
  SIGHUP logs which changed keys need a restart to take effect.
- **Hook script environment is clean.** `tinc-up`, `host-up`, etc.
  receive only the documented `NETNAME`/`NAME`/`DEVICE`/… variables,
  not the daemon's full inherited environment. Scripts that relied
  on ambient `PATH` entries or leaked variables may need adjusting.
  Per-event hooks (`host-up`, `subnet-up`, …) are spawned without
  waiting; only `tinc-up`/`tinc-down` block.
- **Privilege drop is stricter.** All three uids/gids are set and
  verified, `no_new_privs` is always enabled, and failure to drop is
  fatal rather than logged-and-continued.
- **`LocalDiscovery` defaults to `yes`**, matching current upstream
  git but not every 1.1pre tarball.

## Config key summary

| Key                                       | Status                                |
| ----------------------------------------- | ------------------------------------- |
| `ExperimentalProtocol`                    | Effectively forced `yes`.             |
| `Cipher`, `Digest`, `MACLength`           | Warned, ignored.                      |
| `PrivateKey`, `PrivateKeyFile`, `PublicKey` (RSA) | Warned, ignored. Use the Ed25519 equivalents. |
| `UPnP`                                    | Same values as C; also drives PCP.    |
| `DhtDiscovery`, `DhtSecretFile`, `DhtBootstrapAddress` | New.                     |
| `Sandbox`                                 | New (`off`/`normal`/`high`).          |
| `LogLevel`                                | New.                                  |
