# Security model

This document describes what tincr (and the tinc 1.1 protocol it
implements) does and does **not** protect against. Read it before you
hand out an invitation to a node you do not fully control.

For the cryptographic details of the transport, see
[`PROTOCOL.md`](PROTOCOL.md). This file is about the trust boundary
*above* the crypto.

## Trust boundary

**Every authenticated member of a tinc mesh is fully trusted for
routing decisions across the entire mesh.** This is inherent to the
tinc 1.1 meta-protocol — tincr inherits it for wire compatibility, it
is not a tincr bug.

Once a node has a valid Ed25519 key in another node's `hosts/`
directory and can complete the SPTPS handshake, it can:

- announce arbitrary `ADD_SUBNET` messages and have traffic for any IP
  range in the mesh routed to itself (hijack / blackhole);
- announce arbitrary `ADD_EDGE` messages, inventing links between
  other nodes with chosen weights, steering third-party traffic
  through itself or away from a victim;
- send `DEL_EDGE` for links it is not party to and partition the mesh;
- flood gossip to exhaust CPU/memory on every other node.

Gossip is flooded and accepted on the strength of the *neighbour's*
meta-connection, not signed by the originating node. There is no way
for a recipient to distinguish "C really announced 10.0.0.0/8" from "B
made that up about C".

## What SPTPS gives you

SPTPS (the transport, see [`PROTOCOL.md#sptps`](PROTOCOL.md#sptps))
provides, against an attacker **outside** the mesh:

- mutual authentication of the two endpoints (Ed25519);
- confidentiality and integrity of meta and data traffic
  (ChaCha20-Poly1305 / AES-GCM, with PFS);
- replay protection on the data channel.

SPTPS does **not** provide:

- integrity of routing state against a malicious *member*;
- authorisation — possession of any accepted key equals full routing
  authority by default;
- DoS resistance against a member.

In short: SPTPS keeps the outside out. It does nothing about a hostile
inside.

## Mitigations

Both knobs below default to **off** for compatibility with stock C
tinc deployments.

| Option | Effect | Use when |
| --- | --- | --- |
| `StrictSubnets = yes` | Ignore `ADD_SUBNET` for any prefix not already listed in the local `hosts/NAME` file for that node. Peers can only route what you wrote down for them. | Nodes are operated by different parties, or any node runs on hardware you don't control (laptops, cloud VMs). |
| `TunnelServer = yes` | Do not forward gossip between meta-connections; treat each direct peer as its own island. Implies `StrictSubnets`. | Hub-and-spoke / "VPN concentrator" topologies where spokes must never influence each other's routing. |

Neither option stops a malicious member from blackholing traffic
addressed *to its own* authorised subnets, or from flooding its direct
neighbour. They constrain reach, not behaviour.

## Hardened config (multi-tenant / low-trust mesh)

```conf
# tinc.conf
StrictSubnets = yes
# On a hub that should isolate its spokes from each other, also:
# TunnelServer = yes
Broadcast = no
AutoConnect = no        # only dial peers you ConnectTo explicitly
DhtDiscovery = no       # don't learn endpoints for nodes you didn't vet
```

```conf
# hosts/NAME — enumerate exactly what NAME may carry; nothing else
# will be accepted from gossip.
Subnet = 10.42.7.0/24
Ed25519PublicKey = ...
```

With `StrictSubnets`, the `hosts/` directory *is* your authorisation
database. Review changes to it like you would firewall rules.

## When this is fine

If every node in the mesh is yours — same operator, same threat
model — the defaults are fine and you can stop reading. The above
matters when you invite a friend, a customer, or a CI runner.

## Reporting security issues

There is no private security contact at the moment. Please open an
issue at <https://github.com/Mic92/tincr/issues>. If you need to
disclose privately, open an issue saying only that and we will arrange
a channel.
