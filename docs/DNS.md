# In-mesh DNS

With in-mesh DNS enabled, you can reach nodes by name:
`ssh alice.mesh` instead of `ssh 10.21.0.7`. tincd answers
`<node>.<suffix>` queries itself, using the node's `Subnet =`
routes as the source of truth.

This is a tincr-only extension, but it needs no cooperation from
the other side: the peer just routes packets, and the local daemon
parses the query and replies. C tinc nodes in the mesh are
unaffected.

## How it works

The stub never binds a socket. tincd already inspects every TUN
ingress packet for routing. The DNS path is one extra match in code
that is already hot:

```
TUN packet → dst == DNSAddress && dport == 53
            ↓ yes
        parse DNS query (RFC 1035 §4)
            ↓
        lookup in subnet tree → A/AAAA/PTR answer
            ↓
        synthesise reply, inject back into TUN
```

Because no socket is bound, there is no port-53 conflict with
`systemd-resolved`'s `127.0.0.53`, no listener fd to carry through
`drop_privs`, and no need for `CAP_NET_BIND_SERVICE`. The DNS
address is just an IP that routes into the tinc TUN device. Pick
one inside the mesh prefix and the kernel treats it as on-link as
soon as the interface has an address.

## Configuration

Two `tinc.conf` keys, both required to enable the feature:

```
DNSAddress = 10.21.0.53
DNSSuffix  = mesh
```

`DNSAddress` may appear up to twice, once for IPv4 and once for IPv6:

```
DNSAddress = 10.21.0.53
DNSAddress = fd21::53
```

When the stub is enabled, tincd exports `DNS_ADDR`, `DNS_ADDR6`, and
`DNS_SUFFIX` to `tinc-up`/`tinc-down` scripts so OS-side resolver
hooks can pick them up.

## What gets answered

- **A / AAAA** for `<node>.<suffix>`. Returns every host-prefix
  `Subnet=` the node advertises (every `/32` v4 or `/128` v6).
  Multi-homed nodes get multiple records.
- **PTR** for `*.in-addr.arpa` / `*.ip6.arpa`. The exact IP is
  looked up in the subnet tree and the owning node's name is
  returned. This makes `who`, `last`, and `journalctl` show node
  names instead of raw IPs.
- **NXDOMAIN** for everything else. There is no upstream
  forwarding. If the OS resolver routes a non-mesh query here by
  mistake, it gets NXDOMAIN and falls through.

Network-level `Subnet =` routes (e.g. `10.0.0.0/24`, not host-
prefix) are routes, not identities, and are not synthesised into
A records. The node doesn't "have" address `10.0.0.0`.

## OS integration

The stub doesn't take over `/etc/resolv.conf`. Split-DNS is the
operator's responsibility: point only `*.<suffix>` queries at the
DNS address.

### systemd-resolved (manual)

```sh
resolvectl dns    "$INTERFACE" "$DNS_ADDR"
resolvectl domain "$INTERFACE" "~$DNS_SUFFIX" "$DNS_SUFFIX"
```

The `~` prefix means "routing-only domain": resolved sends only
matching queries here. The bare suffix is also a search domain so
`ssh alice` resolves without typing `.mesh`.

### systemd-resolved (NixOS)

The [NixOS module](NIXOS.md) does the wiring declaratively via
`systemd-networkd`'s `[Network] DNS=`/`Domains=` keys. No
`tinc-up` hook is needed: networkd hands the per-link config to
resolved when the interface comes up.

### dnsmasq / unbound / NetworkManager

Any resolver with per-zone forwarding works. Examples:

```
# dnsmasq
server=/mesh/10.21.0.53
```

```
# unbound
forward-zone:
  name: "mesh."
  forward-addr: 10.21.0.53
```

NetworkManager: `dns=systemd-resolved` and let resolved handle it,
or use the per-connection `ipv4.dns-search` / `ipv4.dns-priority`
fields with a routing-only domain (`~mesh`).

## Non-goals

- **Not a recursive resolver.** No upstream forwarding, no caching
  beyond what subnet-tree lookups already do.
- **Not authoritative for other zones.** Only `<suffix>` and the
  reverse zones for nodes' own subnets.
- **Not DNSSEC-signed.** Answers are synthesised on the fly from
  the daemon's runtime view of the graph. Signing would require key
  management out of band of the mesh itself.

## Limits

- One `DNSSuffix` per network. Multiple suffixes would force a
  query-time ambiguity check (`alice.foo` vs `alice.bar`).
- Names are flat: `alice.mesh` works, `alice.dc1.mesh` does not.
  Subnet ownership in tinc is per-node, not per-region.
- No DNS message compression in replies (RFC 1035 §4.1.4
  pointers). This is legal: the spec says a server *may* compress.

