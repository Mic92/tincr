# In-mesh DNS

tincd ships a built-in stub resolver that answers `<node>.<suffix>`
queries with the node's `Subnet =` routes. It's a Rust-only
extension — C tinc has nothing equivalent, so peer-side cooperation
is not required. The peer just routes packets; this side parses and
replies.

## How it works

The stub never binds a socket. tincd already inspects every TUN
ingress packet for routing; the DNS path is one extra match in code
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

So there's no port-53 conflict with `systemd-resolved`'s
`127.0.0.53`, no listener fd to babysit through `drop_privs`, and no
`CAP_NET_BIND_SERVICE` cost. The DNS address is just an IP that
routes to the tinc TUN — pick one inside the mesh prefix and the
kernel sees it as on-link the moment the interface gets an address.

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
  Multi-homed nodes get multiple records — DNS clients have handled
  that since 1987.
- **PTR** for `*.in-addr.arpa` / `*.ip6.arpa`. Reverse-lookup the
  exact IP in the subnet tree; returns the owning node's name.
  Makes `who`, `last`, and `journalctl` show node names instead of
  raw IPs.
- **NXDOMAIN** for everything else. There is no upstream forwarding;
  if the OS resolver routes a non-mesh query here by mistake, it
  gets NXDOMAIN and falls through.

Network-level `Subnet =` routes (e.g. `10.0.0.0/24`, not host-
prefix) are routes, not identities, and are not synthesised into
A records. The node doesn't "have" address `10.0.0.0`.

## OS integration

The stub doesn't take over `/etc/resolv.conf`. Split-DNS is the
operator's responsibility — point only `*.<suffix>` queries at the
DNS address.

### systemd-resolved (manual)

```sh
resolvectl dns    "$INTERFACE" "$DNS_ADDR"
resolvectl domain "$INTERFACE" "~$DNS_SUFFIX" "$DNS_SUFFIX"
```

The `~` prefix is "routing-only domain" — resolved sends only
matching queries here. The bare suffix is also a search domain so
`ssh alice` resolves without typing `.mesh`.

### systemd-resolved (NixOS)

The [NixOS module](NIXOS.md) does the wiring declaratively via
`systemd-networkd`'s `[Network] DNS=`/`Domains=` keys. No
`tinc-up` hook needed; networkd hands the per-link config to
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
  the daemon's runtime view of the graph; signing would require key
  management out of band of the mesh itself.

## Limits

- One `DNSSuffix` per network. Multiple suffixes would force a
  query-time ambiguity check (`alice.foo` vs `alice.bar`); not
  worth the complexity.
- Names are flat: `alice.mesh` works, `alice.dc1.mesh` does not.
  Subnet ownership in tinc is per-node, not per-region.
- No DNS message compression in replies (RFC 1035 §4.1.4 pointers).
  Legal — the spec says a server *may* compress; ours doesn't. The
  bytes saved are not worth the state machine.

## Source

- `crates/tincd/src/dns.rs` — query parsing, answer synthesis.
- `crates/tincd/src/daemon/net/route.rs` — TUN-ingress intercept
  and packet inject path.
- `crates/tincd/src/daemon/setup.rs::load_dns_config` — config
  parse.
