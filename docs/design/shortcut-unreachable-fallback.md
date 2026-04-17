# Shortcut fallback when both endpoints are ingress-filtered

## 0. Motivating failure

`autoconnect` correctly emits `Connect{AutoShortcut}` on **both** blob64
and turingmachine while they relay each other's traffic via eva. Both
dials time out: TUM filters inbound TCP/655 on both the wired
(`131.159.38.0/23`) and wifi (`131.159.192.0/19`) segments. UDP
hole-punch is also dead (TUM drops unsolicited inbound unicast UDP
statelessly), so the shortcut can never collapse to 1-hop and the
`AutoShortcut` slot perpetually retries with exponential backoff.

The question: are there *other* addresses we already know that would
work, and is the daemon trying them?

## 1. C-parity audit: address sources for outgoing connect

`tinc-c/src/address_cache.c::get_recent_address` walks **three** tiers:

1. on-disk recent cache (`cache->data.address[]`)
2. `get_known_addresses(n)` — walks `n->edge_tree`, collects
   `e->reverse->address` (what *other* nodes report seeing `n` at)
3. `Address =` lines from `hosts/n`, lazily `getaddrinfo`'d, with the
   port defaulting to `lookup_config("Port")` then `655`

### Rust status

| tier | Rust impl | parity |
| ---- | --------- | ------ |
| 1 | `AddressCache::cached` (text format, `addrcache.rs`) | ✅ |
| 2 | `AddressCache::known`, populated by `Daemon::setup_outgoing_connection` walking `graph.node_edges(nid) → edge.reverse → edge_addrs[rev]` (`connect.rs:430-451`) | ✅ |
| 3 | `resolve_config_addrs` → `AddressCache::config` | ⚠️ **gap** |

The gap: `resolve_config_addrs` defaulted a bare `Address = host` to
port **655**, ignoring `Port =` in the same host file. C consults
`Port` first (`address_cache.c:165-167`). For a peer that listens on a
non-default port and lists `Address` without an inline port, the Rust
daemon dialled the wrong port until edge gossip (tier 2) supplied the
right one — i.e. cold-start to such a peer was broken.

**Fixed** in this branch (`outgoing.rs::resolve_config_addrs`), with
unit test `resolve_port_directive_default`.

The tier-2 edge-walk *is* already wired, including for the
`AutoAction::Connect` arm in `txpath.rs` (it calls
`setup_outgoing_connection`, which does the walk). So the Rust daemon
**does** dial gossiped edge addresses. No further code gap there.

### Why tier 2 doesn't help blob64 ↔ turingmachine

Every edge address the mesh has for either node is the **same** filtered
v4 address. `ADD_EDGE` carries the address the *initiating* side's TCP
came from with the port rewritten to the **receiver's listen port**
(`connect.rs::on_ack`: `a.set_port(parsed.his_udp_port)`), so even
though both nodes have global IPv6, the edges only advertise the v4
they happened to dial out from. Tier 2 = tier 3 here.

## 2. Empirical reachability: blob64 ↔ turingmachine

Addresses gathered from `hosts/`, `dump edges`, `dump nodes`, and
`ip -br a` on each host.

### From blob64 (`131.159.38.25`, wired)

| target addr (turingmachine) | source | :655 | :22 |
| --- | --- | --- | --- |
| `131.159.202.127` | hosts/, all edges, `dump nodes` | **TIMEOUT** | OK |
| `2a09:80c0:192::…:4c7d` | `ip a` only (not in mesh) | **TIMEOUT** | OK |

### From turingmachine (`131.159.202.127`, wifi)

| target addr (blob64) | source | :655 | :22 |
| --- | --- | --- | --- |
| `131.159.38.25` | hosts/, all edges, `dump nodes` | **TIMEOUT** | TIMEOUT |
| `2a09:80c0:38::25` | hosts/ | **TIMEOUT** | TIMEOUT |

### Intra-TUM relays

| from → to :655 | result |
| --- | --- |
| blob64 → graham `131.159.102.9` | **OK** |
| blob64 → aenderpad `131.159.38.96` | **OK** |
| blob64 → blob64 v6 `2a09:80c0:38::25` (self, sanity) | OK |
| turingmachine → graham `131.159.102.9` | TIMEOUT |
| turingmachine → aenderpad `131.159.38.96` | TIMEOUT |
| turingmachine → blob64 :22 | TIMEOUT |
| turingmachine → blob64 :80/:443/:8080 | TIMEOUT |
| turingmachine → eva `116.203.179.132` | OK |

**Reading**: the wifi VLAN (`131.159.192.0/19`) is fully isolated from
the wired VLANs at L3 — turingmachine cannot reach **any** TUM-wired
host on **any** port, not even ssh. blob64 can reach the other wired
TUM nodes (graham, aenderpad, …) on :655 just fine, and already has a
direct edge `blob64 → graham` (weight 2).

So for *this* pair specifically:

- No alternate address helps (none reachable).
- No alternate port helps (turingmachine→blob64 is filtered on every
  port; blob64→turingmachine only :22 passes, and we are not going to
  squat ssh).
- An intra-filter relay helps **blob64's half** (it already has one:
  graham, RTT weight 2) but cannot help turingmachine's half — the
  wifi segment has *no* retiolum peer it can TCP-dial except the
  public ones (eva/eve/prism), which is exactly the status quo.

The shortcut is **physically impossible** for this pair. The right
behaviour is to *stop wasting a shortcut slot on it*, which the
existing `shortcut_backoff` (60 s) plus `bump_timeout` already do —
but only after the first 5-second connect timeout per retry. That is
acceptable; nothing to fix in code here.

## 3. Design sketch: dial the destination's neighbour

When `Connect{AutoShortcut, dst}` exhausts its address cache, instead
of (only) `retry_outgoing(dst)`, try shortening the path by one hop:
dial a *neighbour* of `dst` that we **can** reach and that is closer
than our current `nexthop`. This turns a 3-hop relay into 2-hop when
the last hop is the only unfilterable one.

```text
on AutoShortcut(dst) addr-cache Exhausted, before arming backoff:
  cur_hops := sssp_distance(myself, dst)        # already in graph
  cands := []
  for e in graph.node_edges(dst):               # dst's neighbours
      n := e.to
      if n == myself || n.directly_connected: continue
      if sssp_distance(myself, n) >= cur_hops - 1: continue   # no gain
      # "can we reach n?" — only knowable by trying. Heuristic gate:
      #   has_address(n) || any edge_addr(n) not in our recent-fail set
      if !has_address(n) && known_edge_addrs(n).is_empty(): continue
      cands.push((edge_weight(dst, n), n))      # prefer dst's low-RTT neighbour
  sort cands by (edge_weight asc, name)
  for (_, n) in cands.take(1):
      if no Outgoing for n and n not in shortcut_backoff:
          emit Connect{ name: n, origin: AutoShortcut }   # counts toward d_shortcut
          return                                          # let normal retry handle dst
```

Against `NodeSnapshot`: needs two extra fields —
`neighbours: Vec<(String /*name*/, i32 /*weight*/)>` and
`distance: u32` (both already in `graph`/`sssp`, just not exported to
the snapshot). `decide()` then runs the above when it would otherwise
re-pick a `dst` that is already in `pending_outgoings` with
`origin == AutoShortcut` and `timeout > 0`.

For blob64↔turingmachine this picks **graham** for blob64 (already
connected, so noop — correct) and picks **eva/prism/eve** for
turingmachine (already connected — correct). Net effect on this pair:
zero, which is the right answer; the value is for the *general* case
of "dst is one filtered hop behind a reachable node".

## 4. Recommendation / ship order

1. **Ship now** — `resolve_config_addrs` `Port =` fallback (this
   branch). Straight C-parity bug; independent of the motivating case.

2. **Ship now, config** — document in `docs/` and the retiolum host
   template that nodes behind ingress filters should set
   `Address = <host> <port-that-passes>` *and* `Port = <same>` so
   peers dial a port the filter admits. For TUM-wired this would be a
   second `Port`/`Address` on e.g. 443; for TUM-wifi nothing helps
   (all inbound filtered). **No code change.**

3. **Don't ship** — neighbour-dial (§3). The empirical table shows it
   buys nothing for the motivating pair, the existing
   `make_new_connection` random walk already discovers reachable
   neighbours over time (blob64→graham edge exists organically), and
   it adds `O(E)` state to `NodeSnapshot` plus a second connect
   decision point. Revisit if a case appears where the random backbone
   provably fails to find the 2-hop relay within a few minutes.

4. **Nothing to do** for tier-2 edge addresses — already implemented
   and exercised on every `setup_outgoing_connection`, including the
   autoconnect path.
