//! `subnet.c`: the routing table.
//!
//! When a packet arrives on the TUN device, `route_ipv4` does
//! `lookup_subnet_ipv4(dst)` → owner node → `send_packet(owner, ...)`.
//! That lookup is a longest-prefix match against every subnet every
//! node has advertised. This module is that table.
//!
//! ## Data structure
//!
//! Upstream uses ONE `splay_tree_t subnet_tree` for all three
//! address families, with a `type` discriminant on each entry and a
//! `if(p->type != SUBNET_IPV4) continue` guard in every lookup loop.
//! We split into three `BTreeMap`s — same iteration
//! order, no per-iteration type check, and the borrow checker doesn't
//! tangle when v4 and v6 lookups happen on the same packet (TAP mode
//! with dual-stack ARP).
//!
//! ## The comparator IS the algorithm
//!
//! `subnet_compare_ipv4` sorts by prefix length DESCENDING first.
//! So in-order tree iteration visits `/32` before `/24` before
//! `/8`. `lookup_subnet_ipv4` is then a linear scan: first `maskcmp` hit IS the longest match.
//! No trie needed. The sort order does the work.
//!
//! Our `Ord for Ipv4Key` is the C comparator; `BTreeMap::iter()` is
//! the in-order walk; `Subnet::matches(addr, true)` is `maskcmp`.
//!
//! ## What's NOT here
//!
//! - The hash cache (`ipv4_cache` etc). Hot-path optimization;
//!   separate commit once routing actually works.
//! - The per-node subnet tree (`node->subnet_tree`). Upstream maintains
//!   TWO trees per subnet (global + the owner's). We only need the
//!   global one for routing; the per-node view is for `dump subnets`
//!   and that can filter the global tree by owner.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use tinc_proto::Subnet;

// ────────────────────────────────────────────────────────────────────
// Keys
//
// One key type per family. The key STORES the full `Subnet` plus the
// owner name: lookup hands back `(&Subnet, &str)` and both live
// inside the key. The alternative — `BTreeMap<SortTuple, (Subnet,
// String)>` — would duplicate addr/prefix/weight bytes between key
// and value. `Subnet` is `Copy` (enum of PODs); storing once saves
// ~28 bytes per entry. The owner `String` is the only allocation.

/// `subnet_compare_ipv4` sort key.
///
/// The `Subnet` field is always `Subnet::V4` — enforced by `add()`.
/// We keep the full enum (not destructured fields) so `lookup_ipv4`
/// can return `&Subnet` without reconstructing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4Key {
    subnet: Subnet,
    owner: Option<String>,
}

/// `subnet_compare_ipv6` sort key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv6Key {
    subnet: Subnet,
    owner: Option<String>,
}

/// `subnet_compare_mac` sort key.
///
/// No prefix length — MAC addresses are exact-match (TAP-mode bridge
/// learning, like a switch's FDB).
#[derive(Debug, Clone, PartialEq, Eq)]
struct MacKey {
    subnet: Subnet,
    owner: Option<String>,
}

// ─── Ord impls: the C comparators ───────────────────────────────────
//
// The C does `b->prefixlength - a->prefixlength` (int subtraction).
// That's fine for u8-range values but `a->weight - b->weight` is an
// i32-on-i32 subtraction and the wire format never range-checks
// weight (`%d` parse). `i32::MIN - 1` is UB in C and a panic in
// Rust. We use `Ord::cmp` chaining; the descending-prefix bit is
// `.reverse()`.
//
// Upstream also short-circuits owner compare when either owner is
// NULL (`if(result || !a->owner || !b->owner)`). That's the
// search-key sentinel pattern: `lookup_subnet` builds a
// fake `subnet_t` with `owner = NULL` and `splay_search`es for it.
// We don't need that — `BTreeMap::get`/`iter` don't take fake
// entries.
//
/// Differential-fuzz hook: the first three tiers of
/// `subnet_compare_ipv4` as a free function over plain fields.
///
/// The `Ord for Ipv4Key` impl below does the same comparison but takes a
/// `Subnet` enum + `Option<String>` owner. The fuzz harness wants to feed
/// arbitrary bytes without constructing `Subnet::V4` (which has its own
/// invariants the parser enforces). Exposing this lets the fuzzer hit
/// the comparison logic directly with garbage `prefix`/`weight`
/// values — upstream `int` accepts those, our `u8 prefix` would
/// clamp them.
///
/// `prefix` is `i32` here (matching bare `int`) not `u8`: the wire
/// format is `%d` and a buggy peer could send `prefixlength = -1`
/// or `300`. The parser rejects those, but the fuzz
/// harness wants to know what happens if one slips through. The
/// `Ipv4Key::cmp` below uses the post-parse `u8` and is therefore a
/// strictly narrower domain — if fuzz over `i32` is clean, `u8` is too.
///
/// Owner tier omitted: C short-circuits when either owner is NULL
/// (`:154`), and the fuzz shim always passes NULL. It's a `strcmp`.
#[cfg(fuzzing)]
#[must_use]
pub fn cmp_ipv4_fuzz(
    a_addr: [u8; 4],
    a_prefix: i32,
    a_weight: i32,
    b_addr: [u8; 4],
    b_prefix: i32,
    b_weight: i32,
) -> Ordering {
    // C :140: `b->prefixlength - a->prefixlength` — descending.
    a_prefix
        .cmp(&b_prefix)
        .reverse()
        // C :146: memcmp on octets. Array Ord is byte-lex.
        .then_with(|| a_addr.cmp(&b_addr))
        // C :152: `a->weight - b->weight`. We use cmp, not subtraction —
        // the C overflows on (i32::MIN, 1) and we don't. That divergence
        // is a *finding*, not a bug to hide.
        .then_with(|| a_weight.cmp(&b_weight))
}

// HOWEVER: `owner = NULL` is also a real tree state. `net_setup.c:
// 485-505` inserts `ff:ff:ff:ff:ff:ff`, `255.255.255.255`,
// `224.0.0.0/4`, `ff00::/8` with `subnet_add(NULL, s)`. `route.c:
// `if(!subnet->owner) route_broadcast()`. We use `None`. The
// upstream short-circuit sorts ownerless before owned at the owner
// tiebreak (NULL stops the strcmp); `Option::Ord` gives us the
// same: `None < Some(_)`.

impl Ord for Ipv4Key {
    /// `subnet_compare_ipv4`. Four-level tiebreak:
    ///
    /// 1. `prefixlength` DESCENDING (C: `b - a`). Longest first.
    /// 2. `address` ascending (C: `memcmp`). `Ipv4Addr` derives `Ord`
    ///    as big-endian byte compare — same as `memcmp` on the octets.
    /// 3. `weight` ascending. Lower weight = preferred route.
    /// 4. `owner` ascending. `strcmp` ≡ `String`'s `Ord` (both are
    ///    byte-lex; node names are `[A-Za-z0-9_]+` so no UTF-8
    ///    surprises).
    fn cmp(&self, other: &Self) -> Ordering {
        let Subnet::V4 {
            addr: a,
            prefix: pa,
            weight: wa,
        } = self.subnet
        else {
            unreachable!("Ipv4Key holds non-V4 subnet")
        };
        let Subnet::V4 {
            addr: b,
            prefix: pb,
            weight: wb,
        } = other.subnet
        else {
            unreachable!("Ipv4Key holds non-V4 subnet")
        };

        // `b->prefixlength - a->prefixlength`. Descending → `.reverse()`.
        pa.cmp(&pb)
            .reverse()
            // C :146: `memcmp(&a->address, &b->address, sizeof ipv4_t)`.
            .then_with(|| a.cmp(&b))
            // C :152: `a->weight - b->weight`. NO subtraction.
            .then_with(|| wa.cmp(&wb))
            // C :158: `strcmp(a->owner->name, b->owner->name)`.
            .then_with(|| self.owner.cmp(&other.owner))
    }
}
impl PartialOrd for Ipv4Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ipv6Key {
    /// `subnet_compare_ipv6`. Same shape as v4, 16 bytes.
    fn cmp(&self, other: &Self) -> Ordering {
        let Subnet::V6 {
            addr: a,
            prefix: pa,
            weight: wa,
        } = self.subnet
        else {
            unreachable!("Ipv6Key holds non-V6 subnet")
        };
        let Subnet::V6 {
            addr: b,
            prefix: pb,
            weight: wb,
        } = other.subnet
        else {
            unreachable!("Ipv6Key holds non-V6 subnet")
        };

        pa.cmp(&pb)
            .reverse()
            .then_with(|| a.cmp(&b))
            .then_with(|| wa.cmp(&wb))
            .then_with(|| self.owner.cmp(&other.owner))
    }
}
impl PartialOrd for Ipv6Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MacKey {
    /// `subnet_compare_mac`. THREE levels, not four — no prefix on MAC:
    /// 1. `address` (`memcmp` 6 bytes ≡ `[u8; 6]` `Ord`)
    /// 2. `weight`
    /// 3. `owner`
    fn cmp(&self, other: &Self) -> Ordering {
        let Subnet::Mac {
            addr: a,
            weight: wa,
        } = self.subnet
        else {
            unreachable!("MacKey holds non-Mac subnet")
        };
        let Subnet::Mac {
            addr: b,
            weight: wb,
        } = other.subnet
        else {
            unreachable!("MacKey holds non-Mac subnet")
        };

        a.cmp(&b)
            .then_with(|| wa.cmp(&wb))
            .then_with(|| self.owner.cmp(&other.owner))
    }
}
impl PartialOrd for MacKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ────────────────────────────────────────────────────────────────────
// SubnetTree

/// `subnet_tree` from `subnet.c`. The global routing table.
///
/// C uses a single `splay_tree_t` with a type tag. We split by
/// family: lookups never cross families anyway (`route_ipv4` never
/// asks about MAC), and three separate trees means iteration skips
/// the `p->type != SUBNET_IPV4` check on every element.
/// `Clone`: snapshot-and-publish for the TX fast path. Clone is O(n)
/// String clones (the `owner` field); for a 100-subnet mesh that's
/// ~1KB, called once per `ADD_SUBNET`/`DEL_SUBNET` gossip event —
/// rare. The hot path reads through `Arc<SubnetTree>`, no fence.
#[derive(Debug, Default, Clone)]
pub struct SubnetTree {
    ipv4: BTreeSet<Ipv4Key>,
    ipv6: BTreeSet<Ipv6Key>,
    mac: BTreeSet<MacKey>,
}

impl SubnetTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `subnet_add`. Dispatches on `Subnet` variant to the right
    /// tree. Upstream
    /// inserts into BOTH the global tree and `n->subnet_tree`; we
    /// only have the global one (see module doc).
    ///
    /// Idempotent — re-adding the same `(subnet, owner)` is a no-op
    /// (`splay_insert` replaces, but the value IS the key so it's
    /// observationally identical).
    pub fn add(&mut self, subnet: Subnet, owner: String) {
        let owner = Some(owner);
        match subnet {
            Subnet::V4 { .. } => {
                self.ipv4.insert(Ipv4Key { subnet, owner });
            }
            Subnet::V6 { .. } => {
                self.ipv6.insert(Ipv6Key { subnet, owner });
            }
            Subnet::Mac { .. } => {
                self.mac.insert(MacKey { subnet, owner });
            }
        }
    }

    /// `subnet_add(NULL, s)`.
    ///
    /// Ownerless subnets divert to `route_broadcast`. The four
    /// hard-coded defaults (Ethernet broadcast,
    /// IPv4 limited broadcast, IPv4 multicast `224/4`, IPv6 multicast
    /// `ff00::/8`) plus any `BroadcastSubnet` config entries.
    ///
    /// `Option::Ord` sorts `None` first — matches upstream's
    /// NULL-short-circuit.
    pub fn add_broadcast(&mut self, subnet: Subnet) {
        match subnet {
            Subnet::V4 { .. } => {
                self.ipv4.insert(Ipv4Key {
                    subnet,
                    owner: None,
                });
            }
            Subnet::V6 { .. } => {
                self.ipv6.insert(Ipv6Key {
                    subnet,
                    owner: None,
                });
            }
            Subnet::Mac { .. } => {
                self.mac.insert(MacKey {
                    subnet,
                    owner: None,
                });
            }
        }
    }

    /// `subnet_del`. Returns `true` if the entry was present.
    /// `splay_delete` is void; we expose the bool because `del_subnet_h` (the
    /// protocol handler) wants to log "got DEL for unknown subnet".
    pub fn del(&mut self, subnet: &Subnet, owner: &str) -> bool {
        // Allocates a `String` for the lookup key. `BTreeSet::remove`
        // takes `&Q where K: Borrow<Q>` but our key is a struct, not
        // a tuple — implementing `Borrow` for a `(Subnet, &str)`
        // newtype is more ceremony than the alloc costs. DEL is
        // rare (only on node death / reconfig).
        let owner = Some(owner.to_owned());
        match *subnet {
            Subnet::V4 { .. } => self.ipv4.remove(&Ipv4Key {
                subnet: *subnet,
                owner,
            }),
            Subnet::V6 { .. } => self.ipv6.remove(&Ipv6Key {
                subnet: *subnet,
                owner,
            }),
            Subnet::Mac { .. } => self.mac.remove(&MacKey {
                subnet: *subnet,
                owner,
            }),
        }
    }

    /// `lookup_subnet`. Exact-match lookup (NOT prefix-match —
    /// that's `lookup_ipv4`/`lookup_ipv6`).
    ///
    /// Used by `add_subnet_h` for the strictsubnets lookup-first
    /// idempotency check: if the gossiped
    /// subnet is already in the tree (preloaded by `load_all_nodes`
    /// from the operator's hosts/ files), the strictsubnets gate is
    /// silently bypassed. The gate fires only on UNAUTHORIZED subnets
    /// (not in tree → fall through to `:116`).
    ///
    /// Allocates a `String` for the lookup key (same shape as
    /// `del()`). `ADD_SUBNET` is control-path-rare; the alloc is fine.
    #[must_use]
    pub fn contains(&self, subnet: &Subnet, owner: &str) -> bool {
        let owner = Some(owner.to_owned());
        match *subnet {
            Subnet::V4 { .. } => self.ipv4.contains(&Ipv4Key {
                subnet: *subnet,
                owner,
            }),
            Subnet::V6 { .. } => self.ipv6.contains(&Ipv6Key {
                subnet: *subnet,
                owner,
            }),
            Subnet::Mac { .. } => self.mac.contains(&MacKey {
                subnet: *subnet,
                owner,
            }),
        }
    }

    /// `lookup_subnet_ipv4`.
    ///
    /// Linear scan in tree order. Tree order has `/32` before `/24`
    /// before `/8` (descending prefix), so the FIRST entry whose
    /// top-`prefix` bits match `addr` is the longest-prefix match.
    /// The C exploits this and so do we.
    ///
    /// ## Reachability
    ///
    /// `if(!p->owner || p->owner->status.reachable) break`. The scan
    /// KEEPS GOING past matches whose owner is down,
    /// looking for a less-specific match owned by someone reachable.
    /// (If alice owns `10.0.0.0/24` but is offline, and bob owns
    /// `10.0.0.0/16`, route to bob.)
    ///
    /// We don't have node state here. `is_reachable` lets the caller
    /// inject it: return `true` for nodes that are up. The closure
    /// is called once per matching subnet, in longest-first order.
    ///
    /// C also remembers the LAST match (`r = p`) even if it never
    /// finds a reachable owner — `route_ipv4` then logs "Node %s
    /// is not reachable" with that owner's name. We return `Some`
    /// for that fallback too: the last `maskcmp`
    /// hit, reachable or not.
    pub fn lookup_ipv4(
        &self,
        addr: &Ipv4Addr,
        mut is_reachable: impl FnMut(&str) -> bool,
    ) -> Option<(&Subnet, Option<&str>)> {
        // Build a /32 query subnet so we can reuse `Subnet::matches`
        // (which is `maskcmp` under the hood). Weight doesn't matter
        // for `matches(_, true)`.
        let q = Subnet::V4 {
            addr: *addr,
            prefix: 32,
            weight: 0,
        };
        let mut last_hit: Option<(&Subnet, Option<&str>)> = None;
        for k in &self.ipv4 {
            // `if(!maskcmp(...))` — `maskcmp` returns 0 for equal
            // (memcmp convention), and `!0` is truthy. So
            // `!maskcmp(...)` is "if equal under mask".
            // Our `matches(_, true)` returns `true` for equal.
            if k.subnet.matches(&q, true) {
                last_hit = Some((&k.subnet, k.owner.as_deref()));
                // C :275: `if(!p->owner || p->owner->status.reachable)
                // break`. Ownerless (broadcast) is always "reachable"
                // — it goes to ALL reachable peers via route_broadcast.
                if k.owner.as_deref().is_none_or(&mut is_reachable) {
                    break;
                }
            }
        }
        last_hit
    }

    /// `lookup_subnet_ipv6`. Same as v4.
    pub fn lookup_ipv6(
        &self,
        addr: &Ipv6Addr,
        mut is_reachable: impl FnMut(&str) -> bool,
    ) -> Option<(&Subnet, Option<&str>)> {
        let q = Subnet::V6 {
            addr: *addr,
            prefix: 128,
            weight: 0,
        };
        let mut last_hit: Option<(&Subnet, Option<&str>)> = None;
        for k in &self.ipv6 {
            if k.subnet.matches(&q, true) {
                last_hit = Some((&k.subnet, k.owner.as_deref()));
                // `!p->owner ||` short-circuit.
                if k.owner.as_deref().is_none_or(&mut is_reachable) {
                    break;
                }
            }
        }
        last_hit
    }

    /// `lookup_subnet_mac`. MAC has no prefix → exact-match only. Still a scan because
    /// the same MAC can be advertised by multiple nodes with
    /// different weights (failover for a service VIP), and we want
    /// the lowest-weight reachable one. Tree order delivers
    /// lowest-weight first (`subnet_compare_mac` sorts addr THEN
    /// weight ascending).
    ///
    /// C also takes an optional `owner` to scope the search to one
    /// node's tree. We don't have per-node trees; the daemon can
    /// filter the result if it cares.
    pub fn lookup_mac(
        &self,
        addr: &[u8; 6],
        mut is_reachable: impl FnMut(&str) -> bool,
    ) -> Option<(&Subnet, Option<&str>)> {
        let mut last_hit: Option<(&Subnet, Option<&str>)> = None;
        for k in &self.mac {
            // `if(!memcmp(address, &p->address, 6))`. Exact match —
            // `Subnet::matches` would work but this is
            // clearer (and skips constructing a query subnet).
            let Subnet::Mac { addr: a, .. } = k.subnet else {
                unreachable!()
            };
            if a == *addr {
                last_hit = Some((&k.subnet, k.owner.as_deref()));
                // `!p->owner ||` short-circuit.
                if k.owner.as_deref().is_none_or(&mut is_reachable) {
                    break;
                }
            }
        }
        last_hit
    }

    /// `for splay_each(subnet_t, subnet, &subnet_tree)` (`subnet.c:
    /// 396`). All families, in C-splay-order: v4 first (descending
    /// prefix), then v6, then MAC. The C has ONE tree interleaved
    /// by `subnet_compare`'s `a->type - b->type` first key; we have
    /// three trees and chain. Same ordering: type discriminant
    /// ascending (the upstream enum is `MAC=0, V4=1, V6=2`, so
    /// MAC sorts FIRST). Match: mac, v4, v6.
    ///
    /// SKIPS ownerless (broadcast) subnets. Upstream `send_everything`
    /// walks per-node `n->subnet_tree`s; broadcast subnets aren't in
    /// any node's tree, so they're never gossiped. Our gossip.rs
    /// walks this global iterator instead —
    /// filtering here keeps the wire output equivalent. (Cosmetic
    /// fallout: `dump_subnets` won't print `(broadcast)` rows.
    /// Separate fix if anyone cares.)
    pub fn iter(&self) -> impl Iterator<Item = (&Subnet, &str)> {
        self.mac
            .iter()
            .map(|k| (&k.subnet, k.owner.as_deref()))
            .chain(self.ipv4.iter().map(|k| (&k.subnet, k.owner.as_deref())))
            .chain(self.ipv6.iter().map(|k| (&k.subnet, k.owner.as_deref())))
            .filter_map(|(s, o)| o.map(|o| (s, o)))
    }

    /// All subnets owned by `name`, collected. Wrapper over `iter()` +
    /// filter + collect: 5 callsites had this exact 5-line block
    /// (`subnet_update(n, NULL, ...)` in upstream terms). The collect
    /// is intentional: callers immediately call `run_subnet_script` /
    /// `del()` while iterating, which would self-borrow on the iterator.
    #[must_use]
    pub fn owned_by(&self, name: &str) -> Vec<Subnet> {
        self.iter()
            .filter(|(_, o)| *o == name)
            .map(|(s, _)| *s)
            .collect()
    }

    /// Total entry count across all three families. For `dump
    /// subnets` and tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len() + self.mac.len()
    }

    /// Is the routing table empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty() && self.mac.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests

#[cfg(test)]
mod tests;
