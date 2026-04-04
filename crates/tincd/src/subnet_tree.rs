//! `subnet.c`: the routing table.
//!
//! When a packet arrives on the TUN device, `route_ipv4` does
//! `lookup_subnet_ipv4(dst)` → owner node → `send_packet(owner, ...)`.
//! That lookup is a longest-prefix match against every subnet every
//! node has advertised. This module is that table.
//!
//! ## Data structure
//!
//! C `subnet.c` uses ONE `splay_tree_t subnet_tree` for all three
//! address families, with a `type` discriminant on each entry and a
//! `if(p->type != SUBNET_IPV4) continue` guard in every lookup loop
//! (`subnet.c:268`). We split into three `BTreeMap`s — same iteration
//! order, no per-iteration type check, and the borrow checker doesn't
//! tangle when v4 and v6 lookups happen on the same packet (TAP mode
//! with dual-stack ARP).
//!
//! ## The comparator IS the algorithm
//!
//! `subnet_compare_ipv4` (`subnet_parse.c:137-159`) sorts by prefix
//! length DESCENDING first. So in-order tree iteration visits `/32`
//! before `/24` before `/8`. `lookup_subnet_ipv4` (`subnet.c:256-290`)
//! is then a linear scan: first `maskcmp` hit IS the longest match.
//! No trie needed. The sort order does the work.
//!
//! Our `Ord for Ipv4Key` is the C comparator; `BTreeMap::iter()` is
//! the in-order walk; `Subnet::matches(addr, true)` is `maskcmp`.
//!
//! ## What's NOT here
//!
//! - The hash cache (`subnet.c:33-36`, `ipv4_cache` etc). Hot-path
//!   optimization; separate commit once routing actually works.
//! - The per-node subnet tree (`node->subnet_tree`). The C maintains
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

/// `subnet_compare_ipv4` sort key. `subnet_parse.c:137-159`.
///
/// The `Subnet` field is always `Subnet::V4` — enforced by `add()`.
/// We keep the full enum (not destructured fields) so `lookup_ipv4`
/// can return `&Subnet` without reconstructing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4Key {
    subnet: Subnet,
    owner: Option<String>,
}

/// `subnet_compare_ipv6` sort key. `subnet_parse.c:161-183`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv6Key {
    subnet: Subnet,
    owner: Option<String>,
}

/// `subnet_compare_mac` sort key. `subnet_parse.c:119-135`.
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
// weight (`%d` parse, `subnet_parse.c:250`). `i32::MIN - 1` is UB
// in C and a panic in Rust. We use `Ord::cmp` chaining; the
// descending-prefix bit is `.reverse()`.
//
// The C also short-circuits owner compare when either owner is NULL
// (`subnet_parse.c:154`: `if(result || !a->owner || !b->owner)`).
// That's the search-key sentinel pattern: `lookup_subnet` builds a
// fake `subnet_t` with `owner = NULL` and `splay_search`es for it.
// We don't need that — `BTreeMap::get`/`iter` don't take fake
// entries.
//
// HOWEVER: `owner = NULL` is also a real tree state. `net_setup.c:
// 485-505` inserts `ff:ff:ff:ff:ff:ff`, `255.255.255.255`,
// `224.0.0.0/4`, `ff00::/8` with `subnet_add(NULL, s)`. `route.c:
// 644,738`: `if(!subnet->owner) route_broadcast()`. We use `None`.
// The C `:154` short-circuit sorts ownerless before owned at the
// owner tiebreak (NULL stops the strcmp); `Option::Ord` gives us
// the same: `None < Some(_)`.

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

        // C `subnet_parse.c:140`: `b->prefixlength - a->prefixlength`.
        // Descending → `.reverse()`.
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
    /// `subnet_parse.c:161-183`.
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
    /// `subnet_compare_mac`. `subnet_parse.c:119-135`.
    ///
    /// THREE levels, not four — no prefix on MAC:
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
#[derive(Debug, Default)]
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

    /// `subnet_add`. C `subnet.c:194-204`.
    ///
    /// Dispatches on `Subnet` variant to the right tree. The C
    /// inserts into BOTH the global tree and `n->subnet_tree`; we
    /// only have the global one (see module doc).
    ///
    /// Idempotent — re-adding the same `(subnet, owner)` is a no-op
    /// (C `splay_insert` replaces, but the value IS the key so it's
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

    /// `subnet_add(NULL, s)`. C `net_setup.c:485-505`.
    ///
    /// Ownerless subnets divert to `route_broadcast` (`route.c:644,
    /// 738,1042`). The four hard-coded defaults (Ethernet broadcast,
    /// IPv4 limited broadcast, IPv4 multicast `224/4`, IPv6 multicast
    /// `ff00::/8`) plus any `BroadcastSubnet` config entries.
    ///
    /// `Option::Ord` sorts `None` first — matches C
    /// `subnet_parse.c:154`'s NULL-short-circuit.
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

    /// `subnet_del`. C `subnet.c:206-214`.
    ///
    /// Returns `true` if the entry was present. The C `splay_delete`
    /// is void; we expose the bool because `del_subnet_h` (the
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

    /// `lookup_subnet`. C `subnet.c:219-227`. Exact-match lookup
    /// (NOT prefix-match — that's `lookup_ipv4`/`lookup_ipv6`).
    ///
    /// Used by `add_subnet_h` (`protocol_subnet.c:93`) for the
    /// strictsubnets lookup-first idempotency check: if the gossiped
    /// subnet is already in the tree (preloaded by `load_all_nodes`
    /// from the operator's hosts/ files), the strictsubnets gate is
    /// silently bypassed. The gate fires only on UNAUTHORIZED subnets
    /// (not in tree → fall through to `:116`).
    ///
    /// Allocates a `String` for the lookup key (same shape as
    /// `del()`). ADD_SUBNET is control-path-rare; the alloc is fine.
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

    /// `lookup_subnet_ipv4`. C `subnet.c:256-290`.
    ///
    /// Linear scan in tree order. Tree order has `/32` before `/24`
    /// before `/8` (descending prefix), so the FIRST entry whose
    /// top-`prefix` bits match `addr` is the longest-prefix match.
    /// The C exploits this and so do we.
    ///
    /// ## Reachability
    ///
    /// C `subnet.c:275`: `if(!p->owner || p->owner->status.reachable)
    /// break`. The scan KEEPS GOING past matches whose owner is down,
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
    /// is not reachable" with that owner's name (`route.c:512`).
    /// We return `Some` for that fallback too: the last `maskcmp`
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
            // C `subnet.c:272`: `if(!maskcmp(...))` — but C `maskcmp`
            // returns 0 for equal (memcmp convention), and `!0` is
            // truthy. So `!maskcmp(...)` is "if equal under mask".
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

    /// `lookup_subnet_ipv6`. C `subnet.c:292-326`. Same as v4.
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
                // C subnet.c:309: `!p->owner ||` short-circuit.
                if k.owner.as_deref().is_none_or(&mut is_reachable) {
                    break;
                }
            }
        }
        last_hit
    }

    /// `lookup_subnet_mac`. C `subnet.c:222-254`.
    ///
    /// MAC has no prefix → exact-match only. Still a scan because
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
            // C `subnet.c:238`: `if(!memcmp(address, &p->address, 6))`.
            // Exact match — `Subnet::matches` would work but this is
            // clearer (and skips constructing a query subnet).
            let Subnet::Mac { addr: a, .. } = k.subnet else {
                unreachable!()
            };
            if a == *addr {
                last_hit = Some((&k.subnet, k.owner.as_deref()));
                // C subnet.c:241: `!p->owner ||` short-circuit.
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
    /// by `subnet_compare`'s `a->type - b->type` first key (`subnet_
    /// parse.c:185-192`); we have three trees and chain. Same
    /// ordering: type discriminant ascending (V4=1, V6=2, MAC=0 in
    /// the C enum — wait, the C enum is `MAC=0, V4=1, V6=2`, so
    /// MAC sorts FIRST). Match: mac, v4, v6.
    ///
    /// SKIPS ownerless (broadcast) subnets. The C `send_everything`
    /// (`protocol_auth.c:892-895`) walks per-node `n->subnet_tree`s;
    /// broadcast subnets aren't in any node's tree, so they're never
    /// gossiped. Our gossip.rs walks this global iterator instead —
    /// filtering here keeps the wire output equivalent. (Cosmetic
    /// fallout: `dump_subnets` won't print `(broadcast)` rows. C
    /// `subnet.c:405` does. Separate fix if anyone cares.)
    pub fn iter(&self) -> impl Iterator<Item = (&Subnet, &str)> {
        self.mac
            .iter()
            .map(|k| (&k.subnet, k.owner.as_deref()))
            .chain(self.ipv4.iter().map(|k| (&k.subnet, k.owner.as_deref())))
            .chain(self.ipv6.iter().map(|k| (&k.subnet, k.owner.as_deref())))
            .filter_map(|(s, o)| o.map(|o| (s, o)))
    }

    /// All subnets owned by `name`, collected. Wrapper over `iter()` +
    /// filter + collect: 5 callsites had this exact 5-line block (`subnet_
    /// update(n, NULL, ...)` in C terms, `subnet.c:352-372`). The collect
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
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Helper. `Subnet::from_str` already handles `"10.0.0.0/24#5"`.
    fn sn(s: &str) -> Subnet {
        Subnet::from_str(s).unwrap()
    }

    /// Convenience: everyone is reachable.
    fn all_up(_: &str) -> bool {
        true
    }

    // ─── Ord: pin every tiebreak level ──────────────────────────────
    //
    // The comparator IS the algorithm. If these break, routing breaks.
    // Each test isolates ONE level by holding the others equal.

    /// Level 1: `prefixlength` DESCENDING. C `subnet_parse.c:140`:
    /// `b - a`. /24 sorts BEFORE /16 in tree order — the longer
    /// prefix is "smaller" so iteration sees it first.
    #[test]
    fn ipv4_ord_prefixlen_desc() {
        let long = Ipv4Key {
            subnet: sn("10.0.0.0/24"),
            owner: Some("n".into()),
        };
        let short = Ipv4Key {
            subnet: sn("10.0.0.0/16"),
            owner: Some("n".into()),
        };
        // /24 < /16 in our Ord (descending prefix → longer is "less").
        assert!(long < short);
    }

    /// Level 2: `address` ascending. C: `memcmp`. Same prefix, lower
    /// addr first. `Ipv4Addr::Ord` is big-endian byte compare, same
    /// as `memcmp` on `ipv4_t` (which is `uint8_t[4]` in network
    /// order — `subnet.h:33`).
    #[test]
    fn ipv4_ord_addr_tiebreak() {
        let lo = Ipv4Key {
            subnet: sn("10.0.0.0/24"),
            owner: Some("n".into()),
        };
        let hi = Ipv4Key {
            subnet: sn("10.0.1.0/24"),
            owner: Some("n".into()),
        };
        assert!(lo < hi);
    }

    /// Level 3: `weight` ascending. C: `a - b` (NOT reversed). Lower
    /// weight = preferred route, sorts first.
    #[test]
    fn ipv4_ord_weight_tiebreak() {
        let pref = Ipv4Key {
            subnet: sn("10.0.0.0/24#5"),
            owner: Some("n".into()),
        };
        let backup = Ipv4Key {
            subnet: sn("10.0.0.0/24#20"),
            owner: Some("n".into()),
        };
        assert!(pref < backup);
    }

    /// Weight is `i32`, C parses with `%d`, never bounds-checks
    /// (`subnet_parse.c:250`). `Ord::cmp` doesn't overflow; the C
    /// `a->weight - b->weight` would. Pin: negative sorts before
    /// positive (it's just integer order).
    #[test]
    fn ipv4_ord_weight_negative() {
        let neg = Ipv4Key {
            subnet: sn("10.0.0.0/24#-100"),
            owner: Some("n".into()),
        };
        let pos = Ipv4Key {
            subnet: sn("10.0.0.0/24#100"),
            owner: Some("n".into()),
        };
        assert!(neg < pos);
    }

    /// Level 4: `owner` ascending. C: `strcmp`. Alpha order.
    #[test]
    fn ipv4_ord_owner_tiebreak() {
        let alice = Ipv4Key {
            subnet: sn("10.0.0.0/24"),
            owner: Some("alice".into()),
        };
        let bob = Ipv4Key {
            subnet: sn("10.0.0.0/24"),
            owner: Some("bob".into()),
        };
        assert!(alice < bob);
    }

    /// V6 has the same comparator shape. Spot-check the descending
    /// prefix; the rest is the same `cmp().then_with()` chain.
    #[test]
    fn ipv6_ord_prefixlen_desc() {
        let long = Ipv6Key {
            subnet: sn("2001:db8::/64"),
            owner: Some("n".into()),
        };
        let short = Ipv6Key {
            subnet: sn("2001:db8::/32"),
            owner: Some("n".into()),
        };
        assert!(long < short);
    }

    /// `subnet_compare_mac` (`subnet_parse.c:119-135`): NO prefix
    /// level. Just addr, weight, owner. Three levels not four.
    #[test]
    fn mac_no_prefix() {
        // Addr is the first key.
        let lo = MacKey {
            subnet: sn("00:00:00:00:00:01"),
            owner: Some("n".into()),
        };
        let hi = MacKey {
            subnet: sn("00:00:00:00:00:02"),
            owner: Some("n".into()),
        };
        assert!(lo < hi);

        // Same addr → weight breaks the tie.
        let pref = MacKey {
            subnet: sn("aa:bb:cc:dd:ee:ff#5"),
            owner: Some("n".into()),
        };
        let backup = MacKey {
            subnet: sn("aa:bb:cc:dd:ee:ff#20"),
            owner: Some("n".into()),
        };
        assert!(pref < backup);
    }

    // ─── Lookup: longest-prefix match ───────────────────────────────

    /// THE routing decision. `10.0.0.0/8` and `10.1.0.0/16` both
    /// cover `10.1.2.3`. The /16 is more specific → wins. Tree
    /// order (descending prefix) means iteration sees /16 first,
    /// `maskcmp` matches, scan stops.
    #[test]
    fn lookup_longest_wins() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/8"), "broad".into());
        t.add(sn("10.1.0.0/16"), "narrow".into());

        let (s, owner) = t.lookup_ipv4(&Ipv4Addr::new(10, 1, 2, 3), all_up).unwrap();
        assert_eq!(owner, Some("narrow"));
        assert_eq!(*s, sn("10.1.0.0/16"));

        // 10.2.x.x is NOT in the /16, falls through to /8.
        let (s, owner) = t.lookup_ipv4(&Ipv4Addr::new(10, 2, 0, 0), all_up).unwrap();
        assert_eq!(owner, Some("broad"));
        assert_eq!(*s, sn("10.0.0.0/8"));
    }

    /// No covering subnet → `None`. C: `r` stays NULL, `return r`.
    #[test]
    fn lookup_miss() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/8"), "n".into());
        assert!(
            t.lookup_ipv4(&Ipv4Addr::new(192, 168, 1, 1), all_up)
                .is_none()
        );
    }

    /// Same subnet, two owners, different weight. Lower weight wins
    /// (sorts first, hits first). C `subnet_parse.c:152`: `a->weight
    /// - b->weight` ascending.
    #[test]
    fn lookup_weight_prefers_lower() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24#20"), "backup".into());
        t.add(sn("10.0.0.0/24#5"), "primary".into());

        let (_, owner) = t.lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), all_up).unwrap();
        assert_eq!(owner, Some("primary"));
    }

    /// C `subnet.c:275`: `if(p->owner->status.reachable) break`.
    /// alice owns the /24 but is down; bob owns the /16 and is up.
    /// Scan finds alice first (longer prefix), `is_reachable` says
    /// no, scan continues, finds bob, breaks. Route to bob.
    #[test]
    fn lookup_skips_unreachable() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());
        t.add(sn("10.0.0.0/16"), "bob".into());

        let (s, owner) = t
            .lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), |o| o == "bob")
            .unwrap();
        assert_eq!(owner, Some("bob"));
        assert_eq!(*s, sn("10.0.0.0/16"));
    }

    /// C `subnet.c:273`: `r = p` happens BEFORE the reachable check.
    /// If NOBODY is reachable, return the last (= shortest matching)
    /// subnet anyway. `route_ipv4` uses this to log "would route to
    /// X but X is unreachable" instead of "no route" (`route.c:512`).
    #[test]
    fn lookup_returns_unreachable_fallback() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());
        t.add(sn("10.0.0.0/16"), "bob".into());

        // Nobody up. C: `r` ends up pointing at the /16 (last match
        // in iteration order — /24 sorted first, then /16).
        let (s, owner) = t
            .lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), |_| false)
            .unwrap();
        assert_eq!(owner, Some("bob"));
        assert_eq!(*s, sn("10.0.0.0/16"));
    }

    /// C `subnet.c:275`: `!p->owner ||` — ownerless ALWAYS breaks
    /// the scan, regardless of `is_reachable`. The predicate isn't
    /// even called (no name to pass). `route_ipv4` then sees `None`
    /// and returns `Broadcast` (`route.c:644`).
    #[test]
    fn lookup_broadcast_short_circuits_reachable() {
        let mut t = SubnetTree::new();
        t.add_broadcast(sn("224.0.0.0/4"));
        // alice owns an overlapping /8 (impossible in practice, but
        // proves the short-circuit: /4 sorts AFTER /8 by descending
        // prefix — wait, /8 is longer than /4. /8 wins on prefix.
        // Use a non-overlapping owned subnet to make sure the
        // broadcast match is the only hit).

        // mDNS to 224.0.0.251: only the /4 covers it.
        let (_, owner) = t
            .lookup_ipv4(&Ipv4Addr::new(224, 0, 0, 251), |_| {
                panic!("is_reachable called for ownerless subnet")
            })
            .unwrap();
        assert_eq!(owner, None);
    }

    /// `iter()` skips ownerless. C `send_everything` walks per-node
    /// trees; broadcast subnets never appear on the wire.
    #[test]
    fn iter_skips_broadcast() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());
        t.add_broadcast(sn("224.0.0.0/4"));
        t.add_broadcast(sn("ff00::/8"));
        t.add_broadcast(sn("ff:ff:ff:ff:ff:ff"));

        let owners: Vec<&str> = t.iter().map(|(_, o)| o).collect();
        assert_eq!(owners, vec!["alice"]);
        // But len() counts everything (it's the raw tree size).
        assert_eq!(t.len(), 4);
    }

    /// V6 longest-prefix. Same logic, 16 bytes.
    #[test]
    fn lookup_ipv6_longest_wins() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::/32"), "broad".into());
        t.add(sn("2001:db8:1::/48"), "narrow".into());

        let q: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let (_, owner) = t.lookup_ipv6(&q, all_up).unwrap();
        assert_eq!(owner, Some("narrow"));

        let q: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        let (_, owner) = t.lookup_ipv6(&q, all_up).unwrap();
        assert_eq!(owner, Some("broad"));
    }

    /// MAC: exact match, weight tiebreak.
    #[test]
    fn lookup_mac_exact() {
        let mut t = SubnetTree::new();
        t.add(sn("aa:bb:cc:dd:ee:ff#20"), "backup".into());
        t.add(sn("aa:bb:cc:dd:ee:ff#5"), "primary".into());
        t.add(sn("11:22:33:44:55:66"), "other".into());

        let (_, owner) = t
            .lookup_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], all_up)
            .unwrap();
        assert_eq!(owner, Some("primary"));

        // Miss.
        assert!(t.lookup_mac(&[0, 0, 0, 0, 0, 0], all_up).is_none());
    }

    // ─── add / del ──────────────────────────────────────────────────

    #[test]
    fn del_removes() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "n".into());
        assert!(t.lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), all_up).is_some());

        assert!(t.del(&sn("10.0.0.0/24"), "n"));
        assert!(t.lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), all_up).is_none());
        assert!(t.is_empty());
    }

    /// `del` of an absent entry returns `false`. `del_subnet_h`
    /// uses this to detect duplicate DEL messages (the protocol
    /// flooding can deliver them twice via different paths).
    #[test]
    fn del_missing_is_false() {
        let mut t = SubnetTree::new();
        assert!(!t.del(&sn("10.0.0.0/24"), "n"));

        // Present but wrong owner → still false (different key).
        t.add(sn("10.0.0.0/24"), "alice".into());
        assert!(!t.del(&sn("10.0.0.0/24"), "bob"));
        assert_eq!(t.len(), 1);
    }

    /// Weight is part of the key. `10.0.0.0/24#5` and
    /// `10.0.0.0/24#10` are DIFFERENT entries (C: `subnet_compare`
    /// includes weight, so `splay_search` distinguishes them).
    /// `del` must match weight too.
    #[test]
    fn del_weight_is_part_of_key() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24#5"), "n".into());
        // Wrong weight (default 10) → miss.
        assert!(!t.del(&sn("10.0.0.0/24"), "n"));
        // Right weight → hit.
        assert!(t.del(&sn("10.0.0.0/24#5"), "n"));
    }

    /// `add` is idempotent. Re-adding doesn't create a second entry
    /// (BTreeMap key uniqueness).
    #[test]
    fn add_idempotent() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "n".into());
        t.add(sn("10.0.0.0/24"), "n".into());
        assert_eq!(t.len(), 1);
    }

    /// `iter()` walks in C-splay-order: type discriminant first
    /// (MAC=0, V4=1, V6=2 in `subnet.h:39-43`), then per-family
    /// comparator. `dump_subnets` (`subnet.c:395-410`) walks this
    /// way. The CLI doesn't depend on order but matching C makes
    /// diffing dump output easy.
    #[test]
    fn iter_order_matches_c_splay() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/8"), "broad".into());
        t.add(sn("10.1.0.0/16"), "narrow".into());
        t.add(sn("2001:db8::/32"), "v6".into());
        t.add(sn("aa:bb:cc:dd:ee:ff"), "mac".into());

        let owners: Vec<&str> = t.iter().map(|(_, o)| o).collect();
        // MAC first (type=0), then V4 by descending prefix (/16
        // before /8), then V6.
        assert_eq!(owners, vec!["mac", "narrow", "broad", "v6"]);
    }

    /// Three families, three trees, no crosstalk.
    #[test]
    fn families_isolated() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "v4".into());
        t.add(sn("2001:db8::/32"), "v6".into());
        t.add(sn("aa:bb:cc:dd:ee:ff"), "mac".into());
        assert_eq!(t.len(), 3);

        // V4 lookup doesn't see v6/mac entries.
        let (_, o) = t.lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), all_up).unwrap();
        assert_eq!(o, Some("v4"));

        // Del v4 doesn't touch the others.
        assert!(t.del(&sn("10.0.0.0/24"), "v4"));
        assert_eq!(t.len(), 2);
    }
}
