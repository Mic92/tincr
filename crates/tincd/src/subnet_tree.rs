//! `subnet.c`: the routing table.
//!
//! When a packet arrives on the TUN device, `route_ipv4` does
//! `lookup_subnet_ipv4(dst)` → owner node → `send_packet(owner, ...)`.
//! That lookup is a longest-prefix match against every subnet every
//! node has advertised. This module is that table.
//!
//! ## Data structure
//!
//! Three `BTreeMap`s, one per address family. Lookups never cross
//! families, and separate trees keep the borrow checker happy when v4
//! and v6 lookups happen on the same packet (TAP mode with dual-stack
//! ARP).
//!
//! ## The comparator IS the algorithm
//!
//! The keys sort by prefix length DESCENDING first, so in-order tree
//! iteration visits `/32` before `/24` before `/8`. Lookup is then a
//! linear scan: the first mask match IS the longest match. No trie
//! needed — the sort order does the work. The ordering matches C
//! tinc's comparators so route selection agrees across the mesh.
//!
//! ## What's NOT here
//!
//! - A lookup cache (hot-path optimization; add if profiling asks).
//! - A per-node subnet index. The global table is enough for routing;
//!   the per-node view (`dump subnets`) filters the global tree by
//!   owner.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use tinc_proto::Subnet;

/// Subset of `224.0.0.0/4` or `ff00::/8`? Subset, not intersect: a /0
/// default is fine; only equal-or-longer prefixes can out-LPM the
/// ownerless broadcast entries.
#[must_use]
pub(crate) fn is_multicast_subnet(subnet: &Subnet) -> bool {
    match *subnet {
        Subnet::V4 { addr, prefix, .. } => prefix >= 4 && addr.is_multicast(),
        Subnet::V6 { addr, prefix, .. } => prefix >= 8 && addr.is_multicast(),
        Subnet::Mac { .. } => false,
    }
}

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

// Ord impls define the routing order (see module doc). Ownerless
// (broadcast) entries sort before owned ones at the owner tiebreak
// (`None < Some(_)`), which matches C tinc's ordering.

impl Ord for Ipv4Key {
    /// Four-level tiebreak:
    ///
    /// 1. `prefix` DESCENDING. Longest first.
    /// 2. `address` ascending (big-endian byte compare).
    /// 3. `weight` ascending. Lower weight = preferred route.
    /// 4. `owner` ascending, byte-lex (node names are `[A-Za-z0-9_]+`
    ///    so no UTF-8 surprises).
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

        pa.cmp(&pb)
            .reverse() // longest prefix first
            .then_with(|| a.cmp(&b))
            .then_with(|| wa.cmp(&wb))
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

// SubnetTree

/// The global routing table, split by address family.
///
/// `Clone`: snapshot-and-publish for the TX fast path. Clone is O(n)
/// String clones (the `owner` field); for a 100-subnet mesh that's
/// ~1KB, called once per `ADD_SUBNET`/`DEL_SUBNET` gossip event —
/// rare. The hot path reads through `Arc<SubnetTree>`, no fence.
#[derive(Debug, Default, Clone)]
pub(crate) struct SubnetTree {
    ipv4: BTreeSet<Ipv4Key>,
    ipv6: BTreeSet<Ipv6Key>,
    mac: BTreeSet<MacKey>,
}

impl SubnetTree {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add an owned subnet, dispatching on the `Subnet` variant to the
    /// right tree.
    ///
    /// Idempotent — re-adding the same `(subnet, owner)` is a no-op.
    pub(crate) fn add(&mut self, subnet: Subnet, owner: String) {
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

    /// Add an ownerless (broadcast) subnet. Ownerless subnets divert
    /// to `route_broadcast`: the four hard-coded defaults (Ethernet
    /// broadcast, IPv4 limited broadcast, IPv4 multicast `224/4`,
    /// IPv6 multicast `ff00::/8`) plus any `BroadcastSubnet` config
    /// entries.
    pub(crate) fn add_broadcast(&mut self, subnet: Subnet) {
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
    pub(crate) fn del(&mut self, subnet: &Subnet, owner: &str) -> bool {
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
    /// (not in tree → fall through to).
    ///
    /// Allocates a `String` for the lookup key (same shape as
    /// `del()`). `ADD_SUBNET` is control-path-rare; the alloc is fine.
    #[must_use]
    pub(crate) fn contains(&self, subnet: &Subnet, owner: &str) -> bool {
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

    /// IPv4 longest-prefix lookup.
    ///
    /// Linear scan in tree order. Tree order has `/32` before `/24`
    /// before `/8` (descending prefix), so the FIRST entry whose
    /// top-`prefix` bits match `addr` is the longest-prefix match.
    ///
    /// ## Reachability
    ///
    /// The scan keeps going past matches whose owner is down, looking
    /// for a less-specific match owned by someone reachable. (If alice
    /// owns `10.0.0.0/24` but is offline, and bob owns `10.0.0.0/16`,
    /// route to bob.)
    ///
    /// We don't have node state here. `is_reachable` lets the caller
    /// inject it: return `true` for nodes that are up. The closure
    /// is called once per matching subnet, in longest-first order.
    ///
    /// If no reachable owner is found, the last mask hit is still
    /// returned so the caller can log "Node %s is not reachable" with
    /// that owner's name.
    pub(crate) fn lookup_ipv4(
        &self,
        addr: Ipv4Addr,
        mut is_reachable: impl FnMut(&str) -> bool,
    ) -> Option<(&Subnet, Option<&str>)> {
        // Build a /32 query subnet so we can reuse `Subnet::matches`
        // (which is `maskcmp` under the hood). Weight doesn't matter
        // for `matches(_, true)`.
        let q = Subnet::V4 {
            addr,
            prefix: 32,
            weight: 0,
        };
        let mut last_hit: Option<(&Subnet, Option<&str>)> = None;
        for k in &self.ipv4 {
            if k.subnet.matches(&q, true) {
                last_hit = Some((&k.subnet, k.owner.as_deref()));
                // Ownerless (broadcast) is always "reachable" — it goes
                // to ALL reachable peers via route_broadcast.
                if k.owner.as_deref().is_none_or(&mut is_reachable) {
                    break;
                }
            }
        }
        last_hit
    }

    /// IPv6 longest-prefix lookup. Same as v4.
    pub(crate) fn lookup_ipv6(
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
                // Ownerless is always "reachable".
                if k.owner.as_deref().is_none_or(&mut is_reachable) {
                    break;
                }
            }
        }
        last_hit
    }

    /// Iterate all owned subnets in C tinc's dump/gossip order:
    /// MAC first, then v4 (descending prefix), then v6. Matching this
    /// order keeps dump output diffable against C tincd.
    ///
    /// SKIPS ownerless (broadcast) subnets so they're never gossiped,
    /// same as C tinc. (Cosmetic fallout: `dump_subnets` won't print
    /// `(broadcast)` rows. Separate fix if anyone cares.)
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Subnet, &str)> {
        self.mac
            .iter()
            .map(|k| (&k.subnet, k.owner.as_deref()))
            .chain(self.ipv4.iter().map(|k| (&k.subnet, k.owner.as_deref())))
            .chain(self.ipv6.iter().map(|k| (&k.subnet, k.owner.as_deref())))
            .filter_map(|(s, o)| o.map(|o| (s, o)))
    }

    /// All subnets owned by `name`, collected. Wrapper over `iter()` +
    /// filter + collect shared by several callsites. The collect is
    /// intentional: callers immediately call `run_subnet_script` /
    /// `del()` while iterating, which would self-borrow on the iterator.
    #[must_use]
    pub(crate) fn owned_by(&self, name: &str) -> Vec<Subnet> {
        self.iter()
            .filter(|(_, o)| *o == name)
            .map(|(s, _)| *s)
            .collect()
    }

    /// Total entry count across all three families. For `dump
    /// subnets` and tests.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len() + self.mac.len()
    }

    /// Is the routing table empty?
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty() && self.mac.is_empty()
    }
}

// Tests

#[cfg(test)]
mod tests;
