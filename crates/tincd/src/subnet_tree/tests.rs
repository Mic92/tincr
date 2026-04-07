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

/// Level 1: `prefixlength` DESCENDING (`b - a`). /24 sorts
/// BEFORE /16 in tree order — the longer prefix is "smaller" so
/// iteration sees it first.
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

/// Weight is `i32`, parsed with `%d`, never bounds-checked.
/// `Ord::cmp` doesn't overflow; `a->weight - b->weight` would.
/// Pin: negative sorts before positive (it's just integer order).
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

/// **[DOCUMENTED]** divergence from upstream `subnet_compare`.
///
/// Found by analysis of the C implementation. Upstream does
/// `a->weight - b->weight` — signed-overflow UB, observably wrap
/// under `-fwrapv`. Rust uses `Ord::cmp` which never overflows.
/// At `i32::MAX` vs `i32::MIN` the C result wraps to `-1` (Less);
/// Rust correctly says Greater.
///
/// **Wire-reachable:** weight is `%d`-parsed with no range check. `Subnet = 10.0.0.0/8#2147483647` is accepted.
/// Two such subnets with the same prefix+addr from different owners
/// route differently on C tincd vs Rust tincd: C's splay tree and
/// Rust's `BTreeMap` iterate them in opposite order.
///
/// **Why we don't match C:** the C behaviour is *undefined*, not
/// merely different. Without `-fwrapv` (which upstream's meson
/// build does NOT set) the optimizer can assume the subtraction
/// never overflows and rearrange the comparison arbitrarily.
/// Replicating UB with `wrapping_sub().signum()` would pin us to
/// the gcc-x86_64-at-O2 behaviour, which is exactly the kind of
/// thing that breaks under LTO or a clang upgrade.
///
/// **This test passes.** It pins the Rust behaviour (correct
/// integer order). If someone later "fixes" the comparator to
/// match C's wrap, this breaks and they read why that's wrong.
/// The right fix is on the parse side: clamp weight to a sane
/// range (±2^30) and the subtraction can't overflow on either
/// side. That's a wire-format change — separate commit, needs
/// crossimpl validation.
#[test]
fn ipv4_ord_weight_at_i32_extremes() {
    // Same prefix+addr forces the comparator down to the weight
    // tier. Use the absolute extremes — the worst the wire can
    // deliver via `%d`.
    let key = |w: i32| Ipv4Key {
        subnet: Subnet::V4 {
            addr: Ipv4Addr::UNSPECIFIED,
            prefix: 24,
            weight: w,
        },
        owner: None,
    };
    let max = key(i32::MAX);
    let min = key(i32::MIN);

    // Rust: MAX > MIN. Obviously. Ord::cmp doesn't care how far apart.
    assert_eq!(max.cmp(&min), Ordering::Greater);
    assert_eq!(min.cmp(&max), Ordering::Less);

    // What C's `a->weight - b->weight` produces under wrap-on-
    // overflow: MAX - MIN = 2^32 - 1 ≡ -1 (mod 2^32). Negative,
    // so C says Less. Computed here to document the divergence;
    // This documents the divergence from the C implementation.
    let c_wrapped = i32::MAX.wrapping_sub(i32::MIN);
    assert_eq!(c_wrapped, -1, "C's view: MAX - MIN wraps to -1");
    assert_ne!(
        c_wrapped.signum(),
        1,
        "C and Rust DISAGREE here — that's the documented divergence"
    );

    // Sanity: just below the overflow boundary, both agree.
    let half_hi = key(i32::MAX / 2);
    let half_lo = key(i32::MIN / 2);
    assert_eq!(half_hi.cmp(&half_lo), Ordering::Greater);
    assert!((i32::MAX / 2).wrapping_sub(i32::MIN / 2) > 0);
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

/// `subnet_compare_mac`: NO prefix level. Just addr, weight,
/// owner. Three levels not four.
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
/// (sorts first, hits first). `a->weight - b->weight` ascending.
#[test]
fn lookup_weight_prefers_lower() {
    let mut t = SubnetTree::new();
    t.add(sn("10.0.0.0/24#20"), "backup".into());
    t.add(sn("10.0.0.0/24#5"), "primary".into());

    let (_, owner) = t.lookup_ipv4(&Ipv4Addr::new(10, 0, 0, 1), all_up).unwrap();
    assert_eq!(owner, Some("primary"));
}

/// `if(p->owner->status.reachable) break`. alice owns the /24
/// but is down; bob owns the /16 and is up.
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

/// `r = p` happens BEFORE the reachable check. If NOBODY is
/// reachable, return the last (= shortest matching) subnet
/// anyway. `route_ipv4` uses this to log "would route to X but X
/// is unreachable" instead of "no route".
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

/// `!p->owner ||` — ownerless ALWAYS breaks the scan, regardless
/// of `is_reachable`. The predicate isn't even called (no name to
/// pass). `route_ipv4` then sees `None` and returns `Broadcast`.
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

/// `iter()` skips ownerless. `send_everything` walks per-node
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
/// (`BTreeMap` key uniqueness).
#[test]
fn add_idempotent() {
    let mut t = SubnetTree::new();
    t.add(sn("10.0.0.0/24"), "n".into());
    t.add(sn("10.0.0.0/24"), "n".into());
    assert_eq!(t.len(), 1);
}

/// `iter()` walks in C-splay-order: type discriminant first
/// (MAC=0, V4=1, V6=2), then per-family comparator.
/// `dump_subnets` walks this way. The CLI doesn't depend on
/// order but matching upstream makes diffing dump output easy.
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
