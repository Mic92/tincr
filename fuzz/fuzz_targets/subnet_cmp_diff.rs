//! Differential fuzz: `cmp_ipv4_fuzz` vs C `subnet_compare_ipv4`.
//!
//! ## What this catches that Alloy didn't
//!
//! Alloy proved the *abstract* total order is correct: longest-prefix
//! first, then address, then weight, then owner. It modelled `cmp` as
//! a mathematical relation. It can't see that `Ipv4Addr::cmp` and
//! `memcmp` agree on byte order, or that `pa.cmp(&pb).reverse()` and
//! `b - a` agree on sign for all values, or what happens at `i32::MIN`.
//!
//! The C does `a->weight - b->weight` (subnet_parse.c:152). That's
//! signed-overflow UB on `(i32::MIN, 1)`. The shim is built with
//! `-fwrapv` so it wraps to a large positive — the Rust uses `Ord::cmp`
//! and gets `Less`. **That's a real divergence** and the fuzzer will
//! find it in seconds. Whether it's a *bug* depends on whether weights
//! that large are reachable on the wire (they are: `%d` parse, no range
//! check). Tag any such finding `[FAILING]` and let a human decide.
//!
//! ## Input shape
//!
//! Structured via `Arbitrary`: two `(addr, prefix, weight)` triples.
//! `prefix` is `i32` not `u8` — the C type is bare `int` and a buggy
//! peer could send garbage. The Rust parser clamps to `0..=32` before
//! the comparator ever sees it, so feeding `prefix = -1` here tests a
//! domain the production code can't reach. That's fine: if the wider
//! domain is clean, the narrow one is too. If it diverges only on
//! out-of-range prefix, that's a finding to note but not a bug.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::cmp::Ordering;
use tinc_ffi::{FfiIpv4Subnet, c_subnet_compare_ipv4};
use tincd::subnet_tree::cmp_ipv4_fuzz;

/// One IPv4 subnet, fuzz-shaped.
///
/// `prefix` is constrained to `0..=32`: the C `b->prefixlength -
/// a->prefixlength` (subnet_parse.c:140) overflows on out-of-range
/// `int` values just like weight does, and the fuzzer found that in
/// <1s. But `str2net` (subnet_parse.c:254) rejects `prefix > 32` and
/// `prefix < 0` BEFORE the subnet ever enters the tree, so the
/// comparator never sees garbage prefix in production. Constraining
/// here keeps the fuzzer focused on the reachable domain.
///
/// `weight` stays unconstrained `i32`: `%d` parse, no range check
/// (subnet_parse.c:250). A peer sending `Subnet = 10.0.0.0/8#-2147483648`
/// is dumb but legal; the comparator WILL see it.
#[derive(Debug, Clone, Copy)]
struct FuzzSubnet {
    addr: [u8; 4],
    prefix: u8, // 0..=32 enforced in Arbitrary impl
    weight: i32,
}

impl<'a> Arbitrary<'a> for FuzzSubnet {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            addr: u.arbitrary()?,
            prefix: u.int_in_range(0..=32)?,
            weight: u.arbitrary()?,
        })
    }
}

impl From<FuzzSubnet> for FfiIpv4Subnet {
    fn from(s: FuzzSubnet) -> Self {
        FfiIpv4Subnet {
            addr: s.addr,
            prefixlength: i32::from(s.prefix),
            weight: s.weight,
        }
    }
}

fuzz_target!(|pair: (FuzzSubnet, FuzzSubnet)| {
    let (a, b) = pair;

    let rust = cmp_ipv4_fuzz(
        a.addr,
        i32::from(a.prefix),
        a.weight,
        b.addr,
        i32::from(b.prefix),
        b.weight,
    );
    let c = c_subnet_compare_ipv4(&a.into(), &b.into());

    // C returns a signed difference; Rust returns Ordering. Compare
    // signs. `c.signum()` maps {neg,0,pos} → {-1,0,1}; `Ordering as
    // i32` does the same via the discriminant (Less=-1, Equal=0,
    // Greater=1 — guaranteed by std).
    let rust_sign = match rust {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };

    // KNOWN divergence: `a->weight - b->weight` (subnet_parse.c:152)
    // wraps under -fwrapv when |a.w - b.w| > i32::MAX. Rust's Ord::cmp
    // doesn't. Only fires when prefix and addr tie (the comparator
    // short-circuits otherwise). Ported to a `[FAILING]` test:
    // `tincd::subnet_tree::tests::ipv4_ord_weight_at_i32_extremes`.
    // Mask it here so the fuzzer can search for *unknown* divergences.
    if a.prefix == b.prefix && a.addr == b.addr {
        let true_diff = i64::from(a.weight) - i64::from(b.weight);
        if true_diff != i64::from(a.weight.wrapping_sub(b.weight)) {
            return; // weight subtraction wrapped on the C side
        }
    }

    assert_eq!(
        rust_sign,
        c.signum(),
        "CMP diverged: a={a:?} b={b:?} → C={c} Rust={rust:?}"
    );
});
