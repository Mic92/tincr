//! Identity-mixed hasher for small integer keys.
//!
//! ## Why
//!
//! `tunnels: HashMap<NodeId, TunnelState>` is hit ~5-10 times per
//! packet on the data path: `send_sptps_data_relay` reads `via`'s
//! and `relay`'s minmtu (2×), `send_sptps_packet` does an
//! `entry().or_default()` (1×), `dispatch_tunnel_outputs` re-reads
//! (1×), `try_tx` reads (1×). At 1.5 Mpps, that's ~10M SipHash
//! invocations/sec on a 4-byte `u32` payload.
//!
//! Profile post-x86-64-v3: `BuildHasher::hash_one` + `sip::Hasher::
//! write` = 5.7% self-time. C tincd does the equivalent lookup with
//! a raw `node_t*` pointer dereference (zero hash cost).
//!
//! `NodeId` is a dense `u32` slab index; `NodeId6` is 48 bits of
//! SHA-512 output. Neither needs a DoS-resistant hash — `NodeId` is
//! locally assigned (no attacker control), `NodeId6` is already
//! cryptographic-hash output (uniform; an attacker who can find
//! 6-byte SHA-512 prefix collisions has bigger problems for us than
//! hash-table degradation).
//!
//! ## What this does
//!
//! `write_u32`/`write_u64` apply one round of `splitmix64` mixing
//! to the input. NOT bare identity: hashbrown's swisstable probes
//! groups using the high 7 bits as a tag, so dense small integers
//! (`NodeId(0)`, `NodeId(1)`, `NodeId(2)`, ...) would all share the
//! tag byte `0x00` and degrade to linear scan within a group. One
//! multiply+shift fixes that. Still ~2ns vs SipHash's ~15ns.
//!
//! `write()` (the byte-slice path) is implemented for `[u8; 6]`
//! `NodeId6` keys: load as little-endian `u64` (zero-extended) and
//! mix. The derived `Hash` for `[u8; 6]` does NOT call `write` with
//! 6 bytes — it calls `write` with the slice then `write_usize` with
//! the length. We handle both: accumulate bytes via shift-or, mix
//! via XOR on the length write. The whole thing inlines to a handful
//! of instructions for fixed-size keys.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// `splitmix64` mixer. One multiply, one xor-shift, one multiply,
/// one xor-shift. Avalanche: every input bit affects every output
/// bit. Public-domain (Steele/Lea/Flood, 2014); used by `java.util.
/// SplittableRandom` and as the seeding function for `xoshiro`.
#[inline]
const fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

/// Hasher state. Just the running `u64`.
///
/// `Default` zeroes; `BuildHasherDefault` constructs fresh per
/// `hash_one`. No per-map seed (no DoS resistance — see module doc
/// for why that's fine here).
#[derive(Default, Clone)]
pub struct IntHasher(u64);

impl Hasher for IntHasher {
    #[inline]
    fn finish(&self) -> u64 {
        // The mix already happened in write_*; the state IS the hash.
        // For the `write()` byte path, mix happens here (the derived
        // Hash impl calls `write` then `write_usize(len)` then
        // `finish`; see write_usize).
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Slow path: only NodeId6's `[u8; 6]` derive hits this. Six
        // bytes, fixed. Accumulate little-endian into u64. The
        // derived Hash also calls write_usize(6) after — that's
        // where mixing happens (see below).
        let mut acc = self.0;
        for &b in bytes {
            acc = (acc << 8) | u64::from(b);
        }
        self.0 = acc;
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        // NodeId(u32) derive path. Mix immediately.
        self.0 = mix64(self.0 ^ u64::from(i));
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = mix64(self.0 ^ i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        // Derived Hash for `[u8; N]` calls this with `N` after the
        // `write()` call. The length is constant (6); we use the
        // call as the trigger to mix the accumulated bytes. The
        // `^ i` is harmless (constant).
        self.0 = mix64(self.0 ^ i as u64);
    }
}

/// `HashMap` with `IntHasher`. Drop-in for `std::collections::
/// HashMap<K, V>` where `K: Hash` is a small integer or short
/// fixed-size byte array.
pub type IntHashMap<K, V> = HashMap<K, V, BuildHasherDefault<IntHasher>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, Hash};

    #[test]
    fn distinct_u32_keys_distinct_hashes() {
        // Dense small keys must not collide. Swisstable uses h >> 57
        // as the tag byte; with bare identity, NodeId(0..128) would
        // all tag 0x00.
        let bh = BuildHasherDefault::<IntHasher>::default();
        let mut hashes: Vec<u64> = (0u32..1000).map(|i| bh.hash_one(i)).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 1000, "no collisions in 0..1000");
        // Tag-byte distribution: should NOT all be the same.
        let tags: std::collections::HashSet<u8> =
            (0u32..128).map(|i| (bh.hash_one(i) >> 57) as u8).collect();
        assert!(
            tags.len() > 50,
            "tag bytes well-distributed: {}",
            tags.len()
        );
    }

    #[test]
    fn six_byte_keys_work() {
        // NodeId6 path: derived Hash for [u8; 6] calls write(&bytes)
        // then write_usize(6).
        let bh = BuildHasherDefault::<IntHasher>::default();
        let h1 = bh.hash_one([1u8, 2, 3, 4, 5, 6]);
        let h2 = bh.hash_one([1u8, 2, 3, 4, 5, 7]);
        let h3 = bh.hash_one([0u8, 0, 0, 0, 0, 0]);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn newtype_u32_keys() {
        // NodeId is a #[derive(Hash)] newtype over u32. The derive
        // calls write_u32 directly.
        #[derive(Hash, PartialEq, Eq, Clone, Copy)]
        struct K(u32);
        let bh = BuildHasherDefault::<IntHasher>::default();
        let mut hashes: Vec<u64> = (0u32..1000).map(|i| bh.hash_one(K(i))).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 1000);
    }
}
