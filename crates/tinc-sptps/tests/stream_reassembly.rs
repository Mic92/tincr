//! `receive_stream`'s two-phase reassembly buffer (`state.rs:1004-`).
//! `vs_c.rs` feeds whole records — the partial-read early returns
//! (mid-length-header, mid-body, exactly-at-boundary) are dark there.
//!
//! Property: chopping the wire byte stream at arbitrary offsets
//! yields the same `Output` sequence as feeding it whole.

pub mod common;

use common::{SeedRng, feed_stream, keypair, wire_only};
use proptest::prelude::*;
use tinc_sptps::{Framing, Output, Role, Sptps};

/// Generate the canonical handshake byte streams (alice→bob, bob→alice)
/// and the `Output` sequence each side observes when fed the other's.
fn reference(aseed: u64, bseed: u64) -> (Vec<u8>, Vec<u8>, Vec<Output>, Vec<Output>) {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);

    let (mut alice, a0) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        akey,
        bpub,
        b"frag".to_vec(),
        0,
        &mut SeedRng(aseed),
    );
    let (mut bob, b0) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        bkey,
        apub,
        b"frag".to_vec(),
        0,
        &mut SeedRng(bseed),
    );

    let mut a2b: Vec<u8> = wire_only(&a0).into_iter().flatten().collect();
    let mut b2a: Vec<u8> = wire_only(&b0).into_iter().flatten().collect();
    let mut alice_obs = Vec::new();
    let mut bob_obs = Vec::new();

    let step = |s: &mut Sptps, bytes: &[u8], obs: &mut Vec<Output>| -> Vec<u8> {
        let mut tx = Vec::new();
        for o in feed_stream(s, bytes) {
            if let Output::Wire { bytes, .. } = &o {
                tx.extend_from_slice(bytes);
            }
            obs.push(o);
        }
        tx
    };

    // bob ← KEX_a (no output)
    let w = step(&mut bob, &a2b, &mut bob_obs);
    debug_assert!(w.is_empty());
    let a2b_mark = a2b.len();

    // alice ← KEX_b → SIG_a
    a2b.extend(step(&mut alice, &b2a, &mut alice_obs));
    let b2a_mark = b2a.len();

    // bob ← SIG_a → SIG_b + HandshakeDone
    b2a.extend(step(&mut bob, &a2b[a2b_mark..], &mut bob_obs));

    // alice ← SIG_b → HandshakeDone
    let w = step(&mut alice, &b2a[b2a_mark..], &mut alice_obs);
    debug_assert!(w.is_empty());

    (a2b, b2a, alice_obs, bob_obs)
}

/// Feed `bytes` chopped at `cuts` (sorted, deduped offsets).
fn feed_chopped(role: Role, seed: u64, bytes: &[u8], cuts: &[usize]) -> Vec<Output> {
    let (mykey, _) = keypair(if matches!(role, Role::Initiator) {
        1
    } else {
        2
    });
    let (_, hiskey) = keypair(if matches!(role, Role::Initiator) {
        2
    } else {
        1
    });
    let (mut sptps, _) = Sptps::start(
        role,
        Framing::Stream,
        mykey,
        hiskey,
        b"frag".to_vec(),
        0,
        &mut SeedRng(seed),
    );

    let mut obs = Vec::new();
    let mut prev = 0;
    for &c in cuts.iter().chain(std::iter::once(&bytes.len())) {
        obs.extend(feed_stream(&mut sptps, &bytes[prev..c]));
        prev = c;
    }
    obs
}

/// Clamp raw u16 cut points into `[0, len)`, sorted and unique.
/// proptest can't generate offsets dependent on a runtime length.
fn norm_cuts(raw: &[u16], len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let mut v: Vec<usize> = raw.iter().map(|&c| usize::from(c) % len).collect();
    v.sort_unstable();
    v.dedup();
    v
}

proptest! {
    #[test]
    fn fragmentation_transparent_initiator(
        aseed in any::<u64>(),
        bseed in any::<u64>(),
        raw_cuts in prop::collection::vec(any::<u16>(), 0..16),
    ) {
        let (_a2b, b2a, alice_ref, _) = reference(aseed, bseed);
        let cuts = norm_cuts(&raw_cuts, b2a.len());
        prop_assert_eq!(feed_chopped(Role::Initiator, aseed, &b2a, &cuts), alice_ref);
    }

    #[test]
    fn fragmentation_transparent_responder(
        aseed in any::<u64>(),
        bseed in any::<u64>(),
        raw_cuts in prop::collection::vec(any::<u16>(), 0..16),
    ) {
        let (a2b, _b2a, _, bob_ref) = reference(aseed, bseed);
        let cuts = norm_cuts(&raw_cuts, a2b.len());
        prop_assert_eq!(feed_chopped(Role::Responder, bseed, &a2b, &cuts), bob_ref);
    }
}
