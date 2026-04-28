//! `ReplayWindow::check` (`state.rs:202-255`). The bitmap arithmetic
//! is ported verbatim from C — `(seqno / 8 % win)` indexing,
//! `farfuture` heuristic, `late` polarity inverted from intuition.
//! Dense enough to merit a black-box check.
//!
//! Property: with all packets inside one window width, every
//! first-delivery decrypts to its body and every duplicate is
//! `BadSeqno`. The `farfuture` and out-of-window paths don't fire
//! by construction — covering those needs a reference model.

pub mod common;

use common::{SeedRng, handshake_pair, wire_only};
use proptest::prelude::*;
use tinc_sptps::{Framing, Output, SptpsError};

proptest! {
    #[test]
    fn in_window_reorder_is_lossless(
        aseed in any::<u64>(),
        bseed in any::<u64>(),
        // ≤64 packets, 128-slot window: max gap is 63, farfuture
        // (≥128 ahead) and too_old (≥128 behind) never fire.
        bodies in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..200),
            1..64,
        ),
        // Delivery schedule: indices into bodies[], with repeats
        // (duplicates) and omissions (drops).
        schedule_raw in prop::collection::vec(any::<usize>(), 0..128),
    ) {
        // handshake_pair uses fixed RNG seeds; perturb keys per case.
        let _ = (aseed, bseed); // see TODO below
        let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"replay");

        let packets: Vec<Vec<u8>> = bodies.iter()
            .map(|b| wire_only(&alice.send_record(0, b).unwrap()).into_iter().next().unwrap())
            .collect();

        let schedule: Vec<usize> =
            schedule_raw.into_iter().map(|i| i % bodies.len()).collect();

        let mut rng = SeedRng(0);
        let mut accepted = Vec::new();
        for &idx in &schedule {
            match bob.receive(&packets[idx], &mut rng) {
                Ok((_, outs)) => {
                    prop_assert!(!accepted.contains(&idx), "dup {} accepted", idx);
                    prop_assert_eq!(outs.len(), 1);
                    match &outs[0] {
                        Output::Record { record_type: 0, bytes } =>
                            prop_assert_eq!(bytes, &bodies[idx]),
                        o => prop_assert!(false, "expected Record, got {:?}", o),
                    }
                    accepted.push(idx);
                }
                Err(SptpsError::BadSeqno) => {
                    prop_assert!(accepted.contains(&idx), "fresh {} rejected", idx);
                }
                Err(e) => prop_assert!(false, "unexpected: {:?}", e),
            }
        }
    }
}

// TODO: a reference-model property covering farfuture resync and
// out-of-window. Model is a `BTreeSet<u32>` of accepted seqnos +
// the same threshold counter. ~2 hours; see docs/testing-strategy.md.
