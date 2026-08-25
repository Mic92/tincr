//! `ReplayWindow::check`, black box: with all packets inside one window
//! width, every first delivery decrypts to its body and every duplicate
//! is `BadSeqno`. The far-future and out-of-window paths do not fire by
//! construction; covering those needs a reference model.

use crate::common::{Pair, SeedRng, wire};
use proptest::prelude::{any, prop, prop_assert, prop_assert_eq, proptest};
use tinc_sptps::{Output, SptpsError};

proptest! {
    #[test]
    fn in_window_reorder_is_lossless(
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
        let (mut alice, mut bob) = Pair::datagram().handshake();

        let packets: Vec<Vec<u8>> = bodies.iter()
            .map(|body| wire(alice.send_record(0, body).unwrap()))
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
