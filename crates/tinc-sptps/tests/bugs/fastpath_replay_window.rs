//! `open_data_into` must NOT advance the replay window on `BadRecord`.
//! The daemon retries the same packet via `receive()`; if the window
//! had advanced, the slow path would `BadSeqno`.
//!
//! Pinned because `receive_datagram` does decrypt → check → dispatch;
//! harmonising the fast path to that order breaks fall-back.

use tinc_sptps::{Framing, Output, SptpsError};

use crate::common::{SeedRng, handshake_pair, wire};

#[test]
fn badrecord_does_not_advance_window() {
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"bug");

    let mut tx_data = Vec::new();
    alice.seal_data_into(0, b"x", &mut tx_data, 0).unwrap();
    let tx_kex = wire(alice.force_kex(&mut SeedRng(0xCC)).unwrap());

    // Fast-path the KEX first: BadRecord, window untouched.
    let mut out = Vec::new();
    let err = bob.open_data_into(&tx_kex, &mut out, 0).unwrap_err();
    assert_eq!(err, SptpsError::BadRecord);

    // Data (lower seqno) accepted; window now past it.
    bob.open_data_into(&tx_data, &mut out, 0).unwrap();

    // KEX seqno still fresh on the slow path → fall-back works.
    let (_, outs) = bob.receive(&tx_kex, &mut SeedRng(0xDD)).unwrap();
    assert!(matches!(outs[0], Output::Wire { .. }));
}
