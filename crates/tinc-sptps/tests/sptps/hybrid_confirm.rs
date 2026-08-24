//! Hybrid `State::Confirm`: ciphers installed, confirm ACK not yet
//! verified, `HandshakeDone` withheld. Application data must neither
//! be sent nor surfaced in that window.

use crate::common::{NoRng, Pair, SeedRng, wire};
use tinc_sptps::{Output, Sptps, SptpsError, SptpsKex};

/// Both sides in `Confirm` with their ACKs in hand but not delivered.
fn pair_at_confirm() -> (Sptps, Sptps, Vec<u8>, Vec<u8>) {
    let mut rng = SeedRng(0xFEED);
    let (mut alice, mut bob, kex_a, kex_b) = Pair::datagram().kex(SptpsKex::X25519MlKem768).start();
    let sig_a = wire(alice.receive(&kex_b, &mut rng).unwrap().1);
    bob.receive(&kex_a, &mut rng).unwrap();

    let (_, outs) = bob.receive(&sig_a, &mut NoRng).unwrap();
    let [
        Output::Wire { bytes: sig_b, .. },
        Output::Wire { bytes: ack_b, .. },
    ] = &outs[..]
    else {
        panic!("bob: expected SIG + ACK only, got {outs:?}");
    };
    let (_, outs) = alice.receive(sig_b, &mut NoRng).unwrap();
    let [Output::Wire { bytes: ack_a, .. }] = &outs[..] else {
        panic!("alice: expected ACK only, got {outs:?}");
    };
    (alice, bob, ack_a.clone(), ack_b.clone())
}

#[test]
fn send_record_refused_in_confirm() {
    let (mut alice, mut bob, _, _) = pair_at_confirm();
    assert_eq!(
        alice.send_record(0, b"early"),
        Err(SptpsError::InvalidState)
    );
    assert_eq!(bob.send_record(0, b"early"), Err(SptpsError::InvalidState));
}

/// alice completes and sends data that UDP reorders ahead of her ACK;
/// bob must reject it rather than emit a `Record` before
/// `HandshakeDone`.
#[test]
fn no_record_before_handshake_done() {
    let (mut alice, mut bob, ack_a, ack_b) = pair_at_confirm();
    let (_, outs) = alice.receive(&ack_b, &mut NoRng).unwrap();
    assert_eq!(outs, [Output::HandshakeDone]);
    let early = wire(alice.send_record(7, b"reordered").unwrap());
    assert_eq!(
        bob.receive(&early, &mut NoRng).unwrap_err(),
        SptpsError::BadRecord
    );
    let (_, outs) = bob.receive(&ack_a, &mut NoRng).unwrap();
    assert_eq!(outs, [Output::HandshakeDone]);
}
