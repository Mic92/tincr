//! Hybrid `State::Confirm`: ciphers installed, confirm-ACK not yet
//! verified, `HandshakeDone` withheld. App data must neither be sent
//! nor surfaced in this window.

use crate::common::{NoRng, SeedRng, keypair, wire};
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsError, SptpsKex};

/// Drive both sides to `State::Confirm` (ACKs sent, neither processed).
/// Returns `(alice, bob, ack_a, ack_b)`.
fn hybrid_pair_at_confirm() -> (Sptps, Sptps, Vec<u8>, Vec<u8>) {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);
    let mut rng = SeedRng(0xFEED);

    let (mut alice, a0) = Sptps::start_with(
        Role::Initiator,
        Framing::Datagram,
        SptpsKex::X25519MlKem768,
        akey,
        bpub,
        b"confirm-gap",
        16,
        &mut SeedRng(0xA11CE),
    );
    let (mut bob, b0) = Sptps::start_with(
        Role::Responder,
        Framing::Datagram,
        SptpsKex::X25519MlKem768,
        bkey,
        apub,
        b"confirm-gap",
        16,
        &mut SeedRng(0xB0B),
    );

    let kex_a = wire(a0);
    let kex_b = wire(b0);

    let (_, outs) = alice.receive(&kex_b, &mut rng).unwrap();
    let sig_a = wire(outs);
    bob.receive(&kex_a, &mut rng).unwrap();

    // bob ← SIG_a → [SIG_b, ACK_b], state=Confirm, no HandshakeDone.
    let (_, outs) = bob.receive(&sig_a, &mut NoRng).unwrap();
    let mut it = outs.into_iter();
    let Some(Output::Wire { bytes: sig_b, .. }) = it.next() else {
        panic!("bob: SIG")
    };
    let Some(Output::Wire { bytes: ack_b, .. }) = it.next() else {
        panic!("bob: ACK")
    };
    assert!(it.next().is_none(), "bob: HandshakeDone leaked early");

    // alice ← SIG_b → [ACK_a], state=Confirm, no HandshakeDone.
    let (_, outs) = alice.receive(&sig_b, &mut NoRng).unwrap();
    let mut it = outs.into_iter();
    let Some(Output::Wire { bytes: ack_a, .. }) = it.next() else {
        panic!("alice: ACK")
    };
    assert!(it.next().is_none(), "alice: HandshakeDone leaked early");

    (alice, bob, ack_a, ack_b)
}

#[test]
fn send_record_refused_before_confirm_ack() {
    let (mut alice, mut bob, _ack_a, _ack_b) = hybrid_pair_at_confirm();

    assert_eq!(
        alice.send_record(0, b"too early").unwrap_err(),
        SptpsError::InvalidState,
        "alice in Confirm: send_record must refuse before HandshakeDone"
    );
    assert_eq!(
        bob.send_record(0, b"too early").unwrap_err(),
        SptpsError::InvalidState,
        "bob in Confirm: send_record must refuse before HandshakeDone"
    );
}

/// Alice completes, sends data; UDP reorders it ahead of her ACK.
/// Bob (still Confirm) must not surface `Record` before `HandshakeDone`.
#[test]
fn no_app_record_before_handshake_done() {
    let (mut alice, mut bob, ack_a, ack_b) = hybrid_pair_at_confirm();

    let (_, outs) = alice.receive(&ack_b, &mut NoRng).unwrap();
    assert!(matches!(outs[0], Output::HandshakeDone));
    let early = wire(alice.send_record(7, b"pre-confirm").unwrap());

    assert_eq!(
        bob.receive(&early, &mut NoRng).unwrap_err(),
        SptpsError::BadRecord,
        "bob in Confirm: app record must be rejected before HandshakeDone"
    );

    let (_, outs) = bob.receive(&ack_a, &mut NoRng).unwrap();
    assert!(matches!(outs[0], Output::HandshakeDone));
}
