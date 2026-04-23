//! Confirm-state edge cases (hybrid initial handshake only).
//!
//! `State::Confirm` is reached after `receive_sig` installs both
//! ciphers but before the peer's encrypted confirm-ACK proves key
//! agreement. `Output::HandshakeDone` is deliberately withheld until
//! that ACK arrives — the whole point of the Confirm round is that a
//! tampered ML-KEM `ct` must never yield a session the daemon treats
//! as valid.
//!
//! `send_record`'s doc contract: "`InvalidState` if called before
//! `Output::HandshakeDone`". The implementation checks
//! `outcipher.is_none()`, which is `false` in Confirm. So app data
//! can be sent (and, on the peer, delivered as `Output::Record`)
//! before either side has emitted `HandshakeDone`.

use crate::common::{NoRng, SeedRng, keypair, wire};
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsError, SptpsKex};

/// Drive a hybrid datagram handshake until BOTH sides sit in
/// `State::Confirm`: in/out ciphers installed, confirm-ACK sent, but
/// neither side has processed the other's ACK yet (so neither has
/// emitted `HandshakeDone`). Returns `(alice, bob, ack_a, ack_b)`.
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

/// `send_record` is documented to return `InvalidState` before
/// `HandshakeDone`. In `State::Confirm` it returns `Ok` instead: the
/// gate is `outcipher.is_none()`, and Confirm has `outcipher` set.
#[test]
#[ignore = "bug: send_record succeeds in Confirm state (before HandshakeDone)"]
fn send_record_refused_before_confirm_ack() {
    let (mut alice, mut bob, _ack_a, _ack_b) = hybrid_pair_at_confirm();

    // Neither side has seen HandshakeDone. Per the doc contract both
    // calls must be refused.
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

/// Receive-side consequence: because `send_record` succeeds in
/// Confirm, a peer can ship app data that arrives (datagram reorder)
/// before the confirm-ACK. `receive_datagram` decrypts it and emits
/// `Output::Record` while still in Confirm — app data delivered to
/// the caller before `HandshakeDone`. The Confirm round's purpose
/// (no `validkey` until key-confirm) is undermined on both ends.
#[test]
#[ignore = "bug: app Record delivered before HandshakeDone in Confirm state"]
fn no_app_record_before_handshake_done() {
    let (mut alice, mut bob, ack_a, ack_b) = hybrid_pair_at_confirm();

    // Alice (in Confirm) sends app data — currently succeeds (see
    // sibling test). Bob receives it BEFORE alice's confirm-ACK
    // (plausible UDP reorder: data has seqno 3, ack_a has seqno 2).
    let early = alice
        .send_record(7, b"pre-confirm")
        .expect("setup: relies on the send-side bug to produce the record");
    let early = wire(early);

    let (_, outs) = bob.receive(&early, &mut NoRng).unwrap();
    assert!(
        !outs
            .iter()
            .any(|o| matches!(o, Output::Record { bytes, .. } if bytes == b"pre-confirm")),
        "bob in Confirm: must not surface app Record before HandshakeDone; got {outs:?}"
    );

    // Sanity: the deferred ACKs still complete the handshake.
    let (_, outs) = bob.receive(&ack_a, &mut NoRng).unwrap();
    assert!(matches!(outs[0], Output::HandshakeDone));
    let (_, outs) = alice.receive(&ack_b, &mut NoRng).unwrap();
    assert!(matches!(outs[0], Output::HandshakeDone));
}
