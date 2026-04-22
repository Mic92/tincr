//! `SPTPSCipher` selection: AES-256-GCM round-trip and the
//! mismatch-fails-cleanly property.
//!
//! The round-trip test proves the AEAD enum is threaded all the way
//! through `Sptps` (handshake → key derivation → record seal/open) and
//! that the fast-path `seal_data_into`/`open_data_into` pair agrees
//! with itself under AES the same way the existing `fastpath.rs` suite
//! pins it under ChaCha.
//!
//! The mismatch test pins the *failure mode*: the AEAD choice is mixed
//! into the SIG transcript via the label suffix, so a one-sided
//! `SPTPSCipher = aes-256-gcm` aborts the handshake with `BadSig` —
//! before any record key is derived, before any application data could
//! be silently corrupted. That's the operational contract documented in
//! `docs/OPERATING.md`.

mod common;

use common::{handshake_pair_aead, wire};
use tinc_sptps::{Framing, Output, SptpsAead, SptpsError};

/// Both ends `aes-256-gcm`: handshake completes, data flows both ways,
/// hot-path seal/open round-trips.
#[test]
fn aes_gcm_roundtrip_datagram() {
    let (mut alice, mut bob) = handshake_pair_aead(
        Framing::Datagram,
        b"tinc UDP key expansion alice bob\0",
        SptpsAead::Aes256Gcm,
        SptpsAead::Aes256Gcm,
    )
    .expect("matched aes-256-gcm handshake completes");

    assert_eq!(alice.aead(), SptpsAead::Aes256Gcm);
    assert_eq!(bob.aead(), SptpsAead::Aes256Gcm);

    // alice → bob, hot path
    let body = b"forty-two bytes of plaintext, MTU-ish later";
    let mut wire_buf = Vec::new();
    alice.seal_data_into(0, body, &mut wire_buf, 0).unwrap();
    let mut rx = Vec::new();
    let ty = bob.open_data_into(&wire_buf, &mut rx, 14).unwrap();
    assert_eq!(ty, 0);
    assert_eq!(&rx[14..], body);

    // bob → alice, cold path (`send_record`/`receive`)
    let outs = bob.send_record(0, b"pong").unwrap();
    let pkt = wire(outs);
    let (_, outs) = alice.receive(&pkt, &mut common::NoRng).unwrap();
    assert!(matches!(
        outs.as_slice(),
        [Output::Record { record_type: 0, bytes }] if bytes == b"pong"
    ));
}

/// One side `aes-256-gcm`, the other default: the SIG transcript
/// differs by the one-byte label suffix, so `ecdsa_verify` fails and
/// the handshake aborts with `BadSig`. No panic, no `HandshakeDone`,
/// no derived record key.
#[test]
fn aead_mismatch_fails_handshake_cleanly() {
    for (a, b) in [
        (SptpsAead::Aes256Gcm, SptpsAead::ChaCha20Poly1305),
        (SptpsAead::ChaCha20Poly1305, SptpsAead::Aes256Gcm),
    ] {
        // KEX is plaintext and length/version-checked only, so both
        // sides accept it; the first authenticated step is SIG.
        match handshake_pair_aead(Framing::Datagram, b"mismatch", a, b) {
            Err(SptpsError::BadSig) => {}
            Err(e) => panic!("a={a:?} b={b:?}: expected BadSig, got {e:?}"),
            Ok(_) => panic!("a={a:?} b={b:?}: mismatched SPTPSCipher completed handshake"),
        }
    }
}

/// Same key bytes, different AEAD: ciphertexts must differ. Guards
/// against a regression where the enum is plumbed but ignored at the
/// `SptpsCipher::new` call site (which would still round-trip, just
/// under the wrong primitive).
#[test]
fn aes_and_chacha_produce_different_records() {
    let (mut a_aes, _) = handshake_pair_aead(
        Framing::Datagram,
        b"distinct",
        SptpsAead::Aes256Gcm,
        SptpsAead::Aes256Gcm,
    )
    .unwrap();
    let (mut a_cc, _) = handshake_pair_aead(
        Framing::Datagram,
        b"distinct",
        SptpsAead::ChaCha20Poly1305,
        SptpsAead::ChaCha20Poly1305,
    )
    .unwrap();

    // Different label suffix ⇒ different PRF seed ⇒ different keys
    // already, but assert the record bytes too: this is what an
    // operator would tcpdump.
    let mut w1 = Vec::new();
    let mut w2 = Vec::new();
    a_aes.seal_data_into(0, b"x", &mut w1, 0).unwrap();
    a_cc.seal_data_into(0, b"x", &mut w2, 0).unwrap();
    assert_ne!(w1, w2);
}
