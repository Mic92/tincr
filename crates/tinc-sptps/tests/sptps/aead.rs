//! `SPTPSCipher` selection. The AEAD is mixed into the SIG transcript
//! via the label suffix, so a one-sided setting must abort the
//! handshake at `BadSig`, before any record key exists.

use crate::common::{NoRng, Pair, record, wire};
use tinc_sptps::{SptpsAead, SptpsError};

#[test]
fn aes_gcm_roundtrip() {
    let (mut alice, mut bob) = Pair::datagram().aead(SptpsAead::Aes256Gcm).handshake();
    assert_eq!(alice.aead(), SptpsAead::Aes256Gcm);
    assert_eq!(bob.aead(), SptpsAead::Aes256Gcm);

    let body = b"forty-two bytes of plaintext, MTU-ish later";
    let mut tx = Vec::new();
    alice.seal_data_into(0, body, &mut tx, 0).unwrap();
    let mut rx = Vec::new();
    assert_eq!(bob.open_data_into(&tx, &mut rx, 14).unwrap(), 0);
    assert_eq!(&rx[14..], body);

    let (_, outs) = alice
        .receive(&wire(bob.send_record(0, b"pong").unwrap()), &mut NoRng)
        .unwrap();
    assert_eq!(record(outs), (0, b"pong".to_vec()));
}

#[test]
fn aead_mismatch_fails_at_sig() {
    for aead in [
        (SptpsAead::Aes256Gcm, SptpsAead::ChaCha20Poly1305),
        (SptpsAead::ChaCha20Poly1305, SptpsAead::Aes256Gcm),
    ] {
        let mut pair = Pair::datagram();
        pair.aead = aead;
        assert_eq!(
            pair.try_handshake().err(),
            Some(SptpsError::BadSig),
            "{aead:?}"
        );
    }
}

/// Guards against the enum being plumbed but ignored where the cipher
/// is constructed, which would still round-trip.
#[test]
fn aes_and_chacha_records_differ() {
    let seal = |aead| {
        let (mut alice, _) = Pair::datagram().aead(aead).handshake();
        let mut tx = Vec::new();
        alice.seal_data_into(0, b"x", &mut tx, 0).unwrap();
        tx
    };
    assert_ne!(
        seal(SptpsAead::Aes256Gcm),
        seal(SptpsAead::ChaCha20Poly1305)
    );
}
