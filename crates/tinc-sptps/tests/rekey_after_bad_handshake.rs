//! A malformed encrypted handshake record (datagram mode, where `Err`
//! is per-packet) must not leave `mykex` set and wedge later rekeys.

pub mod common;

use common::{SeedRng, handshake_pair, wire_only};
use tinc_crypto::chapoly::ChaPoly;
use tinc_sptps::{Framing, REC_HANDSHAKE, SptpsError};

#[test]
fn peer_rekey_survives_prior_malformed_handshake() {
    let mut rng = SeedRng(0x00C0_FFEE);
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"rekey-regress");

    // Hand-seal an encrypted REC_HANDSHAKE with a 3-byte body
    // (≠ KEX_LEN) — `send_record` refuses type ≥ 128.
    let seqno = alice.alloc_seqnos(1).unwrap();
    let cipher = ChaPoly::new(&alice.outcipher_key().unwrap());
    let mut bad = seqno.to_be_bytes().to_vec();
    cipher.seal_into(u64::from(seqno), REC_HANDSHAKE, b"bad", &mut bad, 4);

    let err = bob.receive(&bad, &mut rng).unwrap_err();
    assert!(matches!(err, SptpsError::BadKex), "got {err:?}");

    let kex = wire_only(&alice.force_kex(&mut rng).unwrap()).remove(0);
    let (_, outs) = bob
        .receive(&kex, &mut rng)
        .expect("legitimate rekey after one BadKex must be accepted");
    assert!(!wire_only(&outs).is_empty());
}
