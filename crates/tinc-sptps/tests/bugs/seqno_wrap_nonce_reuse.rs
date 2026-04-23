//! AEAD nonce-reuse regressions: the wire nonce is `outseqno as u32`,
//! and the par-encrypt path (`alloc_seqnos` + `seal_with_seqno`) used
//! to bump the counter without the per-key limit gate.

use super::common::{SeedRng, handshake_pair, wire_only};
use std::sync::atomic::Ordering;
use tinc_sptps::{Framing, SEAL_KEY_LIMIT, SEAL_REKEY_THRESHOLD};

/// The bug: `alloc_seqnos` past 2^32 records would hand back a wrapped
/// seqno, and `seal_with_seqno` would emit a ciphertext byte-identical
/// to the one sealed at that seqno under the same key.
#[test]
fn alloc_seqnos_refuses_before_nonce_wrap() {
    let (alice, _bob) = handshake_pair(Framing::Datagram, b"wrap");
    let base = alice.out_key_base();

    let s0 = alice.alloc_seqnos(1).unwrap();
    let mut tx0 = Vec::new();
    alice
        .seal_with_seqno(s0, 0, b"same body", &mut tx0, 0)
        .unwrap();

    // One short of the hard limit: still allocates, and the ciphertext
    // differs (different nonce).
    alice
        .outseqno_handle()
        .store(base + SEAL_KEY_LIMIT - 1, Ordering::Relaxed);
    let s1 = alice.alloc_seqnos(1).unwrap();
    let mut tx1 = Vec::new();
    alice
        .seal_with_seqno(s1, 0, b"same body", &mut tx1, 0)
        .unwrap();
    assert_ne!(tx0, tx1);

    // At the limit (and at the 2^32 wrap point): refused.
    assert_eq!(alice.alloc_seqnos(1), None);
    alice
        .outseqno_handle()
        .store(base + (1u64 << 32), Ordering::Relaxed);
    assert_eq!(alice.alloc_seqnos(1), None);
}

#[test]
fn rekey_due_at_soft_threshold() {
    let (mut alice, _bob) = handshake_pair(Framing::Datagram, b"soft");
    assert!(!alice.rekey_due());
    let base = alice.out_key_base();
    alice
        .outseqno_handle()
        .store(base + SEAL_REKEY_THRESHOLD, Ordering::Relaxed);
    assert!(alice.rekey_due());
    // Soft threshold ≠ hard limit: seal still works.
    let mut tx = Vec::new();
    alice.seal_data_into(0, b"x", &mut tx, 0).unwrap();
}

/// In-band datagram rekey: wire seqno stays monotone, `out_key_base`
/// rebases so the per-key seal counter starts fresh.
#[test]
fn inband_datagram_rekey_rebases_key_counter() {
    let mut rng = SeedRng(0x5EED);
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"rekey-reset");

    // One pre-rekey packet so bob's replay window has inseqno > 0.
    let mut tx = Vec::new();
    alice.seal_data_into(0, b"pre", &mut tx, 0).unwrap();
    let mut rx = Vec::new();
    bob.open_data_into(&tx, &mut rx, 0).unwrap();

    let kex_a = wire_only(&alice.force_kex(&mut rng).unwrap()).remove(0);
    let kex_b = wire_only(&bob.receive(&kex_a, &mut rng).unwrap().1).remove(0);
    let sig_a = wire_only(&alice.receive(&kex_b, &mut rng).unwrap().1).remove(0);
    let bob_out = wire_only(&bob.receive(&sig_a, &mut rng).unwrap().1);
    let (sig_b, ack_b) = (bob_out[0].clone(), bob_out[1].clone());
    let ack_a = wire_only(&alice.receive(&sig_b, &mut rng).unwrap().1).remove(0);
    bob.receive(&ack_a, &mut rng).unwrap();
    alice.receive(&ack_b, &mut rng).unwrap();

    assert!(alice.out_key_base() > 0);
    assert_eq!(alice.sealed_count(), 0);
    let mut tx = Vec::new();
    alice.seal_data_into(0, b"post", &mut tx, 0).unwrap();
    assert!(u32::from_be_bytes(tx[0..4].try_into().unwrap()) > 0);
    let mut rx = Vec::new();
    let ty = bob.open_data_into(&tx, &mut rx, 0).unwrap();
    assert_eq!(ty, 0);
    assert_eq!(&rx[..], b"post");
}
