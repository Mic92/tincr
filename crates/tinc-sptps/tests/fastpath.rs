//! Rust↔Rust round-trip tests for the zero-alloc fast-path methods
//! (`seal_data_into` / `open_data_into`). Unlike `vs_c.rs` these don't
//! need the C harness, so they always run.

use rand_core::RngCore;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsError};

const REPLAYWIN: usize = 16;

fn keypair(tag: u8) -> (SigningKey, [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    let sk = SigningKey::from_seed(&seed);
    let pk = *sk.public_key();
    (sk, pk)
}

/// Dummy RNG for `receive` calls that won't trigger `send_kex`.
struct NoRng;
impl RngCore for NoRng {
    fn next_u32(&mut self) -> u32 {
        panic!("RNG touched")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("RNG touched")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("RNG touched")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!("RNG touched")
    }
}

/// Minimal seeded RNG for the handshake KEX.
struct SeedRng(u64);
impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn wire(mut outs: Vec<Output>) -> Vec<u8> {
    assert_eq!(outs.len(), 1, "expected one Wire, got {outs:?}");
    match outs.remove(0) {
        Output::Wire { bytes, .. } => bytes,
        o => panic!("expected Wire, got {o:?}"),
    }
}

/// Run the datagram handshake to completion, return both ends.
fn handshake_pair() -> (Sptps, Sptps) {
    let (alice_key, alice_pub) = keypair(1);
    let (bob_key, bob_pub) = keypair(2);

    let (mut alice, outs) = Sptps::start(
        Role::Initiator,
        Framing::Datagram,
        alice_key,
        bob_pub,
        b"fast".to_vec(),
        REPLAYWIN,
        &mut SeedRng(0xAA),
    );
    let kex_a = wire(outs);

    let (mut bob, outs) = Sptps::start(
        Role::Responder,
        Framing::Datagram,
        bob_key,
        alice_pub,
        b"fast".to_vec(),
        REPLAYWIN,
        &mut SeedRng(0xBB),
    );
    let kex_b = wire(outs);

    let (_, outs) = alice.receive(&kex_b, &mut NoRng).unwrap();
    let sig_a = wire(outs);
    let (_, outs) = bob.receive(&kex_a, &mut NoRng).unwrap();
    assert!(outs.is_empty());
    let (_, outs) = bob.receive(&sig_a, &mut NoRng).unwrap();
    // Responder emits SIG then HandshakeDone.
    let sig_b = match outs.into_iter().next().unwrap() {
        Output::Wire { bytes, .. } => bytes,
        o => panic!("expected Wire, got {o:?}"),
    };
    let (_, outs) = alice.receive(&sig_b, &mut NoRng).unwrap();
    assert_eq!(outs, vec![Output::HandshakeDone]);

    (alice, bob)
}

/// `seal_data_into` → `open_data_into` round-trip with nonzero headroom
/// on both sides. Asserts byte equality and that headroom is zero-filled.
#[test]
fn seal_into_open_into_roundtrip() {
    let (mut alice, mut bob) = handshake_pair();

    let body = b"the quick brown fox jumps over the lazy dog";
    let mut tx = Vec::new();
    alice.seal_data_into(7, body, &mut tx, 12).unwrap();
    // tx = [0;12] ‖ seqno:4 ‖ enc(type ‖ body) ‖ tag:16
    assert_eq!(&tx[..12], &[0u8; 12]);
    assert_eq!(tx.len(), 12 + 4 + 1 + body.len() + 16);

    // Receiver: decrypt the SPTPS datagram (skip caller's tx headroom)
    // into rx with 14 bytes recv-side headroom.
    let mut rx = Vec::new();
    let ty = bob.open_data_into(&tx[12..], &mut rx, 14).unwrap();
    assert_eq!(ty, 7);
    assert_eq!(&rx[..14], &[0u8; 14]);
    assert_eq!(&rx[14..], &body[..]);

    // Second packet: rx Vec is reused, capacity retained, no realloc.
    let cap_before = rx.capacity();
    let body2 = b"second";
    let mut tx2 = Vec::new();
    alice.seal_data_into(0, body2, &mut tx2, 12).unwrap();
    let ty = bob.open_data_into(&tx2[12..], &mut rx, 14).unwrap();
    assert_eq!(ty, 0);
    assert_eq!(&rx[14..], &body2[..]);
    assert_eq!(rx.capacity(), cap_before, "rx scratch reallocated");
}

/// `open_data_into` rejects handshake records WITHOUT advancing the
/// replay window, so the slow-path `receive()` fallback can re-decrypt
/// the same seqno.
#[test]
fn open_data_into_handshake_falls_back() {
    let (mut alice, mut bob) = handshake_pair();

    // Trigger a re-KEX from alice. This emits an encrypted REC_HANDSHAKE
    // datagram.
    let outs = alice.force_kex(&mut SeedRng(0xCC)).unwrap();
    let kex2 = wire(outs);

    // Fast path must reject it…
    let mut rx = Vec::new();
    let err = bob.open_data_into(&kex2, &mut rx, 14).unwrap_err();
    assert_eq!(err, SptpsError::BadRecord);

    // …and rejecting again must give the SAME error (replay window NOT
    // advanced; same seqno still fresh).
    let err2 = bob.open_data_into(&kex2, &mut rx, 14).unwrap_err();
    assert_eq!(err2, SptpsError::BadRecord);

    // Slow path then handles it: bob is in SecondaryKex, the encrypted
    // KEX bumps it through the fall-through (send_kex + receive_kex).
    let (_, outs) = bob.receive(&kex2, &mut SeedRng(0xDD)).unwrap();
    // Bob responds with his own KEX.
    assert!(matches!(outs[0], Output::Wire { .. }));
}

/// `open_data_into` before handshake completes → InvalidState (no incipher).
#[test]
fn open_data_into_pre_handshake() {
    let (alice_key, _) = keypair(1);
    let (_, bob_pub) = keypair(2);
    let (mut alice, _) = Sptps::start(
        Role::Initiator,
        Framing::Datagram,
        alice_key,
        bob_pub,
        b"x".to_vec(),
        REPLAYWIN,
        &mut SeedRng(1),
    );
    let mut rx = Vec::new();
    let err = alice.open_data_into(&[0u8; 32], &mut rx, 0).unwrap_err();
    assert_eq!(err, SptpsError::InvalidState);
}
