//! Replayed SIG after a small-order X25519 pubkey must not panic.
//!
//! Datagram mode: errors are per-packet. A peer sending a KEX with an
//! all-zero X25519 pk then its signed SIG twice would, before the fix,
//! panic the receiver on the second SIG (ecdh/mlkem consumed, then
//! `expect` on `None`). The test forges the bytes directly since
//! `handshake_pair` can't inject a small-order point.

pub mod common;

use common::{SeedRng, keypair};
use tinc_crypto::sign::{SIG_LEN, SigningKey};
use tinc_sptps::{
    Framing, KEX_LEN, KEX_LEN_HYBRID, NONCE_LEN, Output, REC_HANDSHAKE, Role, Sptps, SptpsAead,
    SptpsError, SptpsKex, SptpsLabel, VERSION,
};

const MLKEM_CT_LEN: usize = 1088;
const HYBRID_SIG_LEN: usize = SIG_LEN + MLKEM_CT_LEN;

/// Mirrors private `sig_transcript` in `src/state.rs`.
fn sig_transcript(bit: bool, kex_a: &[u8], kex_b: &[u8], label: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + kex_a.len() + kex_b.len() + label.len());
    msg.push(u8::from(bit));
    msg.extend_from_slice(kex_a);
    msg.extend_from_slice(kex_b);
    msg.extend_from_slice(label);
    msg
}

/// `seqno_be32 ‖ type ‖ body`.
fn wire_record(seqno: u32, ty: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 1 + body.len());
    v.extend_from_slice(&seqno.to_be_bytes());
    v.push(ty);
    v.extend_from_slice(body);
    v
}

/// Strips the 5-byte datagram header; returns the KEX transcript bytes.
fn kex_body_of(out: &[Output]) -> Vec<u8> {
    for o in out {
        if let Output::Wire { bytes, .. } = o {
            return bytes[5..].to_vec();
        }
    }
    panic!("no wire output");
}

fn run_case(kex_mode: SptpsKex, label: &[u8]) {
    let (_akey, apub) = keypair(1);
    let (bkey, _bpub) = keypair(2);

    let (mut bob, b_out) = Sptps::start_with(
        Role::Responder,
        Framing::Datagram,
        kex_mode,
        bkey,
        apub,
        SptpsLabel::with_aead(label, SptpsAead::default()),
        common::REPLAYWIN,
        &mut SeedRng(0xBB),
    );
    let bob_kex_body = kex_body_of(&b_out);

    // Forged KEX: version ‖ arbitrary nonce ‖ all-zero X25519 pk
    // (small-order). Hybrid appends garbage ML-KEM ek — `kex_body_ok`
    // doesn't validate it; responder doesn't send SIG so the resulting
    // encap ciphertext goes unused.
    let kex_len = match kex_mode {
        SptpsKex::X25519 => KEX_LEN,
        SptpsKex::X25519MlKem768 => KEX_LEN_HYBRID,
    };
    let mut alice_fake_kex = vec![0u8; kex_len];
    alice_fake_kex[0] = VERSION;
    for (i, b) in alice_fake_kex[1..=NONCE_LEN].iter_mut().enumerate() {
        let i = u8::try_from(i).unwrap();
        *b = i.wrapping_mul(7).wrapping_add(0x5A);
    }

    // Transcript bit/order from bob's verify POV:
    //   bit = !role.is_initiator() = true; (kex_a, kex_b) = (alice, bob).
    let alice_seed = {
        let mut s = [0u8; 32];
        s[0] = 1;
        s
    };
    let alice_sk = SigningKey::from_seed(&alice_seed);
    let mut full_label = label.to_vec();
    let kd = kex_mode.discriminator();
    let cd = SptpsAead::default().discriminator();
    if kd != 0 || cd != 0 {
        full_label.push(kd);
        full_label.push(cd);
    }
    let msg = sig_transcript(true, &alice_fake_kex, &bob_kex_body, &full_label);
    let sig = alice_sk.sign(&msg);
    // Hybrid ct bytes irrelevant: BadKex fires before decapsulate.
    let sig_body = match kex_mode {
        SptpsKex::X25519 => sig.to_vec(),
        SptpsKex::X25519MlKem768 => {
            let mut v = Vec::with_capacity(HYBRID_SIG_LEN);
            v.extend_from_slice(&sig);
            v.resize(HYBRID_SIG_LEN, 0xAB);
            v
        }
    };

    let mut rng = SeedRng(0xC0FE);
    bob.receive(&wire_record(0, REC_HANDSHAKE, &alice_fake_kex), &mut rng)
        .expect("forged KEX is well-formed");

    let err1 = bob
        .receive(&wire_record(1, REC_HANDSHAKE, &sig_body), &mut rng)
        .unwrap_err();
    assert!(matches!(err1, SptpsError::BadKex), "got {err1:?}");

    // Second SIG pre-fix: panic on `None.expect(...)`. Post-fix: Err.
    let err2 = bob
        .receive(&wire_record(2, REC_HANDSHAKE, &sig_body), &mut rng)
        .unwrap_err();
    assert!(
        matches!(err2, SptpsError::InvalidState | SptpsError::BadKex),
        "got {err2:?}"
    );
}

#[test]
fn small_order_ecdh_replayed_sig_no_panic_classical() {
    run_case(SptpsKex::X25519, b"small-order-replay-x25519");
}

#[test]
fn small_order_ecdh_replayed_sig_no_panic_hybrid() {
    run_case(SptpsKex::X25519MlKem768, b"small-order-replay-hybrid");
}
