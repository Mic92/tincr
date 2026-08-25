//! `SPTPSKex = x25519-mlkem768`. C tinc only speaks classical, so
//! hybrid correctness is pinned here rather than in `vs_c.rs`.

use crate::common::{NoRng, Pair, SeedRng, keypair, record, wire};
use std::time::Instant;
use tinc_crypto::hybrid::CT_LEN;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, KEX_LEN, KEX_LEN_HYBRID, Output, Role, Sptps, SptpsError, SptpsKex};

fn hybrid() -> Pair {
    Pair::datagram().kex(SptpsKex::X25519MlKem768)
}

#[test]
fn hybrid_roundtrip() {
    let (_, _, alice_kex, _) = hybrid().start();
    assert_eq!(alice_kex.len(), 4 + 1 + KEX_LEN_HYBRID);

    let (mut alice, mut bob) = hybrid().handshake();
    let (_, outs) = bob
        .receive(
            &wire(alice.send_record(0, b"hello quantum").unwrap()),
            &mut NoRng,
        )
        .unwrap();
    assert_eq!(record(outs), (0, b"hello quantum".to_vec()));
    let (_, outs) = alice
        .receive(
            &wire(bob.send_record(0, b"hello back").unwrap()),
            &mut NoRng,
        )
        .unwrap();
    assert_eq!(record(outs), (0, b"hello back".to_vec()));

    // Pins the role-symmetric `ss_i2r ‖ ss_r2i` ordering: a half-swap
    // passes each side's self-consistency but fails here.
    assert_eq!(alice.outcipher_key(), bob.incipher_key());
    assert_eq!(alice.incipher_key(), bob.outcipher_key());
    assert_ne!(alice.outcipher_key(), alice.incipher_key());
}

/// The ML-KEM ciphertext is not covered by the Ed25519 signature. A
/// tampered `ct` still verifies, but it feeds both decapsulation
/// (implicit rejection) and the PRF seed, so the keys diverge and the
/// confirm round fails its tag: `HandshakeDone` never fires.
#[test]
fn tampered_ct_no_handshake_done() {
    let mut rng = SeedRng(0xFEED);
    let (mut alice, mut bob, kex_a, kex_b) = hybrid().start();
    let sig_a = wire(alice.receive(&kex_b, &mut rng).unwrap().1);
    bob.receive(&kex_a, &mut rng).unwrap();
    let (_, outs) = bob.receive(&sig_a, &mut NoRng).unwrap();
    let [
        Output::Wire { bytes: sig_b, .. },
        Output::Wire { bytes: ack_b, .. },
    ] = &outs[..]
    else {
        panic!("expected SIG + ACK, got {outs:?}");
    };
    let mut sig_b = sig_b.clone();
    assert_eq!(sig_b.len(), 4 + 1 + 64 + CT_LEN);
    // Last byte: well-formed but wrong, so it reaches implicit
    // rejection rather than a parse error.
    *sig_b.last_mut().unwrap() ^= 0x01;

    let ack_a = wire(alice.receive(&sig_b, &mut NoRng).unwrap().1);
    assert!(alice.outcipher_key().is_none() && bob.outcipher_key().is_none());
    assert_eq!(
        alice.receive(ack_b, &mut NoRng).unwrap_err(),
        SptpsError::DecryptFailed
    );
    assert_eq!(
        bob.receive(&ack_a, &mut NoRng).unwrap_err(),
        SptpsError::DecryptFailed
    );
}

/// Pins the derived traffic key for fixed seeds so any change to the
/// KDF input (seed layout, hash binding, secret order) is noticed.
/// Update deliberately if the KDF changes.
const KDF_KAT: &str = "97762babaf1f366bf99a574a037286180aaf210bdead8aa592cdc8fff6927a7f\
                       21ab78c3f7e00146ddf1dfcc8196c93dfcdeb036d904ff6f5a43489cb2368008";

#[test]
fn hybrid_kdf_kat() {
    let mut pair = hybrid();
    pair.label = b"hybrid test".to_vec();
    pair.seeds = (0xA11CE, 0xB0B);
    let (mut alice, mut bob, kex_a, kex_b) = pair.start();
    // Encapsulation draws from the RNG, so its seed is part of the KAT.
    let mut rng = SeedRng(0xFEED);
    let sig_a = wire(alice.receive(&kex_b, &mut rng).unwrap().1);
    bob.receive(&kex_a, &mut rng).unwrap();
    let (_, outs) = bob.receive(&sig_a, &mut NoRng).unwrap();
    let [
        Output::Wire { bytes: sig_b, .. },
        Output::Wire { bytes: ack_b, .. },
    ] = &outs[..]
    else {
        panic!("expected SIG + ACK, got {outs:?}");
    };
    alice.receive(sig_b, &mut NoRng).unwrap();
    alice.receive(ack_b, &mut NoRng).unwrap();

    let expected: Vec<u8> = (0..128)
        .step_by(2)
        .map(|i| u8::from_str_radix(&KDF_KAT[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(alice.outcipher_key().unwrap().to_vec(), expected);
}

/// `kex_body_ok` rejects on length; no key is ever derived.
#[test]
fn kex_mode_mismatch_is_badkex() {
    for kex in [
        (SptpsKex::X25519MlKem768, SptpsKex::X25519),
        (SptpsKex::X25519, SptpsKex::X25519MlKem768),
    ] {
        let mut pair = Pair::datagram();
        pair.kex = kex;
        assert_eq!(
            pair.try_handshake().err(),
            Some(SptpsError::BadKex),
            "{kex:?}"
        );
    }
}

/// `vs_c.rs` pins `start` against C; this pins
/// `start_with(X25519) == start`.
#[test]
fn default_kex_byte_identical() {
    let (alice_key, _) = keypair(1);
    let (_, bob_pub) = keypair(2);
    let (_, classic) = Sptps::start(
        Role::Initiator,
        Framing::Datagram,
        SigningKey::from_blob(&alice_key.to_blob()),
        bob_pub,
        b"label",
        16,
        &mut SeedRng(42),
    );
    let (_, explicit) = Sptps::start_with(
        Role::Initiator,
        Framing::Datagram,
        SptpsKex::X25519,
        alice_key,
        bob_pub,
        b"label",
        16,
        &mut SeedRng(42),
    );
    let classic = wire(classic);
    assert_eq!(classic, wire(explicit));
    assert_eq!(classic.len(), 4 + 1 + KEX_LEN);
}

/// The per-tunnel handshake also rides the meta protocol as base64
/// bounded by `MAX_STRING = 2048`. An ML-KEM-1024 bump should trip
/// this rather than truncate on the wire.
#[test]
fn hybrid_records_fit_meta_protocol() {
    let b64_len = |n: usize| n.div_ceil(3) * 4;
    assert!(b64_len(4 + 1 + KEX_LEN_HYBRID) <= 2048);
    assert!(b64_len(4 + 1 + 64 + CT_LEN) <= 2048);
    assert!(u16::try_from(KEX_LEN_HYBRID).is_ok());
}

/// Prints classical vs hybrid handshake time so CI logs carry the
/// number; the bound is a sanity ceiling for debug builds, not a gate.
#[test]
fn handshake_latency_report() {
    let time = |pair: Pair| {
        let started = Instant::now();
        for _ in 0..16 {
            pair.handshake();
        }
        started.elapsed() / 16
    };
    let classical = time(Pair::datagram());
    let hybrid = time(hybrid());
    eprintln!(
        "SPTPS handshake: classical {classical:?}, hybrid {hybrid:?}, delta +{:?}",
        hybrid.saturating_sub(classical)
    );
    assert!(hybrid.as_millis() < 500, "{hybrid:?}");
}
