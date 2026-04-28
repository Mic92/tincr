//! `SPTPSKex = x25519-mlkem768` round-trip, mismatch, and wire-compat
//! regression. The C differential harness (`vs_c.rs`) only ever
//! exercises classical mode, so hybrid correctness is pinned here.

pub mod common;
use common::{NoRng, SeedRng, keypair, wire};

use std::time::Instant;
use tinc_crypto::hybrid::CT_LEN;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, KEX_LEN, KEX_LEN_HYBRID, Output, Role, Sptps, SptpsError, SptpsKex};

/// Drive a full handshake; propagates the first `receive` error so the
/// mismatch test can assert on it.
fn handshake(
    a_kex: SptpsKex,
    b_kex: SptpsKex,
) -> Result<(Sptps, Sptps, Vec<u8>), (SptpsError, &'static str)> {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);

    let (mut alice, a0) = Sptps::start_with(
        Role::Initiator,
        Framing::Datagram,
        a_kex,
        akey,
        bpub,
        b"hybrid test",
        16,
        &mut SeedRng(0xA11CE),
    );
    let (mut bob, b0) = Sptps::start_with(
        Role::Responder,
        Framing::Datagram,
        b_kex,
        bkey,
        apub,
        b"hybrid test",
        16,
        &mut SeedRng(0xB0B),
    );

    let kex_a = wire(a0);
    let kex_b = wire(b0);

    // Hybrid `receive_kex` draws RNG (encapsulate); `NoRng` would panic.
    let mut rng = SeedRng(0xFEED);

    let (_, outs) = alice
        .receive(&kex_b, &mut rng)
        .map_err(|e| (e, "alice<-kex"))?;
    let sig_a = wire(outs);

    bob.receive(&kex_a, &mut rng).map_err(|e| (e, "bob<-kex"))?;

    let (_, outs) = bob
        .receive(&sig_a, &mut NoRng)
        .map_err(|e| (e, "bob<-sig"))?;
    let mut it = outs.into_iter();
    let Some(Output::Wire { bytes: sig_b, .. }) = it.next() else {
        panic!("bob: expected SIG wire");
    };
    match a_kex {
        SptpsKex::X25519 => {
            assert!(matches!(it.next(), Some(Output::HandshakeDone)));
            let (_, outs) = alice
                .receive(&sig_b, &mut NoRng)
                .map_err(|e| (e, "alice<-sig"))?;
            assert!(matches!(outs[0], Output::HandshakeDone));
        }
        SptpsKex::X25519MlKem768 => {
            // Hybrid: confirm-ACK after SIG; HandshakeDone deferred.
            let Some(Output::Wire { bytes: ack_b, .. }) = it.next() else {
                panic!("bob: expected confirm ACK wire");
            };
            assert!(it.next().is_none(), "no HandshakeDone before confirm");

            let (_, outs) = alice
                .receive(&sig_b, &mut NoRng)
                .map_err(|e| (e, "alice<-sig"))?;
            let Output::Wire { bytes: ack_a, .. } = &outs[0] else {
                panic!("alice: expected confirm ACK wire");
            };
            assert_eq!(outs.len(), 1, "no HandshakeDone before confirm");

            let (_, outs) = alice
                .receive(&ack_b, &mut NoRng)
                .map_err(|e| (e, "alice<-ack"))?;
            assert!(matches!(outs[0], Output::HandshakeDone));
            let (_, outs) = bob
                .receive(ack_a, &mut NoRng)
                .map_err(|e| (e, "bob<-ack"))?;
            assert!(matches!(outs[0], Output::HandshakeDone));
        }
    }

    Ok((alice, bob, kex_a))
}

/// Hybrid both sides: handshake completes, data round-trips, derived
/// keys agree across roles.
#[test]
fn hybrid_round_trip() {
    let (mut alice, mut bob, kex_a) =
        handshake(SptpsKex::X25519MlKem768, SptpsKex::X25519MlKem768).expect("hybrid handshake");

    assert_eq!(kex_a.len(), 4 + 1 + KEX_LEN_HYBRID);

    let pkt = alice.send_record(0, b"hello quantum").unwrap();
    let (_, outs) = bob.receive(&wire(pkt), &mut NoRng).unwrap();
    assert!(matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"hello quantum"));

    let pkt = bob.send_record(0, b"hello back").unwrap();
    let (_, outs) = alice.receive(&wire(pkt), &mut NoRng).unwrap();
    assert!(matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"hello back"));

    // Explicit key equality pins the role-symmetric `ss_i2r ‖ ss_r2i`
    // ordering: a half-swap (initiator orders one way, responder the
    // other) would pass each side's self-consistency but fail here.
    assert_eq!(alice.outcipher_key(), bob.incipher_key());
    assert_eq!(alice.incipher_key(), bob.outcipher_key());
    assert_ne!(alice.outcipher_key(), alice.incipher_key());
}

/// A MITM who tampers the ML-KEM `ct` (which the Ed25519 signature
/// does *not* cover) must still fail. The signature verifies, but the
/// `ct` is bound into the PRF seed (X-Wing style) AND decapsulation
/// implicit-rejects to a garbage `ss`, so both sides derive divergent
/// keys. The hybrid confirm round then fails its AEAD tag and
/// **`HandshakeDone` never fires on either side** — the daemon never
/// marks the tunnel valid on a tampered handshake.
#[test]
fn tampered_ct_no_handshake_done() {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);
    let mut rng = SeedRng(0xFEED);

    let (mut alice, a0) = Sptps::start_with(
        Role::Initiator,
        Framing::Datagram,
        SptpsKex::X25519MlKem768,
        akey,
        bpub,
        b"mitm",
        16,
        &mut SeedRng(0xA),
    );
    let (mut bob, b0) = Sptps::start_with(
        Role::Responder,
        Framing::Datagram,
        SptpsKex::X25519MlKem768,
        bkey,
        apub,
        b"mitm",
        16,
        &mut SeedRng(0xB),
    );

    let kex_a = wire(a0);
    let kex_b = wire(b0);
    let sig_a = wire(alice.receive(&kex_b, &mut rng).unwrap().1);
    bob.receive(&kex_a, &mut rng).unwrap();
    let (mut sig_b, ack_b) = {
        let (_, outs) = bob.receive(&sig_a, &mut NoRng).unwrap();
        let mut it = outs.into_iter();
        let Some(Output::Wire { bytes: sig, .. }) = it.next() else {
            panic!("expected SIG")
        };
        let Some(Output::Wire { bytes: ack, .. }) = it.next() else {
            panic!("expected confirm ACK")
        };
        assert!(it.next().is_none(), "bob: no HandshakeDone yet");
        (sig, ack)
    };

    // MITM: flip the last `ct` byte (plaintext during initial
    // handshake). Last-byte exercises the well-formed-but-wrong
    // implicit-rejection path rather than any parse short-circuit.
    assert_eq!(sig_b.len(), 4 + 1 + 64 + CT_LEN);
    *sig_b.last_mut().unwrap() ^= 0x01;

    // SIG verifies (doesn't cover ct); tampered ct feeds decap AND the
    // PRF seed hash → divergent keys.
    let (_, outs) = alice
        .receive(&sig_b, &mut NoRng)
        .expect("no panic on bad ct");
    let Output::Wire { bytes: ack_a, .. } = &outs[0] else {
        panic!("expected confirm ACK")
    };
    assert_eq!(outs.len(), 1, "alice: no HandshakeDone on tampered ct");
    // Keys hidden in Confirm; divergence proven by AEAD failure below.
    assert!(alice.outcipher_key().is_none() && bob.outcipher_key().is_none());

    // Confirm round fails AEAD both sides → no HandshakeDone anywhere.
    assert_eq!(
        alice.receive(&ack_b, &mut NoRng).unwrap_err(),
        SptpsError::DecryptFailed,
    );
    assert_eq!(
        bob.receive(ack_a, &mut NoRng).unwrap_err(),
        SptpsError::DecryptFailed,
    );
}

/// KAT: pin the derived traffic key for a fixed-seed hybrid handshake
/// so any change to the KDF input (seed layout, hash binding, secret
/// concat order) is caught. Update deliberately if the KDF changes.
#[test]
fn hybrid_kdf_kat() {
    let (alice, _, _) =
        handshake(SptpsKex::X25519MlKem768, SptpsKex::X25519MlKem768).expect("handshake");
    let out = alice.outcipher_key().unwrap();
    let hex = out.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    assert_eq!(
        hex,
        "97762babaf1f366bf99a574a037286180aaf210bdead8aa592cdc8fff6927a7f\
         21ab78c3f7e00146ddf1dfcc8196c93dfcdeb036d904ff6f5a43489cb2368008",
    );
}

/// Hybrid `force_kex` round-trip: fresh ML-KEM material per rekey,
/// SIG+ACK go out under the *old* cipher (the ordering invariant
/// `receive_sig`'s doc comment is about). A regression here would most
/// likely be a stale `mlkem`/`mlkem_encap` from the previous handshake
/// tripping an `expect`.
#[test]
fn hybrid_rekey() {
    let (mut alice, mut bob, _) =
        handshake(SptpsKex::X25519MlKem768, SptpsKex::X25519MlKem768).unwrap();
    let old_key = alice.outcipher_key();

    let mut rng = SeedRng(0xCAFE);
    let kex_a = wire(alice.force_kex(&mut rng).unwrap());
    let (_, outs) = bob.receive(&kex_a, &mut rng).unwrap();
    let mut it = outs.into_iter();
    let Some(Output::Wire { bytes: kex_b, .. }) = it.next() else {
        panic!("expected KEX")
    };
    assert!(it.next().is_none());
    let (_, outs) = alice.receive(&kex_b, &mut rng).unwrap();
    let sig_a = wire(outs);
    let (_, outs) = bob.receive(&sig_a, &mut rng).unwrap();
    let wires: Vec<_> = outs
        .into_iter()
        .filter_map(|o| match o {
            Output::Wire { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect();
    assert_eq!(wires.len(), 2, "SIG + ACK");
    let (_, outs) = alice.receive(&wires[0], &mut rng).unwrap();
    let ack_a = wire(outs);
    alice.receive(&wires[1], &mut rng).unwrap();
    bob.receive(&ack_a, &mut rng).unwrap();

    assert_ne!(alice.outcipher_key(), old_key, "rekey installed new key");
    assert_eq!(alice.outcipher_key(), bob.incipher_key());

    let pkt = alice.send_record(0, b"after rekey").unwrap();
    let (_, outs) = bob.receive(&wire(pkt), &mut NoRng).unwrap();
    assert!(matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"after rekey"));
}

/// Mismatch: alice hybrid, bob classical. `kex_body_ok` rejects on
/// length; the session never reaches key derivation.
#[test]
fn hybrid_mismatch_clean_error() {
    let Err(err) = handshake(SptpsKex::X25519MlKem768, SptpsKex::X25519) else {
        panic!("mismatch must fail")
    };
    assert_eq!(err, (SptpsError::BadKex, "alice<-kex"));

    let Err(err) = handshake(SptpsKex::X25519, SptpsKex::X25519MlKem768) else {
        panic!("mismatch must fail")
    };
    assert_eq!(err, (SptpsError::BadKex, "alice<-kex"));
}

/// Regression: `start_with(X25519, …)` and `start(…)` produce
/// byte-identical KEX wire output. The `vs_c` harness already pins
/// `start` against C tinc; this pins `start == start_with(default)`.
#[test]
fn default_kex_byte_identical() {
    let (akey, _) = keypair(1);
    let (_, bpub) = keypair(2);

    let (_, a0) = Sptps::start(
        Role::Initiator,
        Framing::Datagram,
        SigningKey::from_blob(&akey.to_blob()),
        bpub,
        b"label",
        16,
        &mut SeedRng(42),
    );
    let (_, a1) = Sptps::start_with(
        Role::Initiator,
        Framing::Datagram,
        SptpsKex::X25519,
        akey,
        bpub,
        b"label",
        16,
        &mut SeedRng(42),
    );
    let w0 = wire(a0);
    assert_eq!(w0, wire(a1));
    assert_eq!(w0.len(), 4 + 1 + KEX_LEN);
}

/// Hybrid record sizes vs the framing/transport caps. The stream
/// `reclen: u16` header trivially covers 1249/1152, but the per-tunnel
/// handshake also rides the meta-protocol as a b64 token bounded by
/// `MAX_STRING = 2048` (`tinc-proto/src/lib.rs`). Compute the worst
/// case here so a future ML-KEM-1024 bump (ek 1568, ct 1568) trips
/// this assertion instead of silently truncating on the wire.
#[test]
fn hybrid_record_sizes_fit_transport() {
    let kex_wire = 4 + 1 + KEX_LEN_HYBRID;
    let sig_wire = 4 + 1 + 64 + CT_LEN;
    // tinc b64: 4 chars per 3 bytes, no padding.
    let b64 = |n: usize| n.div_ceil(3) * 4;
    assert!(
        b64(kex_wire) <= 2048,
        "KEX b64 {} > MAX_STRING",
        b64(kex_wire)
    );
    assert!(
        b64(sig_wire) <= 2048,
        "SIG b64 {} > MAX_STRING",
        b64(sig_wire)
    );
    assert!(u16::try_from(KEX_LEN_HYBRID).is_ok());
}

/// Prints classical vs hybrid handshake wall time so CI logs carry the
/// number. Release on Apple M-series: ~+200 µs.
#[test]
fn handshake_latency_report() {
    const N: u32 = 16;
    let time = |kex| {
        let t = Instant::now();
        for _ in 0..N {
            handshake(kex, kex).unwrap();
        }
        t.elapsed() / N
    };
    let classical = time(SptpsKex::X25519);
    let hybrid = time(SptpsKex::X25519MlKem768);
    eprintln!(
        "SPTPS handshake: classical {classical:?}, hybrid {hybrid:?}, \
         delta +{:?}",
        hybrid.saturating_sub(classical)
    );
    // Sanity ceiling, not a perf gate (debug builds on cold CI).
    assert!(hybrid.as_millis() < 500, "hybrid handshake took {hybrid:?}");
}
