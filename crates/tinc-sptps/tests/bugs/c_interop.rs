//! C-interop bug hunt: scenarios `vs_c.rs` doesn't cover.

use tinc_crypto::sign::SigningKey;
use tinc_ffi::{CKey, CSptps, Event, seed_rng, serial_guard};
use tinc_sptps::{Framing, Output, Role, Sptps};

use crate::common::SeedRng;

const REPLAYWIN: usize = 16;

fn keypair(tag: u8) -> ([u8; 96], [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    let sk = SigningKey::from_seed(&seed);
    let pk = *sk.public_key();
    (sk.to_blob(), pk)
}

fn ev2out(e: Event) -> Output {
    match e {
        Event::Wire { record_type, bytes } => Output::Wire { record_type, bytes },
        Event::Record { record_type, bytes } => Output::Record { record_type, bytes },
        Event::HandshakeDone => Output::HandshakeDone,
    }
}

fn evs2outs(es: Vec<Event>) -> Vec<Output> {
    es.into_iter().map(ev2out).collect()
}

fn wire1(mut outs: Vec<Output>) -> Vec<u8> {
    assert_eq!(outs.len(), 1, "expected one Wire, got {outs:?}");
    match outs.remove(0) {
        Output::Wire { bytes, .. } => bytes,
        o => panic!("expected Wire, got {o:?}"),
    }
}

fn wires(outs: Vec<Output>) -> Vec<Vec<u8>> {
    outs.into_iter()
        .filter_map(|o| match o {
            Output::Wire { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect()
}

/// Build a datagram-mode Rust-initiator ↔ C-responder pair, run the
/// initial handshake.
fn handshake_dgram_rust_init_c_resp() -> (Sptps, CSptps<'static>, SeedRng) {
    let (a_priv, a_pub) = keypair(1);
    let (b_priv, b_pub) = keypair(2);

    let mut rng = SeedRng(0xAA);
    let a_key = SigningKey::from_blob(&a_priv);
    let (mut alice, outs) = Sptps::start(
        Role::Initiator,
        Framing::Datagram,
        a_key,
        b_pub,
        b"dgram-rekey".to_vec(),
        REPLAYWIN,
        &mut rng,
    );
    let kex_a = wire1(outs);

    let b_mykey: &'static CKey = Box::leak(Box::new(CKey::from_private_blob(&b_priv)));
    let b_hiskey: &'static CKey = Box::leak(Box::new(CKey::from_public(&a_pub)));
    seed_rng(&[0xBB; 32]);
    let (mut bob, evs) = CSptps::start(
        tinc_ffi::Role::Responder,
        tinc_ffi::Framing::Datagram,
        b_mykey,
        b_hiskey,
        b"dgram-rekey",
    );
    let kex_b = wire1(evs2outs(evs));

    let sig_a = wire1(alice.receive(&kex_b, &mut rng).unwrap().1);
    let (_, e) = bob.receive(&kex_a);
    assert!(e.is_empty());
    let (_, e) = bob.receive(&sig_a);
    let o = evs2outs(e);
    assert_eq!(o.len(), 2);
    let sig_b = match &o[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        x => panic!("{x:?}"),
    };
    assert_eq!(o[1], Output::HandshakeDone);
    let (_, o) = alice.receive(&sig_b, &mut rng).unwrap();
    assert_eq!(o, vec![Output::HandshakeDone]);

    (alice, bob, rng)
}

/// Run the in-band rekey to completion on a datagram pair (Rust drives).
#[expect(clippy::similar_names)] // kex_a2/kex_b2, sig_a2/sig_b2: peer-A vs peer-B
fn dgram_rekey(alice: &mut Sptps, bob: &mut CSptps<'_>, rng: &mut SeedRng) {
    let kex_a2 = wire1(alice.force_kex(rng).unwrap());
    seed_rng(&[0xCC; 32]);
    let (n, e) = bob.receive(&kex_a2);
    assert_eq!(n, kex_a2.len(), "C couldn't decrypt rekey-KEX");
    let kex_b2 = wire1(evs2outs(e));

    let sig_a2 = wire1(alice.receive(&kex_b2, rng).unwrap().1);
    let (n, e) = bob.receive(&sig_a2);
    assert_eq!(n, sig_a2.len(), "C rejected rekey-SIG");
    let o = wires(evs2outs(e));
    assert_eq!(o.len(), 2, "C should emit SIG+ACK");
    let (sig_b2, ack_b) = (o[0].clone(), o[1].clone());

    let ack_a = wire1(alice.receive(&sig_b2, rng).unwrap().1);
    let (_, e) = bob.receive(&ack_a);
    assert_eq!(evs2outs(e), vec![Output::HandshakeDone]);
    let (_, o) = alice.receive(&ack_b, rng).unwrap();
    assert_eq!(o, vec![Output::HandshakeDone]);
}

// ────────────────────────────────────────────────────────────────────

/// In-band rekey on a **datagram** session, Rust ↔ C.
///
/// `state.rs::receive_sig` resets `outseqno` to 0 on datagram rekey
/// ("fresh seqno space so the wire-u32 can never wrap"); `receive_ack`
/// resets the replay window. C `sptps.c` does **neither** — `outseqno`
/// and `inseqno` are session-monotone.
///
/// After the rekey completes, Rust emits app records at wire-seqno
/// 0,1,2,… . The C side's `sptps_check_seqno` still has `inseqno` ≈ 5
/// from the handshake traffic, so seqno 0 is rejected as "late or
/// replayed". With pre-rekey app traffic the gap is wider and the
/// reject is permanent (`seqno < inseqno - replaywin*8`).
///
/// This is the path C tincd actually exercises: `protocol_key.c`'s
/// `send_key_changed()` calls `sptps_force_kex(&n->sptps)` on every
/// reachable SPTPS node — those are datagram sessions. A Rust peer
/// answering that rekey will black-hole its own outbound traffic.
#[test]
#[ignore = "bug: datagram in-band rekey resets seqno/replay; C tinc keeps them monotone → C rejects post-rekey Rust→C traffic as replayed"]
fn datagram_rekey_rust_to_c_post_rekey_traffic() {
    let _g = serial_guard();
    let (mut alice, mut bob, mut rng) = handshake_dgram_rust_init_c_resp();

    // Some pre-rekey traffic so C's inseqno is well past 0.
    for i in 0u8..8 {
        let ct = wire1(alice.send_record(0, &[i]).unwrap());
        let (_, e) = bob.receive(&ct);
        assert_eq!(
            evs2outs(e),
            vec![Output::Record {
                record_type: 0,
                bytes: vec![i]
            }]
        );
    }

    dgram_rekey(&mut alice, &mut bob, &mut rng);

    // Post-rekey: Rust sends at seqno 0. C must accept it.
    let ct = wire1(alice.send_record(0, b"after rekey").unwrap());
    assert_eq!(
        u32::from_be_bytes(ct[0..4].try_into().unwrap()),
        0,
        "Rust did not reset outseqno (test premise broken)"
    );
    let (n, e) = bob.receive(&ct);
    assert_eq!(
        n,
        ct.len(),
        "C dropped post-rekey datagram (sptps_check_seqno rejected seqno 0)"
    );
    assert_eq!(
        evs2outs(e),
        vec![Output::Record {
            record_type: 0,
            bytes: b"after rekey".to_vec()
        }],
        "C did not deliver post-rekey app record"
    );
}

/// Mirror direction: after datagram rekey, C → Rust traffic.
///
/// C keeps its `outseqno` monotone, so the first post-rekey record
/// arrives at wire-seqno ≈ 13 (2 handshake + 8 app + 3 rekey records).
/// Rust's `receive_ack` reset the replay window to `inseqno = 0`, so
/// seqno 13 is "far future" (`>= 0 + win*8` is false for win=16, but
/// the gap-mark loop runs 0..13). With more pre-rekey traffic the
/// seqno lands ≥ 128 and Rust's far-future drop fires for the first
/// `replaywin/4 = 4` packets.
#[test]
#[ignore = "bug: datagram in-band rekey resets replay window; C tinc keeps outseqno monotone → Rust drops first post-rekey C→Rust packets as far-future"]
fn datagram_rekey_c_to_rust_post_rekey_traffic() {
    let _g = serial_guard();
    let (mut alice, mut bob, mut rng) = handshake_dgram_rust_init_c_resp();

    // Push C's outseqno past replaywin*8 = 128 so Rust's reset window
    // sees the first post-rekey packet as far-future, not just a gap.
    for i in 0u8..200 {
        let ct = wire1(evs2outs(bob.send_record(0, &[i])));
        let (_, o) = alice.receive(&ct, &mut rng).unwrap();
        assert_eq!(
            o,
            vec![Output::Record {
                record_type: 0,
                bytes: vec![i]
            }]
        );
    }

    dgram_rekey(&mut alice, &mut bob, &mut rng);

    // Post-rekey: C sends at seqno ≈ 205. Rust must accept it.
    let ct = wire1(evs2outs(bob.send_record(0, b"from c after rekey")));
    let seqno = u32::from_be_bytes(ct[0..4].try_into().unwrap());
    assert!(seqno > 128, "C outseqno should be monotone, got {seqno}");

    let res = alice.receive(&ct, &mut rng);
    match res {
        Ok((_, o)) => assert_eq!(
            o,
            vec![Output::Record {
                record_type: 0,
                bytes: b"from c after rekey".to_vec()
            }]
        ),
        Err(e) => panic!(
            "Rust rejected post-rekey datagram from C (wire seqno {seqno}, replay window reset to 0): {e:?}"
        ),
    }
}
