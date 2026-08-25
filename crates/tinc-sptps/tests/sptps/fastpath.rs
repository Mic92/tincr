//! The zero-alloc data path (`seal_data_into` / `open_data_into`) and
//! the handle-based variants the shards use, checked against the plain
//! `send_record`/`receive` path.

use crate::common::{Pair, SeedRng, wire, wires};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::atomic::Ordering::Relaxed;
use tinc_crypto::chapoly::ChaPoly;
use tinc_sptps::SptpsError;

const HEADROOM: usize = 14;

fn pair() -> (tinc_sptps::Sptps, tinc_sptps::Sptps) {
    Pair::datagram().handshake()
}

#[test]
fn seal_into_open_into_roundtrip() {
    let (mut alice, mut bob) = pair();

    let body = b"the quick brown fox jumps over the lazy dog";
    let mut tx = Vec::new();
    alice.seal_data_into(7, body, &mut tx, 12).unwrap();
    assert_eq!(&tx[..12], &[0u8; 12]);
    assert_eq!(tx.len(), 12 + 4 + 1 + body.len() + 16);

    let mut rx = Vec::new();
    let ty = bob.open_data_into(&tx[12..], &mut rx, 14).unwrap();
    assert_eq!(ty, 7);
    assert_eq!(&rx[..14], &[0u8; 14]);
    assert_eq!(&rx[14..], &body[..]);

    let cap_before = rx.capacity();
    let body2 = b"second";
    let mut tx2 = Vec::new();
    alice.seal_data_into(0, body2, &mut tx2, 12).unwrap();
    let ty = bob.open_data_into(&tx2[12..], &mut rx, 14).unwrap();
    assert_eq!(ty, 0);
    assert_eq!(&rx[14..], &body2[..]);
    assert_eq!(rx.capacity(), cap_before, "rx scratch reallocated");
}

#[test]
fn open_data_into_pre_handshake_is_invalid_state() {
    let mut bob = Pair::datagram().responder();
    let mut rx = Vec::new();
    assert_eq!(
        bob.open_data_into(&[0u8; 32], &mut rx, 0),
        Err(SptpsError::InvalidState)
    );
}

/// On any error `out` must be back to `[0; headroom]`; `BadSeqno`
/// once left the decrypted plaintext in place.
#[test]
fn open_data_into_scrubs_out_on_error() {
    let (mut alice, mut bob) = pair();
    let mut tx = Vec::new();
    alice
        .seal_data_into(7, b"must not survive", &mut tx, 0)
        .unwrap();
    let mut out = Vec::new();
    bob.open_data_into(&tx, &mut out, HEADROOM).unwrap();
    assert_eq!(
        bob.open_data_into(&tx, &mut out, HEADROOM),
        Err(SptpsError::BadSeqno)
    );
    assert_eq!(out, vec![0u8; HEADROOM]);

    let kex = wire(alice.force_kex(&mut SeedRng(0xCC)).unwrap());
    assert_eq!(
        bob.open_data_into(&kex, &mut out, HEADROOM),
        Err(SptpsError::BadRecord)
    );
    assert_eq!(out, vec![0u8; HEADROOM]);

    for len in [0, 4, 20, 64] {
        assert!(
            bob.open_data_into(&vec![0u8; len], &mut out, HEADROOM)
                .is_err()
        );
    }
}

/// `BadRecord` (a handshake record on the fast path) must not advance
/// the replay window: the daemon retries that packet via `receive()`,
/// which would then see a duplicate.
#[test]
fn open_data_into_badrecord_keeps_window() {
    let (mut alice, mut bob) = pair();
    let mut data = Vec::new();
    alice.seal_data_into(0, b"x", &mut data, 0).unwrap();
    let kex = wire(alice.force_kex(&mut SeedRng(0xCC)).unwrap());

    let mut out = Vec::new();
    assert_eq!(
        bob.open_data_into(&kex, &mut out, 0),
        Err(SptpsError::BadRecord)
    );
    bob.open_data_into(&data, &mut out, 0).unwrap();
    let (_, outs) = bob.receive(&kex, &mut SeedRng(0xDD)).unwrap();
    assert_eq!(wires(outs).len(), 1);
}

/// `alloc_seqnos` + `seal_with_seqno` is byte-identical to
/// `seal_data_into` on an identically seeded session.
#[test]
fn alloc_seqnos_seal_with_seqno_byte_identical() {
    let (mut a1, _b1) = pair();
    let (mut a2, _b2) = pair();

    let bodies: [&[u8]; 5] = [
        b"one",
        b"a slightly longer body",
        b"",
        b"three",
        &[0xFF; 1400],
    ];

    let mut ref_wires: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            let mut tx = Vec::new();
            a1.seal_data_into(0, body, &mut tx, 12).unwrap();
            tx
        })
        .collect();

    let n = u32::try_from(bodies.len()).expect("test fixture < u32::MAX");
    let base = a2.alloc_seqnos(n).unwrap();
    let par_wires: Vec<Vec<u8>> = bodies
        .iter()
        .enumerate()
        .map(|(i, body)| {
            let mut tx = Vec::new();
            let seqno = base.wrapping_add(u32::try_from(i).unwrap());
            a2.seal_with_seqno(seqno, 0, body, &mut tx, 12).unwrap();
            tx
        })
        .collect();

    assert_eq!(ref_wires, par_wires);

    // outseqno ended up in the same place.
    let mut tx1 = Vec::new();
    let mut tx2 = Vec::new();
    a1.seal_data_into(0, b"after", &mut tx1, 0).unwrap();
    a2.seal_data_into(0, b"after", &mut tx2, 0).unwrap();
    assert_eq!(tx1, tx2);

    // open_with_seqno keeps the type byte in place.
    let (_a3, mut bob) = pair();
    for body in &bodies {
        let wire = ref_wires.remove(0);
        let mut rx = Vec::new();
        let (seqno, ty) = bob.open_with_seqno(&wire[12..], &mut rx, 14).unwrap();
        assert_eq!(ty, 0);
        bob.replay_check(seqno).unwrap();
        assert_eq!(&rx[..14], &[0u8; 14]);
        assert_eq!(rx[14], ty);
        assert_eq!(&rx[15..], &body[..]);
    }
}

/// What a shard does: seal with only `outseqno_handle()` and
/// `outcipher_key()`, no `Sptps`. Must match `seal_data_into`, and the
/// daemon's own next seal must continue from the shared counter.
#[test]
fn handle_based_seal_byte_identical() {
    let (mut a1, _b1) = pair();
    let (a2, mut b2) = pair();

    let bodies: [&[u8]; 4] = [b"x", b"", &[0xAB; 1400], b"after-handshake"];

    let ref_wires: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            let mut tx = Vec::new();
            a1.seal_data_into(0, body, &mut tx, 12).unwrap();
            tx
        })
        .collect();

    let seqno = a2.outseqno_handle();
    let key = a2.outcipher_key().expect("handshake done");
    let cipher = ChaPoly::new(&key);

    let shard_wires: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            #[expect(clippy::cast_possible_truncation)] // wire is 4-byte BE
            let s = seqno.fetch_add(1, Ordering::Relaxed) as u32;
            let mut tx = Vec::with_capacity(12 + 4 + 1 + body.len() + 16);
            tx.resize(12, 0);
            tx.extend_from_slice(&s.to_be_bytes());
            cipher.seal_into(u64::from(s), 0, body, &mut tx, 12 + 4);
            tx
        })
        .collect();

    assert_eq!(ref_wires, shard_wires);

    {
        let mut a2 = a2; // move into mutable binding for seal_data_into
        let mut tx1 = Vec::new();
        let mut tx2 = Vec::new();
        a1.seal_data_into(0, b"probe", &mut tx1, 0).unwrap();
        a2.seal_data_into(0, b"probe", &mut tx2, 0).unwrap();
        assert_eq!(tx1, tx2, "daemon-side seal sees shard's seqno bumps");
    }

    // Receive side, same idea.
    let in_key = b2.incipher_key().expect("handshake done");
    let in_cipher = ChaPoly::new(&in_key);
    let replay = b2.replay_handle();

    for (wire, body) in ref_wires.iter().zip(&bodies) {
        let ct = &wire[12..]; // strip the 12-byte headroom
        let s = u32::from_be_bytes(ct[..4].try_into().unwrap());
        let pt = in_cipher.open(u64::from(s), &ct[4..]).expect("tag ok");
        replay.lock().unwrap().check_public(s).unwrap();
        assert_eq!(pt[0], 0); // type byte
        assert_eq!(&pt[1..], &body[..]);
    }

    // b2 shares the window the shard advanced.
    let mut rx = Vec::new();
    let err = b2
        .open_data_into(&ref_wires[0][12..], &mut rx, 0)
        .unwrap_err();
    assert_eq!(err, SptpsError::BadSeqno);
}

/// Truncating the `u64` counter at read wraps exactly like the old
/// `u32::wrapping_add`.
#[test]
fn u64_truncate_is_u32_wrap() {
    let a = AtomicU64::new(u64::from(u32::MAX) - 2);
    let mut u: u32 = u32::MAX - 2;

    for _ in 0..5 {
        #[expect(clippy::cast_possible_truncation)]
        let base_a = a.fetch_add(1, Relaxed) as u32;
        let base_u = u;
        u = u.wrapping_add(1);
        assert_eq!(base_a, base_u);
    }

    // Batch allocation after several wraps.
    let a = AtomicU64::new((7_u64 << 32) | u64::from(u));
    #[expect(clippy::cast_possible_truncation)]
    let base_a = a.fetch_add(100, Relaxed) as u32;
    assert_eq!(base_a, u);
    #[expect(clippy::cast_possible_truncation)]
    let next_a = a.load(Relaxed) as u32;
    assert_eq!(next_a, u.wrapping_add(100));
}
