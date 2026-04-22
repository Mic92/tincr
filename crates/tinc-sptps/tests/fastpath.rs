//! Rust↔Rust round-trip tests for the zero-alloc fast-path methods
//! (`seal_data_into` / `open_data_into`). Unlike `vs_c.rs` these don't
//! need the C harness, so they always run.

mod common;

use common::{REPLAYWIN, SeedRng, handshake_pair, keypair};
use tinc_sptps::{Framing, Role, Sptps, SptpsError};

/// `seal_data_into` → `open_data_into` round-trip with nonzero headroom
/// on both sides. Asserts byte equality and that headroom is zero-filled.
#[test]
fn seal_into_open_into_roundtrip() {
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"fast");

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

/// `open_data_into` before handshake completes → `InvalidState` (no incipher).
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

/// `alloc_seqnos(N)` + N×`seal_with_seqno` MUST be byte-identical to
/// N×`seal_data_into`. Same handshake = same key material = same RNG
/// draws; the only difference is who does the `outseqno++`.
#[test]
fn alloc_seqnos_seal_with_seqno_byte_identical() {
    // Two pairs from identical seeds → identical sessions.
    let (mut a1, _b1) = handshake_pair(Framing::Datagram, b"fast");
    let (mut a2, _b2) = handshake_pair(Framing::Datagram, b"fast");

    let bodies: [&[u8]; 5] = [
        b"one",
        b"a slightly longer body",
        b"",
        b"three",
        &[0xFF; 1400],
    ];

    // Ref: 5× the existing fastpath.
    let mut ref_wires: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            let mut tx = Vec::new();
            a1.seal_data_into(0, body, &mut tx, 12).unwrap();
            tx
        })
        .collect();

    // Par-shaped: alloc once, seal with explicit seqnos. `&self`.
    let n = u32::try_from(bodies.len()).expect("test fixture < u32::MAX");
    let base = a2.alloc_seqnos(n);
    let par_wires: Vec<Vec<u8>> = bodies
        .iter()
        .enumerate()
        .map(|(i, body)| {
            let mut tx = Vec::new();
            // i < bodies.len() ≤ n: u32 fits.
            let seqno = base.wrapping_add(u32::try_from(i).unwrap());
            a2.seal_with_seqno(seqno, 0, body, &mut tx, 12).unwrap();
            tx
        })
        .collect();

    assert_eq!(ref_wires, par_wires);

    // outseqno landed in the same place: next packet from each is
    // also byte-identical.
    let mut tx1 = Vec::new();
    let mut tx2 = Vec::new();
    a1.seal_data_into(0, b"after", &mut tx1, 0).unwrap();
    a2.seal_data_into(0, b"after", &mut tx2, 0).unwrap();
    assert_eq!(tx1, tx2);

    // RX side: open_with_seqno + replay_check produces the same body
    // open_data_into would, modulo the type-byte strip.
    let (_a3, mut bob) = handshake_pair(Framing::Datagram, b"fast");
    for body in &bodies {
        let wire = ref_wires.remove(0);
        let mut rx = Vec::new();
        let (seqno, ty) = bob.open_with_seqno(&wire[12..], &mut rx, 14).unwrap();
        assert_eq!(ty, 0);
        bob.replay_check(seqno).unwrap();
        // open_with_seqno leaves the type byte in place.
        assert_eq!(&rx[..14], &[0u8; 14]);
        assert_eq!(rx[14], ty);
        assert_eq!(&rx[15..], &body[..]);
    }
}

/// Handle-based equivalence: `outseqno_handle().fetch_add` +
/// `ChaPoly::new(outcipher_key())` produces the same wire bytes as
/// `seal_data_into`. No `&mut Sptps`, no `&Sptps` either; just an
/// `Arc<AtomicU64>` and a `[u8; 64]` cloned out at handshake time.
///
/// Also proves the `outseqno` continuity claim: after the
/// handle-based seals, `seal_data_into` from the daemon side picks
/// up at the next seqno. The atomic is shared; both views see the
/// same counter.
#[test]
fn handle_based_seal_byte_identical() {
    use std::sync::atomic::Ordering;
    use tinc_crypto::chapoly::ChaPoly;

    let (mut a1, _b1) = handshake_pair(Framing::Datagram, b"fast");
    let (a2, mut b2) = handshake_pair(Framing::Datagram, b"fast");

    let bodies: [&[u8]; 4] = [b"x", b"", &[0xAB; 1400], b"after-handshake"];

    // Ref: daemon's existing path. `&mut Sptps` all the way.
    let ref_wires: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            let mut tx = Vec::new();
            a1.seal_data_into(0, body, &mut tx, 12).unwrap();
            tx
        })
        .collect();

    // Shard shape: clone handles ONCE (at Adopt time), then seal
    // without ever touching `a2` again. `a2` is the daemon's tunnel;
    // these are the shard's local copies.
    let seqno = a2.outseqno_handle();
    let key = a2.outcipher_key().expect("handshake done");
    let cipher = ChaPoly::new(&key);

    let shard_wires: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            // u64 fetch_add, truncate to u32: same as alloc_seqnos's
            // body. Relaxed: nonce uniqueness, not a memory fence.
            #[expect(clippy::cast_possible_truncation)] // wire is 4-byte BE
            let s = seqno.fetch_add(1, Ordering::Relaxed) as u32;
            // Same layout seal_with_seqno builds: headroom + seqno:4
            // + enc(type+body) + tag:16.
            let mut tx = Vec::with_capacity(12 + 4 + 1 + body.len() + 16);
            tx.resize(12, 0);
            tx.extend_from_slice(&s.to_be_bytes());
            cipher.seal_into(u64::from(s), 0, body, &mut tx, 12 + 4);
            tx
        })
        .collect();

    assert_eq!(ref_wires, shard_wires);

    // Continuity: a2's NEXT seal (daemon-side, e.g. a PMTU probe via
    // try_tx) sees the same counter the shard advanced. The Arc IS
    // the storage.
    {
        let mut a2 = a2; // move into mutable binding for seal_data_into
        let mut tx1 = Vec::new();
        let mut tx2 = Vec::new();
        a1.seal_data_into(0, b"probe", &mut tx1, 0).unwrap();
        a2.seal_data_into(0, b"probe", &mut tx2, 0).unwrap();
        assert_eq!(tx1, tx2, "daemon-side seal sees shard's seqno bumps");
    }

    // RX side: same shape. Clone bob's handles, decrypt+replay-check
    // via the cloned mutex without touching `b2`.
    let in_key = b2.incipher_key().expect("handshake done");
    let in_cipher = ChaPoly::new(&in_key);
    let replay = b2.replay_handle();

    for (wire, body) in ref_wires.iter().zip(&bodies) {
        let ct = &wire[12..]; // strip the 12-byte headroom
        let s = u32::from_be_bytes(ct[..4].try_into().unwrap());
        let pt = in_cipher.open(u64::from(s), &ct[4..]).expect("tag ok");
        // Shard locks for ~50ns AFTER the ~4µs decrypt. Same order as
        // open_data_into: a packet that fails decrypt never touches
        // the window.
        replay.lock().unwrap().check_public(s).unwrap();
        assert_eq!(pt[0], 0); // type byte
        assert_eq!(&pt[1..], &body[..]);
    }

    // Continuity, RX: b2's open_data_into sees the same window the
    // shard advanced. Replaying ref_wires[0] is now a duplicate.
    let mut rx = Vec::new();
    let err = b2
        .open_data_into(&ref_wires[0][12..], &mut rx, 0)
        .unwrap_err();
    assert_eq!(err, SptpsError::BadSeqno);
}

/// `u64` truncate-at-read is the same wrap as `u32::wrapping_add`.
/// The wider counter carries high bits the wire never sees; they
/// don't change which 4 bytes go out. This is the property the
/// `outseqno: u32 → Arc<AtomicU64>` change rests on.
#[test]
fn u64_truncate_is_u32_wrap() {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering::Relaxed;

    // Arrange the counter at u32::MAX - 2. After 5 allocs of 1, the
    // u32 wraps; the u64 doesn't. The truncated bases must match.
    let a = AtomicU64::new(u64::from(u32::MAX) - 2);
    let mut u: u32 = u32::MAX - 2;

    for _ in 0..5 {
        #[expect(clippy::cast_possible_truncation)]
        let base_a = a.fetch_add(1, Relaxed) as u32;
        let base_u = u;
        u = u.wrapping_add(1);
        assert_eq!(base_a, base_u);
    }

    // Same for batch alloc: fetch_add(n) base truncated == old u32 base.
    // After 5 single-allocs above, u is at 2 (wrapped). Set a to a
    // post-multiple-wrap value with the same low 32 bits.
    let a = AtomicU64::new((7_u64 << 32) | u64::from(u));
    #[expect(clippy::cast_possible_truncation)]
    let base_a = a.fetch_add(100, Relaxed) as u32;
    assert_eq!(base_a, u);
    #[expect(clippy::cast_possible_truncation)]
    let next_a = a.load(Relaxed) as u32;
    assert_eq!(next_a, u.wrapping_add(100));
}
