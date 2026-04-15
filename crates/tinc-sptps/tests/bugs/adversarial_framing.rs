//! Adversarial wire input for the SPTPS record layer.
//!
//! `vs_c.rs` and `stream_reassembly.rs` exercise well-formed traffic.
//! This file feeds garbage at three points an attacker controls:
//!
//! 1. **Pre-handshake stream bytes** — anyone who can open a TCP
//!    connection to the daemon can send these (they're plaintext
//!    until the SIG verifies). The state machine MUST return `Err`
//!    on every malformed shape, never panic.
//! 2. **Pre-handshake datagram bytes** — same, for the UDP tunnel
//!    initiation path (REQ_KEY-embedded SPTPS records).
//! 3. **Post-handshake encrypted records** — an authenticated peer
//!    (or a replay/bit-flip on the wire). `DecryptFailed` is the
//!    expected outcome; the test asserts no panic.
//!
//! Everything here is "must not panic, must return a defined
//! `SptpsError`".

use crate::common::{SeedRng, handshake_pair, keypair, wire};
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsError};

/// Fresh stream-mode responder, pre-handshake. The attacker model for
/// "anyone who got past `id_h`": they have a real Ed25519 key on file
/// but haven't proven possession. Everything they send hits
/// `receive_stream` in the plaintext phase.
fn fresh_stream() -> Sptps {
    let (akey, _apub) = keypair(1);
    let (_bkey, bpub) = keypair(2);
    let (s, _init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        akey,
        bpub,
        b"adv".to_vec(),
        0,
        &mut SeedRng(1),
    );
    s
}

fn fresh_datagram() -> Sptps {
    let (akey, _apub) = keypair(1);
    let (_bkey, bpub) = keypair(2);
    let (s, _init) = Sptps::start(
        Role::Responder,
        Framing::Datagram,
        akey,
        bpub,
        b"adv".to_vec(),
        16,
        &mut SeedRng(1),
    );
    s
}

/// Feed `bytes` to a stream session, looping until it errors or
/// drains. Returns the error if any. Panics propagate (that's the
/// failure mode we're hunting).
fn feed_stream_err(s: &mut Sptps, bytes: &[u8]) -> Option<SptpsError> {
    let mut rng = SeedRng(0);
    let mut off = 0;
    while off < bytes.len() {
        match s.receive(&bytes[off..], &mut rng) {
            Ok((0, _)) => return None, // wants more bytes
            Ok((n, _)) => off += n,
            Err(e) => return Some(e),
        }
    }
    None
}

// ────────────────────────────────────────────────────────────────────
// Stream framing, pre-handshake (plaintext).

/// Record type ≥ 129 is reserved (`BadRecord`). Type 0..127 before
/// `instate` is also `BadRecord`. Type 128 with a non-KEX body is
/// `BadKex`. All three must Err cleanly.
#[test]
fn stream_plaintext_bad_record_types() {
    // len=0, type=129. 3 bytes total.
    let mut s = fresh_stream();
    assert_eq!(
        feed_stream_err(&mut s, &[0, 0, 129]),
        Some(SptpsError::BadRecord)
    );

    // len=0, type=0 (app record before handshake).
    let mut s = fresh_stream();
    assert_eq!(
        feed_stream_err(&mut s, &[0, 0, 0]),
        Some(SptpsError::BadRecord)
    );

    // len=1, type=128, body=[0] — wrong KEX length.
    let mut s = fresh_stream();
    assert_eq!(
        feed_stream_err(&mut s, &[0, 1, 128, 0]),
        Some(SptpsError::BadKex)
    );

    // len=65, type=128, body[0]=99 (wrong VERSION byte).
    let mut s = fresh_stream();
    let mut rec = vec![0u8, 65, 128];
    rec.extend_from_slice(&[99; 65]);
    assert_eq!(feed_stream_err(&mut s, &rec), Some(SptpsError::BadKex));
}

/// Oversized length header. `reclen` is u16; the reassembly buffer
/// will try to grow to `reclen + 1` bytes. 64 KiB is fine (Vec can do
/// that); the point is that a *short* input declaring a huge length
/// just buffers and waits — no panic, no eager 64K alloc per packet.
#[test]
fn stream_huge_reclen_short_body() {
    let mut s = fresh_stream();
    // len=0xFFFF, then only 1 byte of body. receive() should consume
    // all 3 bytes and return Ok (waiting for more), not Err, not panic.
    let (n, outs) = s.receive(&[0xFF, 0xFF, 0x80], &mut SeedRng(0)).unwrap();
    assert_eq!(n, 3);
    assert!(outs.is_empty());
    // Session is now mid-record; feeding nothing more is the half-open
    // state the daemon's PingTimeout sweep reaps. No crash.
}

/// Zero-length input is a no-op (consumed=0). Regression guard for an
/// off-by-one in the phase-1 length read.
#[test]
fn stream_empty_input() {
    let mut s = fresh_stream();
    let (n, outs) = s.receive(&[], &mut SeedRng(0)).unwrap();
    assert_eq!(n, 0);
    assert!(outs.is_empty());
}

/// Handshake record arriving in the wrong state. After a valid KEX,
/// state is `Sig`; a second KEX-shaped record is *not* a SIG (wrong
/// length) → `BadSig`, not a panic on the `mykex.expect()`.
#[test]
fn stream_double_kex_is_err() {
    // Get a real KEX from an initiator so the responder advances to Sig.
    let (bkey, bpub) = keypair(2);
    let (_init_s, init_out) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        bkey,
        *keypair(1).0.public_key(),
        b"adv".to_vec(),
        0,
        &mut SeedRng(2),
    );
    let kex = wire(init_out);

    let (akey, _) = keypair(1);
    let (mut resp, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        akey,
        bpub,
        b"adv".to_vec(),
        0,
        &mut SeedRng(1),
    );
    // First KEX: accepted, state → Sig.
    assert_eq!(feed_stream_err(&mut resp, &kex), None);
    // Second identical KEX: receive_handshake is in Sig, hands the
    // 65-byte body to receive_sig → len != 64 → BadSig. Clean Err.
    assert_eq!(feed_stream_err(&mut resp, &kex), Some(SptpsError::BadSig));
}

// ────────────────────────────────────────────────────────────────────
// Datagram framing, pre-handshake (plaintext).

#[test]
fn datagram_short_and_malformed() {
    let mut rng = SeedRng(0);

    // < 5 bytes: BadSeqno ("short packet").
    for len in 0..5 {
        let mut s = fresh_datagram();
        let r = s.receive(&vec![0u8; len], &mut rng);
        assert_eq!(r.unwrap_err(), SptpsError::BadSeqno, "len={len}");
    }

    // seqno != 0 in plaintext phase: BadSeqno.
    let mut s = fresh_datagram();
    assert_eq!(
        s.receive(&[0, 0, 0, 1, 128], &mut rng).unwrap_err(),
        SptpsError::BadSeqno
    );

    // seqno=0, type != HANDSHAKE: BadRecord.
    let mut s = fresh_datagram();
    assert_eq!(
        s.receive(&[0, 0, 0, 0, 0], &mut rng).unwrap_err(),
        SptpsError::BadRecord
    );

    // seqno=0, type=128, empty body: BadKex (len != 65).
    let mut s = fresh_datagram();
    assert_eq!(
        s.receive(&[0, 0, 0, 0, 128], &mut rng).unwrap_err(),
        SptpsError::BadKex
    );
}

// ────────────────────────────────────────────────────────────────────
// Post-handshake: encrypted garbage. An on-path attacker flipping
// bits, or a buggy peer.

#[test]
fn datagram_encrypted_garbage() {
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"adv");
    let mut rng = SeedRng(0);

    // < 21 bytes after handshake: BadSeqno (short).
    for len in [0, 1, 4, 20] {
        let r = bob.receive(&vec![0u8; len], &mut rng);
        assert_eq!(r.unwrap_err(), SptpsError::BadSeqno, "len={len}");
    }

    // 21+ bytes of zeros: tag won't verify → DecryptFailed.
    assert_eq!(
        bob.receive(&[0u8; 64], &mut rng).unwrap_err(),
        SptpsError::DecryptFailed
    );

    // Valid record, one bit flipped in the tag: DecryptFailed.
    let mut flipped = wire(alice.send_record(0, b"hello").unwrap());
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        bob.receive(&flipped, &mut rng).unwrap_err(),
        SptpsError::DecryptFailed
    );

    // Crucially: bob is still usable after all those Errs. A fresh
    // valid record from alice still decrypts. (Datagram Err is
    // per-packet; the doc on `receive` says so — this pins it.)
    let good = wire(alice.send_record(0, b"world").unwrap());
    let (_, outs) = bob.receive(&good, &mut rng).unwrap();
    assert!(matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"world"));
}
