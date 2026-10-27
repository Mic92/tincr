// LineBuf.

use super::*;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::write;
use std::fs::File;
use std::sync::atomic::Ordering;
use tinc_crypto::os_rng;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role};

#[test]
fn linebuf_one_full_line() {
    let mut b = LineBuf::default();
    b.add(b"hello world\n");
    let r = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r], b"hello world");
    // Empty (offset==len) but data not cleared — range still valid.
    assert!(b.is_empty());
    assert_eq!(b.live_len(), 0);
    assert!(b.read_line().is_none());
}

#[test]
fn linebuf_partial_then_complete() {
    let mut b = LineBuf::default();
    b.add(b"hello ");
    assert!(b.read_line().is_none()); // no \n yet
    b.add(b"world\n");
    let r = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r], b"hello world");
}

#[test]
fn linebuf_two_lines_one_feed() {
    let mut b = LineBuf::default();
    b.add(b"first\nsecond\n");
    let r1 = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r1], b"first");
    let r2 = b.read_line().unwrap();
    // Same bytes_raw — no compact between read_line calls.
    assert_eq!(&b.bytes_raw()[r2], b"second");
    assert!(b.is_empty());
}

/// Line then partial: `receive_meta`'s inner loop hits this
/// (recv brings "REQ\nPAR", dispatches REQ, PAR stays buffered).
#[test]
fn linebuf_line_then_partial() {
    let mut b = LineBuf::default();
    b.add(b"full\npartial");
    let r = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r], b"full");
    assert_eq!(b.live_len(), 7);
    assert!(b.read_line().is_none());
    b.add(b" done\n");
    let r2 = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r2], b"partial done");
}

/// `"\n"` alone → zero-length range. C: `atoi("")` → 0,
/// `*request == '0'` is false → "Bogus data".
#[test]
fn linebuf_empty_line() {
    let mut b = LineBuf::default();
    b.add(b"\n");
    let r = b.read_line().unwrap();
    assert_eq!(r.len(), 0);
    assert!(b.is_empty());
}

/// Regression: if `read_line` reset on offset==len, `data.clear()`
/// would dangle the returned range.
#[test]
fn linebuf_range_survives_going_empty() {
    let mut b = LineBuf::default();
    b.add(b"only\n");
    let r = b.read_line().unwrap();
    assert!(b.is_empty());
    assert_eq!(&b.bytes_raw()[r], b"only");
}

#[test]
fn linebuf_consume_partial() {
    let mut b = LineBuf::default();
    b.add(b"0123456789");
    b.consume(3);
    assert_eq!(b.live(), b"3456789");
    assert_eq!(b.live_len(), 7);
    assert!(!b.is_empty());
}

#[test]
fn linebuf_consume_all_resets() {
    let mut b = LineBuf::default();
    b.add(b"hello");
    b.consume(5);
    assert!(b.is_empty());
    assert_eq!(b.live_len(), 0);
    assert_eq!(b.offset, 0);
    assert_eq!(b.data.len(), 0);
}

/// Compact-on-add: drain the consumed region instead of growing.
#[test]
fn linebuf_compact_avoids_realloc() {
    let mut b = LineBuf::default();
    b.add(&[b'x'; 100]);
    let cap = b.data.capacity();
    b.consume(90);
    // Without compact: len 180 > cap 100 → realloc. With: len 90.
    b.add(&[b'y'; 80]);
    assert_eq!(b.live_len(), 90);
    assert_eq!(b.live()[..10], [b'x'; 10]);
    assert_eq!(b.live()[10..], [b'y'; 80]);
    // Best-effort: if Vec's growth policy changes, this tells us.
    assert_eq!(b.data.capacity(), cap, "compact should reuse capacity");
}

/// If MAXSIZE bumps (jumbo), this fails.
#[test]
fn maxbufsize_matches_c() {
    const MAXSIZE: usize = 1673; // no-jumbo
    let expected = (if MAXSIZE > 2048 { MAXSIZE } else { 2048 }) + 128;
    assert_eq!(MAXBUFSIZE, expected);
}

// Connection::send.

fn devnull() -> OwnedFd {
    File::open("/dev/null").unwrap().into()
}

#[test]
fn send_formats_id_greeting() {
    let mut c = Connection::test_with_fd(devnull());
    let was_empty = c.send(format_args!("0 testnode 17.7"));
    assert!(was_empty);
    assert_eq!(c.outbuf.live(), b"0 testnode 17.7\n");
}

#[test]
fn outbuf_hard_cap_marks_dead() {
    let mut c = Connection::test_with_fd(devnull());
    let chunk = "x".repeat(1024);
    let max_iters = OUTBUF_HARD_CAP / 1024 + 16;
    for _ in 0..max_iters {
        if c.dead {
            break;
        }
        c.send(format_args!("{chunk}"));
    }
    assert!(c.dead, "cap not tripped within {max_iters} sends");
    assert!(c.outbuf.live_len() <= OUTBUF_HARD_CAP);

    let before = c.outbuf.live_len();
    assert!(!c.send(format_args!("ignored")));
    assert!(!c.send_raw(b"also ignored"));
    assert_eq!(c.outbuf.live_len(), before);
}

/// Second send returns `false` (don't double-register `IO_WRITE`).
#[test]
fn send_second_doesnt_signal() {
    let mut c = Connection::test_with_fd(devnull());
    assert!(c.send(format_args!("0 a 17.7")));
    assert!(!c.send(format_args!("4 0 99")));
    assert_eq!(c.outbuf.live(), b"0 a 17.7\n4 0 99\n");
}

// take_rest.

/// Piggyback: ID line + SPTPS bytes in one buffer.
#[test]
fn take_rest_after_read_line() {
    let mut b = LineBuf::default();
    b.add(b"0 alice 17.7\n\x00\x42garbage");

    let r = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r], b"0 alice 17.7");

    let rest = b.take_rest();
    assert_eq!(rest, b"\x00\x42garbage");
    assert!(b.is_empty());
    assert_eq!(b.live_len(), 0);
    // Cleared state is reusable.
    b.add(b"x\n");
    let r = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r], b"x");
}

/// Common case: ID line was the whole recv.
#[test]
fn take_rest_empty_after_full_line() {
    let mut b = LineBuf::default();
    b.add(b"0 alice 17.7\n");
    let r = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r], b"0 alice 17.7");
    assert!(b.is_empty());
    assert!(b.take_rest().is_empty());
}

// feed_bytes in SPTPS mode.

fn with_sptps(sptps: Sptps) -> Connection {
    let mut c = Connection::test_with_fd(devnull());
    c.sptps = Some(Box::new(sptps));
    c
}

/// Panics if touched. Receive-only handshake doesn't `send_kex`.
struct NoRng;
impl rand_core::TryCryptoRng for NoRng {}
impl rand_core::TryRng for NoRng {
    type Error = rand_core::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("rng touched in receive-only path")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("rng touched in receive-only path")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        unreachable!("rng touched in receive-only path")
    }
}

/// Empty chunk → no events. Early-return before sptps is touched.
#[test]
fn feed_sptps_empty_chunk() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
    let (sptps, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey,
        hispub,
        b"test".to_vec(),
        0,
        &mut os_rng(),
    );

    let r = with_sptps(sptps).feed_bytes(&[], &mut NoRng);
    match r {
        FeedResult::Sptps(evs) => assert!(evs.is_empty()),
        _ => panic!("expected Sptps(empty), got {r:?}"),
    }
    // NoRng not panicked → sptps.receive not called.
}

/// Two records in one chunk → both processed (do-while). Single
/// `receive()` call would strand the second.
#[test]
fn feed_sptps_two_records_one_chunk() {
    let alice_k = SigningKey::from_seed(&[10; 32]);
    let bob_k = SigningKey::from_seed(&[20; 32]);
    let alice_pub = *alice_k.public_key();
    let bob_pub = *bob_k.public_key();

    let (mut alice, a_init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        alice_k,
        bob_pub,
        b"loop-test".to_vec(),
        0,
        &mut os_rng(),
    );
    let (mut bob, b_init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        bob_k,
        alice_pub,
        b"loop-test".to_vec(),
        0,
        &mut os_rng(),
    );

    let wire = |outs: Vec<Output>| -> Vec<u8> {
        outs.into_iter()
            .find_map(|o| match o {
                Output::Wire { bytes, .. } => Some(bytes),
                _ => None,
            })
            .expect("one Wire output")
    };

    let a_kex = wire(a_init);
    let b_kex = wire(b_init);

    let (n, outs) = alice.receive(&b_kex, &mut NoRng).unwrap();
    assert_eq!(n, b_kex.len());
    let a_sig = wire(outs);

    let (n, outs) = bob.receive(&a_kex, &mut NoRng).unwrap();
    assert_eq!(n, a_kex.len());
    assert!(outs.is_empty());

    let (n, outs) = bob.receive(&a_sig, &mut NoRng).unwrap();
    assert_eq!(n, a_sig.len());
    assert_eq!(outs.len(), 2);
    let b_sig = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    assert!(matches!(outs[1], Output::HandshakeDone));

    let (n, outs) = alice.receive(&b_sig, &mut NoRng).unwrap();
    assert_eq!(n, b_sig.len());
    assert!(matches!(outs[0], Output::HandshakeDone));

    // Both done. Glue two records: the coalesced segment.
    let rec1 = wire(alice.send_record(0, b"first").unwrap());
    let rec2 = wire(alice.send_record(0, b"second").unwrap());
    let mut chunk = rec1;
    chunk.extend_from_slice(&rec2);

    let r = with_sptps(bob).feed_bytes(&chunk, &mut NoRng);
    match r {
        FeedResult::Sptps(evs) => {
            assert_eq!(evs.len(), 2, "loop must process both records");
            match (&evs[0], &evs[1]) {
                (
                    SptpsEvent::Record(Output::Record { bytes: b0, .. }),
                    SptpsEvent::Record(Output::Record { bytes: b1, .. }),
                ) => {
                    assert_eq!(b0, b"first");
                    assert_eq!(b1, b"second");
                }
                _ => panic!("expected two Records, got {evs:?}"),
            }
        }
        _ => panic!("expected Sptps(..), got {r:?}"),
    }
}

/// Partial record: length header only. `receive()` returns
/// `(2, [])`; loop terminates (no spin).
#[test]
fn feed_sptps_partial_record() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
    let (sptps, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey,
        hispub,
        b"partial".to_vec(),
        0,
        &mut os_rng(),
    );

    let r = with_sptps(sptps).feed_bytes(&[0x00, 0x05], &mut NoRng);
    match r {
        FeedResult::Sptps(evs) => assert!(evs.is_empty()),
        _ => panic!("expected Sptps(empty), got {r:?}"),
    }
}

/// Decrypt fail → Dead.
#[test]
fn feed_sptps_decrypt_fail_is_dead() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
    let (sptps, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey,
        hispub,
        b"fail".to_vec(),
        0,
        &mut os_rng(),
    );

    // App-data record pre-handshake → BadRecord.
    let bad = [0x00, 0x05, 0x00, b'x', b'x', b'x', b'x', b'x'];
    let r = with_sptps(sptps).feed_bytes(&bad, &mut NoRng);
    assert!(matches!(r, FeedResult::Dead), "expected Dead, got {r:?}");
}

// feed() blob framing.
// Tested via socketpair: write chunk to one end, feed() reads other.

/// Handshaked pair with bob as a Connection's sptps.
fn sptps_conn_pair() -> (Connection, tinc_sptps::Sptps, OwnedFd) {
    let alice_k = SigningKey::from_seed(&[10; 32]);
    let bob_k = SigningKey::from_seed(&[20; 32]);
    let alice_pub = *alice_k.public_key();
    let bob_pub = *bob_k.public_key();

    let (mut alice, a_init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        alice_k,
        bob_pub,
        b"slen".to_vec(),
        0,
        &mut os_rng(),
    );
    let (mut bob, b_init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        bob_k,
        alice_pub,
        b"slen".to_vec(),
        0,
        &mut os_rng(),
    );

    let wire = |outs: Vec<Output>| -> Vec<u8> {
        outs.into_iter()
            .find_map(|o| match o {
                Output::Wire { bytes, .. } => Some(bytes),
                _ => None,
            })
            .expect("one Wire")
    };
    let a_kex = wire(a_init);
    let b_kex = wire(b_init);
    let (_, outs) = alice.receive(&b_kex, &mut NoRng).unwrap();
    let a_sig = wire(outs);
    let (_, outs) = bob.receive(&a_kex, &mut NoRng).unwrap();
    assert!(outs.is_empty());
    let (_, outs) = bob.receive(&a_sig, &mut NoRng).unwrap();
    let b_sig = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    let (_, _) = alice.receive(&b_sig, &mut NoRng).unwrap();

    let (rd, wr) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .expect("socketpair");

    let mut conn = Connection::test_with_fd(rd);
    conn.sptps = Some(Box::new(bob));
    (conn, alice, wr)
}

fn write_all(fd: &OwnedFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        let n = write(fd, buf).expect("write");
        assert!(n > 0, "write: short");
        buf = &buf[n..];
    }
}

/// Blob expected; it arrives in one chunk.
#[test]
fn feed_sptpslen_single_chunk() {
    let (mut conn, _alice, wr) = sptps_conn_pair();
    conn.expect = Expect::Blob(12, Vec::new());
    let blob = b"abcdefghijkl"; // 12 bytes, not SPTPS-framed
    write_all(&wr, blob);
    let r = conn.feed(&mut NoRng);
    match r {
        FeedResult::Sptps(evs) => {
            assert_eq!(evs.len(), 1);
            match &evs[0] {
                SptpsEvent::Blob(b) => assert_eq!(b, blob),
                _ => panic!("expected Blob, got {evs:?}"),
            }
        }
        _ => panic!("expected Sptps, got {r:?}"),
    }
    assert!(matches!(conn.expect, Expect::Request));
}

/// Blob spans two recv()s.
#[test]
fn feed_sptpslen_straddle() {
    let (mut conn, _alice, wr) = sptps_conn_pair();
    conn.expect = Expect::Blob(12, Vec::new());
    write_all(&wr, b"abcde"); // 5 of 12
    match conn.feed(&mut NoRng) {
        FeedResult::Sptps(evs) => assert!(evs.is_empty(), "partial: no event yet"),
        r => panic!("expected Sptps(empty), got {r:?}"),
    }
    assert!(matches!(&conn.expect, Expect::Blob(12, b) if b.len() == 5));

    write_all(&wr, b"fghijkl"); // 7 more
    match conn.feed(&mut NoRng) {
        FeedResult::Sptps(evs) => {
            assert_eq!(evs.len(), 1);
            match &evs[0] {
                SptpsEvent::Blob(b) => assert_eq!(b, b"abcdefghijkl"),
                _ => panic!("expected Blob"),
            }
        }
        r => panic!("expected Sptps, got {r:?}"),
    }
    assert!(matches!(conn.expect, Expect::Request));
}

/// `[17 6 | frame | 21 11 | 11 raw bytes | PING]` in one chunk. The raw
/// bytes look like a record and the frame looks like `21 9`, but neither
/// may be parsed as what it resembles.
#[test]
fn feed_packet_and_blob_framing() {
    let (mut conn, mut alice, wr) = sptps_conn_pair();
    conn.allow_request = None; // peek is gated to post-ACK

    let mut rec = |body: &[u8]| -> Vec<u8> {
        alice
            .send_record(0, body)
            .unwrap()
            .into_iter()
            .find_map(|o| match o {
                Output::Wire { bytes, .. } => Some(bytes),
                _ => None,
            })
            .expect("one Wire")
    };
    let frame = b"21 9 x";
    let blob = b"\x00\x09junkjunk!";
    let mut chunk = rec(b"17 6\n");
    chunk.extend(rec(frame));
    chunk.extend(rec(b"21 11\n"));
    chunk.extend_from_slice(blob);
    chunk.extend(rec(b"8\n"));
    write_all(&wr, &chunk);

    let FeedResult::Sptps(evs) = conn.feed(&mut NoRng) else {
        panic!("framing desynced");
    };
    match &evs[..] {
        [
            SptpsEvent::Packet(p),
            SptpsEvent::Blob(b),
            SptpsEvent::Record(Output::Record { bytes, .. }),
        ] => {
            assert_eq!(p, frame);
            assert_eq!(b, blob);
            assert_eq!(bytes, b"8\n");
        }
        _ => panic!("got {evs:?}"),
    }
}

/// Requests over C's `MAXBUFSIZE` kill the sender's conn on receive.
/// A send that SPTPS can't seal kills ours instead of the daemon.
#[test]
fn oversize_request_is_dead() {
    let (mut conn, mut alice, wr) = sptps_conn_pair();
    let big = vec![b'x'; MAXBUFSIZE + 1];
    for o in alice.send_record(0, &big).unwrap() {
        if let Output::Wire { bytes, .. } = o {
            write_all(&wr, &bytes);
        }
    }
    // The record spans several reads.
    let dead = (0..4).any(|_| matches!(conn.feed(&mut NoRng), FeedResult::Dead));
    assert!(dead);

    let (mut conn, _alice, _wr) = sptps_conn_pair();
    let line = "x".repeat(usize::from(u16::MAX));
    assert!(!conn.send(format_args!("{line}")));
    assert!(conn.dead);
}

/// Sending past the rekey threshold starts an in-band KEX.
#[test]
fn send_rekeys_meta_sptps() {
    let (mut conn, _alice, _wr) = sptps_conn_pair();
    let sptps = conn.sptps.as_deref_mut().unwrap();
    let due = sptps.out_key_base() + tinc_sptps::SEAL_REKEY_THRESHOLD;
    sptps.outseqno_handle().store(due, Ordering::Relaxed);
    assert!(conn.send(format_args!("8")));
    let sptps = conn.sptps.as_deref_mut().unwrap();
    assert!(
        sptps.force_kex(&mut os_rng()).is_err(),
        "KEX already in flight"
    );
}

/// A queue that keeps draining is not stalled, however full.
#[test]
fn flush_stalled_tracks_progress() {
    let mut c = Connection::test_with_fd(devnull());
    let t0 = Instant::now();
    let s = Duration::from_secs;
    assert_eq!(c.flush_stalled(t0 + s(5)), s(0), "empty");
    c.send_raw(&[0; 64]);
    assert_eq!(c.flush_stalled(t0 + s(10)), s(5));
    c.outbuf.consume(1);
    assert_eq!(c.flush_stalled(t0 + s(20)), s(0), "drained a byte");
    assert_eq!(c.flush_stalled(t0 + s(90)), s(70));
}

/// No `\n` appended; 0x0a mid-body left alone.
#[test]
fn send_raw_no_newline() {
    let mut c = Connection::test_with_fd(devnull());
    let bytes = &[0x00, 0x05, 0x0a, 0xde, 0xad, 0xbe, 0xef];
    let signal = c.send_raw(bytes);
    assert!(signal);
    assert_eq!(c.outbuf.live(), bytes);
}
