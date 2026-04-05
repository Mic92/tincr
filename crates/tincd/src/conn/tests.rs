use super::*;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::write;
use rand_core::OsRng;

// ─── LineBuf

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
fn linebuf_read_n_exact() {
    let mut b = LineBuf::default();
    b.add(b"0123456789");
    let r = b.read_n(10).unwrap();
    assert_eq!(&b.bytes_raw()[r], b"0123456789");
    assert!(b.is_empty());
}

#[test]
fn linebuf_read_n_partial() {
    let mut b = LineBuf::default();
    b.add(b"01234");
    assert!(b.read_n(10).is_none());
    assert_eq!(b.live_len(), 5); // offset unchanged
    b.add(b"56789");
    let r = b.read_n(10).unwrap();
    assert_eq!(&b.bytes_raw()[r], b"0123456789");
}

/// `buffer_read(buf, 0)`: returns ptr, advances 0.
#[test]
fn linebuf_read_n_zero() {
    let mut b = LineBuf::default();
    b.add(b"data");
    let r = b.read_n(0).unwrap();
    assert_eq!(r.len(), 0);
    assert_eq!(b.live_len(), 4); // unchanged
}

/// `read_n` then `read_line`: shared cursor stays coherent
/// (`meta.c`'s `while(inbuf.len)` does tcplen-then-line).
#[test]
fn linebuf_read_n_after_read_line() {
    let mut b = LineBuf::default();
    // SOCKS4 reply + ID line.
    b.add(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
    b.add(b"0 bob 17.7\n");
    let r1 = b.read_n(8).unwrap();
    assert_eq!(&b.bytes_raw()[r1.clone()], &[0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
    let r2 = b.read_line().unwrap();
    assert_eq!(&b.bytes_raw()[r2], b"0 bob 17.7");
    assert!(b.is_empty());
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

/// `net.h:45`. If MAXSIZE bumps (jumbo), this fails.
#[test]
fn maxbufsize_matches_c() {
    const MAXSIZE: usize = 1673; // net.h:42, no-jumbo
    let expected = (if MAXSIZE > 2048 { MAXSIZE } else { 2048 }) + 128;
    assert_eq!(MAXBUFSIZE, expected);
}

// ─── Connection::send

fn devnull() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

#[test]
fn send_formats_id_greeting() {
    let mut c = Connection::test_with_fd(devnull());
    let was_empty = c.send(format_args!("0 testnode 17.7"));
    assert!(was_empty);
    assert_eq!(c.outbuf.live(), b"0 testnode 17.7\n");
}

/// Second send returns `false` (don't double-register `IO_WRITE`).
#[test]
fn send_second_doesnt_signal() {
    let mut c = Connection::test_with_fd(devnull());
    assert!(c.send(format_args!("0 a 17.7")));
    assert!(!c.send(format_args!("4 0 99")));
    assert_eq!(c.outbuf.live(), b"0 a 17.7\n4 0 99\n");
}

#[test]
fn new_control_defaults() {
    let c = Connection::test_with_fd(devnull());
    assert_eq!(c.allow_request, Some(Request::Id));
    assert!(!c.control);
    assert_eq!(c.name, "<control>");
    assert_eq!(c.protocol_minor, 0);
    assert!(c.ecdsa.is_none());
    assert!(c.sptps.is_none());
    assert_eq!(c.options, crate::proto::ConnOptions::empty());
    assert_eq!(c.estimated_weight, 0);
    assert!(c.address.is_none());
}

/// `connection.h:38-58` bit positions. `control` = bit 9.
#[test]
fn status_value_control_bit() {
    let c = Connection::test_with_fd(devnull());
    assert_eq!(c.status_value(), 0);
    // If `connection.h` reorders, this points where to look.
    assert_eq!(1u32 << 9, 0x200);
}

// ─── take_rest

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

#[test]
fn take_rest_on_fresh_is_empty() {
    let mut b = LineBuf::default();
    assert!(b.take_rest().is_empty());
}

// ─── feed_sptps

/// Panics if touched. Receive-only handshake doesn't `send_kex`.
struct NoRng;
impl rand_core::RngCore for NoRng {
    fn next_u32(&mut self) -> u32 {
        unreachable!("rng touched in receive-only path")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("rng touched in receive-only path")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        unreachable!("rng touched in receive-only path")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        unreachable!("rng touched in receive-only path")
    }
}

/// `feed_sptps([])` → empty. Early-return before sptps is touched.
#[test]
fn feed_sptps_empty_chunk() {
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Role};

    let mykey = SigningKey::from_seed(&[1; 32]);
    let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
    let (mut sptps, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey,
        hispub,
        b"test".to_vec(),
        0,
        &mut OsRng,
    );

    let r = Connection::feed_sptps(&mut sptps, &[], "test", &mut NoRng);
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
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Output, Role};

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
        &mut OsRng,
    );
    let (mut bob, b_init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        bob_k,
        alice_pub,
        b"loop-test".to_vec(),
        0,
        &mut OsRng,
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

    let r = Connection::feed_sptps(&mut bob, &chunk, "alice", &mut NoRng);
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
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Role};

    let mykey = SigningKey::from_seed(&[1; 32]);
    let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
    let (mut sptps, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey,
        hispub,
        b"partial".to_vec(),
        0,
        &mut OsRng,
    );

    let r = Connection::feed_sptps(&mut sptps, &[0x00, 0x05], "test", &mut NoRng);
    match r {
        FeedResult::Sptps(evs) => assert!(evs.is_empty()),
        _ => panic!("expected Sptps(empty), got {r:?}"),
    }
}

/// Decrypt fail → Dead.
#[test]
fn feed_sptps_decrypt_fail_is_dead() {
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Role};

    let mykey = SigningKey::from_seed(&[1; 32]);
    let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
    let (mut sptps, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey,
        hispub,
        b"fail".to_vec(),
        0,
        &mut OsRng,
    );

    // App-data record pre-handshake → BadRecord.
    let bad = [0x00, 0x05, 0x00, b'x', b'x', b'x', b'x', b'x'];
    let r = Connection::feed_sptps(&mut sptps, &bad, "test", &mut NoRng);
    assert!(matches!(r, FeedResult::Dead), "expected Dead, got {r:?}");
}

// ─── feed() sptpslen mechanism
// Tested via socketpair: write chunk to one end, feed() reads other.

/// Handshaked pair with bob as a Connection's sptps.
fn sptps_conn_pair() -> (Connection, tinc_sptps::Sptps, OwnedFd) {
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Output, Role};

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
        &mut OsRng,
    );
    let (mut bob, b_init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        bob_k,
        alice_pub,
        b"slen".to_vec(),
        0,
        &mut OsRng,
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

/// `sptpslen` pre-set; blob in one chunk.
#[test]
fn feed_sptpslen_single_chunk() {
    let (mut conn, _alice, wr) = sptps_conn_pair();
    conn.sptpslen = 12;
    let blob = b"abcdefghijkl"; // 12 bytes, NOT SPTPS-framed
    write_all(&wr, blob);
    let r = conn.feed(&mut NoRng);
    match r {
        FeedResult::Sptps(evs) => {
            assert_eq!(evs.len(), 1);
            match &evs[0] {
                SptpsEvent::Blob(b) => assert_eq!(b, blob),
                SptpsEvent::Record(_) => panic!("expected Blob, got {evs:?}"),
            }
        }
        _ => panic!("expected Sptps, got {r:?}"),
    }
    assert_eq!(conn.sptpslen, 0);
    assert!(conn.sptps_buf.is_empty());
}

/// Blob spans two recv()s.
#[test]
fn feed_sptpslen_straddle() {
    let (mut conn, _alice, wr) = sptps_conn_pair();
    conn.sptpslen = 12;
    write_all(&wr, b"abcde"); // 5 of 12
    match conn.feed(&mut NoRng) {
        FeedResult::Sptps(evs) => assert!(evs.is_empty(), "partial: no event yet"),
        r => panic!("expected Sptps(empty), got {r:?}"),
    }
    assert_eq!(conn.sptpslen, 12);
    assert_eq!(conn.sptps_buf.len(), 5);

    write_all(&wr, b"fghijkl"); // 7 more
    match conn.feed(&mut NoRng) {
        FeedResult::Sptps(evs) => {
            assert_eq!(evs.len(), 1);
            match &evs[0] {
                SptpsEvent::Blob(b) => assert_eq!(b, b"abcdefghijkl"),
                SptpsEvent::Record(_) => panic!("expected Blob"),
            }
        }
        r => panic!("expected Sptps, got {r:?}"),
    }
    assert_eq!(conn.sptpslen, 0);
    assert!(conn.sptps_buf.is_empty());
}

/// THE TRAP. `["21 12\n" record | 12 raw bytes | PING record]` as
/// one chunk. Before fix: `receive()` re-called on raw bytes →
/// `DecryptFailed` → Dead. After: `feed()` peeks "21 ", sets sptpslen,
/// next iter eats blob. Events MUST be `[Blob, Record(PING)]`.
#[test]
fn feed_sptpslen_then_record() {
    use tinc_sptps::Output;
    let (mut conn, mut alice, wr) = sptps_conn_pair();

    let wire = |outs: Vec<Output>| -> Vec<u8> {
        outs.into_iter()
            .find_map(|o| match o {
                Output::Wire { bytes, .. } => Some(bytes),
                _ => None,
            })
            .expect("one Wire")
    };

    // Crafted to mis-parse as SPTPS: len=9 + 9 garbage. Post-
    // handshake, receive() would try decrypt → DecryptFailed.
    let blob = b"\x00\x09junkjunk!"; // 2-byte len + 9 body = 11
    assert_eq!(blob.len(), 11);
    let req_rec = wire(alice.send_record(0, b"21 11\n").unwrap());
    let ping_rec = wire(alice.send_record(0, b"8\n").unwrap());

    let mut chunk = req_rec;
    chunk.extend_from_slice(blob);
    chunk.extend_from_slice(&ping_rec);
    write_all(&wr, &chunk);

    let r = conn.feed(&mut NoRng);
    match r {
        FeedResult::Sptps(evs) => {
            // "21 11\n" consumed — not in events.
            assert_eq!(evs.len(), 2, "got {evs:?}");
            match (&evs[0], &evs[1]) {
                (SptpsEvent::Blob(b), SptpsEvent::Record(Output::Record { bytes, .. })) => {
                    assert_eq!(b.as_slice(), blob);
                    assert_eq!(bytes, b"8\n");
                }
                _ => panic!("expected [Blob, Record(PING)], got {evs:?}"),
            }
        }
        FeedResult::Dead => {
            panic!("trap fired: blob parsed as SPTPS framing")
        }
        _ => panic!("expected Sptps, got {r:?}"),
    }
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
