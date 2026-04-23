//! Pre-auth `reclen` clamp. Stream reassembly buffers `reclen` bytes
//! before it can verify anything; until `incipher` is set that length
//! is attacker plaintext. Pin the rejection boundary and that the
//! largest real handshake record (hybrid KEX) still passes.

mod common;

use common::{SeedRng, feed_stream_try, keypair, wire, wire_only};
use tinc_sptps::{
    Framing, KEX_LEN_HYBRID, MAX_PREAUTH_RECLEN, Output, Role, Sptps, SptpsError, SptpsKex,
};

fn fresh() -> Sptps {
    Sptps::start(
        Role::Responder,
        Framing::Stream,
        keypair(1).0,
        keypair(2).1,
        b"reclen".to_vec(),
        0,
        &mut SeedRng(1),
    )
    .0
}

/// `MAX+1` rejected, `MAX` buffered. Without the clamp both would
/// return `Ok(2)`.
#[test]
fn preauth_reclen_boundary() {
    let over = u16::try_from(MAX_PREAUTH_RECLEN + 1).unwrap();
    let err = fresh()
        .receive(&over.to_be_bytes(), &mut SeedRng(0))
        .expect_err("MAX+1 rejected");
    assert_eq!(err, SptpsError::RecordTooLong);

    let at = u16::try_from(MAX_PREAUTH_RECLEN).unwrap();
    let (n, outs) = fresh()
        .receive(&at.to_be_bytes(), &mut SeedRng(0))
        .expect("MAX buffered");
    assert_eq!(n, 2);
    assert!(outs.is_empty());
}

/// Hybrid KEX is the largest legitimate pre-auth record; a full
/// stream-mode handshake reaching `HandshakeDone` proves the clamp
/// admits it.
#[test]
fn hybrid_stream_handshake_passes_clamp() {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);

    let (mut alice, a0) = Sptps::start_with(
        Role::Initiator,
        Framing::Stream,
        SptpsKex::X25519MlKem768,
        akey,
        bpub,
        b"reclen",
        0,
        &mut SeedRng(0xA11CE),
    );
    let (mut bob, b0) = Sptps::start_with(
        Role::Responder,
        Framing::Stream,
        SptpsKex::X25519MlKem768,
        bkey,
        apub,
        b"reclen",
        0,
        &mut SeedRng(0xB0B),
    );

    let kex_a = wire(a0);
    let kex_b = wire(b0);
    // `[len:2][type:1][body]`: confirm the large-record path is hit.
    assert_eq!(kex_a.len(), 2 + 1 + KEX_LEN_HYBRID);

    // Ping-pong all `Wire` outputs (KEX, SIG, then the hybrid key-confirmation
    // ACK round) until both sides emit `HandshakeDone`. Any `RecordTooLong`
    // would surface as an `Err` here.
    let mut to_bob = vec![kex_a];
    let mut to_alice = vec![kex_b];
    let (mut a_done, mut b_done) = (false, false);
    for _ in 0..4 {
        for buf in std::mem::take(&mut to_bob) {
            let outs = feed_stream_try(&mut bob, &buf).expect("bob rx");
            b_done |= outs.iter().any(|o| matches!(o, Output::HandshakeDone));
            to_alice.extend(wire_only(&outs));
        }
        for buf in std::mem::take(&mut to_alice) {
            let outs = feed_stream_try(&mut alice, &buf).expect("alice rx");
            a_done |= outs.iter().any(|o| matches!(o, Output::HandshakeDone));
            to_bob.extend(wire_only(&outs));
        }
        if a_done && b_done {
            return;
        }
    }
    panic!("handshake did not complete");
}
