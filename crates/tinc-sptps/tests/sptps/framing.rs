//! Malformed wire input at the three points an attacker controls:
//! pre-handshake stream bytes (anyone who can open a TCP connection),
//! pre-handshake datagrams, and post-handshake encrypted records (an
//! authenticated peer, or bit flips on the path). Everything must be a
//! defined `SptpsError`, never a panic, and datagram errors must not
//! poison the session.

use crate::common::{Pair, SeedRng, feed, keypair, record, wire, wires};
use tinc_sptps::{Framing, KEX_LEN_HYBRID, MAX_PREAUTH_RECLEN, Role, Sptps, SptpsError, SptpsKex};

fn stream_responder() -> Sptps {
    Pair::stream().responder()
}

fn datagram_responder() -> Sptps {
    Pair::datagram().responder()
}

/// Type ≥ 129 is reserved, an app record before the handshake is out
/// of order, and type 128 with a non-KEX body is a bad KEX.
#[test]
fn stream_plaintext_bad_record_types() {
    let cases: [(&[u8], SptpsError); 3] = [
        (&[0, 0, 129], SptpsError::BadRecord),
        (&[0, 0, 0], SptpsError::BadRecord),
        (&[0, 1, 128, 0], SptpsError::BadKex),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            feed(&mut stream_responder(), bytes),
            Err(expected),
            "{bytes:?}"
        );
    }
    // Right length, wrong VERSION byte.
    let mut record = vec![0u8, 65, 128];
    record.extend_from_slice(&[99; 65]);
    assert_eq!(
        feed(&mut stream_responder(), &record),
        Err(SptpsError::BadKex)
    );
}

/// Until `incipher` is set, `reclen` is attacker plaintext and would
/// otherwise be buffered up to 64 KiB. `MAX` is accepted, `MAX + 1`
/// and `0xFFFF` are not.
#[test]
fn stream_preauth_reclen_clamp() {
    let over = u16::try_from(MAX_PREAUTH_RECLEN + 1).unwrap();
    assert_eq!(
        stream_responder().receive(&over.to_be_bytes(), &mut SeedRng(0)),
        Err(SptpsError::RecordTooLong)
    );
    assert_eq!(
        stream_responder().receive(&[0xFF, 0xFF, 0x80], &mut SeedRng(0)),
        Err(SptpsError::RecordTooLong)
    );
    let at = u16::try_from(MAX_PREAUTH_RECLEN).unwrap();
    let (taken, outs) = stream_responder()
        .receive(&at.to_be_bytes(), &mut SeedRng(0))
        .unwrap();
    assert_eq!(taken, 2);
    assert!(outs.is_empty());
}

/// Hybrid KEX is the largest legitimate pre-auth record; the clamp
/// must admit it in stream mode.
#[test]
fn stream_hybrid_kex_passes_clamp() {
    let pair = Pair::stream().kex(SptpsKex::X25519MlKem768);
    let (_, _, alice_kex, _) = pair.start();
    assert_eq!(alice_kex.len(), 2 + 1 + KEX_LEN_HYBRID);
    pair.handshake();
}

#[test]
fn stream_empty_input_is_noop() {
    let (taken, outs) = stream_responder().receive(&[], &mut SeedRng(0)).unwrap();
    assert_eq!(taken, 0);
    assert!(outs.is_empty());
}

/// After a valid KEX the responder expects a SIG; a second KEX has the
/// wrong length for that and must be an error, not a panic on the
/// already-consumed `mykex`.
#[test]
fn stream_double_kex_is_err() {
    let (bob_key, bob_pub) = keypair(2);
    let (_, initiator_out) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        bob_key,
        keypair(1).1,
        b"test".to_vec(),
        0,
        &mut SeedRng(2),
    );
    let kex = wire(initiator_out);
    let (alice_key, _) = keypair(1);
    let (mut responder, _) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        alice_key,
        bob_pub,
        b"test".to_vec(),
        0,
        &mut SeedRng(1),
    );
    feed(&mut responder, &kex).unwrap();
    assert_eq!(feed(&mut responder, &kex), Err(SptpsError::BadSig));
}

/// `send_record` used to panic on bodies over `u16::MAX` in stream
/// mode (C silently truncates the length, desyncing the peer). The
/// gate must fire before `outseqno` is bumped.
#[test]
fn stream_send_record_length_cap() {
    let (mut alice, _bob) = Pair::stream().handshake();
    let bytes = wire(alice.send_record(0, &vec![0x42; 65535]).unwrap());
    assert_eq!(bytes.len(), 2 + 1 + 65535 + 16);
    assert_eq!(&bytes[..2], &[0xFF, 0xFF]);
    assert_eq!(
        alice.send_record(0, &vec![0; 65536]),
        Err(SptpsError::InvalidState)
    );
    alice.send_record(0, b"after").unwrap();

    // Datagram framing has no length header, so no cap.
    let (mut alice, _bob) = Pair::datagram().handshake();
    alice.send_record(0, &vec![0; 70000]).unwrap();
}

#[test]
fn datagram_plaintext_malformed() {
    let mut rng = SeedRng(0);
    for len in 0..5 {
        assert_eq!(
            datagram_responder().receive(&vec![0u8; len], &mut rng),
            Err(SptpsError::BadSeqno),
            "{len} bytes"
        );
    }
    let cases: [(&[u8], SptpsError); 3] = [
        // seqno must be 0 before the handshake
        (&[0, 0, 0, 1, 128], SptpsError::BadSeqno),
        // type must be HANDSHAKE
        (&[0, 0, 0, 0, 0], SptpsError::BadRecord),
        // empty KEX body
        (&[0, 0, 0, 0, 128], SptpsError::BadKex),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            datagram_responder().receive(bytes, &mut rng),
            Err(expected),
            "{bytes:?}"
        );
    }
}

/// Short, all-zero and bit-flipped records after the handshake; bob
/// must still decrypt a good record afterwards (datagram errors are
/// per packet).
#[test]
fn datagram_encrypted_garbage() {
    let (mut alice, mut bob) = Pair::datagram().handshake();
    let mut rng = SeedRng(0);

    for len in [0, 1, 4, 20] {
        assert_eq!(
            bob.receive(&vec![0u8; len], &mut rng),
            Err(SptpsError::BadSeqno),
            "{len} bytes"
        );
    }
    assert_eq!(
        bob.receive(&[0u8; 64], &mut rng),
        Err(SptpsError::DecryptFailed)
    );
    let mut flipped = wire(alice.send_record(0, b"hello").unwrap());
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(
        bob.receive(&flipped, &mut rng),
        Err(SptpsError::DecryptFailed)
    );

    let good = wire(alice.send_record(0, b"world").unwrap());
    let (_, outs) = bob.receive(&good, &mut rng).unwrap();
    assert_eq!(record(outs), (0, b"world".to_vec()));
}

/// A malformed *encrypted* handshake record must not leave `mykex`
/// set and wedge the next legitimate rekey.
#[test]
fn datagram_rekey_survives_malformed_handshake_record() {
    use tinc_crypto::chapoly::ChaPoly;
    use tinc_sptps::REC_HANDSHAKE;

    let mut rng = SeedRng(0x00C0_FFEE);
    let (mut alice, mut bob) = Pair::datagram().handshake();

    // `send_record` refuses type ≥ 128, so seal a 3-byte
    // REC_HANDSHAKE by hand.
    let seqno = alice.alloc_seqnos(1).unwrap();
    let cipher = ChaPoly::new(&alice.outcipher_key().unwrap());
    let mut bad = seqno.to_be_bytes().to_vec();
    cipher.seal_into(u64::from(seqno), REC_HANDSHAKE, b"bad", &mut bad, 4);
    assert_eq!(bob.receive(&bad, &mut rng).unwrap_err(), SptpsError::BadKex);

    let kex = wire(alice.force_kex(&mut rng).unwrap());
    let (_, outs) = bob.receive(&kex, &mut rng).unwrap();
    assert_eq!(wires(outs).len(), 1);
}
