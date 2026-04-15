//! `open_data_into` left decrypted plaintext in `out` on
//! `Err(BadSeqno)` — the `BadRecord` path truncated, this one didn't.
//! Now both restore `out == [0; headroom]`.

use tinc_sptps::{Framing, SptpsError};

use crate::common::{SeedRng, handshake_pair, wire};

const HEADROOM: usize = 14;

#[test]
fn truncates_on_badseqno() {
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"bug");

    let body = b"must not survive replay reject";
    let mut tx = Vec::new();
    alice.seal_data_into(7, body, &mut tx, 0).unwrap();

    let mut out = Vec::new();
    bob.open_data_into(&tx, &mut out, HEADROOM).unwrap();
    assert_eq!(&out[HEADROOM..], &body[..]);

    // Replay → BadSeqno, out scrubbed.
    let err = bob.open_data_into(&tx, &mut out, HEADROOM).unwrap_err();
    assert_eq!(err, SptpsError::BadSeqno);
    assert_eq!(out, vec![0u8; HEADROOM]);
}

#[test]
fn truncates_on_badrecord() {
    let (mut alice, mut bob) = handshake_pair(Framing::Datagram, b"bug");

    // force_kex emits an encrypted REC_HANDSHAKE.
    let kex = wire(alice.force_kex(&mut SeedRng(0xCC)).unwrap());

    let mut out = Vec::new();
    let err = bob.open_data_into(&kex, &mut out, HEADROOM).unwrap_err();
    assert_eq!(err, SptpsError::BadRecord);
    assert_eq!(out, vec![0u8; HEADROOM]);
}

/// Short-packet / tag-mismatch shapes on the hot path: clean `Err`,
/// never panic. Buffer contract on these paths is weaker (the < 21
/// gate fires before `out.clear()`), so only the result is checked.
#[test]
fn rejects_garbage() {
    let (_alice, mut bob) = handshake_pair(Framing::Datagram, b"bug");
    let mut out = Vec::new();
    for pkt in [&[0u8; 0][..], &[0u8; 4][..], &[0u8; 20][..], &[0u8; 64][..]] {
        assert!(
            bob.open_data_into(pkt, &mut out, HEADROOM).is_err(),
            "{} bytes",
            pkt.len()
        );
    }
}
