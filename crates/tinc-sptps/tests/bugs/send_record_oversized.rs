//! `send_record` panicked on `body.len() > u16::MAX` in stream mode
//! (`body.len().try_into().expect(...)` at the framing header). The
//! C silently truncates with a `uint16_t` cast — desyncs the receiver.
//! Gate is in `send_record` only; `send_record_priv` keeps the
//! `expect` for fixed-size handshake records.

use tinc_sptps::{Framing, Output, SptpsError};

use crate::common::handshake_pair;

#[test]
fn stream_gates_at_u16_boundary() {
    let (mut alice, _bob) = handshake_pair(Framing::Stream, b"bug");

    // 65535: OK. wire = len:2 + enc(ty:1 + body) + tag:16.
    let outs = alice.send_record(0, &vec![0x42; 65535]).unwrap();
    let bytes = match &outs[0] {
        Output::Wire { bytes, .. } => bytes,
        o => panic!("expected Wire, got {o:?}"),
    };
    assert_eq!(bytes.len(), 2 + 1 + 65535 + 16);
    assert_eq!(&bytes[..2], &[0xFF, 0xFF]);

    // 65536: Err, not panic.
    assert_eq!(
        alice.send_record(0, &vec![0; 65536]),
        Err(SptpsError::InvalidState)
    );

    // Gate fires before send_record_priv → outseqno not bumped.
    alice.send_record(0, b"after").unwrap();
}

#[test]
fn datagram_has_no_length_cap() {
    let (mut alice, _bob) = handshake_pair(Framing::Datagram, b"bug");
    // No u16 header in datagram framing.
    alice.send_record(0, &vec![0; 70000]).unwrap();
}
