//! C↔C SPTPS through the harness. This does not test `sptps.c`; it
//! pins that the harness is a faithful conduit (bytes in, events out in
//! `sptps.c`'s order, deterministic under `seed_rng`), which is what
//! `tinc-sptps/tests/vs_c.rs` relies on when it swaps one side for Rust.
//!
//! Initial handshake per side: KEX out at start; initiator answers the
//! peer's KEX with SIG; responder answers SIG with its own SIG and is
//! done; initiator is done on receiving that. No ACK on the wire: the
//! `SPTPS_ACK` state is only reached on a rekey, when `outstate` is
//! already set.

use tinc_ffi::{CKey, CSptps, Event, Framing, Role, seed_rng, serial_guard};

const HANDSHAKE: u8 = 128;
const KEX_BODY: usize = 65;
const SIG_BODY: usize = 64;
const TAG: usize = 16;

fn header_len(framing: Framing) -> usize {
    match framing {
        Framing::Stream => 2,   // body length
        Framing::Datagram => 4, // seqno
    }
}

/// Same derivation as `tinc-sptps`'s test keys; the KATs prove
/// `from_seed` matches `ed25519_create_keypair`.
fn keypair(tag: u8) -> ([u8; 96], [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    let key = tinc_crypto::sign::SigningKey::from_seed(&seed);
    (key.to_blob(), *key.public_key())
}

/// `(own private, peer public)` as C key objects.
struct Keys(CKey, CKey);

impl Keys {
    fn new(own: u8, peer: u8) -> Self {
        Self(
            CKey::from_private_blob(&keypair(own).0),
            CKey::from_public(&keypair(peer).1),
        )
    }

    fn start(&self, role: Role, framing: Framing, label: &[u8], seed: u8) -> (CSptps<'_>, Vec<u8>) {
        seed_rng(&[seed; 32]);
        let (sptps, events) = CSptps::start(role, framing, &self.0, &self.1, label);
        (sptps, wire(events))
    }
}

fn wires(events: Vec<Event>) -> Vec<Vec<u8>> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::Wire { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect()
}

fn wire(events: Vec<Event>) -> Vec<u8> {
    assert_eq!(events.len(), 1, "expected one Wire, got {events:?}");
    wires(events).remove(0)
}

type Receive = fn(&mut CSptps, &[u8]) -> Vec<Event>;

fn receive_whole(peer: &mut CSptps, data: &[u8]) -> Vec<Event> {
    let (taken, events) = peer.receive(data);
    assert_eq!(taken, data.len());
    events
}

/// One byte per call: every boundary in the stream reassembly buffer,
/// and on our side, that events from calls producing nothing are not
/// lost.
fn receive_bytewise(peer: &mut CSptps, data: &[u8]) -> Vec<Event> {
    data.iter()
        .flat_map(|byte| receive_whole(peer, std::slice::from_ref(byte)))
        .collect()
}

/// Full handshake plus one record each way; returns every wire record
/// in order.
fn handshake(framing: Framing, receive: Receive) -> Vec<Vec<u8>> {
    let header = header_len(framing);
    let alice_keys = Keys::new(1, 2);
    let bob_keys = Keys::new(2, 1);
    // Distinct seeds, or both sides draw the same ephemeral key.
    let (mut alice, kex_a) = alice_keys.start(Role::Initiator, framing, b"label", 0xAA);
    let (mut bob, kex_b) = bob_keys.start(Role::Responder, framing, b"label", 0xBB);
    for kex in [&kex_a, &kex_b] {
        assert_eq!(kex.len(), header + 1 + KEX_BODY);
        assert_eq!(kex[header], HANDSHAKE);
        assert_eq!(kex[header + 1], 0, "SPTPS_VERSION");
    }
    if matches!(framing, Framing::Datagram) {
        assert_eq!(&kex_a[..4], &[0, 0, 0, 0], "first seqno");
    }

    let sig_a = wire(receive(&mut alice, &kex_b));
    assert_eq!(sig_a.len(), header + 1 + SIG_BODY);
    assert_eq!(receive(&mut bob, &kex_a), []);
    let from_bob = receive(&mut bob, &sig_a);
    assert_eq!(from_bob.len(), 2, "responder: SIG then HandshakeDone");
    assert_eq!(from_bob[1], Event::HandshakeDone);
    let sig_b = wires(from_bob).remove(0);
    assert_eq!(receive(&mut alice, &sig_b), [Event::HandshakeDone]);

    let to_bob = wire(alice.send_record(0, b"hello bob"));
    assert_eq!(to_bob.len(), header + 1 + 9 + TAG);
    match framing {
        // Length header counts the body only; the type byte is inside
        // the ciphertext.
        Framing::Stream => assert_eq!(&to_bob[..2], &[0, 9]),
        Framing::Datagram => assert_eq!(&to_bob[..4], &[0, 0, 0, 2], "third record"),
    }
    assert_eq!(
        receive(&mut bob, &to_bob),
        [Event::Record {
            record_type: 0,
            bytes: b"hello bob".to_vec()
        }]
    );
    let to_alice = wire(bob.send_record(7, b"hi alice"));
    assert_eq!(
        receive(&mut alice, &to_alice),
        [Event::Record {
            record_type: 7,
            bytes: b"hi alice".to_vec()
        }]
    );
    vec![kex_a, kex_b, sig_a, sig_b, to_bob, to_alice]
}

#[test]
fn stream_handshake() {
    let _serial = serial_guard();
    handshake(Framing::Stream, receive_whole);
}

#[test]
fn stream_handshake_bytewise() {
    let _serial = serial_guard();
    handshake(Framing::Stream, receive_bytewise);
}

#[test]
fn datagram_handshake() {
    let _serial = serial_guard();
    handshake(Framing::Datagram, receive_whole);
}

/// The property the differential tests are built on.
#[test]
fn same_seeds_same_bytes() {
    let _serial = serial_guard();
    assert_eq!(
        handshake(Framing::Stream, receive_whole),
        handshake(Framing::Stream, receive_whole)
    );
}

/// `ecdsa_verify` failure makes `sptps_receive_data` return 0 with no
/// events; the harness must surface that rather than swallow it.
#[test]
fn wrong_peer_key_fails_at_sig() {
    let _serial = serial_guard();
    let alice_keys = Keys::new(1, 2);
    let bob_keys = Keys::new(2, 99);
    let (mut alice, kex_a) = alice_keys.start(Role::Initiator, Framing::Stream, b"auth", 0xEE);
    let (mut bob, kex_b) = bob_keys.start(Role::Responder, Framing::Stream, b"auth", 0xFF);
    let sig_a = wire(receive_whole(&mut alice, &kex_b));
    assert_eq!(receive_whole(&mut bob, &kex_a), []);
    let (taken, events) = bob.receive(&sig_a);
    assert_eq!(taken, 0);
    assert_eq!(events, []);
}

/// Rekey reaches `SPTPS_ACK`, which the initial handshake skips. The
/// responder answers SIG with SIG + ACK, both still under the *old*
/// key (`receive_sig` switches `outcipher` only afterwards), and
/// `HandshakeDone` waits for the peer's ACK.
#[test]
fn stream_rekey_uses_ack_state() {
    let _serial = serial_guard();
    let alice_keys = Keys::new(1, 2);
    let bob_keys = Keys::new(2, 1);
    let (mut alice, kex_a) = alice_keys.start(Role::Initiator, Framing::Stream, b"rekey", 1);
    let (mut bob, kex_b) = bob_keys.start(Role::Responder, Framing::Stream, b"rekey", 2);
    let sig_a = wire(receive_whole(&mut alice, &kex_b));
    receive_whole(&mut bob, &kex_a);
    let sig_b = wires(receive_whole(&mut bob, &sig_a)).remove(0);
    receive_whole(&mut alice, &sig_b);

    seed_rng(&[3; 32]);
    let kex_a = wire(alice.force_kex());
    assert_eq!(kex_a.len(), 2 + 1 + KEX_BODY + TAG, "encrypted now");
    // bob draws his new KEX inside receive.
    seed_rng(&[4; 32]);
    let kex_b = wire(receive_whole(&mut bob, &kex_a));
    assert_eq!(kex_b.len(), 2 + 1 + KEX_BODY + TAG);
    let sig_a = wire(receive_whole(&mut alice, &kex_b));
    assert_eq!(sig_a.len(), 2 + 1 + SIG_BODY + TAG);

    let from_bob = wires(receive_whole(&mut bob, &sig_a));
    let [sig_b, ack_b] = &from_bob[..] else {
        panic!("responder rekey: expected SIG + ACK, got {from_bob:?}");
    };
    assert_eq!(ack_b.len(), 2 + 1 + TAG, "ACK has an empty body");
    let ack_a = wire(receive_whole(&mut alice, sig_b));
    assert_eq!(receive_whole(&mut bob, &ack_a), [Event::HandshakeDone]);
    assert_eq!(receive_whole(&mut alice, ack_b), [Event::HandshakeDone]);

    let sealed = wire(alice.send_record(0, b"after rekey"));
    assert_eq!(
        receive_whole(&mut bob, &sealed),
        [Event::Record {
            record_type: 0,
            bytes: b"after rekey".to_vec()
        }]
    );
}
