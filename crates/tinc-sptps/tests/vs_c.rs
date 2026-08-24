//! Differential test: Rust SPTPS vs `sptps.c` via `tinc-ffi`.
//!
//! The strong claim is `byte_identical_wire_output`: same keys and same
//! RNG stream give byte-for-byte the same wire output from both
//! implementations, i.e. the same SIG transcript, PRF seed and record
//! encoding. The interop tests are weaker (Ed25519 accepts any valid
//! signature over the right message) but cover the responder path,
//! datagram framing and rekeying against the real C state machine.
//!
//! All tests take `serial_guard()`: the C side has one global RNG.

#[path = "common/mod.rs"]
mod common;

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use common::{NoRng, keypair, record, wire, wires};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use tinc_ffi::{CKey, CSptps, Event, seed_rng, serial_guard};
use tinc_sptps::{Framing, Output, Role, Sptps};

const REPLAYWIN: usize = 16;

/// Produces the same bytes as the C harness's `randomize()` for the
/// same 32-byte seed: DJB ChaCha20 (8-byte zero nonce) keystream.
/// `chacha.c` is block-granular and bumps the counter at the end of
/// every call even if it used less than 64 bytes, so seek to the next
/// block boundary after each fill. `byte_identical_wire_output` caught
/// this: the nonce (first draw) matched, the ECDH key (second) did not.
struct BridgeRng(ChaCha20Legacy);

impl BridgeRng {
    fn new(seed: &[u8; 32]) -> Self {
        Self(ChaCha20Legacy::new(seed.into(), (&[0u8; 8]).into()))
    }
}

impl TryCryptoRng for BridgeRng {}
impl TryRng for BridgeRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        dest.fill(0);
        self.0.apply_keystream(dest);
        let pos: u64 = self.0.current_pos();
        self.0.seek(pos.div_ceil(64) * 64);
        Ok(())
    }
}

fn outputs(events: Vec<Event>) -> Vec<Output> {
    events
        .into_iter()
        .map(|event| match event {
            Event::Wire { record_type, bytes } => Output::Wire { record_type, bytes },
            Event::Record { record_type, bytes } => Output::Record { record_type, bytes },
            Event::HandshakeDone => Output::HandshakeDone,
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Impl {
    Rust,
    C,
}

/// One end of a session in either implementation, with just enough
/// surface to script a handshake once for both. `Sptps` is boxed only
/// to keep the variants similar in size.
enum Peer {
    Rust(Box<Sptps>),
    C(CSptps<'static>),
}

impl Peer {
    /// Returns the peer and its initial KEX record. C keys are leaked:
    /// `CSptps` borrows them and threading the storage through every
    /// test is not worth it for a few hundred bytes.
    fn start(
        which: Impl,
        role: Role,
        framing: Framing,
        key_tags: (u8, u8),
        label: &[u8],
        seed: [u8; 32],
    ) -> (Self, Vec<u8>) {
        let (my_key, _) = keypair(key_tags.0);
        let (_, his_public) = keypair(key_tags.1);
        match which {
            Impl::Rust => {
                let (sptps, outs) = Sptps::start(
                    role,
                    framing,
                    my_key,
                    his_public,
                    label.to_vec(),
                    REPLAYWIN,
                    &mut BridgeRng::new(&seed),
                );
                (Self::Rust(Box::new(sptps)), wire(outs))
            }
            Impl::C => {
                let my_key: &'static CKey =
                    Box::leak(Box::new(CKey::from_private_blob(&my_key.to_blob())));
                let his_key: &'static CKey = Box::leak(Box::new(CKey::from_public(&his_public)));
                seed_rng(&seed);
                let role = match role {
                    Role::Initiator => tinc_ffi::Role::Initiator,
                    Role::Responder => tinc_ffi::Role::Responder,
                };
                let framing = match framing {
                    Framing::Stream => tinc_ffi::Framing::Stream,
                    Framing::Datagram => tinc_ffi::Framing::Datagram,
                };
                let (sptps, events) = CSptps::start(role, framing, my_key, his_key, label);
                (Self::C(sptps), wire(outputs(events)))
            }
        }
    }

    /// Feed one whole record; asserts it was consumed entirely.
    fn feed(&mut self, data: &[u8]) -> Vec<Output> {
        let (taken, outs) = match self {
            Self::Rust(sptps) => sptps
                .receive(data, &mut NoRng)
                .unwrap_or_else(|e| panic!("Rust rejected record: {e:?}")),
            Self::C(sptps) => {
                let (taken, events) = sptps.receive(data);
                (taken, outputs(events))
            }
        };
        assert_eq!(taken, data.len(), "record not accepted");
        outs
    }

    fn send(&mut self, record_type: u8, body: &[u8]) -> Vec<u8> {
        match self {
            Self::Rust(sptps) => wire(sptps.send_record(record_type, body).unwrap()),
            Self::C(sptps) => wire(outputs(sptps.send_record(record_type, body))),
        }
    }

    /// Fresh RNG bytes for the new ephemeral key.
    fn force_kex(&mut self, seed: [u8; 32]) -> Vec<u8> {
        match self {
            Self::Rust(sptps) => wire(sptps.force_kex(&mut BridgeRng::new(&seed)).unwrap()),
            Self::C(sptps) => {
                seed_rng(&seed);
                wire(outputs(sptps.force_kex()))
            }
        }
    }

    /// C draws its responder KEX for a rekey lazily inside `receive`.
    fn reseed(&self, seed: [u8; 32]) {
        if matches!(self, Self::C(_)) {
            seed_rng(&seed);
        }
    }
}

/// alice initiates, bob responds.
struct Session {
    alice: Peer,
    bob: Peer,
    /// Every record that crossed the wire, in script order.
    transcript: Vec<Vec<u8>>,
}

impl Session {
    fn handshake(alice: Impl, bob: Impl, framing: Framing, label: &[u8]) -> Self {
        let (mut alice, kex_a) =
            Peer::start(alice, Role::Initiator, framing, (1, 2), label, [0x11; 32]);
        let (mut bob, kex_b) =
            Peer::start(bob, Role::Responder, framing, (2, 1), label, [0x22; 32]);

        let sig_a = wire(alice.feed(&kex_b));
        assert_eq!(bob.feed(&kex_a), [], "responder sends nothing on KEX");
        let from_bob = bob.feed(&sig_a);
        assert_eq!(from_bob.len(), 2, "responder: SIG + HandshakeDone");
        assert_eq!(from_bob[1], Output::HandshakeDone);
        let sig_b = wires(from_bob).remove(0);
        assert_eq!(alice.feed(&sig_b), [Output::HandshakeDone]);

        Self {
            alice,
            bob,
            transcript: vec![kex_a, kex_b, sig_a, sig_b],
        }
    }

    fn alice_to_bob(&mut self, record_type: u8, body: &[u8]) {
        let sealed = self.alice.send(record_type, body);
        assert_eq!(record(self.bob.feed(&sealed)), (record_type, body.to_vec()));
        self.transcript.push(sealed);
    }

    fn bob_to_alice(&mut self, record_type: u8, body: &[u8]) {
        let sealed = self.bob.send(record_type, body);
        assert_eq!(
            record(self.alice.feed(&sealed)),
            (record_type, body.to_vec())
        );
        self.transcript.push(sealed);
    }

    /// alice forces a new KEX. During a rekey the responder answers SIG
    /// with SIG + ACK (under the old key) and both sides only report
    /// `HandshakeDone` after the peer's ACK. This is what `receive_sig`'s
    /// `was_rekey` return exists for: without it the Rust initiator
    /// would finish early and never send the ACK C is waiting for.
    fn rekey(&mut self) {
        let kex_a = self.alice.force_kex([0x33; 32]);
        self.bob.reseed([0x44; 32]);
        let kex_b = wire(self.bob.feed(&kex_a));
        let sig_a = wire(self.alice.feed(&kex_b));
        let from_bob = wires(self.bob.feed(&sig_a));
        let [sig_b, ack_b] = &from_bob[..] else {
            panic!("responder rekey: expected SIG + ACK, got {from_bob:?}");
        };
        let ack_a = wire(self.alice.feed(sig_b));
        assert_eq!(self.bob.feed(&ack_a), [Output::HandshakeDone]);
        assert_eq!(self.alice.feed(ack_b), [Output::HandshakeDone]);
    }
}

#[test]
fn rust_initiator_c_responder_stream() {
    let _serial = serial_guard();
    let mut session = Session::handshake(Impl::Rust, Impl::C, Framing::Stream, b"rust-vs-c");
    session.alice_to_bob(0, b"rust says hi");
    session.bob_to_alice(7, b"c says hi back");
}

/// The responder signs in `receive_sig` rather than `receive_kex`, so
/// both directions need covering.
#[test]
fn c_initiator_rust_responder_stream() {
    let _serial = serial_guard();
    let mut session = Session::handshake(Impl::C, Impl::Rust, Framing::Stream, b"rust-vs-c");
    session.alice_to_bob(0, b"from c");
    session.bob_to_alice(0, b"from rust");
}

/// Datagram framing puts the seqno on the wire and uses the replay
/// window instead of the implicit stream counter.
#[test]
fn rust_initiator_c_responder_datagram() {
    let _serial = serial_guard();
    let mut session = Session::handshake(Impl::Rust, Impl::C, Framing::Datagram, b"dgram");
    session.alice_to_bob(0, b"via udp");
    session.bob_to_alice(3, b"reply");
}

#[test]
fn byte_identical_wire_output() {
    let _serial = serial_guard();
    let run = |which| {
        let mut session = Session::handshake(which, which, Framing::Stream, b"byte-identity");
        session.alice_to_bob(0, b"ping");
        session.transcript
    };
    let rust = run(Impl::Rust);
    let c = run(Impl::C);
    let names = ["KEX(init)", "KEX(resp)", "SIG(init)", "SIG(resp)", "app"];
    for ((rust, c), name) in rust.iter().zip(&c).zip(names) {
        if rust != c {
            let offset = rust
                .iter()
                .zip(c)
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| rust.len().min(c.len()));
            panic!(
                "{name} diverges at byte {offset}: rust={:02x?}.. c={:02x?}.. (lens {} vs {})",
                &rust[offset..rust.len().min(offset + 8)],
                &c[offset..c.len().min(offset + 8)],
                rust.len(),
                c.len(),
            );
        }
    }
    assert_eq!(rust, c);
}

#[test]
fn stream_rekey_rust_initiator() {
    let _serial = serial_guard();
    let mut session = Session::handshake(Impl::Rust, Impl::C, Framing::Stream, b"rekey");
    session.rekey();
    session.alice_to_bob(0, b"after rekey");
    session.bob_to_alice(0, b"and back");
}

/// C tincd rekeys datagram sessions via `send_key_changed()`. The wire
/// seqno must stay monotone across the rekey in both directions or the
/// peer's replay window drops post-rekey traffic: as a replay when
/// Rust sends (C's `inseqno` is past 0), as far-future when C sends
/// (more than `replaywin * 8` ahead of a reset window).
#[test]
fn datagram_rekey_keeps_seqno_monotone() {
    let _serial = serial_guard();
    let mut session = Session::handshake(Impl::Rust, Impl::C, Framing::Datagram, b"dgram-rekey");
    for i in 0u8..8 {
        session.alice_to_bob(0, &[i]);
    }
    for i in 0u8..200 {
        session.bob_to_alice(0, &[i]);
    }
    session.rekey();

    session.alice_to_bob(0, b"rust after rekey");
    let seqno = |record: &[u8]| u32::from_be_bytes(record[..4].try_into().unwrap());
    assert!(seqno(session.transcript.last().unwrap()) >= 8);
    session.bob_to_alice(0, b"c after rekey");
    assert!(seqno(session.transcript.last().unwrap()) > 128);
}
