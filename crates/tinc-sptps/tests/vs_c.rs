//! Differential test: Rust SPTPS vs `sptps.c` via `tinc-ffi`.
//!
//! The strongest claim this file makes is in `byte_identical_wire_output`:
//! given the same keys and the same RNG bytes, the Rust state machine
//! produces *byte-for-byte the same wire output* as the C. Not "compatible
//! enough to handshake" — that's a weaker property (Ed25519 will accept
//! any valid signature over the right message). Byte-identical means we
//! built the same SIG transcript, the same PRF seed, the same everything.
//!
//! ## RNG synchronization
//!
//! The C harness's `randomize()` is a `ChaCha20` keystream over a fixed key
//! (set by `tinc_ffi::seed_rng`). We need a Rust `RngCore` that produces
//! the *same byte stream*. `rand_chacha::ChaCha20Rng::from_seed(key)` does
//! NOT — it's a different construction (it sets the nonce to a fixed value
//! and the counter to 0, but the C side uses an 8-byte zero IV with
//! `chacha_ivsetup` which is the *DJB* layout, not the IETF one
//! `rand_chacha` uses).
//!
//! So we don't try to match the keystream. Instead: pre-draw the bytes we
//! need from the C side (by seeding it, calling `randomize` via a tiny
//! shim, capturing the output), then replay them on the Rust side via a
//! deterministic `RngCore` that just hands out those exact bytes. The
//! `BridgeRng` below.
//!
//! Except — there's no Rust-visible `randomize` shim. Simpler: we seed
//! BOTH sides from `rand_chacha`, by exposing a `ffi_set_next_random` in
//! the C shim that lets us inject the exact bytes for the next
//! `randomize()` call. ...also overkill.
//!
//! Actually the simplest thing: **make the Rust RNG match the C's stream
//! by using the same ChaCha primitive**. The C shim uses tinc's vendored
//! `chacha.c` (DJB `ChaCha20`, 64-bit counter, 8-byte nonce). `tinc-crypto`
//! already wraps that exact variant in `ChaPoly` — but that's an AEAD, not
//! a raw stream. The underlying `chacha20::ChaCha20Legacy` *is* the right
//! primitive though. Build a tiny `RngCore` over it.

pub mod common;

use common::NoRng;
use rand_core::{CryptoRng, RngCore};
use tinc_crypto::sign::SigningKey;
use tinc_ffi::{CKey, CSptps, Event, seed_rng, serial_guard};
use tinc_sptps::{Framing, Output, Role, Sptps};

// ────────────────────────────────────────────────────────────────────
// RNG bridge: same ChaCha20 stream as csrc/shim.c's randomize().
//
// shim.c: `chacha_keysetup(ctx, key, 256); chacha_ivsetup(ctx, iv_zero, NULL)`
// then `chacha_encrypt_bytes(ctx, zeros, out, len)`. That's DJB ChaCha20
// with key=seed, nonce=0, counter=0, encrypting zeros → raw keystream.
// `chacha20::ChaCha20Legacy` is the same primitive.

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

/// `RngCore` that produces the same bytes as the C harness's `randomize()`
/// when both are seeded with the same 32-byte key.
///
/// **Subtle:** `chacha.c`'s `chacha_encrypt_bytes` is *block-granular* —
/// it increments the counter on every call exit, even when the call
/// consumed less than a full 64-byte block. So `randomize(32); randomize(32)`
/// produces block 0 bytes 0..32, then block **1** bytes 0..32; the unused
/// half of block 0 is discarded. `ChaCha20Legacy::apply_keystream` is
/// byte-granular and would produce block 0 bytes 32..64 for the second call.
///
/// We replicate the C behaviour by seeking to the next block boundary
/// after every fill. This costs at most 63 bytes per call, which is
/// nothing for a test harness.
///
/// This was caught by `byte_identical_wire_output`: the nonce (first call,
/// 32 bytes) matched, the ECDH pubkey (derived from the *seed* of the
/// second call) diverged. The interop tests still passed — each side
/// agrees with itself — which is exactly why byte-identity is the test
/// that matters.
struct BridgeRng {
    cipher: ChaCha20Legacy,
}

impl BridgeRng {
    fn new(seed: &[u8; 32]) -> Self {
        // Match csrc/shim.c's `chacha_ivsetup(ctx, iv_zero[8], NULL)`.
        // ChaCha20Legacy takes an 8-byte nonce — DJB layout, not IETF 12.
        Self {
            cipher: ChaCha20Legacy::new(seed.into(), (&[0u8; 8]).into()),
        }
    }
}

// Test-only marker: matches C `randomize()` byte for byte.
impl CryptoRng for BridgeRng {}
impl RngCore for BridgeRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // shim.c does `memset(out, 0); chacha_encrypt_bytes(ctx, out, out)`.
        // Same thing: zero the buffer, XOR in keystream.
        dest.fill(0);
        self.cipher.apply_keystream(dest);
        // chacha.c block-granularity quirk: round up to next 64-byte
        // block. If we're already aligned (dest.len() % 64 == 0), the C
        // *also* lands on a boundary — line 184's `j12 = PLUSONE(j12)`
        // runs once per block, and we consumed a whole number of blocks.
        // So this is exactly: round up.
        let pos: u64 = self.cipher.current_pos();
        let aligned = pos.div_ceil(64) * 64;
        self.cipher.seek(aligned);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────
// Harness

const REPLAYWIN: usize = 16; // sptps_replaywin default in C

/// Same key derivation as `tinc-ffi`'s test helper. KAT-proven equivalent
/// to `ed25519_create_keypair`.
fn keypair(tag: u8) -> ([u8; 96], [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    let sk = SigningKey::from_seed(&seed);
    let pk = *sk.public_key();
    (sk.to_blob(), pk)
}

/// Map `tinc-ffi`'s `Event` to `tinc-sptps`'s `Output`. They're the same
/// shape on purpose — this is a witness that the analogy holds.
fn event_to_output(e: Event) -> Output {
    match e {
        Event::Wire { record_type, bytes } => Output::Wire { record_type, bytes },
        Event::Record { record_type, bytes } => Output::Record { record_type, bytes },
        Event::HandshakeDone => Output::HandshakeDone,
    }
}

fn events_to_outputs(es: Vec<Event>) -> Vec<Output> {
    es.into_iter().map(event_to_output).collect()
}

/// Pull the lone Wire bytes from an output vec. Panics if it's not lone.
fn wire(mut outs: Vec<Output>) -> Vec<u8> {
    assert_eq!(outs.len(), 1, "expected one Wire, got {outs:?}");
    match outs.remove(0) {
        Output::Wire { bytes, .. } => bytes,
        o => panic!("expected Wire, got {o:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests

/// Rust initiator ↔ C responder. The "does it interop at all" check.
///
/// Weaker than byte-identity: this passes if the Rust side built a SIG
/// transcript that the C side's `ecdsa_verify` accepts and a PRF seed
/// that produces compatible keys. It doesn't prove the *bytes* are the
/// same — just that they're equivalent under the crypto.
#[test]
#[expect(clippy::similar_names)] // alice_key/alice_kex: signing key vs KEX wire bytes
fn rust_initiator_c_responder() {
    let _g = serial_guard();
    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);

    // Alice (Rust). Seed doesn't need to match Bob's — they're independent
    // ephemerals. Any RNG works here; BridgeRng for symmetry.
    let mut alice_rng = BridgeRng::new(&[0xAA; 32]);
    let alice_key = SigningKey::from_blob(&alice_priv);
    let (mut alice, outs) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        alice_key,
        bob_pub,
        b"rust-vs-c".to_vec(),
        REPLAYWIN,
        &mut alice_rng,
    );
    let alice_kex = wire(outs);

    // Bob (C).
    let bob_mykey = CKey::from_private_blob(&bob_priv);
    let bob_hiskey = CKey::from_public(&alice_pub);
    seed_rng(&[0xBB; 32]);
    let (mut bob, evs) = CSptps::start(
        tinc_ffi::Role::Responder,
        tinc_ffi::Framing::Stream,
        &bob_mykey,
        &bob_hiskey,
        b"rust-vs-c",
    );
    let bob_kex = wire(events_to_outputs(evs));

    // Alice gets Bob's KEX → sends SIG.
    let (n, outs) = alice.receive(&bob_kex, &mut NoRng).unwrap();
    assert_eq!(n, bob_kex.len());
    let alice_sig = wire(outs);

    // Bob gets Alice's KEX → nothing yet (responder).
    let (n, evs) = bob.receive(&alice_kex);
    assert_eq!(n, alice_kex.len());
    assert!(evs.is_empty());

    // Bob gets Alice's SIG → verifies (Rust transcript, C verify) → SIG out → done.
    let (n, evs) = bob.receive(&alice_sig);
    assert_eq!(n, alice_sig.len(), "C rejected Rust's SIG transcript");
    let outs = events_to_outputs(evs);
    assert_eq!(outs.len(), 2);
    let bob_sig = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    assert_eq!(outs[1], Output::HandshakeDone);

    // Alice gets Bob's SIG → verifies (C transcript, Rust verify) → done.
    let (n, outs) = alice.receive(&bob_sig, &mut NoRng).unwrap();
    assert_eq!(n, bob_sig.len());
    assert_eq!(outs, vec![Output::HandshakeDone]);

    // App round-trip: Rust encrypt → C decrypt. Proves PRF output matches.
    let msg = b"rust says hi";
    let outs = alice.send_record(0, msg).unwrap();
    let ct = wire(outs);
    let (_, evs) = bob.receive(&ct);
    assert_eq!(
        events_to_outputs(evs),
        vec![Output::Record {
            record_type: 0,
            bytes: msg.to_vec()
        }],
        "C couldn't decrypt Rust's app record — PRF seed mismatch?"
    );

    // And the reverse: C encrypt → Rust decrypt.
    let reply = b"c says hi back";
    let evs = bob.send_record(7, reply);
    let ct = wire(events_to_outputs(evs));
    let (_, outs) = alice.receive(&ct, &mut NoRng).unwrap();
    assert_eq!(
        outs,
        vec![Output::Record {
            record_type: 7,
            bytes: reply.to_vec()
        }]
    );
}

/// C initiator ↔ Rust responder. Mirror of the above. The responder code
/// path is different (doesn't sign in `receive_kex`, signs in `receive_sig`
/// instead) so both directions need testing.
#[test]
#[expect(clippy::similar_names)] // bob_key/bob_kex: signing key vs KEX wire bytes
fn c_initiator_rust_responder() {
    let _g = serial_guard();
    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);

    // Alice (C).
    let alice_mykey = CKey::from_private_blob(&alice_priv);
    let alice_hiskey = CKey::from_public(&bob_pub);
    seed_rng(&[0xAA; 32]);
    let (mut alice, evs) = CSptps::start(
        tinc_ffi::Role::Initiator,
        tinc_ffi::Framing::Stream,
        &alice_mykey,
        &alice_hiskey,
        b"rust-vs-c",
    );
    let alice_kex = wire(events_to_outputs(evs));

    // Bob (Rust).
    let mut bob_rng = BridgeRng::new(&[0xBB; 32]);
    let bob_key = SigningKey::from_blob(&bob_priv);
    let (mut bob, outs) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        bob_key,
        alice_pub,
        b"rust-vs-c".to_vec(),
        REPLAYWIN,
        &mut bob_rng,
    );
    let bob_kex = wire(outs);

    // Handshake.
    let (_, evs) = alice.receive(&bob_kex);
    let alice_sig = wire(events_to_outputs(evs));

    let (_, outs) = bob.receive(&alice_kex, &mut NoRng).unwrap();
    assert!(outs.is_empty(), "responder doesn't sign on KEX");

    let (n, outs) = bob.receive(&alice_sig, &mut NoRng).unwrap();
    assert_eq!(n, alice_sig.len(), "Rust rejected C's SIG transcript");
    assert_eq!(outs.len(), 2);
    let bob_sig = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    assert_eq!(outs[1], Output::HandshakeDone);

    let (n, evs) = alice.receive(&bob_sig);
    assert_eq!(n, bob_sig.len(), "C rejected Rust responder's SIG");
    assert_eq!(events_to_outputs(evs), vec![Output::HandshakeDone]);

    // App round-trip both ways.
    let evs = alice.send_record(0, b"from c");
    let ct = wire(events_to_outputs(evs));
    let (_, outs) = bob.receive(&ct, &mut NoRng).unwrap();
    assert_eq!(
        outs,
        vec![Output::Record {
            record_type: 0,
            bytes: b"from c".to_vec()
        }]
    );

    let outs = bob.send_record(0, b"from rust").unwrap();
    let ct = wire(outs);
    let (_, evs) = alice.receive(&ct);
    assert_eq!(
        events_to_outputs(evs),
        vec![Output::Record {
            record_type: 0,
            bytes: b"from rust".to_vec()
        }]
    );
}

/// Same as above but datagram framing. The framing layer is independent
/// of the handshake state machine, but the seqno arithmetic interacts:
/// stream uses `inseqno` for the implicit per-record counter, datagram
/// puts the seqno on the wire and uses `ReplayWindow`.
#[test]
#[expect(clippy::similar_names)] // alice_key/alice_kex: signing key vs KEX wire bytes
fn rust_initiator_c_responder_datagram() {
    let _g = serial_guard();
    let (alice_priv, alice_pub) = keypair(3);
    let (bob_priv, bob_pub) = keypair(4);

    let mut alice_rng = BridgeRng::new(&[0xCC; 32]);
    let alice_key = SigningKey::from_blob(&alice_priv);
    let (mut alice, outs) = Sptps::start(
        Role::Initiator,
        Framing::Datagram,
        alice_key,
        bob_pub,
        b"dgram".to_vec(),
        REPLAYWIN,
        &mut alice_rng,
    );
    let alice_kex = wire(outs);

    let bob_mykey = CKey::from_private_blob(&bob_priv);
    let bob_hiskey = CKey::from_public(&alice_pub);
    seed_rng(&[0xDD; 32]);
    let (mut bob, evs) = CSptps::start(
        tinc_ffi::Role::Responder,
        tinc_ffi::Framing::Datagram,
        &bob_mykey,
        &bob_hiskey,
        b"dgram",
    );
    let bob_kex = wire(events_to_outputs(evs));

    let (_, outs) = alice.receive(&bob_kex, &mut NoRng).unwrap();
    let alice_sig = wire(outs);
    let (_, evs) = bob.receive(&alice_kex);
    assert!(evs.is_empty());
    let (_, evs) = bob.receive(&alice_sig);
    let outs = events_to_outputs(evs);
    let bob_sig = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    let (_, outs) = alice.receive(&bob_sig, &mut NoRng).unwrap();
    assert_eq!(outs, vec![Output::HandshakeDone]);

    let msg = b"via udp";
    let outs = alice.send_record(0, msg).unwrap();
    let ct = wire(outs);
    let (_, evs) = bob.receive(&ct);
    assert_eq!(
        events_to_outputs(evs),
        vec![Output::Record {
            record_type: 0,
            bytes: msg.to_vec()
        }]
    );
}

/// **The real test.** Rust↔Rust and C↔C, same seeds → same wire bytes.
///
/// If this passes, the SIG transcript, the PRF seed, and the encrypted
/// record encoding are all byte-identical. That's a much stronger property
/// than interop — it means the Rust side can stand in for the C side
/// against *any* peer, not just the ones we test against.
///
/// The two interop tests above can pass while this fails (e.g. if Rust
/// reordered the SIG transcript fields but both Rust and C built valid
/// signatures over their respective orderings — Ed25519 doesn't care).
/// This test catches that.
#[test]
fn byte_identical_wire_output() {
    let _g = serial_guard();
    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);

    /// Run a full handshake + one app record, return all wire bytes in order.
    /// `who` picks Rust vs C; same script either way.
    #[expect(clippy::items_after_statements)] // local helper, clearer inline
    fn run(
        who: Impl,
        alice_priv: &[u8; 96],
        alice_pub: &[u8; 32],
        bob_priv: &[u8; 96],
        bob_pub: &[u8; 32],
    ) -> Vec<Vec<u8>> {
        let label = b"byte-identity";
        let seed_a = [0x11u8; 32];
        let seed_b = [0x22u8; 32];

        let mut a = who.start(
            tinc_sptps::Role::Initiator,
            alice_priv,
            bob_pub,
            label,
            &seed_a,
        );
        let kex_a = a.kex_out();
        let mut b = who.start(
            tinc_sptps::Role::Responder,
            bob_priv,
            alice_pub,
            label,
            &seed_b,
        );
        let kex_b = b.kex_out();

        let sig_a = a.feed_expect_one_wire(&kex_b);
        b.feed_expect_nothing(&kex_a);
        let (sig_b, done_b) = b.feed_expect_wire_then_done(&sig_a);
        assert!(done_b);
        let done_a = a.feed_expect_done(&sig_b);
        assert!(done_a);

        let app = a.send(0, b"ping");

        vec![kex_a, kex_b, sig_a, sig_b, app]
    }

    let rust_out = run(Impl::Rust, &alice_priv, &alice_pub, &bob_priv, &bob_pub);
    let c_out = run(Impl::C, &alice_priv, &alice_pub, &bob_priv, &bob_pub);

    // The diagnostic on failure here is the actual divergence point.
    // First differing record + byte offset = the bug.
    for (i, (r, c)) in rust_out.iter().zip(c_out.iter()).enumerate() {
        let names = ["KEX(init)", "KEX(resp)", "SIG(init)", "SIG(resp)", "app"];
        if r != c {
            let mismatch = r
                .iter()
                .zip(c.iter())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| r.len().min(c.len()));
            panic!(
                "{} diverges at byte {mismatch}: rust={:02x?}.. c={:02x?}.. (lens {} vs {})",
                names[i],
                &r[mismatch..r.len().min(mismatch + 8)],
                &c[mismatch..c.len().min(mismatch + 8)],
                r.len(),
                c.len(),
            );
        }
    }
    assert_eq!(rust_out, c_out, "byte-identical (full vector compare)");
}

/// Rekey: Rust initiator forces a KEX after the initial handshake.
/// This is the test that the `was_rekey` return value in `receive_sig`
/// exists for — without it, the Rust side would synthesize an ACK during
/// rekey instead of going to the `Ack` state, and the C side (sitting in
/// `Ack` waiting for *our* ACK) would deadlock.
#[test]
#[expect(clippy::similar_names)] // kex_a2/kex_b2, sig_a2/sig_b2: rekey round-2 vs round-1
fn rust_vs_c_rekey() {
    let _g = serial_guard();
    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);

    // Set up: initial handshake (compressed; tested above).
    let mut alice_rng = BridgeRng::new(&[1; 32]);
    let alice_key = SigningKey::from_blob(&alice_priv);
    let (mut alice, outs) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        alice_key,
        bob_pub,
        b"rekey".to_vec(),
        REPLAYWIN,
        &mut alice_rng,
    );
    let kex_a = wire(outs);

    let bob_mykey = CKey::from_private_blob(&bob_priv);
    let bob_hiskey = CKey::from_public(&alice_pub);
    seed_rng(&[2; 32]);
    let (mut bob, evs) = CSptps::start(
        tinc_ffi::Role::Responder,
        tinc_ffi::Framing::Stream,
        &bob_mykey,
        &bob_hiskey,
        b"rekey",
    );
    let kex_b = wire(events_to_outputs(evs));

    let (_, o) = alice.receive(&kex_b, &mut NoRng).unwrap();
    let sig_a = wire(o);
    bob.receive(&kex_a);
    let (_, e) = bob.receive(&sig_a);
    let o = events_to_outputs(e);
    let sig_b = match &o[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    alice.receive(&sig_b, &mut NoRng).unwrap();

    // ─── Re-KEX: Alice (Rust) initiates ───
    // Fresh RNG bytes for the new ephemeral. The Rust RNG and the C RNG
    // are independent here (different sides, different seeds).
    let mut rekey_rng = BridgeRng::new(&[3; 32]);
    let outs = alice.force_kex(&mut rekey_rng).unwrap();
    let kex_a2 = wire(outs);
    // Encrypted KEX: len[2] + chacha-poly(type[1] + body[65]) + tag[16].
    assert_eq!(kex_a2.len(), 2 + 1 + 65 + 16);

    // Bob (C) is in SECONDARY_KEX. The fall-through fires: send_kex first,
    // then receive_kex on Alice's record. One Wire out.
    seed_rng(&[4; 32]);
    let (n, evs) = bob.receive(&kex_a2);
    assert_eq!(n, kex_a2.len(), "C couldn't decrypt Rust's encrypted KEX");
    let kex_b2 = wire(events_to_outputs(evs));

    // Alice (Rust) gets Bob's KEX → send_sig (encrypted).
    let (_, outs) = alice.receive(&kex_b2, &mut NoRng).unwrap();
    let sig_a2 = wire(outs);

    // Bob (C) gets Alice's SIG. receive_sig: verify, ECDH, PRF, then
    // (because !initiator) send_sig under OLD key, (because outstate)
    // send_ack under OLD key, then set_key. Then state → ACK.
    // Two Wire events, no HandshakeDone yet.
    let (n, evs) = bob.receive(&sig_a2);
    assert_eq!(n, sig_a2.len(), "C rejected Rust's encrypted SIG");
    let outs = events_to_outputs(evs);
    assert_eq!(outs.len(), 2, "C should emit SIG + ACK during rekey");
    let sig_b2 = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    let ack_b = match &outs[1] {
        Output::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };

    // Alice (Rust) gets Bob's SIG. She's the initiator, so receive_sig
    // doesn't send_sig. Because was_rekey=true, she does send_ack (under
    // OLD key) and goes to State::Ack. No HandshakeDone yet.
    //
    // This is the moment the `was_rekey` return value in receive_sig is for.
    // Without it, receive_handshake would take the !was_rekey branch,
    // synthesize an ACK, and emit HandshakeDone immediately — never
    // reaching State::Ack, never sending the wire ACK Bob is waiting for.
    let (n, outs) = alice.receive(&sig_b2, &mut NoRng).unwrap();
    assert_eq!(
        n,
        sig_b2.len(),
        "Rust couldn't decrypt C's SIG (under old key!)"
    );
    assert_eq!(
        outs.len(),
        1,
        "Rust initiator rekey: just ACK out, no HandshakeDone yet"
    );
    let ack_a = match &outs[0] {
        Output::Wire { bytes, .. } => bytes.clone(),
        o => panic!("expected Wire(ACK), got {o:?}"),
    };

    // Exchange ACKs. Both sides switch incipher to new key, emit HandshakeDone.
    let (_, evs) = bob.receive(&ack_a);
    assert_eq!(events_to_outputs(evs), vec![Output::HandshakeDone]);
    let (_, outs) = alice.receive(&ack_b, &mut NoRng).unwrap();
    assert_eq!(outs, vec![Output::HandshakeDone]);

    // App data under the new keys.
    let outs = alice.send_record(0, b"after rekey").unwrap();
    let ct = wire(outs);
    let (_, evs) = bob.receive(&ct);
    assert_eq!(
        events_to_outputs(evs),
        vec![Output::Record {
            record_type: 0,
            bytes: b"after rekey".to_vec()
        }],
        "post-rekey decryption failed — outcipher/incipher key halves swapped?"
    );
}

// ────────────────────────────────────────────────────────────────────
// Abstraction for byte_identical_wire_output: same script, two backends.

#[derive(Clone, Copy)]
enum Impl {
    Rust,
    C,
}

/// One end of a session, either Rust or C. Just enough surface to script
/// a handshake. Exists so `byte_identical_wire_output` doesn't have to
/// write the same handshake twice in two type vocabularies.
///
/// `Sptps` is boxed: it's ~700 bytes (mostly the inline KEX/key arrays),
/// and clippy rightly objects to that much padding on the C variant. Test
/// scaffolding doesn't care about the indirection.
enum Peer<'k> {
    Rust(Box<Sptps>, Vec<u8>), // (state, pending KEX from start)
    C(CSptps<'k>, Vec<u8>),
}

impl Impl {
    fn start<'k>(
        self,
        role: Role,
        my_priv: &[u8; 96],
        his_pub: &[u8; 32],
        label: &[u8],
        seed: &[u8; 32],
    ) -> Peer<'k> {
        match self {
            Self::Rust => {
                let mut rng = BridgeRng::new(seed);
                let key = SigningKey::from_blob(my_priv);
                let (s, outs) = Sptps::start(
                    role,
                    Framing::Stream,
                    key,
                    *his_pub,
                    label.to_vec(),
                    REPLAYWIN,
                    &mut rng,
                );
                Peer::Rust(Box::new(s), wire(outs))
            }
            Self::C => {
                // Leak the keys: CSptps borrows them with lifetime 'k, but
                // this function needs to return Peer<'k> and the keys are
                // local. Box::leak gives them 'static. The test process is
                // short-lived; the leak is sub-kilobyte. Alternative would
                // be threading the CKey storage through `run()`, which
                // turns a 5-line script into a lifetime puzzle.
                let mykey: &'static CKey = Box::leak(Box::new(CKey::from_private_blob(my_priv)));
                let hiskey: &'static CKey = Box::leak(Box::new(CKey::from_public(his_pub)));
                seed_rng(seed);
                let c_role = match role {
                    Role::Initiator => tinc_ffi::Role::Initiator,
                    Role::Responder => tinc_ffi::Role::Responder,
                };
                let (s, evs) =
                    CSptps::start(c_role, tinc_ffi::Framing::Stream, mykey, hiskey, label);
                Peer::C(s, wire(events_to_outputs(evs)))
            }
        }
    }
}

impl Peer<'_> {
    fn kex_out(&mut self) -> Vec<u8> {
        match self {
            Peer::Rust(_, kex) | Peer::C(_, kex) => std::mem::take(kex),
        }
    }

    fn feed(&mut self, data: &[u8]) -> Vec<Output> {
        match self {
            Peer::Rust(s, _) => {
                let (n, o) = s.receive(data, &mut NoRng).unwrap();
                assert_eq!(n, data.len());
                o
            }
            Peer::C(s, _) => {
                let (n, e) = s.receive(data);
                assert_eq!(n, data.len());
                events_to_outputs(e)
            }
        }
    }

    fn feed_expect_one_wire(&mut self, data: &[u8]) -> Vec<u8> {
        wire(self.feed(data))
    }

    fn feed_expect_nothing(&mut self, data: &[u8]) {
        let o = self.feed(data);
        assert!(o.is_empty(), "expected no output, got {o:?}");
    }

    fn feed_expect_wire_then_done(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let o = self.feed(data);
        assert_eq!(o.len(), 2);
        let bytes = match &o[0] {
            Output::Wire { bytes, .. } => bytes.clone(),
            x => panic!("expected Wire, got {x:?}"),
        };
        (bytes, matches!(o[1], Output::HandshakeDone))
    }

    fn feed_expect_done(&mut self, data: &[u8]) -> bool {
        self.feed(data) == vec![Output::HandshakeDone]
    }

    fn send(&mut self, ty: u8, body: &[u8]) -> Vec<u8> {
        match self {
            Peer::Rust(s, _) => wire(s.send_record(ty, body).unwrap()),
            Peer::C(s, _) => wire(events_to_outputs(s.send_record(ty, body))),
        }
    }
}
