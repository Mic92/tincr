//! C↔C SPTPS handshake: prove the harness can drive `sptps.c` end-to-end.
//!
//! These tests don't validate `sptps.c` itself — that's what `sptps_test.c`
//! and the integration suite are for. They validate that the *harness* is a
//! faithful conduit: bytes go in, the right bytes come out, the event
//! sequence matches what `sptps.c` documents.
//!
//! Once Phase 2 lands, the same test bodies run again with one peer swapped
//! for the Rust implementation. The "spec" of what events to expect is
//! whatever this file asserts — so be precise.
//!
//! ## What a stream-mode handshake looks like on the wire
//!
//! Reading `sptps_start` → `send_kex` → `receive_handshake`:
//!
//! 1. **Both sides: KEX out** (during `start`). 68 bytes: 2-byte len (0x0041)
//!    + 1-byte type (0x80=HANDSHAKE) + 65-byte body (version[1] + nonce[32]
//!    + `ecdh_pub`[32]). Plaintext — no cipher state yet.
//!
//! 2. **Initiator on receiving KEX → sends SIG.** 67 bytes: 2-byte len +
//!    type + 64-byte Ed25519 signature over `[1][mykex][hiskex][label]`.
//!    Still plaintext.
//!
//! 3. **Responder on receiving KEX → does nothing yet.** (`receive_kex`
//!    early returns when `!initiator`.) Just stores `hiskex`.
//!
//! 4. **Responder on receiving SIG → verifies, sends own SIG, derives keys.**
//!    `receive_sig` runs verify, ECDH, PRF, then `send_sig` (because
//!    `!initiator`), then sets `outcipher`. State → `SECONDARY_KEX`.
//!    Then because `!outstate` was true going in, it synthesizes the ACK
//!    locally (`receive_ack(NULL, 0)`) and fires `HandshakeDone`.
//!
//! 5. **Initiator on receiving SIG → derives keys, `HandshakeDone`.** Same
//!    code path. Doesn't re-send SIG (it's the initiator). Same synthetic
//!    ACK.
//!
//! Net: each side sends exactly 2 records, receives exactly 2 records,
//! handshake done. The ACK record is a *re-KEX* artifact (`SPTPS_ACK`
//! state only happens when `outstate` is already true). The initial
//! handshake doesn't put one on the wire.

use tinc_ffi::{CKey, CSptps, Event, Framing, Role, seed_rng, serial_guard};

const SPTPS_HANDSHAKE: u8 = 128;

/// Wire-format constants. Computed from `sptps.c`, not hand-guessed:
/// stream framing is `len:u16 ‖ type:u8 ‖ body`, plaintext (no tag during
/// handshake). KEX body is `sptps_kex_t` = 65 packed; SIG body is 64
/// (`ecdsa_size`).
const STREAM_KEX_LEN: usize = 2 + 1 + 65;
const STREAM_SIG_LEN: usize = 2 + 1 + 64;

/// Datagram framing is `seqno:u32 ‖ type:u8 ‖ body`. Same bodies.
const DGRAM_KEX_LEN: usize = 4 + 1 + 65;
const DGRAM_SIG_LEN: usize = 4 + 1 + 64;

// ────────────────────────────────────────────────────────────────────
// Helpers

/// Generate a key blob from a deterministic seed. Uses tinc-crypto's
/// `from_seed`, which Phase 0a's KATs proved matches `ed25519_create_keypair`
/// byte-for-byte. So the C side is signing/verifying with key material that
/// the Rust side could have produced — exactly the cross-implementation
/// scenario Phase 2 cares about.
fn keypair(seed_tag: u8) -> ([u8; 96], [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = seed_tag;
    let sk = tinc_crypto::sign::SigningKey::from_seed(&seed);
    let pk = *sk.public_key();
    (sk.to_blob(), pk)
}

/// Pull the single Wire event out of an event vec, assert nothing else
/// is there. Handshake steps that produce multiple events get spelled
/// out manually in the test bodies — they're the interesting cases.
fn sole_wire(mut evs: Vec<Event>) -> Vec<u8> {
    assert_eq!(evs.len(), 1, "expected exactly one Wire event, got {evs:?}");
    match evs.remove(0) {
        Event::Wire { record_type, bytes } => {
            assert_eq!(record_type, SPTPS_HANDSHAKE, "wire event during handshake");
            bytes
        }
        e => panic!("expected Wire, got {e:?}"),
    }
}

/// Feed wire bytes into a peer one byte at a time.
///
/// Stream-mode `sptps_receive_data` is a reassembly state machine that has
/// to handle TCP-style short reads. Feeding it byte-by-byte exercises every
/// boundary in that state machine: the 2-byte length read, the realloc, the
/// partial body. The accumulated event output should be identical to a
/// single bulk feed — that's a property of the C code, not the harness, but
/// it's cheap to assert and would catch a sink-draining bug on our side.
fn dribble(peer: &mut CSptps, data: &[u8]) -> Vec<Event> {
    let mut all = Vec::new();
    for b in data {
        let (n, evs) = peer.receive(std::slice::from_ref(b));
        assert_eq!(n, 1, "stream mode consumes everything it's given");
        all.extend(evs);
    }
    all
}

// ────────────────────────────────────────────────────────────────────

#[test]
fn stream_handshake_c_to_c() {
    let _g = serial_guard();
    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);

    let alice_mykey = CKey::from_private_blob(&alice_priv);
    let alice_hiskey = CKey::from_public(&bob_pub);
    let bob_mykey = CKey::from_private_blob(&bob_priv);
    let bob_hiskey = CKey::from_public(&alice_pub);

    let label = b"tinc-ffi handshake test";

    // ─── Step 1: both sides KEX ───
    // Seed before each start. The two seeds must differ or both sides
    // generate identical ECDH ephemerals and the handshake degenerates
    // into a key-with-yourself test (still passes, but less interesting).
    seed_rng(&[0xAA; 32]);
    let (mut alice, evs) = CSptps::start(
        Role::Initiator,
        Framing::Stream,
        &alice_mykey,
        &alice_hiskey,
        label,
    );
    let alice_kex = sole_wire(evs);
    assert_eq!(alice_kex.len(), STREAM_KEX_LEN);
    // Stream framing: first 2 bytes = body length (65) big-endian.
    assert_eq!(&alice_kex[..3], &[0, 65, SPTPS_HANDSHAKE]);
    // Body: version=0, then nonce[32], then ecdh pub[32]. Don't assert
    // the random bytes — but do assert the version, since SPTPS_VERSION
    // is the one wire-format constant that would change in a protocol bump.
    assert_eq!(alice_kex[3], 0, "SPTPS_VERSION");

    seed_rng(&[0xBB; 32]);
    let (mut bob, evs) = CSptps::start(
        Role::Responder,
        Framing::Stream,
        &bob_mykey,
        &bob_hiskey,
        label,
    );
    let bob_kex = sole_wire(evs);
    assert_eq!(bob_kex.len(), STREAM_KEX_LEN);
    assert_eq!(&bob_kex[..3], &[0, 65, SPTPS_HANDSHAKE]);

    // ─── Step 2: Alice receives Bob's KEX, sends SIG ───
    // Initiator branch in receive_kex: store hiskex, immediately send_sig.
    let (n, evs) = alice.receive(&bob_kex);
    assert_eq!(n, bob_kex.len());
    let alice_sig = sole_wire(evs);
    assert_eq!(alice_sig.len(), STREAM_SIG_LEN);
    assert_eq!(&alice_sig[..3], &[0, 64, SPTPS_HANDSHAKE]);

    // ─── Step 3: Bob receives Alice's KEX, sends nothing ───
    // Responder branch: just stores hiskex, returns true. No callbacks.
    let (n, evs) = bob.receive(&alice_kex);
    assert_eq!(n, alice_kex.len());
    assert!(evs.is_empty(), "responder doesn't SIG until it sees SIG");

    // ─── Step 4: Bob receives Alice's SIG ───
    // This is the busy step. receive_sig:
    //   - verifies, does ECDH, runs PRF, sets outcipher
    //   - because !initiator: calls send_sig() → Wire event
    //   - because !outstate going in: synthesizes receive_ack, then fires
    //     receive_record(HANDSHAKE, NULL, 0) → HandshakeDone
    // Order matters: SIG goes out *before* HandshakeDone.
    let (n, evs) = bob.receive(&alice_sig);
    assert_eq!(n, alice_sig.len());
    assert_eq!(evs.len(), 2, "responder: SIG out, then handshake done");
    let bob_sig = match &evs[0] {
        Event::Wire { record_type, bytes } => {
            assert_eq!(*record_type, SPTPS_HANDSHAKE);
            assert_eq!(bytes.len(), STREAM_SIG_LEN);
            bytes.clone()
        }
        e => panic!("expected Wire(SIG), got {e:?}"),
    };
    assert!(matches!(evs[1], Event::HandshakeDone));

    // ─── Step 5: Alice receives Bob's SIG ───
    // Initiator path: same receive_sig but skips send_sig (already sent).
    let (n, evs) = alice.receive(&bob_sig);
    assert_eq!(n, bob_sig.len());
    assert_eq!(evs, vec![Event::HandshakeDone]);

    // ─── Step 6: app traffic round-trip ───
    // Now outstate=true, instate=true on both sides. send_record encrypts.
    let msg = b"hello bob";
    let evs = alice.send_record(0, msg);
    let ct = sole_wire_app(evs);
    // Stream encrypted: len[2] + chacha-poly(type[1] + body) + tag[16].
    // The 2-byte length is the *body* length (9), not the wire length.
    // So total = 2 + (1 + 9) + 16 = 28.
    assert_eq!(ct.len(), 2 + 1 + msg.len() + 16);
    assert_eq!(&ct[..2], &[0, 9]);
    // The type byte is encrypted (it's inside the ChaPoly span).
    assert_ne!(ct[2], 0, "type byte should be encrypted, not plaintext 0");

    let (n, evs) = bob.receive(&ct);
    assert_eq!(n, ct.len());
    assert_eq!(
        evs,
        vec![Event::Record {
            record_type: 0,
            bytes: msg.to_vec()
        }]
    );

    // And back the other way, with a different record type to make sure
    // the type byte really is round-tripping through the cipher and not
    // being dropped on the floor somewhere.
    let reply = b"hi alice, type 7";
    let evs = bob.send_record(7, reply);
    let ct = sole_wire_app(evs);
    let (n, evs) = alice.receive(&ct);
    assert_eq!(n, ct.len());
    assert_eq!(
        evs,
        vec![Event::Record {
            record_type: 7,
            bytes: reply.to_vec()
        }]
    );
}

/// `sole_wire` variant that doesn't assert the type is HANDSHAKE.
/// Application records use whatever type the caller passed.
fn sole_wire_app(mut evs: Vec<Event>) -> Vec<u8> {
    assert_eq!(evs.len(), 1);
    match evs.remove(0) {
        Event::Wire { bytes, .. } => bytes,
        e => panic!("expected Wire, got {e:?}"),
    }
}

#[test]
fn stream_handshake_survives_byte_dribble() {
    let _g = serial_guard();
    // Same handshake as above, but every receive is byte-by-byte. The
    // resulting event stream must be identical — the reassembly buffer
    // in sptps_receive_data is supposed to be transparent.
    //
    // This isn't an sptps.c test (upstream presumably tests this); it's
    // a harness test. If the sink-draining logic in our shim were
    // dropping events on calls that produce nothing, this would catch it.

    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);

    let ak1 = CKey::from_private_blob(&alice_priv);
    let ak2 = CKey::from_public(&bob_pub);
    let bk1 = CKey::from_private_blob(&bob_priv);
    let bk2 = CKey::from_public(&alice_pub);

    seed_rng(&[0xAA; 32]);
    let (mut alice, evs) = CSptps::start(Role::Initiator, Framing::Stream, &ak1, &ak2, b"dribble");
    let alice_kex = sole_wire(evs);

    seed_rng(&[0xBB; 32]);
    let (mut bob, evs) = CSptps::start(Role::Responder, Framing::Stream, &bk1, &bk2, b"dribble");
    let bob_kex = sole_wire(evs);

    let evs = dribble(&mut alice, &bob_kex);
    let alice_sig = sole_wire(evs);

    let evs = dribble(&mut bob, &alice_kex);
    assert!(evs.is_empty());

    let evs = dribble(&mut bob, &alice_sig);
    assert_eq!(evs.len(), 2);
    let bob_sig = match &evs[0] {
        Event::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    assert!(matches!(evs[1], Event::HandshakeDone));

    let evs = dribble(&mut alice, &bob_sig);
    assert_eq!(evs, vec![Event::HandshakeDone]);
}

#[test]
fn datagram_handshake_c_to_c() {
    let _g = serial_guard();
    // Datagram differs in framing (4-byte seqno prefix instead of 2-byte
    // length) and in the receive path (sptps_receive_data_datagram is its
    // own function, no reassembly). Handshake state machine is identical.

    let (alice_priv, alice_pub) = keypair(3);
    let (bob_priv, bob_pub) = keypair(4);

    let ak1 = CKey::from_private_blob(&alice_priv);
    let ak2 = CKey::from_public(&bob_pub);
    let bk1 = CKey::from_private_blob(&bob_priv);
    let bk2 = CKey::from_public(&alice_pub);

    seed_rng(&[0xCC; 32]);
    let (mut alice, evs) = CSptps::start(Role::Initiator, Framing::Datagram, &ak1, &ak2, b"dgram");
    let alice_kex = sole_wire(evs);
    assert_eq!(alice_kex.len(), DGRAM_KEX_LEN);
    // Datagram framing: 4-byte BE seqno, then type, then body. First record
    // out → seqno 0.
    assert_eq!(&alice_kex[..5], &[0, 0, 0, 0, SPTPS_HANDSHAKE]);

    seed_rng(&[0xDD; 32]);
    let (mut bob, evs) = CSptps::start(Role::Responder, Framing::Datagram, &bk1, &bk2, b"dgram");
    let bob_kex = sole_wire(evs);
    assert_eq!(&bob_kex[..5], &[0, 0, 0, 0, SPTPS_HANDSHAKE]);

    let (_, evs) = alice.receive(&bob_kex);
    let alice_sig = sole_wire(evs);
    assert_eq!(alice_sig.len(), DGRAM_SIG_LEN);
    // Second record out → seqno 1.
    assert_eq!(&alice_sig[..5], &[0, 0, 0, 1, SPTPS_HANDSHAKE]);

    let (_, evs) = bob.receive(&alice_kex);
    assert!(evs.is_empty());

    let (_, evs) = bob.receive(&alice_sig);
    assert_eq!(evs.len(), 2);
    let bob_sig = match &evs[0] {
        Event::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    assert!(matches!(evs[1], Event::HandshakeDone));

    let (_, evs) = alice.receive(&bob_sig);
    assert_eq!(evs, vec![Event::HandshakeDone]);

    // App data over datagram.
    let msg = b"via udp";
    let evs = alice.send_record(0, msg);
    let ct = sole_wire_app(evs);
    // Datagram encrypted: seqno[4] + chacha-poly(type[1] + body) + tag[16].
    // SPTPS_DATAGRAM_OVERHEAD = 21 = 4 + 1 + 16. Plus body.
    assert_eq!(ct.len(), 4 + 1 + msg.len() + 16);
    // Third record out → seqno 2.
    assert_eq!(&ct[..4], &[0, 0, 0, 2]);

    let (_, evs) = bob.receive(&ct);
    assert_eq!(
        evs,
        vec![Event::Record {
            record_type: 0,
            bytes: msg.to_vec()
        }]
    );
}

#[test]
fn handshake_is_deterministic_under_same_seeds() {
    let _g = serial_guard();
    // The whole point of the harness: same inputs → same wire bytes.
    // If this test ever flakes, the harness is useless as a Phase 2 oracle.

    #[allow(clippy::items_after_statements)] // local helper, clearer inline
    fn run() -> Vec<Vec<u8>> {
        let (alice_priv, alice_pub) = keypair(1);
        let (bob_priv, bob_pub) = keypair(2);
        let ak1 = CKey::from_private_blob(&alice_priv);
        let ak2 = CKey::from_public(&bob_pub);
        let bk1 = CKey::from_private_blob(&bob_priv);
        let bk2 = CKey::from_public(&alice_pub);

        seed_rng(&[0x11; 32]);
        let (mut alice, e) = CSptps::start(Role::Initiator, Framing::Stream, &ak1, &ak2, b"det");
        let kex_a = sole_wire(e);
        seed_rng(&[0x22; 32]);
        let (mut bob, e) = CSptps::start(Role::Responder, Framing::Stream, &bk1, &bk2, b"det");
        let kex_b = sole_wire(e);

        let (_, e) = alice.receive(&kex_b);
        let sig_a = sole_wire(e);
        let (_, e) = bob.receive(&kex_a);
        assert!(e.is_empty());
        let (_, e) = bob.receive(&sig_a);
        let sig_b = match &e[0] {
            Event::Wire { bytes, .. } => bytes.clone(),
            _ => panic!(),
        };

        // Also send one app record so we exercise the encrypted path's
        // determinism (which depends on the PRF output being identical,
        // not just the plaintext handshake records).
        let (_, e) = alice.receive(&sig_b);
        assert_eq!(e, vec![Event::HandshakeDone]);
        let e = alice.send_record(0, b"ping");
        let app = sole_wire_app(e);

        vec![kex_a, kex_b, sig_a, sig_b, app]
    }

    let first = run();
    let second = run();
    assert_eq!(
        first, second,
        "identical seeds must produce identical wire bytes"
    );
}

#[test]
fn handshake_fails_on_wrong_peer_key() {
    let _g = serial_guard();
    // Basic auth check: if Bob has the wrong key for Alice, the SIG verify
    // fails. sptps_receive_data returns 0 (the `error()` macro returns
    // `false`, which the size_t return path treats as 0). No events.
    //
    // This is a harness sanity check, not a security test — the security
    // claim is established by the KAT suite proving `verify` matches.

    let (alice_priv, _alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);
    let (_, mallory_pub) = keypair(99); // Bob *thinks* he's talking to Mallory

    let ak1 = CKey::from_private_blob(&alice_priv);
    let ak2 = CKey::from_public(&bob_pub);
    let bk1 = CKey::from_private_blob(&bob_priv);
    let bk2 = CKey::from_public(&mallory_pub); // wrong!

    seed_rng(&[0xEE; 32]);
    let (mut alice, e) = CSptps::start(Role::Initiator, Framing::Stream, &ak1, &ak2, b"auth");
    let alice_kex = sole_wire(e);
    seed_rng(&[0xFF; 32]);
    let (mut bob, e) = CSptps::start(Role::Responder, Framing::Stream, &bk1, &bk2, b"auth");
    let bob_kex = sole_wire(e);

    let (_, e) = alice.receive(&bob_kex);
    let alice_sig = sole_wire(e);
    let (_, e) = bob.receive(&alice_kex);
    assert!(e.is_empty());

    // Here's the failure: Bob tries to verify Alice's SIG against
    // Mallory's pubkey. ecdsa_verify returns false → receive_sig
    // returns false → receive_data returns 0.
    let (n, e) = bob.receive(&alice_sig);
    assert_eq!(n, 0, "verify failure surfaces as zero bytes consumed");
    assert!(e.is_empty(), "no events on auth failure");
}

#[test]
#[allow(clippy::similar_names)] // kex_a2/kex_b2, sig_a2/sig_b2: rekey round-2 vs round-1
fn rekey_uses_ack_state() {
    let _g = serial_guard();
    // Re-KEX after the initial handshake exercises a different state
    // transition: SPTPS_ACK is only reachable when outstate was already
    // true (see receive_handshake). The initial handshake skips it via
    // a synthetic receive_ack. Phase 2's Rust state machine has to get
    // both paths right; this test is the oracle for the second one.

    let (alice_priv, alice_pub) = keypair(1);
    let (bob_priv, bob_pub) = keypair(2);
    let ak1 = CKey::from_private_blob(&alice_priv);
    let ak2 = CKey::from_public(&bob_pub);
    let bk1 = CKey::from_private_blob(&bob_priv);
    let bk2 = CKey::from_public(&alice_pub);

    // ─── Initial handshake (compressed; tested above) ───
    seed_rng(&[1; 32]);
    let (mut alice, e) = CSptps::start(Role::Initiator, Framing::Stream, &ak1, &ak2, b"rekey");
    let kex_a = sole_wire(e);
    seed_rng(&[2; 32]);
    let (mut bob, e) = CSptps::start(Role::Responder, Framing::Stream, &bk1, &bk2, b"rekey");
    let kex_b = sole_wire(e);
    let (_, e) = alice.receive(&kex_b);
    let sig_a = sole_wire(e);
    let (_, _) = bob.receive(&kex_a);
    let (_, e) = bob.receive(&sig_a);
    let sig_b = match &e[0] {
        Event::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    let (_, _) = alice.receive(&sig_b);

    // ─── Re-KEX ───
    // force_kex sends a new KEX. This time it's *encrypted* (outstate=true).
    seed_rng(&[3; 32]); // fresh randomness for the new ephemeral
    let e = alice.force_kex();
    let kex_a2 = sole_wire(e);
    // Encrypted KEX: len[2] + chacha-poly(type[1] + body[65]) + tag[16].
    // Length field is body length (65), wire is 2 + 66 + 16.
    assert_eq!(kex_a2.len(), 2 + 1 + 65 + 16);
    assert_eq!(&kex_a2[..2], &[0, 65]);

    // Bob is in SECONDARY_KEX state. receive_handshake's switch hits that
    // case first: send_kex (Bob's new KEX), then fall-through to the KEX
    // case which does receive_kex. So one Wire event out.
    seed_rng(&[4; 32]);
    let (_, e) = bob.receive(&kex_a2);
    let kex_b2 = sole_wire(e);
    assert_eq!(kex_b2.len(), 2 + 1 + 65 + 16);

    // Alice gets Bob's KEX. She's in SPTPS_KEX (force_kex set that).
    // receive_kex → because she's initiator → send_sig. Encrypted now.
    let (_, e) = alice.receive(&kex_b2);
    let sig_a2 = sole_wire(e);
    assert_eq!(sig_a2.len(), 2 + 1 + 64 + 16);

    // Bob gets Alice's SIG. receive_sig: verify, ECDH, PRF, send_sig
    // (responder), and because outstate=true, also send_ack. Then state
    // → SPTPS_ACK (not the synthetic-ack path this time).
    let (_, e) = bob.receive(&sig_a2);
    // Three events here, not two: SIG, ACK, and... actually wait. Let's
    // trace it precisely. receive_sig with outstate=true:
    //   - verify ok
    //   - ECDH → PRF → outcipher set with NEW key
    //   - !initiator → send_sig (encrypted with NEW key... no wait.
    //     outcipher is set at the end of receive_sig. send_sig uses
    //     send_record_priv which checks outstate, which was already true.
    //     So SIG is encrypted with the OLD key. This matters for Phase 2.)
    //   - outstate was already true → send_ack (encrypted with... the
    //     NEW key now, since chacha_poly1305_set_key already ran. But
    //     wait, send_ack comes BEFORE the set_key call. Let me re-read.)
    //
    // Reading receive_sig more carefully:
    //   send_sig(s)             ← uses old outcipher (outstate already true)
    //   if(outstate) send_ack() ← STILL uses old outcipher
    //   chacha_poly1305_set_key(outcipher, new_key)  ← only NOW switches
    //
    // So both SIG and ACK go out under the old key. The new key takes
    // effect for the NEXT record. Then state → SPTPS_ACK (in
    // receive_handshake). No HandshakeDone yet — that fires on the
    // received ACK, in the SPTPS_ACK case.
    assert_eq!(e.len(), 2, "responder rekey: SIG + ACK, both under old key");
    let sig_b2 = match &e[0] {
        Event::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    let ack_b = match &e[1] {
        Event::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };
    // ACK is an empty body. Encrypted: len[2]=0 + chacha-poly(type[1]) + tag.
    // The +0 spelled out below is the body length — the formula shape is the
    // same as every other length assertion in this file, just with body=0.
    #[allow(clippy::identity_op)] // +0 is the body length: keeps the formula shape uniform
    {
        assert_eq!(ack_b.len(), 2 + 1 + 0 + 16);
    }
    assert_eq!(&ack_b[..2], &[0, 0]);

    // Alice gets Bob's SIG. She's the initiator so receive_sig DOESN'T
    // send_sig. Because outstate=true, she does send_ack. State → SPTPS_ACK.
    let (_, e) = alice.receive(&sig_b2);
    assert_eq!(e.len(), 1, "initiator rekey: just ACK out");
    let ack_a = match &e[0] {
        Event::Wire { bytes, .. } => bytes.clone(),
        _ => panic!(),
    };

    // Now both sides are in SPTPS_ACK. Feed each the other's ACK.
    // receive_ack swaps the incipher to the new key, then receive_handshake
    // fires HandshakeDone and goes back to SECONDARY_KEX.
    let (_, e) = bob.receive(&ack_a);
    assert_eq!(e, vec![Event::HandshakeDone]);
    let (_, e) = alice.receive(&ack_b);
    assert_eq!(e, vec![Event::HandshakeDone]);

    // App traffic still works under the new keys.
    let e = alice.send_record(0, b"after rekey");
    let ct = sole_wire_app(e);
    let (_, e) = bob.receive(&ct);
    assert_eq!(
        e,
        vec![Event::Record {
            record_type: 0,
            bytes: b"after rekey".to_vec()
        }]
    );
}
