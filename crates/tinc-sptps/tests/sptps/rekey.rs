//! In-band rekey (`force_kex`) for both KEX modes and framings. Against
//! C this is covered by `vs_c.rs`; here the hybrid variants, which C
//! does not speak.

use crate::common::{NoRng, Pair, SeedRng, feed, pump, record, wire, wires};
use tinc_sptps::{Framing, Sptps, SptpsKex};

fn rekey(alice: &mut Sptps, bob: &mut Sptps) {
    let kex = wires(alice.force_kex(&mut SeedRng(0xFE)).unwrap());
    pump(alice, bob, kex, Vec::new()).unwrap();
}

fn roundtrip(pair: &Pair) {
    let (mut alice, mut bob) = pair.handshake();
    let old_key = alice.outcipher_key();
    assert_eq!(
        record(feed(&mut bob, &wire(alice.send_record(0, b"one").unwrap())).unwrap()),
        (0, b"one".to_vec())
    );
    rekey(&mut alice, &mut bob);
    assert_ne!(alice.outcipher_key(), old_key);
    assert_eq!(alice.outcipher_key(), bob.incipher_key());
    assert_eq!(
        record(feed(&mut bob, &wire(alice.send_record(0, b"two").unwrap())).unwrap()),
        (0, b"two".to_vec())
    );
    assert_eq!(
        record(feed(&mut alice, &wire(bob.send_record(0, b"three").unwrap())).unwrap()),
        (0, b"three".to_vec())
    );
}

#[test]
fn rekey_roundtrip_all_modes() {
    for framing in [Framing::Datagram, Framing::Stream] {
        for kex in [SptpsKex::X25519, SptpsKex::X25519MlKem768] {
            roundtrip(&Pair::new(framing, b"rekey").kex(kex));
        }
    }
}

/// The message sequence of a hybrid rekey, spelled out: SIG and ACK go
/// out under the *old* cipher, `HandshakeDone` only after both ACKs.
#[test]
fn hybrid_rekey_message_order() {
    let (mut alice, mut bob) = Pair::datagram().kex(SptpsKex::X25519MlKem768).handshake();
    let mut rng = SeedRng(0xCAFE);
    let kex_a = wire(alice.force_kex(&mut rng).unwrap());
    let kex_b = wire(bob.receive(&kex_a, &mut rng).unwrap().1);
    let sig_a = wire(alice.receive(&kex_b, &mut rng).unwrap().1);
    let from_bob = wires(bob.receive(&sig_a, &mut rng).unwrap().1);
    assert_eq!(from_bob.len(), 2, "SIG + ACK");
    let ack_a = wire(alice.receive(&from_bob[0], &mut rng).unwrap().1);
    alice.receive(&from_bob[1], &mut rng).unwrap();
    bob.receive(&ack_a, &mut rng).unwrap();

    let (_, outs) = bob
        .receive(&wire(alice.send_record(0, b"after").unwrap()), &mut NoRng)
        .unwrap();
    assert_eq!(record(outs), (0, b"after".to_vec()));
}
