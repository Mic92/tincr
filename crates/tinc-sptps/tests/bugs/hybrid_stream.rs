//! Bug-hunt probes for the 9d4e6158 hybrid key-confirmation round.
//! Both tests PASS on this branch — kept as positive coverage so a
//! later regression in Stream-mode hybrid or hybrid in-band rekey is
//! caught (neither path was exercised before; `hybrid_kex.rs` is
//! Datagram-only and never calls `force_kex`).

use crate::common::{SeedRng, feed_stream, keypair, wire_only};
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsKex};

fn pump(a: &mut Sptps, b: &mut Sptps, mut to_b: Vec<Vec<u8>>, mut to_a: Vec<Vec<u8>>) {
    let mut rng = SeedRng(0xC0DE);
    let (mut a_done, mut b_done) = (false, false);
    for _ in 0..16 {
        for w in to_a.drain(..) {
            let (_, outs) = a.receive(&w, &mut rng).expect("a recv");
            for o in outs {
                match o {
                    Output::Wire { bytes, .. } => to_b.push(bytes),
                    Output::HandshakeDone => a_done = true,
                    Output::Record { .. } => {}
                }
            }
        }
        for w in to_b.drain(..) {
            let (_, outs) = b.receive(&w, &mut rng).expect("b recv");
            for o in outs {
                match o {
                    Output::Wire { bytes, .. } => to_a.push(bytes),
                    Output::HandshakeDone => b_done = true,
                    Output::Record { .. } => {}
                }
            }
        }
        if to_a.is_empty() && to_b.is_empty() {
            break;
        }
    }
    assert!(a_done && b_done, "handshake did not complete");
}

fn hybrid_pair(framing: Framing) -> (Sptps, Sptps) {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);
    let (mut alice, a0) = Sptps::start_with(
        Role::Initiator,
        framing,
        SptpsKex::X25519MlKem768,
        akey,
        bpub,
        b"hybrid rekey",
        16,
        &mut SeedRng(0xAA),
    );
    let (mut bob, b0) = Sptps::start_with(
        Role::Responder,
        framing,
        SptpsKex::X25519MlKem768,
        bkey,
        apub,
        b"hybrid rekey",
        16,
        &mut SeedRng(0xBB),
    );
    pump(&mut alice, &mut bob, wire_only(&a0), wire_only(&b0));
    (alice, bob)
}

#[test]
fn hybrid_stream_handshake_completes() {
    let (mut alice, mut bob) = hybrid_pair(Framing::Stream);
    let pkt = wire_only(&alice.send_record(0, b"hi").unwrap()).concat();
    let outs = feed_stream(&mut bob, &pkt);
    assert!(matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"hi"));
}

#[test]
fn hybrid_datagram_force_kex_roundtrip() {
    let (mut alice, mut bob) = hybrid_pair(Framing::Datagram);

    let pkt = wire_only(&alice.send_record(0, b"one").unwrap());
    let (_, outs) = bob.receive(&pkt[0], &mut SeedRng(0)).unwrap();
    assert!(matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"one"));

    let outs = alice.force_kex(&mut SeedRng(0xFE)).expect("force_kex");
    pump(&mut alice, &mut bob, wire_only(&outs), Vec::new());

    let pkt = wire_only(&alice.send_record(0, b"two").unwrap());
    let (_, outs) = bob.receive(&pkt[0], &mut SeedRng(0)).unwrap();
    assert!(
        matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"two"),
        "bob post-rekey: {outs:?}"
    );
    let pkt = wire_only(&bob.send_record(0, b"three").unwrap());
    let (_, outs) = alice.receive(&pkt[0], &mut SeedRng(0)).unwrap();
    assert!(
        matches!(&outs[0], Output::Record { bytes, .. } if bytes == b"three"),
        "alice post-rekey: {outs:?}"
    );
}
