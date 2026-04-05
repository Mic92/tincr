//! Fixtures shared across the integration-test crates. Cargo compiles
//! each `tests/*.rs` as a separate crate, so this lives in a directory
//! and gets `mod common;`-ed into each.

#![allow(dead_code)]

use rand_core::RngCore;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps};

pub const REPLAYWIN: usize = 16;

pub fn keypair(tag: u8) -> (SigningKey, [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    let sk = SigningKey::from_seed(&seed);
    let pk = *sk.public_key();
    (sk, pk)
}

/// PCG-ish PRNG. Deterministic from seed; the SPTPS RNG only seeds
/// nonces and ECDH so crypto quality doesn't matter.
pub struct SeedRng(pub u64);
#[allow(clippy::cast_possible_truncation)] // intentional: PRNG output truncation
impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub fn wire(mut outs: Vec<Output>) -> Vec<u8> {
    match outs.remove(0) {
        Output::Wire { bytes, .. } => bytes,
        o => panic!("expected Wire, got {o:?}"),
    }
}

pub fn wire_only(outs: &[Output]) -> Vec<Vec<u8>> {
    outs.iter()
        .filter_map(|o| match o {
            Output::Wire { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// Feed `bytes` to a stream-mode session, looping until drained
/// (stream `receive` consumes at most one record per call).
pub fn feed_stream(sptps: &mut Sptps, bytes: &[u8]) -> Vec<Output> {
    let mut rng = SeedRng(0);
    let mut all = Vec::new();
    let mut off = 0;
    while off < bytes.len() {
        let (n, outs) = sptps.receive(&bytes[off..], &mut rng).unwrap();
        if n == 0 {
            break;
        }
        off += n;
        all.extend(outs);
    }
    all
}

/// Run handshake to completion. Works for both framings — `feed_stream`
/// loops, datagram consumes the whole buffer in one call.
pub fn handshake_pair(framing: Framing, label: &[u8]) -> (Sptps, Sptps) {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);

    let (mut alice, a0) = Sptps::start(
        Role::Initiator,
        framing,
        akey,
        bpub,
        label.to_vec(),
        REPLAYWIN,
        &mut SeedRng(0xAA),
    );
    let (mut bob, b0) = Sptps::start(
        Role::Responder,
        framing,
        bkey,
        apub,
        label.to_vec(),
        REPLAYWIN,
        &mut SeedRng(0xBB),
    );

    let kex_a = wire(a0);
    let kex_b = wire(b0);

    let sig_a = wire(feed_stream(&mut alice, &kex_b));
    feed_stream(&mut bob, &kex_a);
    let sig_b = wire(feed_stream(&mut bob, &sig_a));
    feed_stream(&mut alice, &sig_b);

    (alice, bob)
}
