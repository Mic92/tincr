//! Fixtures shared by the `sptps` and `vs_c` test binaries.

#![allow(
    clippy::allow_attributes,
    reason = "shared by several test binaries, each uses a subset"
)]
#![allow(dead_code)]

use rand_core::{Infallible, TryCryptoRng, TryRng};
use std::mem;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsAead, SptpsError, SptpsKex, SptpsLabel};

pub const REPLAYWIN: usize = 16;

/// Deterministic key from a one-byte tag. alice is 1, bob is 2.
pub fn keypair(tag: u8) -> (SigningKey, [u8; 32]) {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    let key = SigningKey::from_seed(&seed);
    let public = *key.public_key();
    (key, public)
}

/// PCG-ish PRNG. SPTPS only draws nonces and ephemeral keys from it, so
/// quality is irrelevant; determinism is the point.
pub struct SeedRng(pub u64);

impl TryCryptoRng for SeedRng {}
impl TryRng for SeedRng {
    type Error = Infallible;
    #[expect(clippy::cast_possible_truncation)]
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.try_next_u64().map(|x| x as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        Ok(self.0)
    }
    #[expect(clippy::cast_possible_truncation)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for byte in dest {
            *byte = self.try_next_u64()? as u8;
        }
        Ok(())
    }
}

/// Panics when touched: for `receive` calls that must not reach
/// `send_kex`.
pub struct NoRng;

impl TryCryptoRng for NoRng {}
impl TryRng for NoRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        panic!("RNG touched outside send_kex")
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("RNG touched outside send_kex")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        panic!("RNG touched outside send_kex")
    }
}

/// The single `Wire` in `outs`.
pub fn wire(outs: Vec<Output>) -> Vec<u8> {
    assert_eq!(outs.len(), 1, "expected one Wire, got {outs:?}");
    wires(outs).remove(0)
}

pub fn wires(outs: Vec<Output>) -> Vec<Vec<u8>> {
    outs.into_iter()
        .filter_map(|out| match out {
            Output::Wire { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect()
}

/// The single application record in `outs`, as `(type, body)`.
pub fn record(outs: Vec<Output>) -> (u8, Vec<u8>) {
    assert_eq!(outs.len(), 1, "expected one Record, got {outs:?}");
    match outs.into_iter().next().unwrap() {
        Output::Record { record_type, bytes } => (record_type, bytes),
        out => panic!("expected Record, got {out:?}"),
    }
}

/// Feed all of `bytes`, looping because stream-mode `receive` takes at
/// most one record per call (datagram mode takes everything at once).
pub fn feed(sptps: &mut Sptps, bytes: &[u8]) -> Result<Vec<Output>, SptpsError> {
    let mut rng = SeedRng(0);
    let mut outs = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (taken, out) = sptps.receive(&bytes[offset..], &mut rng)?;
        if taken == 0 {
            break;
        }
        offset += taken;
        outs.extend(out);
    }
    Ok(outs)
}

/// Shuttle wire outputs back and forth until both queues drain;
/// asserts both sides reported `HandshakeDone`.
pub fn pump(
    alice: &mut Sptps,
    bob: &mut Sptps,
    mut to_bob: Vec<Vec<u8>>,
    mut to_alice: Vec<Vec<u8>>,
) -> Result<(), SptpsError> {
    let (mut alice_done, mut bob_done) = (false, false);
    for _ in 0..16 {
        for bytes in mem::take(&mut to_bob) {
            let outs = feed(bob, &bytes)?;
            bob_done |= outs.contains(&Output::HandshakeDone);
            to_alice.extend(wires(outs));
        }
        for bytes in mem::take(&mut to_alice) {
            let outs = feed(alice, &bytes)?;
            alice_done |= outs.contains(&Output::HandshakeDone);
            to_bob.extend(wires(outs));
        }
        if to_alice.is_empty() && to_bob.is_empty() {
            break;
        }
    }
    assert!(alice_done && bob_done, "handshake did not complete");
    Ok(())
}

/// alice (initiator, key 1) and bob (responder, key 2) with matching
/// parameters unless overridden per side.
#[derive(Clone)]
pub struct Pair {
    pub framing: Framing,
    pub label: Vec<u8>,
    pub kex: (SptpsKex, SptpsKex),
    pub aead: (SptpsAead, SptpsAead),
    pub seeds: (u64, u64),
    pub replaywin: usize,
}

impl Pair {
    pub fn new(framing: Framing, label: &[u8]) -> Self {
        Self {
            framing,
            label: label.to_vec(),
            kex: (SptpsKex::default(), SptpsKex::default()),
            aead: (SptpsAead::default(), SptpsAead::default()),
            seeds: (0xAA, 0xBB),
            replaywin: REPLAYWIN,
        }
    }

    pub fn datagram() -> Self {
        Self::new(Framing::Datagram, b"test")
    }

    pub fn stream() -> Self {
        Self::new(Framing::Stream, b"test")
    }

    #[must_use]
    pub fn kex(mut self, kex: SptpsKex) -> Self {
        self.kex = (kex, kex);
        self
    }

    #[must_use]
    pub fn aead(mut self, aead: SptpsAead) -> Self {
        self.aead = (aead, aead);
        self
    }

    /// Both sessions plus their initial KEX records, nothing exchanged.
    pub fn start(&self) -> (Sptps, Sptps, Vec<u8>, Vec<u8>) {
        let (alice_key, alice_public) = keypair(1);
        let (bob_key, bob_public) = keypair(2);
        let (alice, from_alice) = Sptps::start_with(
            Role::Initiator,
            self.framing,
            self.kex.0,
            alice_key,
            bob_public,
            SptpsLabel::with_aead(self.label.clone(), self.aead.0),
            self.replaywin,
            &mut SeedRng(self.seeds.0),
        );
        let (bob, from_bob) = Sptps::start_with(
            Role::Responder,
            self.framing,
            self.kex.1,
            bob_key,
            alice_public,
            SptpsLabel::with_aead(self.label.clone(), self.aead.1),
            self.replaywin,
            &mut SeedRng(self.seeds.1),
        );
        (alice, bob, wire(from_alice), wire(from_bob))
    }

    /// Handshake run to `HandshakeDone` on both sides, or the first
    /// `receive` error.
    pub fn try_handshake(&self) -> Result<(Sptps, Sptps), SptpsError> {
        let (mut alice, mut bob, alice_kex, bob_kex) = self.start();
        pump(&mut alice, &mut bob, vec![alice_kex], vec![bob_kex])?;
        Ok((alice, bob))
    }

    pub fn handshake(&self) -> (Sptps, Sptps) {
        self.try_handshake().expect("handshake")
    }

    /// Only the responder, pre-handshake: what an unauthenticated peer
    /// talks to.
    pub fn responder(&self) -> Sptps {
        self.start().1
    }
}
