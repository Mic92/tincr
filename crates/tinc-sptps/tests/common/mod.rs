//! Fixtures shared across the integration-test crates. Cargo compiles
//! each `tests/*.rs` as a separate crate, so this lives in a directory
//! and gets `mod common;`-ed into each.

#![allow(dead_code)]

use rand_core::{Infallible, TryCryptoRng, TryRng};
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsAead, SptpsLabel};

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
// Test-only marker: not crypto-grade, drives deterministic fixtures.
// `Rng`/`CryptoRng` arrive via rand_core's blanket impls over
// infallible `TryRng`/`TryCryptoRng`.
impl TryCryptoRng for SeedRng {}
impl TryRng for SeedRng {
    type Error = Infallible;
    #[expect(clippy::cast_possible_truncation)] // intentional: PRNG output truncation
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
    #[expect(clippy::cast_possible_truncation)] // intentional: PRNG output truncation
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for b in dest {
            *b = self.try_next_u64()? as u8;
        }
        Ok(())
    }
}

/// RNG that panics on use. For `receive` calls that must not reach
/// `send_kex` — if they do, the panic surfaces the routing bug.
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
    feed_stream_try(sptps, bytes).unwrap()
}

/// As [`feed_stream`] but propagates `receive` errors instead of
/// panicking. The AEAD-mismatch test wants to observe the `BadSig`.
pub fn feed_stream_try(
    sptps: &mut Sptps,
    bytes: &[u8],
) -> Result<Vec<Output>, tinc_sptps::SptpsError> {
    let mut rng = SeedRng(0);
    let mut all = Vec::new();
    let mut off = 0;
    while off < bytes.len() {
        let (n, outs) = sptps.receive(&bytes[off..], &mut rng)?;
        if n == 0 {
            break;
        }
        off += n;
        all.extend(outs);
    }
    Ok(all)
}

/// Run handshake to completion. Works for both framings — `feed_stream`
/// loops, datagram consumes the whole buffer in one call.
pub fn handshake_pair(framing: Framing, label: &[u8]) -> (Sptps, Sptps) {
    handshake_pair_aead(framing, label, SptpsAead::default(), SptpsAead::default())
        .expect("default-aead handshake never BadSig's against itself")
}

/// As [`handshake_pair`] but with per-side AEAD selection. Returns
/// `Err` if the handshake itself fails — used by the AEAD-mismatch
/// test, which wants exactly that.
pub fn handshake_pair_aead(
    framing: Framing,
    label: &[u8],
    a_aead: SptpsAead,
    b_aead: SptpsAead,
) -> Result<(Sptps, Sptps), tinc_sptps::SptpsError> {
    let (akey, apub) = keypair(1);
    let (bkey, bpub) = keypair(2);

    let (mut alice, a0) = Sptps::start(
        Role::Initiator,
        framing,
        akey,
        bpub,
        SptpsLabel::with_aead(label, a_aead),
        REPLAYWIN,
        &mut SeedRng(0xAA),
    );
    let (mut bob, b0) = Sptps::start(
        Role::Responder,
        framing,
        bkey,
        apub,
        SptpsLabel::with_aead(label, b_aead),
        REPLAYWIN,
        &mut SeedRng(0xBB),
    );

    let kex_a = wire(a0);
    let kex_b = wire(b0);

    let sig_a = wire(feed_stream_try(&mut alice, &kex_b)?);
    feed_stream_try(&mut bob, &kex_a)?;
    let sig_b = wire(feed_stream_try(&mut bob, &sig_a)?);
    feed_stream_try(&mut alice, &sig_b)?;

    Ok((alice, bob))
}
