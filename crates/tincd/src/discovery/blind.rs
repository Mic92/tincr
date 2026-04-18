//! Tor-v3-style ed25519 key blinding + SHAKE256 KDF for the BEP 44
//! publish/resolve path.
//!
//! Reference: Tor rend-spec-v3 §A.2 [KEYBLIND] and §2.2.1; Arti
//! `tor-hscrypto/src/pk.rs` (`HsBlindKeypair`). The math is the same
//! (h·A on the curve, h·a mod ℓ on the scalar); the hash inputs are
//! ours (no Tor `BLIND_STRING` / credential layering — we just need
//! "different daily key, derivable from the long-term pk").
//!
//! All hashing in this module is SHA-3/SHAKE by design — see
//! `crates/tincd/Cargo.toml` for the rationale (future SPTPS-KDF
//! migration to SHAKE can drop `hkdf` entirely if nothing else
//! anchors on SHA-2). The *internal* SHA-512 inside `raw_sign` stays
//! — that's RFC 8032's choice, fixed by ed25519 itself.

#![forbid(unsafe_code)]

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use sha2::Sha512;
use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Shake256};

use tinc_crypto::sign::SigningKey;

/// Domain-separation string. Fed into both the blinding-scalar hash
/// and the SHAKE derive.
pub const N: &[u8] = b"tinc-dht-blind-v1";

/// Daily epoch, UTC. Tor uses a configurable `hsdir-interval`
/// (default 1440 min); we hard-code one day. Re-publish interval is
/// 5 min, old-period record expires from the DHT in ~2h, so a reader
/// near UTC midnight tries `period` then `period-1`.
pub const PERIOD_SECS: u64 = 86_400;

/// `floor(unix_time / 86400)`. Monotone in wall-clock; a backwards
/// clock step can decrement it, which just republishes under
/// yesterday's key — readers' `period-1` fallback covers that.
#[must_use]
pub fn current_period() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        / PERIOD_SECS
}

/// `h = SHA3-256(N ‖ pk ‖ period_be8)` clamped + reduced mod ℓ.
///
/// Clamp mirrors Tor (rend-spec-v3 §A.2). It does *not* survive the
/// mod-ℓ reduction as a cofactor-clear (ℓ is odd) — we rely on `A`
/// being prime-order already, which any basepoint-derived key is.
/// What the clamp *does* buy: bit 254 set ⇒ input ∈ [2²⁵⁴, 2²⁵⁵), so
/// the reduced scalar is never 0 ⇒ `blind_pk` is never the identity.
fn blinding_scalar(pk: &[u8; 32], period: u64) -> Scalar {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, N);
    Digest::update(&mut h, pk);
    Digest::update(&mut h, period.to_be_bytes());
    let out: [u8; 32] = h.finalize().into();
    Scalar::from_bytes_mod_order(clamp_integer(out))
}

/// `blind_pk = h · A`. Reader-side: anyone with `pk_A` (from
/// `hosts/NAME`) recomputes the *same* key the publisher signed
/// under. A DHT storer with only `blind_pk` would need ec DLOG to
/// recover `pk_A`.
///
/// Returns `None` iff `pk` is not a valid Edwards point encoding —
/// can't happen for a key that came out of `hosts/NAME` (it was
/// produced by basepoint-mul), but the type admits garbage.
#[must_use]
pub fn blind_public_key(pk: &[u8; 32], period: u64) -> Option<[u8; 32]> {
    let a = CompressedEdwardsY(*pk).decompress()?;
    let h = blinding_scalar(pk, period);
    Some((h * a).compress().to_bytes())
}

/// Blinded signer: signs BEP 44 records such that a stock
/// `ed25519_dalek::VerifyingKey::verify` against [`Self::public_key`]
/// accepts. mainline's `from_dht_message` does exactly that, so DHT
/// nodes store the put without ever seeing the long-term key.
pub struct BlindSigner {
    esk: ExpandedSecretKey,
    vk: VerifyingKey,
}

impl BlindSigner {
    /// Derive the period-`period` blinded keypair from `sk`.
    ///
    /// `scalar' = h · a mod ℓ` where `a` is the long-term secret
    /// scalar (the clamped low 32 bytes of the expanded key).
    /// `prefix' = SHA3-256(N ‖ "prefix" ‖ sk_prefix ‖ period_be8)` —
    /// a fresh nonce-prefix so two periods' signatures over the same
    /// message don't reuse `r`. Tor does the same (its `h[32..64]`).
    ///
    /// `blind_pk` is computed as `scalar' · G` rather than `h · A`:
    /// algebraically identical (`A = a·G`, `G` has prime order), and
    /// avoids a decompress that could fail on a malformed stored
    /// pubkey. The reader's `blind_public_key(pk, period)` reaches
    /// the same point from the other side.
    #[must_use]
    pub fn new(sk: &SigningKey, period: u64) -> Self {
        let pk = sk.public_key();
        let h = blinding_scalar(pk, period);
        let base = ExpandedSecretKey::from_bytes(sk.expanded_private());

        let mut pf = Sha3_256::new();
        Digest::update(&mut pf, N);
        Digest::update(&mut pf, b"prefix");
        Digest::update(&mut pf, &sk.expanded_private()[32..]);
        Digest::update(&mut pf, period.to_be_bytes());

        let esk = ExpandedSecretKey {
            scalar: h * base.scalar,
            hash_prefix: pf.finalize().into(),
        };
        let vk = VerifyingKey::from(EdwardsPoint::mul_base(&esk.scalar));
        Self { esk, vk }
    }

    /// Compressed blinded public key — what goes in BEP 44's `k`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }

    /// Standard RFC 8032 Ed25519 signature under the blinded key.
    /// `raw_sign`'s internal hash stays SHA-512 (the verify side is
    /// fixed); only the *key derivation* above is SHA-3.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        raw_sign::<Sha512>(&self.esk, msg, &self.vk).to_bytes()
    }
}

/// Per-period BEP 44 salt + AEAD key. Both flow from
/// `SHAKE256(N ‖ period_be8 ‖ pk_A ‖ DhtSecret)`.
///
/// - DHT storer: has `blind_pk` only → can't derive either.
/// - `hosts/`-repo reader, mesh sets no `DhtSecret`: has `pk_A` →
///   derives both → decrypts. Hidden from crawlers, not from anyone
///   with the (possibly public) host file. Mesh's choice.
/// - `hosts/`-repo reader, `DhtSecret` set: missing the 32 bytes →
///   wrong salt (BEP 44 lookup misses) *and* wrong key.
#[derive(Clone)]
pub struct Derived {
    pub salt: [u8; 16],
    pub aead_key: [u8; 32],
}

/// Squeeze 48 bytes from SHAKE256. Single-call XOF: simpler than
/// HKDF (no extract/expand split, no separate `info` per output) and
/// keeps this module SHA-3-only.
#[must_use]
pub fn derive(pk: &[u8; 32], secret: Option<&[u8; 32]>, period: u64) -> Derived {
    let mut x = Shake256::default();
    x.update(N);
    x.update(&period.to_be_bytes());
    x.update(pk);
    if let Some(s) = secret {
        x.update(s);
    }
    let mut okm = [0u8; 48];
    x.finalize_xof().read(&mut okm);
    let mut salt = [0u8; 16];
    let mut aead_key = [0u8; 32];
    salt.copy_from_slice(&okm[..16]);
    aead_key.copy_from_slice(&okm[16..]);
    Derived { salt, aead_key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// The load-bearing property: a stock dalek `verify()` (what
    /// mainline's `from_dht_message` calls) accepts a signature made
    /// by `BlindSigner`, against the key a *reader* derives via
    /// `blind_public_key`. If this fails, fall back to the
    /// per-period ephemeral-seed scheme (see commit body).
    #[test]
    fn blind_sign_verify_roundtrip() {
        let sk = SigningKey::from_seed(&[7u8; 32]);
        let period = 12_345;

        let signer = BlindSigner::new(&sk, period);
        let reader_pk = blind_public_key(sk.public_key(), period).expect("valid pk");
        // Signer's `(h·a)·G` == reader's `h·A`: the two derivation
        // paths meet. This is *the* interop seam.
        assert_eq!(signer.public_key(), reader_pk);

        let msg = b"4:salt16:................3:seqi1e1:v3:foo";
        let sig = signer.sign(msg);
        let vk = VerifyingKey::from_bytes(&reader_pk).unwrap();
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("blind signature must verify under blind_pk");

        // Unlinkable across periods (different h).
        let next = blind_public_key(sk.public_key(), period + 1).unwrap();
        assert_ne!(reader_pk, next);
        // And neither is the long-term key (recovering pk_A would
        // need DLOG; ≠ is the most a unit test can say).
        assert_ne!(reader_pk, *sk.public_key());
        assert_ne!(next, *sk.public_key());
    }

    /// Known-answer pin. If someone swaps SHA3-256→SHA-256 or
    /// SHAKE256→SHAKE128 "for consistency", this trips. Values
    /// captured from the implementation above; the *contract* is
    /// "matches every other node running this code", not an external
    /// spec, so a self-generated KAT is the right pin.
    #[test]
    fn kat_pin() {
        let pk = *SigningKey::from_seed(&[7u8; 32]).public_key();
        let blind = blind_public_key(&pk, 20_000).unwrap();
        let d = derive(&pk, Some(&[0x42u8; 32]), 20_000);
        // secret=None is a distinct code path (the `if let Some` in
        // `derive`); pin its salt too so dropping the branch trips.
        let d0 = derive(&pk, None, 20_000);
        assert_eq!(
            hex(&blind),
            "b2127ebe1f03803aa3aa2e371c7ff18ac3c7780ca5d728ba04377dcdd3531db4",
            "blind_public_key KAT drift"
        );
        assert_eq!(
            hex(&d.salt),
            "889a0625af3b2e88fe2e906995190672",
            "SHAKE256 salt KAT drift"
        );
        assert_eq!(
            hex(&d.aead_key),
            "6385283d6170790c583e4c8d5a4d27872b3b728f149000bac91a64a5f4cce40f",
            "SHAKE256 aead_key KAT drift"
        );
        assert_eq!(
            hex(&d0.salt),
            "3a43ac3824b6c3319ccb01284d013c0c",
            "SHAKE256 secret=None KAT drift"
        );
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }
}
