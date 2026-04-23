//! Ed25519 signatures using tinc's expanded-key on-disk format.
//!
//! C reference: `src/ed25519/sign.c`, `src/ed25519/ecdsa.c`.
//!
//! The signature algorithm itself is bog-standard RFC 8032 Ed25519 — `sign.c`
//! is a faithful ref10 port. What's non-standard is the key handling:
//!
//! - On-disk private keys are the **64-byte expanded form** (`SHA-512(seed)`
//!   with the low 32 bytes clamped), not the 32-byte seed. The seed is gone.
//! - `ed25519-dalek::SigningKey` only accepts seeds, so we go through the
//!   crate's `hazmat` module which exposes the expanded-key path.
//!
//! There's also a verify-side concern: `verify.c` uses the standard cofactored
//! verification equation. `ed25519-dalek::VerifyingKey::verify` does the same.
//! `verify_strict` would *additionally* reject some malleable signatures the C
//! code accepts — fine for new protocols, wrong for interop.

use curve25519_dalek::scalar::clamp_integer;
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use zeroize::ZeroizeOnDrop;

/// Signature length: standard Ed25519, R ‖ S.
pub const SIG_LEN: usize = 64;

/// Public key length: a compressed Edwards point.
pub const PUBLIC_LEN: usize = 32;

/// tinc's on-disk key blob: 96 bytes inside its custom PEM-ish framing.
///
/// Layout (`ecdsa_t` in C): `private[64] ‖ public[32]`. We keep both halves
/// because signing needs both — the public key feeds into the
/// `H(R ‖ A ‖ M)` step. Re-deriving it from the expanded private would
/// require a basepoint mult, and there's no reason to redo that work when
/// the file already has it.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    expanded: [u8; 64],
    #[zeroize(skip)] // public key is, well, public
    public: [u8; PUBLIC_LEN],
}

/// Signature verification or key parsing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignError;

impl SigningKey {
    /// Load from the 96-byte on-disk blob (post-PEM-decode).
    ///
    /// No validation that `public` actually matches `expanded` — the C loader
    /// doesn't check either, and a mismatched pair just produces signatures
    /// that fail to verify. Garbage in, garbage out.
    #[must_use]
    pub fn from_blob(blob: &[u8; 96]) -> Self {
        let mut expanded = [0u8; 64];
        let mut public = [0u8; 32];
        expanded.copy_from_slice(&blob[..64]);
        public.copy_from_slice(&blob[64..]);
        Self { expanded, public }
    }

    /// Serialize back to the 96-byte on-disk layout.
    ///
    /// Round-trips with [`from_blob`](Self::from_blob). Used by the FFI
    /// harness to feed identical key material to the C side.
    #[must_use]
    pub fn to_blob(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..64].copy_from_slice(&self.expanded);
        out[64..].copy_from_slice(&self.public);
        out
    }

    /// The public key half. Same bytes that go on the wire in the KEX.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }

    /// Generate from a fresh seed.
    ///
    /// KAT use only — production keys come from disk via [`from_blob`].
    /// Mirrors `ed25519_create_keypair` exactly: SHA-512 the seed, clamp
    /// the low half, basepoint-multiply for the public key. The same
    /// function feeds both signing and ECDH in the C code, which is why
    /// the on-disk format works for both.
    ///
    /// [`from_blob`]: Self::from_blob
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut expanded: [u8; 64] = Sha512::digest(seed).into();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&expanded[..32]);
        expanded[..32].copy_from_slice(&clamp_integer(scalar));

        // dalek's SigningKey does this same expansion internally, so its
        // verifying key is bit-identical to what `ge_scalarmult_base`
        // produces — verified by the KAT suite.
        let public = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();

        Self { expanded, public }
    }

    /// The expanded private half, for serialisation.
    #[must_use]
    pub const fn expanded_private(&self) -> &[u8; 64] {
        &self.expanded
    }

    /// The public half, for serialisation and verification.
    #[must_use]
    pub const fn public(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }

    /// Sign a message.
    ///
    /// Produces the same 64-byte signature `ed25519_sign` would. The `hazmat`
    /// path is the *only* way to feed dalek an expanded key; the safe
    /// `SigningKey` API insists on the 32-byte seed, which we don't have.
    ///
    /// # Panics
    ///
    /// If `self.public` is not a valid Ed25519 point encoding. Keys built
    /// via [`from_seed`](Self::from_seed) are always valid; keys loaded
    /// via [`from_blob`](Self::from_blob) may not be, and will panic here
    /// rather than silently producing a signature against the wrong public
    /// key. (The C code would happily sign with garbage; we're stricter on
    /// purpose since a panic at key-load time is far better than a bad
    /// signature on the wire.)
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        // ExpandedSecretKey splits the 64 bytes into (scalar, hash_prefix)
        // exactly as `sign.c` does: scalar from low half, nonce-prefix from
        // high half. dalek re-clamps internally — idempotent on our input.
        let esk = ExpandedSecretKey::from_bytes(&self.expanded);

        // raw_sign needs the matching VerifyingKey for the H(R‖A‖M) step.
        let vk = VerifyingKey::from_bytes(&self.public)
            .expect("public key in SigningKey must be a valid Ed25519 point");

        raw_sign::<Sha512>(&esk, msg, &vk).to_bytes()
    }
}

/// Verify an Ed25519 signature.
///
/// `verify.c` uses the standard (cofactored, batch-compatible) equation.
///
/// Canonicality: the scalar `S` from the signature is reduced mod `L`
/// inside the verification equation rather than range-checked, and `R`
/// is not required to be the canonical encoding of its point. Non-
/// canonical signatures (e.g. `S ≥ L`, or alternate `R` encodings)
/// therefore VERIFY, matching ref10 and C tinc — confirmed against
/// Project Wycheproof vectors. This is deliberate: rejecting inputs
/// that a C peer accepts would be an interop divergence. It's not a
/// security issue here because tinc does not treat signatures as
/// identifiers or map keys; signature malleability doesn't create a
/// replay or confusion primitive in the meta-protocol or SPTPS.
///
/// # Errors
///
/// [`SignError`] if `public` is not a valid point encoding, or if the
/// signature does not verify. The two cases are deliberately conflated:
/// the caller's response (drop the connection) is the same either way.
pub fn verify(public: &[u8; PUBLIC_LEN], msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), SignError> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| SignError)?;
    let sig = Signature::from_bytes(sig);
    vk.verify(msg, &sig).map_err(|_| SignError)
}
