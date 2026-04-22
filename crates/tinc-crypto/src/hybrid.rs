//! Hybrid X25519 + ML-KEM-768 key encapsulation for SPTPS.
//!
//! Harvest-now-decrypt-later: an adversary recording today's SPTPS
//! traffic and the X25519 ephemeral public keys in the KEX records can
//! decrypt all of it the day a CRQC solves the discrete log on
//! Curve25519. Mixing an ML-KEM-768 (FIPS 203) shared secret into the
//! same PRF input means *both* primitives must fall before recorded
//! traffic is readable — the classical leg covers "ML-KEM is too new
//! to trust alone", the lattice leg covers "X25519 falls to Shor".
//!
//! This module is a thin byte-array wrapper around `ml-kem` so the
//! SPTPS state machine never sees `hybrid_array::Array` typenum soup.
//! Ed25519 transcript signatures stay as-is; PQ authentication is a
//! separate, later concern (signatures protect against active MITM
//! *now*, not against a future quantum adversary replaying a recording
//! — there's nothing to forge in a recording).
//!
//! ## `SptpsKex` lives here, not in `tinc-sptps`
//!
//! `tinc-conf` parses it, `tinc-sptps` consumes it, `tincd` threads it
//! between the two. `tinc-crypto` is already a dependency of all three;
//! putting the enum here avoids `tinc-conf → tinc-sptps` (wrong layer)
//! or duplicating the `FromStr`.

use core::fmt;
use core::str::FromStr;

use ml_kem::array::Array;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

/// ML-KEM-768 encapsulation key (`ek`). FIPS 203 §8, table 2.
pub const EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext (`c`).
pub const CT_LEN: usize = 1088;
/// ML-KEM shared-secret length. Same for all parameter sets.
pub const SS_LEN: usize = 32;

/// Static, per-host key-exchange selection. **Not negotiated** — both
/// ends must agree out-of-band (host file). A mismatch derives
/// different traffic keys (the choice is mixed into the KDF label) and
/// the handshake fails cleanly at SIG verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SptpsKex {
    /// Classical SPTPS. Byte-identical wire format to C tinc 1.1.
    #[default]
    X25519,
    /// Hybrid: X25519 shared secret ‖ two ML-KEM-768 shared secrets
    /// (one encapsulation per direction; SPTPS sends both KEX records
    /// blind so neither side can encapsulate at KEX time).
    X25519MlKem768,
}

impl SptpsKex {
    /// KDF label discriminator. Appended to the SPTPS label as
    /// `[kex_byte, cipher_byte]` *iff* either is non-zero, so the
    /// default configuration's PRF input — and therefore its derived
    /// keys — stay byte-identical to C tinc. The `cipher_byte` slot
    /// is reserved for the sibling `SPTPSCipher` work; this crate
    /// always writes 0 there. See `docs/PROTOCOL.md`.
    #[must_use]
    pub const fn discriminator(self) -> u8 {
        match self {
            Self::X25519 => 0,
            Self::X25519MlKem768 => 1,
        }
    }

    /// Config-file / log spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::X25519MlKem768 => "x25519-mlkem768",
        }
    }
}

impl fmt::Display for SptpsKex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SptpsKex {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // Case-insensitive: tinc.conf values aren't case-normalised by
        // the parser (only keys are).
        if s.eq_ignore_ascii_case("x25519") {
            Ok(Self::X25519)
        } else if s.eq_ignore_ascii_case("x25519-mlkem768") {
            Ok(Self::X25519MlKem768)
        } else {
            Err(())
        }
    }
}

/// Ephemeral ML-KEM-768 decapsulation key. Heap-boxed: the encoded
/// form is 2400 bytes and the SPTPS struct already carries a handful
/// of these handshake-transient `Option`s; keeping `None` cheap
/// matters more than one alloc per handshake.
///
/// `ml-kem`'s `DecapsulationKey` is `ZeroizeOnDrop` behind the
/// `zeroize` feature (enabled), so dropping the box wipes it.
pub struct MlKemPrivate(Box<DecapsulationKey<MlKem768Params>>);

// The inner type already zeroizes on drop; this marker just lets
// `#[derive(ZeroizeOnDrop)]` on a containing struct accept the field.
impl ZeroizeOnDrop for MlKemPrivate {}

impl MlKemPrivate {
    /// `ML-KEM.KeyGen`. Returns the decapsulation key plus the encoded
    /// encapsulation key that goes on the wire.
    ///
    /// Takes `RngCore`, not `CryptoRngCore`, to match the existing
    /// `Sptps` signature (which threads a single `&mut impl RngCore`
    /// through the whole state machine and whose differential-test
    /// harness feeds a non-`CryptoRng` keystream). Production callers
    /// pass `OsRng`; the marker trait is satisfied via [`AsCrypto`].
    pub fn generate(rng: &mut impl RngCore) -> (Self, [u8; EK_LEN]) {
        let (dk, ek) = MlKem768::generate(&mut AsCrypto(rng));
        let mut ek_bytes = [0u8; EK_LEN];
        ek_bytes.copy_from_slice(&ek.as_bytes());
        (Self(Box::new(dk)), ek_bytes)
    }

    /// `ML-KEM.Decaps`. Infallible per FIPS 203: an invalid ciphertext
    /// yields the implicit-rejection key, not an error. The resulting
    /// shared secret won't match the encapsulator's, the PRF derives
    /// different traffic keys, and the first AEAD tag check fails —
    /// same observable outcome as a SIG mismatch.
    #[must_use]
    #[expect(clippy::missing_panics_doc)] // Error = (); ml-kem decaps is total (implicit rejection)
    pub fn decapsulate(&self, ct: &[u8; CT_LEN]) -> [u8; SS_LEN] {
        // `Array<u8, U1088>: From<&[u8; 1088]>` — no fallible parse.
        let ct: &Ciphertext<MlKem768> = ct.into();
        let ss = ::kem::Decapsulate::decapsulate(&*self.0, ct).expect("ML-KEM decaps infallible");
        let mut out = [0u8; SS_LEN];
        out.copy_from_slice(&ss);
        out
    }
}

/// `ML-KEM.Encaps` against an encoded encapsulation key.
///
/// FIPS 203 §7.2 mandates an `ek` "modulus check" (each coefficient
/// `< q`); `ml-kem` 0.2's `from_bytes` does **not** perform it. That's
/// acceptable here: the `ek` is covered by the Ed25519 transcript
/// signature, so a peer that authenticates can only hurt itself with a
/// malformed key, and an unauthenticated attacker fails SIG before any
/// derived key is used.
#[expect(clippy::missing_panics_doc)] // Error = (); ml-kem encaps never returns Err
pub fn encapsulate(ek: &[u8; EK_LEN], rng: &mut impl RngCore) -> ([u8; CT_LEN], [u8; SS_LEN]) {
    let ek_arr: &Encoded<EncapsulationKey<MlKem768Params>> = ek.into();
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(ek_arr);
    let (ct, ss) =
        ::kem::Encapsulate::encapsulate(&ek, &mut AsCrypto(rng)).expect("ML-KEM encaps infallible");
    let mut ct_out = [0u8; CT_LEN];
    ct_out.copy_from_slice(&ct);
    let mut ss_out = [0u8; SS_LEN];
    ss_out.copy_from_slice(&ss);
    (ct_out, ss_out)
}

/// Compile-time check that the byte-array constants above match
/// `ml-kem`'s typenum-derived sizes. A bump of the `ml-kem` crate that
/// changed encodings (there is exactly one FIPS 203 encoding, so this
/// would be a bug) fails to build rather than producing garbage on the
/// wire.
const _: () = {
    assert!(core::mem::size_of::<Encoded<EncapsulationKey<MlKem768Params>>>() == EK_LEN);
    assert!(core::mem::size_of::<Ciphertext<MlKem768>>() == CT_LEN);
    assert!(core::mem::size_of::<Array<u8, <MlKem768 as KemCore>::SharedKeySize>>() == SS_LEN);
};

/// Adapter: stamp `CryptoRng` onto an `RngCore` borrow.
///
/// SPTPS threads a single `&mut impl RngCore` everywhere so the C
/// differential test can feed both implementations the same
/// `ChaCha20Legacy` keystream (which is *not* `CryptoRng`-marked).
/// `ml-kem` requires the marker. Widening the SPTPS bound to
/// `CryptoRngCore` would touch every receive-path signature and three
/// test RNGs for a marker trait that `OsRng` (the only production RNG)
/// already carries. The adapter is the smaller blast radius.
struct AsCrypto<'a, R: RngCore>(&'a mut R);

impl<R: RngCore> RngCore for AsCrypto<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
impl<R: RngCore> CryptoRng for AsCrypto<'_, R> {}

/// Hybrid PRF secret: `X25519_ss(32) ‖ ss_i2r(32) ‖ ss_r2i(32)`.
pub const HYBRID_SHARED_LEN: usize = crate::ecdh::SHARED_LEN + 2 * SS_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Raw-primitive KAT: exercises the byte-array ↔ `hybrid_array`
    /// shimming both ways. End-to-end coverage (incl. implicit
    /// rejection) lives in `tinc-sptps/tests/hybrid_kex.rs`.
    #[test]
    fn mlkem768_round_trip() {
        let (dk, ek) = MlKemPrivate::generate(&mut OsRng);
        let (ct, ss_send) = encapsulate(&ek, &mut OsRng);
        assert_eq!(ss_send, dk.decapsulate(&ct));
    }
}
