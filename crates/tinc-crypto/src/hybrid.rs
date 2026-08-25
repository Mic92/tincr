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

use crate::ecdh::SHARED_LEN;
use kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::MlKem768;
use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
pub struct MlKemPrivate(Box<DecapsulationKey>);

// The inner type already zeroizes on drop; this marker just lets
// `#[derive(ZeroizeOnDrop)]` on a containing struct accept the field.
impl ZeroizeOnDrop for MlKemPrivate {}

impl MlKemPrivate {
    /// `ML-KEM.KeyGen`. Returns the decapsulation key plus the encoded
    /// encapsulation key that goes on the wire.
    ///
    /// `rng` must be `CryptoRng`. Production: the OS RNG.
    pub fn generate(rng: &mut impl CryptoRng) -> (Self, [u8; EK_LEN]) {
        let (dk, ek) = MlKem768::generate_keypair_from_rng(rng);
        let mut ek_bytes = [0u8; EK_LEN];
        ek_bytes.copy_from_slice(&ek.to_bytes());
        (Self(Box::new(dk)), ek_bytes)
    }

    /// `ML-KEM.Decaps`. Infallible per FIPS 203: an invalid ciphertext
    /// yields the implicit-rejection key, not an error. The resulting
    /// shared secret won't match the encapsulator's, the PRF derives
    /// different traffic keys, and the first AEAD tag check fails —
    /// same observable outcome as a SIG mismatch.
    #[must_use]
    pub fn decapsulate(&self, ct: &[u8; CT_LEN]) -> Zeroizing<[u8; SS_LEN]> {
        // Fixed-size input → the Array conversion cannot fail.
        let ct: ml_kem::ml_kem_768::Ciphertext = (*ct).into();
        let mut ss = self.0.decapsulate(&ct);
        let mut out = Zeroizing::new([0u8; SS_LEN]);
        out.copy_from_slice(&ss);
        // Wipe ml-kem's copy; `out` is the only surviving reference.
        ss.zeroize();
        out
    }
}

/// `ML-KEM.Encaps` against an encoded encapsulation key.
///
/// FIPS 203 §7.2 mandates an `ek` "modulus check" (each coefficient
/// `< q`); `ml-kem` 0.3 performs it in `EncapsulationKey::new`, so a
/// malformed key is rejected here (`None`) and the caller fails the
/// handshake instead of deriving keys from an out-of-range point.
pub fn encapsulate(
    ek: &[u8; EK_LEN],
    rng: &mut impl CryptoRng,
) -> Option<([u8; CT_LEN], Zeroizing<[u8; SS_LEN]>)> {
    let ek = EncapsulationKey::new(&(*ek).into()).ok()?;
    let (ct, mut ss) = ek.encapsulate_with_rng(rng);
    let mut ct_out = [0u8; CT_LEN];
    ct_out.copy_from_slice(&ct);
    let mut ss_out = Zeroizing::new([0u8; SS_LEN]);
    ss_out.copy_from_slice(&ss);
    // `ct` is public; `ss` is secret — wipe ml-kem's copy.
    ss.zeroize();
    Some((ct_out, ss_out))
}

/// Compile-time check that the byte-array constants above match
/// `ml-kem`'s typenum-derived sizes. A bump of the `ml-kem` crate that
/// changed encodings (there is exactly one FIPS 203 encoding, so this
/// would be a bug) fails to build rather than producing garbage on the
/// wire.
const _: () = {
    assert!(core::mem::size_of::<kem::Key<EncapsulationKey>>() == EK_LEN);
    assert!(core::mem::size_of::<ml_kem::ml_kem_768::Ciphertext>() == CT_LEN);
    assert!(core::mem::size_of::<kem::SharedKey<MlKem768>>() == SS_LEN);
};

/// Hybrid PRF secret: `X25519_ss(32) ‖ ss_i2r(32) ‖ ss_r2i(32)`.
pub const HYBRID_SHARED_LEN: usize = SHARED_LEN + 2 * SS_LEN;

/// `SHA-512(ek_i ‖ ek_r ‖ ct_i2r ‖ ct_r2i)`: X-Wing–style binding of
/// all public KEM material into the PRF seed. Hashed (4544 B → 64 B)
/// so the seed stays small. See `docs/PROTOCOL.md`.
#[must_use]
pub fn kem_transcript_hash(ek_i: &[u8], ek_r: &[u8], ct_i2r: &[u8], ct_r2i: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(ek_i);
    h.update(ek_r);
    h.update(ct_i2r);
    h.update(ct_r2i);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::UnwrapErr;

    /// Raw-primitive KAT: exercises the byte-array ↔ `hybrid_array`
    /// shimming both ways. End-to-end coverage (incl. implicit
    /// rejection) lives in `tinc-sptps/tests/hybrid_kex.rs`.
    #[test]
    fn mlkem768_round_trip() {
        let mut rng = UnwrapErr(getrandom::SysRng);
        let (dk, ek) = MlKemPrivate::generate(&mut rng);
        let (ct, ss_send) = encapsulate(&ek, &mut rng).expect("valid ek");
        assert_eq!(*ss_send, *dk.decapsulate(&ct));
    }
}
