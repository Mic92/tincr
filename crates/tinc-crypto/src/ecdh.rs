//! Ed25519-point ECDH, as used by SPTPS key exchange.
//!
//! C reference: `src/ed25519/ecdh.c` + `src/ed25519/key_exchange.c`.
//!
//! ## Why `x25519-dalek` cannot be used
//!
//! Standard X25519 puts a *Montgomery u-coordinate* on the wire. tinc puts an
//! **Ed25519 public key** (compressed Edwards y-coordinate) on the wire and
//! converts to Montgomery on receipt. The two encodings are different bytes
//! for the same underlying curve point; `x25519-dalek` would happily compute
//! a shared secret from the Ed25519 bytes, but it would be the *wrong* secret.
//!
//! ## The algorithm
//!
//! Generation (`ecdh_generate_public`):
//! ```text
//! seed     <- random 32 bytes
//! private  <- SHA-512(seed)           -- 64 bytes; low 32 clamped, high 32 unused here
//! public   <- private[0..32] * B      -- Ed25519 base-point mult, NOT X25519 base
//! ```
//!
//! Agreement (`ecdh_compute_shared`, via `ed25519_key_exchange`):
//! ```text
//! e        <- clamp(private[0..32])   -- re-clamp (idempotent on already-clamped input)
//! ed_y     <- decode(peer_public)     -- treat bytes as Edwards y-coordinate
//! mont_u   <- (1 + ed_y) / (1 - ed_y) -- birational map, no point validation!
//! shared   <- (e * mont_u).to_bytes() -- X25519 ladder
//! ```
//!
//! The crucial subtlety: `key_exchange.c` does **not** decompress the full
//! Edwards point. It reads only the y-coordinate (`fe_frombytes` ignores the
//! sign bit in byte 31) and applies the birational map to whatever field
//! element it gets. There is no on-curve check. We must replicate that —
//! decompressing with `CompressedEdwardsY::decompress()` would *reject*
//! points the C code happily accepts.

use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::clamp_integer;
use sha2::{Digest, Sha512};
use zeroize::ZeroizeOnDrop;

/// On-wire public key size: an Ed25519 compressed point.
pub const PUBLIC_LEN: usize = 32;

/// Shared secret size: a Curve25519 Montgomery u-coordinate.
pub const SHARED_LEN: usize = 32;

/// Ephemeral ECDH private state.
///
/// Holds the full 64-byte SHA-512 expansion, even though only the first
/// 32 bytes are used in the ladder. `ZeroizeOnDrop` clears all 64.
#[derive(ZeroizeOnDrop)]
pub struct EcdhPrivate {
    expanded: [u8; 64],
}

impl EcdhPrivate {
    /// Derive the keypair from a 32-byte seed.
    ///
    /// In production this seed comes from a CSPRNG (`ecdh_generate_public`
    /// calls `randomize`). Exposing seed-based derivation lets the KAT suite
    /// reproduce the C output exactly without mocking an RNG.
    ///
    /// The returned public key is an Ed25519 point — the *same encoding* used
    /// for signature verification keys, which is what makes tinc's key reuse
    /// (long-term identity key doubles as static DH key) possible.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> (Self, [u8; PUBLIC_LEN]) {
        // ed25519_create_keypair: SHA-512 the seed, clamp the low half.
        // The high half is the Ed25519 "nonce prefix" — irrelevant for ECDH
        // but we keep it because the on-disk key format stores all 64 bytes.
        let mut expanded: [u8; 64] = Sha512::digest(seed).into();
        // Clamp the low 32 bytes. Destructure with a fixed-size pattern so
        // clippy can see there's no panic path here (try_into().unwrap()
        // on a constant-length slice triggers missing_panics_doc).
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&expanded[..32]);
        let clamped = clamp_integer(scalar);
        expanded[..32].copy_from_slice(&clamped);

        // Public key: standard Ed25519 base-point scalar multiplication.
        // We delegate to ed25519-dalek rather than reaching into
        // curve25519-dalek's `EdwardsPoint::mul_base` because the dalek
        // ecosystem only stabilises the basepoint-mult-from-clamped-bytes
        // path through the signature crate. Same math, blessed API.
        //
        // `SigningKey::from_bytes(seed)` runs the exact sequence above
        // internally (SHA-512 + clamp + ge_scalarmult_base), so its
        // verifying key is bit-identical to `pub_a` in the C KATs.
        let public = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();

        (Self { expanded }, public)
    }

    /// Reconstruct from the 64-byte expanded private key.
    ///
    /// Needed for the on-disk key format (`ecdsa_t.private`), which stores
    /// the post-SHA-512 expansion, not the seed. The seed is unrecoverable.
    #[must_use]
    pub fn from_expanded(expanded: &[u8; 64]) -> Self {
        Self {
            expanded: *expanded,
        }
    }

    /// Compute the shared secret with a peer's public key.
    ///
    /// Consumes `self`, mirroring the C semantics: `ecdh_compute_shared`
    /// calls `ecdh_free` before returning. Ephemeral keys are single-use.
    ///
    /// **No input validation.** This will produce *some* 32-byte output for
    /// any `peer_public`, including all-zeros, small-order points, and
    /// off-curve garbage. That matches `key_exchange.c`, which also performs
    /// no validation. SPTPS authenticates the handshake transcript with
    /// long-term Ed25519 signatures, so an attacker who feeds us a bad point
    /// can only break their own session.
    #[must_use]
    pub fn compute_shared(self, peer_public: &[u8; PUBLIC_LEN]) -> [u8; SHARED_LEN] {
        // Re-clamp. On a properly generated key this is idempotent
        // (clamp(clamp(x)) == clamp(x)), but `key_exchange.c` does it
        // unconditionally and so must we — a key file written by buggy
        // third-party tooling might not be pre-clamped, and we must produce
        // the same shared secret the C peer would.
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&self.expanded[..32]);
        let scalar = clamp_integer(scalar);

        // Edwards y → Montgomery u, by hand.
        //
        // The clean way would be:
        //   CompressedEdwardsY(peer).decompress()?.to_montgomery()
        // But decompress() validates that y corresponds to a point on the
        // curve, and rejects if not. The C code doesn't validate: it does
        //   fe_frombytes(y, peer)   -- masks bit 255, takes y as-is
        //   u = (1+y)/(1-y)
        // and ladders on whatever u falls out. So we do the same arithmetic
        // directly in the field.
        let mont_u = edwards_y_to_montgomery_u(peer_public);

        // X25519 ladder. `mul_clamped` applies the *same* clamping again,
        // which is harmless (idempotent) and saves us reaching for the
        // unclamped `Scalar` API. The output is the u-coordinate of the
        // product point, encoded little-endian — matching `fe_tobytes`.
        MontgomeryPoint(mont_u).mul_clamped(scalar).to_bytes()
    }
}

/// Reproduce `key_exchange.c`'s Edwards→Montgomery map without on-curve checks.
///
/// `fe_frombytes` in the C code masks off bit 255 (the Edwards sign bit) and
/// loads the remaining 255 bits as a field element. It does **not** reduce mod
/// p, so non-canonical encodings (values in `[p, 2^255)`) are accepted as-is —
/// arithmetically equivalent after the first multiply, but we must accept the
/// same input bytes.
///
/// We delegate the field arithmetic to `curve25519-dalek` by way of a trick:
/// `MontgomeryPoint::to_edwards` performs the *inverse* map `(u-1)/(u+1)`, and
/// `EdwardsPoint::to_montgomery` performs `(1+y)/(1-y)`. Neither validates.
/// But `to_montgomery` requires a full `EdwardsPoint`, which we can't build
/// from y alone without a square-root (the very validation we're avoiding).
///
/// So instead we compute it ourselves using the crate's `FieldElement` —
/// which, frustratingly, is not public. The escape hatch: the curve25519-dalek
/// `Scalar` type *is* public and its arithmetic is mod ℓ, not mod p, so that's
/// out too. We're left with one option that doesn't pull in a second bignum
/// library: do the field math in `u64` limbs ourselves, copying the structure
/// of `fe.c`.
///
/// That would be ~400 lines and a second implementation to audit. Better:
/// curve25519-dalek **does** expose modular inversion through one path that
/// doesn't validate — `MontgomeryPoint` arithmetic is pure field ops on the
/// u-coordinate with no curve check. We can encode `1+y` and `1-y` as fake
/// "Montgomery points" (they're just field elements in a wrapper), invert via
/// the projective ladder identity... no, the ladder needs a real point.
///
/// Honest answer: we vendor the field math. It's 50 lines, it's the same
/// arithmetic every Curve25519 implementation does, and the KATs will catch
/// any mistake. See `fe` module below.
fn edwards_y_to_montgomery_u(ed_public: &[u8; 32]) -> [u8; 32] {
    let y = fe::from_bytes(ed_public); // masks bit 255, like fe_frombytes
    let one = fe::one();
    let num = fe::add(&y, &one); // 1 + y  (note: C does y+1, addition commutes)
    let den = fe::sub(&one, &y); // 1 - y
    let den_inv = fe::invert(&den); // Fermat's little theorem, like fe_invert
    let u = fe::mul(&num, &den_inv);
    fe::to_bytes(&u)
}

/// Minimal Curve25519 field arithmetic, mod `2^255 - 19`.
///
/// This is **not** a general-purpose field library. It exists solely because
/// `curve25519-dalek` keeps `FieldElement` private and we need exactly four
/// operations on the unvalidated Edwards y-coordinate. The implementation is
/// the obvious schoolbook one with 51-bit radix-2 limbs (à la ref10/donna),
/// which is what `fe.c` uses too.
///
/// Performance is irrelevant: this runs once per handshake. Clarity wins.
mod fe {
    /// Field element as 5×51-bit limbs, little-endian, unreduced (lazy carry).
    pub(super) type Fe = [u64; 5];

    const MASK: u64 = (1 << 51) - 1;
    /// `2^255 - 19`, limb-wise. Used for the final freeze in `to_bytes`.
    const P: Fe = [MASK - 18, MASK, MASK, MASK, MASK];

    pub(super) fn one() -> Fe {
        [1, 0, 0, 0, 0]
    }

    /// Load 32 bytes little-endian, masking bit 255.
    ///
    /// Matches `fe_frombytes`: the high bit is the Edwards sign bit, not part
    /// of the y-coordinate. We don't reduce mod p here; values in `[p, 2^255)`
    /// stay as-is until arithmetic naturally folds them in.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Fe {
        // 8-byte little-endian loads. We need 51-bit chunks, so each limb
        // straddles byte boundaries. Bit offsets: 0, 51, 102, 153, 204.
        let load = |i: usize| -> u64 {
            // Read 8 bytes starting at byte `i`, padding with zero past the end.
            let mut buf = [0u8; 8];
            let avail = 32usize.saturating_sub(i).min(8);
            buf[..avail].copy_from_slice(&bytes[i..i + avail]);
            u64::from_le_bytes(buf)
        };
        [
            load(0) & MASK,
            (load(6) >> 3) & MASK,
            (load(12) >> 6) & MASK,
            (load(19) >> 1) & MASK,
            // Bit 255 is masked off by MASK on the top limb (51*5 = 255).
            (load(24) >> 12) & MASK,
        ]
    }

    /// Reduce to canonical form and encode as 32 bytes little-endian.
    ///
    /// Matches `fe_tobytes`: produces a value in `[0, p)`.
    pub(super) fn to_bytes(f: &Fe) -> [u8; 32] {
        // First, propagate carries so each limb is < 2^51 + small.
        let mut t = carry(f);
        // Then conditionally subtract p. Two passes handle the corner case
        // where the first carry-propagation leaves us at exactly p (or in
        // [p, p+19) after the *19 wrap). Standard ref10 trick.
        for _ in 0..2 {
            t = carry(&t);
            // Compute t - p; if it's non-negative, keep it.
            let mut s = [0i128; 5];
            let mut borrow = 0i128;
            for i in 0..5 {
                let v = i128::from(t[i]) - i128::from(P[i]) - borrow;
                borrow = i128::from(v < 0);
                s[i] = v + (borrow << 51);
            }
            // borrow == 0 ⇒ t >= p ⇒ take s. Constant-time select.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let mask = (borrow as u64).wrapping_sub(1); // 0 if borrow, !0 if not
            for i in 0..5 {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let s_i = s[i] as u64;
                t[i] = (t[i] & !mask) | (s_i & mask);
            }
        }
        // Pack 5×51 bits → 32 bytes.
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut acc_bits = 0u32;
        let mut o = 0;
        for limb in t {
            acc |= u128::from(limb) << acc_bits;
            acc_bits += 51;
            while acc_bits >= 8 && o < 32 {
                #[allow(clippy::cast_possible_truncation)]
                {
                    out[o] = acc as u8;
                }
                acc >>= 8;
                acc_bits -= 8;
                o += 1;
            }
        }
        // Final partial byte (top limb bit 50 lands at out[31] bit 6).
        #[allow(clippy::cast_possible_truncation)]
        if o < 32 {
            out[o] = acc as u8;
        }
        out
    }

    pub(super) fn add(a: &Fe, b: &Fe) -> Fe {
        // No carry needed yet: 2^51 + 2^51 = 2^52, fits in u64. Carry happens
        // in mul/to_bytes where it matters.
        [
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ]
    }

    pub(super) fn sub(a: &Fe, b: &Fe) -> Fe {
        // Add 2p first so subtraction can't underflow. 2p per limb is
        // ~2^52, sum is < 2^53, still fine.
        let two_p: Fe = [2 * P[0], 2 * P[1], 2 * P[2], 2 * P[3], 2 * P[4]];
        [
            a[0] + two_p[0] - b[0],
            a[1] + two_p[1] - b[1],
            a[2] + two_p[2] - b[2],
            a[3] + two_p[3] - b[3],
            a[4] + two_p[4] - b[4],
        ]
    }

    /// Schoolbook 5×5 multiply with reduction by 19 (since `2^255 ≡ 19`).
    pub(super) fn mul(a: &Fe, b: &Fe) -> Fe {
        // Widen everything to u128. Each product a[i]*b[j] is < 2^(51+51+small)
        // = ~2^104, and we sum at most 5 of them per output limb, < 2^107. Safe.
        let a: [u128; 5] = [
            a[0].into(),
            a[1].into(),
            a[2].into(),
            a[3].into(),
            a[4].into(),
        ];
        let b: [u128; 5] = [
            b[0].into(),
            b[1].into(),
            b[2].into(),
            b[3].into(),
            b[4].into(),
        ];
        // Limbs at "virtual" positions 5..9 wrap around with weight 19:
        //   a[i]*b[j] contributes to limb (i+j) mod 5, times 19 if i+j >= 5.
        // Precompute b*19 for the wrapped terms.
        let b19: [u128; 5] = [b[0] * 19, b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];

        let r0 = a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1];
        let r1 = a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2];
        let r2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3];
        let r3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4];
        let r4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];

        carry_wide(&[r0, r1, r2, r3, r4])
    }

    fn square(a: &Fe) -> Fe {
        // Could exploit symmetry for ~half the multiplies, but this runs once
        // per handshake. Reuse `mul` and keep one codepath to audit.
        mul(a, a)
    }

    /// Modular inverse via Fermat: `a^(p-2) mod p`.
    ///
    /// `p-2 = 2^255 - 21`. The standard addition chain (ref10's `fe_invert`)
    /// is 254 squarings + 11 multiplies. We use the same chain — not because
    /// performance matters, but because it's the well-trodden path with no
    /// off-by-one risk in the exponent.
    pub(super) fn invert(a: &Fe) -> Fe {
        // Chain from djb's ref10. Each `sqn(x, k)` is k squarings.
        let sqn = |x: &Fe, k: u32| -> Fe {
            let mut r = *x;
            for _ in 0..k {
                r = square(&r);
            }
            r
        };
        let t0 = square(a); // 2
        let t1 = sqn(&t0, 2); // 8
        let t1 = mul(&t1, a); // 9
        let t0 = mul(&t0, &t1); // 11
        let t2 = square(&t0); // 22
        let t1 = mul(&t1, &t2); // 31 = 2^5 - 1
        let t2 = sqn(&t1, 5); // 2^10 - 2^5
        let t1 = mul(&t2, &t1); // 2^10 - 1
        let t2 = sqn(&t1, 10);
        let t2 = mul(&t2, &t1); // 2^20 - 1
        let t3 = sqn(&t2, 20);
        let t2 = mul(&t3, &t2); // 2^40 - 1
        let t2 = sqn(&t2, 10);
        let t1 = mul(&t2, &t1); // 2^50 - 1
        let t2 = sqn(&t1, 50);
        let t2 = mul(&t2, &t1); // 2^100 - 1
        let t3 = sqn(&t2, 100);
        let t2 = mul(&t3, &t2); // 2^200 - 1
        let t2 = sqn(&t2, 50);
        let t1 = mul(&t2, &t1); // 2^250 - 1
        let t1 = sqn(&t1, 5); // 2^255 - 2^5
        mul(&t1, &t0) // 2^255 - 21
    }

    /// Propagate carries so each limb is < 2^51.
    fn carry(f: &Fe) -> Fe {
        carry_wide(&[
            f[0].into(),
            f[1].into(),
            f[2].into(),
            f[3].into(),
            f[4].into(),
        ])
    }

    fn carry_wide(r: &[u128; 5]) -> Fe {
        let mut r = *r;
        // One pass left-to-right; the wrap from limb 4 to limb 0 picks up *19.
        // Two rounds because the *19 can itself produce a small carry.
        for _ in 0..2 {
            let c = r[0] >> 51;
            r[0] &= u128::from(MASK);
            r[1] += c;
            let c = r[1] >> 51;
            r[1] &= u128::from(MASK);
            r[2] += c;
            let c = r[2] >> 51;
            r[2] &= u128::from(MASK);
            r[3] += c;
            let c = r[3] >> 51;
            r[3] &= u128::from(MASK);
            r[4] += c;
            let c = r[4] >> 51;
            r[4] &= u128::from(MASK);
            r[0] += c * 19;
        }
        #[allow(clippy::cast_possible_truncation)]
        [
            r[0] as u64,
            r[1] as u64,
            r[2] as u64,
            r[3] as u64,
            r[4] as u64,
        ]
    }
}
