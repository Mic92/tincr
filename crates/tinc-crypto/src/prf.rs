//! tinc's key-derivation PRF: TLS-1.0 `P_hash` over HMAC-SHA512, with a twist.
//!
//! C reference: `src/nolegacy/prf.c`.
//!
//! ## Why `hkdf` cannot be used
//!
//! This is **not** HKDF. It's the RFC 4346 §5 `P_hash` construction, which
//! predates HKDF and has a different chaining structure. Worse, tinc deviates
//! from RFC 4346 in one critical way: where the RFC says `A(0) = seed`, tinc
//! initialises `A(0) = [0u8; 64]` (because the C code `memset`s before the
//! first HMAC). One iteration in, the outputs diverge from any TLS library.
//!
//! ## The algorithm, as actually implemented in `prf.c`
//!
//! ```text
//! data = [0u8; 64] ++ seed                    -- A(0) is ZEROS, not seed!
//! loop until out is full:
//!     data[0..64] = HMAC-SHA512(secret, data) -- A(i) = HMAC(secret, A(i-1) ++ seed)
//!     emit HMAC-SHA512(secret, data)          -- chunk = HMAC(secret, A(i) ++ seed)
//! ```
//!
//! Note: the inner HMAC overwrites `data[0..64]` *in place*, so the second
//! HMAC sees the new `A(i)` already concatenated with the original seed.
//! That's why we mirror the same buffer layout below — it's the simplest way
//! to be certain we match.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// SHA-512 output size, and therefore the chunk size of this PRF.
const MD_LEN: usize = 64;

/// Derive `out.len()` bytes of key material.
///
/// SPTPS calls this exactly once per handshake with the ECDH shared secret as
/// `secret`, a label-plus-nonces blob as `seed`, and `out.len() == 128` (two
/// 64-byte [`ChaPoly`](crate::chapoly::ChaPoly) keys). Other lengths are
/// exercised only by the KAT suite.
///
/// `secret` may be any length, including zero and including values larger
/// than the HMAC block size (128 bytes for SHA-512); the `hmac` crate handles
/// the key-hashing fallback so we don't replicate `prf.c`'s manual version.
pub fn prf(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    // Mirror the C buffer exactly: [A(i) | seed]. Starting with A(0) = zeros
    // is the load-bearing tinc-specific quirk. Allocating per call is fine;
    // this runs once per handshake, not per packet.
    let mut data = vec![0u8; MD_LEN + seed.len()];
    data[MD_LEN..].copy_from_slice(seed);

    let mut written = 0;
    while written < out.len() {
        // Inner HMAC: A(i) = HMAC(secret, A(i-1) ++ seed).
        // Result overwrites the first MD_LEN bytes of `data`, so the seed
        // tail stays put for the next iteration — same trick the C code uses.
        let a_i = hmac(secret, &data);
        data[..MD_LEN].copy_from_slice(&a_i);

        // Outer HMAC: emit one chunk. Same input as inner, but with the
        // *updated* A(i) prefix. (Yes, two HMACs over the same buffer per
        // chunk. RFC 4346 designed it that way.)
        let chunk = hmac(secret, &data);

        // Partial-chunk handling for the final iteration. The C code has an
        // explicit if/else here with a temp buffer; slicing achieves the same.
        let take = chunk.len().min(out.len() - written);
        out[written..written + take].copy_from_slice(&chunk[..take]);
        written += take;
    }
}

/// One-shot HMAC-SHA512.
///
/// `new_from_slice`'s `Result` is an artifact of the generic `Mac` trait
/// (some MACs restrict key length); RFC 2104 HMAC accepts any length, so
/// the unwrap is unreachable. The lint allow is preferable to bubbling a
/// phantom error variant up through `prf()`.
///
/// Kept separate purely so the loop above reads as two distinct steps —
/// the C code names them "inner" and "outer" and that distinction matters
/// when comparing implementations side-by-side.
fn hmac(key: &[u8], msg: &[u8]) -> [u8; MD_LEN] {
    // `new_from_slice` accepts any key length and applies RFC 2104's
    // hash-if-too-long rule internally, matching `hmac_sha512` in prf.c.
    let mut mac = HmacSha512::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().into()
}
