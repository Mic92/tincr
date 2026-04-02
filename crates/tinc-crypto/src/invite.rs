//! Invitation URL crypto kernel.
//!
//! C reference: `src/invitation.c:499-551` (`cmd_invite`),
//! `src/invitation.c:1308-1410` (`cmd_join`),
//! `src/protocol_auth.c:199-207` (`receive_invitation_sptps` daemon side).
//!
//! ## What an invitation URL is
//!
//! ```text
//! ADDRESS[:PORT]/KEYHASHCOOKIEISNEXTHERE48CHARS_TOTAL
//!                ^^^^^^^^^^^^^^^^^^^^^^^^ key hash, 24 chars
//!                                        ^^^^^^^^^^^^^^^^^^^^^^^^ cookie, 24 chars
//! ```
//!
//! The slug after `/` is exactly **48 characters** of url-safe tinc-b64.
//! The first 24 characters are the **key hash** — they let `cmd_join`
//! authenticate the inviting daemon (which has to prove it holds the
//! invitation private key by completing the SPTPS handshake). The second
//! 24 characters are the **cookie** — a bearer token the daemon uses to
//! locate the invitation file.
//!
//! ## The composition (and why it's its own module)
//!
//! ```text
//! fingerprint = b64_std(pubkey)              43 chars; +/ alphabet, NOT urlsafe
//! key_hash    = sha512(fingerprint)[..18]    hash the STRING, not the raw key
//! cookie_hash = sha512(cookie || fingerprint)[..18]   same fingerprint reused
//! slug        = b64_url(key_hash) || b64_url(cookie)
//! filename    = b64_url(cookie_hash)
//! ```
//!
//! Each line is a place to be silently wrong:
//!
//! - `fingerprint` uses `b64encode_tinc` (the `+/` variant) because that's
//!   what `ecdsa_get_base64_public_key` calls (`ecdsa.c:63`). Only the
//!   *output* of the kernel is url-safe.
//! - `key_hash` hashes the **base64 string**, not the raw pubkey. The C
//!   does `sha512(fingerprint, strlen(fingerprint), hash)` — `strlen` is
//!   the giveaway. This is unusual; you'd expect raw bytes. But it's wire-
//!   locked: the daemon sends the same b64 string in its meta-greeting,
//!   and `cmd_join` hashes *that* to compare. Hashing raw bytes on one side
//!   and b64 on the other = failed auth, no error message.
//! - `cookie_hash` is `cookie || fingerprint`, **cookie first**. Swapped
//!   = daemon can't find the file. The invitation file's name doesn't
//!   reveal the cookie (a bearer token), so `ls invitations/` doesn't leak
//!   it; but the daemon must be able to recompute the name from the cookie
//!   it receives over SPTPS. Hence the same hash on both sides.
//! - 18 bytes truncated, not 16 or 20. `b64(18)` = 24 chars exactly (no
//!   pad); 144 bits is "enough" for collision resistance and round numbers
//!   in the URL.
//!
//! Nothing here is configurable. The shapes are protocol-locked between
//! `cmd_invite`, `cmd_join`, and the daemon — change any one and the
//! other two reject silently. Hence: KAT-tested via `kat/gen_kat.c`.

use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::b64;
use crate::sign::PUBLIC_LEN;

/// Cookie length, raw bytes. `invitation.c:508`: `randomize(cookie, 18)`.
///
/// Why 18: it's `144 / 8`. 144 bits → exactly 24 base64 characters with no
/// padding (`18 * 4 / 3 = 24`). The same length is used for the truncated
/// hash for the same reason — round-number URL slug.
pub const COOKIE_LEN: usize = 18;

/// b64-urlsafe-of-18-bytes length. `b64encode_tinc_urlsafe(_, _, 18)` → 24.
///
/// The URL slug after `/` is exactly `2 * SLUG_PART_LEN`.
pub const SLUG_PART_LEN: usize = 24;

/// Full slug length: `b64(key_hash) || b64(cookie)`.
///
/// `invitation.c:1277`: `if(strlen(slash) != 48) goto invalid;`.
pub const SLUG_LEN: usize = 2 * SLUG_PART_LEN;

// Compile-time witness that 18 → 24 is the encoding length we claimed.
// b64 length for n bytes (no padding) is `(n*4).div_ceil(3)`. 18*4/3 = 24
// exactly, no ceil needed. If someone bumps COOKIE_LEN this fires.
const _: () = assert!(COOKIE_LEN * 4 / 3 == SLUG_PART_LEN);
const _: () = assert!(COOKIE_LEN * 4 % 3 == 0); // exactness, not just division

/// `ecdsa_get_base64_public_key`. `ed25519/ecdsa.c:62`.
///
/// Encodes the 32-byte public key with the standard `+/` alphabet — *not*
/// url-safe. This string is what the daemon transmits in its meta-greeting
/// (`protocol_auth.c:354`: `send_request(c, "%d %s", ACK, mykey)`), so
/// `cmd_join` receives it and hashes it directly for comparison. The b64
/// alphabet is therefore protocol-locked. Always 43 chars (32 → 43 in
/// no-pad b64).
///
/// `tinc-tools` already does this manually in a couple places (it's just
/// `b64::encode(public)`). It's its own function here because the *exact*
/// bytes of this string are the input to `key_hash`, and giving it a name
/// makes the composition obvious at the call site.
#[must_use]
pub fn fingerprint(public: &[u8; PUBLIC_LEN]) -> String {
    // b64::encode is the +/ variant. 32 bytes → 43 chars.
    let f = b64::encode(public);
    debug_assert_eq!(f.len(), 43, "32 bytes b64-encode to 43 chars");
    f
}

/// `sha512(fingerprint(pk))[..18]`. `invitation.c:500-502`.
///
/// This is what the first half of the URL slug encodes. `cmd_join` decodes
/// it from the URL, then after the meta-greeting receives the daemon's
/// pubkey (as a b64 string), hashes *that*, and compares. If they match,
/// the daemon really holds the invitation key. `invitation.c:1400`:
/// `sha512(fingerprint, strlen(fingerprint), hishash); mem_eq(hishash, hash, 18)`.
///
/// The hash is over the b64 string, not the raw pubkey. See module doc
/// for why that's not a bug.
#[must_use]
pub fn key_hash(public: &[u8; PUBLIC_LEN]) -> [u8; COOKIE_LEN] {
    // Intermediate string is short-lived and not secret (it's the public
    // key); no zeroize needed. We could avoid the allocation by feeding
    // the encoder output to a streaming hasher, but 43 bytes is noise and
    // the allocation makes the C correspondence obvious.
    let fp = fingerprint(public);
    let digest = Sha512::digest(fp.as_bytes());
    let mut out = [0u8; COOKIE_LEN];
    out.copy_from_slice(&digest[..COOKIE_LEN]);
    out
}

/// `sha512(cookie || fingerprint(pk))[..18]`. `invitation.c:511-518`,
/// `protocol_auth.c:199-207`.
///
/// This is the **filename** of the invitation file. The cookie is a
/// bearer token; storing the file as `invitations/COOKIE` would leak it
/// to anyone who can `ls`. Instead the file is named by this hash.
/// The daemon receives the raw cookie over SPTPS, recomputes the same
/// hash, and `rename()`s the file to `.used` atomically.
///
/// **Cookie comes first** in the concatenation. The fingerprint binds the
/// hash to the invitation key — without it, knowledge of the cookie alone
/// would let you compute the filename, defeating the point.
///
/// Zeroizes the intermediate buffer because it contains the cookie.
#[must_use]
pub fn cookie_hash(cookie: &[u8; COOKIE_LEN], public: &[u8; PUBLIC_LEN]) -> [u8; COOKIE_LEN] {
    // C: `memcpy(buf, cookie, 18); memcpy(buf+18, fingerprint, fplen);`
    //    `sha512(buf, buflen, cookiehash);`
    // protocol_auth.c does the same dance, byte-for-byte.
    let fp = fingerprint(public);
    // 18 + 43 = 61 bytes. Preallocate to final size — only zeroize one
    // allocation. (The Zeroizing<Vec> rule from sign.rs.)
    let mut buf = Vec::with_capacity(COOKIE_LEN + fp.len());
    buf.extend_from_slice(cookie);
    buf.extend_from_slice(fp.as_bytes());
    let digest = Sha512::digest(&buf);
    buf.zeroize();
    let mut out = [0u8; COOKIE_LEN];
    out.copy_from_slice(&digest[..COOKIE_LEN]);
    out
}

/// Build the URL slug: `b64_url(key_hash) || b64_url(cookie)`.
/// `invitation.c:502, 522, 551`.
///
/// Returns the 48-character string that goes after `/` in the URL.
/// The `address[:port]/` prefix is the caller's job — this is the
/// crypto-derived part.
///
/// Returned `String` should be zeroized after use; it embeds the cookie.
#[must_use]
pub fn build_slug(public: &[u8; PUBLIC_LEN], cookie: &[u8; COOKIE_LEN]) -> String {
    let mut s = b64::encode_urlsafe(&key_hash(public));
    s.push_str(&b64::encode_urlsafe(cookie));
    debug_assert_eq!(s.len(), SLUG_LEN);
    s
}

/// Filename for the invitation file. `b64_url(cookie_hash)`, 24 chars.
///
/// `invitation.c:518` + `protocol_auth.c:207`. Relative name only;
/// caller prepends `<confbase>/invitations/`.
///
/// The expiry sweep in `cmd_invite` uses `strlen(ent->d_name) != 24`
/// (`invitation.c:409`) to recognize invitation files in a `readdir`
/// scan. The filename length is therefore load-bearing; this returns
/// exactly that.
#[must_use]
pub fn cookie_filename(cookie: &[u8; COOKIE_LEN], public: &[u8; PUBLIC_LEN]) -> String {
    let s = b64::encode_urlsafe(&cookie_hash(cookie, public));
    debug_assert_eq!(s.len(), SLUG_PART_LEN);
    s
}

/// Parse a URL slug back into `(key_hash, cookie)`. `invitation.c:1310`.
///
/// `cmd_join` does this:
/// ```c
/// if(!b64decode_tinc(slash, hash, 24) || !b64decode_tinc(slash + 24, cookie, 24))
///     goto invalid;
/// ```
///
/// Returns `None` for slugs of the wrong length or with invalid base64
/// characters. Valid base64 of 24 chars *always* decodes to 18 bytes
/// (no slop in tinc-b64 — `24 * 6 / 8 = 18`), so length is the only
/// failure mode after the alphabet check.
///
/// The cookie should be zeroized after use; the key hash is not secret.
#[must_use]
pub fn parse_slug(slug: &str) -> Option<([u8; COOKIE_LEN], [u8; COOKIE_LEN])> {
    if slug.len() != SLUG_LEN {
        return None;
    }
    // We slice at SLUG_PART_LEN, which is 24 — a known-ASCII boundary
    // because b64 output is all ASCII. No `from_utf8` round-trip needed;
    // `&str` slicing at an ASCII byte index is sound. (The "don't
    // round-trip when slicing at ASCII" rule.) But actually we need to
    // verify the slug IS ASCII first, or the slice could panic mid-char.
    // b64::decode does that: it rejects non-alphabet bytes. So decode
    // each half independently and let decode's None propagate. But we
    // still need the slice to be valid... use `is_char_boundary`.
    //
    // Actually, simpler: the slug came from a URL. If it has multibyte
    // UTF-8 in it, it's garbage. Check up front.
    if !slug.is_ascii() {
        return None;
    }
    let (h, c) = slug.split_at(SLUG_PART_LEN);
    // b64::decode accepts both alphabets (+ and -, / and _) — that's
    // the C `base64_decode` table's union behavior. So a slug printed
    // with +/ would also parse here. The C does the same (`b64decode_tinc`
    // is the only decoder; it's alphabet-agnostic). In practice slugs
    // are always urlsafe because `cmd_invite` emits them that way.
    let hash = b64::decode(h)?;
    let cookie = b64::decode(c)?;
    // 24 chars → 18 bytes is exact for valid b64; the array conversions
    // can't fail given decode succeeded. But `try_into` keeps it total.
    Some((hash.try_into().ok()?, cookie.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build_slug` and `parse_slug` are inverses. Property-style with a
    /// fixed key — the KAT covers correctness, this covers the boundary
    /// between build and parse (where a thinko like "encode the hash
    /// twice instead of hash+cookie" would slip past the KAT).
    #[test]
    fn slug_roundtrip() {
        let pk = [7u8; PUBLIC_LEN];
        let cookie = [3u8; COOKIE_LEN];
        let slug = build_slug(&pk, &cookie);
        assert_eq!(slug.len(), SLUG_LEN);
        let (h, c) = parse_slug(&slug).unwrap();
        assert_eq!(c, cookie);
        assert_eq!(h, key_hash(&pk));
    }

    /// Filename is recomputable from cookie alone (given the same key) —
    /// the daemon's recovery path.
    #[test]
    fn filename_from_cookie() {
        let pk = [9u8; PUBLIC_LEN];
        let cookie = [5u8; COOKIE_LEN];
        let f1 = cookie_filename(&cookie, &pk);
        let f2 = cookie_filename(&cookie, &pk);
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), SLUG_PART_LEN);
        // Filename does NOT contain the cookie's b64. That's the point.
        assert!(!f1.contains(&b64::encode_urlsafe(&cookie)));
    }

    /// Short slug → None.
    #[test]
    fn parse_short() {
        assert!(parse_slug("tooshort").is_none());
    }

    /// 48 chars but bad alphabet → None. `b64::decode` rejects.
    #[test]
    fn parse_bad_alphabet() {
        assert!(parse_slug(&"!".repeat(48)).is_none());
    }

    /// 48-byte non-ASCII → None, no panic at split_at. The point is the
    /// `is_ascii` guard: without it, `split_at(24)` on a string with a
    /// multibyte char straddling byte 24 panics. 48 bytes ≠ 48 chars.
    /// `'ü'` is `0xC3 0xBC` — 2 bytes, 1 char. 24 of them = 48 bytes,
    /// every odd byte index is a non-boundary.
    #[test]
    fn parse_multibyte_no_panic() {
        let evil = "ü".repeat(24);
        assert_eq!(evil.len(), 48); // bytes, not chars
        assert!(parse_slug(&evil).is_none());
    }

    /// Different cookies → different filenames. (Collision is
    /// cryptographically unlikely but the test really proves "the
    /// cookie is an input", not that SHA-512 is collision-resistant.)
    #[test]
    fn cookie_affects_filename() {
        let pk = [0u8; PUBLIC_LEN];
        let f0 = cookie_filename(&[0u8; COOKIE_LEN], &pk);
        let f1 = cookie_filename(&[1u8; COOKIE_LEN], &pk);
        assert_ne!(f0, f1);
    }

    /// Different keys → different slugs (key_hash half changes).
    /// Same cookie → same cookie half.
    #[test]
    fn key_affects_slug_prefix_only() {
        let cookie = [42u8; COOKIE_LEN];
        let s0 = build_slug(&[0u8; PUBLIC_LEN], &cookie);
        let s1 = build_slug(&[1u8; PUBLIC_LEN], &cookie);
        assert_ne!(s0[..SLUG_PART_LEN], s1[..SLUG_PART_LEN]);
        assert_eq!(s0[SLUG_PART_LEN..], s1[SLUG_PART_LEN..]);
    }
}
