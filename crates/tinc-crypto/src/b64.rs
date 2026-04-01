//! tinc's non-standard base64.
//!
//! C reference: `src/utils.c` (`b64encode_tinc`, `b64decode_tinc`).
//!
//! ## Why the `base64` crate cannot be used
//!
//! Two independent deviations from RFC 4648, either of which is fatal:
//!
//! 1. **Reversed bit packing.** RFC 4648 packs bytes MSB-first:
//!    `triplet = b[0]<<16 | b[1]<<8 | b[2]`, emit top 6 bits first.
//!    tinc packs LSB-first:
//!    `triplet = b[0] | b[1]<<8 | b[2]<<16`, emit *bottom* 6 bits first.
//!    These produce **different strings** for the same input. tinc's
//!    encoding of `[0x48]` is `"IB"`; RFC 4648's is `"SA"`.
//!
//! 2. **Permissive decode alphabet.** The decoder maps both `'+'` and `'-'`
//!    to 62, both `'/'` and `'_'` to 63 — accepting standard, URL-safe,
//!    and even mixed input in the same string. The encode side picks one
//!    alphabet (tinc emits `+/` for keys, `-_` for invitation URLs).
//!
//! No `=` padding either way.
//!
//! This format appears on the wire (Ed25519 public keys in the meta-protocol
//! are 43 chars of this encoding) and on disk (PEM-ish key files), so it's
//! protocol-locked.

/// Standard alphabet, used for keys in host files and on the meta-connection.
const ALPHABET_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// URL-safe alphabet, used for invitation URLs.
const ALPHABET_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode with the standard `+/` alphabet.
#[must_use]
pub fn encode(src: &[u8]) -> String {
    encode_with(src, ALPHABET_STD)
}

/// Encode with the URL-safe `-_` alphabet.
#[must_use]
pub fn encode_urlsafe(src: &[u8]) -> String {
    encode_with(src, ALPHABET_URL)
}

fn encode_with(src: &[u8], alphabet: &[u8; 64]) -> String {
    // Walk forward in 3-byte groups; the C code walks *backward* purely so it
    // can encode in-place when src and dst overlap. We have separate buffers,
    // so the straightforward direction is fine — same output, easier to read.
    let mut out = Vec::with_capacity(src.len().div_ceil(3) * 4);
    for chunk in src.chunks(3) {
        // LSB-first pack. The chunk may be 1, 2, or 3 bytes; missing bytes
        // contribute zero, which the partial-emit below then truncates.
        let triplet = u32::from(chunk[0])
            | chunk.get(1).map_or(0, |&b| u32::from(b) << 8)
            | chunk.get(2).map_or(0, |&b| u32::from(b) << 16);
        // Emit 2 chars per input byte for partials, 4 for a full triplet.
        // (1 byte → 2 chars, 2 bytes → 3 chars, 3 bytes → 4 chars: 6 bits
        // each, no padding.)
        let nchars = chunk.len() + 1;
        let mut t = triplet;
        for _ in 0..nchars {
            out.push(alphabet[(t & 63) as usize]);
            t >>= 6;
        }
    }
    // SAFETY-ish: alphabet bytes are all ASCII, so this is valid UTF-8 by
    // construction. Use the checked variant anyway; it's not a hot path.
    String::from_utf8(out).expect("base64 alphabet is ASCII")
}

/// Decode, accepting both alphabets simultaneously.
///
/// Returns `None` if any character is outside the union alphabet. Unlike the
/// C version this does **not** decode in-place and does not silently truncate
/// at embedded NUL (the C code's `&& src[i]` check) — Rust strings can't
/// contain interior NULs from the places we read them anyway.
#[must_use]
pub fn decode(src: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len() / 4 * 3 + 2);
    let mut triplet: u32 = 0;
    let mut i = 0u32; // position within current group of 4 chars

    for byte in src.bytes() {
        let v = decode_byte(byte)?;
        triplet |= u32::from(v) << (6 * i);
        i += 1;
        if i == 4 {
            // The C code checks `triplet & 0xff000000` here to detect a -1
            // sextet that smeared into the high byte. We've already rejected
            // bad chars in `decode_byte`, so triplet is clean; emit 3 bytes.
            out.extend_from_slice(&triplet.to_le_bytes()[..3]);
            triplet = 0;
            i = 0;
        }
    }

    // Trailing partial group. i==1 means 6 bits → 0 whole output bytes (the
    // C code returns 0 here too, treating it as "no extra bytes" rather than
    // an error — odd but harmless given valid input lengths never produce
    // a 1-char tail).
    let tail = match i {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        _ => unreachable!(),
    };
    out.extend_from_slice(&triplet.to_le_bytes()[..tail]);
    Some(out)
}

/// Map a single character to its 6-bit value, accepting the union alphabet.
///
/// Returns `None` for anything else, including `'='` (tinc never pads).
#[inline]
fn decode_byte(c: u8) -> Option<u8> {
    // Explicit match rather than a 256-byte table: the optimizer turns this
    // into a jump table anyway, and the source stays grep-able for "where
    // does the union-alphabet thing happen".
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}
