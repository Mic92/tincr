//! OpenSSH-style ChaCha20-Poly1305, as used by SPTPS.
//!
//! C reference: `src/chacha-poly1305/chacha-poly1305.c`.
//!
//! ## Why `chacha20poly1305` (the AEAD crate) cannot be used
//!
//! | Aspect          | tinc / OpenSSH-style          | RFC 8439 (the crate)         |
//! |-----------------|-------------------------------|------------------------------|
//! | Nonce           | 8 bytes, big-endian seqno     | 12 bytes                     |
//! | ChaCha variant  | DJB original: 64-bit counter  | IETF: 32-bit counter         |
//! | Poly1305 input  | `tag = Poly1305(ciphertext)`  | AD‖pad‖CT‖pad‖len(AD)‖len(CT)|
//! | Key size        | 64 bytes (two ChaCha keys)    | 32 bytes                     |
//!
//! The 64-byte key splits into a "main" key (`key[0..32]`, used here) and a
//! "header" key (`key[32..64]`, used by OpenSSH for length encryption but
//! **never touched by SPTPS**). We accept all 64 bytes anyway because that's
//! the size the SPTPS key schedule produces; misalignment here would silently
//! shift everything by 32 bytes.
//!
//! ## Construction
//!
//! For sequence number `n`:
//! 1. `nonce = n.to_be_bytes()` (8 bytes)
//! 2. `poly_key = ChaCha20(main_key, nonce, counter=0)[0..32]`
//! 3. `ciphertext = plaintext XOR ChaCha20(main_key, nonce, counter=1)`
//! 4. `tag = Poly1305(poly_key, ciphertext)` — no padding, no AD, no lengths
//!
//! The counter is the *block* counter inside ChaCha's state words 12–13, not
//! a byte offset.
//!
//! ## Backend
//!
//! ChaCha20 always comes from the `chacha20` crate (`ChaCha20Legacy`; its
//! NEON/AVX2 backends are competitive with hand-written asm). Poly1305 has
//! two backends behind [`backend::poly1305`], selected at build time:
//!
//! - **aarch64 + `vendored-poly1305-asm`** (default): the OpenSSL/
//!   CRYPTOGAMS `poly1305-armv8` NEON kernel, vendored under `asm/`.
//!   On Apple M-series this drops a 1400 B seal from ~2300 ns to
//!   ~830 ns. Neither `ring` nor `aws-lc` ship a standalone aarch64
//!   Poly1305 — their fast path is the *fused* RFC 8439 AEAD kernel,
//!   whose MAC framing (AAD‖pad‖CT‖pad‖lengths) is incompatible with
//!   the OpenSSH-style `Poly1305(ct)` SPTPS uses. See `asm/README.md`.
//! - **everything else**: the `poly1305` crate. Has AVX2 on x86_64,
//!   soft backend elsewhere.
//!
//! Both backends are exercised by the same C-generated KAT vectors
//! (`tests/kat.rs::chapoly_seal_matches_c`), so the wire bytes are pinned
//! regardless of which one is compiled in.

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key material size: 64 bytes, even though only the first 32 are used.
///
/// SPTPS derives exactly this many bytes per direction from its PRF
/// (`CHACHA_POLY1305_KEYLEN` in `chacha-poly1305.h`). Shrinking this would
/// shift the key schedule output and break the *next* primitive in line.
pub const KEY_LEN: usize = 64;

/// Poly1305 tag size, appended to every sealed record.
pub const TAG_LEN: usize = 16;

/// SPTPS record sealer.
///
/// Unlike a generic AEAD, this is keyed once and then driven entirely by a
/// monotonically increasing sequence number — there is no separate nonce API
/// because the protocol never needs one.
#[derive(ZeroizeOnDrop)]
pub struct ChaPoly {
    /// Only the first 32 bytes ever feed ChaCha. We keep all 64 to match the
    /// C struct layout and to make zeroize-on-drop wipe the full key blob.
    key: [u8; KEY_LEN],
}

/// Decryption rejected the ciphertext.
///
/// Deliberately uninformative: distinguishing "bad tag" from "too short" leaks
/// nothing useful to the caller and slightly more to an attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenError;

impl ChaPoly {
    /// Set the 64-byte key.
    ///
    /// Equivalent to `chacha_poly1305_set_key`. The C version also sets up a
    /// `header_ctx` from `key[32..64]`; we don't, because SPTPS never calls
    /// the header-encrypt path.
    #[must_use]
    pub const fn new(key: &[u8; KEY_LEN]) -> Self {
        Self { key: *key }
    }

    /// Borrow the raw 64-byte key.
    ///
    /// For external seal/open without holding the cipher: copy once per
    /// session (not per packet), build a fresh `ChaPoly::new(&key)`.
    /// 64 bytes is cheaper than `Arc<ChaPoly>` at ~800k seals/s — no
    /// atomic refcount on a contended cacheline. A stale key (after
    /// re-KEX) means a tag mismatch, which is exactly the signal the
    /// caller needs to ask for a fresh one.
    ///
    /// Caller is responsible for zeroizing the copy.
    #[must_use]
    pub const fn key_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// Derive the per-record Poly1305 key and a cipher positioned at block 1.
    ///
    /// Factored out so seal/open share the exact same setup — the C code
    /// duplicates these ~6 lines, which is fine in C but in Rust we'd rather
    /// have one place to get the nonce endianness wrong. Returning the cipher
    /// (rather than re-initing for the body) saves one key-schedule per
    /// record; measurable at ~800 k records/s.
    #[inline]
    fn record_state(&self, seqno: u64) -> ([u8; 32], ChaCha20Legacy) {
        // Big-endian, matching `put_u64` in the C source. ChaCha20Legacy
        // (DJB: 32-byte key, 8-byte nonce, 64-bit block counter) then loads
        // these LE into state words 14/15 — exactly what the wire protocol
        // expects. Don't "fix" the endianness.
        let nonce = seqno.to_be_bytes();
        let mut cipher = ChaCha20Legacy::new(self.key[..32].into(), (&nonce).into());

        // Block 0: keystream for the Poly1305 key. apply_keystream over zeros
        // is the idiomatic way to read raw keystream out of a StreamCipher.
        let mut poly_key = [0u8; 32];
        cipher.apply_keystream(&mut poly_key);

        // Block 1: where the actual ciphertext keystream starts. The C code
        // does this by calling chacha_ivsetup again with counter=one; we use
        // seek (which is in *bytes*, hence the 64-byte block size).
        cipher.seek(64u64);

        (poly_key, cipher)
    }

    /// Encrypt `plaintext` and append a 16-byte tag.
    ///
    /// Output length is always `plaintext.len() + TAG_LEN`. SPTPS frames are
    /// short (≤ 64KiB on the wire) so a `Vec` allocation per record is fine
    /// at this layer; the hot UDP path uses [`seal_into`](Self::seal_into)
    /// for in-place encryption.
    #[must_use]
    pub fn seal(&self, seqno: u64, plaintext: &[u8]) -> Vec<u8> {
        let (mut poly_key, mut cipher) = self.record_state(seqno);

        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        cipher.apply_keystream(&mut out);

        // RFC 8439 would do: poly.update_padded(ad); poly.update_padded(ct);
        // poly.update(len(ad)||len(ct)). tinc does none of that. The MAC is
        // over the raw ciphertext bytes, period.
        let tag = backend::poly1305(&poly_key, &out);
        poly_key.zeroize();
        out.extend_from_slice(&tag);
        out
    }

    /// In-place variant of [`seal`]. The hot-path encrypt for SPTPS data
    /// records.
    ///
    /// `out` MUST already contain `[..encrypt_from]` bytes that are NOT
    /// encrypted (e.g. the seqno header for datagram framing, or the length
    /// prefix for stream framing). This function:
    /// 1. Pushes `type_byte` at `out[encrypt_from]`.
    /// 2. Extends `out` with `body` at `encrypt_from + 1`.
    /// 3. Encrypts `out[encrypt_from..]` in-place (ChaCha20 XOR).
    /// 4. Computes Poly1305 over those same encrypted bytes, appends the
    ///    16-byte tag.
    ///
    /// Net: ONE copy of `body` (the `extend_from_slice`), zero scratch
    /// allocs. Replaces [`seal`]'s alloc-out + extend-plaintext + return-Vec
    /// with append-to-caller's-buffer + encrypt-in-place. The C reference
    /// does the same shape: encrypt in place over the same span,
    /// starting past a plaintext header.
    ///
    /// `encrypt_from` lets the caller pre-write headers that stay plaintext.
    pub fn seal_into(
        &self,
        seqno: u64,
        type_byte: u8,
        body: &[u8],
        out: &mut Vec<u8>,
        encrypt_from: usize,
    ) {
        debug_assert_eq!(out.len(), encrypt_from);
        out.push(type_byte);
        out.extend_from_slice(body);
        let (mut poly_key, mut cipher) = self.record_state(seqno);
        cipher.apply_keystream(&mut out[encrypt_from..]);
        let tag = backend::poly1305(&poly_key, &out[encrypt_from..]);
        poly_key.zeroize();
        out.extend_from_slice(&tag);
    }

    /// Verify the trailing tag and decrypt.
    ///
    /// # Errors
    ///
    /// [`OpenError`] if `sealed` is shorter than [`TAG_LEN`] or the tag does
    /// not verify. Timing of the error is independent of how many tag bytes
    /// match (constant-time compare via `subtle`).
    ///
    /// Returns the plaintext on success. The C code decrypts in-place into a
    /// caller-supplied buffer; we return a fresh `Vec` because the borrow
    /// checker makes "verify then overwrite the same slice" awkward, and
    /// again, this isn't the hot path yet.
    pub fn open(&self, seqno: u64, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        // Length check first. The C code subtracts TAG_LEN unconditionally
        // and then reads past the buffer if inlen < 16 — we'd rather not.
        let ct_len = sealed.len().checked_sub(TAG_LEN).ok_or(OpenError)?;
        let (ct, tag) = sealed.split_at(ct_len);

        let (mut poly_key, mut cipher) = self.record_state(seqno);

        // MAC-then-decrypt, matching the C order. Either order is safe here
        // (the cipher is a pure stream XOR with no key-dependent branching),
        // but matching the reference makes side-channel review easier.
        let expected = backend::poly1305(&poly_key, ct);
        poly_key.zeroize();
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(OpenError);
        }

        let mut out = ct.to_vec();
        cipher.apply_keystream(&mut out);
        Ok(out)
    }

    /// In-place variant of [`open`]. The hot-path decrypt for SPTPS data
    /// records. Mirror of [`seal_into`].
    ///
    /// `out` MUST already contain `[..decrypt_at]` bytes that the caller
    /// pre-reserved (e.g. headroom for an ethernet header). This function:
    /// 1. Verifies the trailing tag (constant-time, MAC-then-decrypt).
    /// 2. Extends `out` with the ciphertext (one `extend_from_slice` body
    ///    copy — unavoidable; can't XOR an immutable input slice in place).
    /// 3. Decrypts `out[decrypt_at..]` in-place (ChaCha20 XOR).
    ///
    /// Net: ONE copy of the ciphertext body, zero scratch allocs.
    /// Replaces [`open`]'s `ct.to_vec()` + return-Vec with append-to-
    /// caller's-buffer + decrypt-in-place. The C reference does the same
    /// shape: decrypt in place over the same span, starting past a
    /// plaintext header.
    ///
    /// # Errors
    ///
    /// [`OpenError`] if `sealed` is shorter than [`TAG_LEN`] or the tag
    /// does not verify. On error, `out` is unchanged (the extend happens
    /// only after the tag check passes).
    pub fn open_into(
        &self,
        seqno: u64,
        sealed: &[u8],
        out: &mut Vec<u8>,
        decrypt_at: usize,
    ) -> Result<(), OpenError> {
        let ct_len = sealed.len().checked_sub(TAG_LEN).ok_or(OpenError)?;
        let (ct, tag) = sealed.split_at(ct_len);

        let (mut poly_key, mut cipher) = self.record_state(seqno);

        // MAC-then-decrypt, matching the C order. Tag check BEFORE the
        // extend so a forged packet doesn't dirty the caller's buffer.
        let expected = backend::poly1305(&poly_key, ct);
        poly_key.zeroize();
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(OpenError);
        }

        debug_assert_eq!(out.len(), decrypt_at);
        out.extend_from_slice(ct);
        cipher.apply_keystream(&mut out[decrypt_at..]);
        Ok(())
    }
}

// ─── backend ────────────────────────────────────────────────────────────────

mod backend {
    use super::TAG_LEN;

    /// Raw one-shot Poly1305 over `msg` (no padding, no length suffix).
    #[cfg(tinc_poly1305_asm)]
    #[inline]
    pub(super) fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
        // The crate is `#![deny(unsafe_code)]`; the FFI is the one place we
        // must opt back in. Scoped to this function.
        #![allow(unsafe_code)]

        // SAFETY: declaration matches `tinc_poly1305` in
        // `asm/poly1305_glue.c` exactly (4× pointer/size_t args, no
        // return). Linked by `build.rs` whenever `tinc_poly1305_asm` is
        // set, so the symbol is always present when this cfg is active.
        unsafe extern "C" {
            fn tinc_poly1305(key: *const u8, inp: *const u8, len: usize, mac: *mut u8);
        }
        let mut tag = [0u8; TAG_LEN];
        // SAFETY: `tinc_poly1305` reads `key[0..32]` and `msg[0..len]`,
        // writes exactly 16 bytes to `mac`, and touches nothing else (its
        // 192-byte scratch is on its own stack). All three pointers are
        // into live slices of the stated lengths; `tag` is exclusively
        // borrowed. `msg.len()` fits `size_t` by construction.
        unsafe { tinc_poly1305(key.as_ptr(), msg.as_ptr(), msg.len(), tag.as_mut_ptr()) };
        tag
    }

    #[cfg(not(tinc_poly1305_asm))]
    #[inline]
    pub(super) fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
        use poly1305::Poly1305;
        use poly1305::universal_hash::KeyInit;
        // `compute_unpadded` is the crate's escape hatch for legacy
        // constructions that MAC the raw bytes with no AD/len framing.
        Poly1305::new(key.into()).compute_unpadded(msg).into()
    }
}
