//! OpenSSH-style ChaCha20-Poly1305, as used by SPTPS. Not RFC 8439:
//! 8-byte big-endian seqno nonce, DJB ChaCha with a 64-bit block
//! counter, `tag = Poly1305(ciphertext)` with no AAD/pad/length
//! framing, 64-byte key of which only the first 32 feed ChaCha.
//! Block 0 of the keystream is the Poly1305 key, blocks 1+ encrypt
//! the payload. C reference: `src/chacha-poly1305/chacha-poly1305.c`.
//!
//! Backed by OpenSSL (`EVP_chacha20` IV = LE64 counter ‖ nonce, so
//! DJB semantics come for free, plus the `POLY1305` EVP_MAC): ~3×
//! the pure-Rust AVX2 crates on x86-64 via the AVX-512/IFMA kernels.
//! Contexts are thread-local and reused across records — only the
//! key/IV re-init runs per packet. Wire bytes are pinned by the
//! C-generated KAT vectors.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key material size: the exact PRF output SPTPS derives per
/// direction. Only `key[0..32]` is ever used.
pub const KEY_LEN: usize = 64;

/// Poly1305 tag size, appended to every sealed record.
pub const TAG_LEN: usize = 16;

/// SPTPS record sealer. Keyed once, driven by the record seqno.
#[derive(ZeroizeOnDrop)]
pub struct ChaPoly {
    key: [u8; KEY_LEN],
}

/// Decryption rejected the ciphertext. Deliberately uninformative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenError;

impl ChaPoly {
    /// Set the 64-byte key.
    #[must_use]
    pub const fn new(key: &[u8; KEY_LEN]) -> Self {
        Self { key: *key }
    }

    /// Borrow the raw 64-byte key, e.g. to build a per-session copy.
    /// Caller is responsible for zeroizing that copy.
    #[must_use]
    pub const fn key_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    fn iv(seqno: u64) -> [u8; 16] {
        let mut iv = [0u8; 16]; // counter=0 ‖ BE seqno
        iv[8..].copy_from_slice(&seqno.to_be_bytes());
        iv
    }

    /// Encrypt `plaintext` and append a 16-byte tag.
    #[must_use]
    pub fn seal(&self, seqno: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        backend::with_record(&self.key[..32], &Self::iv(seqno), |rec| {
            let mut poly_key = rec.block0();
            rec.xor_into(plaintext, &mut out);
            let tag = rec.poly1305(&poly_key, &out);
            poly_key.zeroize();
            out.extend_from_slice(&tag);
        });
        out
    }

    /// Hot-path seal: append `type_byte` + `body` encrypted, then the
    /// tag, to `out`. `out[..encrypt_from]` must already hold the
    /// plaintext record header.
    pub fn seal_into(
        &self,
        seqno: u64,
        type_byte: u8,
        body: &[u8],
        out: &mut Vec<u8>,
        encrypt_from: usize,
    ) {
        debug_assert_eq!(out.len(), encrypt_from);
        backend::with_record(&self.key[..32], &Self::iv(seqno), |rec| {
            let mut poly_key = rec.block0();
            // One aligned update: a separate 1-byte type update would
            // push the body through EVP's partial-block slow path.
            out.push(type_byte);
            out.extend_from_slice(body);
            rec.xor_in_place(&mut out[encrypt_from..]);
            let tag = rec.poly1305(&poly_key, &out[encrypt_from..]);
            poly_key.zeroize();
            out.extend_from_slice(&tag);
        });
    }

    /// Verify the trailing tag and decrypt.
    ///
    /// # Errors
    /// [`OpenError`] on short input or tag mismatch.
    pub fn open(&self, seqno: u64, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        let mut out = Vec::with_capacity(sealed.len());
        self.open_into(seqno, sealed, &mut out, 0)?;
        Ok(out)
    }

    /// Hot-path open: verify the tag, then append the decrypted body
    /// to `out`. On error `out` is unchanged.
    ///
    /// # Errors
    /// [`OpenError`] on short input or tag mismatch.
    pub fn open_into(
        &self,
        seqno: u64,
        sealed: &[u8],
        out: &mut Vec<u8>,
        decrypt_at: usize,
    ) -> Result<(), OpenError> {
        let ct_len = sealed.len().checked_sub(TAG_LEN).ok_or(OpenError)?;
        let (ct, tag) = sealed.split_at(ct_len);
        debug_assert_eq!(out.len(), decrypt_at);

        backend::with_record(&self.key[..32], &Self::iv(seqno), |rec| {
            // MAC-then-decrypt, matching the C reference.
            let mut poly_key = rec.block0();
            let expected = rec.poly1305(&poly_key, ct);
            poly_key.zeroize();
            if expected.ct_eq(tag).unwrap_u8() != 1 {
                return Err(OpenError);
            }
            rec.xor_into(ct, out);
            Ok(())
        })
    }
}

mod backend {
    // The crate denies unsafe_code; this FFI module is the one opt-out.
    #![expect(unsafe_code)]

    use super::TAG_LEN;
    use openssl_sys as ffi;
    use std::cell::RefCell;
    use std::sync::OnceLock;

    /// Fetched `POLY1305` EVP_MAC: immutable, refcounted, thread-safe.
    struct Mac(*mut ffi::EVP_MAC);
    unsafe impl Send for Mac {}
    unsafe impl Sync for Mac {}

    fn mac() -> *mut ffi::EVP_MAC {
        static MAC: OnceLock<Mac> = OnceLock::new();
        MAC.get_or_init(|| {
            ffi::init();
            // SAFETY: NUL-terminated name, default libctx/properties.
            let p = unsafe {
                ffi::EVP_MAC_fetch(std::ptr::null_mut(), c"POLY1305".as_ptr(), std::ptr::null())
            };
            assert!(!p.is_null(), "OpenSSL POLY1305 EVP_MAC missing");
            Mac(p)
        })
        .0
    }

    /// Per-thread contexts, reused across records: only key/IV
    /// re-init runs per packet, no alloc/free.
    struct Ctx {
        cipher: *mut ffi::EVP_CIPHER_CTX,
        mac: *mut ffi::EVP_MAC_CTX,
    }

    impl Ctx {
        fn new() -> Self {
            // SAFETY: plain constructors; null-checked. The cipher is
            // bound once here — per-record init passes NULL cipher
            // (key/IV only), skipping the costly provider re-fetch.
            let (cipher, mac) = unsafe { (ffi::EVP_CIPHER_CTX_new(), ffi::EVP_MAC_CTX_new(mac())) };
            assert!(!cipher.is_null() && !mac.is_null());
            let ok = unsafe {
                ffi::EVP_EncryptInit_ex(
                    cipher,
                    ffi::EVP_chacha20(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            assert_eq!(ok, 1, "EVP_chacha20 bind");
            Self { cipher, mac }
        }
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            // SAFETY: owned non-null pointers, freed exactly once.
            unsafe {
                ffi::EVP_CIPHER_CTX_free(self.cipher);
                ffi::EVP_MAC_CTX_free(self.mac);
            }
        }
    }

    thread_local! {
        static CTX: RefCell<Ctx> = RefCell::new(Ctx::new());
    }

    /// One record's contexts, keyed/positioned by [`with_record`].
    pub(super) struct Record {
        cipher: *mut ffi::EVP_CIPHER_CTX,
        mac: *mut ffi::EVP_MAC_CTX,
    }

    impl Record {
        /// Keystream block 0: the Poly1305 key. One full-block update
        /// (partial updates hit EVP's buffering slow path). u64-typed
        /// so the wipe is 8 volatile stores, not 64.
        pub(super) fn block0(&mut self) -> [u8; 32] {
            use zeroize::Zeroize;
            const ZEROS: [u8; 64] = [0u8; 64];
            let mut block = [0u64; 8];
            let mut n = 0;
            // SAFETY: distinct 64-byte in/out buffers.
            let ok = unsafe {
                ffi::EVP_EncryptUpdate(
                    self.cipher,
                    block.as_mut_ptr().cast::<u8>(),
                    &raw mut n,
                    ZEROS.as_ptr(),
                    64,
                )
            };
            assert_eq!(ok, 1);
            let mut key = [0u8; 32];
            for (dst, src) in key.chunks_exact_mut(8).zip(&block[..4]) {
                dst.copy_from_slice(&src.to_ne_bytes());
            }
            block.zeroize();
            key
        }

        /// XOR `buf` through the keystream in place.
        pub(super) fn xor_in_place(&mut self, buf: &mut [u8]) {
            let mut n = 0;
            // SAFETY: exact in-place aliasing (out == in) is EVP's
            // supported in-place mode; stream cipher writes exactly
            // `inl` bytes.
            let ok = unsafe {
                ffi::EVP_EncryptUpdate(
                    self.cipher,
                    buf.as_mut_ptr(),
                    &raw mut n,
                    buf.as_ptr(),
                    i32::try_from(buf.len()).expect("record < 2GiB"),
                )
            };
            assert_eq!(ok, 1);
            debug_assert_eq!(usize::try_from(n).ok(), Some(buf.len()));
        }

        /// XOR `input` through the keystream, appending to `out`.
        pub(super) fn xor_into(&mut self, input: &[u8], out: &mut Vec<u8>) {
            let at = out.len();
            out.reserve(input.len());
            let mut n = 0;
            // SAFETY: `reserve` guarantees capacity; chacha is a
            // stream cipher so EVP writes exactly `inl` bytes into the
            // spare capacity, made visible by `set_len` after the
            // success check. Input and output never alias.
            unsafe {
                let ok = ffi::EVP_EncryptUpdate(
                    self.cipher,
                    out.as_mut_ptr().add(at),
                    &raw mut n,
                    input.as_ptr(),
                    i32::try_from(input.len()).expect("record < 2GiB"),
                );
                assert_eq!(ok, 1);
                out.set_len(at + input.len());
            }
            debug_assert_eq!(usize::try_from(n).ok(), Some(input.len()));
        }

        /// Raw one-shot Poly1305 over `msg` (no padding, no length
        /// suffix). Re-keys the reused thread-local MAC ctx.
        pub(super) fn poly1305(&mut self, key: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
            let mut tag = [0u8; TAG_LEN];
            let mut taglen = 0usize;
            // SAFETY: ctx is valid; init re-keys, update/final read
            // only the stated lengths and write exactly TAG_LEN bytes.
            unsafe {
                let ok = ffi::EVP_MAC_init(self.mac, key.as_ptr(), 32, std::ptr::null())
                    & ffi::EVP_MAC_update(self.mac, msg.as_ptr(), msg.len())
                    & ffi::EVP_MAC_final(self.mac, tag.as_mut_ptr(), &raw mut taglen, TAG_LEN);
                assert_eq!(ok, 1, "EVP_MAC POLY1305 failed");
            }
            debug_assert_eq!(taglen, TAG_LEN);
            tag
        }
    }

    /// Run `f` with a keystream freshly keyed/positioned for one record.
    pub(super) fn with_record<R>(key: &[u8], iv: &[u8; 16], f: impl FnOnce(&mut Record) -> R) -> R {
        debug_assert_eq!(key.len(), 32);
        CTX.with(|c| {
            let c = c.borrow_mut();
            // SAFETY: ctx is valid and pre-bound to EVP_chacha20; key
            // is 32 bytes, iv 16 — the sizes the cipher declares.
            let ok = unsafe {
                ffi::EVP_EncryptInit_ex(
                    c.cipher,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    iv.as_ptr(),
                )
            };
            assert_eq!(ok, 1, "EVP_chacha20 init");
            f(&mut Record {
                cipher: c.cipher,
                mac: c.mac,
            })
        })
    }
}
