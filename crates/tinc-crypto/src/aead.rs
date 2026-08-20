//! SPTPS record AEAD selector.
//!
//! SPTPS has always used the OpenSSH-style ChaCha20-Poly1305 in
//! [`chapoly`](crate::chapoly). On every CPU shipped since ~2013
//! (x86 AES-NI+PCLMUL, ARMv8 AES+PMULL) AES-256-GCM is 2-3× faster
//! per byte, so tincr↔tincr edges can opt into it via the
//! `SPTPSCipher` host-file knob. There is **no runtime negotiation**:
//! both ends must be configured identically, and the choice is mixed
//! into the SPTPS KDF label so a mismatch derives different session
//! keys and fails the first authenticated record instead of silently
//! corrupting data.
//!
//! The default — and the only value C tinc 1.1 understands — is
//! ChaCha20-Poly1305. With the default, [`SptpsAead::label_suffix`]
//! is empty and the wire bytes are identical to a build without this
//! module.
//!
//! ## Construction (AES-256-GCM)
//!
//! Same key schedule as the ChaCha path: the SPTPS PRF still emits a
//! 64-byte key blob per direction, of which AES-256-GCM consumes the
//! first 32 (matching ChaCha's "main key" half). The 32-bit record
//! seqno is mapped onto GCM's 96-bit nonce as `0⁸ ‖ seqno_be⁴` —
//! exactly the IETF-ChaCha layout, so the nonce-uniqueness argument
//! is the same one [`chapoly`](crate::chapoly) already relies on.
//! No AAD; tag is 16 bytes, so record framing is unchanged.
//!
//! ## Backend
//!
//! OpenSSL `EVP_aes_256_gcm`, same thread-local reused-context
//! pattern as [`chapoly`](crate::chapoly)'s backend. AES-NI/PMULL
//! (VAES/AVX-512 where available) with a constant-time fallback;
//! [`hw_aes_available`] lets the daemon warn at startup.

use crate::chapoly::{ChaPoly, KEY_LEN, OpenError, TAG_LEN};

/// Which AEAD an SPTPS session seals records with.
///
/// `Default` is [`ChaCha20Poly1305`](Self::ChaCha20Poly1305) — the
/// only value wire-compatible with C tinc 1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SptpsAead {
    /// OpenSSH-style ChaCha20-Poly1305 ([`chapoly`](crate::chapoly)).
    /// Wire-compatible with C tinc 1.1.
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM via OpenSSL. tincr↔tincr only.
    Aes256Gcm,
}

impl SptpsAead {
    /// Parse the `SPTPSCipher` config value. Case-insensitive.
    /// `None` for unknown strings — caller turns that into a config
    /// error so a typo doesn't silently fall back to the default and
    /// then fail the handshake MAC against a correctly-configured
    /// peer.
    #[must_use]
    pub fn from_config_str(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("chacha20-poly1305") {
            Some(Self::ChaCha20Poly1305)
        } else if s.eq_ignore_ascii_case("aes-256-gcm") {
            Some(Self::Aes256Gcm)
        } else {
            None
        }
    }

    /// Canonical config spelling. Round-trips through
    /// [`from_config_str`](Self::from_config_str).
    #[must_use]
    pub const fn as_config_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }

    /// Discriminator appended to the SPTPS `label` before it feeds
    /// the SIG transcript and PRF seed.
    ///
    /// **Empty for the default** so a fresh config produces the exact
    /// same handshake bytes as C tinc — that invariant is what the
    /// `vs_c` differential tests pin. Any non-default value emits a
    /// fixed-shape `[kex_byte, cipher_byte]` pair; a mismatch then
    /// changes the SIG transcript, the peer's `ecdsa_verify` fails,
    /// and the session aborts with `BadSig` before any record key is
    /// derived.
    ///
    /// `kex_byte` is reserved for the post-quantum-KEX selector (a
    /// sibling change) and is always `0` from this module. Emitting
    /// both bytes whenever *either* knob is non-default means the two
    /// features compose without re-deriving the suffix shape: a peer
    /// with PQ-KEX + ChaCha sends `[kex, 0x00]`, one with X25519 +
    /// AES sends `[0x00, 0x01]`, and the all-default peer sends
    /// nothing — every pair of mismatched configs differs in at least
    /// one signed byte.
    #[must_use]
    pub const fn label_suffix(self) -> &'static [u8] {
        match self {
            Self::ChaCha20Poly1305 => b"",
            Self::Aes256Gcm => b"\x00\x01",
        }
    }

    /// Second byte of the `[kex, cipher]` label suffix appended in
    /// [`Sptps::start_with`](../tinc_sptps). 0 = C-tinc default.
    #[must_use]
    pub const fn discriminator(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 0,
            Self::Aes256Gcm => 1,
        }
    }
}

/// Runtime check for the CPU features `ring`'s fast AES-GCM path
/// needs. `false` means ring will fall back to bitsliced AES + soft
/// GHASH — still constant-time per ring's docs, but slow enough that
/// the operator almost certainly wanted ChaCha instead.
#[must_use]
pub fn hw_aes_available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        // PMULL is the GHASH half; AES alone isn't enough.
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        false
    }
}

/// SPTPS record sealer, dispatching to ChaCha20-Poly1305 or
/// AES-256-GCM by the configured [`SptpsAead`].
///
/// Drop-in for [`ChaPoly`]: same `seal`/`open`/`seal_into`/`open_into`
/// signatures, same 64-byte key blob (AES consumes the first 32),
/// same 16-byte tag, same "seqno-is-the-nonce" model. `new` is one
/// 64-byte copy; the AES key schedule runs in the thread-local EVP
/// context, cached across records of the same key.
pub struct SptpsCipher {
    aead: SptpsAead,
    /// Always populated: holds and zeroizes the full 64-byte blob,
    /// serves the ChaCha arm directly.
    chapoly: ChaPoly,
}

impl SptpsCipher {
    /// Key a session cipher.
    #[must_use]
    pub fn new(aead: SptpsAead, key: &[u8; KEY_LEN]) -> Self {
        Self {
            aead,
            chapoly: ChaPoly::new(key),
        }
    }

    /// Which AEAD this cipher was keyed for.
    #[must_use]
    pub const fn aead(&self) -> SptpsAead {
        self.aead
    }

    /// Borrow the raw 64-byte key. See [`ChaPoly::key_bytes`].
    #[must_use]
    pub const fn key_bytes(&self) -> &[u8; KEY_LEN] {
        self.chapoly.key_bytes()
    }

    /// 96-bit GCM nonce from a 32-bit record seqno: `0⁸ ‖ seqno_be⁴`
    /// (the wire seqno is 4 bytes, so the high half is always zero —
    /// uniqueness reduces to seqno uniqueness, as for ChaCha).
    #[inline]
    fn gcm_nonce(seqno: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seqno.to_be_bytes());
        n
    }

    #[inline]
    fn aes_key(&self) -> &[u8; 32] {
        self.chapoly.key_bytes()[..32]
            .try_into()
            .expect("32-byte prefix")
    }

    /// Encrypt `plaintext` and append a 16-byte tag. See
    /// [`ChaPoly::seal`].
    #[must_use]
    pub fn seal(&self, seqno: u64, plaintext: &[u8]) -> Vec<u8> {
        match self.aead {
            SptpsAead::ChaCha20Poly1305 => self.chapoly.seal(seqno, plaintext),
            SptpsAead::Aes256Gcm => {
                let mut out = plaintext.to_vec();
                let tag = gcm::seal(self.aes_key(), &Self::gcm_nonce(seqno), &mut out);
                out.extend_from_slice(&tag);
                out
            }
        }
    }

    /// In-place hot-path encrypt. See [`ChaPoly::seal_into`] for the
    /// buffer-layout contract; this matches it exactly so the SPTPS
    /// framing code stays AEAD-agnostic.
    pub fn seal_into(
        &self,
        seqno: u64,
        type_byte: u8,
        body: &[u8],
        out: &mut Vec<u8>,
        encrypt_from: usize,
    ) {
        match self.aead {
            SptpsAead::ChaCha20Poly1305 => self
                .chapoly
                .seal_into(seqno, type_byte, body, out, encrypt_from),
            SptpsAead::Aes256Gcm => {
                debug_assert_eq!(out.len(), encrypt_from);
                out.push(type_byte);
                out.extend_from_slice(body);
                let tag = gcm::seal(
                    self.aes_key(),
                    &Self::gcm_nonce(seqno),
                    &mut out[encrypt_from..],
                );
                out.extend_from_slice(&tag);
            }
        }
    }

    /// Verify and decrypt. See [`ChaPoly::open`].
    ///
    /// # Errors
    /// [`OpenError`] on short input or tag mismatch.
    pub fn open(&self, seqno: u64, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        match self.aead {
            SptpsAead::ChaCha20Poly1305 => self.chapoly.open(seqno, sealed),
            SptpsAead::Aes256Gcm => {
                let mut out = Vec::with_capacity(sealed.len());
                self.open_into(seqno, sealed, &mut out, 0)?;
                Ok(out)
            }
        }
    }

    /// In-place hot-path decrypt. See [`ChaPoly::open_into`] for the
    /// buffer-layout contract — in particular, `out`'s length is
    /// restored on `Err` (GCM decrypts before the tag verifies, so
    /// the failed plaintext bytes linger in spare capacity, same as
    /// the previous ring backend).
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
        match self.aead {
            SptpsAead::ChaCha20Poly1305 => self.chapoly.open_into(seqno, sealed, out, decrypt_at),
            SptpsAead::Aes256Gcm => {
                let ct_len = sealed.len().checked_sub(TAG_LEN).ok_or(OpenError)?;
                let (ct, tag) = sealed.split_at(ct_len);
                debug_assert_eq!(out.len(), decrypt_at);
                out.extend_from_slice(ct);
                if gcm::open(
                    self.aes_key(),
                    &Self::gcm_nonce(seqno),
                    &mut out[decrypt_at..],
                    tag,
                ) {
                    Ok(())
                } else {
                    out.truncate(decrypt_at);
                    Err(OpenError)
                }
            }
        }
    }
}

mod gcm {
    // The crate denies unsafe_code; this FFI module is the one opt-out.
    #![allow(unsafe_code)]

    use super::TAG_LEN;
    use openssl_sys as ffi;
    use std::cell::RefCell;

    /// Per-thread encrypt/decrypt contexts, reused across records.
    /// The last key is cached so steady-state records re-init IV only
    /// (the AES key schedule is the expensive part).
    struct Ctx {
        enc: *mut ffi::EVP_CIPHER_CTX,
        dec: *mut ffi::EVP_CIPHER_CTX,
        enc_key: [u8; 32],
        dec_key: [u8; 32],
        keyed: [bool; 2],
    }

    impl Ctx {
        fn new() -> Self {
            // SAFETY: constructors + one-time cipher bind; null-checked.
            unsafe {
                let enc = ffi::EVP_CIPHER_CTX_new();
                let dec = ffi::EVP_CIPHER_CTX_new();
                assert!(!enc.is_null() && !dec.is_null());
                let ok = ffi::EVP_EncryptInit_ex(
                    enc,
                    ffi::EVP_aes_256_gcm(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                ) & ffi::EVP_DecryptInit_ex(
                    dec,
                    ffi::EVP_aes_256_gcm(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                );
                assert_eq!(ok, 1, "EVP_aes_256_gcm bind");
                Self {
                    enc,
                    dec,
                    enc_key: [0; 32],
                    dec_key: [0; 32],
                    keyed: [false; 2],
                }
            }
        }
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            // SAFETY: owned non-null pointers, freed exactly once.
            unsafe {
                ffi::EVP_CIPHER_CTX_free(self.enc);
                ffi::EVP_CIPHER_CTX_free(self.dec);
            }
            self.enc_key.zeroize();
            self.dec_key.zeroize();
        }
    }

    thread_local! {
        static CTX: RefCell<Ctx> = RefCell::new(Ctx::new());
    }

    /// Encrypt `buf` in place, return the 16-byte tag.
    pub(super) fn seal(key: &[u8; 32], iv: &[u8; 12], buf: &mut [u8]) -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            let fresh = !(c.keyed[0] && c.enc_key == *key);
            if fresh {
                c.enc_key = *key;
                c.keyed[0] = true;
            }
            let mut n = 0;
            let len = i32::try_from(buf.len()).expect("record < 2GiB");
            // SAFETY: ctx pre-bound to AES-256-GCM; key 32B, iv 12B
            // (GCM default IV length); in-place update writes exactly
            // `len` bytes; GET_TAG writes TAG_LEN into `tag`.
            let ok = unsafe {
                ffi::EVP_EncryptInit_ex(
                    c.enc,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    if fresh { key.as_ptr() } else { std::ptr::null() },
                    iv.as_ptr(),
                ) & ffi::EVP_EncryptUpdate(c.enc, buf.as_mut_ptr(), &raw mut n, buf.as_ptr(), len)
                    & ffi::EVP_EncryptFinal_ex(c.enc, buf.as_mut_ptr(), &raw mut n)
                    & ffi::EVP_CIPHER_CTX_ctrl(
                        c.enc,
                        ffi::EVP_CTRL_GCM_GET_TAG,
                        16,
                        tag.as_mut_ptr().cast(),
                    )
            };
            assert_eq!(ok, 1, "GCM seal");
        });
        tag
    }

    /// Decrypt `buf` in place; `true` iff the tag verifies.
    pub(super) fn open(key: &[u8; 32], iv: &[u8; 12], buf: &mut [u8], tag: &[u8]) -> bool {
        debug_assert_eq!(tag.len(), TAG_LEN);
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            let fresh = !(c.keyed[1] && c.dec_key == *key);
            if fresh {
                c.dec_key = *key;
                c.keyed[1] = true;
            }
            let mut n = 0;
            let len = i32::try_from(buf.len()).expect("record < 2GiB");
            // SAFETY: as in `seal`; SET_TAG reads TAG_LEN bytes from
            // `tag`, final verifies and returns 0 on mismatch.
            unsafe {
                let ok = ffi::EVP_DecryptInit_ex(
                    c.dec,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    if fresh { key.as_ptr() } else { std::ptr::null() },
                    iv.as_ptr(),
                ) & ffi::EVP_DecryptUpdate(c.dec, buf.as_mut_ptr(), &raw mut n, buf.as_ptr(), len)
                    & ffi::EVP_CIPHER_CTX_ctrl(
                        c.dec,
                        ffi::EVP_CTRL_GCM_SET_TAG,
                        16,
                        tag.as_ptr().cast_mut().cast(),
                    );
                ok == 1 && ffi::EVP_DecryptFinal_ex(c.dec, buf.as_mut_ptr(), &raw mut n) == 1
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_str_roundtrip() {
        for a in [SptpsAead::ChaCha20Poly1305, SptpsAead::Aes256Gcm] {
            assert_eq!(SptpsAead::from_config_str(a.as_config_str()), Some(a));
        }
        assert_eq!(
            SptpsAead::from_config_str("AES-256-GCM"),
            Some(SptpsAead::Aes256Gcm)
        );
        assert_eq!(SptpsAead::from_config_str("aes256gcm"), None);
    }

    /// Load-bearing wire-compat invariant: default suffix is empty,
    /// so the SPTPS label (and therefore SIG transcript and PRF seed)
    /// is byte-identical to a build without this module. The
    /// `vs_c.rs` differential suite is the end-to-end check; this is
    /// the tripwire that names the culprit when that suite breaks.
    #[test]
    fn default_label_suffix_empty() {
        assert_eq!(SptpsAead::default(), SptpsAead::ChaCha20Poly1305);
        assert!(SptpsAead::default().label_suffix().is_empty());
        assert_eq!(SptpsAead::Aes256Gcm.label_suffix(), b"\x00\x01");
    }

    /// `open_into`'s out-unchanged-on-Err contract for the AES arm.
    /// The shard RX fast path (`rx.rs::rx_open`) relies on a forged
    /// packet leaving `scratch` at `[0u8; headroom]`; ChaPoly gets
    /// this for free (MAC-then-extend), the AES arm has to truncate.
    #[test]
    fn aes_open_into_err_leaves_out_unchanged() {
        let s = SptpsCipher::new(SptpsAead::Aes256Gcm, &[0x11; KEY_LEN]);
        let mut bad = s.seal(9, b"body");
        *bad.last_mut().unwrap() ^= 1;
        let mut out = vec![0u8; 6];
        assert!(s.open_into(9, &bad, &mut out, 6).is_err());
        assert_eq!(out, vec![0u8; 6]);
    }
}
