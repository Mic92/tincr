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
//! `ring::aead::AES_256_GCM`. ring carries hand-tuned AES-NI/PCLMUL
//! and ARMv8 AES/PMULL kernels and falls back to a constant-time
//! bitsliced AES otherwise. The fallback is *correct* but ~10× slower
//! and historically a side-channel minefield on shared-cache hosts;
//! [`hw_aes_available`] lets the daemon warn at startup.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

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
    /// AES-256-GCM via `ring`. tincr↔tincr only.
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
/// signatures, same 64-byte key blob, same 16-byte tag, same
/// "seqno-is-the-nonce" model. The hot UDP path constructs one of
/// these per packet from the 64-byte key snapshot in `TunnelHandles`;
/// `new` is therefore kept cheap (one 64-byte copy plus, for AES, one
/// key-schedule expansion — ~90 ns on Apple M, lost in the ~250 ns
/// seal it precedes).
pub struct SptpsCipher {
    aead: SptpsAead,
    /// Always populated. Holds the full 64-byte PRF output (and
    /// zeroizes it on drop) so [`key_bytes`](Self::key_bytes) can
    /// hand the snapshot back to the shard fast-path verbatim, and so
    /// the ChaCha arm of every seal/open call is a direct method call
    /// rather than a fresh `ChaPoly::new` per record.
    chapoly: ChaPoly,
    /// `Some` iff `aead == Aes256Gcm`. ring's `LessSafeKey` owns the
    /// expanded round keys; building it once per `SptpsCipher` rather
    /// than per `seal_into` matters for the per-packet `new` above.
    /// ring does not document zeroize-on-drop for the schedule, but
    /// the raw key bytes are wiped via `chapoly`'s `ZeroizeOnDrop`.
    aes: Option<LessSafeKey>,
}

impl SptpsCipher {
    /// Key a session cipher.
    ///
    /// # Panics
    ///
    /// Only if `ring` rejects a 32-byte AES-256 key, which its API
    /// contract says it never does for `AES_256_GCM`. Unwrapping here
    /// keeps the signature infallible like [`ChaPoly::new`].
    #[must_use]
    pub fn new(aead: SptpsAead, key: &[u8; KEY_LEN]) -> Self {
        let aes = match aead {
            SptpsAead::ChaCha20Poly1305 => None,
            SptpsAead::Aes256Gcm => Some(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, &key[..32]).expect("AES-256 key is 32 bytes"),
            )),
        };
        Self {
            aead,
            chapoly: ChaPoly::new(key),
            aes,
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

    /// 96-bit GCM nonce from a 32-bit record seqno: `0⁸ ‖ seqno_be⁴`.
    /// SPTPS feeds `seqno as u64` here; the high 32 bits are always
    /// zero (the wire seqno is 4 bytes), so the leading 8 zero bytes
    /// are fixed and uniqueness reduces to seqno uniqueness — the
    /// same property `SEAL_KEY_LIMIT` in `tinc-sptps` already
    /// enforces for the ChaCha path.
    #[inline]
    fn gcm_nonce(seqno: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seqno.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }

    /// Encrypt `plaintext` and append a 16-byte tag. See
    /// [`ChaPoly::seal`].
    #[expect(clippy::missing_panics_doc)] // unreachable: ring GCM seal only errs on len overflow (> 64 GiB)
    #[must_use]
    pub fn seal(&self, seqno: u64, plaintext: &[u8]) -> Vec<u8> {
        match &self.aes {
            None => self.chapoly.seal(seqno, plaintext),
            Some(k) => {
                let mut out = plaintext.to_vec();
                let tag = k
                    .seal_in_place_separate_tag(Self::gcm_nonce(seqno), Aad::empty(), &mut out)
                    .expect("GCM seal");
                out.extend_from_slice(tag.as_ref());
                out
            }
        }
    }

    /// In-place hot-path encrypt. See [`ChaPoly::seal_into`] for the
    /// buffer-layout contract; this matches it exactly so the SPTPS
    /// framing code stays AEAD-agnostic.
    #[expect(clippy::missing_panics_doc)] // unreachable: ring GCM seal only errs on len overflow (> 64 GiB)
    pub fn seal_into(
        &self,
        seqno: u64,
        type_byte: u8,
        body: &[u8],
        out: &mut Vec<u8>,
        encrypt_from: usize,
    ) {
        match &self.aes {
            None => self
                .chapoly
                .seal_into(seqno, type_byte, body, out, encrypt_from),
            Some(k) => {
                debug_assert_eq!(out.len(), encrypt_from);
                out.push(type_byte);
                out.extend_from_slice(body);
                let tag = k
                    .seal_in_place_separate_tag(
                        Self::gcm_nonce(seqno),
                        Aad::empty(),
                        &mut out[encrypt_from..],
                    )
                    .expect("GCM seal");
                out.extend_from_slice(tag.as_ref());
            }
        }
    }

    /// Verify and decrypt. See [`ChaPoly::open`].
    ///
    /// # Errors
    /// [`OpenError`] on short input or tag mismatch.
    pub fn open(&self, seqno: u64, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        match &self.aes {
            None => self.chapoly.open(seqno, sealed),
            Some(k) => {
                // ring's `open_in_place` wants the tag at the tail of
                // the same buffer. One copy is unavoidable here; this
                // is the cold path (handshake / TCP fallback).
                if sealed.len() < TAG_LEN {
                    return Err(OpenError);
                }
                let mut buf = sealed.to_vec();
                let pt_len = k
                    .open_in_place(Self::gcm_nonce(seqno), Aad::empty(), &mut buf)
                    .map_err(|_| OpenError)?
                    .len();
                buf.truncate(pt_len);
                Ok(buf)
            }
        }
    }

    /// In-place hot-path decrypt. See [`ChaPoly::open_into`] for the
    /// buffer-layout contract — in particular, **`out` is unchanged on
    /// `Err`**. The shard RX fast-path relies on that to leave its
    /// scratch buffer at `[0u8; headroom]` when a forged packet fails
    /// the tag, so the AES arm truncates back on failure to match
    /// ChaPoly's MAC-then-extend ordering.
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
        match &self.aes {
            None => self.chapoly.open_into(seqno, sealed, out, decrypt_at),
            Some(k) => {
                if sealed.len() < TAG_LEN {
                    return Err(OpenError);
                }
                debug_assert_eq!(out.len(), decrypt_at);
                // ring decrypts in place over `ct‖tag`, so we have to
                // extend first; restore the contract by truncating on
                // failure (and by stripping the tag tail on success).
                out.extend_from_slice(sealed);
                if let Ok(pt) =
                    k.open_in_place(Self::gcm_nonce(seqno), Aad::empty(), &mut out[decrypt_at..])
                {
                    let pt_len = pt.len();
                    out.truncate(decrypt_at + pt_len);
                    Ok(())
                } else {
                    out.truncate(decrypt_at);
                    Err(OpenError)
                }
            }
        }
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
