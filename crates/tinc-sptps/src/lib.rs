//! SPTPS — Simple Peer-to-Peer Security — the handshake and record
//! layer tinc 1.1 uses for both meta-protocol authentication and the
//! encrypted data channel.
//!
//! A session is driven step by step: feed it received bytes, get back
//! a list of [`Output`] events (datagrams to send, decrypted records
//! to deliver, state transitions) instead of taking re-entrant
//! callbacks. The handshake transcript and PRF seed are owned
//! `Vec`s, the AEAD and KDF come from `tinc-crypto`, and randomness
//! is supplied by an injected `RngCore` so production code can wire
//! `OsRng` while tests can drive both peers from the same
//! deterministic stream.
//!
//! Wire compatibility with the existing tinc network is the central
//! invariant and is verified by the differential tests in
//! `tests/vs_c.rs`: Rust and the C reference implementation, fed the
//! same keys and RNG, must produce byte-identical handshake and
//! record output and successfully interoperate in both directions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    // SPTPS, ChaCha, Ed25519 etc. are proper nouns, not code identifiers
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    // SptpsError is the standard idiom for an error type in a crate named
    // sptps. The lint dislikes it; the ecosystem does it anyway.
)]

mod state;

pub use state::{
    Framing, MAX_PREAUTH_RECLEN, Output, ReplayWindow, Role, SEAL_KEY_LIMIT, SEAL_REKEY_THRESHOLD,
    Sptps, SptpsError, SptpsLabel,
};
pub use tinc_crypto::aead::SptpsAead;
pub use tinc_crypto::hybrid::SptpsKex;

/// Body of a *classical* KEX record: `version[1] ‖ nonce[32] ‖
/// ecdh_pubkey[32]`. Hybrid (`SptpsKex::X25519MlKem768`) appends an
/// ML-KEM-768 `ek` for [`KEX_LEN_HYBRID`] total.
///
/// The KEX wire payload. 65 bytes. A flat byte array rather than a
/// struct so there's no `#[repr(packed)]` to forget — it goes on the wire byte-for-byte
/// either way, and the field accessors are just slice math.
pub const KEX_LEN: usize = 65;

/// Body of a hybrid KEX record: classical 65 + ML-KEM-768 `ek` 1184.
/// Both directions — SPTPS sends KEX records simultaneously, so both
/// sides publish an `ek` and the ciphertexts ride on the SIG record.
pub const KEX_LEN_HYBRID: usize = KEX_LEN + tinc_crypto::hybrid::EK_LEN;

/// Nonce length. `ECDH_SIZE` in C — same as the public key length, which
/// is a coincidence the C exploits by reusing the constant. We give them
/// distinct names.
pub const NONCE_LEN: usize = 32;

/// SPTPS protocol version, byte 0 of every KEX. Hardcoded to 0 since the
/// protocol's inception. A peer sending anything else is rejected.
pub const VERSION: u8 = 0;

/// Record type for handshake records (KEX, SIG, ACK all use this).
/// Application records use 0..=127.
pub const REC_HANDSHAKE: u8 = 128;

/// Datagram-mode wire overhead when encrypted: `seqno[4] + type[1] + tag[16]`.
/// `SPTPS_DATAGRAM_OVERHEAD` in `sptps.h`.
pub const DATAGRAM_OVERHEAD: usize = 21;
