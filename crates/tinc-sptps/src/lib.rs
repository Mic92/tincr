//! SPTPS — Simple Peer-to-Peer Security. The handshake and record layer
//! tinc 1.1 uses for both meta-protocol auth and the data channel.
//!
//! ## What this is a port of
//!
//! `src/sptps.c`, function-for-function. The C is small (774 lines) and
//! has no dependencies past the crypto primitives — which `tinc-crypto`'s
//! KAT vectors proved equivalent. So this crate is "structurally boring on
//! purpose": every method here has a corresponding `static bool` in the C,
//! named the same, doing the same thing in the same order. The interesting
//! work was the byte-level KATs; this is plumbing.
//!
//! That said, three places diverge from a mechanical translation, because
//! the C does something Rust can't or shouldn't:
//!
//! 1. **No callbacks.** `sptps.c` fires `send_data`/`receive_record`
//!    re-entrantly during `sptps_receive_data`. Rust doesn't want closures
//!    captured in a struct that outlives a borrow. We accumulate
//!    [`Output`]s and return them — same shape as `tinc-ffi`'s `Event`,
//!    deliberately, so the differential tests in `tests/vs_c.rs` can
//!    compare event-for-event.
//!
//! 2. **No `alloca`.** The SIG transcript and the PRF seed are heap
//!    `Vec`s on every handshake step. The transcript is at most
//!    `1 + 65 + 65 + label.len()` bytes; the allocation is not a hot path.
//!
//! 3. **RNG injected, not global.** `send_kex` calls `randomize()` which is
//!    a process-global in the C. We take an `RngCore` so the differential
//!    test can feed identical bytes to both sides. Production wires
//!    `OsRng`.
//!
//! ## What "compatible" means
//!
//! Same wire bytes given same inputs. The differential test
//! (`tests/vs_c.rs`) seeds Rust and `tinc-ffi`'s C harness with the same
//! RNG stream and asserts that:
//!
//! - Rust-initiator ↔ C-responder completes a handshake and round-trips
//!   app data
//! - C-initiator ↔ Rust-responder, same
//! - Rust ↔ Rust produces *byte-identical* wire output to C ↔ C
//!
//! The last one is the real check. Passing handshakes doesn't prove the
//! transcript bytes match — Ed25519 will accept any signature over the
//! right message. Byte-identity proves we built the same message.

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

pub use state::{Framing, Output, Role, Sptps, SptpsError};

/// Differential-fuzz hook. Gated on `--cfg fuzzing` (set by cargo-fuzz)
/// so the daemon build doesn't grow a public API surface for what is
/// strictly a test concern.
#[cfg(fuzzing)]
pub use state::ReplayWindow;

/// Body of a KEX record: `version[1] ‖ nonce[32] ‖ ecdh_pubkey[32]`.
///
/// The KEX wire payload. 65 bytes. A flat byte array rather than a
/// struct so there's no `#[repr(packed)]` to forget — it goes on the wire byte-for-byte
/// either way, and the field accessors are just slice math.
pub const KEX_LEN: usize = 65;

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

/// Stream-mode wire overhead when encrypted: `len[2] + type[1] + tag[16]`.
/// The body length goes in the 2-byte header; this is what surrounds it.
pub const STREAM_OVERHEAD: usize = 19;

/// Datagram-mode wire overhead when encrypted: `seqno[4] + type[1] + tag[16]`.
/// `SPTPS_DATAGRAM_OVERHEAD` in `sptps.h`.
pub const DATAGRAM_OVERHEAD: usize = 21;

#[cfg(test)]
mod tests {
    /// `sptps.h` line 58: `STATIC_ASSERT(sizeof(sptps_kex_t) == 65, ...)`.
    /// We don't have a `sptps_kex_t`, but the same arithmetic must hold.
    #[test]
    fn kex_layout() {
        use tinc_crypto::ecdh::PUBLIC_LEN;
        assert_eq!(super::KEX_LEN, 1 + super::NONCE_LEN + PUBLIC_LEN);
    }

    /// `sptps.h` line 68: `STATIC_ASSERT(sizeof(sptps_key_t) == 128, ...)`.
    /// Our PRF output is two ChaPoly keys back-to-back; same constraint.
    #[test]
    fn key_material_layout() {
        use tinc_crypto::chapoly::KEY_LEN;
        assert_eq!(2 * KEY_LEN, 128);
    }
}
