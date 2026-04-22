//! Wire-protocol crypto primitives for tinc: the AEAD, KDF, ECDH and
//! base64 building blocks used by SPTPS and the on-disk key files.
//!
//! Nothing here is general-purpose cryptography — each module
//! reproduces a specific framing or encoding quirk required for
//! interoperability with the existing tinc network, which off-the-shelf
//! RustCrypto crates do not match. Correctness is pinned by the Known
//! Answer Tests in `tests/kat.rs`; a KAT failure after a dependency
//! bump means the dependency changed something protocol-relevant, not
//! that the test is wrong.

// `forbid` would block the `#![allow(unsafe_code)]` on chapoly's
// vendored-asm Poly1305 FFI. Everything else stays safe; the allow is
// scoped to that one function and every block carries a SAFETY comment.
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::module_name_repetitions,
    // ChaCha, OpenSSH, X25519 etc. are proper nouns, not code identifiers
    clippy::doc_markdown,
)]

pub mod aead;
pub mod b64;
pub mod chapoly;
pub mod ecdh;
pub mod invite;
pub mod prf;
pub mod sign;
