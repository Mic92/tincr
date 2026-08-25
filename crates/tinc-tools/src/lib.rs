//! Shared library code for the standalone tinc binaries: the `tinc`
//! administration CLI plus the `sptps_keypair` and `sptps_test`
//! helpers. Each binary in `src/bin` is a thin entry point; everything
//! testable lives here as modules (`names`, `keypair`, `cmd`, ...).
//!
//! `sptps_keypair` generates an Ed25519 identity in tinc's PEM-ish key
//! file format, and `sptps_test` runs an SPTPS session over a real
//! UDP socket so independent implementations can be checked against
//! each other end-to-end on the wire (the `tests/self_roundtrip.rs`
//! harness drives the full Rust↔C 2×2 matrix and parses the
//! `Listening on N...` stderr line as a stable API).
//!
//! The `tinc` CLI itself covers both filesystem-only commands
//! (`init`, `generate-keys`, `export`/`import`, `fsck`, `sign`/`verify`,
//! `invite`/`join`) and daemon-RPC commands (`dump`, `top`, `log`, ...)
//! that talk to a running daemon over its control socket.

// `deny` not `forbid`: `cmd::info::fmt_localtime` needs one `unsafe` block for
// `libc::localtime_r`, which nix doesn't wrap and which isn't worth chrono's
// dependency tree. The wire-safety crates stay `forbid`.
#![deny(unsafe_code)]
#![warn(unreachable_pub)]

// Backticking proper nouns reads like a ransom note. Same allow as
// tinc-crypto/tinc-sptps.

pub mod cmd;
pub mod ctl;
pub mod idp;
pub mod keypair;
pub mod names;
#[cfg(test)]
pub mod testutil;
mod tui;
