//! Standalone binaries: `sptps_keypair`, `sptps_test`, `tinc`.
//!
//! ## `sptps_keypair` / `sptps_test`
//!
//! Cross-implementation testing on real sockets. See `tests/self_roundtrip.rs`
//! for the Rust↔C 2×2 matrix. The Phase 2 differential tests prove
//! byte-identity given the same RNG seed; these prove wire compatibility
//! with independent entropy.
//!
//! `sptps_test.c`'s debug knobs (`--tun`, `--packet-loss`, `--special`
//! line prefixes, Windows stdin-thread) aren't ported — not used by
//! `sptps_basic.py`, port on demand. The `"Listening on (\d+)\.\.\."`
//! stderr line *is* API — the test harness regexes it.
//!
//! ## `tinc`
//!
//! The CLI. Phase 4a: filesystem-only commands (`init`, eventually
//! `generate-keys`/`export`/`import`/`fsck`/`sign`/`verify`). Phase 5b
//! adds the daemon-RPC commands (`dump`/`top`/`log`/...) once there's
//! a daemon to RPC against. See `RUST_REWRITE_PLAN.md` for the split.
//!
//! Shared code lives here as a lib crate (`names`, `keypair`, `cmd`);
//! the binaries are thin entry points.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
// Backticking proper nouns reads like a ransom note. Same allow as
// tinc-crypto/tinc-sptps.
#![allow(clippy::doc_markdown)]

pub mod cmd;
pub mod keypair;
pub mod names;
