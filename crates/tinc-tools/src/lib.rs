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

// `deny` not `forbid` because `cmd::info::fmt_localtime` needs ONE
// `unsafe` block for `libc::localtime_r`. nix doesn't wrap it (it's
// a TZ-file-parsing libc library function, not a syscall — outside
// nix's scope). chrono would cost ~6 transitive deps for one strftime
// call; `localtime_r` is one of the safest unsafe calls there is
// (no heap, no aliasing, pure on a valid `tm*`). The `#[allow]` is
// scoped to the one shim. Everywhere else: write code as if `forbid`.
//
// Context: the wire-safety crates (tinc-crypto, tinc-proto, etc.)
// stay `forbid` — those are the ones where `unsafe` would be a
// memory-safety regression vs the C. tinc-tools is a CLI binary that
// already does plenty of OS-specific things via nix; one localtime_r
// is the same shape as one nix::sys::stat::utimes.
#![deny(unsafe_code)]

// Backticking proper nouns reads like a ransom note. Same allow as
// tinc-crypto/tinc-sptps.

pub mod cmd;
pub mod ctl;
pub mod keypair;
pub mod names;
pub mod tui;
