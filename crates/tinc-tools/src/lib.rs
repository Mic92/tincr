//! Standalone binaries: `sptps_keypair`, `sptps_test`, `tinc`.
//!
//! ## `sptps_keypair` / `sptps_test`
//!
//! Cross-implementation testing on real sockets. See `tests/self_roundtrip.rs`
//! for the Rust↔C 2×2 matrix. The `tinc-sptps` differential tests prove
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
//! The CLI. Filesystem-only commands (`init`/`generate-keys`/`export`/
//! `import`/`fsck`/`sign`/`verify`/`invite`/`join`) plus daemon-RPC
//! commands (`dump`/`top`/`log`/...) over the control socket.
//!
//! Shared code lives here as a lib crate (`names`, `keypair`, `cmd`);
//! the binaries are thin entry points.

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
