//! Standalone binaries: `sptps_keypair`, `sptps_test`.
//!
//! These exist for one reason: **cross-implementation testing on real
//! sockets.** The Phase 2 differential tests (`tinc-sptps/tests/vs_c.rs`)
//! prove byte-identity in-process — same RNG seed, same wire bytes.
//! That's necessary but not sufficient: it doesn't exercise the socket
//! framing assumptions (TCP can split/coalesce, UDP can reorder),
//! `OsRng` instead of seeded ChaCha, or the PEM key file format end to
//! end.
//!
//! `test/integration/sptps_basic.py` drives `sptps_keypair` to generate
//! keys, then `sptps_test` server ↔ client to push 256 bytes through and
//! diff. With `SPTPS_TEST_PATH` pointed at *this* binary, the same script
//! tests Rust↔Rust. With one side C and one Rust: cross-impl on a real
//! socket.
//!
//! ## What's not ported
//!
//! `sptps_test.c` has a pile of debug knobs: `--tun` (Linux raw TUN
//! device instead of stdio), `--packet-loss` (drop N% of inbound),
//! `--special` (`#seqno`/`^rekey`/`$force-kex` line prefixes), Windows
//! stdin-thread shim. None used by `sptps_basic.py`; port on demand.
//!
//! ## What *is* API
//!
//! `sptps_basic.py` parses `"Listening on (\d+)\.\.\."` from stderr to
//! find the bound port. That line's format is load-bearing.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
// Backticking proper nouns reads like a ransom note. Same allow as
// tinc-crypto/tinc-sptps.
#![allow(clippy::doc_markdown)]

pub mod keypair;
