//! Parsers and formatters for tinc's meta-protocol — the plain ASCII,
//! newline-terminated, space-separated request grammar spoken over
//! the SPTPS-secured control channel.
//!
//! The crate does no I/O, no crypto and no graph mutation; it just
//! turns bytes into typed message values and back, so the grammar can
//! be property-tested in isolation from the daemon. Fields are
//! whitespace-delimited and capped at 2048 bytes per token, splitting
//! is on a single ASCII space (which is what actually appears on the
//! wire), and correctness is pinned by fixed-string KATs plus
//! round-trip proptests over every message variant.

#![forbid(unsafe_code)]

pub mod addr;
pub mod msg;
pub mod request;
pub mod subnet;
mod tok;

pub use addr::AddrStr;
pub use request::Request;
pub use subnet::Subnet;
pub use tok::{ParseError, Tok};

/// `check_id` from `utils.c`: non-empty `[A-Za-z0-9_]+`.
///
/// Node names, used everywhere in the protocol. The C uses libc `isalnum`
/// which is locale-sensitive in theory; in practice tincd runs in POSIX
/// locale and the protocol assumes ASCII anyway. We match POSIX.
#[must_use]
pub fn check_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `MAX_STRING_SIZE - 1` from `protocol.h`. `sscanf %2048s` rejects
/// anything longer (well, truncates — we treat that as a parse failure).
pub const MAX_STRING: usize = 2048;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_id_basics() {
        assert!(check_id("alice"));
        assert!(check_id("BOB_2"));
        assert!(check_id("_"));
        assert!(check_id("a"));
        assert!(!check_id(""));
        assert!(!check_id("a b"));
        assert!(!check_id("a-b")); // - is not alnum or _
        assert!(!check_id("a.b"));
        assert!(!check_id("ä")); // not ASCII alnum
    }
}
