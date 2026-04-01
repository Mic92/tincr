//! Wire-protocol parse/format.
//!
//! tinc's meta-protocol is plain ASCII: `printf` to build, `sscanf` to
//! parse, newline-terminated. This crate does just that — no I/O, no
//! crypto, no graph mutation. It exists so the message *grammar* can be
//! property-tested in isolation from the daemon.
//!
//! The C handlers (`*_h` in `protocol_*.c`) `sscanf` and then immediately
//! `lookup_node()` / `subnet_add()` — there is no parse seam to call
//! through FFI. So this crate is verified by:
//!
//! - **Fixed-string KATs**: lift the exact `send_request(c, "%d %x %s ...")`
//!   format strings, generate test inputs, assert the parse extracts what
//!   `sscanf` would.
//! - **Round-trip proptests**: `parse(format(x)) == x` for every message.
//!
//! ## Why hand-rolled, not `nom`
//!
//! 23 `sscanf` call sites, all `%d`/`%x`/`%s`/`%hd` over space-separated
//! tokens. A token splitter and four conversions is ~50 LOC. `nom` would
//! be more code than the parsers it'd parse with.
//!
//! ## What `%2048s` means
//!
//! `MAX_STRING` in `protocol.h` is `"%2048s"` — `sscanf %s` stops at
//! whitespace and writes up to 2048 chars + NUL. So fields are
//! whitespace-delimited and at most 2048 bytes. The whitespace is always
//! single spaces (because `printf` `%d %s` puts exactly one). We split on
//! ASCII space, not the full whitespace class — that's what `%s` would
//! see and what's actually on the wire.

#![forbid(unsafe_code)]

pub mod addr;
pub mod msg;
pub mod request;
pub mod subnet;
mod tok;

pub use addr::AddrStr;
pub use request::Request;
pub use subnet::Subnet;
pub use tok::ParseError;

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
