//! `netutl.c`: `sockaddr2str` / `str2sockaddr` — but only the wire-string
//! shape, not the `getaddrinfo` resolution.
//!
//! ## Why addresses are just strings here
//!
//! `sockaddr2str` calls `getnameinfo(NI_NUMERICHOST | NI_NUMERICSERV)`.
//! For `AF_INET` that's the dotted-quad. For `AF_INET6` it's RFC 5952
//! plus a `%scopeid` that the C immediately strips. For `AF_UNSPEC` it's
//! the literal string `"unspec"`. And for `AF_UNKNOWN` — tinc's escape
//! hatch — it's *whatever string was originally fed in*.
//!
//! That last one is key. `str2sockaddr` does `getaddrinfo(AI_NUMERICHOST)`
//! and on failure stuffs the input into `AF_UNKNOWN` verbatim. So the
//! protocol layer's contract is: address and port are arbitrary
//! whitespace-free tokens. Numeric resolution happens *later*, in the
//! socket layer, when something tries to `connect()`.
//!
//! For the Rust port that means: at parse time, just take the string.
//! Don't validate. Don't `IpAddr::parse`. The daemon resolves when it
//! needs to. This crate has no I/O.
//!
//! ## What this module *does* provide
//!
//! A newtype with the wire constraints baked in: non-empty,
//! whitespace-free (so `printf %s` and `sscanf %s` agree on
//! boundaries), ≤2048 bytes. That's it.

use core::fmt;

use crate::tok::ParseError;
use crate::MAX_STRING;

/// One address-or-port string field, as `sockaddr2str` would emit and
/// `str2sockaddr` would consume. Opaque token; resolution is the
/// daemon's problem.
///
/// Why a newtype and not just `String`: makes the proptest generator's
/// constraints obvious, and the `Display` impl documents that no
/// escaping happens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddrStr(String);

impl AddrStr {
    /// `"unspec"`: what `sockaddr2str` emits for `AF_UNSPEC`. Shows up
    /// in `ADD_EDGE` for the local-address field on the relay path.
    pub const UNSPEC: &'static str = "unspec";

    /// Construct, enforcing the `%s`-round-trip invariant: no whitespace,
    /// non-empty, fits in `MAX_STRING`.
    ///
    /// # Errors
    /// `ParseError` if the constraint is violated. Same opaque error as
    /// everything else — the daemon doesn't distinguish failure modes.
    pub fn new(s: impl Into<String>) -> Result<Self, ParseError> {
        let s = s.into();
        if s.is_empty() || s.len() > MAX_STRING || s.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(ParseError);
        }
        Ok(Self(s))
    }

    /// Underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AddrStr {
    /// Literal pass-through. No escaping — `%s` is `%s`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<AddrStr> for String {
    fn from(a: AddrStr) -> String {
        a.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts() {
        for s in [
            "10.0.0.1",
            "::1",
            "fe80::1",                          // scope ID is stripped before the wire
            "655",                              // port
            "unspec",                           // AF_UNSPEC sentinel
            "garbage-that-getaddrinfo-rejects", // AF_UNKNOWN round-trip
            "host.example.com",                 // tinc.conf can have hostnames
        ] {
            AddrStr::new(s).unwrap_or_else(|_| panic!("{s:?}"));
        }
    }

    #[test]
    fn rejects() {
        assert!(AddrStr::new("").is_err());
        assert!(AddrStr::new("a b").is_err()); // would split as two %s tokens
        assert!(AddrStr::new("a\tb").is_err());
        assert!(AddrStr::new("a\n").is_err());
        assert!(AddrStr::new("x".repeat(MAX_STRING + 1)).is_err());
        assert!(AddrStr::new("x".repeat(MAX_STRING)).is_ok());
    }
}
