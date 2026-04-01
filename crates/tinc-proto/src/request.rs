//! `request_t` enum + `atoi`-style discriminant parsing.
//!
//! Every protocol line starts with a decimal integer: the request number.
//! `receive_request` does `atoi(request)` and dispatches. The actual
//! message parsing happens in the per-type handlers (`id_h`, `add_edge_h`,
//! etc.); this module is just the discriminant.
//!
//! ## Why no full `parse(line) -> Message` here
//!
//! The C handlers don't share a parse layer — each does its own `sscanf`
//! and immediately mutates daemon state. There's no `struct id_msg` to
//! port. The Rust message types live in per-handler modules (`edge.rs`,
//! `auth.rs`, ...) once those are written; this enum is just the
//! `match atoi(first_field)` part.

use core::fmt;

/// Wire request types. Values match `request_t` in `protocol.h`.
///
/// `STATUS` and `ERROR` exist in the C enum but have no handler
/// (`request_entries[STATUS] = {NULL, "STATUS"}`). They're here because
/// the discriminant values are positional and skipping them would shift
/// everything after.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Request {
    Id = 0,
    Metakey = 1,
    Challenge = 2,
    ChalReply = 3,
    Ack = 4,
    /// No handler in C. Legacy.
    Status = 5,
    /// No handler in C. Legacy. (Windows `#define ERROR` conflict in C
    /// is the reason for the `#undef` in `protocol.h`; not our problem.)
    Error = 6,
    Termreq = 7,
    Ping = 8,
    Pong = 9,
    AddSubnet = 10,
    DelSubnet = 11,
    AddEdge = 12,
    DelEdge = 13,
    KeyChanged = 14,
    ReqKey = 15,
    AnsKey = 16,
    Packet = 17,
    /// 1.1 only: control socket.
    Control = 18,
    /// 1.1 only. Not a "real" request — sub-type of `ReqKey`.
    /// `request_entries[REQ_PUBKEY] = {NULL, ...}`.
    ReqPubkey = 19,
    /// 1.1 only. Same.
    AnsPubkey = 20,
    /// 1.1 only: SPTPS-tunnelled UDP packet over TCP.
    SptpsPacket = 21,
    /// 1.1 only.
    UdpInfo = 22,
    /// 1.1 only.
    MtuInfo = 23,
}

impl Request {
    /// Discriminant → enum. `None` for out-of-range, including the
    /// guard values `ALL = -1` and `LAST = 24`.
    #[must_use]
    pub fn from_id(id: i32) -> Option<Self> {
        // No `#[repr]` magic transmute: explicit match. The compiler
        // turns this into a jump table; the explicitness means adding
        // a variant without a case is a compile error, which is what
        // we want.
        Some(match id {
            0 => Self::Id,
            1 => Self::Metakey,
            2 => Self::Challenge,
            3 => Self::ChalReply,
            4 => Self::Ack,
            5 => Self::Status,
            6 => Self::Error,
            7 => Self::Termreq,
            8 => Self::Ping,
            9 => Self::Pong,
            10 => Self::AddSubnet,
            11 => Self::DelSubnet,
            12 => Self::AddEdge,
            13 => Self::DelEdge,
            14 => Self::KeyChanged,
            15 => Self::ReqKey,
            16 => Self::AnsKey,
            17 => Self::Packet,
            18 => Self::Control,
            19 => Self::ReqPubkey,
            20 => Self::AnsPubkey,
            21 => Self::SptpsPacket,
            22 => Self::UdpInfo,
            23 => Self::MtuInfo,
            _ => return None,
        })
    }

    /// `request_entries[req].name`. The C uses these for log output
    /// (`"Got %s from..."`). All-caps in C; we match.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Id => "ID",
            Self::Metakey => "METAKEY",
            Self::Challenge => "CHALLENGE",
            Self::ChalReply => "CHAL_REPLY",
            Self::Ack => "ACK",
            Self::Status => "STATUS",
            Self::Error => "ERROR",
            Self::Termreq => "TERMREQ",
            Self::Ping => "PING",
            Self::Pong => "PONG",
            Self::AddSubnet => "ADD_SUBNET",
            Self::DelSubnet => "DEL_SUBNET",
            Self::AddEdge => "ADD_EDGE",
            Self::DelEdge => "DEL_EDGE",
            Self::KeyChanged => "KEY_CHANGED",
            Self::ReqKey => "REQ_KEY",
            Self::AnsKey => "ANS_KEY",
            Self::Packet => "PACKET",
            Self::Control => "CONTROL",
            Self::ReqPubkey => "REQ_PUBKEY",
            Self::AnsPubkey => "ANS_PUBKEY",
            Self::SptpsPacket => "SPTPS_PACKET",
            Self::UdpInfo => "UDP_INFO",
            Self::MtuInfo => "MTU_INFO",
        }
    }

    /// `atoi(line)` then `from_id`. Doesn't consume — handlers re-scan
    /// from the start with `%*d` (skip the request number) anyway.
    ///
    /// `atoi` semantics: leading whitespace, optional sign, digits, stop
    /// at first non-digit. We're stricter — no leading whitespace
    /// (`send_request` never emits any) and we require the digits to be
    /// followed by either end-of-string or a space. This rejects
    /// `0garbage`, which `atoi` would parse as `0`. The protocol doesn't
    /// produce that, and accepting it would mask a corrupted-line bug.
    #[must_use]
    pub fn peek(line: &str) -> Option<Self> {
        let end = line
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(line.len());
        if end == 0 {
            return None;
        }
        // The token must be followed by space or end. `0 ...` ok, `0x` no.
        match line.as_bytes().get(end) {
            None | Some(b' ') => {}
            _ => return None,
        }
        Self::from_id(line[..end].parse().ok()?)
    }
}

impl fmt::Display for Request {
    /// `printf %d` — just the number. For building messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (*self as u8).fmt(f)
    }
}

/// Protocol version constants. `PROT_MAJOR.PROT_MINOR` in `protocol.h`.
///
/// Different `MAJOR` → cannot connect. `MINOR` is feature-negotiation
/// (1.1 features are gated on peer minor). Minor is encoded in the
/// `options` bitfield's high byte (see `protocol_auth.c` line 867:
/// `(options & 0xffffff) | (PROT_MINOR << 24)`).
pub const PROT_MAJOR: u8 = 17;
pub const PROT_MINOR: u8 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_roundtrip() {
        for i in 0..24 {
            let r = Request::from_id(i).unwrap();
            assert_eq!(r as i32, i);
            assert_eq!(r.to_string(), i.to_string());
        }
        assert!(Request::from_id(-1).is_none()); // ALL guard
        assert!(Request::from_id(24).is_none()); // LAST guard
    }

    #[test]
    fn peek() {
        assert_eq!(Request::peek("0 alice 17.7"), Some(Request::Id));
        assert_eq!(Request::peek("12 a b c"), Some(Request::AddEdge));
        assert_eq!(Request::peek("8"), Some(Request::Ping)); // no body
        assert_eq!(Request::peek("99 x"), None); // out of range
        assert_eq!(Request::peek(""), None);
        assert_eq!(Request::peek("x"), None);
        assert_eq!(Request::peek("0x"), None); // not space-terminated
                                               // atoi would accept this; we don't.
        assert_eq!(Request::peek(" 8"), None);
    }

    #[test]
    fn names_match_c() {
        // Lifted from request_entries[] in protocol.c.
        assert_eq!(Request::Id.name(), "ID");
        assert_eq!(Request::ChalReply.name(), "CHAL_REPLY");
        assert_eq!(Request::SptpsPacket.name(), "SPTPS_PACKET");
    }
}
