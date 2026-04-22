//! MAC-layer routing for `RMODE_SWITCH`.
//!
//! Exact-match MAC lookup; unknown → broadcast (switch learning).
//! `learn_mac` is split out: we return [`LearnAction`], daemon does
//! the subnet-add + `ADD_SUBNET` broadcast.
//!
//! Daemon-side: `age_subnets` (`:491-521`), `route_broadcast`
//! (`:559`), and the post-route mutations (`:1052-1102`).

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::route::RouteResult;

/// Ethernet header length. We check this here (we're `pub`).
pub(crate) const ETH_HDR_LEN: usize = 14;

pub(crate) type Mac = [u8; 6];

/// `learn_mac` extraction. Daemon does the actual subnet-add +
/// `ADD_SUBNET` broadcast.
///
/// New-vs-Refresh is provisional: `mac_table` is a snapshot of ALL
/// nodes' MACs, not just `myself`'s. The C scopes the lookup to
/// `myself` (`:525`); the daemon does that check on receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LearnAction {
    /// `:1031` source != myself.
    NotOurs,

    /// `:528 if(!subnet)`. Daemon: `subnet_add`, `ADD_SUBNET`, arm timer.
    New(Mac),

    /// `:551-555 else`. Daemon: bump lease (no gossip). Fires even
    /// for remotely-owned MACs (VM migration); daemon re-scopes.
    Refresh(Mac),
}

/// `route_mac`. `frame` includes the real eth header (TAP). Unknown
/// dest →
/// `Broadcast` (`:1042`), not `Unreachable` — switches flood.
///
/// `from_myself`: gates learning (`:1031`). `source`: for the
/// `:1047` loop check (we have the table here, unlike `route_ipv4`).
/// `myself`: gates the `FMODE_OFF/decrement_ttl` deferrals (`:1052`).
/// `resolve`: `None` → Broadcast (stale gossip safe default).
///
/// # Panics
/// Never; `try_into` is length-checked. Clippy doc note.
#[must_use]
pub(crate) fn route_mac<T, S: std::hash::BuildHasher>(
    frame: &[u8],
    from_myself: bool,
    source: &str,
    myself: &str,
    mac_table: &HashMap<Mac, String, S>,
    resolve: impl FnOnce(&str) -> Option<T>,
) -> (RouteResult<T>, LearnAction) {
    if frame.len() < ETH_HDR_LEN {
        return (
            RouteResult::TooShort {
                need: ETH_HDR_LEN,
                have: frame.len(),
            },
            LearnAction::NotOurs,
        );
    }

    // :1033, :1039 — expects are infallible: ETH_HDR_LEN guard above ensures 14+ bytes
    let src: Mac = frame[6..12].try_into().expect("len-checked above");
    let dst: Mac = frame[0..6].try_into().expect("len-checked above");

    // :1031-1035 learn_mac (daemon does the actual subnet_add/broadcast)
    let learn = if from_myself {
        if mac_table.contains_key(&src) {
            LearnAction::Refresh(src)
        } else {
            LearnAction::New(src)
        }
    } else {
        LearnAction::NotOurs
    };

    // :1040-1041 lookup_subnet_mac(NULL, &dest)
    let Some(owner) = mac_table.get(&dst) else {
        // :1042-1045 route_broadcast. Also covers ff:ff:... and
        // multicast — never in the table, no special case.
        return (RouteResult::Broadcast, learn);
    };
    // :1047-1050 loop detection. C logs WARNING + drops (no MAC-layer
    // ICMP). route_ipv4 defers this to daemon; we have the table here.
    if owner.as_str() == source {
        return (
            RouteResult::Unsupported {
                reason: "MAC routing loop (owner == source)",
            },
            learn,
        );
    }

    // :1052-1102 (FMODE_OFF, decrement_ttl, priorityinheritance,
    // via=, directonly, PMTU clamp, clamp_mss): all daemon-side in
    // dispatch_route_result — they need tunnels/last_routes/settings.
    let _ = myself;

    // :1104 send_packet. resolve None (stale gossip) → Broadcast.
    match resolve(owner) {
        Some(to) => (RouteResult::Forward { to }, learn),
        None => (RouteResult::Broadcast, learn),
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: Mac, src: Mac) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETH_HDR_LEN);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x08, 0x00]);
        f
    }

    #[expect(clippy::unnecessary_wraps)] // signature must match `resolve`
    fn id(n: &str) -> Option<String> {
        Some(n.to_owned())
    }

    fn table() -> HashMap<Mac, String> {
        let mut t = HashMap::new();
        t.insert([0xaa; 6], "alice".into());
        t.insert([0xbb; 6], "bob".into());
        t.insert([0xcc; 6], "charlie".into());
        t
    }

    /// All standard-shape cases: `table()` fixture + `frame()` helper,
    /// `myself` param constant. Varies `dst/src/from_myself/source`.
    /// C-refs preserved in row labels.
    #[test]
    fn route_mac_table() {
        type Row = (
            &'static str,
            Mac,
            Mac,
            bool,
            &'static str,
            RouteResult<String>,
            LearnAction,
        );
        use LearnAction::{New, NotOurs, Refresh};
        use RouteResult::{Broadcast, Forward, Unsupported};

        // frame() always emits exactly ETH_HDR_LEN — boundary case is
        // every row (was route_mac_exactly_eth_hdr).
        assert_eq!(frame([0; 6], [0; 6]).len(), ETH_HDR_LEN);

        let fwd = |to: &str| Forward { to: to.into() };
        let loop_ = Unsupported {
            reason: "MAC routing loop (owner == source)",
        };
        #[rustfmt::skip]
        let cases: &[Row] = &[
            // (label,                                       dst,                          src,       from_myself, source,    route,          learn)
            ("forwards known dest",                [0xbb;6],                     [0xaa;6],  false,       "alice",   fwd("bob"),     NotOurs),
            ("broadcasts unknown dest",            [0xdd;6],                     [0xaa;6],  false,       "alice",   Broadcast,      NotOurs),
            ("learns New (src not in table)",      [0xdd;6],                     [0xee;6],  true,        "myself",  Broadcast,      New([0xee;6])),
            ("refreshes (src IS in table)",        [0xbb;6],                     [0xaa;6],  true,        "myself",  fwd("bob"),     Refresh([0xaa;6])),
            ("no learn when !from_myself",         [0xbb;6],                     [0xee;6],  false,       "charlie", fwd("bob"),     NotOurs),
            ("loop (owner==source)",               [0xbb;6],                     [0xee;6],  false,       "bob",     loop_,           NotOurs),
            ("ff:ff:.. broadcast MAC → not in table",        [0xff;6],                     [0xaa;6],  false,       "alice",   Broadcast,      NotOurs),
            ("33:33:.. v6 multicast (RFC 2464 §7)",          [0x33,0x33,0,0,0,1],          [0xaa;6],  false,       "alice",   Broadcast,      NotOurs),
            ("01:00:5e:.. v4 multicast (RFC 1112 §6.4)",     [0x01,0x00,0x5e,0,0,1],       [0xaa;6],  false,       "alice",   Broadcast,      NotOurs),
            ("learn + route independent (New + Forward)",    [0xcc;6],                     [0xee;6],  true,        "myself",  fwd("charlie"), New([0xee;6])),
        ];
        let t = table();
        for (label, dst, src, from_myself, source, want_r, want_learn) in cases {
            let f = frame(*dst, *src);
            let (r, learn) = route_mac(&f, *from_myself, source, "myself", &t, id);
            assert_eq!(r, *want_r, "{label}: route");
            assert_eq!(learn, *want_learn, "{label}: learn");
        }
    }

    /// Truncated frame (not `frame()` shape).
    #[test]
    fn route_mac_too_short() {
        let t = table();
        let f = vec![0u8; 13];

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::TooShort {
                need: ETH_HDR_LEN,
                have: 13,
            }
        );
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// Custom table (myself owns a MAC). Different setup → separate.
    #[test]
    fn route_mac_forwards_to_self() {
        let mut t = HashMap::new();
        t.insert([0xaa; 6], "myself".into());
        t.insert([0xbb; 6], "bob".into());

        let f = frame([0xaa; 6], [0xbb; 6]);

        let (r, _) = route_mac(&f, false, "bob", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Forward {
                to: "myself".into()
            }
        );
    }

    /// Offset KAT: `memcpy(&src, &DATA[6], 6)` / `(&dest, &DATA[0], 6)`.
    #[test]
    fn route_mac_kat_real_frame() {
        // 60 bytes (eth min). Locally-administered MACs.
        let dst: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let src: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let mut f = Vec::with_capacity(60);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x08, 0x00]);
        f.resize(60, 0);

        let mut t = HashMap::new();
        t.insert(dst, "destnode".into());

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Forward {
                to: "destnode".into()
            }
        );
        assert_eq!(learn, LearnAction::New(src));
    }

    /// Cold-start: empty table → everything floods.
    #[test]
    fn route_mac_empty_table_broadcasts() {
        let t = HashMap::new();
        let f = frame([0xbb; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
        assert_eq!(learn, LearnAction::New([0xaa; 6]));
    }
}
