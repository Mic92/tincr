//! MAC-layer routing for `RMODE_SWITCH` (`route.c:1025-1100`).
//!
//! Exact-match MAC lookup; unknown → broadcast (switch learning).
//! C `learn_mac` (`:524-556`) is split out: we return [`LearnAction`],
//! daemon does the subnet-add + ADD_SUBNET broadcast.
//!
//! Daemon-side: `age_subnets` (`:491-521`), `route_broadcast`
//! (`:559`). DEFERRED(chunk-9): `do_decrement_ttl` (`:1056`),
//! `priorityinheritance` (`:1063`), PMTU clamp (`:1073-1100`).

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::route::RouteResult;

/// `ethernet.h:36`. C `route_mac` doesn't check this (`:1028`); the
/// caller `route()` does at `:1132`. We check anyway (we're `pub`).
pub const ETH_HDR_LEN: usize = 14;

/// C `mac_t` (`net.h:92`).
pub type Mac = [u8; 6];

/// `learn_mac` extraction (`route.c:524-556`). Daemon does the
/// actual subnet-add + `ADD_SUBNET` broadcast.
///
/// New-vs-Refresh is provisional: `mac_table` is a snapshot of ALL
/// nodes' MACs, not just `myself`'s. The C scopes the lookup to
/// `myself` (`:525`); the daemon does that check on receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnAction {
    /// `:1031` source != myself.
    NotOurs,

    /// `:528 if(!subnet)`. Daemon: subnet_add, ADD_SUBNET, arm timer.
    New(Mac),

    /// `:551-555 else`. Daemon: bump lease (no gossip). Fires even
    /// for remotely-owned MACs (VM migration); daemon re-scopes.
    Refresh(Mac),
}

/// `route_mac` (`route.c:1025-1100`).
///
/// `frame` includes the real eth header (TAP). Unknown dest →
/// `Broadcast` (`:1042`), not `Unreachable` — switches flood.
///
/// `from_myself`: gates learning (`:1031`). `source`: for the
/// `:1047` loop check (we have the table here, unlike route_ipv4).
/// `myself`: gates the FMODE_OFF/decrement_ttl deferrals (`:1052`).
/// `resolve`: `None` → Broadcast (stale gossip safe default).
///
/// # Panics
/// Never; `try_into` is length-checked. Clippy doc note.
#[must_use]
pub fn route_mac<T, S: std::hash::BuildHasher>(
    frame: &[u8],
    from_myself: bool,
    source: &str,
    myself: &str,
    mac_table: &HashMap<Mac, String, S>,
    resolve: impl FnOnce(&str) -> Option<T>,
) -> (RouteResult<T>, LearnAction) {
    // route.c:1132 checklength (C does it at dispatch level; we're pub)
    if frame.len() < ETH_HDR_LEN {
        return (
            RouteResult::TooShort {
                need: ETH_HDR_LEN,
                have: frame.len(),
            },
            LearnAction::NotOurs,
        );
    }

    // :1033, :1039
    #[allow(clippy::missing_panics_doc)]
    let src: Mac = frame[6..12].try_into().expect("len-checked above");
    #[allow(clippy::missing_panics_doc)]
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

    // DEFERRED(chunk-9): :1052 FMODE_OFF (pure transit only); :1056
    // decrement_ttl (do_decrement_ttl is eth-aware, route.c:327);
    // :1063 priorityinheritance; :1073 via=; :1075 directonly;
    // :1079-1100 PMTU clamp; :1102 clamp_mss.
    let _ = myself; // :1052 owner != myself goes here

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

    #[allow(clippy::unnecessary_wraps)] // signature must match `resolve`
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

    /// route.c:1104 happy path.
    #[test]
    fn route_mac_forwards_known_dest() {
        let t = table();
        let f = frame([0xbb; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// route.c:1042-1045.
    #[test]
    fn route_mac_broadcasts_unknown_dest() {
        let t = table();
        let f = frame([0xdd; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// route.c:1031-1035: learn New independent of route decision.
    #[test]
    fn route_mac_learns_new_src_when_from_myself() {
        let t = table();
        let f = frame([0xdd; 6], [0xee; 6]); // src not in table

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
        assert_eq!(learn, LearnAction::New([0xee; 6]));
    }

    /// route.c:551-555.
    #[test]
    fn route_mac_refreshes_known_src_when_from_myself() {
        let t = table();
        let f = frame([0xbb; 6], [0xaa; 6]); // src IS in table

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
        assert_eq!(learn, LearnAction::Refresh([0xaa; 6]));
    }

    /// route.c:1031: source != myself → no learning.
    #[test]
    fn route_mac_does_not_learn_when_not_from_myself() {
        let t = table();
        let f = frame([0xbb; 6], [0xee; 6]);

        let (r, learn) = route_mac(&f, false, "charlie", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// route.c:1132 checklength.
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

    #[test]
    fn route_mac_exactly_eth_hdr() {
        let t = table();
        let f = frame([0xbb; 6], [0xaa; 6]);
        assert_eq!(f.len(), ETH_HDR_LEN);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
    }

    /// route.c:1047-1050.
    #[test]
    fn route_mac_loop_detection() {
        let t = table();
        let f = frame([0xbb; 6], [0xee; 6]); // dst owned by bob; bob sent it

        let (r, learn) = route_mac(&f, false, "bob", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Unsupported {
                reason: "MAC routing loop (owner == source)",
            }
        );
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// ff:ff:... never in table → Broadcast (no special case).
    #[test]
    fn route_mac_broadcast_mac() {
        let t = table();
        let f = frame([0xff; 6], [0xaa; 6]);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
    }

    /// 33:33:... (RFC 2464 §7). Not in table → Broadcast.
    #[test]
    fn route_mac_multicast_mac_v6() {
        let t = table();
        let f = frame([0x33, 0x33, 0x00, 0x00, 0x00, 0x01], [0xaa; 6]);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
    }

    /// 01:00:5e:... (RFC 1112 §6.4).
    #[test]
    fn route_mac_multicast_mac_v4() {
        let t = table();
        let f = frame([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01], [0xaa; 6]);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
    }

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

    /// Learn + route are independent.
    #[test]
    fn route_mac_learns_and_forwards() {
        let t = table();
        let f = frame([0xcc; 6], [0xee; 6]);

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Forward {
                to: "charlie".into()
            }
        );
        assert_eq!(learn, LearnAction::New([0xee; 6]));
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
