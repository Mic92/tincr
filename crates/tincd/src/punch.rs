//! TCP simultaneous-open coordination state machine.
//!
//! See `docs/PUNCH.md`. Pure half: state transitions, RTT arithmetic,
//! timeout arming. No I/O — `Instant` and `SocketAddr` only.
//!
//! Roles: **B** (initiator, the side whose `AutoShortcut` exhausted
//! its addrs) drives the handshake and dials immediately on `SYNC`.
//! **A** (responder) waits `RTT/2` after `SYNC`, where RTT is A's own
//! meta SRTT toward B's nexthop.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// B's wait for A's `PUNCH` reply. Generous: meta path is multi-hop.
pub(crate) const AWAIT_CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);

/// A's wait for `SYNC` after replying. Slightly longer than B's window
/// to cover one more half-trip + retransmit slack.
pub(crate) const AWAIT_SYNC_TIMEOUT: Duration = Duration::from_millis(3000);

/// Floor for A's delayed dial. If SRTT is wildly low don't fire before
/// B has dialed.
pub(crate) const MIN_DIAL_DELAY: Duration = Duration::from_millis(20);

/// Cap for A's delayed dial. SRTT can spike; firing seconds late risks
/// B's connect timing out first.
pub(crate) const MAX_DIAL_DELAY: Duration = Duration::from_millis(1500);

/// Per-peer punch state. Removing the entry is the cancellation
/// primitive — no cleanup hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PunchState {
    /// B: sent `PUNCH` at `t0`, waiting for A's `PUNCH`.
    AwaitConnect { t0: Instant },
    /// A: replied with our addrs, waiting for `SYNC`.
    AwaitSync {
        b_addrs: Vec<SocketAddr>,
        armed: Instant,
    },
    /// Either side: dial scheduled. B fires now; A at `now + RTT/2`.
    Delaying {
        addrs: Vec<SocketAddr>,
        fire_at: Instant,
    },
}

/// What the daemon must do next. Pure data; daemon does the I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PunchAction {
    /// `REQ_KEY <me> <peer> 64 <addrlist>`.
    SendPunch { addrs: Vec<SocketAddr> },
    /// `REQ_KEY <me> <peer> 65`.
    SendSync,
    /// One-shot timer; on fire, dial in parallel.
    DialAt { at: Instant, addrs: Vec<SocketAddr> },
    /// Replay/race; drop, keep current state.
    Drop,
}

/// B: start a punch.
pub(crate) fn start(now: Instant, my_addrs: Vec<SocketAddr>) -> (PunchState, Vec<PunchAction>) {
    (
        PunchState::AwaitConnect { t0: now },
        vec![PunchAction::SendPunch { addrs: my_addrs }],
    )
}

/// A: received `PUNCH` with no inflight state.
pub(crate) fn on_punch_fresh(
    now: Instant,
    b_addrs: Vec<SocketAddr>,
    my_addrs: Vec<SocketAddr>,
) -> (PunchState, Vec<PunchAction>) {
    (
        PunchState::AwaitSync {
            b_addrs,
            armed: now,
        },
        vec![PunchAction::SendPunch { addrs: my_addrs }],
    )
}

/// B: A's `PUNCH` arrived. Send `SYNC`, dial now.
pub(crate) fn on_punch_reply(
    state: &PunchState,
    now: Instant,
    a_addrs: Vec<SocketAddr>,
) -> (Option<PunchState>, Vec<PunchAction>) {
    let PunchState::AwaitConnect { .. } = state else {
        return (None, vec![PunchAction::Drop]);
    };
    (
        Some(PunchState::Delaying {
            addrs: a_addrs.clone(),
            fire_at: now,
        }),
        vec![
            PunchAction::SendSync,
            PunchAction::DialAt {
                at: now,
                addrs: a_addrs,
            },
        ],
    )
}

/// A: `SYNC` arrived. Dial at `now + clamp(srtt/2)`.
pub(crate) fn on_sync(
    state: &PunchState,
    now: Instant,
    srtt: Duration,
) -> (Option<PunchState>, Vec<PunchAction>) {
    let PunchState::AwaitSync { b_addrs, .. } = state else {
        return (None, vec![PunchAction::Drop]);
    };
    let fire_at = now + (srtt / 2).clamp(MIN_DIAL_DELAY, MAX_DIAL_DELAY);
    (
        Some(PunchState::Delaying {
            addrs: b_addrs.clone(),
            fire_at,
        }),
        vec![PunchAction::DialAt {
            at: fire_at,
            addrs: b_addrs.clone(),
        }],
    )
}

/// Periodic-sweep expiry check. `Delaying` is timer-owned, never swept.
pub(crate) fn is_expired(state: &PunchState, now: Instant) -> bool {
    let (since, limit) = match state {
        PunchState::AwaitConnect { t0 } => (*t0, AWAIT_CONNECT_TIMEOUT),
        PunchState::AwaitSync { armed, .. } => (*armed, AWAIT_SYNC_TIMEOUT),
        PunchState::Delaying { .. } => return false,
    };
    now.saturating_duration_since(since) > limit
}

/// Parse `,`-separated addrlist (`addr_port` elements). Lenient: bad
/// elements skipped.
pub(crate) fn parse_addrlist(s: &str) -> Vec<SocketAddr> {
    s.split(',')
        .filter_map(|tok| {
            let (addr, port) = tok.rsplit_once('_')?;
            crate::local_addr::parse_addr_port(addr, port)
        })
        .collect()
}

/// Format addrlist. Caps at 4 (parallel dial fan-out is small).
pub(crate) fn format_addrlist(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .take(4)
        .map(|sa| {
            let (a, p) = crate::local_addr::format_addr_port(sa);
            format!("{a}_{p}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addrlist_roundtrip_and_caps() {
        let addrs = vec![sa("1.2.3.4:655"), sa("[2001:db8::1]:655")];
        let s = format_addrlist(&addrs);
        assert_eq!(s, "1.2.3.4_655,2001:db8::1_655");
        assert_eq!(parse_addrlist(&s), addrs);
        // Garbage elements skipped.
        assert_eq!(
            parse_addrlist("notanaddr,5.6.7.8_99,nounderscoreport"),
            vec![sa("5.6.7.8:99")]
        );
        // Cap at 4.
        let many: Vec<_> = (1..=8).map(|i| sa(&format!("10.0.0.{i}:1"))).collect();
        assert_eq!(format_addrlist(&many).matches(',').count(), 3);
    }

    #[test]
    fn handshake_b_then_a() {
        // B side: start → AwaitConnect → reply arrives → Delaying(now).
        let now = Instant::now();
        let mine = vec![sa("1.1.1.1:655")];
        let (st, acts) = start(now, mine.clone());
        assert_eq!(acts, vec![PunchAction::SendPunch { addrs: mine }]);
        let later = now + Duration::from_millis(30);
        let theirs = vec![sa("2.2.2.2:655")];
        let (next, acts) = on_punch_reply(&st, later, theirs.clone());
        assert!(matches!(next, Some(PunchState::Delaying { fire_at, .. }) if fire_at == later));
        assert_eq!(
            acts,
            vec![
                PunchAction::SendSync,
                PunchAction::DialAt {
                    at: later,
                    addrs: theirs
                }
            ]
        );

        // A side: fresh PUNCH → AwaitSync → SYNC → Delaying(+srtt/2).
        let b_addrs = vec![sa("1.1.1.1:655")];
        let (st, _) = on_punch_fresh(now, b_addrs.clone(), vec![sa("2.2.2.2:655")]);
        let (next, acts) = on_sync(&st, later, Duration::from_millis(80));
        let expect = later + Duration::from_millis(40);
        assert!(matches!(next, Some(PunchState::Delaying { fire_at, .. }) if fire_at == expect));
        assert_eq!(
            acts,
            vec![PunchAction::DialAt {
                at: expect,
                addrs: b_addrs
            }]
        );
    }

    #[test]
    fn dial_delay_clamped() {
        let now = Instant::now();
        let st = PunchState::AwaitSync {
            b_addrs: vec![sa("1.1.1.1:1")],
            armed: now,
        };
        for (srtt, want) in [
            (Duration::ZERO, MIN_DIAL_DELAY),
            (Duration::from_secs(10), MAX_DIAL_DELAY),
        ] {
            let (Some(PunchState::Delaying { fire_at, .. }), _) = on_sync(&st, now, srtt) else {
                panic!()
            };
            assert_eq!(fire_at - now, want);
        }
    }

    #[test]
    fn replay_dropped() {
        let now = Instant::now();
        let st = PunchState::Delaying {
            addrs: vec![sa("1.1.1.1:1")],
            fire_at: now,
        };
        assert_eq!(
            on_punch_reply(&st, now, vec![sa("9.9.9.9:9")]),
            (None, vec![PunchAction::Drop])
        );
        assert_eq!(
            on_sync(&st, now, Duration::from_millis(10)),
            (None, vec![PunchAction::Drop])
        );
    }

    #[test]
    fn expiry() {
        let t0 = Instant::now();
        let eps = Duration::from_millis(1);
        for (st, limit) in [
            (PunchState::AwaitConnect { t0 }, AWAIT_CONNECT_TIMEOUT),
            (
                PunchState::AwaitSync {
                    b_addrs: vec![],
                    armed: t0,
                },
                AWAIT_SYNC_TIMEOUT,
            ),
        ] {
            assert!(!is_expired(&st, t0 + limit));
            assert!(is_expired(&st, t0 + limit + eps));
        }
        // Delaying never expires via sweep.
        assert!(!is_expired(
            &PunchState::Delaying {
                addrs: vec![],
                fire_at: t0
            },
            t0 + Duration::from_secs(3600)
        ));
    }
}
