//! TCP simultaneous-open coordination state machine. See
//! `docs/PUNCH.md`. Pure: no I/O.
//!
//! **B** measures the PUNCH round trip, sends `SYNC` and dials rtt/2
//! later — when SYNC reaches A. **A** dials immediately on `SYNC`.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// B's wait for A's `PUNCH` reply.
pub(crate) const AWAIT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// A's wait for `SYNC` after replying.
pub(crate) const AWAIT_SYNC_TIMEOUT: Duration = Duration::from_secs(3);

/// Floor for B's delayed dial.
pub(crate) const MIN_DIAL_DELAY: Duration = Duration::from_millis(20);

/// Cap for B's delayed dial.
pub(crate) const MAX_DIAL_DELAY: Duration = Duration::from_millis(1500);

/// Payload version token.
const VERSION: &str = "v1";

/// Per-peer punch state. Removing the entry cancels the punch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PunchState {
    /// B: sent `PUNCH` at `t0`, waiting for A's echo.
    AwaitConnect { t0: Instant },
    /// A: replied with our addrs, waiting for `SYNC`.
    AwaitSync {
        b_addrs: Vec<SocketAddr>,
        armed: Instant,
    },
    /// B only: dial scheduled at `fire_at` (SYNC send + rtt/2).
    Delaying {
        addrs: Vec<SocketAddr>,
        fire_at: Instant,
    },
}

/// What the daemon must do next. Pure data; daemon does the I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PunchAction {
    /// `REQ_KEY <me> <peer> 64 v1;<nonce>;<addrlist>`.
    SendPunch { addrs: Vec<SocketAddr> },
    /// `REQ_KEY <me> <peer> 65 v1;<nonce>`.
    SendSync,
    /// One-shot timer; on fire, dial in parallel.
    DialAt { at: Instant, addrs: Vec<SocketAddr> },
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

/// B: A's echo arrived. Dial when SYNC should reach A (measured
/// rtt/2). `None` on replay.
pub(crate) fn on_punch_reply(
    state: &PunchState,
    now: Instant,
    a_addrs: Vec<SocketAddr>,
) -> Option<(PunchState, Vec<PunchAction>)> {
    let PunchState::AwaitConnect { t0 } = state else {
        return None;
    };
    let rtt = now.saturating_duration_since(*t0);
    let fire_at = now + (rtt / 2).clamp(MIN_DIAL_DELAY, MAX_DIAL_DELAY);
    Some((
        PunchState::Delaying {
            addrs: a_addrs.clone(),
            fire_at,
        },
        vec![
            PunchAction::SendSync,
            PunchAction::DialAt {
                at: fire_at,
                addrs: a_addrs,
            },
        ],
    ))
}

/// A: `SYNC` arrived — dial now. `None` on replay.
pub(crate) fn on_sync(state: &PunchState, now: Instant) -> Option<(PunchState, Vec<PunchAction>)> {
    let PunchState::AwaitSync { b_addrs, .. } = state else {
        return None;
    };
    Some((
        PunchState::Delaying {
            addrs: b_addrs.clone(),
            fire_at: now,
        },
        vec![PunchAction::DialAt {
            at: now,
            addrs: b_addrs.clone(),
        }],
    ))
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

/// `v1;<nonce_hex>;<addrlist>` — one wire token.
pub(crate) fn format_punch_payload(nonce: u64, addrs: &[SocketAddr]) -> String {
    format!("{VERSION};{nonce:016x};{}", format_addrlist(addrs))
}

/// `None` on unknown version or malformed nonce.
pub(crate) fn parse_punch_payload(s: &str) -> Option<(u64, Vec<SocketAddr>)> {
    let mut parts = s.splitn(3, ';');
    if parts.next()? != VERSION {
        return None;
    }
    let nonce = u64::from_str_radix(parts.next()?, 16).ok()?;
    Some((nonce, parse_addrlist(parts.next()?)))
}

/// `v1;<nonce_hex>`.
pub(crate) fn format_sync_payload(nonce: u64) -> String {
    format!("{VERSION};{nonce:016x}")
}

pub(crate) fn parse_sync_payload(s: &str) -> Option<u64> {
    let mut parts = s.splitn(2, ';');
    if parts.next()? != VERSION {
        return None;
    }
    u64::from_str_radix(parts.next()?, 16).ok()
}

/// Parse `,`-separated `addr_port` list. Bad elements skipped.
fn parse_addrlist(s: &str) -> Vec<SocketAddr> {
    s.split(',')
        .filter_map(|tok| {
            let (addr, port) = tok.rsplit_once('_')?;
            crate::local_addr::parse_addr_port(addr, port)
        })
        .collect()
}

/// Format addrlist. Caps at 4.
fn format_addrlist(addrs: &[SocketAddr]) -> String {
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
    fn payload_roundtrip() {
        let addrs = vec![sa("1.2.3.4:655"), sa("[2001:db8::1]:655")];
        let p = format_punch_payload(0xdead_beef, &addrs);
        assert_eq!(p, "v1;00000000deadbeef;1.2.3.4_655,2001:db8::1_655");
        assert_eq!(parse_punch_payload(&p), Some((0xdead_beef, addrs)));
        assert_eq!(parse_punch_payload("v2;00;1.2.3.4_655"), None);
        assert_eq!(parse_punch_payload("v1;zz;1.2.3.4_655"), None);

        let s = format_sync_payload(7);
        assert_eq!(parse_sync_payload(&s), Some(7));
        assert_eq!(parse_sync_payload("v2;07"), None);

        // Garbage addr elements skipped; cap at 4.
        let (_, got) = parse_punch_payload("v1;01;notanaddr,5.6.7.8_99,x").unwrap();
        assert_eq!(got, vec![sa("5.6.7.8:99")]);
        let many: Vec<_> = (1..=8).map(|i| sa(&format!("10.0.0.{i}:1"))).collect();
        assert_eq!(format_addrlist(&many).matches(',').count(), 3);
    }

    #[test]
    fn handshake_b_then_a() {
        // B: start → AwaitConnect → echo after 100ms → dial at +50ms.
        let now = Instant::now();
        let mine = vec![sa("1.1.1.1:655")];
        let (st, acts) = start(now, mine.clone());
        assert_eq!(acts, vec![PunchAction::SendPunch { addrs: mine }]);
        let later = now + Duration::from_millis(100);
        let theirs = vec![sa("2.2.2.2:655")];
        let (next, acts) = on_punch_reply(&st, later, theirs.clone()).unwrap();
        let expect = later + Duration::from_millis(50);
        assert!(matches!(next, PunchState::Delaying { fire_at, .. } if fire_at == expect));
        assert_eq!(
            acts,
            vec![
                PunchAction::SendSync,
                PunchAction::DialAt {
                    at: expect,
                    addrs: theirs
                }
            ]
        );

        // A: fresh PUNCH → AwaitSync → SYNC → dial immediately.
        let b_addrs = vec![sa("1.1.1.1:655")];
        let (st, _) = on_punch_fresh(now, b_addrs.clone(), vec![sa("2.2.2.2:655")]);
        let (next, acts) = on_sync(&st, later).unwrap();
        assert!(matches!(next, PunchState::Delaying { fire_at, .. } if fire_at == later));
        assert_eq!(
            acts,
            vec![PunchAction::DialAt {
                at: later,
                addrs: b_addrs
            }]
        );
    }

    #[test]
    fn dial_delay_clamped() {
        let now = Instant::now();
        let st = |t0| PunchState::AwaitConnect { t0 };
        // Instant reply → floor; 10s reply → cap.
        let (PunchState::Delaying { fire_at, .. }, _) =
            on_punch_reply(&st(now), now, vec![sa("1.1.1.1:1")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(fire_at - now, MIN_DIAL_DELAY);
        let later = now + Duration::from_secs(10);
        let (PunchState::Delaying { fire_at, .. }, _) =
            on_punch_reply(&st(now), later, vec![sa("1.1.1.1:1")]).unwrap()
        else {
            panic!()
        };
        assert_eq!(fire_at - later, MAX_DIAL_DELAY);
    }

    #[test]
    fn replay_dropped() {
        let now = Instant::now();
        let st = PunchState::Delaying {
            addrs: vec![sa("1.1.1.1:1")],
            fire_at: now,
        };
        assert_eq!(on_punch_reply(&st, now, vec![sa("9.9.9.9:9")]), None);
        assert_eq!(on_sync(&st, now), None);
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
        assert!(!is_expired(
            &PunchState::Delaying {
                addrs: vec![],
                fire_at: t0
            },
            t0 + Duration::from_hours(1)
        ));
    }
}
