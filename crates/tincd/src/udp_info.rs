//! `UDP_INFO`/`MTU_INFO` hint messages.
//!
//! `UDP_INFO`: relay-observed addresses propagate so endpoints can
//! hole-punch (alice → mid → bob: mid tells bob alice's UDP addr).
//! `MTU_INFO`: same shape for path-MTU.
//!
//! Pure-decision: snapshot in, action enum out, daemon does I/O.
//! Gate logic and MTU clamping ([`adjust_mtu_for_send`]) live here
//! so they're testable; udp-address-tree re-indexing and other
//! mutations stay daemon-side.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tinc_proto::msg::misc::{MtuInfo, UdpInfo};

use crate::dispatch::ConnOptions;

/// Jumbo-build MTU ceiling (9000 + 14 eth + 4 VLAN). Clamping to
/// a smaller value would underreport for jumbo peers; clamping
/// larger is harmless (PMTU finds the real ceiling).
pub(crate) const MTU_MAX: i32 = 9018;

/// Below the IPv4 minimum reassembly buffer (RFC 791); `MTU_INFO`
/// values lower than this are corrupt, not just pessimistic.
pub(crate) const MTU_MIN: i32 = 512;

/// State of `from` (the node whose address we're learning) for
/// `on_receive_udp_info`. `None` at the call-site means the node isn't
/// in our graph → `UnknownNode`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FromState {
    /// Direct meta connection to `from`; we already know their address
    /// from the TCP edge, so a relay's UDP observation isn't useful.
    pub directly_connected: bool,
    /// We already have a working UDP address (got a reply from it).
    /// Don't overwrite.
    pub udp_confirmed: bool,
    /// Route to `from` is direct (no static relay between us).
    /// `UDP_INFO` terminates at the static relay, so a message arriving
    /// when this is `false` wandered too far.
    pub via_is_self: bool,
}

/// Per-node MTU state for `from` in `on_receive_mtu_info`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FromMtuState {
    /// Current effective MTU we use for packets to `from`.
    pub mtu: u16,
    /// Lower probe bound.
    pub minmtu: u16,
    /// Upper probe bound.
    pub maxmtu: u16,
}

/// Snapshot of one node's PMTU convergence for [`adjust_mtu_for_send`].
/// `minmtu == maxmtu` means PMTU discovery has converged (the probe
/// ladder narrows until they meet).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PmtuSnapshot {
    pub minmtu: u16,
    pub maxmtu: u16,
}

impl PmtuSnapshot {
    /// Probing converged.
    #[must_use]
    pub(crate) const fn converged(self) -> bool {
        self.minmtu == self.maxmtu
    }
}

/// Gates before sending `UDP_INFO`. Returns `true` if the message
/// should be sent; the caller builds the actual `UdpInfo`.
///
/// On `true` return when `from_is_myself`, the caller must also bump
/// the `last_sent` timestamp so the debounce works.
#[expect(clippy::too_many_arguments)] // each param is one independent snapshot read; struct just moves the noise
#[expect(clippy::fn_params_excessive_bools)] // independent gates, not a state machine
#[must_use]
pub(crate) fn should_send_udp_info(
    // Sending a hint to ourselves would be pointless: after relay
    // resolution, `to` is the actual hop; if that's us, we're the endpoint.
    to_is_myself: bool,
    // Graph says no path to `to`.
    to_reachable: bool,
    // Direct meta connection to `to` → they already know our address
    // from the edge; the UDP_INFO would be circular. Only checked when
    // we originate.
    to_directly_connected: bool,
    // Whether we originate (enables the directly-connected and debounce
    // checks). When forwarding, the originator already debounced and
    // the directly-connected check is about the originator, not us.
    from_is_myself: bool,
    // Any party opting out of UDP (TCPONLY) makes UDP info moot.
    from_options: ConnOptions,
    to_options: ConnOptions,
    myself_options: ConnOptions,
    // Next hop's protocol options; UDP_INFO requires protocol minor ≥ 5.
    // Older peers would log "unknown request type" and possibly drop
    // the connection.
    nexthop_options: ConnOptions,
    // Per-`to` debounce. `None` = never sent → no debounce. Only
    // checked when `from_is_myself`.
    last_sent: Option<Instant>,
    now: Instant,
    interval: Duration,
) -> bool {
    if to_is_myself {
        return false;
    }
    if !to_reachable {
        return false;
    }
    // Originator-only checks.
    if from_is_myself {
        if to_directly_connected {
            return false;
        }
        if let Some(last) = last_sent
            && now.saturating_duration_since(last) < interval
        {
            return false;
        }
    }
    if (myself_options | from_options | to_options).contains(ConnOptions::TCPONLY) {
        return false;
    }
    // Relay too old to understand UDP_INFO.
    if nexthop_options.prot_minor() < 5 {
        return false;
    }
    true
}

/// What to do with a received `UDP_INFO`.
///
/// Every variant except `UnknownNode` and `DroppedPastRelay` implies
/// "and then forward up the chain"; the daemon re-runs
/// `should_send_udp_info(from, to)` on Forward / Update.
///
/// `N` is the caller's node-id type. The forwarding variants carry
/// `from`/`to` so the caller doesn't have to re-unwrap `Option`s
/// whose `Some`-ness this function already proved.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UdpInfoAction<N> {
    /// `from` is not directly connected, not UDP-confirmed, and the
    /// message's address differs from what we have. Daemon updates
    /// `from`'s UDP address then forwards. The payoff case: a relay
    /// told us where `from` is reachable.
    UpdateAndForward {
        from: N,
        to: N,
        new_addr: SocketAddr,
    },
    /// Forward without learning: we're directly connected, or
    /// UDP-confirmed, or the addr matches what we already have, or the
    /// addr didn't parse.
    Forward { from: N, to: N },
    /// Message wandered past a static relay. Log warning, drop; not a
    /// protocol violation, so the connection stays up.
    DroppedPastRelay,
    /// `from` or `to` not in our graph. Drop without connection
    /// teardown.
    UnknownNode,
}

/// `UDP_INFO` receive decision. Pure: parsing already happened; we get
/// the parsed message and node snapshots.
///
/// `from`/`to`: `None` if the node isn't in our graph; the `N` rides
///   along so the caller gets it back in the action.
/// `current_from_addr`: what we currently hold for `from`. `None` =
///   never learned. Only differing addresses trigger an update.
#[must_use]
pub(crate) fn on_receive_udp_info<N>(
    parsed: &UdpInfo,
    from: Option<(N, FromState)>,
    to: Option<N>,
    current_from_addr: Option<SocketAddr>,
) -> UdpInfoAction<N> {
    let Some((from_nid, from)) = from else {
        return UdpInfoAction::UnknownNode;
    };

    if !from.via_is_self {
        return UdpInfoAction::DroppedPastRelay;
    }

    // Learn `from`'s address only if we don't have a better source of
    // truth (direct connection or confirmed UDP). If the address fails
    // to parse (garbage or `unspec`), fall through to Forward.
    let learned = if !from.directly_connected && !from.udp_confirmed {
        parse_socket_addr(parsed.addr.as_str(), parsed.port.as_str())
            .filter(|a| current_from_addr != Some(*a))
    } else {
        None
    };

    // If `to` is unknown, drop the learned address as well: the
    // learning is opportunistic, and losing one relay observation when
    // our graph is inconsistent is fine.
    let Some(to_nid) = to else {
        return UdpInfoAction::UnknownNode;
    };

    match learned {
        Some(new_addr) => UdpInfoAction::UpdateAndForward {
            from: from_nid,
            to: to_nid,
            new_addr,
        },
        None => UdpInfoAction::Forward {
            from: from_nid,
            to: to_nid,
        },
    }
}

/// Join `addr` and `port` `AddrStr` tokens into a `SocketAddr`.
///
/// Returns `None` for unparseable addresses (including `unspec`).
/// Handles bracketing for IPv6: `[::1]:655`.
fn parse_socket_addr(addr: &str, port: &str) -> Option<SocketAddr> {
    // `unspec` is the wire placeholder for "no address"; never a real address.
    if addr == tinc_proto::AddrStr::UNSPEC {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let ip: IpAddr = addr.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// Gates before sending `MTU_INFO`.
///
/// Same shape as [`should_send_udp_info`] but: no TCPONLY check
/// (MTU info is useful even on TCP-mostly paths — *some* hop might
/// use UDP), and the minor-version gate is **6** not 5 (`MTU_INFO`
/// was introduced one protocol minor after `UDP_INFO`).
///
/// On `true` return when `from_is_myself`, caller bumps the MTU-info
/// timestamp — a separate timestamp from the UDP-info one.
///
/// The MTU *value* adjustment is not here — see
/// [`adjust_mtu_for_send`].
#[expect(clippy::too_many_arguments)] // mirrors should_send_udp_info: each param is one snapshot read
#[expect(clippy::fn_params_excessive_bools)] // independent gates, not a state machine
#[must_use]
pub(crate) fn should_send_mtu_info(
    to_is_myself: bool,
    to_reachable: bool,
    // Only checked when `from_is_myself`.
    to_directly_connected: bool,
    from_is_myself: bool,
    // Separate timestamp from UDP_INFO.
    last_sent: Option<Instant>,
    now: Instant,
    interval: Duration,
    nexthop_options: ConnOptions,
) -> bool {
    if to_is_myself {
        return false;
    }
    if !to_reachable {
        return false;
    }
    if from_is_myself {
        if to_directly_connected {
            return false;
        }
        if let Some(last) = last_sent
            && now.saturating_duration_since(last) < interval
        {
            return false;
        }
    }
    // MTU_INFO requires protocol minor ≥ 6 (introduced after UDP_INFO).
    if nexthop_options.prot_minor() < 6 {
        return false;
    }
    true
}

/// MTU adjustment before sending, called by the daemon after
/// `should_send_mtu_info` returns `true`. Takes the MTU we were about
/// to send and possibly tightens it based on what we know about the
/// path to `from`.
///
/// `mtu`: the value we were going to send. On the originating call
///   this is the compile-time max; on forward it's the received value.
/// `from_via_is_myself`: route to `from` has no static relay — we send
///   directly or via dynamic relays, so our own measurement is
///   authoritative.
/// `from_pmtu`: our PMTU state for `from`. `None` if we have no tunnel.
/// `via_pmtu`: the relay's PMTU. `None` if no tunnel.
/// `via_nexthop_pmtu`: the relay's *own* nexthop's PMTU. Only consulted
///   in the dynamic-relay case.
///
/// Branches:
///   1. converged direct measurement and no static relay: override
///      `mtu` entirely — the only branch that can increase it.
///   2. static relay converged: `min` clamp, never increase.
///   3. dynamic relay's nexthop converged: same `min` clamp.
///   4. else: leave `mtu` alone (path is TCP-only for us, but forward
///      anyway — downstream might use UDP).
#[must_use]
pub(crate) fn adjust_mtu_for_send(
    mtu: i32,
    from_via_is_myself: bool,
    from_pmtu: Option<PmtuSnapshot>,
    via_pmtu: Option<PmtuSnapshot>,
    via_nexthop_pmtu: Option<PmtuSnapshot>,
) -> i32 {
    // Converged direct measurement: override entirely. The only branch
    // that can increase mtu.
    if from_via_is_myself
        && let Some(f) = from_pmtu
        && f.converged()
    {
        return i32::from(f.minmtu);
    }
    // Static relay converged: clamp.
    if let Some(v) = via_pmtu
        && v.converged()
    {
        return mtu.min(i32::from(v.minmtu));
    }
    // Dynamic relay's nexthop converged: clamp.
    if let Some(n) = via_nexthop_pmtu
        && n.converged()
    {
        return mtu.min(i32::from(n.minmtu));
    }
    // No measurement: pass through.
    mtu
}

/// What to do with a received `MTU_INFO`.
///
/// `N` is the caller's node-id type; forwarding variants carry
/// `from`/`to` so the caller doesn't re-unwrap.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MtuInfoAction<N> {
    /// Set the *provisional* MTU (we haven't converged ourselves; trust
    /// the relay's number until we do), then forward. `new_mtu` is
    /// already clamped to `[MTU_MIN, MTU_MAX]`.
    ClampAndForward { from: N, to: N, new_mtu: u16 },
    /// Forward without clamping: we already converged, or our MTU
    /// already matches.
    Forward { from: N, to: N },
    /// MTU below the IPv4 minimum reassembly size — nonsense, treated
    /// as connection-fatal by the caller.
    Malformed,
    /// `from` or `to` not in graph.
    UnknownNode,
}

/// `MTU_INFO` receive decision.
///
/// `from`/`to`: `None` if the node isn't in our graph; `N` rides along
///   so the caller gets it back in the action.
///
/// The `mtu < 512` check happens first, before node lookups. That's
/// the only `Malformed` (connection-fatal) outcome; everything else is
/// drop-and-continue.
#[must_use]
pub(crate) fn on_receive_mtu_info<N>(
    parsed: &MtuInfo,
    from: Option<(N, FromMtuState)>,
    to: Option<N>,
) -> MtuInfoAction<N> {
    if parsed.mtu < MTU_MIN {
        return MtuInfoAction::Malformed;
    }
    let mtu = parsed.mtu.min(MTU_MAX);
    #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation)] // clamped to [512,9018]
    let mtu = mtu as u16;

    let Some((from_nid, from)) = from else {
        return MtuInfoAction::UnknownNode;
    };

    // Only take the relay's number if it differs and we haven't
    // converged; a converged local measurement beats hearsay.
    let learned = from.mtu != mtu && from.minmtu != from.maxmtu;

    // If `to` is unknown, drop the provisional hint too; losing one
    // hint when the graph is inconsistent is fine.
    let Some(to_nid) = to else {
        return MtuInfoAction::UnknownNode;
    };

    if learned {
        MtuInfoAction::ClampAndForward {
            from: from_nid,
            to: to_nid,
            new_mtu: mtu,
        }
    } else {
        MtuInfoAction::Forward {
            from: from_nid,
            to: to_nid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_proto::AddrStr;

    // Minor-version-N nexthop options (UDP_INFO needs ≥5, MTU_INFO
    // needs ≥6). Minor is in the top byte.
    const MINOR_5: ConnOptions = ConnOptions::from_bits_retain(5 << 24);
    const MINOR_6: ConnOptions = ConnOptions::from_bits_retain(6 << 24);
    const MINOR_4: ConnOptions = ConnOptions::from_bits_retain(4 << 24);

    fn mkudp(addr: &str, port: &str) -> UdpInfo {
        UdpInfo {
            from: "alice".into(),
            to: "bob".into(),
            addr: AddrStr::new(addr).unwrap(),
            port: AddrStr::new(port).unwrap(),
        }
    }

    // Struct with all-gates-pass defaults; each test row flips one input.

    #[derive(Clone, Copy)]
    #[expect(clippy::struct_excessive_bools)] // flat test fixture, not a state machine
    struct Send {
        to_myself: bool,
        reachable: bool,
        to_conn: bool,
        from_myself: bool,
        from_opt: ConnOptions,
        to_opt: ConnOptions,
        my_opt: ConnOptions,
        nexthop: ConnOptions,
        last_ago: Option<Duration>,
    }
    impl Send {
        // "All gates pass" baseline; proven by the first assert in `udp_send_gates`.
        const PASS: Self = Self {
            to_myself: false,
            reachable: true,
            to_conn: false,
            from_myself: true,
            from_opt: ConnOptions::empty(),
            to_opt: ConnOptions::empty(),
            my_opt: ConnOptions::empty(),
            nexthop: MINOR_5,
            last_ago: None,
        };
        fn run(&self, now: Instant) -> bool {
            let last = self.last_ago.map(|d| now.checked_sub(d).unwrap());
            should_send_udp_info(
                self.to_myself,
                self.reachable,
                self.to_conn,
                self.from_myself,
                self.from_opt,
                self.to_opt,
                self.my_opt,
                self.nexthop,
                last,
                now,
                Duration::from_secs(5),
            )
        }
    }

    /// `should_send_udp_info` gates. Each row perturbs ONE field
    /// from `Send::PASS`.
    #[test]
    #[rustfmt::skip]
    fn udp_send_gates() {
        let now = Instant::now();
        let p = Send::PASS;
        let s = |secs| Some(Duration::from_secs(secs));

        assert!( p.run(now),                                        "all gates pass");
        assert!(!Send { to_myself: true,       ..p }.run(now),      "to_myself blocks");
        assert!(!Send { reachable: false,      ..p }.run(now),      "unreachable blocks");
        assert!(!Send { to_conn: true,         ..p }.run(now),      "directly_connected blocks");
        assert!( Send { to_conn: true, from_myself: false, ..p }.run(now),
                                                                    "forwarding ignores directly_connected");
        // debounce: sent 2s ago, interval 5s
        assert!(!Send { last_ago: s(2),        ..p }.run(now),      "debounce suppresses");
        assert!( Send { last_ago: s(6),        ..p }.run(now),      "debounce passed");
        assert!( Send { last_ago: s(1), from_myself: false, ..p }.run(now),
                                                                    "forwarding ignores debounce");
        assert!(!Send { my_opt:   ConnOptions::TCPONLY, ..p }.run(now),   "tcponly myself blocks");
        assert!(!Send { from_opt: ConnOptions::TCPONLY, ..p }.run(now),   "tcponly from blocks");
        assert!(!Send { to_opt:   ConnOptions::TCPONLY, ..p }.run(now),   "tcponly to blocks");
        assert!(!Send { nexthop: MINOR_4,      ..p }.run(now),      "nexthop minor<5 blocks");
        assert!( Send { nexthop: MINOR_5,      ..p }.run(now),      "nexthop minor==5 ok");
    }

    fn from_ok() -> FromState {
        FromState {
            directly_connected: false,
            udp_confirmed: false,
            via_is_self: true,
        }
    }

    /// `on_receive_udp_info` decision table. Unparseable addresses drop
    /// the learning so garbage never propagates into our address tree.
    #[test]
    #[rustfmt::skip]
    fn udp_recv_table() {
        use UdpInfoAction::*;
        // N = (): tests only care about which variant fires, not the
        // node-id payload (the daemon's NodeId is just plumbed through).
        type Row = (&'static str, &'static str, &'static str,
                    Option<FromState>, bool, Option<SocketAddr>, UdpInfoAction<()>);
        let sa = |s: &str| -> SocketAddr { s.parse().unwrap() };
        let ok = from_ok();
        let direct = FromState { directly_connected: true,  ..ok };
        let confm  = FromState { udp_confirmed:      true,  ..ok };
        let novia  = FromState { via_is_self:        false, ..ok };
        let v4 = sa("192.168.1.5:50123");
        let fwd = || Forward { from: (), to: () };

        let cases: &[Row] = &[
            // (label,                       addr,          port,    from_state,  to_ok, cur_addr,           expected)
            (":238 unknown from",            "192.168.1.5", "50123", None,        true,  None,               UnknownNode),
            (":261 unknown to",              "192.168.1.5", "50123", Some(ok),    false, None,               UnknownNode),
            (":247 past static relay",       "192.168.1.5", "50123", Some(novia), true,  None,               DroppedPastRelay),
            (":251 directly_connected",      "192.168.1.5", "50123", Some(direct),true,  None,               fwd()),
            (":251 udp_confirmed",           "192.168.1.5", "50123", Some(confm),  true,  None,               fwd()),
            (":254 same addr no-op",         "192.168.1.5", "50123", Some(ok),    true,  Some(v4),           fwd()),
            (":255 payoff: addr differs",    "192.168.1.5", "50123", Some(ok),    true,  Some(sa("10.0.0.1:655")), UpdateAndForward { from: (), to: (), new_addr: v4 }),
            (":255 payoff: cur=None",        "192.168.1.5", "50123", Some(ok),    true,  None,               UpdateAndForward { from: (), to: (), new_addr: v4 }),
            ("ipv6 parses",                  "fe80::1",     "655",   Some(ok),    true,  None,               UpdateAndForward { from: (), to: (), new_addr: sa("[fe80::1]:655") }),
            ("unspec → Forward (diverge)",   "unspec",      "0",     Some(ok),    true,  None,               fwd()),
            ("non-ip → Forward (diverge)",   "not-an-ip",   "655",   Some(ok),    true,  None,               fwd()),
        ];
        for (label, addr, port, from, to_ok, cur, want) in cases {
            let m = mkudp(addr, port);
            let from = from.map(|s| ((), s));
            let to = to_ok.then_some(());
            assert_eq!(on_receive_udp_info(&m, from, to, *cur), *want, "{label}");
        }
    }

    /// `should_send_mtu_info` gates. No TCPONLY check (UDP_INFO-only
    /// gate); minor-version gate is 6.
    #[test]
    fn mtu_send_gates() {
        let now = Instant::now();
        let int = Duration::from_secs(5);
        let ago = |s| Some(now.checked_sub(Duration::from_secs(s)).unwrap());
        let send = |last, nh| should_send_mtu_info(false, true, false, true, last, now, int, nh);

        assert!(send(None, MINOR_6), "all gates pass");
        assert!(!send(None, MINOR_5), "nexthop minor<6 blocks");
        assert!(send(None, MINOR_6), "nexthop minor==6 ok");
        // separate debounce timestamp from UDP_INFO
        assert!(!send(ago(1), MINOR_6), "debounce suppresses");
        assert!(send(ago(10), MINOR_6), "debounce passed");
    }

    /// `adjust_mtu_for_send` branches.
    #[test]
    #[rustfmt::skip]
    fn mtu_adjust_table() {
        type Row = (&'static str, i32, bool,
                    Option<PmtuSnapshot>, Option<PmtuSnapshot>, Option<PmtuSnapshot>, i32);
        let conv = |m| Some(PmtuSnapshot { minmtu: m, maxmtu: m });
        let probe = Some(PmtuSnapshot { minmtu: 1000, maxmtu: 1500 }); // unconverged

        let cases: &[Row] = &[
            // (label,                        mtu,  via_myself, from,       via,        via_nh,     want)
            (":308 direct override (increase)", 1000, true,  conv(1400), None,       None,       1400),
            (":308 direct override (decrease)", 9000, true,  conv(1400), None,       None,       1400),
            (":308 needs via_is_myself",        1000, false, conv(1400), None,       None,       1000),
            (":314 via clamp (tighten)",        1500, false, None,       conv(1300), None,       1300),
            (":314 via clamp is min not set",   1000, false, None,       conv(1300), None,       1000),
            (":318 via_nexthop clamp",          1500, false, None,       None,       conv(1200), 1200),
            ("unconverged → passthrough",       1400, true,  probe,      probe,      probe,      1400),
        ];
        for &(label, mtu, via_my, from, via, nh, want) in cases {
            assert_eq!(adjust_mtu_for_send(mtu, via_my, from, via, nh), want, "{label}");
        }
    }

    fn mkmtu(mtu: i32) -> MtuInfo {
        MtuInfo {
            from: "alice".into(),
            to: "bob".into(),
            mtu,
            udp_rx_len: 0,
        }
    }

    /// `on_receive_mtu_info` decision table.
    #[test]
    fn mtu_recv_table() {
        use MtuInfoAction::*;
        type Row = (
            &'static str,
            i32,
            Option<FromMtuState>,
            bool,
            MtuInfoAction<()>,
        );
        let unconv = FromMtuState {
            mtu: 1500,
            minmtu: 1000,
            maxmtu: 1500,
        };
        let conv = FromMtuState {
            mtu: 1500,
            minmtu: 1500,
            maxmtu: 1500,
        };
        let max_u16 = u16::try_from(MTU_MAX).unwrap();
        let fwd = || Forward { from: (), to: () };

        #[rustfmt::skip]
        let cases: &[Row] = &[
            // (label,                        mtu,   from,         to_ok, expected)
            (":345 mtu<512 → Malformed",      400,   Some(unconv), true,  Malformed),
            (":365 unconverged → clamp",      1400,  Some(unconv), true,  ClampAndForward { from: (), to: (), new_mtu: 1400 }),
            ("converged → Forward",           1400,  Some(conv),   true,  fwd()),
            ("same mtu → Forward",            1500,  Some(unconv), true,  fwd()),
            (":349 clamp to MTU_MAX",         12000, Some(unconv), true,  ClampAndForward { from: (), to: (), new_mtu: max_u16 }),
            (":357 unknown from",             1400,  None,         true,  UnknownNode),
            (":371 unknown to",               1400,  Some(unconv), false, UnknownNode),
        ];
        for &(label, mtu, from, to_ok, ref want) in cases {
            let from = from.map(|s| ((), s));
            let to = to_ok.then_some(());
            assert_eq!(on_receive_mtu_info(&mkmtu(mtu), from, to), *want, "{label}");
        }
        // boundary: exactly 512 is NOT Malformed (assert_ne! preserved)
        assert_ne!(
            on_receive_mtu_info(&mkmtu(512), Some(((), unconv)), Some(())),
            Malformed,
            ":345 boundary: mtu==512 is fine"
        );
    }
}
