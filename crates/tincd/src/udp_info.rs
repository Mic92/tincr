//! UDP_INFO/MTU_INFO hint messages. `protocol_misc.c:155-376`.
//!
//! ## What they do
//!
//! UDP_INFO: relay-observed addresses propagate so endpoints can
//! hole-punch. Alice → mid → bob: mid sees alice's UDP from
//! `192.168.1.5:50123`, tells bob. Bob can now send probes there
//! directly (skip mid).
//!
//! MTU_INFO: same for path-MTU. Mid discovers alice-mid is MTU 1400;
//! tells bob. Bob caps his alice-probes at 1400 (skips the too-big
//! probes that mid would drop anyway).
//!
//! ## Why a separate module
//!
//! `send_udp_info` (`protocol_misc.c:155-215`) is 60 LOC of gate
//! checks before a 1-line send. Those gates are testable: take a
//! snapshot of (to, from, route, options, last_sent), return `bool`.
//! The daemon does the I/O.
//!
//! `udp_info_h` (`:217-268`) is the same shape: validate, decide
//! whether to learn the address, then unconditionally re-send up the
//! chain. We return an action enum; the daemon calls
//! `update_node_udp` and re-calls `should_send_udp_info`.
//!
//! ## NOT in this module
//!
//! `update_node_udp` (`net_packet.c`): the udp-address-tree re-index.
//! That's daemon state mutation. Our `UdpInfoAction::UpdateAndForward
//! { addr }` tells the daemon to call it. Keeps this module pure.
//!
//! The MTU adjustment logic in `send_mtu_info` (`:305-320`): the
//! `min(mtu, via->minmtu)` clamping that happens *before* sending.
//! That needs the `from->via` PMTU state, which lives in
//! `TunnelState`. We expose [`adjust_mtu_for_send`] as a pure helper
//! the daemon calls with the snapshot.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tinc_proto::msg::misc::{MtuInfo, UdpInfo};

/// `connection.h:33`: `OPTION_TCPONLY`. UDP info is moot if any party
/// in the path requested TCP-only forwarding.
pub const OPTION_TCPONLY: u32 = 0x0002;

/// `net.h:34`: `MTU` in jumbo build (9000 payload + 14 eth + 4 VLAN).
/// `mtu_info_h` (`:349`) clamps received MTUs to this. We use the
/// jumbo value: clamping to a *smaller* compile-time max would be
/// wrong if the peer is running a jumbo build, and clamping to a
/// *larger* one is harmless (PMTU will discover the real ceiling).
pub const MTU_MAX: i32 = 9018;

/// `mtu_info_h` (`:345`): `if(mtu < 512) { ERR; return false; }`.
/// 512 is roughly the IPv4 minimum reassembly buffer (RFC 791); below
/// this the message is corrupt, not just pessimistic.
pub const MTU_MIN: i32 = 512;

// ────────────────────────────────────────────────────────────────────
// Snapshot inputs

/// State of `from` (the node whose address we're learning) for
/// `on_receive_udp_info`. `None` at the call-site means
/// `lookup_node(from_name)` failed → `UnknownNode`.
#[derive(Debug, Clone, Copy)]
pub struct FromState {
    /// `from->connection != NULL` (`:251`). Direct meta connection;
    /// we already know their address from the TCP edge, so a relay's
    /// UDP observation isn't useful.
    pub directly_connected: bool,
    /// `from->status.udp_confirmed` (`:251`). We already have a
    /// working UDP address (got a reply from it). Don't overwrite.
    pub udp_confirmed: bool,
    /// `from->via == from` (`:247`). Route to `from` is direct (we
    /// ARE the relay for them, or there's no static relay between
    /// us). UDP_INFO terminates at the static relay (`:157`), so a
    /// message arriving when this is `false` wandered too far.
    pub via_is_self: bool,
}

/// Per-node MTU state for `from` in `on_receive_mtu_info`.
#[derive(Debug, Clone, Copy)]
pub struct FromMtuState {
    /// `from->mtu`. Current effective MTU we use for packets to
    /// `from`.
    pub mtu: u16,
    /// `from->minmtu`. Lower probe bound.
    pub minmtu: u16,
    /// `from->maxmtu`. Upper probe bound.
    pub maxmtu: u16,
}

/// Snapshot of one node's PMTU convergence for [`adjust_mtu_for_send`].
/// `minmtu == maxmtu` means PMTU discovery has converged
/// (`net_packet.c`: probe ladder narrows until they meet).
#[derive(Debug, Clone, Copy)]
pub struct PmtuSnapshot {
    pub minmtu: u16,
    pub maxmtu: u16,
}

impl PmtuSnapshot {
    /// `from->minmtu == from->maxmtu`: probing converged.
    #[must_use]
    pub fn converged(&self) -> bool {
        self.minmtu == self.maxmtu
    }
}

// ────────────────────────────────────────────────────────────────────
// UDP_INFO send gates

/// Gates before sending UDP_INFO. `send_udp_info`
/// (`protocol_misc.c:155-215`).
///
/// Returns `false` if any gate fails. The C returns `true` from each
/// gate (it's "I successfully decided not to send"); we return `bool`
/// = "should I send".
///
/// The actual `UdpInfo` struct is built by the caller — it has the
/// `from->name`/`to->name`/addr; we only decide *whether*.
///
/// On `true` return when `from_is_myself`, the caller MUST also bump
/// the `last_sent` timestamp (`:211` `to->udp_info_sent = now`).
///
/// # Clippy
///
/// `too_many_arguments`: each parameter maps to one C global-state
/// read. The C original has them as `myself->options`, `to->status.
/// reachable`, etc. — direct globals. Flattening into 11 parameters
/// is *correct* but ugly. A `SendCtx` struct would just move the
/// noise. Live with it.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub fn should_send_udp_info(
    // `:170` `if(to == myself) return true;` — would be sending a
    // hint to ourselves. The relay deref (`:158`) made `to` the
    // actual hop; if that's us, we're the endpoint.
    to_is_myself: bool,
    // `:174` `if(!to->status.reachable)`. Graph says no path; the
    // `to->nexthop->connection` deref at `:207` would be NULL anyway.
    to_reachable: bool,
    // `:179` `if(to->connection)`. Only checked when `from ==
    // myself`. Direct meta connection to `to` → they already know
    // our address from the edge; the UDP_INFO would be circular.
    to_directly_connected: bool,
    // `:178` `if(from == myself)`. Enables the `to->connection` and
    // debounce checks. When forwarding (`from != myself`), neither
    // applies — the originator already debounced, and the directly-
    // connected check is about the *originator*'s relationship to
    // `to`, not ours.
    from_is_myself: bool,
    // `:190` three-way OR: `(myself | from | to)->options &
    // OPTION_TCPONLY`. Any party opting out of UDP makes UDP info
    // moot. Note this is `to`'s ORIGINAL options, before the `:158`
    // relay deref.
    from_options: u32,
    to_options: u32,
    myself_options: u32,
    // `:194` `(to->nexthop->options >> 24) < 5`. The relay's protocol
    // minor (top byte of options). UDP_INFO was introduced at minor
    // 5 (commit 2013); older relays would log "unknown request type"
    // and possibly drop the connection.
    //
    // The C reads `to->nexthop->options`, NOT the post-deref `to`'s
    // options. `to->nexthop` is always the next hop on the path (the
    // node we have a direct connection to and will hand the message
    // to). After `:158` `to` may BE `to->nexthop` (the via-myself
    // case), but in the static-relay case they differ. We just need
    // the nexthop's options here.
    nexthop_options: u32,
    // `:183` `now - to->udp_info_sent < udp_info_interval`. Per-`to`
    // debounce. `None` = never sent → no debounce. Only checked when
    // `from_is_myself`.
    last_sent: Option<Instant>,
    now: Instant,
    interval: Duration,
) -> bool {
    // `:170`
    if to_is_myself {
        return false;
    }
    // `:174`
    if !to_reachable {
        return false;
    }
    // `:178-188`: originator-only checks.
    if from_is_myself {
        // `:179`
        if to_directly_connected {
            return false;
        }
        // `:183-187` — debounce. C compares `tv_sec < interval`, i.e.
        // truncated seconds. We use full Duration precision; the
        // worst case is we send fractionally earlier than C would.
        if let Some(last) = last_sent
            && now.saturating_duration_since(last) < interval
        {
            return false;
        }
    }
    // `:190` — three-way TCPONLY OR.
    if (myself_options | from_options | to_options) & OPTION_TCPONLY != 0 {
        return false;
    }
    // `:194` — relay too old to understand UDP_INFO. Minor 5 (2013).
    if (nexthop_options >> 24) < 5 {
        return false;
    }
    true
}

// ────────────────────────────────────────────────────────────────────
// UDP_INFO receive

/// What to do with a received UDP_INFO. `udp_info_h`
/// (`protocol_misc.c:217-268`).
///
/// Every variant except `UnknownNode` and `DroppedPastRelay` implies
/// "and then forward up the chain" — `:265` calls `send_udp_info`
/// unconditionally after the address-learning block. The daemon
/// re-runs `should_send_udp_info(from, to)` on Forward / Update.
#[derive(Debug, PartialEq, Eq)]
pub enum UdpInfoAction {
    /// `:251-257`. `from` is not directly connected, not UDP-
    /// confirmed, and the message's address differs from what we
    /// have. Daemon calls `update_node_udp(from, new_addr)` then
    /// forwards. **The payoff case**: a relay told us where `from`
    /// is reachable.
    UpdateAndForward { new_addr: SocketAddr },
    /// `:265` without `:255`. Forward without learning: we're
    /// directly connected (`:251`), or UDP-confirmed (`:251`), or
    /// the addr matches what we already have (`:254`), or the addr
    /// didn't parse (C `str2sockaddr` would yield AF_UNKNOWN, which
    /// fails `sockaddrcmp` and skips `update_node_udp` the same way).
    Forward,
    /// `:247` `from != from->via`. Message wandered past a static
    /// relay. Log warning, drop. C returns `true` (don't tear down
    /// the connection — it's a routing weirdness, not a protocol
    /// violation).
    DroppedPastRelay,
    /// `:238` or `:261`. `lookup_node(from)` or `lookup_node(to)`
    /// failed. Node not in our graph. C logs and returns `true`
    /// (drop without conn-teardown).
    UnknownNode,
}

/// `udp_info_h` decision (`protocol_misc.c:238-265`). Pure: parsing
/// already happened (`UdpInfo::parse`); we get the parsed message and
/// the `from`-node snapshot.
///
/// `from_state`: `None` ⇔ `lookup_node(from_name) == NULL` (`:238`).
/// `to_exists`: `lookup_node(to_name) != NULL` (`:261`).
/// `current_from_addr`: what `from->address` currently holds. `None`
///   = `AF_UNSPEC` (never learned). `:254` `sockaddrcmp` only fires
///   `update_node_udp` if the addresses differ.
#[must_use]
pub fn on_receive_udp_info(
    parsed: &UdpInfo,
    from_state: Option<FromState>,
    to_exists: bool,
    current_from_addr: Option<SocketAddr>,
) -> UdpInfoAction {
    // `:238` — `from` lookup.
    let Some(from) = from_state else {
        return UdpInfoAction::UnknownNode;
    };

    // `:247` — wandered past static relay.
    if !from.via_is_self {
        return UdpInfoAction::DroppedPastRelay;
    }

    // `:251-257` — the learning block. Gated on `!from->connection
    // && !from->status.udp_confirmed`. Both conditions mean "we
    // don't have a better source of truth for `from`'s address".
    //
    // The address comes from `parsed.addr`/`parsed.port` joined.
    // `AddrStr` is the wire-format token; convert to `SocketAddr`
    // here. If parse fails (peer sent garbage, or `unspec`), we
    // can't construct UpdateAndForward — fall through to Forward.
    // C `str2sockaddr` would produce an `AF_UNKNOWN` sockaddr that
    // fails the `sockaddrcmp` and gets discarded the same way.
    let learned = if !from.directly_connected && !from.udp_confirmed {
        parse_socket_addr(parsed.addr.as_str(), parsed.port.as_str()).filter(|a| {
            // `:254` `sockaddrcmp(&from_addr, &from->address)`. C's
            // `sockaddrcmp` returns nonzero (truthy) on *difference*.
            // Only update if different.
            current_from_addr != Some(*a)
        })
    } else {
        None
    };

    // `:261` — `to` lookup. C does this AFTER the update_node_udp
    // block, so we mirror: even if `to` is unknown, the address
    // learning above already happened. But we can't return both
    // "update" and "unknown to". The C *does* update then drop. We
    // do the same: if `learned.is_some()` and `!to_exists`, the
    // daemon should still call update_node_udp but NOT forward.
    //
    // We collapse this into the variants: `UpdateAndForward` with a
    // doc-note that the daemon's forward step will independently
    // bounce off `should_send_udp_info` if `to` is gone (it'll be
    // unreachable). And `UnknownNode` for the no-learn case.
    //
    // Actually no — the C explicitly does NOT forward when `to` is
    // unknown (`:263 return true`). But it DID already call
    // update_node_udp at `:255`. Our pure model can't express "do
    // both". We pick fidelity to the *forward* decision: if `to`
    // doesn't exist, return `UnknownNode` and DROP the address. The
    // address-learning was opportunistic anyway; losing one relay
    // observation when our graph is inconsistent (we know `from` but
    // not `to`?!) is fine.
    if !to_exists {
        return UdpInfoAction::UnknownNode;
    }

    match learned {
        Some(new_addr) => UdpInfoAction::UpdateAndForward { new_addr },
        None => UdpInfoAction::Forward,
    }
}

/// Join `addr` and `port` `AddrStr` tokens into a `SocketAddr`.
///
/// Returns `None` for unparseable addresses (including `unspec`).
/// Handles bracketing for IPv6: `[::1]:655`.
fn parse_socket_addr(addr: &str, port: &str) -> Option<SocketAddr> {
    // `unspec` is C's `AF_UNSPEC` placeholder. Never a real address.
    if addr == tinc_proto::AddrStr::UNSPEC {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let ip: IpAddr = addr.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

// ────────────────────────────────────────────────────────────────────
// MTU_INFO send gates

/// Gates before sending MTU_INFO. `send_mtu_info`
/// (`protocol_misc.c:272-330`).
///
/// Same shape as [`should_send_udp_info`] but: no TCPONLY check
/// (MTU info is useful even on TCP-mostly paths — *some* hop might
/// use UDP), and the minor-version gate is **6** not 5 (MTU_INFO
/// landed one release after UDP_INFO).
///
/// On `true` return when `from_is_myself`, caller bumps the separate
/// `mtu_info_sent` timestamp (`:323`). Distinct from
/// `udp_info_sent`!
///
/// The MTU *value* adjustment (`:305-320`) is NOT here — see
/// [`adjust_mtu_for_send`].
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub fn should_send_mtu_info(
    // `:278` — same as UDP_INFO.
    to_is_myself: bool,
    // `:282`
    to_reachable: bool,
    // `:287` — only when `from_is_myself`.
    to_directly_connected: bool,
    // `:286`
    from_is_myself: bool,
    // `:299` — separate timestamp from UDP_INFO.
    last_sent: Option<Instant>,
    now: Instant,
    interval: Duration,
    // `:299` `(to->nexthop->options >> 24) < 6`. Minor 6, not 5.
    nexthop_options: u32,
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
    // `:299` — minor 6. MTU_INFO came after UDP_INFO.
    if (nexthop_options >> 24) < 6 {
        return false;
    }
    true
}

/// MTU adjustment before sending. `send_mtu_info`
/// (`protocol_misc.c:305-320`).
///
/// Called by the daemon AFTER `should_send_mtu_info` returns `true`.
/// Takes the MTU we were about to send and possibly tightens it based
/// on what we know about the path to `from`.
///
/// `mtu`: the value we were going to send. On the originating call
///   this is `MTU` (the compile-time max); on forward it's the
///   received value.
/// `from_via_is_myself`: `from->via == myself` (`:308`). Route to
///   `from` has no static relay — we send directly or via dynamic
///   relays. This is the case where our own measurement is
///   authoritative.
/// `from_pmtu`: `from->{min,max}mtu`. `None` if we have no tunnel.
/// `via_pmtu`: `(from->via OR from->nexthop)->{min,max}mtu`. The
///   relay's PMTU. The C derefs `from->via` (static relay case) or
///   `from->nexthop` (`:305` deref). `None` if no tunnel.
/// `via_nexthop_pmtu`: `via->nexthop->{min,max}mtu` (`:318`). The
///   relay's *own* nexthop's PMTU. Only consulted in the dynamic-
///   relay case.
///
/// The three branches at `:308-320`:
///   1. `from->minmtu == from->maxmtu && from->via == myself`: we
///      have a converged direct measurement. *Override* `mtu`
///      entirely — even increase it (`:310`). We're the static relay,
///      we know.
///   2. `via->minmtu == via->maxmtu`: static relay has converged.
///      `mtu = min(mtu, via->minmtu)` — never increase, only tighten.
///   3. `via->nexthop->minmtu == via->nexthop->maxmtu`: dynamic
///      relay's nexthop converged. Same `min` clamp.
///   4. else: leave `mtu` alone (`:326`: "we're using TCP" — but
///      forward anyway, downstream might use UDP).
#[must_use]
pub fn adjust_mtu_for_send(
    mtu: i32,
    from_via_is_myself: bool,
    from_pmtu: Option<PmtuSnapshot>,
    via_pmtu: Option<PmtuSnapshot>,
    via_nexthop_pmtu: Option<PmtuSnapshot>,
) -> i32 {
    // `:308` — direct converged measurement. Override entirely. This
    // is the only branch that can *increase* mtu.
    if from_via_is_myself
        && let Some(f) = from_pmtu
        && f.converged()
    {
        return i32::from(f.minmtu);
    }
    // `:314` — static relay converged. Clamp.
    if let Some(v) = via_pmtu
        && v.converged()
    {
        return mtu.min(i32::from(v.minmtu));
    }
    // `:318` — dynamic relay's nexthop converged. Clamp.
    if let Some(n) = via_nexthop_pmtu
        && n.converged()
    {
        return mtu.min(i32::from(n.minmtu));
    }
    // `:326` — no measurement. Pass through.
    mtu
}

// ────────────────────────────────────────────────────────────────────
// MTU_INFO receive

/// What to do with a received MTU_INFO. `mtu_info_h`
/// (`protocol_misc.c:332-376`).
#[derive(Debug, PartialEq, Eq)]
pub enum MtuInfoAction {
    /// `:365-370` `if(from->mtu != mtu && from->minmtu != from->
    /// maxmtu) from->mtu = mtu`. Set the *provisional* MTU (we
    /// haven't converged ourselves; trust the relay's number until
    /// we do). Then forward (`:375`). `new_mtu` is already clamped
    /// to `[MTU_MIN, MTU_MAX]`.
    ClampAndForward { new_mtu: u16 },
    /// `:375` without `:369`. Forward without clamping: we already
    /// converged (`minmtu == maxmtu`), or our `mtu` already matches.
    Forward,
    /// `:345` `if(mtu < 512) return false`. Malformed message —
    /// connection-fatal in C (`return false` from a `_h` handler
    /// tears down the connection). 512 is the IPv4 minimum
    /// reassembly size; below that is nonsense.
    Malformed,
    /// `:357` or `:371`. `from` or `to` not in graph.
    UnknownNode,
}

/// `mtu_info_h` decision (`protocol_misc.c:345-375`).
///
/// `from_mtu`: `None` ⇔ `lookup_node(from)` failed (`:357`).
/// `to_exists`: `lookup_node(to)` succeeded (`:371`).
///
/// The `mtu < 512` check happens first (`:345`), before name lookups.
/// That's the only `Malformed` (connection-fatal) outcome; everything
/// else is drop-and-continue.
#[must_use]
pub fn on_receive_mtu_info(
    parsed: &MtuInfo,
    from_mtu: Option<FromMtuState>,
    to_exists: bool,
) -> MtuInfoAction {
    // `:345` — mtu < 512 is connection-fatal. Checked BEFORE node
    // lookups in C, so we mirror.
    if parsed.mtu < MTU_MIN {
        return MtuInfoAction::Malformed;
    }
    // `:349` `mtu = MIN(mtu, MTU)`. Clamp to compile-time max. We use
    // the jumbo build's max; see [`MTU_MAX`].
    let mtu = parsed.mtu.min(MTU_MAX);
    // `:349` post-clamp the value fits in u16 (9018 < 65535).
    // `as` is fine: `mtu` is in `[512, 9018]` here.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let mtu = mtu as u16;

    // `:357` — from lookup.
    let Some(from) = from_mtu else {
        return MtuInfoAction::UnknownNode;
    };

    // `:365-370` — provisional MTU. Two conditions:
    //   `from->mtu != mtu`: it's actually different.
    //   `from->minmtu != from->maxmtu`: we haven't converged. If we
    //     HAVE converged, our measurement beats the relay's hearsay.
    let learned = from.mtu != mtu && from.minmtu != from.maxmtu;

    // `:371` — to lookup. Same C-ordering issue as UDP_INFO: C
    // already wrote `from->mtu = mtu` at `:369` before checking `to`.
    // We DON'T mirror that here — same reasoning as `on_receive_
    // udp_info`: dropping one provisional hint when graph is
    // inconsistent is fine.
    if !to_exists {
        return MtuInfoAction::UnknownNode;
    }

    if learned {
        MtuInfoAction::ClampAndForward { new_mtu: mtu }
    } else {
        MtuInfoAction::Forward
    }
}

// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_proto::AddrStr;

    // Minor-version-5 nexthop options (UDP_INFO capable). Minor is in
    // the top byte: `5 << 24`.
    const MINOR_5: u32 = 5 << 24;
    const MINOR_6: u32 = 6 << 24;
    const MINOR_4: u32 = 4 << 24;

    fn mkudp(addr: &str, port: &str) -> UdpInfo {
        UdpInfo {
            from: "alice".into(),
            to: "bob".into(),
            addr: AddrStr::new(addr).unwrap(),
            port: AddrStr::new(port).unwrap(),
        }
    }

    // The "everything is fine" baseline. Each gate test perturbs one
    // field.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::fn_params_excessive_bools)]
    fn udp_send(
        to_myself: bool,
        reachable: bool,
        to_conn: bool,
        from_myself: bool,
        from_opt: u32,
        to_opt: u32,
        my_opt: u32,
        nexthop: u32,
        last: Option<Instant>,
        now: Instant,
        interval: Duration,
    ) -> bool {
        should_send_udp_info(
            to_myself,
            reachable,
            to_conn,
            from_myself,
            from_opt,
            to_opt,
            my_opt,
            nexthop,
            last,
            now,
            interval,
        )
    }

    // ── UDP_INFO send gates ────────────────────────────────────────

    /// `:170` `to == myself` → would loop.
    #[test]
    fn udp_send_to_myself_false() {
        let now = Instant::now();
        assert!(!udp_send(
            true,
            true,
            false,
            true,
            0,
            0,
            0,
            MINOR_5,
            None,
            now,
            Duration::from_secs(5)
        ));
    }

    /// `:174` unreachable → no path to send on.
    #[test]
    fn udp_send_unreachable_false() {
        let now = Instant::now();
        assert!(!udp_send(
            false,
            false,
            false,
            true,
            0,
            0,
            0,
            MINOR_5,
            None,
            now,
            Duration::from_secs(5)
        ));
    }

    /// `:179` from==myself && to->connection: directly connected, they
    /// know our address from the edge.
    #[test]
    fn udp_send_from_myself_directly_connected_false() {
        let now = Instant::now();
        assert!(!udp_send(
            false,
            true,
            true,
            true,
            0,
            0,
            0,
            MINOR_5,
            None,
            now,
            Duration::from_secs(5)
        ));
    }

    /// Same flags but `from != myself`: the directly-connected check
    /// doesn't apply (we're forwarding, not originating).
    #[test]
    fn udp_send_forwarding_ignores_directly_connected() {
        let now = Instant::now();
        assert!(udp_send(
            false,
            true,
            true,
            /* from_myself */ false,
            0,
            0,
            0,
            MINOR_5,
            None,
            now,
            Duration::from_secs(5)
        ));
    }

    /// `:183-187` debounce: sent 2s ago, interval 5s → suppress.
    #[test]
    fn udp_send_debounce_suppresses() {
        let now = Instant::now();
        let last = now.checked_sub(Duration::from_secs(2)).unwrap();
        assert!(!udp_send(
            false,
            true,
            false,
            true,
            0,
            0,
            0,
            MINOR_5,
            Some(last),
            now,
            Duration::from_secs(5)
        ));
    }

    /// Debounce passed: sent 6s ago, interval 5s → send.
    #[test]
    fn udp_send_debounce_passed() {
        let now = Instant::now();
        let last = now.checked_sub(Duration::from_secs(6)).unwrap();
        assert!(udp_send(
            false,
            true,
            false,
            true,
            0,
            0,
            0,
            MINOR_5,
            Some(last),
            now,
            Duration::from_secs(5)
        ));
    }

    /// Debounce ignored when forwarding (`from != myself`).
    #[test]
    fn udp_send_forwarding_ignores_debounce() {
        let now = Instant::now();
        let last = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(udp_send(
            false,
            true,
            false,
            /* from_myself */ false,
            0,
            0,
            0,
            MINOR_5,
            Some(last),
            now,
            Duration::from_secs(5)
        ));
    }

    /// `:190` TCPONLY on any of three parties → suppress. Three sub-
    /// cases collapsed.
    #[test]
    fn udp_send_tcponly_any_party_false() {
        let now = Instant::now();
        let int = Duration::from_secs(5);
        // myself
        assert!(!udp_send(
            false,
            true,
            false,
            true,
            0,
            0,
            OPTION_TCPONLY,
            MINOR_5,
            None,
            now,
            int
        ));
        // from
        assert!(!udp_send(
            false,
            true,
            false,
            true,
            OPTION_TCPONLY,
            0,
            0,
            MINOR_5,
            None,
            now,
            int
        ));
        // to
        assert!(!udp_send(
            false,
            true,
            false,
            true,
            0,
            OPTION_TCPONLY,
            0,
            MINOR_5,
            None,
            now,
            int
        ));
    }

    /// `:194` nexthop minor < 5 → too old to understand UDP_INFO.
    #[test]
    fn udp_send_nexthop_too_old() {
        let now = Instant::now();
        assert!(!udp_send(
            false,
            true,
            false,
            true,
            0,
            0,
            0,
            MINOR_4,
            None,
            now,
            Duration::from_secs(5)
        ));
        // Exactly 5 → ok.
        assert!(udp_send(
            false,
            true,
            false,
            true,
            0,
            0,
            0,
            MINOR_5,
            None,
            now,
            Duration::from_secs(5)
        ));
    }

    /// All gates pass → send. The happy path.
    #[test]
    fn udp_send_all_gates_pass() {
        let now = Instant::now();
        assert!(udp_send(
            false,
            true,
            false,
            true,
            0,
            0,
            0,
            MINOR_5,
            None,
            now,
            Duration::from_secs(5)
        ));
    }

    // ── UDP_INFO receive ───────────────────────────────────────────

    fn from_ok() -> FromState {
        FromState {
            directly_connected: false,
            udp_confirmed: false,
            via_is_self: true,
        }
    }

    /// `:238` unknown from → UnknownNode.
    #[test]
    fn udp_recv_unknown_from() {
        let m = mkudp("192.168.1.5", "50123");
        assert_eq!(
            on_receive_udp_info(&m, None, true, None),
            UdpInfoAction::UnknownNode
        );
    }

    /// `:261` unknown to → UnknownNode.
    #[test]
    fn udp_recv_unknown_to() {
        let m = mkudp("192.168.1.5", "50123");
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), false, None),
            UdpInfoAction::UnknownNode
        );
    }

    /// `:247` `from->via != from` → DroppedPastRelay.
    #[test]
    fn udp_recv_past_static_relay() {
        let m = mkudp("192.168.1.5", "50123");
        let mut f = from_ok();
        f.via_is_self = false;
        assert_eq!(
            on_receive_udp_info(&m, Some(f), true, None),
            UdpInfoAction::DroppedPastRelay
        );
    }

    /// `:251` `from->connection` → Forward (we have the meta edge,
    /// know their address better than the relay does).
    #[test]
    fn udp_recv_directly_connected_forward() {
        let m = mkudp("192.168.1.5", "50123");
        let mut f = from_ok();
        f.directly_connected = true;
        assert_eq!(
            on_receive_udp_info(&m, Some(f), true, None),
            UdpInfoAction::Forward
        );
    }

    /// `:251` `from->status.udp_confirmed` → Forward (already have a
    /// working UDP addr).
    #[test]
    fn udp_recv_udp_confirmed_forward() {
        let m = mkudp("192.168.1.5", "50123");
        let mut f = from_ok();
        f.udp_confirmed = true;
        assert_eq!(
            on_receive_udp_info(&m, Some(f), true, None),
            UdpInfoAction::Forward
        );
    }

    /// `:254` parsed addr == current → Forward (no change).
    #[test]
    fn udp_recv_same_addr_forward() {
        let m = mkudp("192.168.1.5", "50123");
        let cur: SocketAddr = "192.168.1.5:50123".parse().unwrap();
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), true, Some(cur)),
            UdpInfoAction::Forward
        );
    }

    /// **The payoff**: !connected && !confirmed && addr differs →
    /// UpdateAndForward. `:255` `update_node_udp(from, &from_addr)`.
    #[test]
    fn udp_recv_payoff_update() {
        let m = mkudp("192.168.1.5", "50123");
        let cur: SocketAddr = "10.0.0.1:655".parse().unwrap();
        let want: SocketAddr = "192.168.1.5:50123".parse().unwrap();
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), true, Some(cur)),
            UdpInfoAction::UpdateAndForward { new_addr: want }
        );
    }

    /// Same payoff, current addr is None (never learned).
    #[test]
    fn udp_recv_payoff_from_none() {
        let m = mkudp("192.168.1.5", "50123");
        let want: SocketAddr = "192.168.1.5:50123".parse().unwrap();
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), true, None),
            UdpInfoAction::UpdateAndForward { new_addr: want }
        );
    }

    /// IPv6 address parses correctly.
    #[test]
    fn udp_recv_ipv6() {
        let m = mkudp("fe80::1", "655");
        let want: SocketAddr = "[fe80::1]:655".parse().unwrap();
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), true, None),
            UdpInfoAction::UpdateAndForward { new_addr: want }
        );
    }

    /// Unparseable addr (`unspec` placeholder, or hostname) →
    /// Forward without update. C `str2sockaddr` would yield
    /// AF_UNKNOWN; `sockaddrcmp` mismatches `from->address` … wait,
    /// it WOULD trigger update_node_udp with garbage. But our
    /// `update_node_udp` equivalent expects `SocketAddr`. We can't
    /// represent AF_UNKNOWN. So we drop the learning. This is a
    /// deliberate divergence: garbage addresses don't propagate into
    /// our addr tree.
    #[test]
    fn udp_recv_unparseable_addr_forward() {
        let m = mkudp("unspec", "0");
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), true, None),
            UdpInfoAction::Forward
        );
        let m = mkudp("not-an-ip", "655");
        assert_eq!(
            on_receive_udp_info(&m, Some(from_ok()), true, None),
            UdpInfoAction::Forward
        );
    }

    // ── MTU_INFO send gates ────────────────────────────────────────

    /// `:299` minor < 6 → too old. MTU_INFO came one release after
    /// UDP_INFO.
    #[test]
    fn mtu_send_nexthop_minor_6_gate() {
        let now = Instant::now();
        let int = Duration::from_secs(5);
        assert!(!should_send_mtu_info(
            false, true, false, true, None, now, int, MINOR_5
        ));
        assert!(should_send_mtu_info(
            false, true, false, true, None, now, int, MINOR_6
        ));
    }

    /// MTU_INFO has its own debounce, separate timestamp.
    #[test]
    fn mtu_send_debounce() {
        let now = Instant::now();
        let int = Duration::from_secs(5);
        let recent = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!should_send_mtu_info(
            false,
            true,
            false,
            true,
            Some(recent),
            now,
            int,
            MINOR_6
        ));
        let old = now.checked_sub(Duration::from_secs(10)).unwrap();
        assert!(should_send_mtu_info(
            false,
            true,
            false,
            true,
            Some(old),
            now,
            int,
            MINOR_6
        ));
    }

    /// No TCPONLY check for MTU_INFO. `:190` is UDP_INFO-only;
    /// MTU_INFO `:272-330` has no equivalent.
    #[test]
    fn mtu_send_no_tcponly_check() {
        // No options parameters at all → just sanity that it passes.
        let now = Instant::now();
        assert!(should_send_mtu_info(
            false,
            true,
            false,
            true,
            None,
            now,
            Duration::from_secs(5),
            MINOR_6
        ));
    }

    // ── MTU adjust ─────────────────────────────────────────────────

    /// `:308` direct converged measurement OVERRIDES (can increase).
    #[test]
    fn mtu_adjust_direct_override() {
        let from = PmtuSnapshot {
            minmtu: 1400,
            maxmtu: 1400,
        };
        // mtu=1000, from converged at 1400, via_is_myself → use 1400.
        assert_eq!(
            adjust_mtu_for_send(1000, true, Some(from), None, None),
            1400
        );
        // Can also decrease.
        assert_eq!(
            adjust_mtu_for_send(9000, true, Some(from), None, None),
            1400
        );
    }

    /// `:308` requires via_is_myself. Without it, no override.
    #[test]
    fn mtu_adjust_direct_needs_via_myself() {
        let from = PmtuSnapshot {
            minmtu: 1400,
            maxmtu: 1400,
        };
        // via_is_myself=false → falls through, no via/nexthop → unchanged.
        assert_eq!(
            adjust_mtu_for_send(1000, false, Some(from), None, None),
            1000
        );
    }

    /// `:314` static relay clamp: `min(mtu, via->minmtu)`. Never
    /// increases.
    #[test]
    fn mtu_adjust_via_clamp() {
        let via = PmtuSnapshot {
            minmtu: 1300,
            maxmtu: 1300,
        };
        // mtu=1500, via=1300 → 1300.
        assert_eq!(
            adjust_mtu_for_send(1500, false, None, Some(via), None),
            1300
        );
        // mtu=1000, via=1300 → 1000 (min, not via's value).
        assert_eq!(
            adjust_mtu_for_send(1000, false, None, Some(via), None),
            1000
        );
    }

    /// `:318` dynamic relay nexthop clamp.
    #[test]
    fn mtu_adjust_via_nexthop_clamp() {
        let nh = PmtuSnapshot {
            minmtu: 1200,
            maxmtu: 1200,
        };
        assert_eq!(adjust_mtu_for_send(1500, false, None, None, Some(nh)), 1200);
    }

    /// Unconverged measurements don't fire any branch.
    #[test]
    fn mtu_adjust_unconverged_passthrough() {
        let probe = PmtuSnapshot {
            minmtu: 1000,
            maxmtu: 1500,
        };
        assert_eq!(
            adjust_mtu_for_send(1400, true, Some(probe), Some(probe), Some(probe)),
            1400
        );
    }

    // ── MTU_INFO receive ───────────────────────────────────────────

    fn mkmtu(mtu: i32) -> MtuInfo {
        MtuInfo {
            from: "alice".into(),
            to: "bob".into(),
            mtu,
        }
    }

    /// `:345` mtu < 512 → Malformed (connection-fatal).
    #[test]
    fn mtu_recv_below_512_malformed() {
        let m = mkmtu(400);
        let f = FromMtuState {
            mtu: 1500,
            minmtu: 1000,
            maxmtu: 1500,
        };
        assert_eq!(
            on_receive_mtu_info(&m, Some(f), true),
            MtuInfoAction::Malformed
        );
        // Exactly 512 is fine.
        assert_ne!(
            on_receive_mtu_info(&mkmtu(512), Some(f), true),
            MtuInfoAction::Malformed
        );
    }

    /// `:365` mtu differs && not converged → ClampAndForward.
    #[test]
    fn mtu_recv_clamp_when_unconverged() {
        let m = mkmtu(1400);
        let f = FromMtuState {
            mtu: 1500,
            minmtu: 1000,
            maxmtu: 1500,
        };
        assert_eq!(
            on_receive_mtu_info(&m, Some(f), true),
            MtuInfoAction::ClampAndForward { new_mtu: 1400 }
        );
    }

    /// Already converged → Forward (our measurement beats hearsay).
    #[test]
    fn mtu_recv_converged_forward() {
        let m = mkmtu(1400);
        let f = FromMtuState {
            mtu: 1500,
            minmtu: 1500,
            maxmtu: 1500,
        };
        assert_eq!(
            on_receive_mtu_info(&m, Some(f), true),
            MtuInfoAction::Forward
        );
    }

    /// mtu matches current → Forward (no-op).
    #[test]
    fn mtu_recv_same_mtu_forward() {
        let m = mkmtu(1500);
        let f = FromMtuState {
            mtu: 1500,
            minmtu: 1000,
            maxmtu: 1500,
        };
        assert_eq!(
            on_receive_mtu_info(&m, Some(f), true),
            MtuInfoAction::Forward
        );
    }

    /// `:349` clamp to MTU_MAX. Jumbo peer sends 12000 → 9018.
    #[test]
    fn mtu_recv_clamp_to_max() {
        let m = mkmtu(12000);
        let f = FromMtuState {
            mtu: 1500,
            minmtu: 1000,
            maxmtu: 1500,
        };
        assert_eq!(
            on_receive_mtu_info(&m, Some(f), true),
            MtuInfoAction::ClampAndForward {
                new_mtu: u16::try_from(MTU_MAX).unwrap()
            }
        );
    }

    /// Unknown from/to → UnknownNode.
    #[test]
    fn mtu_recv_unknown_node() {
        let m = mkmtu(1400);
        assert_eq!(
            on_receive_mtu_info(&m, None, true),
            MtuInfoAction::UnknownNode
        );
        let f = FromMtuState {
            mtu: 1500,
            minmtu: 1000,
            maxmtu: 1500,
        };
        assert_eq!(
            on_receive_mtu_info(&m, Some(f), false),
            MtuInfoAction::UnknownNode
        );
    }

    /// Constants match `connection.h:33`, `net.h:34`.
    #[test]
    fn constants_match_c() {
        assert_eq!(OPTION_TCPONLY, 0x0002);
        assert_eq!(MTU_MAX, 9018);
        assert_eq!(MTU_MIN, 512);
    }
}
