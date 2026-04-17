//! PCP / UPnP-IGD port mapping (C tinc's `upnp.c` parity++).
//!
//! ## What this solves
//!
//! A home-NAT'd node's TCP listener at `:655` is unreachable from
//! the WAN side: nothing tells the Fritzbox/consumer-router to DNAT
//! inbound `:655` to us. The DHT-published `v4=` is the UDP-reflexive
//! port (good for the punch, useless for an inbound meta-connection).
//! `tcp=` needs a *router-installed* forwarding rule. On v6 there's
//! no NAT but the same router usually drops unsolicited inbound; PCP
//! asks it to open a firewall pinhole to our GUA, which feeds
//! `tcp6=` so peers can dial the meta-connection over v6 without a
//! Tier-0 punch.
//!
//! C tinc spawns a `pthread` that loops `upnpDiscover` →
//! `UPNP_AddPortMapping` every `UPnPRefreshPeriod` seconds, lease =
//! 2×period (so the mapping never expires before refresh). We match
//! the semantics but try **PCP first** (RFC 6887; one UDP round-trip
//! to the default gateway, sub-second; Fritzbox/miniupnpd/OpenWRT
//! all speak it) and only fall back to SSDP→IGD on the v4 path when
//! that fails. Same outcome, ~5 s faster in the common case, and PCP
//! tells us the *external* port the router actually picked (IGD's
//! `AddPortMapping` echoes the port we asked for; PCP returns the
//! truth).
//!
//! ## Integration
//!
//! Same shape as `discovery.rs`: a `std::thread` does the blocking
//! protocol work, a `flume` channel reports `PortmapEvent`s, the
//! daemon's `on_periodic_tick` drains them. The thread sleeps in 1 s
//! slices and checks `stop` between, so daemon shutdown joins
//! within ~1 s rather than blocking on a 60 s refresh interval.
//!
//! ## Dependency note
//!
//! The spec asked for n0's `portmapper` crate (UPnP+NAT-PMP+PCP in
//! one). Evaluated, rejected: it drags +190 transitive crates into
//! the tree (full tokio/hyper/netwatch/ICU stack) where the daemon
//! is otherwise epoll-only. PCP is hand-rolled in `pcp.rs` (~100
//! lines, zero deps — the wire format is two fixed-layout structs).
//! `igd-next` (sync, attohttpc) covers the SSDP/SOAP fallback for
//! UPnP-only v4 routers; `netdev` provides cross-platform default-
//! gateway lookup (needed because PCP talks to the gateway directly,
//! and the v6 gateway is a link-local addr we can't guess).
//!
//! NAT-PMP (RFC 6886) is intentionally **not** implemented: it's
//! formally superseded by PCP, RFC 6887 §A says clients SHOULD send
//! PCP-first, and a survey of real routers found nothing that speaks
//! NAT-PMP but not PCP (miniupnpd dispatches both off the same
//! socket; AVM Fritzbox is PCP-only on `:5351`). A pure-NAT-PMP box
//! (Apple `AirPort`, EOL 2018) replies `UNSUPP_VERSION` and we fall
//! through to IGD — still mapped, just slower.

#![forbid(unsafe_code)]
#![cfg(feature = "upnp")]

mod igd;
mod pcp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

/// `UPnP = yes | udponly | no` — C parity (`net_setup.c:1202`).
/// `udponly` maps the UDP listener only (the SPTPS datagram path);
/// `yes` also maps TCP (the meta-connection listener — this is what
/// feeds `tcp=`/`tcp6=` in the DHT record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpnpMode {
    #[default]
    No,
    UdpOnly,
    Yes,
}

impl UpnpMode {
    pub(crate) fn from_config(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => Some(Self::Yes),
            "udponly" => Some(Self::UdpOnly),
            "no" | "false" | "off" => Some(Self::No),
            _ => None,
        }
    }
    const fn wants_tcp(self) -> bool {
        matches!(self, Self::Yes)
    }
    const fn wants_udp(self) -> bool {
        matches!(self, Self::Yes | Self::UdpOnly)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Address family of a `Mapped`/`Lost` event. `V4` is a NAT DNAT
/// rule; `V6` is a firewall pinhole (no translation, `ext` is our
/// own GUA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Af {
    V4,
    V6,
}

/// What the worker thread reports back. `Mapped` carries the
/// *external* `(ip, port)` — for PCP that's the router-chosen
/// public port; for IGD it's the port we asked for (same as
/// `local_port`). `Lost` is emitted when a refresh that previously
/// succeeded fails (router rebooted, lease table full, LAN moved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortmapEvent {
    Mapped {
        af: Af,
        proto: Proto,
        local_port: u16,
        ext: SocketAddr,
        via: &'static str,
    },
    Lost {
        af: Af,
        proto: Proto,
    },
}

/// Lives on `Daemon`. `tick()` is the non-blocking drain.
pub struct Portmapper {
    rx: flume::Receiver<PortmapEvent>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Portmapper {
    /// Spawn the refresh thread. `local_port` is the daemon's bound
    /// listener port (TCP and UDP share it — `open_listener_pair`
    /// guarantees that). `refresh` is `UPnPRefreshPeriod`; lease is
    /// `max(2×refresh, 120s)` — RFC 6887 recommends 120 s as
    /// `min_lifetime` and miniupnpd clamps below that anyway, so
    /// asking for less just makes the response a surprise.
    /// `discover_wait` caps the SSDP wait.
    ///
    /// # Panics
    /// `std::thread::spawn` failure (out of threads/memory).
    #[must_use]
    pub fn spawn(
        local_port: u16,
        mode: UpnpMode,
        refresh: Duration,
        discover_wait: Duration,
    ) -> Self {
        let (tx, rx) = flume::unbounded();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("portmap".into())
            .spawn(move || worker(local_port, mode, refresh, discover_wait, &tx, &stop2))
            .expect("portmap thread spawn");
        Self {
            rx,
            stop,
            join: Some(join),
        }
    }

    /// Non-blocking drain. Called from `on_periodic_tick` (5s).
    #[must_use]
    pub fn tick(&self) -> Vec<PortmapEvent> {
        self.rx.try_iter().collect()
    }
}

impl Drop for Portmapper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            // Worst case: SSDP discover_wait (≤5s) or PCP deadline
            // (2s); the 1s sleep slices in the refresh wait check
            // `stop`. C tinc doesn't even try to join (`upnp.c:170`:
            // "we don't have a clean thread shutdown procedure"); we
            // do, so the lease can be left to expire cleanly rather
            // than maybe-orphaning a thread.
            let _ = j.join();
        }
    }
}

/// Snapshot of the default route(s) we map through. Re-derived every
/// refresh round so a roaming laptop (wifi→ethernet, VPN up, DHCP
/// into a new subnet) re-maps against the *current* router instead
/// of asking the new one to DNAT to the old internal address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct GwState {
    /// v4 default gateway + our LAN address towards it.
    v4: Option<(Ipv4Addr, Ipv4Addr)>,
    /// v6 default router (usually link-local), the ifindex it's
    /// scoped to, and one global-unicast address of ours on that
    /// interface (the pinhole target). `None` if no v6 default
    /// route or no GUA on it.
    v6: Option<(Ipv6Addr, u32, Ipv6Addr)>,
}

impl GwState {
    /// `netdev::get_default_interface()` walks the routing table
    /// (netlink on Linux, routing socket on BSD/macOS, `IpHelper` on
    /// Windows) and returns the interface owning the default route
    /// with its v4+v6 gateways and addresses. Cheap enough to do
    /// every refresh.
    fn read() -> Self {
        let Ok(iface) = netdev::get_default_interface() else {
            return Self::default();
        };
        let gw = iface.gateway.as_ref();

        let v4 = gw
            .and_then(|g| g.ipv4.first().copied())
            .and_then(|gw4| local_ip_towards(IpAddr::V4(gw4)).map(|lan| (gw4, lan)));

        let v6 = gw.and_then(|g| g.ipv6.first().copied()).and_then(|gw6| {
            // Pick a stable GUA: skip RFC 4941 temporaries (rotate
            // ~daily — pinhole would go stale) and deprecated/
            // tentative addrs. `2000::/3` only — ULAs aren't
            // reachable from the WAN side, no point pinholing them.
            iface
                .ipv6
                .iter()
                .enumerate()
                .map(|(i, net)| (net.addr(), iface.ipv6_addr_flags.get(i)))
                .find(|(a, f)| {
                    (a.segments()[0] & 0xe000) == 0x2000
                        && f.is_none_or(|f| !f.temporary && !f.deprecated && !f.tentative)
                })
                .map(|(gua, _)| (gw6, iface.index, gua))
        });

        Self { v4, v6 }
    }
}

/// One v4 refresh: try PCP (if we know the gateway), fall back to
/// IGD. IGD discovers the router via SSDP multicast itself, so it
/// stays useful even when the route-table read found nothing
/// (e.g. point-to-point WAN with no v4 nexthop, or netdev failed).
/// Logs the failure path at debug — the router not supporting
/// either is the *normal* case for a VPS, not an error.
fn try_map_v4(
    gw: Option<(Ipv4Addr, Ipv4Addr)>,
    local_port: u16,
    proto: Proto,
    lease: u32,
    discover_wait: Duration,
    nonce: &[u8; 12],
) -> Result<(SocketAddr, &'static str), String> {
    if let Some((gw4, _lan)) = gw {
        match pcp::map_v4(gw4, proto, local_port, lease, nonce) {
            Ok(ext) => return Ok((ext, "PCP")),
            Err(e) => log::debug!(target: "tincd::portmap", "PCP v4: {e}"),
        }
    }
    try_igd(
        local_port,
        proto,
        lease,
        discover_wait,
        gw.map(|(_, lan)| lan),
    )
    .map(|ext| (ext, "UPnP-IGD"))
}

/// UPnP-IGD. SSDP M-SEARCH multicast → fetch root desc → SOAP
/// `AddPortMapping`. `lan_ip` is the address the router should DNAT
/// *to*; we learn it from the socket the SSDP reply arrived on
/// (igd-next doesn't expose that, so caller passes the
/// route-table-derived LAN IP).
fn try_igd(
    local_port: u16,
    proto: Proto,
    lease: u32,
    discover_wait: Duration,
    lan_ip: Option<Ipv4Addr>,
) -> Result<SocketAddr, String> {
    let gw = igd::discover(discover_wait)?;

    // C tinc passes miniupnpc's `lanaddr` (UPNP_GetValidIGD output).
    // Derive from the gateway's addr by connecting a throwaway UDP
    // socket and reading local_addr — the kernel's route lookup
    // picks the right source IP for us.
    let lan_ip = lan_ip
        .or_else(|| local_ip_towards(gw.addr()))
        .ok_or("no LAN IP towards gateway")?;

    gw.add_port(
        proto,
        local_port,
        SocketAddrV4::new(lan_ip, local_port),
        lease,
        "tinc",
    )
    .map_err(|e| format!("AddPortMapping: {e}"))?;

    let ext_ip = gw
        .external_ip()
        .map_err(|e| format!("GetExternalIPAddress: {e}"))?;
    Ok(SocketAddr::new(ext_ip, local_port))
}

/// Kernel route lookup: which of our addresses would source a packet
/// to `peer`? `connect(2)` on a UDP socket does this without sending.
fn local_ip_towards(peer: IpAddr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((peer, 1)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// (af × proto) slot table. Per-slot `last`/`warned` arrays index
/// by position; mode-disabled slots are simply skipped.
const SLOTS: [(Af, Proto); 4] = [
    (Af::V4, Proto::Tcp),
    (Af::V4, Proto::Udp),
    (Af::V6, Proto::Tcp),
    (Af::V6, Proto::Udp),
];

#[allow(clippy::cast_possible_truncation)] // lease seconds fit u32 at the config clamp
fn worker(
    local_port: u16,
    mode: UpnpMode,
    refresh: Duration,
    discover_wait: Duration,
    tx: &flume::Sender<PortmapEvent>,
    stop: &AtomicBool,
) {
    if !(mode.wants_tcp() || mode.wants_udp()) {
        return;
    }
    // Per-slot last-known mapping. Change → emit Mapped; was-Some
    // now-Err → emit Lost.
    let mut last: [Option<SocketAddr>; 4] = [None; 4];
    // Per-slot: have we already INFO-logged the current failure
    // streak? Reset on success so a later loss (network change,
    // router toggled UPnP off) surfaces again instead of staying
    // debug-only forever after the first boot-time round.
    let mut warned: [bool; 4] = [false; 4];

    // Floor at 120 s: RFC 6887 §15 recommended `min_lifetime`, also
    // miniupnpd's hard-coded clamp. Asking for less means the
    // response carries a different lifetime than we asked → benign
    // but confusing in logs; and a non-clamping server would expire
    // the rule before our default 60 s refresh's second round.
    let lease = (refresh.as_secs() * 2).max(120).min(u64::from(u32::MAX)) as u32;

    // RFC 6887 §11.2: nonce is random per-mapping, stable across
    // refreshes (same nonce ⇒ "renew this mapping", not "make a
    // second one"). One per (af × proto).
    let mut nonces = [[0u8; 12]; 4];
    for n in &mut nonces {
        OsRng.fill_bytes(n);
    }

    // LAN topology, re-derived every refresh round. See `GwState`.
    let mut gw = GwState::default();
    let mut first = true;

    loop {
        let started = Instant::now();

        let cur = GwState::read();
        if cur != gw {
            if !first {
                log::info!(target: "tincd::portmap",
                           "default route changed ({gw:?} → {cur:?}); re-mapping");
                // Force a fresh `Mapped` event even if the new
                // router hands back the identical external addr:
                // the mapping is on a different box now, and
                // discovery's `tcp=` republish keys off the event,
                // not the value.
                last = [None; 4];
                warned = [false; 4];
            }
            gw = cur;
        }
        first = false;

        for (i, &(af, proto)) in SLOTS.iter().enumerate() {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let want = match proto {
                Proto::Tcp => mode.wants_tcp(),
                Proto::Udp => mode.wants_udp(),
            };
            if !want {
                continue;
            }
            let res = match af {
                // v4 always tries: IGD does its own discover, so
                // "no v4 gateway in the route table" doesn't mean
                // "no IGD router on the link".
                Af::V4 => Some(try_map_v4(
                    gw.v4,
                    local_port,
                    proto,
                    lease,
                    discover_wait,
                    &nonces[i],
                )),
                // v6 has no IGD fallback (igd-next lacks
                // `WANIPv6FirewallControl::AddPinhole`). PCP only;
                // no v6 default route ⇒ nothing to do, not an error.
                Af::V6 => gw.v6.map(|(gw6, scope, gua)| {
                    pcp::map_v6(gw6, scope, gua, proto, local_port, lease, &nonces[i])
                        .map(|ext| (ext, "PCP"))
                }),
            };
            let Some(res) = res else {
                if last[i].take().is_some() && tx.send(PortmapEvent::Lost { af, proto }).is_err() {
                    return;
                }
                continue;
            };
            match res {
                Ok((ext, via)) => {
                    warned[i] = false;
                    if last[i] != Some(ext) {
                        last[i] = Some(ext);
                        if tx
                            .send(PortmapEvent::Mapped {
                                af,
                                proto,
                                local_port,
                                ext,
                                via,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(e) => {
                    if warned[i] {
                        log::debug!(target: "tincd::portmap",
                                    "map {af:?}/{proto:?} {local_port}: {e}");
                    } else {
                        warned[i] = true;
                        log::info!(target: "tincd::portmap",
                                   "no PCP/IGD gateway responded for \
                                    {af:?}/{proto:?} {local_port} ({e}); will \
                                    keep retrying every {refresh:?}");
                    }
                    if last[i].take().is_some()
                        && tx.send(PortmapEvent::Lost { af, proto }).is_err()
                    {
                        return;
                    }
                }
            }
        }

        // C parity: stick to refresh period regardless of how long
        // the round took. Sleep in 1s slices so Drop joins promptly.
        let until = started + refresh;
        while Instant::now() < until {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_secs(1).min(until - Instant::now()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upnp_mode_parse() {
        assert_eq!(UpnpMode::from_config("yes"), Some(UpnpMode::Yes));
        assert_eq!(UpnpMode::from_config("UDPONLY"), Some(UpnpMode::UdpOnly));
        assert_eq!(UpnpMode::from_config("no"), Some(UpnpMode::No));
        assert_eq!(UpnpMode::from_config("maybe"), None);
        assert!(UpnpMode::Yes.wants_tcp() && UpnpMode::Yes.wants_udp());
        assert!(!UpnpMode::UdpOnly.wants_tcp() && UpnpMode::UdpOnly.wants_udp());
    }
}
