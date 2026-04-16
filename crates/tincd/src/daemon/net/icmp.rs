use super::super::Daemon;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use crate::route::{self, TtlResult};
use crate::{icmp, neighbor};

use tinc_graph::NodeId;

use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, SockaddrStorage, connect, getsockname, socket,
};

impl Daemon {
    pub(super) fn handle_arp(&mut self, data: &[u8], from: Option<NodeId>) -> bool {
        // ARP from a peer in router mode is a misconfig (their
        // kernel shouldn't be ARPing across an L3 tunnel).
        if let Some(from_nid) = from {
            log::warn!(target: "tincd::net",
                       "Got ARP request from {} while in router mode!",
                       self.node_log_name(from_nid));
            return false;
        }
        let Some(target) = neighbor::parse_arp_req(data) else {
            log::debug!(target: "tincd::net",
                        "route: dropping ARP packet (not a valid request)");
            return false;
        };
        // Snatch the kernel's MAC. parse_arp_req gated data.len()≥42
        // so [6..12] is safe. Snatch BEFORE the subnet lookup; the
        // snatch is the only useful side effect even if no subnet
        // owns the target.
        if self.overwrite_mac {
            self.mymac.copy_from_slice(&data[6..12]);
        }
        // No reachability check — ARP just answers "does someone own
        // this", not "are they up".
        let Some((_, owner)) = self.subnets.lookup_ipv4(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: ARP for unknown {target}");
            return false;
        };
        // Silently ignore ARPs for our own subnets — the kernel
        // already knows; replying would create a wrong arp-cache
        // entry pointing at the TUN.
        if owner == Some(&self.name) {
            return false;
        }
        let mut reply = neighbor::build_arp_reply(data);
        log::debug!(target: "tincd::net",
                    "route: ARP reply for {target} (owner {})",
                    owner.unwrap_or("(broadcast)"));
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ARP reply to device: {e}");
        }
        false
    }

    pub(super) fn handle_ndp(&mut self, data: &mut [u8], from: Option<NodeId>) {
        // NDP solicit from a peer in router mode — misconfig
        // (router-mode is L3; kernel shouldn't be doing neighbor
        // discovery across the tunnel).
        if let Some(from_nid) = from {
            log::warn!(target: "tincd::net",
                       "Got neighbor solicitation request from {} \
                        while in router mode!",
                       self.node_log_name(from_nid));
            return;
        }
        let Some(target) = neighbor::parse_ndp_solicit(data) else {
            log::debug!(target: "tincd::net",
                        "route: dropping NDP solicit (parse/checksum failed)");
            return;
        };
        // Snatch the kernel's MAC. parse_ndp_solicit gated
        // data.len()≥78. Snatch BEFORE the subnet lookup; the snatch
        // is the only useful side effect even if no subnet owns the
        // target (we still learned the kernel's MAC).
        if self.overwrite_mac {
            self.mymac.copy_from_slice(&data[6..12]);
        }
        let Some((_, owner)) = self.subnets.lookup_ipv6(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: NDP solicit for unknown {target}");
            return;
        };
        if owner == Some(&self.name) {
            return;
        }
        // decrement_ttl on the SOLICIT before building the advert.
        // Triple-gate: DecrementTTL=yes (rare) + NDP (rarer) + the
        // from-peer arm is unreachable here (gated above).
        // decrement_ttl(v6, hlim=255) → 254 in the original;
        // build_ndp_advert copies that hlim into the reply.
        if self.settings.decrement_ttl {
            match route::decrement_ttl(data) {
                TtlResult::Decremented | TtlResult::TooShort => {}
                TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                    // No ICMP synth.
                    return;
                }
            }
        }
        let Some(mut reply) = neighbor::build_ndp_advert(data) else {
            return;
        };
        log::debug!(target: "tincd::net",
                    "route: NDP advert for {target} (owner {})",
                    owner.unwrap_or("(broadcast)"));
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing NDP advert to device: {e}");
        }
    }

    /// v4/v6 dispatch on ethertype, not `icmp_type`: `ICMP_DEST_UNREACH`
    /// =3 collides with `ICMP6_TIME_EXCEEDED=3` (bug audit `deef1268`).
    /// data.len()≥14 holds: every caller is `post-route()` (`TooShort`
    /// gate) or post-decrement_ttl. `discover_src`: do the
    /// `local_ip_facing` lookup so traceroute shows OUR hop —
    /// `TIME_EXCEEDED` only; `DEST_UNREACH` uses orig-dst (`None`).
    pub(super) fn write_icmp_to_device(
        &mut self,
        data: &[u8],
        icmp_type: u8,
        icmp_code: u8,
        discover_src: bool,
    ) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        // orig src lives at fixed offsets: eth(14)+ip_src(12)=[26..30]
        // for v4, eth(14)+ip6_src(8)=[22..38] for v6. None on any
        // failure → falls back to orig-dst-as-src.
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let reply = if ethertype == 0x86DD {
            // ETH_P_IPV6
            let src = discover_src
                .then(|| {
                    data.get(22..38)
                        .and_then(|s| <[u8; 16]>::try_from(s).ok())
                        .map(Ipv6Addr::from)
                        .and_then(|a| match local_ip_facing(IpAddr::V6(a))? {
                            IpAddr::V6(v6) => Some(v6.octets()),
                            IpAddr::V4(_) => None,
                        })
                })
                .flatten();
            icmp::build_v6_unreachable(data, icmp_type, icmp_code, None, src)
        } else {
            let src = discover_src
                .then(|| {
                    data.get(26..30)
                        .and_then(|s| <[u8; 4]>::try_from(s).ok())
                        .map(Ipv4Addr::from)
                        .and_then(|a| match local_ip_facing(IpAddr::V4(a))? {
                            IpAddr::V4(v4) => Some(v4.octets()),
                            IpAddr::V6(_) => None,
                        })
                })
                .flatten();
            icmp::build_v4_unreachable(data, icmp_type, icmp_code, None, src)
        };
        if let Some(reply) = reply {
            log::debug!(target: "tincd::net",
                        "route: sending ICMP type={icmp_type} \
                         code={icmp_code} ({} bytes)", reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// v4 `FRAG_NEEDED`. Separate helper: passes `frag_mtu` through.
    pub(super) fn write_icmp_frag_needed(&mut self, data: &[u8], frag_mtu: u16) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        if let Some(reply) = icmp::build_v4_unreachable(
            data,
            route::ICMP_DEST_UNREACH,
            route::ICMP_FRAG_NEEDED,
            Some(frag_mtu),
            None,
        ) {
            log::debug!(target: "tincd::net",
                        "route: FRAG_NEEDED, mtu={frag_mtu} ({} bytes)",
                        reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// v6 `PACKET_TOO_BIG`.
    pub(super) fn write_icmp_pkt_too_big(&mut self, data: &[u8], mtu: u32) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        if let Some(reply) =
            icmp::build_v6_unreachable(data, route::ICMP6_PACKET_TOO_BIG, 0, Some(mtu), None)
        {
            log::debug!(target: "tincd::net",
                        "route: PACKET_TOO_BIG, mtu={mtu} ({} bytes)",
                        reply.len());
            self.write_icmp_reply(reply);
        }
    }

    pub(super) fn write_icmp_reply(&mut self, mut reply: Vec<u8>) {
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ICMP to device: {e}");
        }
    }
}

/// For ICMP `TIME_EXCEEDED`: find our local IP facing the original
/// sender so traceroute shows us correctly. UDP `connect()` then
/// `getsockname()` — no packets sent (UDP connect is a route lookup
/// plus dst association). Same trick `choose_initial_maxmtu` uses
/// (`9e2540ab`).
///
/// Port is irrelevant (route lookup); use 1 (some kernels reject 0
/// for connect). All errors fall through to the default via `?` →
/// `None`.
fn local_ip_facing(orig_src: IpAddr) -> Option<IpAddr> {
    let af = match orig_src {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    let sock = socket(af, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None).ok()?;
    let ss = SockaddrStorage::from(SocketAddr::new(orig_src, 1));
    connect(sock.as_raw_fd(), &ss).ok()?;
    let local: SockaddrStorage = getsockname(sock.as_raw_fd()).ok()?;
    match orig_src {
        IpAddr::V4(_) => Some(IpAddr::V4(local.as_sockaddr_in()?.ip())),
        IpAddr::V6(_) => Some(IpAddr::V6(local.as_sockaddr_in6()?.ip())),
    }
}
