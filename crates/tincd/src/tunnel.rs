//! `node_t` (`node.h:50-128`) — DATA-PLANE half. C `node_t` is a 60-field
//! god-struct; `NodeState` is the meta-connection half, this is the
//! per-tunnel half (`sptps`/`status`/`address`/`mtu*`/counters). Separate
//! maps: `TunnelState` exists for ANY reachable node, not just direct
//! TCP neighbors (`protocol_key.c:111` forwards via `nexthop`).
//!
//! SPTPS-only: legacy fields (`node.h:67-74`, `:89-93`) dropped.
//! `status.sptps` is always true; kept for `dump nodes` parity.
//!
//! `node_status_t` (`node.h:31-48`): GCC packs LSB-first; field
//! DECLARATION order = bit order.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::Instant;

use tinc_sptps::Sptps;

use crate::pmtu::PmtuState;

/// `net.h:36` `#define MTU 1518` (1500 + 14 eth + 4 VLAN).
pub const MTU: u16 = 1518;

/// `node_t` data-plane fields (`node.h:50-118`). Parallel map to
/// `NodeState`. C `new_node` (`node.c:43-64`): `xzalloc` + `maxmtu=MTU`.
#[derive(Default)]
pub struct TunnelState {
    /// `n->sptps` (`node.h:64`). Set by `sptps_start` (`protocol_key.c:131`,
    /// `datagram=true`); cleared by `graph.c:259`. Boxed: ~1KB, most nodes
    /// never tunnel.
    pub sptps: Option<Box<Sptps>>,

    /// `n->address` (`node.h:57`). UDP send-to. Set by `update_node_udp`
    /// (`node.c:165` via `graph.c:201` SSSP). NOT `NodeState.edge_addr`
    /// (that's TCP `getpeername`); may be NAT-reflexive from `ans_key_h`
    /// (`protocol_key.c:571`).
    pub udp_addr: Option<SocketAddr>,

    /// `(sockaddr, listener_index)` cached after `udp_confirmed`. The
    /// confirmed branch of `choose_udp_address` is deterministic given
    /// `udp_addr`; recomputing per-packet at 1.5 Mpps was 2% self-time.
    /// `socket2::SockAddr` (not std `SocketAddr`): `sendto` wants kernel
    /// shape; per-packet repacking was 0.37%.
    pub udp_addr_cached: Option<(socket2::SockAddr, u8)>,

    /// `n->status` (`node.h:59`). Unpacked (C bitfield is splay-node
    /// memory squeeze; we have a HashMap).
    pub status: TunnelStatus,

    /// `n->last_req_key` (`node.h:61`). Debounce gate (`net_packet.c:1167`,
    /// `protocol_key.c:560`). `None` = C `0` (always passes).
    pub last_req_key: Option<Instant>,

    /// `n->{mtu,minmtu,maxmtu,mtuprobes,...}` (`node.h:108-118`).
    /// `pmtu.udp_confirmed` is authoritative; `status.udp_confirmed`
    /// mirrors for `dump_nodes`. `pmtu.mtu` SURVIVES `reset_unreachable`
    /// (`graph.c:266-269` resets the others). `Option` because
    /// `PmtuState::new` needs an `Instant`; lazily seeded by `try_tx`.
    pub pmtu: Option<PmtuState>,

    /// `n->udp_reply_sent` (`node.h:121`). `try_udp` keepalive gate
    /// (`net_packet.c:1211`).
    pub udp_reply_sent: Option<Instant>,

    /// `n->udp_info_sent` (`node.h:122`). `send_udp_info` debounce
    /// (`protocol_misc.c:183`). Only when WE originate; forwarding skips.
    pub udp_info_sent: Option<Instant>,

    /// `n->mtu_info_sent` (`node.h:123`). Separate from `udp_info_sent`
    /// (`protocol_misc.c:291`): independent debounces.
    pub mtu_info_sent: Option<Instant>,

    /// `n->outcompression` (`node.h:77`). Level PEER advertised in ANS_KEY
    /// (`protocol_key.c:545`); we compress TO them at this level
    /// (`net_packet.c:708`).
    pub outcompression: u8,

    /// `n->incompression` (`node.h:76`). OUR config copied per-tunnel at
    /// handshake (`net_packet.c:995`). Per-tunnel (not settings read) so
    /// SIGHUP-reload mid-session doesn't break decompress.
    pub incompression: u8,

    /// `n->{in,out}_{packets,bytes}` (`node.h:113-116`). `dump_nodes` cols.
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

impl TunnelState {
    /// `graph.c:256-297`, `BecameUnreachable`. `n->mtu` NOT reset (learned
    /// PMTU survives). Traffic counters NOT reset (lifetime totals).
    pub fn reset_unreachable(&mut self) {
        self.sptps = None; // C `:259` `sptps_stop`
        self.last_req_key = None; // C `:263`
        // C `:266-269`: probe state reset; `mtu` preserved.
        if let Some(p) = &mut self.pmtu {
            p.maxmtu = MTU;
            p.minmtu = 0;
            p.mtuprobes = 0;
            p.maxrecentlen = 0;
            p.udp_confirmed = false;
            p.ping_sent = false;
            p.udp_ping_rtt = -1;
        }
        self.udp_reply_sent = None;
        self.udp_addr = None; // C `:296` `update_node_udp(n, NULL)`
        self.udp_addr_cached = None;
        // C `:297`: `memset(&n->status, 0, ...)`. Subsumes `:256,260,265`.
        self.status = TunnelStatus::default();
    }
}

/// `node_status_t` (`node.h:31-48`). Unpacked; `as_u32()` reconstructs
/// for `dump_nodes`. `visited`/`indirect`/`validkey_in`/`has_address`/
/// `ping_sent` omitted (graph scratch / PMTU / unused).
//
// `struct_excessive_bools`: C struct IS independent bits. `validkey`
// and `udp_confirmed` are orthogonal (TCP-tunneled SPTPS = `validkey
// && !udp_confirmed`).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunnelStatus {
    /// `node.h:34`. Bit 1. Set by SPTPS `receive_record` cb on
    /// `SPTPS_HANDSHAKE` (NOT `ans_key_h` — `protocol_key.c:568` reads).
    /// Gates `send_sptps_packet` (`net_packet.c:685`).
    pub validkey: bool,

    /// `node.h:35`. Bit 2. Set in `send_req_key:128`; cleared on
    /// handshake complete. (`last_req_key` is the actual gate; this
    /// is for `dump nodes`.)
    pub waitingforkey: bool,

    /// `node.h:40`. Bit 6. Always true (no legacy). `dump nodes` parity.
    pub sptps: bool,

    /// `node.h:41`. Bit 7. Valid UDP packet received from this node
    /// (`net_packet.c:164`). Gates TCP-tunnel → UDP-direct switch.
    pub udp_confirmed: bool,

    /// `node.h:42`. Bit 8. Transient: set/clear bracket around
    /// `send_udp_probe_packet` (`net_packet.c:1242,1244`). Side-channel
    /// from `try_udp` to `send_sptps_data` (4 layers down).
    pub send_locally: bool,

    /// `node.h:43`. Bit 9. Ephemeral, per-packet. `route.c` reads for
    /// "reply same way".
    pub udppacket: bool,
}

impl TunnelState {
    /// `n->mtu`. `MTU` if unseeded.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.pmtu.as_ref().map_or(MTU, |p| p.mtu)
    }

    /// `n->minmtu`.
    #[must_use]
    pub fn minmtu(&self) -> u16 {
        self.pmtu.as_ref().map_or(0, |p| p.minmtu)
    }

    /// `n->maxmtu`.
    #[must_use]
    pub fn maxmtu(&self) -> u16 {
        self.pmtu.as_ref().map_or(MTU, |p| p.maxmtu)
    }
}

impl TunnelStatus {
    /// Reconstruct C `node_status_t.value` for `dump_nodes`.
    /// `node.h:31-48` GCC-LSB-first: bit 0 unused_active, 1 validkey,
    /// 2 waitingforkey, 3 visited†, 4 reachable(param), 5 indirect†,
    /// 6 sptps, 7 udp_confirmed, 8 send_locally‡, 9 udppacket,
    /// 10-12 omitted†. († always 0: graph scratch / unported.
    /// ‡ transient — 0 in practice between event-loop turns.)
    /// `reachable` is a param (owned by graph, not `TunnelStatus`).
    #[must_use]
    pub fn as_u32(&self, reachable: bool) -> u32 {
        let mut v = 0u32;
        if self.validkey {
            v |= 1 << 1;
        }
        if self.waitingforkey {
            v |= 1 << 2;
        }
        if reachable {
            v |= 1 << 4;
        }
        if self.sptps {
            v |= 1 << 6;
        }
        if self.udp_confirmed {
            v |= 1 << 7;
        }
        if self.send_locally {
            v |= 1 << 8;
        }
        if self.udppacket {
            v |= 1 << 9;
        }
        v
    }
}

/// `protocol_key.c:124` `"tinc UDP key expansion %s %s"`. Per-tunnel
/// HKDF label, (initiator, responder). DIFFERENT from `"tinc TCP key
/// expansion"` (`protocol_auth.c:462`) — meta vs tunnel must not
/// share keys.
#[must_use]
pub fn make_udp_label(initiator: &str, responder: &str) -> Vec<u8> {
    // C `:122-131`: `labellen = 25 + a + b`, passed to `sptps_start`
    // (NOT `strlen(label)`). Format is 24 fixed chars; +1 is snprintf's
    // NUL. The NUL is in the SIG transcript + HKDF seed (`sptps.c:206,258`).
    // Same arithmetic as TCP label. Previously omitted the NUL —
    // Rust↔Rust agreed with itself on the wrong label until cross-impl
    // tests caught it.
    let mut label = format!("tinc UDP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mtu_is_net_h_macro() {
        assert_eq!(MTU, 1518); // `net.h:36`
        let t = TunnelState::default();
        assert_eq!(t.mtu(), 1518);
        assert_eq!(t.maxmtu(), 1518);
        assert_eq!(t.minmtu(), 0);
        assert!(t.pmtu.is_none());
    }

    #[test]
    fn reset_unreachable_clears_everything() {
        let mut t = TunnelState {
            sptps: None, // can't construct without keys; test the Option
            udp_addr: Some("10.0.0.1:655".parse().unwrap()),
            udp_addr_cached: None,
            status: TunnelStatus {
                validkey: true,
                waitingforkey: true,
                sptps: true,
                udp_confirmed: true,
                send_locally: true,
                udppacket: true,
            },
            last_req_key: Some(Instant::now()),
            pmtu: Some({
                let mut p = PmtuState::new(Instant::now(), MTU);
                p.mtu = 1400;
                p.minmtu = 1200;
                p.maxmtu = 1450;
                p.mtuprobes = 7;
                p.udp_confirmed = true;
                p
            }),
            udp_reply_sent: Some(Instant::now()),
            udp_info_sent: Some(Instant::now()),
            mtu_info_sent: Some(Instant::now()),
            outcompression: 6,
            incompression: 12,
            in_packets: 100,
            in_bytes: 50000,
            out_packets: 80,
            out_bytes: 40000,
        };

        t.reset_unreachable();

        assert!(t.sptps.is_none()); // `graph.c:259`
        assert!(t.last_req_key.is_none()); // `:263`
        // `:266-269`: `mtu` survives, rest reset.
        let p = t.pmtu.as_ref().expect("pmtu state survives");
        assert_eq!(p.mtu, 1400, "mtu survives unreachable");
        assert_eq!(p.maxmtu, MTU);
        assert_eq!(p.minmtu, 0);
        assert_eq!(p.mtuprobes, 0);
        assert!(!p.udp_confirmed);
        assert!(t.udp_reply_sent.is_none());
        assert!(t.udp_addr.is_none()); // `:296`
        assert_eq!(t.status, TunnelStatus::default()); // `:297`
        // Traffic counters NOT reset (lifetime totals).
        assert_eq!(t.in_packets, 100);
        assert_eq!(t.in_bytes, 50000);
        assert_eq!(t.out_packets, 80);
        assert_eq!(t.out_bytes, 40000);
    }

    #[test]
    fn make_udp_label_format() {
        // `protocol_key.c:122-131`: `labellen = 25 + a + b` (NOT strlen).
        // NUL is in the signed/HKDF material (`sptps.c:206,258`).
        assert_eq!(
            make_udp_label("alice", "bob"),
            b"tinc UDP key expansion alice bob\0"
        );
        // `:259` responder: args swapped at call site, fn doesn't swap.
        assert_eq!(
            make_udp_label("bob", "alice"),
            b"tinc UDP key expansion bob alice\0"
        );
    }

    #[test]
    fn make_udp_label_differs_from_tcp() {
        // `protocol_auth.c:462` vs `protocol_key.c:124`.
        let udp = make_udp_label("a", "b");
        let tcp = b"tinc TCP key expansion a b";
        assert_ne!(udp.as_slice(), tcp.as_slice());
    }

    #[test]
    fn tunnel_status_bitfield_packing() {
        // `node.h:31-48` GCC-LSB-first; declaration order = bit order.
        let z = TunnelStatus::default();
        assert_eq!(z.as_u32(false), 0);

        // Each bit in isolation.
        let bit = |s: TunnelStatus| s.as_u32(false);
        assert_eq!(
            bit(TunnelStatus {
                validkey: true,
                ..z
            }),
            1 << 1
        );
        assert_eq!(
            bit(TunnelStatus {
                waitingforkey: true,
                ..z
            }),
            1 << 2
        );
        assert_eq!(z.as_u32(true), 1 << 4); // `reachable` is the param
        assert_eq!(bit(TunnelStatus { sptps: true, ..z }), 1 << 6);
        assert_eq!(
            bit(TunnelStatus {
                udp_confirmed: true,
                ..z
            }),
            1 << 7
        );
        assert_eq!(
            bit(TunnelStatus {
                udppacket: true,
                ..z
            }),
            1 << 9
        );

        // All set: 0b11_1101_0110 = 0x3d6.
        let all = TunnelStatus {
            validkey: true,
            waitingforkey: true,
            sptps: true,
            udp_confirmed: true,
            send_locally: true,
            udppacket: true,
        };
        assert_eq!(
            all.as_u32(true),
            (1 << 1) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9)
        );
        assert_eq!(all.as_u32(true), 0x3d6);

        // Post-handshake steady state: 0xd2.
        let steady = TunnelStatus {
            validkey: true,
            waitingforkey: false,
            sptps: true,
            udp_confirmed: true,
            send_locally: false,
            udppacket: false,
        };
        assert_eq!(steady.as_u32(true), 0xd2);
    }
}
