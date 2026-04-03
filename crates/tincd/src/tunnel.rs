//! `node_t` (`node.h:50-128`) — DATA-PLANE half.
//!
//! ## `TunnelState` vs `NodeState`
//!
//! C `node_t` is a 60-field god-struct. The chunk-5 `NodeState`
//! carries the META-connection runtime (`connection`, `prevedge`-
//! derived `edge_addr`/`edge_weight`/`edge_options`). This module
//! is the per-tunnel half: `n->sptps`, `n->status`, `n->address`
//! (UDP send-to), `n->mtu*`, `n->{in,out}_{packets,bytes}`.
//!
//! Separate maps because the lifecycles differ. `NodeState` is
//! tied to the meta-connection (one direct neighbor at a time);
//! `TunnelState` exists for ANY reachable node — chunk-7 sends
//! UDP to nodes we have no TCP connection to (forwarding via
//! `n->nexthop->connection`, `protocol_key.c:111`).
//!
//! ## SPTPS-only
//!
//! C `node_t` carries the legacy fork too (`incipher`/`indigest`/
//! `outcipher`/`outdigest`, `node.h:67-74`; `sent_seqno`/`late`,
//! `:89-93`). The Rust port is SPTPS-only (`--disable-legacy`
//! equivalent). `n->status.sptps` is therefore ALWAYS true once
//! a tunnel exists; we keep the bit for `dump nodes` parity but
//! never branch on it.
//!
//! ## Bitfield packing
//!
//! `node_status_t` (`node.h:31-48`) is a packed `union { struct
//! { bool x:1; ... }; uint32_t value; }`. GCC packs bit-fields
//! LSB-first on little-endian (same chunk-4b finding for
//! `connection_status_t.control` = bit 9). Field DECLARATION
//! order is bit order. The brief's "bit 4 = validkey" is wrong
//! — `validkey` is the SECOND field declared, so bit 1.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::Instant;

use tinc_sptps::Sptps;

/// `net.h:36` `#define MTU 1518` (1500 payload + 14 ethernet + 4
/// VLAN). The non-jumbogram build. C `node_t.maxmtu` initializes
/// to this and `BecameUnreachable` resets to it (`graph.c:266`).
pub const MTU: u16 = 1518;

/// `node_t` data-plane fields (`node.h:50-118`). Lives in
/// `HashMap<NodeId, TunnelState>` parallel to `NodeState`.
///
/// Chunk-7 reads/writes exactly these fields via `send_req_key`
/// (`protocol_key.c:114-132`), `ans_key_h` SPTPS branch
/// (`:549-578`), `send_sptps_packet` gate (`net_packet.c:685`),
/// and `BecameUnreachable` reset (`graph.c:256-297`).
pub struct TunnelState {
    /// `n->sptps` (`node.h:64`). The per-tunnel SPTPS state
    /// machine. `None` before the first `send_req_key`; `Some`
    /// after `sptps_start` (`protocol_key.c:131`, called with
    /// `datagram=true` — the second bool). `BecameUnreachable`
    /// resets to `None` (`graph.c:259` `sptps_stop(&n->sptps)`).
    ///
    /// Boxed: `Sptps` is ~1KB and most nodes never get a tunnel
    /// (only the reachable ones we actually send to). Same trade
    /// as `Connection.sptps`.
    pub sptps: Option<Box<Sptps>>,

    /// `n->address` (`node.h:57`). The UDP send-to addr. Set by
    /// `update_node_udp` (`node.c:165`, called from `graph.c:201`
    /// SSSP via the `prevedge->reverse->address` chain). Cleared
    /// on unreachable (`graph.c:296` `update_node_udp(n, NULL)`).
    ///
    /// **Not `NodeState.edge_addr`.** That's the META-connection
    /// peer addr (the TCP `getpeername`). This is the UDP-packet
    /// destination — possibly a NAT-reflexive addr learned from
    /// `ans_key_h` (`protocol_key.c:571` `str2sockaddr(address,
    /// port)`).
    pub udp_addr: Option<SocketAddr>,

    /// `n->status` (`node.h:59`). The chunk-7-relevant bits,
    /// unpacked. The C bitfield is a memory squeeze for splay
    /// nodes; we have a `HashMap` and don't care.
    pub status: TunnelStatus,

    /// `n->last_req_key` (`node.h:61`). Debounce. `net_packet.c:
    /// 1167` `n->last_req_key + 10 < now.tv_sec` gates `send_req_
    /// key` re-sends; `protocol_key.c:560` same gate on the
    /// "stuck tunnel restart" path. Set in `send_req_key:129`.
    /// `None` is the C `0` (epoch — always passes the gate).
    pub last_req_key: Option<Instant>,

    /// `n->mtu` (`node.h:108`). Current PMTU to this node.
    /// Chunk 9's `try_fix_mtu` writes; chunk 7's `send_sptps_
    /// packet` fragments on it. Init `MTU`; never reset (the
    /// learned PMTU survives reconnects in C — only `minmtu`/
    /// `maxmtu`/`mtuprobes` reset, `graph.c:266-269`).
    pub mtu: u16,

    /// `n->minmtu` (`node.h:109`). Probed lower bound. Init 0.
    /// `graph.c:268` resets to 0 on unreachable.
    pub minmtu: u16,

    /// `n->maxmtu` (`node.h:110`). Probed upper bound. Init `MTU`.
    /// `graph.c:266` resets to `MTU` on unreachable.
    pub maxmtu: u16,

    /// `n->mtuprobes` (`node.h:111`). Probe sequence counter.
    /// Negative values = "fixed, count to next re-probe". Init 0.
    /// `graph.c:269` resets to 0 on unreachable.
    pub mtuprobes: i32,

    /// `n->in_packets`, `n->in_bytes`, `n->out_packets`,
    /// `n->out_bytes` (`node.h:113-116`). `dump_nodes` columns.
    /// `uint64_t` in C.
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

impl Default for TunnelState {
    fn default() -> Self {
        // C `new_node` (`node.c:43-64`): `xzalloc` everything,
        // then `n->maxmtu = MTU`. `n->mtu` STAYS 0 in C — the
        // first `try_fix_mtu` writes it. We init to `MTU` because
        // chunk 7 reads `mtu` before chunk 9 lands; matches the
        // "no PMTU discovery yet" semantics of `net_packet.c:1042`
        // `if(n->minmtu)` gate (which is false at default).
        Self {
            sptps: None,
            udp_addr: None,
            status: TunnelStatus::default(),
            last_req_key: None,
            mtu: MTU,
            minmtu: 0,
            maxmtu: MTU,
            mtuprobes: 0,
            in_packets: 0,
            in_bytes: 0,
            out_packets: 0,
            out_bytes: 0,
        }
    }
}

impl TunnelState {
    /// `graph.c:256-297`, `BecameUnreachable` transition.
    ///
    /// Order matches the C exactly (matters for nothing — no
    /// reentrancy here — but makes diffs against C readable).
    /// The C also `memset(&n->status, 0, sizeof(n->status))`
    /// AFTER the per-field clears (`:297`); we do the equivalent
    /// `TunnelStatus::default()` once at the end.
    ///
    /// `n->mtu` is NOT reset (see field doc). `maxrecentlen` IS
    /// reset in C (`:267`) but that's a chunk-9 field we don't
    /// carry yet.
    ///
    /// Traffic counters are NOT reset — `dump nodes` shows
    /// lifetime totals across reconnects (verified: no `*_packets
    /// = 0` anywhere in `graph.c`).
    pub fn reset_unreachable(&mut self) {
        // C `:259`: `sptps_stop(&n->sptps)` — frees the keys,
        // zeroes the struct. Our `Option::take()` drops the Box.
        self.sptps = None;
        // C `:263`: `n->last_req_key = 0`.
        self.last_req_key = None;
        // C `:266-269`: mtu probe state.
        self.maxmtu = MTU;
        self.minmtu = 0;
        self.mtuprobes = 0;
        // C `:296`: `update_node_udp(n, NULL)`.
        self.udp_addr = None;
        // C `:297`: `memset(&n->status, 0, sizeof(n->status))`.
        // The per-field `validkey = false` (`:256`), `waitingfor
        // key = false` (`:260`), `udp_confirmed = false` (`:265`)
        // are subsumed.
        self.status = TunnelStatus::default();
    }
}

/// `node_status_t` (`node.h:31-48`). The chunk-7-relevant bits.
///
/// Unpacked because (a) the C bitfield is a splay-node memory
/// squeeze we don't need, (b) `#[repr]` bitfield ergonomics in
/// Rust are bad, and (c) the only place the packed `u32` matters
/// is `dump_nodes` — `as_u32()` reconstructs it on demand.
///
/// `visited`/`indirect`/`send_locally`/`validkey_in`/`has_
/// address`/`ping_sent` omitted: graph-algorithm scratch (chunk 5
/// owns `visited`/`reachable`), chunk-9 PMTU (`ping_sent`), or
/// not on any chunk-7 read path.
//
// `struct_excessive_bools`: the C struct IS a bag of independent
// bits (`node.h:31-48`). "Refactor into a state machine" is
// wrong — `validkey` and `udp_confirmed` are orthogonal axes
// (TCP-tunneled SPTPS works fine with `validkey && !udp_
// confirmed`). The packed `u32` is the alternative; we already
// have `as_u32()` for the one place that needs it.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunnelStatus {
    /// `node.h:34`. Bit 1. SPTPS handshake completed; `n->sptps`
    /// has session keys. Set by the SPTPS `receive_record` cb
    /// when `SPTPS_HANDSHAKE` arrives (NOT directly in
    /// `ans_key_h` — `protocol_key.c:568` only READS it: `if
    /// (from->status.validkey)`). `send_sptps_packet` gates on
    /// it (`net_packet.c:685` `if(!n->status.validkey)`).
    pub validkey: bool,

    /// `node.h:35`. Bit 2. `REQ_KEY` sent, `ANS_KEY` not yet
    /// received. Set in `send_req_key:128`; cleared by the
    /// handshake-complete cb. Prevents `REQ_KEY` storms (the
    /// gate is `last_req_key`, but this bit is what `dump nodes`
    /// shows).
    pub waitingforkey: bool,

    /// `node.h:40`. Bit 6. This node speaks SPTPS. Set from
    /// `n->options & OPTION_VERSION` at edge-add time (the
    /// `extract_version(edge->options) >= 2` check). For chunk 7:
    /// ALWAYS true (no legacy support). Kept for `dump nodes`
    /// parity.
    pub sptps: bool,

    /// `node.h:41`. Bit 7. We've received a valid UDP packet
    /// FROM this node. Set in `udp_probe_h` reply path
    /// (`net_packet.c:164` — actually a temp set; the real set
    /// is in the probe-reply handling). Gates: switch from
    /// TCP-tunneled SPTPS to UDP-direct.
    pub udp_confirmed: bool,

    /// `node.h:43`. Bit 9. Most-recently-received packet was
    /// UDP (vs TCP-tunneled). Ephemeral — flips per packet.
    /// `route.c` reads it for the "send reply same way" logic.
    pub udppacket: bool,
}

impl TunnelStatus {
    /// Reconstruct the C `node_status_t.value` for `dump_nodes`.
    ///
    /// `node.h:31-48` field order under GCC-LSB-first packing:
    ///
    /// | bit | field            | source        |
    /// |-----|------------------|---------------|
    /// | 0   | `unused_active`  | always 0      |
    /// | 1   | `validkey`       | self          |
    /// | 2   | `waitingforkey`  | self          |
    /// | 3   | `visited`        | always 0 †    |
    /// | 4   | `reachable`      | param         |
    /// | 5   | `indirect`       | always 0 ‡    |
    /// | 6   | `sptps`          | self          |
    /// | 7   | `udp_confirmed`  | self          |
    /// | 8   | `send_locally`   | always 0      |
    /// | 9   | `udppacket`      | self          |
    /// | 10  | `validkey_in`    | always 0 §    |
    /// | 11  | `has_address`    | always 0 §    |
    /// | 12  | `ping_sent`      | always 0 §    |
    ///
    /// † `visited` is graph-algorithm scratch; cleared between
    /// SSSP runs. `dump_nodes` between runs sees 0.
    ///
    /// ‡ `indirect` is set by SSSP (`graph.c:195`); chunk 5's
    /// graph doesn't track it yet. Harmless: `dump nodes` is
    /// human-readable diagnostics.
    ///
    /// § Chunk-9+ fields. Zero until then.
    ///
    /// `reachable` is a parameter because it's owned by chunk-5's
    /// graph (`NodeState`-adjacent), not by `TunnelStatus`.
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
        if self.udppacket {
            v |= 1 << 9;
        }
        v
    }
}

/// `protocol_key.c:124` `"tinc UDP key expansion %s %s"`.
///
/// The SPTPS HKDF label for the per-tunnel handshake. Initiator
/// name first, responder name second — `send_req_key` (initiator
/// side, `:124`) uses `myself->name, to->name`; `req_key_ext_h`
/// REQ_SPTPS_START (responder side, `:259`) uses `from->name,
/// myself->name`. Same label both ends.
///
/// DIFFERENT from the meta-connection label `"tinc TCP key
/// expansion %s %s"` (`protocol_auth.c:462`). The two SPTPS
/// instances (meta vs tunnel) MUST NOT share keys.
///
/// `tinc-sptps::Sptps::start` takes `impl Into<Vec<u8>>`; no
/// newtype wrapper needed.
#[must_use]
pub fn make_udp_label(initiator: &str, responder: &str) -> Vec<u8> {
    // C: `snprintf(label, labellen, "tinc UDP key expansion %s
    // %s", ...)`. `labellen = 25 + strlen(a) + strlen(b)`. The
    // `25` is `strlen("tinc UDP key expansion  ") + 1` for the
    // NUL — but `snprintf` doesn't write past `labellen-1`, so
    // the label passed to `sptps_start` is the bytes WITHOUT the
    // trailing NUL. We match: no NUL.
    format!("tinc UDP key expansion {initiator} {responder}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mtu_is_net_h_macro() {
        // `net.h:36` `#define MTU 1518`. Non-jumbogram build.
        assert_eq!(MTU, 1518);
        let t = TunnelState::default();
        assert_eq!(t.mtu, 1518);
        assert_eq!(t.maxmtu, 1518);
        assert_eq!(t.minmtu, 0);
        assert_eq!(t.mtuprobes, 0);
    }

    #[test]
    fn reset_unreachable_clears_everything() {
        let mut t = TunnelState {
            // Can't construct an `Sptps` without keys/rng; test
            // the `Option` machinery, which is what `reset` does.
            sptps: None,
            udp_addr: Some("10.0.0.1:655".parse().unwrap()),
            status: TunnelStatus {
                validkey: true,
                waitingforkey: true,
                sptps: true,
                udp_confirmed: true,
                udppacket: true,
            },
            last_req_key: Some(Instant::now()),
            mtu: 1400,
            minmtu: 1200,
            maxmtu: 1450,
            mtuprobes: 7,
            in_packets: 100,
            in_bytes: 50000,
            out_packets: 80,
            out_bytes: 40000,
        };

        t.reset_unreachable();

        // `graph.c:259` `sptps_stop`.
        assert!(t.sptps.is_none());
        // `graph.c:263` `n->last_req_key = 0`.
        assert!(t.last_req_key.is_none());
        // `graph.c:266-269` mtu probe state. Note `mtu` itself
        // is NOT reset — the learned PMTU survives.
        assert_eq!(t.mtu, 1400, "mtu survives unreachable");
        assert_eq!(t.maxmtu, MTU);
        assert_eq!(t.minmtu, 0);
        assert_eq!(t.mtuprobes, 0);
        // `graph.c:296` `update_node_udp(n, NULL)`.
        assert!(t.udp_addr.is_none());
        // `graph.c:297` `memset(&n->status, 0, ...)`.
        assert_eq!(t.status, TunnelStatus::default());
        // Traffic counters NOT reset (lifetime totals).
        assert_eq!(t.in_packets, 100);
        assert_eq!(t.in_bytes, 50000);
        assert_eq!(t.out_packets, 80);
        assert_eq!(t.out_bytes, 40000);
    }

    #[test]
    fn make_udp_label_format() {
        // `protocol_key.c:124`. No trailing NUL (`snprintf`
        // writes one but `labellen` excludes it from the
        // `sptps_start` view).
        assert_eq!(
            make_udp_label("alice", "bob"),
            b"tinc UDP key expansion alice bob"
        );
        // `protocol_key.c:259` responder side: `from->name,
        // myself->name` — same format string, args swapped at
        // call site. The function doesn't swap; caller does.
        assert_eq!(
            make_udp_label("bob", "alice"),
            b"tinc UDP key expansion bob alice"
        );
    }

    #[test]
    fn make_udp_label_differs_from_tcp() {
        // `protocol_auth.c:462` vs `protocol_key.c:124`. The
        // two SPTPS instances MUST NOT derive the same keys.
        let udp = make_udp_label("a", "b");
        let tcp = b"tinc TCP key expansion a b";
        assert_ne!(udp.as_slice(), tcp.as_slice());
    }

    #[test]
    fn tunnel_status_bitfield_packing() {
        // `node.h:31-48` under GCC-LSB-first. Declaration order
        // = bit order. Computed by hand:
        //
        //   bit 0: unused_active
        //   bit 1: validkey
        //   bit 2: waitingforkey
        //   bit 3: visited
        //   bit 4: reachable
        //   bit 5: indirect
        //   bit 6: sptps
        //   bit 7: udp_confirmed
        //   bit 8: send_locally
        //   bit 9: udppacket

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

        // All set. 0b10_1101_0110 = 0x2d6 = 726.
        let all = TunnelStatus {
            validkey: true,
            waitingforkey: true,
            sptps: true,
            udp_confirmed: true,
            udppacket: true,
        };
        assert_eq!(
            all.as_u32(true),
            (1 << 1) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 9)
        );
        assert_eq!(all.as_u32(true), 0x2d6);

        // The realistic post-handshake steady state: reachable,
        // sptps, validkey, udp_confirmed. 0b1101_0010 = 0xd2.
        let steady = TunnelStatus {
            validkey: true,
            waitingforkey: false,
            sptps: true,
            udp_confirmed: true,
            udppacket: false,
        };
        assert_eq!(steady.as_u32(true), 0xd2);
    }
}
