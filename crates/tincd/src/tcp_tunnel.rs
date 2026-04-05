//! Binary `SPTPS_PACKET` TCP-tunnel frame.
//!
//! ## Why this exists
//!
//! When PMTU is unconverged or `TCPOnly = yes`, packets go over the
//! meta-conn TCP, not UDP. Two paths:
//!
//! - b64 via `REQ_KEY`: `"15 from to 21 <b64>\n"`. Works always;
//!   ALREADY WIRED (`daemon/gossip.rs:312`). Slow: b64 inflate × meta-conn-SPTPS encrypt × per-tunnel-SPTPS
//!   encrypt. The 12.9 Mbps from `2b5dda45`'s commit body.
//!
//! - binary (`:975-986`): `"21 LEN\n"` then `LEN` raw bytes via
//!   `c->sptpslen`. proto-minor ≥ 7 only (so the receiver knows to
//!   read raw blobs). WHAT THIS MODULE BUILDS/PARSES.
//!
//! Frame layout (BOTH paths' inner blob, identical to the UDP wire
//! frame at `daemon/net.rs:1246`):
//!
//! ```text
//!   dst_id : NodeId6 [6 bytes]
//!   src_id : NodeId6 [6 bytes]
//!   ct     : SPTPS ciphertext (per-tunnel session)
//! ```
//!
//! `dst` first because the relay only needs the first 6 bytes to
//! route (`receive_tcppacket_sptps:624`).
//!
//! ## What's NOT here
//!
//! - `c->sptpslen` field: `conn.rs`, daemon serial.
//! - `Request::SptpsPacket` dispatch arm: `metaconn.rs`, daemon
//!   serial. CURRENTLY TERMINATES ON IT (`metaconn.rs:892`).
//! - The `(options >> 24) >= 7` gate: send-side daemon.
//! - `send_udp_info` / `send_mtu_info` side-effects: the route
//!   decision RETURNS them as flags; daemon acts.

#![forbid(unsafe_code)]

use rand_core::RngCore;

use crate::node_id::NodeId6;

// ─── frame build/parse ───────────────────────────────────────────────

/// `dst_id ‖ src_id` header length. `if(len <
/// sizeof(node_id_t) * 2)`.
pub const HDR_LEN: usize = 12;

/// `dst[6] ‖ src[6] ‖ sptps_ct`.
///
/// IDENTICAL to the UDP wire frame at `daemon/net.rs:1246-1254`. The
/// transport differs; bytes don't.
///
/// Allocates. `STUB(chunk-11-perf)` if this becomes hot (it's
/// TCP-fallback — already slow).
#[must_use]
pub fn build_frame(dst: NodeId6, src: NodeId6, ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR_LEN + ct.len());
    out.extend_from_slice(dst.as_bytes());
    out.extend_from_slice(src.as_bytes());
    out.extend_from_slice(ct);
    out
}

/// `:616-634`. Parse `dst_id`, `src_id`, return tail.
///
/// `None` on `len < 12` (the C: `return false`, hard error — unlike
/// the unknown-ID cases below which `return true` to keep the conn
/// alive).
#[must_use]
pub fn parse_frame(blob: &[u8]) -> Option<(NodeId6, NodeId6, &[u8])> {
    let (hdr, ct) = blob.split_first_chunk::<HDR_LEN>()?;
    let (dst, src) = hdr.split_at(6);
    Some((
        NodeId6::from_bytes(dst.try_into().ok()?),
        NodeId6::from_bytes(src.try_into().ok()?),
        ct,
    ))
}

// ─── random early drop ───────────────────────────────────────────────

/// Congestion gate for the TCP fallback. Higher outbuf fill →
/// linearly higher drop probability above the half-max threshold.
///
/// `if(outbuf.len > max/2) if((outbuf.len - max/2) > prng(max/2))
/// return true`.
///
/// Returns `true` = DROP this packet. Don't send.
///
/// We use `next_u32() % half` (modulo bias is negligible at these
/// sizes; matches `autoconnect.rs`
/// idiom). Doesn't matter — this is congestion heuristics, not
/// crypto.
#[must_use]
pub fn random_early_drop<R: RngCore>(outbuf_len: usize, max: usize, rng: &mut R) -> bool {
    // Degenerate config: max == 0 or max == 1 → half == 0. C would
    // call prng(0); our `% 0` would panic. Never drop instead — a
    // zero/tiny outbuf cap means "don't bother gating".
    let half = max / 2;
    if half == 0 {
        return false;
    }
    if outbuf_len <= half {
        return false;
    }
    // `as` cast is fine: outbuf max is a config int (kB-range), and
    // even a pathological multi-GB outbuf overflowing u32 just
    // saturates the drop probability — which is what you'd want.
    #[allow(clippy::cast_possible_truncation)]
    let excess = (outbuf_len - half) as u32;
    #[allow(clippy::cast_possible_truncation)]
    let r = rng.next_u32() % (half as u32);
    excess > r
}

// ─── route decision ──────────────────────────────────────────────────

/// `receive_tcppacket_sptps` decision tree. The daemon supplies a
/// context view; we return what to do.
///
/// **Design**: `&dyn Fn` chosen over a plain-data struct
/// (`HashMap<NodeId6, &str>` + bool maps). The dyn-fn version maps
/// 1:1 onto the original call sites (`lookup_node_id`,
/// `n->status.X`). This is the fallback path — not hot — so the
/// indirect call cost is irrelevant. Tests build closures over
/// `HashMap`s.
#[derive(Clone, Copy)]
pub struct RouteCtx<'a> {
    /// `lookup_node_id` (`:623`, `:632`). `None` = unknown.
    pub lookup: &'a dyn Fn(NodeId6) -> Option<&'a str>,
    /// `n->status.reachable` (`:640`).
    pub reachable: &'a dyn Fn(&str) -> bool,
    /// `to->via == myself` (`:649`). The static-relay check; gates
    /// `send_udp_info`.
    pub via_is_self: &'a dyn Fn(&str) -> bool,
    /// `to == myself` (`:654`).
    pub is_self: &'a dyn Fn(&str) -> bool,
    /// `to->status.validkey` (`:656`). Gates relay
    /// `send_sptps_data`.
    pub validkey: &'a dyn Fn(&str) -> bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpRouteDecision<'a> {
    /// `:617` `return false`. Hard error; daemon terminates the
    /// connection.
    TooShort,
    /// `:627` `return true`. Log + keep conn.
    UnknownDest(NodeId6),
    /// `:637` `return true`. Same.
    UnknownSrc { dest: &'a str, src: NodeId6 },
    /// `:644` `return true`. Race vs `DEL_EDGE`.
    Unreachable { from: &'a str, to: &'a str },
    /// `:655-659`. `to != myself`. Daemon: if `validkey`
    /// `send_sptps_data(to, from, 0, data)`; always `try_tx(to,
    /// true)`.
    Relay {
        from: &'a str,
        to: &'a str,
        data: &'a [u8],
        validkey: bool,
        /// `:649-651`. Side-effect: `send_udp_info(myself, from)`
        /// BEFORE relay. Only when `to->via == myself`.
        send_udp_info: bool,
    },
    /// `:664-680`. `to == myself`. Daemon feeds `data` to `from`'s
    /// tunnel SPTPS. On decrypt fail + 10s since `last_req_key`:
    /// `send_req_key(from)`. Always `send_mtu_info` after.
    DeliverLocal {
        from: &'a str,
        data: &'a [u8],
        /// Same `via_is_self` gate (`:649`). When `to == myself`,
        /// `to->via == myself` is trivially true in C (`myself->via
        /// = myself` invariant from `graph.c`), but we pass it
        /// through honestly rather than hardcode.
        send_udp_info: bool,
    },
}

#[must_use]
pub fn route<'a>(blob: &'a [u8], ctx: &RouteCtx<'a>) -> TcpRouteDecision<'a> {
    // :617 — len check
    let Some((dst_id, src_id, data)) = parse_frame(blob) else {
        return TcpRouteDecision::TooShort;
    };

    // :622-628 — to = lookup_node_id(data); if !to return true
    let Some(to) = (ctx.lookup)(dst_id) else {
        return TcpRouteDecision::UnknownDest(dst_id);
    };

    // :631-637 — from = lookup_node_id(data); if !from return true
    let Some(from) = (ctx.lookup)(src_id) else {
        return TcpRouteDecision::UnknownSrc {
            dest: to,
            src: src_id,
        };
    };

    // :640-645 — if !to->status.reachable return true
    if !(ctx.reachable)(to) {
        return TcpRouteDecision::Unreachable { from, to };
    }

    // :649-651 — if to->via == myself send_udp_info(myself, from)
    // Captured as a flag; daemon acts before relay/deliver.
    let send_udp_info = (ctx.via_is_self)(to);

    // :654-659 — if to != myself: relay
    if !(ctx.is_self)(to) {
        return TcpRouteDecision::Relay {
            from,
            to,
            data,
            validkey: (ctx.validkey)(to),
            send_udp_info,
        };
    }

    // :664-680 — to == myself: deliver locally
    TcpRouteDecision::DeliverLocal {
        from,
        data,
        send_udp_info,
    }
}

// ─── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    use super::*;

    // ── frame ────────────────────────────────────────────────────────

    #[test]
    fn build_roundtrip() {
        let dst = NodeId6::from_bytes([1, 2, 3, 4, 5, 6]);
        let src = NodeId6::from_bytes([7, 8, 9, 10, 11, 12]);
        let ct = b"hello sptps ciphertext";
        let frame = build_frame(dst, src, ct);
        assert_eq!(frame.len(), HDR_LEN + ct.len());
        let (d, s, t) = parse_frame(&frame).unwrap();
        assert_eq!(d, dst);
        assert_eq!(s, src);
        assert_eq!(t, ct);
    }

    #[test]
    fn parse_short() {
        assert!(parse_frame(&[0u8; 11]).is_none());
        assert!(parse_frame(&[]).is_none());
    }

    #[test]
    fn parse_exactly_12() {
        let frame = [0u8; 12];
        let (d, s, t) = parse_frame(&frame).unwrap();
        assert_eq!(d, NodeId6::NULL);
        assert_eq!(s, NodeId6::NULL);
        assert_eq!(t, &[] as &[u8]);
    }

    /// KAT pinning wire byte order. `from_name` is SHA-512[..6],
    /// deterministic — vectors lifted from `node_id.rs::from_name_kat`
    /// (alice = `408b27d3097e`, bob = `0416a26ba554`). This guards
    /// against any struct-endianness or field-order regression: the
    /// frame is `dst ‖ src ‖ ct`, same as the UDP wire frame at
    /// `daemon/net.rs:1246`.
    #[test]
    fn kat_wire_bytes() {
        let dst = NodeId6::from_name("alice");
        let src = NodeId6::from_name("bob");
        let ct = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        let frame = build_frame(dst, src, &ct);
        #[rustfmt::skip]
        let expect: [u8; 20] = [
            // dst: alice = 408b27d3097e
            0x40, 0x8b, 0x27, 0xd3, 0x09, 0x7e,
            // src: bob = 0416a26ba554
            0x04, 0x16, 0xa2, 0x6b, 0xa5, 0x54,
            // ct
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        ];
        assert_eq!(frame, expect);
    }

    // ── RED ──────────────────────────────────────────────────────────

    #[test]
    fn red_below_half_never_drops() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..100 {
            assert!(!random_early_drop(100, 1000, &mut rng));
        }
        // Exactly at half: `<=` → still no drop.
        assert!(!random_early_drop(500, 1000, &mut rng));
    }

    #[test]
    fn red_at_max_mostly_drops() {
        // outbuf=999, max=1000 → half=500, excess=499.
        // Drop iff 499 > rng%500 → drop unless rng%500 == 499.
        // Probability ≈ 499/500 = 99.8%.
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let drops: u32 = (0..100)
            .map(|_| u32::from(random_early_drop(999, 1000, &mut rng)))
            .sum();
        // Loose bound: ≥ 90 of 100. Seeded so deterministic anyway.
        assert!(drops >= 90, "drops = {drops}");
    }

    #[test]
    fn red_max_zero_never_drops() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        // max=0 → half=0: don't panic on `% 0`.
        assert!(!random_early_drop(0, 0, &mut rng));
        assert!(!random_early_drop(100, 0, &mut rng));
        // max=1 → half=0: same.
        assert!(!random_early_drop(100, 1, &mut rng));
    }

    // ── route ────────────────────────────────────────────────────────

    /// Test fixture: closures over `HashMaps`. The `RouteCtx` borrows
    /// these, so they must outlive the ctx — hence build inline in
    /// each test rather than via a helper returning `RouteCtx`.
    struct Fixture {
        names: HashMap<NodeId6, &'static str>,
        reachable: HashMap<&'static str, bool>,
        via_self: HashMap<&'static str, bool>,
        is_self: HashMap<&'static str, bool>,
        validkey: HashMap<&'static str, bool>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                names: HashMap::new(),
                reachable: HashMap::new(),
                via_self: HashMap::new(),
                is_self: HashMap::new(),
                validkey: HashMap::new(),
            }
        }
    }

    macro_rules! ctx {
        ($f:expr_2021) => {{
            let lookup = |id: NodeId6| $f.names.get(&id).copied();
            let reachable = |n: &str| *$f.reachable.get(n).unwrap_or(&false);
            let via_is_self = |n: &str| *$f.via_self.get(n).unwrap_or(&false);
            let is_self = |n: &str| *$f.is_self.get(n).unwrap_or(&false);
            let validkey = |n: &str| *$f.validkey.get(n).unwrap_or(&false);
            (lookup, reachable, via_is_self, is_self, validkey)
        }};
    }

    macro_rules! mkctx {
        ($lk:ident, $rch:ident, $via:ident, $slf:ident, $vk:ident) => {
            RouteCtx {
                lookup: &$lk,
                reachable: &$rch,
                via_is_self: &$via,
                is_self: &$slf,
                validkey: &$vk,
            }
        };
    }

    fn id(b: u8) -> NodeId6 {
        NodeId6::from_bytes([b, 0, 0, 0, 0, 0])
    }

    #[test]
    fn route_too_short() {
        let fix = Fixture::new();
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        assert_eq!(route(&[0u8; 11], &ctx), TcpRouteDecision::TooShort);
    }

    #[test]
    fn route_unknown_dest() {
        let fix = Fixture::new();
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"ct");
        assert_eq!(route(&frame, &ctx), TcpRouteDecision::UnknownDest(id(1)));
    }

    #[test]
    fn route_unknown_src() {
        let mut fix = Fixture::new();
        fix.names.insert(id(1), "alice");
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"ct");
        assert_eq!(
            route(&frame, &ctx),
            TcpRouteDecision::UnknownSrc {
                dest: "alice",
                src: id(2)
            }
        );
    }

    #[test]
    fn route_unreachable() {
        let mut fix = Fixture::new();
        fix.names.insert(id(1), "alice");
        fix.names.insert(id(2), "bob");
        fix.reachable.insert("alice", false);
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"ct");
        assert_eq!(
            route(&frame, &ctx),
            TcpRouteDecision::Unreachable {
                from: "bob",
                to: "alice"
            }
        );
    }

    #[test]
    fn route_relay_validkey() {
        let mut fix = Fixture::new();
        fix.names.insert(id(1), "alice");
        fix.names.insert(id(2), "bob");
        fix.reachable.insert("alice", true);
        fix.via_self.insert("alice", true);
        fix.is_self.insert("alice", false);
        fix.validkey.insert("alice", true);
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"payload");
        assert_eq!(
            route(&frame, &ctx),
            TcpRouteDecision::Relay {
                from: "bob",
                to: "alice",
                data: b"payload",
                validkey: true,
                send_udp_info: true,
            }
        );
    }

    #[test]
    fn route_relay_no_validkey() {
        let mut fix = Fixture::new();
        fix.names.insert(id(1), "alice");
        fix.names.insert(id(2), "bob");
        fix.reachable.insert("alice", true);
        fix.via_self.insert("alice", true);
        fix.is_self.insert("alice", false);
        fix.validkey.insert("alice", false);
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"x");
        // validkey=false → daemon skips send_sptps_data, still try_tx.
        assert_eq!(
            route(&frame, &ctx),
            TcpRouteDecision::Relay {
                from: "bob",
                to: "alice",
                data: b"x",
                validkey: false,
                send_udp_info: true,
            }
        );
    }

    #[test]
    fn route_relay_no_udp_info() {
        // `:648` "every hop would initiate its own UDP info message,
        // resulting in elevated chatter" — only the dest/static-relay
        // sends udp_info.
        let mut fix = Fixture::new();
        fix.names.insert(id(1), "alice");
        fix.names.insert(id(2), "bob");
        fix.reachable.insert("alice", true);
        fix.via_self.insert("alice", false); // we're a transit hop
        fix.is_self.insert("alice", false);
        fix.validkey.insert("alice", true);
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"x");
        match route(&frame, &ctx) {
            TcpRouteDecision::Relay {
                send_udp_info: false,
                ..
            } => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn route_deliver_local() {
        let mut fix = Fixture::new();
        fix.names.insert(id(1), "self");
        fix.names.insert(id(2), "bob");
        fix.reachable.insert("self", true);
        fix.via_self.insert("self", true);
        fix.is_self.insert("self", true);
        let (lk, rch, via, slf, vk) = ctx!(fix);
        let ctx = mkctx!(lk, rch, via, slf, vk);
        let frame = build_frame(id(1), id(2), b"sptps-ct");
        assert_eq!(
            route(&frame, &ctx),
            TcpRouteDecision::DeliverLocal {
                from: "bob",
                data: b"sptps-ct",
                send_udp_info: true,
            }
        );
    }
}
