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
//! - Route decision (`receive_tcppacket_sptps`): open-coded in
//!   `daemon/metaconn.rs`.

#![forbid(unsafe_code)]

use rand_core::RngCore;

use crate::node_id::NodeId6;

// ─── frame build/parse ───────────────────────────────────────────────

/// `dst_id ‖ src_id` header length. `if(len <
/// sizeof(node_id_t) * 2)`.
pub(crate) const HDR_LEN: usize = 12;

/// `dst[6] ‖ src[6] ‖ sptps_ct`.
///
/// IDENTICAL to the UDP wire frame at `daemon/net.rs:1246-1254`. The
/// transport differs; bytes don't.
///
/// Allocates. `STUB(chunk-11-perf)` if this becomes hot (it's
/// TCP-fallback — already slow).
#[must_use]
pub(crate) fn build_frame(dst: NodeId6, src: NodeId6, ct: &[u8]) -> Vec<u8> {
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
pub(crate) fn parse_frame(blob: &[u8]) -> Option<(NodeId6, NodeId6, &[u8])> {
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
pub(crate) fn random_early_drop<R: RngCore>(outbuf_len: usize, max: usize, rng: &mut R) -> bool {
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
    #[allow(clippy::cast_possible_truncation)] // see comment above: kB-range, overflow saturates
    let excess = (outbuf_len - half) as u32;
    #[allow(clippy::cast_possible_truncation)] // half ≤ max/2, config-int kB-range
    let r = rng.next_u32() % (half as u32);
    excess > r
}

// ─── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
}
