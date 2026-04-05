//! RX fast-path: probe + open.
//!
//! Mirror of [`tx_probe`](super::tx_probe) / [`seal_super`](super::seal_super)
//! for the receive side. `rx_probe` walks the same gate chain
//! `handle_incoming_vpn_packet` would, returning `Some` only if THIS
//! packet can take the direct-decrypt-write-TUN path with no per-
//! packet `&mut Daemon` reborrow. `rx_open` then decrypts +
//! ethertype-synth + dst-subnet check, all with `&TxSnapshot`.
//!
//! Unlike TX (one probe per super), RX probes per packet: a recvmmsg
//! batch is N independent UDP datagrams from possibly-different
//! peers. The amortization comes from [`RxDstMemo`]: a TCP flow
//! produces 64 packets with the SAME inner dst-ip; one trie probe,
//! 63 `[u8; 4]` compares.
//!
//! ## Side effects the slow path does that we PUNT
//!
//! - `tunnel.in_packets`/`in_bytes` (sptps.rs:483) — `dump nodes`
//!   stats. Fast-path packets show as 0. The wire is correct;
//!   the operator just doesn't see RX traffic in stats. Atomic
//!   mirror later if anyone notices.
//! - `pmtu.maxrecentlen` (sptps.rs:476) — biggest packet seen.
//!   `PKT_PROBE` goes slow-path and updates it; the heuristic only
//!   accelerates PMTU convergence, doesn't gate it. Probes still
//!   converge via the slow path.
//! - `myself.out_packets`/`out_bytes` (device.rs:417) — same.
//! - `udp_addr` cache populate (rx.rs:325) — gate at probe-time:
//!   `handles.udp_addr.is_some()`. The FIRST valid packet from a
//!   peer goes slow-path, slow-path caches, every subsequent packet
//!   goes fast.
//! - `overwrite_mac` stamp (device.rs:410) — Router+TAP only;
//!   `slowpath_all` already gates `!= Router`, and TAP is irrelevant
//!   to TUN (kernel doesn't read the eth header on a TUN write).

use super::{TunnelHandles, TxSnapshot};
use crate::node_id::NodeId6;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tinc_crypto::chapoly::ChaPoly;
use tinc_graph::NodeId;

/// `PKT_NORMAL`. Re-stated (not re-exported from `daemon.rs`) so
/// `shard` doesn't reach into `daemon` private constants. The byte
/// is fixed by the wire protocol — `connection.h`, won't change.
const PKT_NORMAL: u8 = 0;

/// `REC_HANDSHAKE`. Mirror of `tinc_sptps::REC_HANDSHAKE`. Gate:
/// `ty >= REC_HANDSHAKE` ⇒ KEX-renegotiate ⇒ slow path. Re-stated
/// so the RX hot path doesn't pull in the full sptps module.
const REC_HANDSHAKE: u8 = 128;

/// Ethernet header length. The synthetic header `rx_open` builds.
const ETH_HLEN: usize = 14;

/// Minimum SPTPS datagram payload: 4 (seqno) + 1 (type) + 16 (tag).
/// Shorter ⇒ can't possibly decrypt; bail before `ChaPoly::new`.
/// Same gate as `Sptps::open_with_seqno` (state.rs:838).
const SPTPS_DGRAM_MIN: usize = 21;

/// IPv4 header length (no options). dst-ip lives at +16.
const IP4_HLEN: usize = 20;
/// IPv4 dst offset within the IP header.
const IP4_DST: usize = 16;

/// IPv6 header length. dst-ip lives at +24.
const IP6_HLEN: usize = 40;
/// IPv6 dst offset within the IP header.
const IP6_DST: usize = 24;

/// Ethertype for IPv4. `route.rs` and `packet.rs` each have a private
/// copy; one more here keeps the dep graph flat.
const ETH_P_IP: u16 = 0x0800;
/// Ethertype for IPv6.
const ETH_P_IPV6: u16 = 0x86DD;

// ────────────────────────────────────────────────────────────────────
// RxTarget — probe result

/// One packet's fast-path target. Everything is a borrow into the
/// snapshot (lifetime `'a`) plus the `NodeId` copy. ~32 bytes; cheap
/// to construct and discard per packet.
///
/// `ct` is `pkt[12..]` — the SPTPS frame past the id6 prefix. Carried
/// as a slice so [`rx_open`] doesn't re-slice; the daemon's dispatch
/// loop already had `pkt` borrowed from `batch.bufs`, so this is the
/// same memory, no copy.
pub struct RxTarget<'a> {
    /// `id6.lookup(src_id6)`. For the replay lock + cipher key probe.
    /// Carried so the caller can do per-peer accounting later (or so
    /// a stuck-decrypt can `send_req_key` — but that's slow-path, so
    /// in practice this is just for the test asserts today).
    pub from_nid: NodeId,
    /// The peer's handles. `rx_open` reads `inkey` (decrypt) and
    /// `replay` (commit). Borrow not clone: probe is per-packet, an
    /// `Arc::clone` per packet is one atomic inc + one dec at MTU
    /// rate (~800k pkts/s); the borrow is free.
    pub handles: &'a Arc<TunnelHandles>,
    /// `pkt[12..]`. `[seqno:4][enc(type‖body)][tag:16]`.
    pub ct: &'a [u8],
}

// ────────────────────────────────────────────────────────────────────
// RxDstMemo — per-batch trie cache

/// Per-batch dst-subnet memo. `rx_open` decrypts then asks "does
/// `route(dst_ip)` resolve to myself?" — a trie probe. For a TCP
/// flow, 64 packets in one recvmmsg batch share the SAME inner dst.
/// Cache the answer keyed on the raw dst bytes; reset at batch
/// boundary (the GRO scope).
///
/// `bool` = "owner is myself". `false` covers BOTH "not myself"
/// (peer is forwarding through us — slow path does the relay) AND
/// "no covering subnet" (slow path sends ICMP unreachable). The
/// fast path doesn't distinguish; either way it's a punt.
///
/// Separate v4/v6 slots because a dual-stack flow could in
/// principle interleave (rare, but two slots is cheaper than an
/// enum match per packet). `None` ⇒ memo cold; do the trie probe.
///
/// `Default` for the per-batch reset — `RxDstMemo::default()` at
/// the top of the dispatch loop. Stack-allocated, ~50 bytes.
#[derive(Default)]
pub struct RxDstMemo {
    v4: Option<([u8; 4], bool)>,
    v6: Option<([u8; 16], bool)>,
}

impl RxDstMemo {
    /// One v4 dst probe. On memo hit: 4-byte compare, return cached.
    /// On miss: `subnets.lookup_ipv4` (the trie walk) + string
    /// compare against `myself_name`, cache, return.
    ///
    /// `lookup_ipv4` is the same fn `route_ipv4` calls (route.rs:113).
    /// We pass `|_| true` for `is_reachable` — myself is always
    /// reachable, and we only care about the myself case anyway.
    /// The subtlety: `lookup_ipv4` keeps walking on unreachable
    /// owners (the LPM "fallback" semantics), but with `|_| true`
    /// it always breaks on the first prefix match. That's correct
    /// for "is dst mine?": if the longest match is myself, that's
    /// the answer; if it's some unreachable peer, route would have
    /// returned Unreachable, which is not-myself, which is a punt.
    /// We collapse "first match owner == myself" to the answer.
    fn probe_v4(&mut self, dst: [u8; 4], snap: &TxSnapshot) -> bool {
        if let Some((k, v)) = self.v4
            && k == dst
        {
            return v;
        }
        let addr = Ipv4Addr::from(dst);
        // `Some((_, Some(owner)))` ⇒ subnet found, owned (not
        // broadcast). Broadcast (`owner=None`) is slow-path
        // (broadcast_packet has side effects). Unreachable owner
        // would still match `owner == myself_name` if we own a
        // subnet — and we're always reachable to ourselves.
        let mine = snap
            .subnets
            .lookup_ipv4(&addr, |_| true)
            .and_then(|(_, o)| o)
            .is_some_and(|o| o == &*snap.myself_name);
        self.v4 = Some((dst, mine));
        mine
    }

    /// v6 mirror. dst at IP+24, 16 bytes.
    fn probe_v6(&mut self, dst: [u8; 16], snap: &TxSnapshot) -> bool {
        if let Some((k, v)) = self.v6
            && k == dst
        {
            return v;
        }
        let addr = Ipv6Addr::from(dst);
        let mine = snap
            .subnets
            .lookup_ipv6(&addr, |_| true)
            .and_then(|(_, o)| o)
            .is_some_and(|o| o == &*snap.myself_name);
        self.v6 = Some((dst, mine));
        mine
    }
}

// ────────────────────────────────────────────────────────────────────
// rx_probe — gate chain (no decrypt)

/// Probe whether THIS packet can take the RX fast path. Runs the
/// same gate chain `handle_incoming_vpn_packet` would, returning
/// `Some(RxTarget)` only if the packet is direct-to-us from a peer
/// with a live tunnel and a cached UDP address. No side effects.
/// `None` ⇒ caller falls through to slow path.
///
/// Gates (any ⇒ `None`):
///   - `slowpath_all` (setup-time fold; covers `!Router` and DHT
///     discovery — the `dht_probe_sent` demux at rx.rs:237 only
///     matters when discovery is on, and `slowpath_all` folds
///     `dht_discovery` via setup.rs)
///   - `pkt.len() < 12 + 21` (id6 prefix + minimum SPTPS datagram)
///   - `dst_id6 != NULL` (relay branch — we don't decrypt for relay)
///   - `src_id6` not in `id6` table (unknown peer)
///   - no `TunnelHandles` (pre-handshake; slow path runs `send_req_key`)
///   - `udp_addr` not cached (FIRST valid packet from this peer;
///     slow path's rx.rs:325 caches it; next packet goes fast)
///
/// Gates DEFERRED to [`rx_open`] (post-decrypt):
///   - `ty != PKT_NORMAL` (probe/compressed/mac; encrypted)
///   - `route(dst_ip) != myself` (dst is encrypted)
///   - `body_len > MTU` (also post-decrypt, body length unknown here)
///
/// Non-gates (covered by `slowpath_all`'s `!= Router` fold):
///   - `overwrite_mac`: Router+TAP; TUN ignores eth header anyway
///   - `forwarding_mode == Kernel`: gated `from.is_some()`, that's
///     us, but only for FORWARDING; `to == myself` arm precedes it
///
/// `pkt` is the raw UDP payload: `[dst_id6:6][src_id6:6][SPTPS]`.
#[must_use]
pub fn rx_probe<'a>(snap: &'a TxSnapshot, pkt: &'a [u8]) -> Option<RxTarget<'a>> {
    // Setup-time fold. Same gate as tx_probe; same one-bool early-out.
    // Covers DHT discovery: setup.rs:846 only spawns when
    // `settings.dht_discovery` is true, and that's NOT folded here
    // YET — but the rx.rs gate is `dht_probe_sent.contains(&peer)`,
    // which is non-empty only when discovery is on. We could fold
    // `dht_discovery` into slowpath_all (it IS spawn-const), but
    // probes are sent to addrs LEARNED FROM the DHT, which by
    // construction aren't peer UDP addrs. The src_id6 lookup at the
    // bottom of this fn fails for non-peers anyway (DHT bootstrap
    // nodes have no entry). Belt: leave slowpath_all as-is; the
    // src_id6 gate covers it.
    if snap.slowpath_all {
        return None;
    }

    // Length: id6 prefix (12) + min SPTPS datagram (21). The slow
    // path checks `< 12` at rx.rs:249 and `< 21` at state.rs:838;
    // we fuse them. A 20-byte ct can't possibly decrypt — no point
    // building the target just to fail in rx_open.
    if pkt.len() < 12 + SPTPS_DGRAM_MIN {
        return None;
    }

    // dst==NULL ⇔ direct-to-us. `dst!=NULL` means relay: either
    // we're a hop (forward without decrypt, rx.rs:451) or it WAS
    // for us via relay (`handle_relay_receive` returns false for
    // `to==myself`, falls through with `direct=false`). Both have
    // side effects (`send_mtu_info`, the security gate scan) that
    // need `&mut Daemon`. Punt the whole `!is_null()` branch.
    //
    // The 6-byte all-zero check inlines to one u32 + one u16 compare.
    // Cheaper than `NodeId6::from_bytes` + `is_null()` (compiler
    // probably folds those anyway, but this is the hot path; be
    // explicit).
    if pkt[..6] != [0u8; 6] {
        return None;
    }

    // src_id6 → NodeId. Unknown ⇒ legacy packet or NodeId6 collision
    // (rx.rs:262 logs + drops). One IntHashMap probe — same as the
    // slow path's `id6_table.lookup`.
    let src_id = NodeId6::from_bytes(pkt[6..12].try_into().ok()?);
    let from_nid = snap.id6.lookup(src_id)?;

    // Tunnel handles. None ⇒ pre-handshake (rx.rs:278 runs
    // `send_req_key`). We CAN'T run that without `&mut Daemon`; punt.
    let handles = snap.tunnels.get(&from_nid)?;

    // udp_addr cached ⇔ first valid packet already went slow-path
    // and populated it (rx.rs:325). The fast path doesn't write
    // tunnel state; gate so we don't deadlock the cache.
    //
    // The lock is uncontended single-threaded. `is_none()` not
    // `is_some()` for the `?` ergonomics: `then_some(())` would
    // be uglier than the `if` here.
    if handles.udp_addr.lock().ok()?.is_none() {
        return None;
    }

    Some(RxTarget {
        from_nid,
        handles,
        ct: &pkt[12..],
    })
}

// ────────────────────────────────────────────────────────────────────
// rx_open — decrypt + post-gates + ethertype synth

/// Decrypt `target.ct` into `scratch`, run post-decrypt gates, synth
/// the ethernet header, strip the type byte. On `Ok(len)`:
/// `scratch[..len]` is `[synth_eth:14][IP body]`, ready for GRO offer
/// or `device.write`. On `Err(())`: scratch is dirtied but the replay
/// window is UNTOUCHED — caller falls through to slow path, which
/// re-decrypts (same ct, same key, same seqno) and handles it
/// correctly.
///
/// The wasted re-decrypt costs ~4µs. Gates that fail post-decrypt
/// are rare (`PKT_PROBE` is once/sec; dst-not-myself is per-flow,
/// memoized in `dst_memo`; tag mismatch is ~never for a healthy
/// tunnel). The trade is: one branch in `rx_open` vs. plumbing a
/// "decrypt OK but gate failed, here's the plaintext" return through
/// the slow path. The branch is cheaper.
///
/// ## Gate order (the hard rule from the brief)
///
/// 1. **`ChaPoly::open_into`** (decrypt; `&self`, no commit). Tag
///    fail ⇒ `Err(())`. `out` is unchanged on tag fail (chapoly.rs:254
///    extends only after the tag check passes), so a forged packet
///    doesn't dirty `scratch`.
/// 2. **Type gate** (`ty == PKT_NORMAL`). `PKT_PROBE`/`COMPRESSED`/
///    `MAC` ⇒ `Err(())`. Replay NOT advanced — slow path's
///    `open_data_into` re-decrypts, gets the same `ty`, dispatches
///    `udp_probe_h`/decompress correctly.
/// 3. **MTU gate** (`body_len > MTU`). Same rationale.
/// 4. **dst-subnet gate** (memo probe on plaintext dst-ip). Same.
/// 5. **THEN `replay.check_public`** — only commit after EVERY gate
///    passed. A replayed packet that would have failed a gate is
///    fine (it'll fail in the slow path too, double-drop, no harm),
///    but a fresh packet that fails a gate MUST stay un-committed
///    so the slow path can handle it.
/// 6. ethertype synth + type-byte strip (the memmove).
///
/// `scratch`: cleared and resized internally. Same `Vec` the slow
/// path uses (`dp.rx_scratch`); after the first MTU-sized packet
/// it's grown to ~1550 bytes and stays there. Zero allocs steady-state.
///
/// # Errors
/// `Err(())` on any gate fail. The unit error is intentional: every
/// failure mode has the same caller response (fall through to slow
/// path), and the slow path's own error handling produces the
/// log line. Adding an enum here would just be dead-code at the
/// call site.
#[allow(clippy::result_unit_err)] // see doc above; uniform fall-through
#[allow(clippy::missing_panics_doc)] // mutex poison: only on panic in slow-path open
pub fn rx_open(
    target: &RxTarget<'_>,
    snap: &TxSnapshot,
    scratch: &mut Vec<u8>,
    dst_memo: &mut RxDstMemo,
) -> Result<usize, ()> {
    let ct = target.ct;
    // Len gate already done in rx_probe (12 + 21). Re-state the
    // invariant for the slice math below.
    debug_assert!(ct.len() >= SPTPS_DGRAM_MIN);

    let seqno = u32::from_be_bytes([ct[0], ct[1], ct[2], ct[3]]);

    // ─── Step 1: decrypt. `ChaPoly::new` is `const fn` — just
    // `*key`, 64-byte copy. Cheaper than caching per batch (the
    // brief verified this; one keystream-block prep per packet
    // is in the noise next to the 1500-byte ChaCha XOR).
    //
    // `scratch` setup: clear, resize to ETH_HLEN headroom.
    // `open_into` debug-asserts `out.len() == decrypt_at` then
    // extends. On tag fail it returns BEFORE the extend
    // (chapoly.rs:254), so `scratch` stays at `[0; 14]` — the
    // slow path's `open_data_into` will re-clear it anyway.
    scratch.clear();
    scratch.resize(ETH_HLEN, 0);
    let cipher = ChaPoly::new(&target.handles.inkey);
    cipher
        .open_into(u64::from(seqno), &ct[4..], scratch, ETH_HLEN)
        .map_err(|_| ())?;
    // scratch = [0;14][type:1][body]

    let ty = scratch[ETH_HLEN];

    // ─── Step 2: type gate. PKT_NORMAL is 0; PKT_COMPRESSED bit 0,
    // PKT_MAC bit 1, PKT_PROBE bit 2. Any nonzero bit ⇒ slow path.
    // REC_HANDSHAKE (≥128) is the KEX-renegotiate marker — open_into
    // succeeded (tag passed) but the body is a handshake record;
    // slow path's `sptps.receive(ct)` handles the rekey. The
    // `open_data_into` slow path returns `BadRecord` for this and
    // falls through to receive(); we do the same by punting.
    // ty < REC_HANDSHAKE covers PROBE/COMPRESSED/MAC (bits 0-2);
    // ty >= REC_HANDSHAKE covers in-band rekey. Both punt. The
    // const exists so the next person to add a ty bit greps for it.
    let _ = REC_HANDSHAKE;
    if ty != PKT_NORMAL {
        return Err(());
    }

    // body_len: scratch is [0;14][ty:1][body] now.
    let body_len = scratch.len() - ETH_HLEN - 1;

    // ─── Step 3: MTU gate. sptps.rs:332 — body bigger than the
    // configured MTU is a peer misconfig; slow path logs + drops.
    // `MTU` is the daemon's `tunnel::MTU` (1518); we compare body
    // length against it same as `receive_sptps_record_fast` does.
    if body_len > usize::from(crate::tunnel::MTU) {
        return Err(());
    }

    // ─── Step 4: dst-subnet gate. Read the IP version nibble
    // (`body[0] >> 4`), parse dst, probe memo. Body lives at
    // `scratch[15..]` (ETH_HLEN + type byte). Empty body ⇒ can't
    // route ⇒ punt (sptps.rs:443 has the same check).
    //
    // The version-nibble dispatch mirrors sptps.rs:457: `4` ⇒ IPv4,
    // `6` ⇒ IPv6, anything else ⇒ "unknown IP version" log. We
    // punt instead of log; slow path logs.
    if body_len == 0 {
        return Err(());
    }
    let body_off = ETH_HLEN + 1;
    let (ethertype, mine) = match scratch[body_off] >> 4 {
        4 => {
            // dst at IP+16, need at least IP_HLEN bytes of header.
            // `route_ipv4` checks `len < ETHER+IP` (route.rs:98);
            // we're past the eth header so check IP only.
            if body_len < IP4_HLEN {
                return Err(());
            }
            let dst: [u8; 4] = scratch[body_off + IP4_DST..body_off + IP4_DST + 4]
                .try_into()
                .map_err(|_| ())?; // unreachable: len-checked above
            (ETH_P_IP, dst_memo.probe_v4(dst, snap))
        }
        6 => {
            if body_len < IP6_HLEN {
                return Err(());
            }
            let dst: [u8; 16] = scratch[body_off + IP6_DST..body_off + IP6_DST + 16]
                .try_into()
                .map_err(|_| ())?; // unreachable
            (ETH_P_IPV6, dst_memo.probe_v6(dst, snap))
        }
        _ => return Err(()), // unknown IP version; slow path logs
    };
    if !mine {
        // dst routes to some OTHER peer. We're being used as a
        // forwarder (`from.is_some()` arm of `dispatch_forward`).
        // That path has decrement_ttl/forwarding_mode/via= logic
        // (route.rs:395-526) — all `&mut Daemon`. Punt.
        return Err(());
    }

    // ─── Step 5: replay commit. THE COMMIT. Everything above was
    // `&self`; this mutates. After this, the slow path's
    // `open_data_into` would get `BadSeqno` for the same packet —
    // but we're past every gate, so we're not falling through.
    //
    // `Arc<Mutex<ReplayWindow>>` shared with the control-side
    // `Sptps`. Lock is uncontended single-threaded; `~50ns`.
    target
        .handles
        .replay
        .lock()
        .unwrap()
        .check_public(seqno)
        .map_err(|_| ())?;

    // ─── Step 6: ethertype synth + type-byte strip.
    // scratch is `[0;14][ty:1][body]`. We want `[0;12][et:2][body]`.
    // Stamp the ethertype at [12..14] (the headroom is already zero,
    // so the eth dst/src MACs are zero — TUN ignores them).
    scratch[12..14].copy_from_slice(&ethertype.to_be_bytes());
    // Strip the type byte: shift [15..] down to [14..]. Same
    // memmove `open_data_into` does (state.rs:791). body_len bytes
    // moved by 1; small, in-L1.
    scratch.copy_within(body_off.., ETH_HLEN);
    let frame_len = scratch.len() - 1;
    scratch.truncate(frame_len);

    Ok(frame_len)
}

// ════════════════════════════════════════════════════════════════════
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inthash::IntHashMap;
    use crate::node_id::NodeId6Table;
    use crate::shard::NodeView;
    use crate::subnet_tree::SubnetTree;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
    use tinc_sptps::ReplayWindow;

    /// Build a UDP wire packet: `[NULL:6][src_id6:6][seqno:4]
    /// [enc(ty‖body)][tag:16]`. `src_id6` derived from `src_name`;
    /// body is encrypted with `key`. Mirror of what
    /// `seal_data_into` → `send_sptps_data_relay` produces for a
    /// direct-send (dst=NULL).
    fn wire_packet(src_name: &str, seqno: u32, ty: u8, body: &[u8], key: &[u8; 64]) -> Vec<u8> {
        let cipher = ChaPoly::new(key);
        let src_id6 = NodeId6::from_name(src_name);
        let mut pkt = Vec::with_capacity(12 + 4 + 1 + body.len() + 16);
        pkt.extend_from_slice(&[0u8; 6]); // dst = NULL (direct)
        pkt.extend_from_slice(src_id6.as_bytes());
        pkt.extend_from_slice(&seqno.to_be_bytes());
        // seal_into: out.len() must == encrypt_from (16 here:
        // 12 prefix + 4 seqno).
        cipher.seal_into(u64::from(seqno), ty, body, &mut pkt, 16);
        pkt
    }

    /// IPv4 packet: [vhl:1][tos:1][totlen:2][id:2][frag:2][ttl:1]
    /// [proto:1][csum:2][src:4][dst:4][payload]. Minimal — only
    /// the version nibble and dst matter to `rx_open`.
    fn v4_body(dst: [u8; 4], payload_len: usize) -> Vec<u8> {
        let mut b = vec![0u8; IP4_HLEN + payload_len];
        b[0] = 0x45; // v4, ihl=5
        b[IP4_DST..IP4_DST + 4].copy_from_slice(&dst);
        b
    }

    /// alice (myself) ← bob fixture. alice owns 10.0.0.0/24; bob
    /// has `TunnelHandles` with `inkey` set to a known value, replay
    /// window fresh, `udp_addr` cached. id6 table has both names.
    ///
    /// Returns `(snap, bob_nid, inkey)`: `inkey` is what bob would
    /// have as his outbound key (the handshake derives them as a
    /// pair; here we just pick a constant).
    fn fixture() -> (TxSnapshot, NodeId, [u8; 64]) {
        let alice = NodeId(0);
        let bob = NodeId(1);
        // Non-zero key so a wrong-key encrypt actually fails the
        // tag (zero-key passes for zero-body edge cases).
        let inkey = [0x42u8; 64];

        // id6: both names. rx_probe looks up bob by his sha512[:6].
        let mut id6 = NodeId6Table::new();
        id6.add("alice", alice);
        id6.add("bob", bob);

        // subnets: alice owns 10.0.0.0/24. The dst-subnet gate
        // checks `lookup_ipv4(dst).owner == myself_name`.
        let mut st = SubnetTree::new();
        st.add("10.0.0.0/24".parse().unwrap(), "alice".into());
        // Also a subnet bob owns, for the negative dst test.
        st.add("10.1.0.0/24".parse().unwrap(), "bob".into());

        // bob's handles. inkey IS the test key; outkey doesn't
        // matter (RX doesn't seal). replay starts empty (seqno 0
        // is the first valid). udp_addr cached so probe passes.
        let handles = Arc::new(TunnelHandles {
            outseqno: Arc::new(AtomicU64::new(0)),
            replay: Arc::new(Mutex::new(ReplayWindow::default())),
            outkey: [0u8; 64],
            inkey,
            udp_addr: Mutex::new(Some((
                socket2::SockAddr::from("10.0.0.2:655".parse::<std::net::SocketAddr>().unwrap()),
                0,
            ))),
            validkey: AtomicBool::new(true),
            minmtu: AtomicU16::new(1400),
            outcompression: 0,
        });
        let mut tunnels = IntHashMap::default();
        tunnels.insert(bob, handles);

        // NodeView/routes/ns: empty/minimal. rx_probe doesn't read
        // them (no route() call — that's the dst-subnet gate's
        // job, and it goes through `subnets` directly). We still
        // need them for the struct to be valid.
        let snap = TxSnapshot {
            slowpath_all: false,
            myself: alice,
            myself_options: 0,
            id6_prefix: [0u8; 12],
            myself_name: "alice".into(),
            id6: Arc::new(id6),
            routes: Arc::new(vec![None, None]),
            subnets: Arc::new(st),
            ns: Arc::new(NodeView::default()),
            tunnels,
        };
        (snap, bob, inkey)
    }

    /// THE positive test (lesson from F8). Full roundtrip: encrypt
    /// a body via `ChaPoly::seal_into` (the seal-side primitive
    /// `seal_super` uses), build the wire packet, probe + open,
    /// assert the bytes match. Proves the gate chain doesn't
    /// reject a valid packet AND the byte layout (ethertype synth,
    /// type-byte strip) is correct.
    #[test]
    fn roundtrip_probe_open_ok() {
        let (snap, bob, inkey) = fixture();
        let body = v4_body([10, 0, 0, 5], 100); // 120 bytes, dst in alice's /24
        let pkt = wire_packet("bob", 0, PKT_NORMAL, &body, &inkey);

        let target = rx_probe(&snap, &pkt).expect("probe must pass");
        assert_eq!(target.from_nid, bob);
        assert_eq!(target.ct.len(), pkt.len() - 12);

        let mut scratch = Vec::new();
        let mut memo = RxDstMemo::default();
        let len = rx_open(&target, &snap, &mut scratch, &mut memo).expect("open must pass");

        // scratch[..len] = [eth:14][body]. eth[12..14] = ethertype.
        assert_eq!(len, ETH_HLEN + body.len());
        assert_eq!(scratch.len(), len);
        assert_eq!(&scratch[12..14], &ETH_P_IP.to_be_bytes());
        // Body byte-identical to what we sealed.
        assert_eq!(&scratch[ETH_HLEN..], &body[..]);

        // Memo cached the dst.
        assert_eq!(memo.v4, Some(([10, 0, 0, 5], true)));
        // (Replay-advance-on-success is structurally guaranteed by
        // step 5 being unconditional after step 4. NOT asserted here:
        // ReplayWindow has no public constructor with a real window
        // size; default() is zero-width. The *_no_replay_advance
        // tests below prove the converse via seqno reuse, which works
        // with any window.)
    }

    /// Tag mismatch ⇒ `rx_open` Err, replay window NOT advanced.
    /// (The hard rule: forged seqno + bad tag must not commit.)
    #[test]
    fn bad_tag_no_replay_advance() {
        let (snap, _bob, _inkey) = fixture();
        let body = v4_body([10, 0, 0, 5], 100);
        // Seal with WRONG key.
        let pkt = wire_packet("bob", 0, PKT_NORMAL, &body, &[0xFFu8; 64]);

        let target = rx_probe(&snap, &pkt).expect("probe doesn't decrypt");
        let mut scratch = Vec::new();
        let mut memo = RxDstMemo::default();
        assert!(rx_open(&target, &snap, &mut scratch, &mut memo).is_err());

        // Now seal with the RIGHT key, same seqno. Must succeed —
        // the bad-tag attempt didn't burn seqno 0.
        let inkey = snap.tunnels[&target.from_nid].inkey;
        let pkt2 = wire_packet("bob", 0, PKT_NORMAL, &body, &inkey);
        let target2 = rx_probe(&snap, &pkt2).unwrap();
        assert!(rx_open(&target2, &snap, &mut scratch, &mut memo).is_ok());
    }

    /// `PKT_PROBE` ⇒ Err, replay NOT advanced. Slow path must be
    /// able to re-decrypt and dispatch `udp_probe_h`.
    #[test]
    fn pkt_probe_punts_no_replay_advance() {
        let (snap, _bob, inkey) = fixture();
        let body = v4_body([10, 0, 0, 5], 100);
        let pkt = wire_packet(
            "bob", 5, /* PKT_PROBE = 4, also test bit 0 noise */ 4, &body, &inkey,
        );

        let target = rx_probe(&snap, &pkt).expect("probe passes — ty is encrypted");
        let mut scratch = Vec::new();
        let mut memo = RxDstMemo::default();
        assert!(rx_open(&target, &snap, &mut scratch, &mut memo).is_err());

        // seqno 5 NOT committed: a PKT_NORMAL at seqno 5 still works.
        let pkt2 = wire_packet("bob", 5, PKT_NORMAL, &body, &inkey);
        let target2 = rx_probe(&snap, &pkt2).unwrap();
        assert!(rx_open(&target2, &snap, &mut scratch, &mut memo).is_ok());
    }

    /// dst routes to bob (10.1.0.0/24), not alice ⇒ punt. Replay
    /// NOT advanced — slow path forwards.
    #[test]
    fn dst_not_myself_punts_no_replay_advance() {
        let (snap, _bob, inkey) = fixture();
        // dst in BOB's subnet.
        let body = v4_body([10, 1, 0, 5], 100);
        let pkt = wire_packet("bob", 0, PKT_NORMAL, &body, &inkey);

        let target = rx_probe(&snap, &pkt).unwrap();
        let mut scratch = Vec::new();
        let mut memo = RxDstMemo::default();
        assert!(rx_open(&target, &snap, &mut scratch, &mut memo).is_err());

        // Memo cached the negative.
        assert_eq!(memo.v4, Some(([10, 1, 0, 5], false)));

        // seqno 0 NOT committed.
        let body2 = v4_body([10, 0, 0, 5], 100);
        let pkt2 = wire_packet("bob", 0, PKT_NORMAL, &body2, &inkey);
        let target2 = rx_probe(&snap, &pkt2).unwrap();
        // Memo had a v4 entry but for a DIFFERENT dst; this is a
        // miss → trie probe → cache overwrite.
        assert!(rx_open(&target2, &snap, &mut scratch, &mut memo).is_ok());
        assert_eq!(memo.v4, Some(([10, 0, 0, 5], true)));
    }

    /// Too-short packet ⇒ probe None (before any expensive work).
    #[test]
    fn short_packet_is_none() {
        let (snap, _bob, _inkey) = fixture();
        // 12 + 20 = 32 bytes: id6 prefix + 1 byte short of min ct.
        let mut pkt = vec![0u8; 32];
        pkt[6..12].copy_from_slice(NodeId6::from_name("bob").as_bytes());
        assert!(rx_probe(&snap, &pkt).is_none());
        // 33 bytes: exactly min. Probe passes (tunnel exists,
        // udp_addr cached); rx_open fails on tag (garbage ct).
        pkt.push(0);
        assert!(rx_probe(&snap, &pkt).is_some());
    }
}
