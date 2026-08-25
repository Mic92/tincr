//! RX fast-path: probe + open.
//!
//! Mirror of [`tx_probe`](super::tx_probe) / [`seal_super`](super::seal_super)
//! for the receive side. `rx_probe` walks the same gate chain
//! `handle_incoming_vpn_packet` would, returning `Some` only if this
//! packet can take the direct-decrypt-write-TUN path with no per-
//! packet `&mut Daemon` reborrow. `rx_open` then decrypts +
//! ethertype-synth + dst-subnet check, all with `&TxSnapshot`.
//!
//! Unlike TX (one probe per super), RX probes per packet: a recvmmsg
//! batch is N independent UDP datagrams from possibly-different
//! peers. The amortization comes from [`RxDstMemo`]: a TCP flow
//! produces 64 packets with the same inner dst-ip; one trie probe,
//! 63 `[u8; 4]` compares.
//!
//! ## Side effects the slow path does that we PUNT
//!
//! - `pmtu.maxrecentlen` (sptps.rs:476) — biggest packet seen.
//!   `PKT_PROBE` goes slow-path and updates it; the heuristic only
//!   accelerates PMTU convergence, doesn't gate it. Probes still
//!   converge via the slow path.
//! - `myself.out_packets`/`out_bytes` on TUN-write — own-node stats
//!   aren't in `TunnelHandles`; the per-peer RX bump is.
//! - `udp_addr` cache populate (rx.rs:325) — gate at probe-time:
//!   `handles.udp_addr.is_some()`. The first valid packet from a
//!   peer goes slow-path, slow-path caches, every subsequent packet
//!   goes fast.
//! - `overwrite_mac` stamp (device.rs:410) — Router+TAP only;
//!   `slowpath_all` already gates `!= Router`, and TAP is irrelevant
//!   to TUN (kernel doesn't read the eth header on a TUN write).

use super::{TunnelHandles, TxSnapshot};
use crate::graph::NodeId;
use crate::node_id::NodeId6;
use crate::tunnel::MTU;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// `PKT_NORMAL`. Re-stated (not re-exported from `daemon.rs`) so
/// `shard` doesn't reach into `daemon` private constants. The byte
/// is fixed by the wire protocol.
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

/// One packet's fast-path target: borrows into the snapshot plus the `NodeId`.
/// `ct` is `pkt[12..]`, the SPTPS frame past the id6 prefix, carried so
/// [`rx_open`] doesn't re-slice; same memory as `batch.bufs`.
pub(crate) struct RxTarget<'a> {
    /// `id6.lookup(src_id6)`. For the replay lock + cipher key probe.
    /// Carried so the caller can do per-peer accounting later (or so
    /// a stuck-decrypt can `send_req_key` — but that's slow-path, so
    /// in practice this is just for the test asserts today).
    #[cfg_attr(not(test), expect(dead_code))]
    // cfg-dependent: tests assert routing; shard slow-path will read for `send_req_key`
    pub from_nid: NodeId,
    /// The peer's handles. `rx_open` reads `incipher` (decrypt) and
    /// `replay` (commit). Borrow not clone: probe is per-packet, an
    /// `Arc::clone` per packet is one atomic inc + one dec at MTU
    /// rate (~800k pkts/s); the borrow is free.
    pub handles: &'a Arc<TunnelHandles>,
    /// `pkt[12..]`. `[seqno:4][enc(type‖body)][tag:16]`.
    pub ct: &'a [u8],
}

/// Per-batch memo for "does `route(dst_ip)` resolve to myself?", keyed on the
/// raw dst bytes: a TCP flow's 64 packets per recvmmsg share one dst, so one
/// trie probe serves the batch. `false` covers both not-myself and
/// no-covering-subnet; either punts. Separate v4/v6 slots; `Default` resets it
/// at the top of each dispatch loop.
#[derive(Default)]
pub(crate) struct RxDstMemo {
    v4: Option<([u8; 4], bool)>,
    v6: Option<([u8; 16], bool)>,
}

impl RxDstMemo {
    /// One v4 dst probe: 4-byte compare on a memo hit; on a miss
    /// `subnets.lookup_ipv4` plus a name compare, cached. `is_reachable` is `|_|
    /// true`, so the walk stops at the first (longest) prefix match: if that's
    /// myself the answer is yes, and if it's an unreachable peer `route` would say
    /// Unreachable, which is also a punt.
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
            .lookup_ipv4(addr, |_| true)
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

/// Can this raw UDP payload `[dst_id6][src_id6][SPTPS]` take the RX fast path?
/// No side effects; `None` ⇒ slow path when: `slowpath_all`; shorter than
/// 12+21; `dst_id6` non-null (relay); unknown `src_id6`; no `TunnelHandles`
/// yet; no cached `udp_addr` (the slow path caches it on the first valid
/// packet). Type, dst-subnet and MTU gates need plaintext and are deferred to
/// [`rx_open`]. `overwrite_mac` and kernel forwarding are covered by the
/// `!Router` fold.
#[must_use]
pub(crate) fn rx_probe<'a>(snap: &'a TxSnapshot, pkt: &'a [u8]) -> Option<RxTarget<'a>> {
    // Setup-time fold. Same gate as tx_probe; same one-bool early-out.
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

    // dst == NULL ⇔ direct to us. Non-null is the relay branch (forward without
    // decrypt, or for-us-via-relay), which has `&mut Daemon` side effects; punt
    // all of it. The 6-byte zero check is written as u32+u16 compares explicitly
    // on this hot path.
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

/// Decrypt `target.ct` into `scratch`, run post-decrypt gates, synthesize
/// the eth header, strip the type byte; `Ok(len)` leaves `[eth:14][IP]` for
/// GRO or `device.write`. Order is the hard rule: `open_into` (tag fail
/// leaves `scratch` untouched), type == `PKT_NORMAL`, body ≤ MTU, dst is
/// ours, and only then `replay.check_public` — a fresh packet failing a gate
/// stays uncommitted for the slow path. `Err(())` on any gate; the caller's
/// only response is the slow path, which re-decrypts (~4µs, rare) and logs.
pub(crate) fn rx_open(
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

    // Step 1: decrypt with the prebuilt session cipher.
    //
    // `scratch` setup: clear, resize to ETH_HLEN headroom.
    // `open_into` debug-asserts `out.len() == decrypt_at` then
    // extends. On tag fail it returns before the extend
    // (chapoly.rs:254), so `scratch` stays at `[0; 14]` — the
    // slow path's `open_data_into` will re-clear it anyway.
    scratch.clear();
    scratch.resize(ETH_HLEN, 0);
    target
        .handles
        .incipher
        .open_into(u64::from(seqno), &ct[4..], scratch, ETH_HLEN)
        .map_err(|_| ())?;
    // scratch = [0;14][type:1][body]

    let ty = scratch[ETH_HLEN];

    // Step 2: type gate. `PKT_NORMAL` is 0; COMPRESSED/MAC/PROBE are bits 0-2 and
    // `REC_HANDSHAKE` (≥128) marks an in-band rekey record. Anything nonzero
    // punts, matching `open_data_into`'s `BadRecord` fallthrough. The const exists
    // so the next ty bit is greppable.
    let _ = REC_HANDSHAKE;
    if ty != PKT_NORMAL {
        return Err(());
    }

    // body_len: scratch is [0;14][ty:1][body] now.
    let body_len = scratch.len() - ETH_HLEN - 1;

    // Step 3: MTU gate. sptps.rs:332 — body bigger than the.
    // configured MTU is a peer misconfig; slow path logs + drops.
    // `MTU` is the daemon's `tunnel::MTU` (1518); we compare body
    // length against it same as `receive_sptps_record` does.
    if body_len > usize::from(MTU) {
        return Err(());
    }

    // Step 4: dst-subnet gate. Body is at `scratch[15..]` (eth + type byte); empty
    // ⇒ punt. Dispatch on the version nibble as sptps.rs does (4/6), punting
    // instead of logging on anything else.
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

    // Step 5: replay commit. THE COMMIT. Everything above was.
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

    // Step 6: ethertype synth + type-byte strip.
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

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inthash::IntHashMap;
    use crate::node_id::NodeId6Table;
    use crate::shard::NodeView;
    use crate::subnet_tree::SubnetTree;
    use std::net;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
    use tinc_crypto::aead::SptpsCipher;
    use tinc_sptps::ReplayWindow;

    /// Build a UDP wire packet: `[NULL:6][src_id6:6][seqno:4]
    /// [enc(ty‖body)][tag:16]`. `src_id6` derived from `src_name`;
    /// body is encrypted with `key`. Mirror of what
    /// `seal_data_into` → `send_sptps_data_relay` produces for a
    /// direct-send (dst=NULL).
    fn wire_packet(src_name: &str, seqno: u32, ty: u8, body: &[u8], key: &[u8; 64]) -> Vec<u8> {
        let cipher = SptpsCipher::new(tinc_sptps::SptpsAead::default(), key);
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

        // bob's handles. inkey is the test key; outcipher doesn't
        // matter (RX doesn't seal). replay starts empty (seqno 0
        // is the first valid). udp_addr cached so probe passes.
        let aead = tinc_sptps::SptpsAead::default();
        let handles = Arc::new(TunnelHandles {
            outseqno: Arc::new(AtomicU64::new(0)),
            out_key_base: 0,
            replay: Arc::new(Mutex::new(ReplayWindow::default())),
            outcipher: SptpsCipher::new(aead, &[0u8; 64]),
            incipher: SptpsCipher::new(aead, &inkey),
            udp_addr: Mutex::new(Some((
                socket2::SockAddr::from("10.0.0.2:655".parse::<net::SocketAddr>().unwrap()),
                0,
            ))),
            validkey: AtomicBool::new(true),
            minmtu: AtomicU16::new(1400),
            outcompression: 0,
            stats: Arc::default(),
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
    /// reject a valid packet and the byte layout (ethertype synth,
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
        // step 5 being unconditional after step 4. Not asserted here:
        // ReplayWindow has no public constructor with a real window
        // size; default() is zero-width. The *_no_replay_advance
        // tests below prove the converse via seqno reuse, which works
        // with any window.)
    }

    /// Tag mismatch ⇒ `rx_open` Err, replay window not advanced.
    /// (The hard rule: forged seqno + bad tag must not commit.)
    #[test]
    fn bad_tag_no_replay_advance() {
        let (snap, _bob, inkey) = fixture();
        let body = v4_body([10, 0, 0, 5], 100);
        // Seal with WRONG key.
        let pkt = wire_packet("bob", 0, PKT_NORMAL, &body, &[0xFFu8; 64]);

        let target = rx_probe(&snap, &pkt).expect("probe doesn't decrypt");
        let mut scratch = Vec::new();
        let mut memo = RxDstMemo::default();
        assert!(rx_open(&target, &snap, &mut scratch, &mut memo).is_err());

        // Now seal with the RIGHT key, same seqno. Must succeed —
        // the bad-tag attempt didn't burn seqno 0.
        let pkt2 = wire_packet("bob", 0, PKT_NORMAL, &body, &inkey);
        let target2 = rx_probe(&snap, &pkt2).unwrap();
        assert!(rx_open(&target2, &snap, &mut scratch, &mut memo).is_ok());
    }

    /// `PKT_PROBE` ⇒ Err, replay not advanced. Slow path must be
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

        // seqno 5 not committed: a PKT_NORMAL at seqno 5 still works.
        let pkt2 = wire_packet("bob", 5, PKT_NORMAL, &body, &inkey);
        let target2 = rx_probe(&snap, &pkt2).unwrap();
        assert!(rx_open(&target2, &snap, &mut scratch, &mut memo).is_ok());
    }

    /// dst routes to bob (10.1.0.0/24), not alice ⇒ punt. Replay
    /// not advanced — slow path forwards.
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

        // seqno 0 not committed.
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
