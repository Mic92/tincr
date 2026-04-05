use super::super::Daemon;
use super::DEVICE_DRAIN_CAP;

use std::io;

use crate::tunnel::{MTU, TunnelState};

use tinc_graph::NodeId;

impl Daemon {
    /// Drain loop. LT epoll re-fires next turn if we leave bytes
    /// behind; the loop here is a fairness cap (iperf3 saturating
    /// the TUN shouldn't starve meta-conn flush/UDP recv/timers)
    /// and pulls `GSO_NONE` ACKs that pile up behind a TSO super.
    ///
    /// One `device.drain(&mut arena, cap)` returns N frames in arena
    /// slots. The default `drain()` IS `read()`-in-a-loop — byte-for-
    /// byte the same syscall sequence on bsd/fd backends. The Linux
    /// `vnet_hdr` device override returns `Super` for TSO segments.
    // `Super` arm is the TSO-split path. Factoring it out
    // would mean threading `arena`/`nw`/`tx_batch` through a helper;
    // the control flow reads cleaner inline.
    pub(in crate::daemon) fn on_device_read(&mut self) {
        let mut nw = false;
        // The default `Device::drain` loops INTERNALLY until EAGAIN
        // or cap; one call suffices. The vnet_hdr drain reads ONE
        // skb (`Super` or `Frames{1}`) per call — looping HERE pulls
        // the GSO_NONE ACKs queued behind a TSO super. Bounded so a
        // saturating sender doesn't starve UDP/timers (`0f120b11`).
        //
        // The `Frames` arm with the default drain hits this loop
        // once: it returns count<cap (drained to EAGAIN, the second
        // iteration sees `Empty`) or count==cap (we break out; LT
        // re-fires next turn). Either way, no behavior change for
        // the non-vnet path.
        let mut iters = 0usize;
        // tx_batch armed ACROSS outer-loop iterations. The original
        // batch-then-ship logic was designed for one drain returning
        // N frames; the vnet path returns 1 frame per drain but
        // multiple drains per epoll wake. The burst is in `iters`,
        // not `count`. Arm here, ship after the loop.
        //
        // The non-vnet path is unchanged: it hits the loop once with
        // count>1, the Frames arm flushes inline (so the sendmsg
        // happens before this fn returns either way), and the
        // post-loop flush is a no-op on an already-empty batch.
        let mut batch_armed = false;
        while iters < DEVICE_DRAIN_CAP {
            iters += 1;
            // mem::take: `route_packet` borrows `&mut self`; the
            // arena slot borrow conflicts. Same dance as
            // `udp_rx_batch`. The arena is `Some` between calls
            // (set in `setup`, never taken elsewhere).
            let mut arena = self
                .device_arena
                .take()
                .expect("device_arena is Some between on_device_read calls");

            let result = match self.device.drain(&mut arena, DEVICE_DRAIN_CAP) {
                Ok(r) => r,
                Err(e) => {
                    // 10 consecutive failures → exit. No sleep-on-
                    // error backoff (bound is 10, sleep would total
                    // 2.75s then exit anyway).
                    log::error!(target: "tincd::net",
                                "Error reading from device: {e}");
                    self.device_errors += 1;
                    if self.device_errors > 10 {
                        log::error!(target: "tincd",
                                    "Too many errors from device, exiting!");
                        self.running = false;
                    }
                    self.device_arena = Some(arena);
                    if nw {
                        self.maybe_set_write_any();
                    }
                    return;
                }
            };

            match result {
                tinc_device::DrainResult::Empty => {
                    // EAGAIN. Queue drained; we hold the EPOLLET
                    // contract. Put arena back, exit the loop.
                    self.device_arena = Some(arena);
                    break;
                }
                tinc_device::DrainResult::Frames { count } => {
                    self.device_errors = 0;
                    // TX batching (`RUST_REWRITE_10G.md`): same
                    // per-frame route+encrypt loop, but the SEND is
                    // deferred. `tx_batch` being `Some` signals the
                    // send site
                    // (`send_sptps_data_relay` UDP path) to stage
                    // instead of `sendto`. After the loop, ship the
                    // accumulated run in one `EgressBatch` (one
                    // `sendmsg` with `UDP_SEGMENT` cmsg on Linux).
                    //
                    // The encrypt still goes into `tx_scratch` per-
                    // frame; the batch COPIES from there. One extra
                    // ~1.5KB memcpy per frame vs 43× fewer syscalls.
                    // The memcpy is the price of not restructuring
                    // `seal_data_into`'s Vec-based API.
                    //
                    // Lazy init: the ~100KB buffer only allocates the
                    // first time a device read fires. A tunnelserver
                    // (no local TUN) never gets here.
                    //
                    // Arm tx_batch when there's a burst to coalesce.
                    // "Burst" = either count>1 (default drain batched
                    // multiple frames) OR iters>1 (vnet drain returned
                    // Frames{1} multiple times this epoll wake — bob's
                    // ACK-burst case). An idle ping fires epoll per-
                    // frame, hits count==1 && iters==1, falls through
                    // to immediate send (no memcpy tax).
                    //
                    // Once armed, stays armed across outer iterations:
                    // the vnet's Frames{1}-then-Frames{1}-then-Super
                    // sequence accumulates into one sendmsg.
                    if !batch_armed && (count > 1 || iters > 1) {
                        if self.tx_batch.is_none() {
                            self.tx_batch = Some(crate::egress::TxBatch::new(
                                DEVICE_DRAIN_CAP
                                    * (12 + usize::from(MTU) + tinc_sptps::DATAGRAM_OVERHEAD),
                            ));
                        }
                        batch_armed = true;
                    }
                    for i in 0..count {
                        let n = arena.lens()[i];
                        let myself_tunnel = self.tunnels.entry(self.myself).or_default();
                        myself_tunnel.in_packets += 1;
                        myself_tunnel.in_bytes += n as u64;

                        // `slot_mut` because route_packet mutates
                        // (overwrite_mac, fragment in-place). The send
                        // site sees `tx_batch.is_some()` and stages;
                        // or flushes-then-stages on dst/size mismatch;
                        // or falls through to immediate send for the
                        // cold path (no `udp_addr_cached`).
                        nw |= self.route_packet(&mut arena.slot_mut(i)[..n], None);
                    }
                    // count>1: default drain already drained to
                    // EAGAIN (or hit cap). Ship now. The vnet
                    // count==1 case ships AFTER the outer loop
                    // (accumulating across iterations).
                    if count > 1 {
                        self.flush_tx_batch();
                    }
                    self.device_arena = Some(arena);
                    if count == DEVICE_DRAIN_CAP {
                        // Cap hit. LT re-fires next turn.
                        break;
                    }
                    // count < cap: the default drain looped to EAGAIN
                    // internally. We're done (the next outer iteration
                    // would just see Empty). Exit the loop. The vnet
                    // drain returns Frames{1} for GSO_NONE — we DO
                    // need to loop for those (the next read might be
                    // another GSO_NONE or a Super).
                    if count > 1 {
                        // count>1 only happens with the default drain
                        // (it batched). It already drained to EAGAIN.
                        break;
                    }
                    // count==1: vnet GSO_NONE. Loop again.
                }
                tinc_device::DrainResult::Super {
                    len,
                    gso_size,
                    gso_type,
                    csum_start,
                    csum_offset,
                } => {
                    // TSO ingest: the vnet_hdr device put a ≤64KB
                    // TCP super-segment in `arena`.
                    // `tso_split` re-segments it into MTU-sized frames
                    // with re-synthesized TCP/IP headers. `route_packet`
                    // runs ONCE (chunk[0]; same dst for all chunks — TSO
                    // is single-flow) then the rest skip the trie lookup.
                    self.device_errors = 0;

                    // Lazy alloc the scratch (first Super only).
                    let scratch = self.tso_scratch.get_or_insert_with(|| {
                        vec![0u8; DEVICE_DRAIN_CAP * tinc_device::DeviceArena::STRIDE]
                            .into_boxed_slice()
                    });
                    // Same `mem::take` dance as `device_arena`:
                    // `route_packet` borrows `&mut self`, the slice
                    // borrow conflicts.
                    let mut scratch = std::mem::take(scratch);
                    let mut tso_lens = std::mem::take(&mut self.tso_lens);

                    let hdr = tinc_device::VirtioNetHdr {
                        flags: 0,    // unused by tso_split (it always csums)
                        gso_type: 0, // ditto; gso_type passed separately
                        hdr_len: 0,  // recomputed from csum_start + tcp doff
                        gso_size,
                        csum_start,
                        csum_offset,
                    };
                    let split = tinc_device::tso_split(
                        &arena.as_contiguous()[..len],
                        &hdr,
                        gso_type,
                        &mut scratch,
                        tinc_device::DeviceArena::STRIDE,
                        &mut tso_lens,
                    );
                    match split {
                        Ok(count) => {
                            // Same TX-batch staging as `Frames`. Gate on
                            // count>1 (one segment = no batch advantage).
                            if count > 1 && self.tx_batch.is_none() {
                                self.tx_batch = Some(crate::egress::TxBatch::new(
                                    DEVICE_DRAIN_CAP
                                        * (12 + usize::from(MTU) + tinc_sptps::DATAGRAM_OVERHEAD),
                                ));
                            }
                            // Stats: count the super-packet as one ingest
                            // (the "read() drops 30×" gate metric counts
                            // syscalls, not stat increments). Bytes = the
                            // raw IP payload we got from the kernel.
                            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
                            myself_tunnel.in_packets += 1;
                            myself_tunnel.in_bytes += len as u64;

                            // The win: `route_packet` runs once per super.
                            // The first call does the trie lookup; the
                            // rest reuse the same dst (TSO is single-flow,
                            // mixed-dst super-packets don't exist — the
                            // kernel TCP stack segments per-socket).
                            //
                            // BUT: route_packet has side effects per-packet
                            // (TX stats, PMTU drive via try_tx, the dense
                            // batch staging). Calling it once and looping
                            // would mean rewriting the send path. For now:
                            // call it `count` times. The 0.94µs→0.56µs
                            // "other" projection assumed the trie lookup
                            // amortizes; it does (same `last_routes[]`
                            // index), and that's the expensive half.
                            //
                            // Re-profile after this lands: if `route_packet`
                            // overhead is still visible, factor a
                            // `route_first_then_send_rest` that hoists the
                            // dst out. ~+40 LOC; not yet.
                            for i in 0..count {
                                let n = tso_lens[i];
                                let off = i * tinc_device::DeviceArena::STRIDE;
                                nw |= self.route_packet(&mut scratch[off..off + n], None);
                            }
                            // Ship the super's segments. The post-loop
                            // flush below is a no-op on empty.
                            self.flush_tx_batch();
                        }
                        Err(e) => {
                            // Kernel-contract violation (vnet_hdr describes
                            // a packet shape that doesn't match the bytes)
                            // or undersized scratch (gso_size tiny). Log +
                            // drop. Inner-TCP retransmits.
                            log::warn!(target: "tincd::net",
                                   "tso_split: {e:?} (len={len} \
                                    gso_size={gso_size}); dropping");
                        }
                    }

                    self.tso_scratch = Some(scratch);
                    self.tso_lens = tso_lens;
                    self.device_arena = Some(arena);

                    // One Super = ~30-43 frames worth. Count it against
                    // the iteration budget as if it were a Frames{cap}
                    // — we don't want 64× super-packets per epoll wake
                    // (that's 64×43 = 2752 frames; encrypt/send would
                    // run for milliseconds, starving recv). One Super
                    // per wake is the design; loop only to drain the
                    // tail (the GSO_NONE ACKs that pile up behind).
                    break;
                }
            } // match result
        } // while iters

        // Ship anything accumulated across vnet Frames{1} iterations.
        // No-op for the non-vnet path (count>1 arm flushed already)
        // and for the iters==1 idle-ping case (batch never armed).
        // Disarm so UDP-recv→forward / meta-conn→relay / probes go
        // back to immediate-send outside this fn.
        if batch_armed {
            self.flush_tx_batch();
            self.tx_batch = None;
        }
        // Cap hit. LT re-fires next turn — encrypt cost of one super
        // (~43 frames) per wake is the fairness bound, not an ET
        // workaround.
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// Ship the staged TX batch. Called at the end of
    /// `on_device_read`'s drain loop and on dst/size mismatch
    /// mid-loop. No-op on empty.
    fn flush_tx_batch(&mut self) {
        if let Some(mut b) = self.tx_batch.take() {
            Self::ship_tx_batch(&mut b, &mut self.listeners, &mut self.tunnels, &self.graph);
            self.tx_batch = Some(b);
        }
    }

    /// Ship one batch run. Static + explicit field borrows so the
    /// mid-loop flush (in `send_sptps_data_relay`, while
    /// `tx_scratch` is also borrowed) doesn't fight `&mut self`.
    /// Same `EMSGSIZE`/`WouldBlock` dispatch as the immediate-send
    /// path; the wire result is identical to `count` immediate
    /// sends, so the error handling is too.
    pub(super) fn ship_tx_batch(
        batch: &mut crate::egress::TxBatch,
        listeners: &mut [super::ListenerSlot],
        tunnels: &mut crate::inthash::IntHashMap<NodeId, TunnelState>,
        graph: &tinc_graph::Graph,
    ) {
        let Some((b, sock, relay_nid, origlen)) = batch.take() else {
            return;
        };
        // Ship, then let `b` (which borrows `batch.buf`/`batch.dst`)
        // fall out of scope before `reset` mutates `batch`.
        let result = {
            let r = listeners
                .get_mut(usize::from(sock))
                .map(|slot| slot.egress.send_batch(&b));
            let _ = b;
            r
        };
        batch.reset();

        let Some(result) = result else {
            // Listener gone (reload mid-batch). Same as the
            // immediate path's `listeners.get_mut` returning None:
            // silently drop. UDP is unreliable.
            return;
        };
        if let Err(e) = result {
            if e.kind() == io::ErrorKind::WouldBlock {
                // sndbuf full. Drop the whole run — same outcome
                // as the per-frame path dropping each one. The
                // kernel's UDP sndbuf doesn't partial-accept a
                // GSO send (`udp_send_skb` is all-or-nothing).
            } else if e.raw_os_error() == Some(libc::EMSGSIZE) {
                // PMTU shrank under us. Shrink the relay's maxmtu
                // so the NEXT batch's stride is smaller. The frames
                // in THIS batch are lost (the kernel rejected the
                // whole sendmsg) — same as the per-frame path losing
                // one frame, just `count×` at once. Inner-TCP
                // retransmits.
                if let Some(p) = tunnels.get_mut(&relay_nid).and_then(|t| t.pmtu.as_mut()) {
                    let relay_name = graph.node(relay_nid).map_or("<gone>", |n| n.name.as_str());
                    for a in p.on_emsgsize(origlen) {
                        Self::log_pmtu_action(relay_name, &a);
                    }
                }
            } else {
                let relay_name = graph.node(relay_nid).map_or("<gone>", |n| n.name.as_str());
                log::warn!(target: "tincd::net",
                           "Error sending UDP SPTPS batch to \
                            {relay_name}: {e}");
            }
        }
    }

    /// The local-delivery half: write to the device, with the
    /// `overwrite_mac` stamp gated on Mode=router + TAP-ish device.
    /// Factored out so the kernel-mode shortcut, broadcast echo, and
    /// `Forward{to:myself}` arms all hit the same stamp.
    pub(super) fn send_packet_myself(&mut self, data: &mut [u8]) {
        // Dest MAC ← the kernel's own (snatched from ARP/NDP);
        // source MAC ← dest XOR 0xFF on the last byte ("arbitrary
        // fake source" — just-different so the kernel doesn't see
        // its own MAC as src). data.len()≥12 holds at every callsite
        // (post-route or post-checklength).
        if self.overwrite_mac && data.len() >= 12 {
            data[0..6].copy_from_slice(&self.mymac);
            data[6..12].copy_from_slice(&self.mymac);
            data[11] ^= 0xFF;
        }
        let len = data.len() as u64;
        let myself_tunnel = self.tunnels.entry(self.myself).or_default();
        myself_tunnel.out_packets += 1;
        myself_tunnel.out_bytes += len;

        // ─── GRO write ─────────────────────────────────────────────
        // Armed only inside `recvmmsg_batch`'s dispatch loop. The
        // other call sites (broadcast echo, kernel-mode forward,
        // ICMP unreachable) reach here with `gro_bucket = None` and
        // fall through to the immediate write.
        //
        // `data` is `[synth eth(14)][IP]` — the offer wants raw IP.
        // The eth header is throwaway in TUN mode anyway (the
        // existing `device.write` stomps it for the vnet_hdr stomp).
        if let Some(mut bucket) = self.gro_bucket.take() {
            use tinc_device::GroVerdict;
            const ETH_HLEN: usize = 14;
            if data.len() > ETH_HLEN {
                match bucket.offer(&data[ETH_HLEN..]) {
                    GroVerdict::Coalesced => {
                        self.gro_bucket = Some(bucket);
                        return; // absorbed; written on flush
                    }
                    GroVerdict::FlushFirst => {
                        // Ship the run, then re-offer. The packet
                        // is a valid candidate (passed all the
                        // shape checks), it just doesn't fit —
                        // different ack, seq gap, post-PSH. Seeding
                        // it now starts the NEXT run.
                        self.gro_flush(&mut bucket);
                        let v = bucket.offer(&data[ETH_HLEN..]);
                        // Either it seeds the empty bucket
                        // (Coalesced) or some race made it stop
                        // qualifying (NotCandidate, can't happen
                        // with an immutable slice but we don't
                        // build correctness on that). Never
                        // FlushFirst on an empty bucket.
                        debug_assert_ne!(v, GroVerdict::FlushFirst);
                        self.gro_bucket = Some(bucket);
                        if v == GroVerdict::Coalesced {
                            return;
                        }
                        // NotCandidate: fall through to write.
                    }
                    GroVerdict::NotCandidate => {
                        // Non-TCP, FIN/SYN/RST, pure-ACK, fragment,
                        // IP options. Ordering: anything already in
                        // the bucket goes out FIRST. Same-flow stuff
                        // can't be in the bucket (would've been a
                        // key mismatch → FlushFirst), but a non-
                        // candidate from the SAME flow (e.g. a FIN)
                        // mustn't reorder past data with lower seq.
                        self.gro_flush(&mut bucket);
                        self.gro_bucket = Some(bucket);
                    }
                }
            } else {
                self.gro_bucket = Some(bucket);
            }
        }

        if let Err(e) = self.device.write(data) {
            log::debug!(target: "tincd::net", "Error writing to device: {e}");
        }
    }

    /// Ship the GRO bucket. `bucket.flush()` finalizes `vnet_hdr` +
    /// IP totlen/csum; `device.write_super` is a raw fd write.
    /// `Unsupported` here means `gro_enabled` was wrong at setup
    /// (the gate is supposed to make this unreachable). Log at
    /// `warn` not `debug`: it's a daemon bug, not a transient.
    pub(super) fn gro_flush(&mut self, bucket: &mut tinc_device::GroBucket) {
        if let Some(buf) = bucket.flush()
            && let Err(e) = self.device.write_super(buf)
        {
            log::warn!(target: "tincd::net",
                       "GRO super write failed: {e} — \
                        gro_enabled gate let a non-vnet device through?");
        }
    }
}
