use super::super::Daemon;
use super::DEVICE_DRAIN_CAP;

use std::io;

use crate::tunnel::TunnelState;

use crate::graph::NodeId;

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
        // tx_batch_live tells send_sptps_data_relay to stage instead
        // of send; must not outlive this fn. The buffer is warm-
        // reused but must be empty between calls.
        debug_assert!(!self.dp.tx_batch_live, "tx_batch_live leaked");
        debug_assert_eq!(
            self.dp.tx_batch.count(),
            0,
            "tx_batch carries staged frames"
        );
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
        // tx_batch spans outer-loop iterations: vnet drain returns 1
        // frame per call, the burst is in `iters` not `count`. Arm
        // lazily on first burst; ship+disarm unconditionally after.
        while iters < DEVICE_DRAIN_CAP {
            iters += 1;
            // mem::take: `route_packet` borrows `&mut self`; the
            // arena slot borrow conflicts. Same dance as
            // `udp_rx_batch`. The arena is `Some` between calls
            // (set in `setup`, never taken elsewhere).
            let mut arena = self
                .dp
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
                    self.dp.device_arena = Some(arena);
                    // Same disarm as the post-loop path: iters>1 may
                    // have armed/staged before the error.
                    self.flush_tx_batch();
                    self.dp.tx_batch_live = false;
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
                    self.dp.device_arena = Some(arena);
                    break;
                }
                tinc_device::DrainResult::Frames { count } => {
                    self.device_errors = 0;
                    // TX batching: `tx_batch` Some → send site stages
                    // instead of `sendto`; ship the run in one
                    // `EgressBatch` after the loop. Encrypt still goes
                    // into `tx_scratch` per-frame, batch COPIES from
                    // there (one ~1.5KB memcpy vs 43× fewer syscalls).
                    //
                    // Arm on a burst: count>1 OR iters>1. An idle ping
                    // (count==1 && iters==1) falls through to immediate
                    // send. Once armed, stays armed across iterations
                    // so vnet's Frames{1}×N then Super coalesce into
                    // one sendmsg.
                    if count > 1 || iters > 1 {
                        self.dp.tx_batch_live = true;
                    }
                    for i in 0..count {
                        let n = arena.lens()[i];
                        let myself_tunnel = self.dp.tunnels.entry(self.myself).or_default();
                        myself_tunnel.stats.add_in(1, n as u64);

                        // `slot_mut` because route_packet mutates
                        // (overwrite_mac, fragment in-place). The send
                        // site sees `tx_batch.is_some()` and stages;
                        // or flushes-then-stages on dst/size mismatch;
                        // or falls through to immediate send for the
                        // cold path (no `udp_addr_cached`).
                        nw |= self.route_packet(&mut arena.slot_mut(i)[..n], None);
                    }
                    self.dp.device_arena = Some(arena);
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
                    let scratch = self.dp.tso_scratch.get_or_insert_with(|| {
                        vec![0u8; DEVICE_DRAIN_CAP * tinc_device::DeviceArena::STRIDE]
                            .into_boxed_slice()
                    });
                    // Same `mem::take` dance as `device_arena`:
                    // `route_packet` borrows `&mut self`, the slice
                    // borrow conflicts.
                    let mut scratch = std::mem::take(scratch);
                    let mut tso_lens = std::mem::take(&mut self.dp.tso_lens);

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
                            if count > 1 {
                                self.dp.tx_batch_live = true;
                            }
                            // Stats: count the super-packet as one ingest
                            // (the "read() drops 30×" gate metric counts
                            // syscalls, not stat increments). Bytes = the
                            // raw IP payload we got from the kernel.
                            let myself_tunnel = self.dp.tunnels.entry(self.myself).or_default();
                            myself_tunnel.stats.add_in(1, len as u64);

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
                            // TX fast-path: tx_probe walks the gate
                            // chain on the snapshot once per super.
                            // On Some we seal+ship inline — no
                            // route_packet, no &mut self reborrow per
                            // chunk. Wire-identical (handle_based_
                            // seal_byte_identical proves the bytes;
                            // netns tests prove the wiring).
                            //
                            // mem::take: tx_probe is &TxSnapshot but
                            // seal+ship needs &mut self.dp +
                            // &mut self.listeners alongside. Same
                            // dance as device_arena/tso_scratch.
                            let snap = self.tx_snap.take();
                            // any_pcap is the only slowpath_all input
                            // that flips at runtime (`tinc pcap` arms
                            // it via the control conn). The fold was
                            // computed at setup; check the live bit
                            // here. One bool load per super.
                            if self.any_pcap
                                || !self.tx_fast_super(
                                    snap.as_ref(),
                                    count,
                                    &scratch,
                                    &tso_lens[..count],
                                )
                            {
                                for i in 0..count {
                                    let n = tso_lens[i];
                                    let off = i * tinc_device::DeviceArena::STRIDE;
                                    nw |= self.route_packet(&mut scratch[off..off + n], None);
                                }
                            }
                            self.tx_snap = snap;
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

                    self.dp.tso_scratch = Some(scratch);
                    self.dp.tso_lens = tso_lens;
                    self.dp.device_arena = Some(arena);

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

        // Ship + disarm unconditionally. ship is a no-op on empty so
        // the idle count==1 path is unchanged. Buffer stays warm; only
        // the live flag drops.
        self.flush_tx_batch();
        self.dp.tx_batch_live = false;
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
        Self::ship_tx_batch(
            &mut self.dp.tx_batch,
            &mut self.listeners,
            &mut self.dp.tunnels,
            &self.graph,
        );
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
        graph: &crate::graph::Graph,
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
            } else if e.raw_os_error() == Some(nix::Error::EMSGSIZE as i32) {
                // PMTU shrank under us; frames in THIS batch are
                // lost (kernel rejected the whole sendmsg) — same
                // outcome as the per-frame path, just `count×`.
                super::helpers::handle_udp_emsgsize(tunnels, graph, relay_nid, origlen);
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
        self.dp
            .tunnels
            .entry(self.myself)
            .or_default()
            .stats
            .add_out(1, len);

        // GRO write. Bucket armed only inside `recvmmsg_batch`'s
        // dispatch loop; other callers (broadcast echo, kernel-
        // mode forward, ICMP unreachable) reach here with
        // `gro_bucket = None` and fall through to the immediate
        // write. `data` is `[synth eth(14)][IP]`; the helper skips
        // the eth header.
        super::helpers::gro_offer_or_write(&mut self.device, &mut self.dp.gro_bucket, data);
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

    /// TX fast-path attempt for one super. Returns `true` if the
    /// super was sealed+shipped (caller skips the slow loop), `false`
    /// if any gate failed (caller runs `route_packet` per chunk).
    ///
    /// Lifted out of the Super arm to keep nesting sane: the caller
    /// is already 5 levels deep in `match drain { Super { match split`.
    /// `count > 1`: single-chunk supers get no batch win. `tx_batch`
    /// is `Some` here (armed at `count > 1`). Snap is `&Option<_>`
    /// because the caller `mem::take`s and restores; passing it by
    /// value would force the restore inside this fn for both arms.
    fn tx_fast_super(
        &mut self,
        snap: Option<&crate::shard::TxSnapshot>,
        count: usize,
        scratch: &[u8],
        lens: &[usize],
    ) -> bool {
        let Some(snap) = snap else { return false };
        // count <= DEVICE_DRAIN_CAP = 64; try_from succeeds. The else
        // arm is dead with the current cap; falls to slow path if
        // someone bumps the cap past u32 (unlikely).
        let Ok(alloc) = u32::try_from(count) else {
            return false;
        };
        if alloc < 2 {
            return false;
        }
        let Some(target) = crate::shard::tx_probe(snap, &scratch[..lens[0]], alloc) else {
            return false;
        };
        // target.sock is the listener index from udp_addr.1 — same
        // socket the slow path's send_sptps_data_relay would pick.
        // Listener-gone (reload mid-super) ⇒ slow path; rare.
        // Seqnos already burned by tx_probe — fine, gaps are valid
        // (replay window is a sliding bitmap).
        let Some(slot) = self.listeners.get_mut(usize::from(target.sock)) else {
            return false;
        };
        // Disjoint dp fields (tx_batch / tx_scratch / tunnels);
        // destructure once instead of take+restore.
        let dp = &mut self.dp;
        let r = crate::shard::seal_super(
            &target,
            tinc_device::DeviceArena::STRIDE,
            lens,
            scratch,
            &mut dp.tx_scratch,
            &mut dp.tx_batch,
            slot.egress.as_mut(),
        );
        match r {
            Ok(ok) => {
                // Out-stats. Slow path bumps these per-chunk in
                // route_packet → send_sptps_packet; we sum once.
                target.handles.stats.add_out(ok.packets, ok.bytes);
            }
            Err((relay, origlen)) => {
                // PMTU shrank under us; frames lost, inner-TCP
                // retransmits. Cap maxmtu for the next super.
                super::helpers::handle_udp_emsgsize(
                    &mut self.dp.tunnels,
                    &self.graph,
                    relay,
                    origlen,
                );
            }
        }
        // Batch already shipped inside seal_super.
        true
    }
}
