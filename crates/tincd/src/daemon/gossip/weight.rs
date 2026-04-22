//! PONG-driven edge-weight EWMA + hysteresis-gated re-gossip.

use crate::daemon::{ConnId, Daemon};

impl Daemon {
    /// EWMA + asymmetric-hysteresis weight update (§3.C of
    /// `edge-weight-stability.md`, RFC 9616 / ironwood shape).
    ///
    /// `srtt += (min(rtt, srtt*2) - srtt) >> 3`. Re-gossip our own
    /// edge when `srtt` leaves the `[0.7·g, 1.5·g]` band around the
    /// last-advertised weight `g`, but never more often than
    /// `5·PingInterval`. Upward band is wider (queueing only adds
    /// delay) so jitter alone can't push the weight up.
    ///
    /// Returns `needs_write` for the broadcast it queues.
    pub(in crate::daemon) fn on_pong_rtt(&mut self, id: ConnId, now: std::time::Instant) -> bool {
        let pinginterval = u64::from(self.settings.pinginterval);
        let Some(conn) = self.conns.get_mut(id) else {
            return false;
        };
        let rtt = conn.ping_rtt_ms;
        if rtt == 0 {
            // Unmeasured (PONG without a recorded PING send-time).
            return false;
        }
        if conn.srtt_ms == 0 {
            // Seed from the first real sample, not the connect-time
            // weight: that one includes kernel SYN back-off and would
            // take α=1/8 dozens of pings to decay through. Babel and
            // ironwood both seed from the first Hello/SigReq RTT.
            // Fall through to the band check so a wildly inflated
            // handshake weight can be corrected on the very first PONG.
            conn.srtt_ms = rtt.max(1);
        } else {
            // Ironwood spike guard: a single delayed PONG (HoL on the
            // meta-TCP, GC pause) can't move SRTT by more than 1/8 of
            // its current value.
            let sample = rtt.min(conn.srtt_ms.saturating_mul(2));
            // RFC 6298 α=1/8, integer form. i64: diff may be negative.
            let srtt = i64::from(conn.srtt_ms);
            let new = srtt + ((i64::from(sample) - srtt) >> 3);
            conn.srtt_ms = u32::try_from(new).unwrap_or(1).max(1);
        }

        // The advertised weight `g` is what's in the graph for OUR
        // forward edge to this peer (set by `on_ack` and any prior
        // re-gossip from here). `NodeState.edge_weight` mirrors it.
        let Some(nid) = self.node_ids.get(&conn.name).copied() else {
            return false;
        };
        let Some(ns) = self.nodes.get(&nid) else {
            return false;
        };
        let Some(eid) = ns.edge else {
            return false;
        };
        let g = u32::try_from(ns.edge_weight).unwrap_or(0).max(1);
        let s = conn.srtt_ms;

        if !rtt_out_of_band(s, g) {
            return false;
        }

        // Re-gossip floor: 5·PingInterval. Hard cap on flood rate
        // independent of jitter (REPORT.md σ_j=20 row). Skipped for
        // the FIRST re-gossip (`last_weight_gossip == None`) so the
        // connect-time outlier is corrected at t≈PingInterval, same
        // latency as the one-shot outlier-reject scheme.
        let floor = std::time::Duration::from_secs(5 * pinginterval);
        if let Some(t) = conn.last_weight_gossip
            && now.saturating_duration_since(t) < floor
        {
            return false;
        }
        conn.last_weight_gossip = Some(now);

        let new_w = i32::try_from(s).unwrap_or(i32::MAX);
        log::debug!(target: "tincd::weight",
                    "re-gossiping edge weight to {}: {} → {} (rtt={rtt}ms)",
                    conn.name, g, new_w);

        let opts = ns.edge_options.bits();
        self.graph.update_edge(eid, new_w, opts);
        if let Some(ns) = self.nodes.get_mut(&nid) {
            ns.edge_weight = new_w;
        }
        // Weight changed → SSSP tie-break may flip.
        self.graph_dirty = true;

        // Same wire shape as `on_ack`'s initial broadcast: one nonce,
        // all active conns. Tunnelserver hubs don't propagate edges,
        // so a re-gossip would only reach the one peer anyway - skip.
        let Some(line) = self.fmt_add_edge(eid, Self::nonce()) else {
            return false;
        };
        if self.settings.tunnelserver {
            self.conns
                .get_mut(id)
                .is_some_and(|c| c.send(format_args!("{line}")))
        } else {
            self.broadcast_line(&line)
        }
    }
}

/// Asymmetric hysteresis band: 30 % drop / 50 % rise around the
/// last-advertised weight `g`. Integer form avoids the f64 round-trip
/// on the per-PingInterval hot-ish path. `u64` because `g` derives
/// from the peer-supplied ACK weight (clamped only `>= 0`, so up to
/// `i32::MAX/2` after `midpoint`) and `g*7` would overflow `u32`.
#[inline]
const fn rtt_out_of_band(srtt_ms: u32, g: u32) -> bool {
    let s = srtt_ms as u64;
    let g = g as u64;
    s * 10 < g * 7 || s * 2 > g * 3
}

#[cfg(test)]
mod tests {
    use super::rtt_out_of_band;

    /// Peer sends ACK `his_weight = i32::MAX`; `on_ack` stores
    /// `i32::midpoint(his_weight, our_estimate)` as `edge_weight`. The
    /// band check must not panic on that, and a small first-PONG SRTT
    /// must read as out-of-band (we're way below `0.7·g`) so the
    /// inflated handshake weight gets corrected.
    #[test]
    fn band_check_survives_hostile_ack_weight() {
        let his_weight: i32 = i32::MAX;
        let our_estimate: i32 = 10;
        let edge_weight = i32::midpoint(his_weight, our_estimate);
        let g = u32::try_from(edge_weight).unwrap_or(0).max(1);
        assert!(
            u64::from(g) * 7 > u64::from(u32::MAX),
            "premise: u32 would wrap"
        );
        let s: u32 = 10;
        assert!(rtt_out_of_band(s, g), "s ≪ 0.7·g → must re-gossip");
    }

    #[test]
    fn band_check_edges() {
        assert!(!rtt_out_of_band(100, 100));
        assert!(rtt_out_of_band(69, 100)); // 30 % drop
        assert!(!rtt_out_of_band(70, 100));
        assert!(rtt_out_of_band(151, 100)); // 50 % rise
        assert!(!rtt_out_of_band(150, 100));
    }
}
