//! Daemon glue for `crate::autoconnect`: build the snapshot `decide()`
//! reads, execute the resulting action, and load `hosts/` so nodes we
//! have no edge to are still candidates.

use super::{Daemon, TimerWhat, parse_subnets_from_config};

use std::collections::HashSet;
use std::time::Duration;

use crate::addrcache::AddressCache;
use crate::autoconnect::{self, AutoAction, NodeSnapshot, OutgoingSnapshot, ShortcutKnobs};
use crate::keys;
use crate::outgoing::{OutOrigin, Outgoing, OutgoingId, resolve_config_addrs};
use std::fs;
use tinc_crypto::os_rng;

impl Daemon {
    /// Walk `confbase/hosts/`, add every valid-named file to the graph and populate
    /// `has_address`; a `has_address && !reachable` node is exactly what
    /// autoconnect may dial, so it must exist in the graph. With strictsubnets,
    /// `Subnet=` lines are preloaded so `on_add_subnet`'s lookup-first gate finds
    /// them (cold start only; a reload doesn't diff the authorised set yet).
    pub(super) fn load_all_nodes(&mut self) {
        let hosts_dir = self.confbase.join("hosts");
        let dir = match fs::read_dir(&hosts_dir) {
            Ok(d) => d,
            Err(e) => {
                log::error!(target: "tincd",
                            "Could not open {}: {e}", hosts_dir.display());
                return;
            }
        };

        // Clear on reload — a removed Address= would otherwise keep
        // the stale bit until restart. Only autoconnect reads it, and
        // dialing a no-Address node is harmless (addr-cache-empty →
        // backoff).
        self.has_address.clear();

        for ent in dir.flatten() {
            let Some(fname) = ent.file_name().to_str().map(str::to_owned) else {
                continue; // non-UTF-8 filename — can't be a node name
            };
            // also filters `.` `..` and swap files.
            if !tinc_proto::check_id(&fname) {
                continue;
            }

            self.lookup_or_add_node(&fname);

            let cfg = keys::read_host_config(&self.confbase, &fname);

            if cfg.lookup("Address").next().is_some() {
                self.has_address.insert(fname.clone());
            }

            // Preload authorized subnets. Skip our own name (setup()
            // already added them; add is idempotent but skipping
            // saves a parse).
            if self.settings.strictsubnets && fname != self.name {
                for s in parse_subnets_from_config(&cfg, &fname) {
                    self.subnets.add(s, fname.clone());
                }
            }
        }
    }

    /// Build snapshot, call `autoconnect::decide`. Nodes sorted by
    /// name: `decide()` indexes by position (`prng(count)` then walk-
    /// to-index).
    ///
    /// `&mut self`: the EWMA bookkeeping (`relay_rate`/`tx_rate`) lives
    /// in `TunnelState` and is updated here, not in the hot path —
    /// `send_sptps_data_relay` only bumps the lifetime counter.
    pub(super) fn decide_autoconnect(&mut self) -> AutoAction {
        let now = self.timers.now();

        // EWMA update (cold path, ~5s cadence).
        // α=0.3 ⇒ τ≈15s at the 5s tick. dt is wall-clock between
        // ticks (the contradicting-edge backoff can stretch it). On
        // the very first tick we have no prev sample → seed prev to
        // now (rate=0) so a single burst doesn't immediately cross
        // RELAY_HI on a bogus dt.
        let dt = self
            .last_autoconnect_tick
            .map(|p| now.saturating_duration_since(p).as_secs_f64())
            .filter(|d| *d > 0.5);
        // 5s deltas at link rate are << 2^52; precision loss is
        // immaterial for a coarse demand signal compared against
        // KiB/s thresholds.
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        for t in self.dp.tunnels.values_mut() {
            if let Some(dt) = dt {
                let rd = (t.relay_tx_bytes.saturating_sub(t.relay_tx_bytes_prev)) as f64 / dt;
                let out_bytes = t.stats.out_bytes();
                let td = (out_bytes.saturating_sub(t.out_bytes_prev)) as f64 / dt;
                t.relay_rate_bps = (0.3 * rd + 0.7 * t.relay_rate_bps as f64) as u64;
                t.tx_rate_bps = (0.3 * td + 0.7 * t.tx_rate_bps as f64) as u64;
            }
            t.relay_tx_bytes_prev = t.relay_tx_bytes;
            t.out_bytes_prev = t.stats.out_bytes();
        }
        self.last_autoconnect_tick = Some(now);

        // GC stale backoff entries so the map doesn't grow unbounded
        // on a long-lived daemon with churning shortcut targets.
        self.shortcut_backoff.retain(|_, &mut t| t > now);
        self.sweep_punches();

        let mut names: Vec<&str> = self.node_ids.keys().map(String::as_str).collect();
        names.sort_unstable();

        let nodes: Vec<NodeSnapshot> = names
            .iter()
            .filter_map(|&name| {
                let &nid = self.node_ids.get(name)?;
                let gnode = self.graph.node(nid)?;
                let edge_count = self.graph.node_edges(nid).len();
                let directly_connected = self
                    .nodes
                    .get(&nid)
                    .and_then(|ns| ns.conn)
                    .and_then(|cid| self.conns.get(cid))
                    .is_some();
                let tunnel = self.dp.tunnels.get(&nid);
                Some(NodeSnapshot {
                    name: name.to_owned(),
                    reachable: gnode.reachable,
                    has_address: self.has_address.contains(name),
                    directly_connected,
                    edge_count,
                    relay_rate_bps: tunnel.map_or(0, |t| t.relay_rate_bps),
                    tx_rate_bps: tunnel.map_or(0, |t| t.tx_rate_bps),
                    nexthop: self
                        .route_of(nid)
                        .and_then(|r| self.graph.node(r.nexthop))
                        .map(|n| n.name.clone()),
                    backoff_until: self.shortcut_backoff.get(name).copied(),
                })
            })
            .collect();

        // Past-ACK + initiated. Carry provenance for the drop arm.
        let active_outgoing_conns: Vec<OutgoingSnapshot> = self
            .conns
            .values()
            .filter(|c| c.active && c.outgoing.is_some())
            .map(|c| OutgoingSnapshot {
                name: c.name.clone(),
                origin: c
                    .outgoing
                    .and_then(|oid| self.outgoings.get(oid))
                    .map_or(OutOrigin::AutoBackbone, |o| o.origin),
                age: c
                    .activated_at
                    .map_or(Duration::MAX, |t| now.saturating_duration_since(t)),
            })
            .collect();

        // pending = Outgoing slots with no live conn. Pre-ACK conns
        // count as serving.
        let served: HashSet<OutgoingId> = self.conns.values().filter_map(|c| c.outgoing).collect();
        let pending_outgoings: Vec<OutgoingSnapshot> = self
            .outgoings
            .iter()
            .filter(|(oid, _)| !served.contains(oid))
            .map(|(_, o)| OutgoingSnapshot {
                name: o.node_name.clone(),
                origin: o.origin,
                age: Duration::MAX,
            })
            .collect();

        autoconnect::decide(
            &self.name,
            &nodes,
            &active_outgoing_conns,
            &pending_outgoings,
            &ShortcutKnobs::default(),
            now,
            &mut os_rng(),
        )
    }

    /// Execute one `AutoAction`. The daemon-side I/O for `decide()`'s
    /// pure decision.
    pub(super) fn execute_auto_action(&mut self, action: AutoAction) {
        match action {
            AutoAction::Noop => {}
            AutoAction::Connect { name, origin } => {
                // dedup: a served (pre-ACK) slot isn't in pending_outgoings, so decide() can re-pick it
                if self.outgoings.values().any(|o| o.node_name == name) {
                    return;
                }
                // Same path as setup()'s ConnectTo loop.
                if origin == OutOrigin::AutoShortcut {
                    log::info!(target: "tincd",
                               "Autoconnecting to {name} (relay shortcut)");
                } else {
                    log::info!(target: "tincd",
                               "Autoconnecting to {name}");
                }
                self.lookup_or_add_node(&name);
                let config_addrs = resolve_config_addrs(&self.confbase, &name);
                let addr_cache = AddressCache::open(&self.confbase, &name, config_addrs);
                let oid = self.outgoings.insert(Outgoing {
                    node_name: name,
                    origin,
                    timeout: 0,
                    addr_cache,
                });
                let tid = self.timers.add(TimerWhat::RetryOutgoing(oid));
                self.outgoing_timers.insert(oid, tid);
                self.setup_outgoing_connection(oid);
            }
            AutoAction::Disconnect { name, origin } => {
                if origin == OutOrigin::AutoShortcut {
                    let until = self.timers.now() + autoconnect::SHORTCUT_BACKOFF;
                    self.shortcut_backoff.insert(name.clone(), until);
                }
                // Clear conn.outgoing before terminate so its retry
                // path doesn't fire; this drop is deliberate.
                log::info!(target: "tincd",
                           "Autodisconnecting from {name}");
                let cid = self
                    .conns
                    .iter()
                    .find(|(_, c)| c.active && c.outgoing.is_some() && c.name == name)
                    .map(|(id, _)| id);
                if let Some(cid) = cid {
                    let oid = self.conns.get_mut(cid).and_then(|c| c.outgoing.take());
                    if let Some(oid) = oid {
                        if let Some(tid) = self.outgoing_timers.remove(oid) {
                            self.timers.del(tid);
                        }
                        self.outgoings.remove(oid);
                    }
                    self.terminate(cid);
                }
            }
            AutoAction::CancelPending { name } => {
                // Stamp backoff if this was a shortcut slot —
                // cancelling a still-retrying shortcut means the dial
                // failed; don't immediately re-decide to add it.
                let is_shortcut = self
                    .outgoings
                    .values()
                    .any(|o| o.node_name == name && o.origin == OutOrigin::AutoShortcut);
                if is_shortcut {
                    let until = self.timers.now() + autoconnect::SHORTCUT_BACKOFF;
                    self.shortcut_backoff.insert(name.clone(), until);
                }
                // Drop slot, no conn to kill. Fires routinely once ≥3
                // conns are up (including for ConnectTo targets), so
                // debug, not info.
                log::debug!(target: "tincd",
                            "Cancelled outgoing connection to {name}");
                let oid = self
                    .outgoings
                    .iter()
                    .find(|(_, o)| o.node_name == name)
                    .map(|(id, _)| id);
                if let Some(oid) = oid {
                    if let Some(tid) = self.outgoing_timers.remove(oid) {
                        self.timers.del(tid);
                    }
                    self.outgoings.remove(oid);
                }
            }
        }
    }
}
