#![forbid(unsafe_code)]

//! Meta-protocol gossip handling, split by message family.
//!
//! - `keys` — `REQ_KEY`/`ANS_KEY`/`KEY_CHANGED` (routed, per-tunnel SPTPS)
//! - `edges` — `ADD_EDGE`/`DEL_EDGE` (flooded, topology)
//! - `subnets` — `ADD_SUBNET`/`DEL_SUBNET` (flooded, routing)
//! - `send` — outbound formatters (`send_everything`, `fmt_add_edge`, …)
//! - `graph` — `run_graph_and_log` / `flush_graph_dirty`
//! - `weight` — PONG-driven edge-weight EWMA + re-gossip
//!
//! Shared helpers (`seen_request`, `forward_request`, `flooded_prologue`,
//! `routed_prologue`, …) live here so the per-family files are pure
//! handler bodies.

use super::{ConnId, Daemon};

use std::fmt;

use crate::graph::NodeId;
use rand_core::{OsRng, RngCore};

mod edges;
mod graph;
mod keys;
mod send;
mod subnets;
mod weight;

/// Hard cap on gossip-learned nodes. Past this, `ADD_EDGE`/
/// `ADD_SUBNET` naming a new node are dropped (not forwarded).
/// Direct peers (`on_ack`) and locally-provisioned names go through
/// `lookup_or_add_node` directly and aren't gated.
pub(super) const MAX_NODES: usize = 65_536;
pub(super) const MAX_EDGES: usize = 4 * MAX_NODES;

impl Daemon {
    /// Lookup-or-add fused. Does NOT add a `NodeState` - transitives
    /// are in the graph only.
    pub(super) fn lookup_or_add_node(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.node_ids.get(name) {
            return id;
        }
        let id = self.graph.add_node(name);
        // Graph crate defaults reachable=true; zero it so run_graph
        // emits BecameReachable.
        self.graph.set_reachable(id, false);
        self.node_ids.insert(name.to_owned(), id);
        self.id6_table.add(name, id);
        id
    }

    /// Read `hosts/{name}` and return its Ed25519 pubkey. Shared by
    /// `send_req_key` (initiator) and `on_req_key` (responder); both
    /// need the same "parse host config → read key" pair and both
    /// hard-error on miss because `REQ_PUBKEY` is unsupported.
    /// Per-tunnel SPTPS handshake inputs from `hosts/NAME`: the peer's
    /// Ed25519 pubkey and the `SPTPSCipher` to use for that edge
    /// (per-host override, else the global default). One host-file
    /// read for both so the UDP-tunnel start path doesn't open the
    /// same file twice.
    pub(super) fn load_peer_tunnel_cfg(
        &self,
        name: &str,
    ) -> Option<([u8; tinc_crypto::sign::PUBLIC_LEN], tinc_sptps::SptpsAead)> {
        let cfg = crate::keys::read_host_config(&self.confbase, name);
        let key = crate::keys::read_ecdsa_public_key(&cfg, &self.confbase, name)?;
        let aead = crate::keys::read_sptps_cipher(&cfg, name).unwrap_or(self.settings.sptps_cipher);
        Some((key, aead))
    }

    /// Per-tunnel `SPTPSKex` for `name`: per-host override, else the
    /// tinc.conf global. Reads `hosts/NAME` again (separate from
    /// `load_peer_ed25519`) rather than threading the `Config` through
    /// — this runs once per `REQ_KEY` (10s-debounced), and keeping the
    /// two reads independent means the meta-conn and UDP-tunnel paths
    /// can't drift on which one consults the host file.
    pub(super) fn peer_sptps_kex(&self, name: &str) -> tinc_sptps::SptpsKex {
        let cfg = crate::keys::read_host_config(&self.confbase, name);
        crate::daemon::read_sptps_kex(&cfg, self.settings.sptps_kex).unwrap_or_else(|v| {
            log::warn!(target: "tincd::net",
                           "hosts/{name}: SPTPSKex = {v}: invalid, using {}",
                           self.settings.sptps_kex);
            self.settings.sptps_kex
        })
    }

    /// Resolve a routed message's `from`/`to` names to known `NodeId`s.
    /// Logs the C-parity "unknown" error and returns `None` so callers
    /// can `let-else return Ok(false)` without repeating the two blocks.
    fn resolve_from_to(
        &self,
        what: &str,
        conn_name: &str,
        from: &str,
        to: &str,
    ) -> Option<(NodeId, NodeId)> {
        let Some(&from_nid) = self.node_ids.get(from) else {
            log::error!(target: "tincd::proto",
                        "Got {what} from {conn_name} origin {from} which is unknown");
            return None;
        };
        let Some(&to_nid) = self.node_ids.get(to) else {
            log::error!(target: "tincd::proto",
                        "Got {what} from {conn_name} destination {to} which is unknown");
            return None;
        };
        Some((from_nid, to_nid))
    }

    /// Shared prologue for flooded handlers (`ADD_EDGE`/`DEL_EDGE`/
    /// `ADD_SUBNET`/`DEL_SUBNET`): `seen_request` →
    /// `tunnelserver_reject_indirect`. Returns `Some(conn_name)` to
    /// proceed, `None` to drop. Encodes the ordering invariant so a
    /// fifth handler can't get it wrong; callers do
    /// `lookup_or_add_node` AFTER this.
    pub(super) fn flooded_prologue(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
        kind: &str,
        about: &[&str],
        detail: fmt::Arguments<'_>,
    ) -> Option<String> {
        if self.seen_request(body) {
            return None;
        }
        let conn_name = self.conn(from_conn).name.clone();
        if self.tunnelserver_reject_indirect(from_conn, kind, about, detail) {
            return None;
        }
        Some(conn_name)
    }

    /// Shared prologue for routed messages (`REQ_KEY`/`ANS_KEY`):
    /// `conn_name` clone + `resolve_from_to`. Relay is NOT folded in:
    /// the two callers gate the reflexive-addr append differently.
    pub(super) fn routed_prologue(
        &self,
        from_conn: ConnId,
        what: &str,
        from: &str,
        to: &str,
    ) -> Option<(String, NodeId, NodeId)> {
        let conn_name = self.conn(from_conn).name.clone();
        let (from_nid, to_nid) = self.resolve_from_to(what, &conn_name, from, to)?;
        Some((conn_name, from_nid, to_nid))
    }

    /// Dedup gate; `true` = already seen, caller drops silently. Key
    /// is the whole line; the nonce token makes distinct origins
    /// distinct.
    pub(super) fn seen_request(&mut self, body: &[u8]) -> bool {
        // Parsers validated UTF-8; failure → not-seen (handler rejects).
        let Ok(s) = std::str::from_utf8(body) else {
            return false;
        };
        self.seen.check(s, self.timers.now())
    }

    /// Dedup nonce. `OsRng` (overkill, but linked + not hot).
    pub(super) fn nonce() -> u32 {
        OsRng.next_u32()
    }

    /// Vec not iterator: callers `get_mut` while sending; slotmap
    /// borrow would conflict.
    pub(super) fn broadcast_targets(&self, from: Option<ConnId>) -> Vec<ConnId> {
        self.conns
            .iter()
            .filter(|&(id, c)| Some(id) != from && c.active)
            .map(|(id, _)| id)
            .collect()
    }

    /// Re-send to every active conn except `from`. Receivers'
    /// `seen.check` + the `from` skip = loop break.
    pub(super) fn forward_request(&mut self, from: ConnId, body: &[u8]) -> bool {
        // Post-parse; from_utf8 already succeeded.
        let Ok(s) = std::str::from_utf8(body) else {
            log::warn!(target: "tincd::proto",
                       "forward_request: non-UTF-8 body, dropping");
            return false;
        };
        let targets = self.broadcast_targets(Some(from));
        if targets.is_empty() {
            return false;
        }
        log::debug!(target: "tincd::proto",
                    "Forwarding to {} peer(s): {s:?}", targets.len());
        let mut nw = false;
        for id in targets {
            if let Some(c) = self.conns.get_mut(id) {
                nw |= c.send(format_args!("{s}"));
            }
        }
        nw
    }

    /// `from=None` skips nothing; new/dying conn isn't `active` so
    /// filtered anyway. Format once outside loop → one nonce.
    ///
    /// `#[must_use]`: dropping the return is the `97ef5af0` bug class
    /// — line sits in outbuf until the next natural WRITE arm (up to
    /// pinginterval=60s away). Either OR into the caller's `nw`, or
    /// `let _nw =` with a comment pointing at the `maybe_set_write_any`
    /// that covers it.
    #[must_use]
    pub(super) fn broadcast_line(&mut self, line: &str) -> bool {
        let targets = self.broadcast_targets(None);
        let mut nw = false;
        for id in targets {
            if let Some(c) = self.conns.get_mut(id) {
                nw |= c.send(format_args!("{line}"));
            }
        }
        nw
    }

    /// Tunnelserver indirect filter: in tunnelserver mode, gossip about
    /// third parties is dropped. Returns `true` if the message should be
    /// IGNORED (and logs the warning). `about` is the set of node names
    /// the message concerns (1 for subnets, 2 for edges); the message is
    /// allowed iff ANY of them is us or the direct peer `from_conn`.
    /// Call BEFORE `lookup_or_add_node` so indirect names don't pollute
    /// the graph, but AFTER `seen_request` (mark seen even on drop).
    fn tunnelserver_reject_indirect(
        &self,
        from_conn: ConnId,
        kind: &str,
        about: &[&str],
        detail: fmt::Arguments<'_>,
    ) -> bool {
        if !self.settings.tunnelserver {
            return false;
        }
        let conn_name = self.conn(from_conn).name.as_str();
        if about.iter().any(|n| *n == self.name || *n == conn_name) {
            return false;
        }
        log::warn!(target: "tincd::proto",
                   "Ignoring indirect {kind} from {conn_name} {detail}");
        true
    }
}
