//! TX fast-path snapshot state.
//!
//! The `on_device_read` Super arm wants to seal+ship a whole TSO super
//! without N×`forward_packet` reborrows of `&mut Daemon`. The shape that
//! works: a read-only snapshot of the routing state (`TxSnapshot`),
//! built/refreshed at gossip-event sites, consulted once per super
//! ([`tx_probe`]) without touching `&mut self`. On `Some(target)` the
//! seal-send loop ([`seal_super`]) runs over `&target` + the daemon's
//! own `tx_scratch`/`TxBatch`/`egress` — no new state, no new allocs.
//!
//! Wire-identical to the slow path: `handle_based_seal_byte_identical`
//! (tinc-sptps test) proves the bytes; the netns integration tests
//! prove the wiring.
//!
//! ## Why `Arc` push, not `ArcSwap` pull
//!
//! Measured. `ArcSwap::load()` does a `SeqCst` fence + debt-slot dance,
//! called twice per outgoing packet (to-route + via-route): -2.4% on
//! the hot path. Plain `Arc` deref is a pointer chase, identical
//! codegen to `&Vec`. The daemon refreshes the snapshot fields
//! directly at the gossip-event sites; no fence on the read side.
//! Staleness is one event-loop iteration: routes change on edge
//! events, not packets.

// deny (not forbid): bpf::attach needs an explicit #[expect(unsafe_code)]
// for the TUNSETSTEERINGEBPF ioctl.
#![deny(unsafe_code)]

pub mod bpf;
mod probe;
mod punt;
pub(crate) mod runtime;
mod rx;
mod seal;
mod snapshot;
pub(crate) mod worker;
pub(crate) use probe::tx_probe;
pub(crate) use rx::{RxDstMemo, rx_open, rx_probe};
pub(crate) use seal::seal_super;
pub(crate) use snapshot::NodeView;

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::{Arc, Mutex};

use crate::graph::{NodeId, Route};
use tinc_crypto::aead::SptpsCipher;
use tinc_sptps::ReplayWindow;

use crate::inthash::IntHashMap;
use crate::node_id::NodeId6Table;
use crate::subnet_tree::SubnetTree;
use crate::tunnel::TrafficStats;

/// Per-peer fast-path state taken from the live `Sptps` at `HandshakeDone`: the
/// outseqno/replay Arcs (shared with the Sptps), copies of both cipher keys,
/// and the cached `udp_addr`. The daemon and [`TxSnapshot`] hold the same
/// `Arc<TunnelHandles>`; rekey builds a fresh one and the old drops with its
/// last reference. Not `Debug`: live key material.
pub(crate) struct TunnelHandles {
    /// `Sptps::outseqno_handle()`. `fetch_add(n, Relaxed)` per super
    /// (not per packet — one alloc, N seals). Shared with the
    /// control-side `Sptps`; both see the same counter. Relaxed:
    /// seqno uniqueness is the only requirement.
    pub outseqno: Arc<AtomicU64>,

    /// `Sptps::out_key_base()` snapshot. Paired with `outseqno` for
    /// [`tx_probe`]'s [`tinc_sptps::SEAL_KEY_LIMIT`] gate. Immutable
    /// for the lifetime of this `TunnelHandles`.
    pub out_key_base: u64,

    /// `Sptps::replay_handle()`. RX-path: `lock()` + `check_public(seqno)`
    /// per incoming packet after decrypt succeeds. Uncontended in steady
    /// state (each peer's flow lands on one socket). Stored here so the
    /// daemon's mirror lookup works for both TX and RX without a
    /// separate type.
    pub replay: Arc<Mutex<ReplayWindow>>,

    /// Seal-side cipher, built once at `HandshakeDone` from
    /// `(Sptps::aead(), Sptps::outcipher_key())`. Prebuilt because
    /// `SptpsCipher::new` runs the AES-256 key schedule + GHASH
    /// table init — ~5% of RX cycles when done per packet.
    pub outcipher: SptpsCipher,

    /// Open-side cipher. Same story.
    pub incipher: SptpsCipher,

    /// Cached `sendto` target in kernel sockaddr layout plus the listener index to
    /// send from. `None` until UDP is confirmed; [`tx_probe`] then returns `None`
    /// and the slow path runs `choose_udp_address`. `Mutex` rather than atomic (128
    /// bytes); written once from `rx.rs`, read once per super.
    pub udp_addr: Mutex<Option<(socket2::SockAddr, u8)>>,

    /// `false` when control starts a rekey. [`tx_probe`] checks before
    /// seal; on `false`, returns `None` (slow path runs `send_req_key`).
    /// Flipped back to `true` when the new `TunnelHandles` arrives.
    /// `Relaxed` load: a stale `true` seals one packet with the old
    /// key, peer drops it, no harm.
    pub validkey: AtomicBool,

    /// `TunnelState::minmtu()` mirror. The fast-path eligibility gate
    /// (`body_len <= minmtu`). `0` until PMTU discovery converges
    /// (~3.3s) — `0` fails the gate, packet goes slow-path, slow path
    /// drives PMTU. Control `store(Relaxed)` when `pmtu.minmtu`
    /// advances; [`tx_probe`] `load(Relaxed)` at the gate. A stale `0`
    /// means one extra super on the slow path; a stale-high value
    /// means one EMSGSIZE → `on_emsgsize` shrinks. Self-correcting.
    pub minmtu: AtomicU16,

    /// The compression level the peer asked for in `ANS_KEY`. Non-zero means
    /// `send_sptps_packet` must compress the body, which the seal fast path can't,
    /// so it is an eligibility gate. Set before the `Arc` is published and never
    /// changed.
    pub outcompression: u8,

    /// `TunnelState::stats` clone. RX fast-path bumps `in_*` after a
    /// successful `rx_open`; without this the operator sees a frozen
    /// RX counter once the fast path takes over.
    pub stats: Arc<TrafficStats>,
}

/// The Super arm's read-only view of routing state. [`tx_probe`] borrows it
/// while seal+ship needs `&mut self.dp`, so the daemon `mem::take`s it out of
/// `self.tx_snap` for the arm. Fields are assigned directly at gossip-event
/// sites (graph run, `HandshakeDone`, subnet add/del, PMTU advance, UDP addr
/// confirm); stale by at most one loop iteration.
#[derive(Clone)]
pub(crate) struct TxSnapshot {
    /// Spawn-time fold of every config-immutable slow-path gate:
    /// `dns.is_some() | routing_mode != Router | priorityinheritance`.
    /// `any_pcap` is not folded — it flips at runtime; checked live
    /// at the device.rs call site. Set once at setup; never re-read.
    pub slowpath_all: bool,

    /// `Daemon::myself`. The loopback gate (`to == myself`).
    pub myself: NodeId,

    /// `Daemon::myself_options.bits()`. The TCPONLY gate ORs this
    /// with `route.options`.
    pub myself_options: u32,

    /// `[NodeId6::NULL ‖ id6_table.id_of(myself)]`. The 12-byte
    /// prefix every direct-send packet writes at offset 0. Direct
    /// ⇒ dst=NULL; src is always us. Computed
    /// once at setup; the seal loop `copy_from_slice`s it.
    pub id6_prefix: [u8; 12],

    /// `Daemon::name`, set once. [`rx_open`]'s dst-subnet probe only asks whether
    /// the trie's owner string is us, once per memo miss; a string compare is
    /// cheaper than resolving owner→nid as the TX `route()` does.
    pub myself_name: Box<str>,

    /// `id6_table` snapshot for the RX gate chain (`pkt[6..12]` → `NodeId` →
    /// tunnel). Cloned into an `Arc` at gossip rate in `tx_snap_refresh_graph`,
    /// which already runs on every event that changes the table
    /// (`lookup_or_add_node`'s first sighting, `purge`). A node known only via
    /// `ADD_SUBNET` can't send us UDP yet, so that lag is harmless.
    pub id6: Arc<NodeId6Table>,

    /// `last_routes` snapshot. Same Arc the daemon holds; refreshed
    /// at the end of `run_graph_and_log` (one `Arc::clone`, no copy).
    pub routes: Arc<Vec<Option<Route>>>,

    /// Subnet trie snapshot. The daemon's `SubnetTree` is mutated
    /// in-place by gossip; refreshed by clone-into-Arc after each
    /// `add`/`del`. Subnets change rarely; clone cost is fine.
    pub subnets: Arc<SubnetTree>,

    /// Per-nid name/reachable lookup. The route resolve closure
    /// reads this (`ns.resolve(name)`). Refreshed at the end of
    /// `run_graph_and_log` and after `purge` (the only path that
    /// removes from `node_ids` without a follow-up BFS).
    pub ns: Arc<NodeView>,

    /// Per-peer fast-path handles. Same `Arc` the daemon holds in
    /// `tunnel_handles`; inserted at `HandshakeDone`, removed at
    /// `BecameUnreachable`.
    pub tunnels: IntHashMap<NodeId, Arc<TunnelHandles>>,
}

impl TxSnapshot {
    /// Same body as `Daemon::route_of`; same codegen.
    #[inline]
    #[must_use]
    pub(crate) fn route_of(&self, nid: NodeId) -> Option<Route> {
        *self.routes.get(nid.0 as usize)?
    }
}
