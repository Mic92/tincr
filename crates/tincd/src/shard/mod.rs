//! TX fast-path snapshot state.
//!
//! The `on_device_read` Super arm wants to seal+ship a whole TSO super
//! without N×`route_packet` reborrows of `&mut Daemon`. The shape that
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

// deny (not forbid): bpf::attach needs an explicit #[allow(unsafe_code)]
// for the TUNSETSTEERINGEBPF ioctl.
#![deny(unsafe_code)]

pub mod bpf;
mod probe;
mod rx;
mod seal;
mod snapshot;
pub(crate) use probe::tx_probe;
pub(crate) use rx::{RxDstMemo, rx_open, rx_probe};
pub(crate) use seal::seal_super;
pub(crate) use snapshot::NodeView;

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::{Arc, Mutex};

use tinc_graph::{NodeId, Route};
use tinc_sptps::ReplayWindow;

use crate::inthash::IntHashMap;
use crate::node_id::NodeId6Table;
use crate::subnet_tree::SubnetTree;

/// ChaCha20-Poly1305 cipher key length. Re-stated here (not re-exported
/// by `tinc-sptps`) to keep the `TunnelHandles` key fields fixed-size.
const CIPHER_KEY_LEN: usize = 64;

// ────────────────────────────────────────────────────────────────────
// TunnelHandles — shared per-peer fast-path state

/// Per-peer fast-path state cloned out of the live `Sptps` at
/// `HandshakeDone` time. The daemon holds `Arc<TunnelHandles>` per
/// peer; the [`TxSnapshot`] holds a copy of the same `Arc`.
///
/// Built from `Sptps`: take `outseqno_handle()`/`replay_handle()`
/// (clone the existing Arcs inside the Sptps — both views see the
/// same counter), snapshot `outcipher_key()`/`incipher_key()`, copy
/// the cached `udp_addr`. On rekey: build a fresh `TunnelHandles`,
/// swap; the old `Arc` drops when the last reference goes.
///
/// Not `Debug`: holds live key material.
pub(crate) struct TunnelHandles {
    /// `Sptps::outseqno_handle()`. `fetch_add(n, Relaxed)` per super
    /// (not per packet — one alloc, N seals). Shared with the
    /// control-side `Sptps`; both see the same counter. Relaxed:
    /// seqno uniqueness is the only requirement.
    pub outseqno: Arc<AtomicU64>,

    /// `Sptps::replay_handle()`. RX-path: `lock()` + `check_public(seqno)`
    /// per incoming packet AFTER decrypt succeeds. Uncontended in steady
    /// state (each peer's flow lands on one socket). Stored here so the
    /// daemon's mirror lookup works for both TX and RX without a
    /// separate type.
    pub replay: Arc<Mutex<ReplayWindow>>,

    /// `Sptps::outcipher_key()` snapshot. Seal-side. Copied at
    /// `HandshakeDone`; [`seal_super`] builds its own `ChaPoly` from
    /// this — no `Arc<ChaPoly>` refcount traffic at high seal rates.
    pub outkey: [u8; CIPHER_KEY_LEN],

    /// `Sptps::incipher_key()` snapshot. Open-side. Same story.
    pub inkey: [u8; CIPHER_KEY_LEN],

    /// Cached `sendto` target. `socket2::SockAddr` not `std::net`
    /// because `sendto` wants the kernel sockaddr layout. The `u8` is
    /// the listen-socket index (which UDP socket to send from). `None`
    /// when UDP isn't confirmed yet — [`tx_probe`] returns `None`
    /// (slow path drives `choose_udp_address`).
    ///
    /// `Mutex` not atomic: `SockAddr` is 128 bytes. Written once when
    /// the first valid UDP packet arrives (`rx.rs`); read once per
    /// super by [`tx_probe`]. Uncontended.
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

    /// `tunnel.outcompression`. The level the PEER asked for in
    /// `ANS_KEY`. Non-zero ⇒ `send_sptps_packet` mutates the body
    /// (compress, set `PKT_COMPRESSED`); the seal-send fast path
    /// can't do that without `&mut Compressor`. Gate at eligibility:
    /// `outcompression != 0` ⇒ slow path. Set once at `HandshakeDone`
    /// from `ANS_KEY`; never changes mid-session. Not atomic: written
    /// once before the `Arc` is published, happens-before via
    /// `Arc::new`/send.
    pub outcompression: u8,

    /// `TunnelState::stats` clone. RX fast-path bumps `in_*` after a
    /// successful `rx_open`; without this the operator sees a frozen
    /// RX counter once the fast path takes over.
    pub stats: Arc<crate::tunnel::TrafficStats>,
}

// ────────────────────────────────────────────────────────────────────
// TxSnapshot — the fast-path's read-only view of routing state

/// The Super arm's read-only snapshot. [`tx_probe`] takes
/// `&TxSnapshot`; the seal+ship needs `&mut self.dp`/`&mut listeners`
/// alongside, so the daemon `mem::take`s this out of `self.tx_snap`
/// for the duration of the Super arm — same dance as `device_arena`/
/// `tso_scratch`.
///
/// Fields are refreshed at gossip-event sites (post-`run_graph_and_log`,
/// `HandshakeDone`, `ADD_SUBNET`/`DEL_SUBNET`, PMTU advance, UDP addr
/// confirm). Direct field assigns; no channels, no fences. Stale by
/// at most one event-loop iteration.
///
pub(crate) struct TxSnapshot {
    /// Spawn-time fold of every config-immutable slow-path gate:
    /// `dns.is_some() | routing_mode != Router | priorityinheritance`.
    /// `any_pcap` is NOT folded — it flips at runtime; checked live
    /// at the device.rs call site. Set once at setup; never re-read.
    pub slowpath_all: bool,

    /// `Daemon::myself`. The loopback gate (`to == myself`).
    pub myself: NodeId,

    /// `Daemon::myself_options.bits()`. The TCPONLY gate ORs this
    /// with `route.options`.
    pub myself_options: u32,

    /// `[NodeId6::NULL ‖ id6_table.id_of(myself)]`. The 12-byte
    /// prefix every direct-send packet writes at offset 0. Direct
    /// ⇒ dst=NULL (`net_packet.c:1015`); src is always us. Computed
    /// once at setup; the seal loop `copy_from_slice`s it.
    pub id6_prefix: [u8; 12],

    /// `Daemon::name`. The dst-subnet probe in [`rx_open`] resolves
    /// the trie's owner string to "is this me?" by string compare.
    /// One compare per memo MISS (≈ once per recvmmsg batch for a
    /// unidirectional flow). The TX path's `route()` doesn't need
    /// this — it resolves owner→nid via `ns.resolve()` and compares
    /// nids — but the RX path only cares about myself/not-myself
    /// (everything else is slow-path forwarding) so a string compare
    /// is cheaper than a hashmap probe + nid compare. Set once at
    /// setup; never changes.
    pub myself_name: Box<str>,

    /// `id6_table` snapshot. The RX gate chain reads `pkt[6..12]`
    /// (`src_id6`), looks it up here → `NodeId`, then `tunnels.get()`.
    /// Same `Arc::new(clone())` pattern as `subnets`: O(nodes) clone
    /// at gossip-rate. Refreshed in `tx_snap_refresh_graph` — the
    /// table only changes on `lookup_or_add_node` (which only does
    /// real work on the FIRST `ADD_EDGE`/`ADD_SUBNET` mentioning a
    /// new name) and `purge`, both of which already run that hook.
    /// A node learned via `ADD_SUBNET` alone (no edge) cannot send
    /// us UDP — unreachable — so the lag between subnet-learn and
    /// edge-learn-triggers-refresh is harmless.
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
