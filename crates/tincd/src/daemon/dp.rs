//! `DataPlane` — the per-packet half of `Daemon`.
//!
//! Everything here is touched on the per-packet send/recv paths and
//! NOTHING here is touched by the gossip/meta-conn/timer machinery
//! *except* `tunnels` — grep `self.dp.tunnels` outside `net/` and
//! `txpath` to find those sites. Making them `self.dp.tunnels` instead
//! of `self.tunnels` is the point: the boundary between "touches the
//! data plane" and "touches gossip/conn state" is now grep-visible.

use tinc_device::{DeviceArena, GroBucket};
use crate::graph::NodeId;

use crate::compress;
use crate::egress::TxBatch;
use crate::inthash::IntHashMap;
use crate::tunnel::TunnelState;

use super::net;

/// Data-plane state. The per-packet hot loop reads and writes ONLY
/// this struct + `last_routes` (an `Arc` snapshot, read-only) +
/// `myself: NodeId` (Copy) + `listeners` (the UDP socket fd table).
///
/// Not `Default` — `gro_enabled` is platform-derived at setup, and
/// the scratch capacities are MTU-derived. `setup.rs` builds this
/// the same way it built the inline fields before.
pub(crate) struct DataPlane {
    /// Data-plane half. Separate from `nodes`/`NodeState` because
    /// the lifecycles differ — `TunnelState` exists for ANY
    /// reachable node (we send UDP to nodes we have no TCP
    /// connection to, forwarding the handshake via nexthop's conn).
    ///
    /// `entry().or_default()` lazy-init: a node learned from
    /// `ADD_EDGE` has no tunnel until `send_req_key` starts one.
    ///
    /// Gossip-side accesses (`gossip.rs`, `metaconn.rs`) appear as
    /// `self.dp.tunnels` outside the hot-path modules — the boundary
    /// between gossip-triggered tunnel state changes and per-packet
    /// reads is now grep-visible.
    pub tunnels: IntHashMap<NodeId, TunnelState>,

    /// `choose_udp_address` cycle counter. 2-of-3 calls explore an
    /// edge address; 1-of-3 sticks with the reflexive. NOT random —
    /// a strict cycle. One global counter, not per-node.
    pub choose_udp_x: u8,

    /// `compression.h` state. Persistent compress/decompress
    /// dictionaries. `Compressor::new()` does the setup;
    /// adding persistent `z_stream` state doesn't churn wire-up sites.
    pub compressor: compress::Compressor,

    /// Reused send-side scratch for the UDP data path. `seal_data_into`
    /// writes `[0;12] ‖ SPTPS-datagram` here; `send_sptps_data_relay`
    /// then overwrites the 12-byte prefix with `[dst_id6 ‖ src_id6]`
    /// in-place and `sendto`s the whole thing. Cleared (not freed)
    /// between packets — after the first packet at MTU, capacity is
    /// `12 + MTU + 21` and stays there. Net: zero allocs on the
    /// per-packet send path. Can't VLA in Rust; an owned Vec is the
    /// closest equivalent to a stack arena.
    pub tx_scratch: Vec<u8>,

    /// Inner-packet TOS set by `route_packet`, read by the UDP send
    /// path. Single-threaded so a field works in lieu of threading
    /// it via a packet struct. Reset to 0 at the top of each
    /// `route_packet`.
    pub tx_priority: u8,

    /// Reused recv-side scratch for the UDP data path. Mirror of
    /// `tx_scratch`. `open_data_into` writes `[0;14] ‖ decrypted-body`
    /// here; `receive_sptps_record` then overwrites `[12..14]` with
    /// the synthesized ethertype in-place and routes the whole slice.
    /// Cleared (not freed) between packets — after the first packet at
    /// MTU, capacity is `14 + MTU` and stays there. Net: zero allocs on
    /// the per-packet receive path.
    pub rx_scratch: Vec<u8>,

    /// RX fast-path decrypt scratch. Separate from `rx_scratch` so
    /// fast/slow paths interleave in one batch without contention
    /// (slow path takes `rx_scratch` internally; touching the same
    /// Vec from the dispatch loop would race the take/restore).
    /// Same growth pattern: ~14+MTU after first packet, then zero
    /// allocs. Taken per batch in `recvmmsg_batch`.
    pub rx_fast_scratch: Vec<u8>,

    /// recvmmsg batch state (~108KB). Heap-allocated once at setup.
    /// `Option` so `on_udp_recv` can `mem::take` it (the bufs borrow
    /// fights `&mut self` for `handle_incoming_vpn_packet`; same
    /// dance as `rx_scratch`).
    pub udp_rx_batch: Option<net::UdpRxBatch>,

    /// GRO TUN-write coalescer.
    /// `recvmmsg_batch` arms it; `send_packet_myself` offers each
    /// inbound-for-us packet; the post-dispatch flush ships the
    /// super. Same `mem::take`-out-of-self dance as `rx_scratch`
    /// (`send_packet_myself` is `&mut self` and the bucket borrow
    /// would conflict). `None` outside the batch loop — the send
    /// site checks: `Some` ⇒ try coalesce, `None` ⇒ immediate write
    /// (the ICMP-reply / broadcast-echo / kernel-mode paths, which
    /// hit `send_packet_myself` outside any UDP recv batch).
    pub gro_bucket: Option<GroBucket>,

    /// Persistent backing for `gro_bucket`. `GroBucket::new()` heap-
    /// allocs 64KB; doing that per recvmmsg batch (the original
    /// `then(GroBucket::new)` sketch) would be ~10k allocs/sec at
    /// line rate. Same heap-once pattern as `udp_rx_batch`.
    /// `recvmmsg_batch` parks it in `gro_bucket` for the dispatch
    /// loop, then puts it back here. `flush()` resets internal
    /// state; the 64KB stays.
    pub gro_bucket_spare: Option<GroBucket>,

    /// Whether `device.write_super()` works. Linux TUN with
    /// `IFF_VNET_HDR` (the only backend that overrides the trait
    /// default). Captured at setup so the hot path doesn't dyn-
    /// dispatch a `mode()` call per packet.
    pub gro_enabled: bool,

    /// Slot arena for `Device::drain`. Replaces `on_device_read`'s 1.5KB stack buf: drain reads
    /// frames into slots, the loop body walks them. Phase 1 widens:
    /// encrypt into slots, hand the contiguous run to `egress`.
    /// Phase 0 only uses it on the read side; `tx_scratch` stays
    /// for the encrypt path until Phase 1 unifies them (separate
    /// buffers, no overlap).
    ///
    /// `Option` for the same `mem::take` dance as `udp_rx_batch`:
    /// `route_packet` borrows `&mut self`; the arena slot borrow
    /// conflicts. Take, walk, put back.
    pub device_arena: Option<DeviceArena>,

    /// `tso_split` output scratch.
    /// `DrainResult::Super` means the device put a ≤64KB IP super-
    /// segment in `device_arena`; `tso_split` writes N × ~1500B
    /// eth frames into THIS buffer (the input slice can't overlap
    /// the output — same arena would alias). Same `mem::take` dance:
    /// `route_packet` borrows `&mut self`, the slot borrow conflicts.
    ///
    /// Sized at `DEVICE_DRAIN_CAP * STRIDE` = 64*1600 = 100KB. A
    /// 64KB super-segment at MSS 1400 = 47 segments; fits with room.
    /// `None` until the first `Super` arrives (the non-vnet path
    /// never allocates this).
    pub tso_scratch: Option<Box<[u8]>>,

    /// Per-segment lengths from `tso_split`. Same lifetime as
    /// `tso_scratch`; same lazy alloc.
    pub tso_lens: Box<[usize]>,

    /// TX batch accumulator. The `on_device_read` drain loop stages
    /// encrypted frames here instead of `sendto`-per-frame; one
    /// `EgressBatch` ships the run after the loop. Allocated once at
    /// setup (~64KB) and reused warm. Storage only — the
    /// stage-vs-immediate-send gate is `tx_batch_live`.
    pub tx_batch: TxBatch,

    /// "Inside `on_device_read`'s drain loop": `send_sptps_data_relay`
    /// stages when true, sends immediately when false. Separate from
    /// `tx_batch` so the buffer survives across calls; conflating the
    /// two either reallocs every burst or leaks the gate.
    pub tx_batch_live: bool,
}
