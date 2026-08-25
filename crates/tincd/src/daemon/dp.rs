//! `DataPlane` — the per-packet half of `Daemon`.
//!
//! Everything here is touched on the per-packet send/recv paths and
//! NOTHING here is touched by the gossip/meta-conn/timer machinery
//! *except* `tunnels` — grep `self.dp.tunnels` outside `net/` and
//! `tx_control` to find those sites. Making them `self.dp.tunnels` instead
//! of `self.tunnels` is the point: the boundary between "touches the
//! data plane" and "touches gossip/conn state" is now grep-visible.

use crate::graph::NodeId;
use tinc_device::{DeviceArena, GroBucket};

use crate::compress;
use crate::egress::TxBatch;
use crate::inthash::IntHashMap;
use crate::tunnel::TunnelState;

use super::net;

/// Data-plane state. The per-packet hot loop reads and writes only
/// this struct + `last_routes` (an `Arc` snapshot, read-only) +
/// `myself: NodeId` (Copy) + `listeners` (the UDP socket fd table).
///
/// Not `Default` — `gro_enabled` is platform-derived at setup, and
/// the scratch capacities are MTU-derived. `setup.rs` builds this
/// the same way it built the inline fields before.
pub(crate) struct DataPlane {
    /// Data-plane half, separate from `nodes` because the lifecycles differ:
    /// `TunnelState` exists for any reachable node, including ones we only reach
    /// via a nexthop's conn. Lazily created via `entry().or_default()` when
    /// `send_req_key` starts a tunnel. Gossip-side accesses show up as
    /// `self.dp.tunnels`, keeping the hot-path boundary grep-visible.
    pub tunnels: IntHashMap<NodeId, TunnelState>,

    /// `choose_udp_address` cycle counter. 2-of-3 calls explore an
    /// edge address; 1-of-3 sticks with the reflexive. Not random —
    /// a strict cycle. One global counter, not per-node.
    pub choose_udp_x: u8,

    /// `compression.h` state. Persistent compress/decompress
    /// dictionaries. `Compressor::new()` does the setup;
    /// adding persistent `z_stream` state doesn't churn wire-up sites.
    pub compressor: compress::Compressor,

    /// Reused send-side scratch: `seal_data_into` writes `[0;12] ‖ SPTPS-datagram`,
    /// `send_sptps_data_relay` overwrites the prefix with `dst_id6 ‖ src_id6` and
    /// sends the buffer. Cleared between packets, so after the first MTU-sized
    /// packet the send path allocates nothing.
    pub tx_scratch: Vec<u8>,

    /// Inner-packet TOS set by `forward_packet`, read by the UDP send
    /// path. Single-threaded so a field works in lieu of threading
    /// it via a packet struct. Reset to 0 at the top of each
    /// `forward_packet`.
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

    /// GRO TUN-write coalescer: armed by `recvmmsg_batch`, offered each
    /// inbound-for-us packet by `send_packet_myself`, flushed after dispatch.
    /// `None` outside the batch loop, in which case the send site writes
    /// immediately (ICMP replies, broadcast echo). `mem::take`n like `rx_scratch`
    /// to dodge the `&mut self` conflict.
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

    /// Slot arena for `Device::drain`: frames land in slots and the loop body walks
    /// them; the encrypt path still uses `tx_scratch`. `Option` for the `mem::take`
    /// dance, since `forward_packet` borrows `&mut self` while a slot is borrowed.
    pub device_arena: Option<DeviceArena>,

    /// `tso_split` output scratch: a `DrainResult::Super` in `device_arena` is
    /// split into N eth frames here (input and output can't alias). Sized
    /// `DEVICE_DRAIN_CAP * STRIDE`, enough for a 64KB super at MSS 1400. `None`
    /// until the first `Super`; same `mem::take` dance as the arena.
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
