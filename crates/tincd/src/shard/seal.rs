//! TX fast-path seal-send: the per-chunk loop body.
//!
//! [`tx_probe`](super::tx_probe) decided this super CAN take the fast
//! path and burned the seqnos. This module does the per-chunk seal +
//! `TxBatch` stage + ship-on-full + final ship. No `&mut Daemon`, no
//! `Sptps` borrow — `ChaPoly::new(&handles.outkey)` directly.
//!
//! Wire-identical to the slow path's `seal_data_into` →
//! `send_sptps_data_relay` → `ship_tx_batch` chain because:
//!   - `ChaPoly::seal_into` IS what `Sptps::seal_with_seqno` calls
//!     internally; we just inline the prefix/seqno header writes
//!   - same `TxBatch::can_coalesce`/`stage`/`take` calls, same
//!     `(dst, sock, relay, origlen)` tuple, same egress trait
//!   - `PKT_NORMAL` only ([`tx_probe`](super::tx_probe) gates
//!     `outcompression == 0`)

use super::probe::TxTarget;
use crate::daemon::PKT_NORMAL;
use crate::egress::{TxBatch, UdpEgress};
use crate::graph::NodeId;
use tinc_crypto::chapoly::ChaPoly;

/// Stats for the daemon's `myself_tunnel.out_{packets,bytes}` and the
/// per-dst tunnel counters. `bytes` is sum of BODY lengths (the inner
/// IP packet — what `route_packet` would have counted), not on-wire
/// (which is `bytes + packets×33`).
pub(crate) struct SealOk {
    pub packets: u64,
    pub bytes: u64,
}

/// `EMSGSIZE` from `send_batch`. `(relay, origlen)` is exactly what
/// `TxBatch::take()` returned — caller dispatches `on_emsgsize`.
pub(crate) type SealErr = (NodeId, u16);

/// Seal every chunk strided into `scratch_in`, stage into `batch`,
/// ship-on-full, final-ship at the end. One `ChaPoly` per super (key
/// copy + state init); seqno-per-chunk varies.
///
/// `lens[i]` is the FRAME length of chunk i (eth header included);
/// chunks are at `scratch_in[i*stride .. i*stride + lens[i]]`.
/// `tso_split` writes `[eth:14 ‖ ip]` per slot; the slow path strips
/// at the seal site (`sptps.rs:24` offset=14, Router mode); we strip
/// here. [`tx_probe`](super::tx_probe) gates `slowpath_all` on
/// `!= Router`, so offset is always 14.
///
/// `tx_scratch` is cleared+reused per chunk — same buffer the slow
/// path uses (`dp.tx_scratch`), so no new alloc.
///
/// # Errors
/// `EMSGSIZE` from `send_batch` — PMTU shrank under us. The batch IS
/// reset (`ship` always resets on take). EMSGSIZE may have happened
/// mid-super: frames before it shipped fine, frames after it never
/// sealed. Same loss profile as `ship_tx_batch`; inner-TCP retransmits.
///
/// # Panics
/// `tx_scratch.len() != 16` at the `seal_into` call — i.e. `prefix`
/// isn't 12 bytes. It always is (`TxTarget.prefix: [u8; 12]`).
#[expect(clippy::cast_possible_truncation)] // body_len ≤ MTU < u16::MAX
pub(crate) fn seal_super(
    target: &TxTarget,
    stride: usize,
    lens: &[usize],
    scratch_in: &[u8],
    tx_scratch: &mut Vec<u8>,
    batch: &mut TxBatch,
    egress: &mut dyn UdpEgress,
) -> Result<SealOk, SealErr> {
    let cipher = ChaPoly::new(&target.handles.outkey);
    let mut bytes = 0u64;

    for (i, &len) in lens.iter().enumerate() {
        let off = i * stride;
        // Body: frame minus eth header. tso_split guarantees len > 14
        // (frame_len = ETH_HLEN + total_len, total_len ≥ iphlen ≥ 20).
        let body = &scratch_in[off + 14..off + len];
        let body_len = len - 14;
        // i < lens.len() ≤ DEVICE_DRAIN_CAP = 64; `as u32` is fine.
        let seqno = target.seqno_base.wrapping_add(i as u32);

        // prefix(12) + seqno BE(4) → encrypt_from = 16. `seal_into`
        // debug-asserts `tx_scratch.len() == 16` on entry.
        tx_scratch.clear();
        tx_scratch.extend_from_slice(&target.prefix);
        tx_scratch.extend_from_slice(&seqno.to_be_bytes());
        cipher.seal_into(u64::from(seqno), PKT_NORMAL, body, tx_scratch, 16);
        // tx_scratch.len() == 16 + 1 + body_len + 16 == body_len + 33

        // Ship-on-full BEFORE stage. `can_coalesce` returns true for
        // empty, so first iteration always falls through to stage.
        // `target.sock`: daemon picks the listener's egress; the
        // sock recorded in `batch` must match the egress passed to
        // `ship`.
        if !batch.can_coalesce(&target.dst, target.sock, tx_scratch.len()) {
            ship(batch, egress)?;
        }
        // `origlen` is PRE-encrypt body — what PMTU is measured at.
        // Same value the slow path passes (`len - offset` after the
        // eth strip), so EMSGSIZE → on_emsgsize(origlen) caps the
        // same maxmtu the next probe round will read.
        batch.stage(
            &target.dst,
            target.sock,
            target.to_nid,
            body_len as u16,
            tx_scratch,
        );
        bytes += body_len as u64;
    }

    ship(batch, egress)?;
    Ok(SealOk {
        packets: lens.len() as u64,
        bytes,
    })
}

/// `take` → `send_batch` → `reset`, with the borrow-ordering dance
/// (`EgressBatch<'_>` borrows `batch.buf`; can't `reset` while alive).
/// `WouldBlock` and other-errors are dropped+logged here; only
/// `EMSGSIZE` propagates because only it needs caller-side state
/// (PMTU). UDP is unreliable; dropped frames retransmit at TCP layer.
fn ship(batch: &mut TxBatch, egress: &mut dyn UdpEgress) -> Result<(), SealErr> {
    let Some((b, _sock, relay, origlen)) = batch.take() else {
        return Ok(());
    };
    // `b` borrows `batch.buf`; let it fall out of scope before `reset`
    // mutates. Same scoping as `ship_tx_batch` (device.rs).
    let r = {
        let r = egress.send_batch(&b);
        let _ = b;
        r
    };
    batch.reset();
    match r {
        Err(e) if e.raw_os_error() == Some(nix::Error::EMSGSIZE as i32) => Err((relay, origlen)),
        // sndbuf full. GSO send is all-or-nothing (`udp_send_skb`);
        // no partial-accept to recover. Same as `ship_tx_batch`.
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => {
            log::warn!(target: "tincd::net", "fast-path sendmsg: {e}");
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}
