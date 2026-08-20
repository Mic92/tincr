//! Shard worker: one thread per shard, owning one reuseport UDP
//! socket per listener and one multi-queue TUN fd. RX fast path
//! only; everything else punts to the control thread. Routing state
//! arrives as `Arc<TxSnapshot>` via an epoch mailbox, reloaded
//! between batches; per-tunnel state is shared through the
//! `Arc<TunnelHandles>` inside it.

#![cfg(target_os = "linux")]
// Wired into setup in the next commit; see bpf/mod.rs for the same staging.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{MsgFlags, SockaddrStorage, recvmmsg};

use super::punt::{PUNT_SLOT, PuntQueue};
use super::{RxDstMemo, TxSnapshot, rx_open, rx_probe, seal_super, tx_probe};
use crate::egress::{TxBatch, UdpEgress};
use crate::listen::unmap;
use crate::daemon::net::helpers::gro_offer_or_write;
use tinc_device::{Device, DeviceArena, DrainResult, GroBucket, VirtioNetHdr, tso_split};

const RX_BATCH: usize = 64;
const DRAIN_CAP: usize = 64;

pub(crate) struct SnapMailbox {
    epoch: AtomicU64,
    snap: Mutex<Option<Arc<TxSnapshot>>>,
}

impl SnapMailbox {
    pub(crate) fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            snap: Mutex::new(None),
        }
    }

    pub(crate) fn publish(&self, snap: Arc<TxSnapshot>) {
        *self.snap.lock().expect("snap lock") = Some(snap);
        self.epoch.fetch_add(1, Ordering::Release);
    }

    fn load_if_newer(&self, seen: &mut u64) -> Option<Arc<TxSnapshot>> {
        let e = self.epoch.load(Ordering::Acquire);
        if e == *seen {
            return None;
        }
        *seen = e;
        self.snap.lock().expect("snap lock").clone()
    }
}

pub(crate) struct WorkerHandle {
    pub punt: Arc<PuntQueue>,
    /// Written after pushing punts; control drains on wake.
    pub punt_efd: Arc<OwnedFd>,
    pub mailbox: Arc<SnapMailbox>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl WorkerHandle {
    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn worker `idx` (1-based; shard 0 is the control thread).
///
/// # Panics
/// Thread spawn failure.
pub(crate) fn spawn(
    idx: usize,
    udp: Vec<OwnedFd>,
    egress: Vec<Box<dyn UdpEgress + Send>>,
    tun: Box<dyn Device + Send>,
) -> WorkerHandle {
    let punt = Arc::new(PuntQueue::new());
    let punt_efd = Arc::new(
        nix::sys::eventfd::EventFd::from_flags(nix::sys::eventfd::EfdFlags::EFD_NONBLOCK)
            .expect("eventfd")
            .into(),
    );
    let mailbox = Arc::new(SnapMailbox::new());
    let stop = Arc::new(AtomicBool::new(false));

    let h = {
        let punt = Arc::clone(&punt);
        let punt_efd = Arc::clone(&punt_efd);
        let mailbox = Arc::clone(&mailbox);
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name(format!("tinc-shard{idx}"))
            .spawn(move || run(&udp, egress, tun, &punt, &punt_efd, &mailbox, &stop))
            .expect("spawn shard worker")
    };
    WorkerHandle {
        punt,
        punt_efd,
        mailbox,
        stop,
        join: Some(h),
    }
}

struct TxState {
    arena: DeviceArena,
    tso_scratch: Box<[u8]>,
    tso_lens: Box<[usize]>,
    tx_scratch: Vec<u8>,
    batch: TxBatch,
    egress: Vec<Box<dyn UdpEgress + Send>>,
}

fn run(
    udp: &[OwnedFd],
    egress: Vec<Box<dyn UdpEgress + Send>>,
    mut tun: Box<dyn Device + Send>,
    punt: &PuntQueue,
    punt_efd: &OwnedFd,
    mailbox: &SnapMailbox,
    stop: &AtomicBool,
) {
    let mut snap: Option<Arc<TxSnapshot>> = None;
    let mut seen_epoch = 0u64;
    let mut bufs = vec![[0u8; PUNT_SLOT]; RX_BATCH];
    let mut scratch: Vec<u8> = Vec::with_capacity(PUNT_SLOT);
    let mut gro_spare = GroBucket::new();
    let mut tx = TxState {
        arena: DeviceArena::new(DRAIN_CAP),
        tso_scratch: vec![0u8; DRAIN_CAP * DeviceArena::STRIDE].into_boxed_slice(),
        tso_lens: vec![0usize; DRAIN_CAP].into_boxed_slice(),
        tx_scratch: Vec::new(),
        batch: TxBatch::default(),
        egress,
    };

    while !stop.load(Ordering::Relaxed) {
        let mut fds: Vec<PollFd> = udp
            .iter()
            .map(|fd| PollFd::new(fd.as_fd(), PollFlags::POLLIN))
            .collect();
        if let Some(fd) = tun.fd() {
            fds.push(PollFd::new(fd, PollFlags::POLLIN));
        }
        // 100ms cap so stop and snapshot epoch are checked while idle.
        match nix::poll::poll(&mut fds, PollTimeout::from(100u16)) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {
                if let Some(s) = mailbox.load_if_newer(&mut seen_epoch) {
                    snap = Some(s);
                }
                continue;
            }
            Err(e) => {
                log::warn!(target: "tincd::shard", "worker poll: {e}");
                return;
            }
            Ok(_) => {}
        }
        if let Some(s) = mailbox.load_if_newer(&mut seen_epoch) {
            snap = Some(s);
        }

        let mut punted = false;
        let mut gro = Some(std::mem::take(&mut gro_spare));
        for fd in udp {
            punted |= rx_batch(
                fd,
                &mut tun,
                &mut gro,
                snap.as_deref(),
                punt,
                &mut bufs,
                &mut scratch,
            );
        }
        if let Some(mut b) = gro.take() {
            if let Some(buf) = b.flush()
                && let Err(e) = tun.write_super(buf)
            {
                log::debug!(target: "tincd::shard", "gro flush: {e}");
            }
            gro_spare = b;
        }
        if let Err(e) = tun.write_flush() {
            log::debug!(target: "tincd::shard", "tun flush: {e}");
        }
        punted |= tun_drain(&mut tun, snap.as_deref(), punt, &mut tx);
        if punted {
            let one = 1u64.to_ne_bytes();
            let _ = nix::unistd::write(punt_efd.as_fd(), &one);
        }
    }
}

/// Drain the worker's TUN queue: supers go through the seal-send fast
/// path, everything else punts. Returns whether anything was punted.
fn tun_drain(
    tun: &mut Box<dyn Device + Send>,
    snap: Option<&TxSnapshot>,
    punt: &PuntQueue,
    tx: &mut TxState,
) -> bool {
    let mut punted = false;
    for _ in 0..DRAIN_CAP {
        match tun.drain(&mut tx.arena, DRAIN_CAP) {
            Ok(DrainResult::Empty) | Err(_) => break,
            Ok(DrainResult::Frames { count }) => {
                for i in 0..count {
                    punted |= punt.push(tx.arena.slot(i), None);
                }
                if count > 1 {
                    break;
                }
            }
            Ok(DrainResult::Super {
                len,
                gso_size,
                gso_type,
                csum_start,
                csum_offset,
            }) => {
                let hdr = VirtioNetHdr {
                    flags: 0,
                    gso_type: 0,
                    hdr_len: 0,
                    gso_size,
                    csum_start,
                    csum_offset,
                };
                let Ok(count) = tso_split(
                    &tx.arena.as_contiguous()[..len],
                    &hdr,
                    gso_type,
                    &mut tx.tso_scratch,
                    DeviceArena::STRIDE,
                    &mut tx.tso_lens,
                ) else {
                    break;
                };
                punted |= tx_super(snap, punt, tx, count);
                break;
            }
        }
    }
    punted
}

/// Seal-send one split super; punts the segments when the fast path
/// doesn't apply.
fn tx_super(snap: Option<&TxSnapshot>, punt: &PuntQueue, tx: &mut TxState, count: usize) -> bool {
    #[expect(clippy::cast_possible_truncation)] // count <= DRAIN_CAP
    let target = snap.and_then(|s| tx_probe(s, &tx.tso_scratch[..tx.tso_lens[0]], count as u32));
    if let Some(target) = target
        && let Some(egress) = tx.egress.get_mut(usize::from(target.sock))
    {
        let r = seal_super(
            &target,
            DeviceArena::STRIDE,
            &tx.tso_lens[..count],
            &tx.tso_scratch,
            &mut tx.tx_scratch,
            &mut tx.batch,
            egress.as_mut(),
        );
        match r {
            Ok(ok) => {
                target.handles.stats.add_out(ok.packets, ok.bytes);
                return false;
            }
            Err(_) => return false, // EMSGSIZE: dropped, control's probes re-shrink
        }
    }
    let mut punted = false;
    for i in 0..count {
        let off = i * DeviceArena::STRIDE;
        punted |= punt.push(&tx.tso_scratch[off..off + tx.tso_lens[i]], None);
    }
    punted
}

/// One `recvmmsg` + fast-path dispatch. Returns whether anything was punted.
fn rx_batch(
    udp: &OwnedFd,
    tun: &mut Box<dyn Device + Send>,
    gro: &mut Option<GroBucket>,
    snap: Option<&TxSnapshot>,
    punt: &PuntQueue,
    bufs: &mut [[u8; PUNT_SLOT]],
    scratch: &mut Vec<u8>,
) -> bool {
    let metas: Vec<(usize, Option<SocketAddr>)> = {
        let mut iovs: Vec<[std::io::IoSliceMut<'_>; 1]> = bufs
            .iter_mut()
            .map(|b| [std::io::IoSliceMut::new(&mut b[..])])
            .collect();
        let mut data =
            nix::sys::socket::MultiHeaders::<SockaddrStorage>::preallocate(RX_BATCH, None);
        match recvmmsg(
            udp.as_raw_fd(),
            &mut data,
            &mut iovs,
            MsgFlags::MSG_DONTWAIT,
            None,
        ) {
            Ok(msgs) => msgs
                .map(|m| (m.bytes, m.address.as_ref().and_then(sockaddr_to_std)))
                .collect(),
            Err(nix::errno::Errno::EAGAIN) => return false,
            Err(e) => {
                log::warn!(target: "tincd::shard", "worker recvmmsg: {e}");
                return false;
            }
        }
    };
    let mut punted = false;
    let mut memo = RxDstMemo::default();
    for (i, &(n, src)) in metas.iter().enumerate() {
        if n == 0 {
            continue;
        }
        let pkt = &bufs[i][..n];
        if let Some(s) = snap
            && let Some(target) = rx_probe(s, pkt)
            && let Ok(len) = rx_open(&target, s, scratch, &mut memo)
        {
            target.handles.stats.add_in(1, len as u64);
            gro_offer_or_write(&mut **tun, gro, &mut scratch[..len]);
            continue;
        }
        let Some(src) = src else { continue };
        punted |= punt.push(pkt, Some(unmap(src)));
    }
    punted
}

fn sockaddr_to_std(ss: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(sin) = ss.as_sockaddr_in() {
        return Some(SocketAddr::V4(std::net::SocketAddrV4::new(
            sin.ip(),
            sin.port(),
        )));
    }
    ss.as_sockaddr_in6().map(|sin6| {
        SocketAddr::V6(std::net::SocketAddrV6::new(
            sin6.ip(),
            sin6.port(),
            sin6.flowinfo(),
            sin6.scope_id(),
        ))
    })
}
