//! Shard worker executor: one thread per shard, owning one reuseport
//! UDP socket and one multi-queue TUN fd. RX fast path only so far;
//! everything else goes to the control thread via [`PuntQueue`].
//!
//! Control publishes routing state as `Arc<TxSnapshot>` through a
//! mailbox (epoch counter + mutex); workers reload it between
//! batches, never mid-packet. Per-tunnel state (seqno, replay,
//! stats, `udp_addr`) is shared via the `Arc<TunnelHandles>` inside
//! the snapshot, so worker and control stay coherent without any
//! new synchronization.

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
use super::{RxDstMemo, TxSnapshot, rx_open, rx_probe};
use tinc_device::Device;

const RX_BATCH: usize = 64;

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
    /// Worker writes 1 here after pushing punts; control's event loop
    /// registers the fd and drains on wake.
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

/// Spawn shard worker `idx` (1-based; shard 0 is the control thread).
///
/// # Panics
/// Thread spawn failure (out of threads/memory).
pub(crate) fn spawn(
    idx: usize,
    udp: OwnedFd,
    tun: Box<dyn Device + Send>,
    sock_slot: u8,
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
            .spawn(move || run(&udp, tun, sock_slot, &punt, &punt_efd, &mailbox, &stop))
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

fn run(
    udp: &OwnedFd,
    mut tun: Box<dyn Device + Send>,
    sock_slot: u8,
    punt: &PuntQueue,
    punt_efd: &OwnedFd,
    mailbox: &SnapMailbox,
    stop: &AtomicBool,
) {
    let mut snap: Option<Arc<TxSnapshot>> = None;
    let mut seen_epoch = 0u64;
    let mut bufs = vec![[0u8; PUNT_SLOT]; RX_BATCH];
    let mut scratch: Vec<u8> = Vec::with_capacity(PUNT_SLOT);

    while !stop.load(Ordering::Relaxed) {
        let mut fds = [PollFd::new(udp.as_fd(), PollFlags::POLLIN)];
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

        let mut iovs: Vec<[std::io::IoSliceMut<'_>; 1]> = bufs
            .iter_mut()
            .map(|b| [std::io::IoSliceMut::new(&mut b[..])])
            .collect();
        let mut data = nix::sys::socket::MultiHeaders::<SockaddrStorage>::preallocate(RX_BATCH, None);
        let msgs = match recvmmsg(
            udp.as_raw_fd(),
            &mut data,
            &mut iovs,
            MsgFlags::MSG_DONTWAIT,
            None,
        ) {
            Ok(m) => m,
            Err(nix::errno::Errno::EAGAIN) => continue,
            Err(e) => {
                log::warn!(target: "tincd::shard", "worker recvmmsg: {e}");
                continue;
            }
        };

        let mut punted = false;
        let mut memo = RxDstMemo::default();
        let metas: Vec<(usize, Option<SocketAddr>)> = msgs
            .map(|m| {
                let n = m.bytes;
                let src = m.address.as_ref().and_then(sockaddr_to_std);
                (n, src)
            })
            .collect();
        for (i, &(n, src)) in metas.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let pkt = &bufs[i][..n];
            if let Some(s) = snap.as_ref()
                && let Some(target) = rx_probe(s, pkt)
                && let Ok(len) = rx_open(&target, s, &mut scratch, &mut memo)
            {
                target.handles.stats.add_in(1, len as u64);
                if let Err(e) = tun.write_stage(&mut scratch[..len]) {
                    log::debug!(target: "tincd::shard", "tun write: {e}");
                }
                continue;
            }
            let Some(src) = src else { continue };
            punted |= punt.push(pkt, src, sock_slot);
        }
        if let Err(e) = tun.write_flush() {
            log::debug!(target: "tincd::shard", "tun flush: {e}");
        }
        if punted {
            let one = 1u64.to_ne_bytes();
            let _ = nix::unistd::write(punt_efd.as_fd(), &one);
        }
    }
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
