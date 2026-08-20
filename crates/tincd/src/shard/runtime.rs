//! Platform-neutral facade over the shard workers; all sharding
//! `cfg(target_os)` lives here. Non-Linux: no-op methods, `resolve()`
//! pinned to 1.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use tinc_conf::Config;

use super::TxSnapshot;
use super::punt::PuntQueue;
use crate::daemon::{DaemonSettings, RoutingMode};

#[cfg(target_os = "linux")]
use super::{bpf, worker};
#[cfg(target_os = "linux")]
use crate::daemon::{IoWhat, ListenerSlot};
#[cfg(target_os = "linux")]
use crate::event::{EventLoop, Io};
#[cfg(target_os = "linux")]
use crate::listen::{SockOpts, open_udp_siblings};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use tinc_device::Device;

/// Effective shard count. >1 needs Linux, TUN + `Interface` set,
/// router mode, and no socket activation; otherwise 1.
pub(crate) fn resolve(settings: &DaemonSettings, config: &Config) -> usize {
    if !cfg!(target_os = "linux") {
        return 1;
    }
    let auto = || std::thread::available_parallelism().map_or(1, |p| p.get().min(4));
    let n = settings.shards.map_or_else(auto, usize::from);
    if n <= 1 {
        return 1;
    }
    // DeviceType unset defaults to tun.
    let tun = config
        .lookup("DeviceType")
        .next()
        .is_none_or(|e| e.get_str().eq_ignore_ascii_case("tun"));
    // Socket activation is fine: systemd adopts TCP only, UDP is
    // always bound by tincd with our own sockopts.
    let ok = tun && settings.routing_mode == RoutingMode::Router;
    if !ok {
        if settings.shards.is_some() {
            log::warn!(target: "tincd",
                "Shards > 1 needs DeviceType=tun and Mode=router; \
                 running single-threaded");
        }
        return 1;
    }
    n
}

/// The spawned workers, or nothing. Dropping stops the threads.
#[derive(Default)]
pub(crate) struct ShardRuntime {
    #[cfg(target_os = "linux")]
    workers: Vec<worker::WorkerHandle>,
}

impl ShardRuntime {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(workers: Vec<worker::WorkerHandle>) -> Self {
        Self { workers }
    }

    /// Publish a routing snapshot to every worker.
    pub(crate) fn publish(&self, snap: &TxSnapshot) {
        #[cfg(target_os = "linux")]
        {
            if self.workers.is_empty() {
                return;
            }
            let snap = Arc::new(snap.clone());
            for w in &self.workers {
                w.mailbox.publish(Arc::clone(&snap));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = snap;
    }

    /// Worker `k`'s punt queue + wake eventfd, as cloned Arcs.
    pub(crate) fn punt_handle(&self, k: usize) -> Option<(Arc<PuntQueue>, Arc<OwnedFd>)> {
        #[cfg(target_os = "linux")]
        {
            let w = self.workers.get(k)?;
            Some((Arc::clone(&w.punt), Arc::clone(&w.punt_efd)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = k;
            None
        }
    }
}

/// Open reuseport siblings, attach the cBPF steer, spawn workers,
/// register their punt eventfds.
#[cfg(target_os = "linux")]
pub(crate) fn spawn_all(
    n: usize,
    tuns: Vec<Box<dyn Device + Send>>,
    listeners: &[ListenerSlot],
    opts: &SockOpts,
    ev: &mut EventLoop<IoWhat>,
) -> std::io::Result<ShardRuntime> {
    debug_assert_eq!(tuns.len(), n - 1);

    // Attach the steering prog only after the whole group is bound so
    // it never selects an index without a socket behind it.
    let mut per_listener: Vec<Vec<OwnedFd>> = Vec::with_capacity(listeners.len());
    for slot in listeners {
        let sibs = open_udp_siblings(&slot.listener, opts, n - 1)?;
        per_listener.push(sibs.into_iter().map(OwnedFd::from).collect());
    }
    for slot in listeners {
        #[expect(clippy::cast_possible_truncation)] // n <= 64
        bpf::attach_reuseport_id6(slot.listener.udp_fd(), n as u32)?;
    }

    let mut workers = Vec::with_capacity(n - 1);
    for (k, tun) in tuns.into_iter().enumerate() {
        let udp: Vec<OwnedFd> = per_listener.iter_mut().map(|v| v.remove(0)).collect();
        let egress = udp
            .iter()
            .map(|fd| {
                let s = socket2::Socket::from(fd.try_clone()?);
                let e = crate::egress::linux::Fast::new(&s)?;
                Ok(Box::new(e) as Box<dyn crate::egress::UdpEgress + Send>)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        workers.push(worker::spawn(k + 1, udp, egress, tun));
    }
    for (i, w) in workers.iter().enumerate() {
        #[expect(clippy::cast_possible_truncation)] // n <= 64
        ev.add(w.punt_efd.as_fd(), Io::Read, IoWhat::ShardPunt(i as u8))?;
    }
    log::info!(target: "tincd", "Sharding: {n} data-plane threads");
    Ok(ShardRuntime::new(workers))
}
