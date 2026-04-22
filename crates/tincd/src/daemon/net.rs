// Re-export: device.rs body references `super::ListenerSlot`.
pub(super) use super::ListenerSlot;

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(target_os = "linux")]
use nix::sys::socket::MultiHeaders;
use nix::sys::socket::SockaddrStorage;

mod device;
mod helpers;
mod icmp;
mod route;
mod rx;
mod sptps;

pub(super) const UDP_RX_BATCH: usize = 64;

/// Device drain cap. `pub(super)` so `daemon::setup` can size the
/// arena. The 64-per-turn-then-yield is load-bearing (`0f120b11`:
/// over-draining starves the TUN reader of TX time — iperf3
/// saturating the device must not block UDP recv/meta-conn flush).
pub(super) const DEVICE_DRAIN_CAP: usize = 64;
/// Wire packets cap ~1700; 2KB oversize truncates and the SPTPS
/// decrypt fails (same outcome as the old stack buf).
pub(super) const UDP_RX_BUFSZ: usize = 2048;

/// Persistent recvmmsg state. Heap-once, reuse-forever.
pub(crate) struct UdpRxBatch {
    /// 64 × 2KB packet buffers. Boxed so `Option<UdpRxBatch>` is
    /// `mem::take`-cheap (one ptr, not 128KB).
    bufs: Box<[[u8; UDP_RX_BUFSZ]; UDP_RX_BATCH]>,
    /// nix's `mmsghdr` + `sockaddr_storage` arrays. Linux only.
    #[cfg(target_os = "linux")]
    headers: MultiHeaders<SockaddrStorage>,
}

impl UdpRxBatch {
    pub(crate) fn new() -> Self {
        // `Box::new([[0u8; 2048]; 64])` would build 128KB on the
        // stack first then move — overflow risk. vec→boxed→array
        // goes straight to the heap.
        let bufs: Box<[[u8; UDP_RX_BUFSZ]]> =
            vec![[0u8; UDP_RX_BUFSZ]; UDP_RX_BATCH].into_boxed_slice();
        let bufs: Box<[[u8; UDP_RX_BUFSZ]; UDP_RX_BATCH]> = bufs
            .try_into()
            .expect("vec![_; 64].into_boxed_slice() has length 64");
        Self {
            bufs,
            #[cfg(target_os = "linux")]
            headers: MultiHeaders::preallocate(UDP_RX_BATCH, None),
        }
    }
}

/// nix `SockaddrStorage` → std `SocketAddr`. nix has `From` impls
/// for the v4/v6 views but not the union; do it by hand.
pub(super) fn ss_to_std(ss: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = ss.as_sockaddr_in() {
        Some(SocketAddr::V4(SocketAddrV4::from(*v4)))
    } else {
        ss.as_sockaddr_in6()
            .map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6)))
    }
}
