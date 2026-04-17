//! Kernel-side flow steering for the shard-per-thread tincd. Despite
//! the crate name, no eBPF is involved.
//!
//! On the UDP ingress side this installs a tiny classic-BPF program
//! via `SO_ATTACH_REUSEPORT_CBPF` that hashes a few bytes of the tinc
//! wire prefix into the `SO_REUSEPORT` socket group, so every packet
//! from a given peer lands on the same shard deterministically and
//! without a `bpf()` syscall. On the TUN egress side it relies on the
//! kernel's built-in `automq` flow table: each shard's writes teach
//! the kernel which queue handles a given flow, and replies come back
//! on the same queue, so the only ioctl exposed for TUN is a
//! defensive `TUNSETSTEERINGEBPF(fd, -1)` that clears any stale
//! program left over from a previous daemon crash.
//!
//! Non-Linux targets get stub implementations returning `Unsupported`
//! so that `tincd`'s `use tincd_bpf::...` keeps compiling on BSD and
//! macOS.

#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
mod cbpf;
#[cfg(target_os = "linux")]
pub use cbpf::{ReuseportGroup, attach_reuseport_id6, open_reuseport_group};

#[cfg(target_os = "linux")]
mod attach;
#[cfg(target_os = "linux")]
pub use attach::{TUNSETSTEERINGEBPF, tunsetsteeringebpf};

// ───────────────── Non-Linux stubs ─────────────────────────────────
//
// `tincd` guards the call sites behind `cfg(linux)` AND a runtime
// `TINCD_SHARDS` check, so these stubs never actually run. They exist
// so `cargo check --target x86_64-unknown-freebsd` doesn't break on
// missing symbols. Signature-match, return `ErrorKind::Unsupported`;
// the caller's error path is exercised identically on Linux-EPERM
// and BSD-Unsupported.

#[cfg(not(target_os = "linux"))]
mod stubs {
    use std::io;

    /// Stub: BSD/macOS get the dispatch-thread fallback,
    /// no kernel steering. The error message names the platform so
    /// the startup log is unambiguous about WHY shards>1 fell back.
    #[allow(clippy::missing_errors_doc)] // doc explains the only outcome
    pub fn open_reuseport_group(
        _ip: std::net::IpAddr,
        _port: u16,
        _n: u32,
    ) -> io::Result<std::convert::Infallible> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_ATTACH_REUSEPORT_CBPF: linux only",
        ))
    }

    /// Stub: detach is a no-op on platforms without `TUNSETSTEERINGEBPF`.
    /// Returns `Ok` (not `Unsupported`) because the daemon calls this
    /// defensively at startup; "nothing to detach" is success.
    #[allow(clippy::missing_errors_doc, clippy::unnecessary_wraps)]
    pub fn tunsetsteeringebpf(
        _tun_fd: std::os::fd::BorrowedFd<'_>,
        _prog_fd: i32,
    ) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
pub use stubs::*;
