//! Kernel steering for shard-per-thread tincd. **No eBPF** despite the name.
//!
//! Two attach points, both unprivileged-within-userns:
//!
//!   - **UDP ingress** (`SO_ATTACH_REUSEPORT_CBPF`): three-instruction
//!     classic BPF prog. Input: skb past the UDP header
//!     (`sock_reuseport.c:512` does `pskb_pull(skb, sizeof(udphdr))`).
//!     Reads `src_id6[0..4]` from the tincd wire prefix at offset 6,
//!     returns `% N` as the index into `reuse->socks[]` (bind order).
//!     **No `bpf()` syscall**: this is `setsockopt`, the tcpdump path.
//!
//!   - **TUN egress** (`tun_automq_select_queue`, `tun.c:461`): **no
//!     prog**. The kernel maintains a flow→queue table that it
//!     populates from our *writes* (`tun_get_user` → `tun_flow_update`)
//!     and consults on its *sends* (`ndo_select_queue`). Reflexive.
//!     The only ioctl this crate exposes for TUN is
//!     `tunsetsteeringebpf(fd, -1)` — a defensive detach to clear any
//!     leftover prog from a prior daemon crash, ensuring automq runs.
//!
//! ────────────── Why not eBPF (history) ──────────────────────────
//!
//! The original plan was eBPF: a `TUNSETSTEERINGEBPF` prog
//! doing LPM-trie subnet lookup + a `nid_to_shard` ARRAY map, plus
//! `SK_REUSEPORT` + SOCKMAP on the UDP side. Dropped because:
//!
//! 1. `bpf(BPF_PROG_LOAD)` needs init-ns `CAP_BPF` when
//!    `kernel.unprivileged_bpf_disabled` is set (most distros). bwrap
//!    can't grant init-ns caps. The TUN-side test would self-skip on
//!    every CI run; only the NixOS-VM tests would exercise it.
//!
//! 2. The kernel already does the work. automq has been in the tree
//!    since `IFF_MULTI_QUEUE` shipped (3.8, 2013). The shard that
//!    receives a peer's UDP (cBPF-steered, deterministic) writes the
//!    decrypted inner packet to *its own* TUN queue → kernel learns
//!    that flow → next reply on the same 4-tuple comes back to the
//!    same queue. One cold miss per outgoing connection, then
//!    converged.
//!
//! Net: zero `bpf()` syscalls, zero `CAP_BPF`, full nextest coverage
//! in bwrap-userns. Kernel floor 4.5 (cBPF reuseport sockopt) instead
//! of 4.19 (eBPF features) — dropping eBPF *widened* compat.
//!
//! ────────────── No-op on non-Linux ──────────────────────────────
//!
//! `#![cfg(target_os = "linux")]` at crate root would make the crate
//! empty on BSD/macOS, breaking `tincd`'s `use tincd_bpf::...`. Gate
//! the bodies; leave a stub returning `Unsupported`. Same shape as
//! `tinc-device`'s `tap_dummy.rs`.

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
    use std::os::fd::RawFd;

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
    pub fn tunsetsteeringebpf(_tun_fd: RawFd, _prog_fd: i32) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
pub use stubs::*;
