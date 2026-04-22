//! Kernel-side flow steering for the shard-per-thread tincd. Despite
//! the module name, no eBPF is involved.
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

#![cfg(target_os = "linux")]
// Not yet wired into the shard runtime — kernel steering landed ahead
// of the shard-per-thread executor. Kept compiling so the cBPF prog
// and ioctl shims don't bit-rot before `TINCD_SHARDS` ships.
#![allow(dead_code, unreachable_pub)]

mod cbpf;
pub use cbpf::{ReuseportGroup, attach_reuseport_id6, open_reuseport_group};

mod attach;
pub use attach::{TUNSETSTEERINGEBPF, tunsetsteeringebpf};
