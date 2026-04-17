//! Real kernel TUN inside an unprivileged user+net namespace.
//!
//! `first_packet_across_tunnel` (`two_daemons.rs`) uses `DeviceType =
//! fd` on a socketpair: the test process IS the IP stack. Proves the
//! daemon's wiring; doesn't prove `linux/if_tun.h` interop. THIS test
//! uses `DeviceType = tun` — `LinuxTun::open()` does TUNSETIFF, the
//! `+10`-offset reads, `IFF_NO_PI` flag.
//!
//! ## The bwrap re-exec trick
//!
//! `enter_netns()` is called at the top of each `#[test] fn`. If
//! `BWRAP_INNER` is unset (the OUTER invocation, libtest's first
//! call), we spawn `bwrap ... -- /proc/self/exe --exact <test_name>`
//! and assert on its exit code. The INNER invocation (bwrap's exec)
//! sees `BWRAP_INNER=1`, returns `Some(NetNs)`, runs the test body.
//! Same binary, same `#[test] fn`, two passes.
//!
//! Feature-detect: if `bwrap` is missing or unprivileged userns is
//! disabled (Debian default; `/proc/sys/kernel/unprivileged_userns_
//! clone = 0`), the outer pass `eprintln!("SKIP: ...")` and returns
//! `None` — test PASSES as a no-op. More discoverable than `#[ignore]`
//! (the SKIP shows in `cargo test -- --nocapture`).
//!
//! ## The two-kernel-stacks problem
//!
//! Both daemons in ONE netns is the simple plan: same `127.0.0.1:N`
//! listeners as `two_daemons.rs`, two TUN devices `tinc0`/`tinc1`.
//! BUT: if `10.42.0.1` is on `tinc0` and `10.42.0.2` is on `tinc1`,
//! both are local addresses → `ping 10.42.0.2` shortcuts via `lo`,
//! never enters either TUN. The kernel's local-address check fires
//! before output routing.
//!
//! Fix: ONE daemon's TUN lives in a CHILD netns. The trick: `Tun::
//! open()` does TUNSETIFF (creating/attaching the device), THEN we
//! `ip link set tinc1 netns bobside`. The fd→device binding SURVIVES
//! the move (`tun_net_init` doesn't reset the file ref). Bob's daemon
//! stays in the OUTER netns (its TCP/UDP listeners are at `127.0.0.1`
//! same as alice), but packets it writes to its TUN fd land in the
//! CHILD netns's IP stack. Ping in the outer ns goes into `tinc0`;
//! the reply comes from `tinc1` in the child ns.
//!
//! Sequence (proven in the python proof-of-concept during development):
//!   1. `ip tuntap add tinc0` + `tinc1` (persistent, outer ns)
//!   2. spawn alice (TUNSETIFF attaches to `tinc0`)
//!   3. spawn bob (TUNSETIFF attaches to `tinc1`)
//!   4. wait for carrier (`LOWER_UP` in `ip link show` — proves
//!      TUNSETIFF fired)
//!   5. `unshare -n` a sleeper → bind-mount its nsfd at
//!      `/run/netns/bobside`
//!   6. `ip link set tinc1 netns bobside` — bob's TUN moves
//!   7. configure addrs in BOTH namespaces, bring UP
//!   8. handshake (poll `dump nodes` for reachable + validkey)
//!   9. `ping -c 3 10.42.0.2` from outer ns
//!
//! `CAP_SYS_ADMIN` is needed (in addition to `CAP_NET_ADMIN`/`_RAW`)
//! for steps 5–6: `unshare(CLONE_NEWNET)` and `mount --bind`. All
//! three caps are USERNS-LOCAL (granted by bwrap inside the new
//! userns); none leak to the host.
//!
//! ## What's gained vs `first_packet_across_tunnel`
//!
//! 1. `LinuxTun::open()` exercised: TUNSETIFF with `IFF_NO_PI |
//!    IFF_VNET_HDR`; `drain()` reads `[vnet_hdr][IP]` and synthesizes
//!    the eth header. Socketpair-TUN (`FdTun`) reads at `+14` and
//!    synthesizes from the IP version nibble — different code path.
//! 2. Kernel's IP stack is source AND sink: real ICMP, real
//!    checksums, real route lookup. The socketpair test hand-crafted
//!    raw bytes with a zero checksum (nothing checked it).
//! 3. Future: chunk-9's ICMP-unreachable synth becomes pinnable
//!    (`ping 10.42.0.99` → no subnet → daemon should write
//!    `ICMP_NET_UNKNOWN` back into the TUN → ping surfaces it).
//!
//! ## Chaos tests (`chaos_*`)
//!
//! `tc netem` on `lo` injects loss/reorder/dup into the daemon↔
//! daemon transport. Both daemons bind `127.0.0.1:PORT` (`Address
//! = 127.0.0.1` in `hosts/OTHER`); the SPTPS UDP between them
//! traverses loopback. netem on `tinc0`/`tinc1` would only delay
//! the kernel's ICMP write — wrong layer.
//!
//! Control socket (`Ctl`) is `AF_UNIX`: doesn't touch a netdev,
//! immune to netem. We can apply chaos and still poll stats.
//!
//! Chaos is applied AFTER `validkey`: the meta-conn TCP also
//! traverses `lo`, so chaos-during-handshake conflates SPTPS-hs
//! retry behavior (kernel TCP retransmit, not our code) with the
//! data-path semantics we're actually probing. Separate concern.
//!
//! See each `chaos_*` test's doc for what "finding" looks like.

#![cfg(target_os = "linux")]

#[path = "../common/mod.rs"]
mod common;

mod rig;

mod autoconnect_shortcut;
mod busyloop;
mod chaos;
mod dns;
mod ping;
mod rekey;
mod sandbox;
mod stress;
mod tcp_fallback;
mod udp_asymmetric;
