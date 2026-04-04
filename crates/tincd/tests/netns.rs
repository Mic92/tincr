//! Real kernel TUN inside an unprivileged user+net namespace.
//!
//! `first_packet_across_tunnel` (two_daemons.rs) uses `DeviceType =
//! fd` on a socketpair: the test process IS the IP stack. Proves the
//! daemon's wiring; doesn't prove `linux/if_tun.h` interop. THIS test
//! uses `DeviceType = tun` — `LinuxTun::open()` does TUNSETIFF, the
//! `+10`-offset reads, `IFF_NO_PI` flag. All previously dark in CI.
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
//! Sequence (proven in the python PoC during development):
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
//! 1. `LinuxTun::open()` exercised: TUNSETIFF, the `+10` offset,
//!    `tun_pi` framing. Socketpair-TUN reads at `+14` (no tun_pi).
//! 2. Kernel's IP stack is source AND sink: real ICMP, real
//!    checksums, real route lookup. The socketpair test hand-crafted
//!    raw bytes with a zero checksum (nothing checked it).
//! 3. Future: chunk-9's ICMP-unreachable synth becomes pinnable
//!    (`ping 10.42.0.99` → no subnet → daemon should write
//!    `ICMP_NET_UNKNOWN` back into the TUN → ping surfaces it).

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

mod common;
use common::linux::{run_ip, wait_for_carrier};
use common::{
    Ctl, TmpGuard, alloc_port, drain_stderr, node_status, poll_until, pubkey_from_seed, tincd_cmd,
    wait_for_file, write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("netns", tag)
}

// ═════════════════════════ the bwrap re-exec wrapper ══════════════════════

/// Re-exec the current test binary inside bwrap. See module doc.
///
/// `Some(NetNs)` → we ARE inside; run the test body.
/// `None` → outer pass spawned-and-waited (or SKIP); body must not run.
fn enter_netns(test_name: &str) -> Option<NetNs> {
    if std::env::var_os("BWRAP_INNER").is_some() {
        return Some(NetNs::setup());
    }

    // ─── feature-detect ────────────────────────────────────────────
    // `bwrap --unshare-user --bind / / true`: cheapest probe. Non-
    // zero → either no bwrap (ENOENT on spawn) or userns disabled
    // (bwrap prints "needs unprivileged user namespaces" or
    // "setting up uid map: Permission denied").
    let probe = Command::new("bwrap")
        .args(["--unshare-user", "--bind", "/", "/", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match probe {
        Err(e) => {
            eprintln!("SKIP {test_name}: bwrap not found ({e})");
            return None;
        }
        Ok(out) if !out.status.success() => {
            let why = String::from_utf8_lossy(&out.stderr);
            eprintln!(
                "SKIP {test_name}: bwrap probe failed (unprivileged \
                 userns disabled?): {}",
                why.trim()
            );
            return None;
        }
        Ok(_) => {}
    }
    // /dev/net/tun must exist on the HOST (we dev-bind it).
    if !std::path::Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing (CONFIG_TUN=n?)");
        return None;
    }

    // ─── spawn bwrap ───────────────────────────────────────────────
    // Each flag explained:
    //
    //   --unshare-net      New netns. Starts empty (just `lo`, DOWN).
    //   --unshare-user     New userns. Grants us caps INSIDE only.
    //   --cap-add CAP_NET_ADMIN   ip link/addr/tuntap, TUNSETIFF.
    //   --cap-add CAP_NET_RAW     ping (SOCK_RAW for ICMP). Modern
    //                             ping can use SOCK_DGRAM (no cap)
    //                             but the sysctl gating that is
    //                             host-side; safer to grant the cap.
    //   --cap-add CAP_SYS_ADMIN   unshare(CLONE_NEWNET) + mount(2),
    //                             for the child-netns construction.
    //   --uid 0 --gid 0    Map to root inside. `ip` checks uid==0
    //                      before even trying capability checks on
    //                      some paths. Easiest to just be 0.
    //   --bind / /         Whole rootfs visible. The test binary,
    //                      tincd binary, ip/ping/unshare, /tmp for
    //                      confbase — all just work.
    //   --tmpfs /dev       THE LOAD-BEARING FLAG. A plain dev-bind
    //                      of /dev/net/tun fails TUNSETIFF with
    //                      EPERM: kernel commit 2ab8baf (2016-06)
    //                      checks `tun->owner_net == current->
    //                      nsproxy->net_ns->user_ns`. The HOST's
    //                      /dev is a devtmpfs owned by the init
    //                      userns; binding from it inherits that
    //                      ownership. Mounting a FRESH tmpfs at
    //                      /dev means OUR userns owns the mount;
    //                      dev-binding /dev/net/tun on top of THAT
    //                      satisfies the check.
    //   --dev-bind /dev/net/tun /dev/net/tun
    //                      The TUN multiplexer. Must be a dev-bind
    //                      (regular bind would lose the device
    //                      semantics on the userns-owned tmpfs).
    //   --dev-bind /dev/null /dev/null
    //                      Stdio::null(), conn.rs test helper.
    //   --dev-bind /dev/urandom /dev/urandom
    //                      OsRng fallback (control.rs cookie). On
    //                      modern kernels getrandom(2) is the
    //                      primary; urandom is the libc fallback.
    //   --proc /proc       Fresh procfs. /proc/self/exe is us.
    //   --tmpfs /run       Writable /run for /run/netns/ mount.
    //                      Host /run is read-only-ish in many CI
    //                      environments; fresh tmpfs sidesteps.
    //
    // Stdio: inherit stdout/stderr so the inner test's panics
    // surface in the outer test's output. `--nocapture` on the
    // inner libtest call ensures they're not swallowed.
    //
    // `/proc/self/exe` resolved HERE, not passed literally: bwrap
    // forks, then execs the program. Inside the child (post-`--proc
    // /proc` remount), `/proc/self/exe` is BWRAP, not us. Readlink
    // in the outer process and pass the real path. `--bind / /`
    // means it's reachable at the same path inside.
    let self_exe = std::fs::read_link("/proc/self/exe").expect("readlink /proc/self/exe");
    let status = Command::new("bwrap")
        .args(["--unshare-net", "--unshare-user"])
        .args(["--cap-add", "CAP_NET_ADMIN"])
        .args(["--cap-add", "CAP_NET_RAW"])
        .args(["--cap-add", "CAP_SYS_ADMIN"])
        .args(["--uid", "0", "--gid", "0"])
        .args(["--bind", "/", "/"])
        .args(["--tmpfs", "/dev"])
        .args(["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
        .args(["--dev-bind", "/dev/null", "/dev/null"])
        .args(["--dev-bind", "/dev/urandom", "/dev/urandom"])
        .args(["--proc", "/proc"])
        .args(["--tmpfs", "/run"])
        .arg("--")
        .arg(&self_exe)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    None
}

/// Handle for the inner-side netns state. `setup()` brings up `lo`,
/// precreates persistent TUN devices, builds the child netns.
/// Dropping kills the child-netns sleeper (devices vanish with the
/// userns when the inner test process exits — no explicit teardown).
struct NetNs {
    /// Holds the child netns open. `unshare -n sleep <big>`. The
    /// nsfd is bind-mounted at `/run/netns/bobside` so `ip netns
    /// exec` works. Killing this DOESN'T destroy the netns (the
    /// mount keeps it alive); but the whole bwrap process exiting
    /// does.
    sleeper: Child,
}

impl NetNs {
    fn setup() -> Self {
        // ─── lo up ───────────────────────────────────────────────
        // New netns starts with `lo` DOWN. The daemons listen on
        // `127.0.0.1`; bind() succeeds with lo down but connect()
        // gets ENETUNREACH.
        run_ip(&["link", "set", "lo", "up"]);

        // ─── persistent TUN devices ──────────────────────────────
        // `ip tuntap add` sets the TUN_PERSIST flag: the device
        // outlives the fd that created it. The daemon's TUNSETIFF
        // with `ifr_name = "tinc0"` then ATTACHES to the existing
        // device (kernel `tun_set_iff`: name lookup hits → attach
        // path) instead of creating a fresh one. We need persist
        // because step 6 (move to child netns) only works on a
        // device that exists independently of the daemon's fd from
        // the kernel's view.
        //
        // (Non-persistent: TUNSETIFF creates, close destroys. The
        // daemon's TUNSETIFF would create `tinc0`, but THEN we
        // can't `ip link set tinc1 netns ...` from the test
        // process — only the daemon's userns "owns" a non-persist
        // device. Persistent sidesteps the ownership tangle.)
        run_ip(&["tuntap", "add", "mode", "tun", "name", "tinc0"]);
        run_ip(&["tuntap", "add", "mode", "tun", "name", "tinc1"]);
        // Admin-UP now (NO-CARRIER until TUNSETIFF). `LOWER_UP`
        // (the carrier flag) is only reported on UP devices, so
        // `wait_for_carrier` needs them UP before the daemon
        // attaches. The UP state on tinc1 is reset by the netns
        // move; `place_devices` re-ups it.
        run_ip(&["link", "set", "tinc0", "up"]);
        run_ip(&["link", "set", "tinc1", "up"]);

        // ─── child netns for bob's TUN ───────────────────────────
        // `ip netns add` wants `mount --make-shared /run/netns`
        // which our CAP_SYS_ADMIN-in-userns can't do (shared
        // propagation needs real-root). Manual: spawn `unshare -n
        // sleep`, bind-mount its `/proc/PID/ns/net` ourselves.
        // `ip netns exec NAME` then works (it just reads the
        // mount).
        std::fs::create_dir_all("/run/netns").expect("mkdir /run/netns");
        let sleeper = Command::new("unshare")
            .args(["-n", "sleep", "3600"])
            .spawn()
            .expect("spawn unshare sleeper");
        // Race: sleeper's netns isn't ready until unshare(2) ran.
        // Poll for /proc/PID/ns/net being a DIFFERENT inode than
        // ours. In practice 50ms is plenty.
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write("/run/netns/bobside", b"").expect("touch nsfd target");
        let status = Command::new("mount")
            .args(["--bind"])
            .arg(format!("/proc/{}/ns/net", sleeper.id()))
            .arg("/run/netns/bobside")
            .status()
            .expect("spawn mount");
        assert!(status.success(), "mount --bind nsfd: {status:?}");

        run_ip(&["netns", "exec", "bobside", "ip", "link", "set", "lo", "up"]);

        Self { sleeper }
    }

    /// Called AFTER both daemons have done TUNSETIFF (carrier up
    /// on both). Moves bob's TUN into the child netns and
    /// configures addresses on both. Moving an interface resets
    /// its UP state and flushes addresses, so configure AFTER move.
    fn place_devices(&self) {
        // ─── move tinc1 into bobside ─────────────────────────────
        // The fd→device binding survives. Bob's daemon (in the
        // OUTER netns) keeps writing to its fd; packets surface
        // in the CHILD netns. Kernel: `tun_chr_write_iter` finds
        // the netdev via the file's private_data, doesn't care
        // which netns the device migrated to.
        run_ip(&["link", "set", "tinc1", "netns", "bobside"]);

        // ─── configure tinc0 (alice, outer ns) ───────────────────
        // /24 on the device → kernel installs a connected route
        // for 10.42.0.0/24 via tinc0. The /32 in tinc.conf's
        // `Subnet =` is a SEPARATE thing: that's what the daemon's
        // `route_ipv4` looks up. Kernel route gets the packet INTO
        // tinc0; daemon route gets it OUT to bob.
        run_ip(&["addr", "add", "10.42.0.1/24", "dev", "tinc0"]);
        run_ip(&["link", "set", "tinc0", "up"]);

        // ─── configure tinc1 (bob, inner ns) ─────────────────────
        run_ip(&[
            "netns",
            "exec",
            "bobside",
            "ip",
            "addr",
            "add",
            "10.42.0.2/24",
            "dev",
            "tinc1",
        ]);
        run_ip(&[
            "netns", "exec", "bobside", "ip", "link", "set", "tinc1", "up",
        ]);
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
    }
}

// ═══════════════════════════ daemon plumbing ═══════════════════════════════

struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    port: u16,
    /// Real TUN: this is the precreated persistent device name.
    /// Goes into `Interface = ...` in tinc.conf. The daemon's
    /// `LinuxTun::open` TUNSETIFF-attaches to it.
    iface: &'static str,
    /// /32 in `hosts/NAME` `Subnet = ...`. The daemon's route()
    /// lookup key. NOT the /24 on the device — that's kernel-side.
    subnet: &'static str,
}

impl Node {
    fn new(
        tmp: &std::path::Path,
        name: &'static str,
        seed_byte: u8,
        iface: &'static str,
        subnet: &'static str,
    ) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
            iface,
            subnet,
        }
    }

    fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    /// Write `tinc.conf` + `hosts/NAME` + `ed25519_key.priv` +
    /// `hosts/OTHER`. `connect_to` toggles ConnectTo + Address.
    /// `DeviceType = tun` + `Interface = ...` (vs two_daemons.rs's
    /// `dummy`/`fd`). Subnet always set.
    fn write_config(&self, other: &Node, connect_to: bool) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        // tinc.conf — DeviceType=tun + Interface. AddressFamily=
        // ipv4 keeps the listener simple (no v6 dance).
        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = ipv4\n",
            self.name, self.iface
        );
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        tinc_conf.push_str("PingTimeout = 1\n");
        // Linux TUN unconditionally uses IFF_VNET_HDR (Phase 2a).
        // `real_tun_ping`/`real_tun_unreachable` exercise the
        // GSO_NONE path (ICMP → gso_none_checksum + eth synth);
        // `tso_ingest_stream_integrity` exercises the Super arm.
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port + Subnet.
        std::fs::write(
            self.confbase.join("hosts").join(self.name),
            format!("Port = {}\nSubnet = {}\n", self.port, self.subnet),
        )
        .unwrap();

        // hosts/OTHER — pubkey + maybe Address.
        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
        if connect_to {
            other_cfg.push_str(&format!("Address = 127.0.0.1 {}\n", other.port));
        }
        std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    fn spawn(&self) -> Child {
        self.spawn_with_log("tincd=debug")
    }

    /// Spawn with explicit `RUST_LOG`. The `tso_ingest_stream_
    /// integrity` test pushes 8 MiB through; at `debug` per-packet
    /// log volume the 64 KiB stderr pipe fills and the daemon
    /// blocks on `write(2, ...)`. Same issue throughput.rs hit
    /// (see `ChildWithLog`); here we just turn the volume down.
    fn spawn_with_log(&self, rust_log: &str) -> Child {
        tincd_cmd()
            .arg("-c")
            .arg(&self.confbase)
            .arg("--pidfile")
            .arg(&self.pidfile)
            .arg("--socket")
            .arg(&self.socket)
            .env("RUST_LOG", rust_log)
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }
}

// ═══════════════════════════════ the test ══════════════════════════════════

/// Real kernel TUN, real ping. Kernel→daemon→SPTPS→UDP→daemon→kernel.
///
/// ## What's proven (vs `first_packet_across_tunnel`)
///
/// 1. **`LinuxTun::open()` TUNSETIFF**: the daemon attaches to a
///    precreated persistent device. Carrier flips from `NO-CARRIER`
///    to `LOWER_UP`. `wait_for_carrier` pins it.
/// 2. **The `+10` offset trick**: `linux.rs::Tun::read` reads at
///    `buf[10..]`, the kernel's 4-byte `tun_pi` lands with `proto`
///    at `buf[12..14]` = ethertype slot. ICMP echo from ping has
///    `tun_pi.proto = ETH_P_IP = 0x0800`; `route()` reads it as the
///    ethertype, dispatches to `route_ipv4`. The socketpair test
///    used `FdTun` which reads at `+14` (no tun_pi) — different
///    code path.
/// 3. **Kernel checksums + TTL**: ping's ICMP echo has a real
///    checksum; the daemon doesn't touch it (just the route lookup
///    on `dst`); bob's kernel verifies it on receipt and replies.
///    The reply's checksum is also kernel-computed. The socketpair
///    test had a zero checksum that nothing verified.
/// 4. **fd→device binding survives netns move**: bob's daemon stays
///    in the outer netns (127.0.0.1 listeners), bob's TUN moves to
///    the child netns. Daemon writes to its fd; packets land in
///    child kernel's IP stack. The PoC during dev proved this; the
///    test pins it (ping wouldn't reply otherwise).
#[test]
fn real_tun_ping() {
    let Some(netns) = enter_netns("real_tun_ping") else {
        return;
    };

    let tmp = tmp("ping");
    let alice = Node::new(tmp.path(), "alice", 0xA8, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xB8, "tinc1", "10.42.0.2/32");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn ──────────────────────────────────────────────────
    // Bob first (listener); alice has ConnectTo. Same ordering
    // rationale as two_daemons.rs (avoid the 5s retry backoff).
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // ─── wait for carrier (proves TUNSETIFF fired) ──────────────
    // The precreated devices are `NO-CARRIER` until TUNSETIFF.
    // Daemon's `Tun::open` runs in `Daemon::setup` which finishes
    // before the socket file appears, so usually carrier is
    // already up by now — but the carrier event is async (kernel
    // queues a netlink notification). Poll to be safe.
    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF didn't bring carrier up; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(
        wait_for_carrier("tinc1", Duration::from_secs(2)),
        "bob TUNSETIFF didn't bring carrier up"
    );

    // ─── move bob's TUN, configure addresses ────────────────────
    // AFTER both daemons attached. The fd binding survives the
    // move; bob's daemon doesn't notice (no event on the fd).
    netns.place_devices();

    // ─── meta-conn handshake ────────────────────────────────────
    // Status bit 4 (reachable) on both → ACK + graph() done. Same
    // poll as first_packet_across_tunnel.
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // ─── kick the per-tunnel handshake ──────────────────────────
    // First packet hits `send_sptps_packet` with `!validkey` →
    // dropped, but kicks `send_req_key`. ICMP echo is the kick:
    // `ping -c 1 -W 1` sends one, waits 1s, fails. We don't care
    // about THIS ping's exit; it's the validkey trigger.
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // ─── wait for validkey (status bit 1) ───────────────────────
    // Per-tunnel SPTPS done on BOTH sides. catch_unwind: on
    // timeout, dump both daemons' captured stderr (it's piped;
    // never read otherwise).
    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey_result.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── THE PING ───────────────────────────────────────────────
    // validkey set. `ping -c 3` sends three echo requests; each
    // one: kernel writes ICMP into tinc0 → alice's `Tun::read`
    // (at +10, tun_pi.proto=0x0800 lands at ethertype slot) →
    // `route()` reads dst=10.42.0.2, finds bob's /32 →
    // `Forward{to: bob}` → `send_sptps_packet` → SPTPS record →
    // UDP sendto(bob's 127.0.0.1:PORT) → bob's `on_udp_recv` →
    // SPTPS receive → `route()` reads dst=10.42.0.2, finds OWN
    // subnet → `Forward{to: myself}` → `Tun::write` (at +10,
    // tun_pi reconstructed) → bobside kernel ICMP layer →
    // generates reply with dst=10.42.0.1 → backflow.
    //
    // `-W 2`: per-packet timeout. Loopback RTT is microseconds;
    // 2s is slack for CI scheduler jitter.
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");

    if !ping.status.success() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "ping failed: {:?}\nstdout: {}\nstderr: {}\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}",
            ping.status,
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr),
        );
    }

    // Show the ping output even on success (--nocapture).
    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    // ─── traffic counters ───────────────────────────────────────
    // alice: out_packets ≥ 3 for bob (the kick ping + 3 echoes;
    // counted at `send_packet` BEFORE the validkey gate, so the
    // dropped kick still counts). bob: in_packets ≥ 3 for alice.
    let node_traffic = |rows: &[String], name: &str| -> Option<(u64, u64)> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            let n = toks.len();
            Some((toks[n - 4].parse().ok()?, toks[n - 2].parse().ok()?))
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    let (_, a_out_p) = node_traffic(&a_nodes, "bob").expect("alice's bob row");
    let (b_in_p, _) = node_traffic(&b_nodes, "alice").expect("bob's alice row");
    assert!(
        a_out_p >= 3,
        "alice out_packets={a_out_p}; nodes: {a_nodes:?}"
    );
    assert!(b_in_p >= 3, "bob in_packets={b_in_p}; nodes: {b_nodes:?}");

    // ─── stderr: TUNSETIFF success log + SPTPS handshake ────────
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    // `Tun::open` doesn't log itself, but daemon.rs:693 does:
    // "Device mode: Tun, interface: tinc0". Proves the kernel-
    // assigned name matched what we requested (TUNSETIFF wrote
    // it back into ifr_name; `Tun::open` read it).
    assert!(
        alice_stderr.contains("interface: tinc0"),
        "alice's TUNSETIFF; stderr:\n{alice_stderr}"
    );
    assert!(
        bob_stderr.contains("interface: tinc1"),
        "bob's TUNSETIFF; stderr:\n{bob_stderr}"
    );
    assert!(
        alice_stderr.contains("SPTPS key exchange with bob successful"),
        "alice's per-tunnel HandshakeDone; stderr:\n{alice_stderr}"
    );

    drop(netns);
}

/// Ping a destination NO daemon owns. The kernel route gets it INTO
/// tinc0 (it's in 10.42.0.0/24); alice's `route()` finds no subnet
/// → `RouteResult::Unreachable{ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN}`
/// → `icmp::build_v4_unreachable` synthesizes the ICMP error →
/// `device.write` puts it BACK into tinc0 → kernel parses it,
/// matches the quoted IP header to ping's socket → ping prints
/// "Destination Net Unknown" (or similar; the exact string varies
/// by ping implementation — iputils vs busybox).
///
/// **THIS PROVES THE WIRE IS CORRECT.** The kernel's ICMP receive
/// path is strict: bad checksum → silently dropped, wrong quoted
/// header → no socket match → ping just times out. Ping printing
/// the error means our `inet_checksum` is right, our ip header is
/// right, our quoted-original is right, our MAC swap is right.
///
/// Single daemon (alice only): the unreachable path doesn't need a
/// peer. The ICMP synth fires BEFORE `send_sptps_packet`. No SPTPS
/// handshake, no validkey wait — just route() → Unreachable →
/// device.write. Faster + less moving parts than `real_tun_ping`.
#[test]
fn real_tun_unreachable() {
    let Some(netns) = enter_netns("real_tun_unreachable") else {
        return;
    };

    let tmp = tmp("unreach");
    let alice = Node::new(tmp.path(), "alice", 0xA9, "tinc0", "10.42.0.1/32");
    // Bob's TUN exists (NetNs::setup precreated it) but no daemon
    // attaches. We need `bob` only for `write_config`'s pubkey/
    // hosts cross-registration; alice's id_h reads `hosts/bob` if
    // bob ever connects (it won't here).
    let bob = Node::new(tmp.path(), "bob", 0xB9, "tinc1", "10.42.0.2/32");

    // alice has NO ConnectTo. She just listens. The unreachable
    // path is local: TUN read → route() → Unreachable → TUN write.
    alice.write_config(&bob, false);

    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF didn't bring carrier up; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // ─── configure tinc0 only (no bob, no child netns move) ────
    // /24 on the device → kernel route for 10.42.0.0/24 via tinc0.
    // 10.42.0.99 is in that /24 but NOT in any daemon Subnet.
    run_ip(&["addr", "add", "10.42.0.1/24", "dev", "tinc0"]);
    run_ip(&["link", "set", "tinc0", "up"]);

    // ─── THE PING ────────────────────────────────────────────────
    // `-c 2`: send 2 echoes. Stay under the 3/sec rate limit
    // (`route.c:130` `ratelimit(3)`); a 4th would silently time
    // out instead of getting ICMP back.
    // `-W 2`: 2s per-packet timeout. The ICMP error is synchronous
    // (TUN write → kernel ICMP rcv is in-process); 2s is just CI
    // slack. WITHOUT our synth, ping would block for the full 2s
    // and exit with NO ICMP message — just "packet loss". WITH it,
    // ping immediately prints the error (and still exits non-zero;
    // unreachable is a failure to ping(1)).
    let ping = Command::new("ping")
        .args(["-c", "2", "-W", "2", "10.42.0.99"])
        .output()
        .expect("spawn ping");

    let stdout = String::from_utf8_lossy(&ping.stdout);
    let stderr = String::from_utf8_lossy(&ping.stderr);
    eprintln!("ping stdout:\n{stdout}\nping stderr:\n{stderr}");

    // Ping exits non-zero (no replies). That's expected.
    assert!(
        !ping.status.success(),
        "ping should fail (no route to 10.42.0.99); stdout: {stdout}"
    );

    // The ICMP error surfaces in ping's output. iputils-ping
    // prints "Destination Net Unknown" for ICMP type=3 code=6;
    // busybox ping prints "No route to host" (it lumps codes).
    // Match the common substring. WITHOUT the synth, neither
    // appears — ping just says "100% packet loss".
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Unreachable")
            || combined.contains("Unknown")
            || combined.contains("No route"),
        "ping should surface the synthesized ICMP error; got:\n{combined}"
    );

    // ─── daemon stderr: the synth log ────────────────────────────
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        alice_stderr.contains("unreachable, sending ICMP"),
        "alice should log the ICMP synth; stderr:\n{alice_stderr}"
    );

    drop(netns);
}

/// Phase 2a TSO ingest integrity gate. `RUST_REWRITE_10G.md`.
///
/// With `ExperimentalGSO = on`, the daemon sets `IFF_VNET_HDR +
/// TUNSETOFFLOAD(TUN_F_TSO4|6)`. Kernel TCP stops segmenting at the
/// TUN MTU; it hands the daemon ≤64KB super-segments. The daemon's
/// `tso_split` re-segments them with re-synthesized TCP headers
/// (seqno arithmetic, csum recompute, IPv4 ID++).
///
/// **The risk: get TCP seqno wrong → silent stream corruption.**
/// The receiving kernel reassembles by seqno; off-by-one means
/// wrong bytes in the right place, no error visible. Only a
/// sha256-of-stream catches it.
///
/// ## What this proves
///
/// 1. **Seqno arithmetic**: 8 MiB of TCP at MSS ≈1400 = ~6000
///    segments. Each segment's seqno = first + i*gso_size. If the
///    arithmetic is off (e.g. `*` vs `+`, or `i` vs `i+1`), the
///    sha256 differs.
/// 2. **IPv4 csum recompute**: bob's kernel verifies the IP header
///    csum on receipt (`ip_rcv` → `ip_fast_csum`). Bad csum →
///    silently dropped → TCP retransmit storm → transfer either
///    hangs (timeout) or completes via retransmit (which proves
///    nothing). Either way, sha256 differs OR test times out.
/// 3. **TCP csum recompute**: same, but `tcp_v4_rcv` →
///    `tcp_checksum_complete`. The pseudo-header chaining must be
///    correct.
/// 4. **PSH/FIN flag clearing**: PSH on a non-last segment makes
///    bob's kernel deliver early (cosmetic; doesn't corrupt). FIN
///    on a non-last segment closes the connection mid-stream —
///    `socat` exits early, sha256 differs.
/// 5. **`gso_none_checksum`**: the FIN/ACK and bare-ACK frames at
///    the end of the transfer are GSO_NONE with NEEDS_CSUM. If we
///    don't complete the partial csum, bob drops the FIN → socat
///    waits for FIN → timeout.
///
/// ## Why 8 MiB
///
/// Large enough that the kernel definitely batches into super-
/// segments (it batches once cwnd opens, after ~10 RTTs of slow
/// start). At 8 MiB, ~5800 full-MSS frames + a short tail —
/// exercises both the even-split and short-tail paths in `tso_split`.
/// Small enough to finish in <2s on loopback (no ChaCha20 release
/// build needed; dev profile is fine).
///
/// ## Why socat not iperf3
///
/// iperf3 measures throughput; we want INTEGRITY. socat pipes raw
/// bytes: `dd if=/dev/urandom | socat - TCP:bob` on one side,
/// `socat TCP-LISTEN | sha256sum` on the other. Compare hashes.
/// One process either side, no JSON parsing, deterministic.
#[test]
fn tso_ingest_stream_integrity() {
    let Some(netns) = enter_netns("tso_ingest_stream_integrity") else {
        return;
    };

    let tmp = tmp("tso");
    let alice = Node::new(tmp.path(), "alice", 0xA7, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xB7, "tinc1", "10.42.0.2/32");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn (same dance as real_tun_ping) ────────────────────
    // `info` not `debug`: 8 MiB at MSS 1400 = ~6000 frames; the
    // per-packet `debug!("Sending packet of {len} bytes")` floods
    // the 64 KiB stderr pipe. The `tinc_device=info` part lets the
    // "TSO ingest enabled" log through (it's at info level).
    let mut bob_child = bob.spawn_with_log("tincd=info");
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn_with_log("info");
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));

    netns.place_devices();

    // ─── handshake ──────────────────────────────────────────────
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // Kick validkey (same as real_tun_ping).
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let validkey = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── generate test data + reference hash ────────────────────
    // 8 MiB of random bytes. Written to a temp file so we can hash
    // it once and pipe it once (urandom would give different bytes
    // on each read).
    let data_path = tmp.path().join("stream.bin");
    let dd = Command::new("dd")
        .args(["if=/dev/urandom", "bs=1M", "count=8"])
        .arg(format!("of={}", data_path.display()))
        .stderr(Stdio::null())
        .status()
        .expect("spawn dd");
    assert!(dd.success(), "dd: {dd:?}");

    let ref_hash = Command::new("sha256sum")
        .arg(&data_path)
        .output()
        .expect("spawn sha256sum");
    let ref_hash = String::from_utf8_lossy(&ref_hash.stdout)
        .split_whitespace()
        .next()
        .expect("sha256sum output")
        .to_owned();
    eprintln!("reference sha256: {ref_hash}");

    // ─── receiver: socat TCP-LISTEN | sha256sum (in bobside) ───
    // The hash is written to a file because piping back across
    // `ip netns exec` is finicky. We read the file after.
    let rx_hash_path = tmp.path().join("rx.sha256");
    let rx = Command::new("ip")
        .args(["netns", "exec", "bobside", "sh", "-c"])
        .arg(format!(
            "socat -u TCP-LISTEN:18099,reuseaddr - | sha256sum > '{}'",
            rx_hash_path.display()
        ))
        .spawn()
        .expect("spawn rx socat");
    // Wait for the listener to bind. socat doesn't have a
    // ready-signal; poll for the socket via `ss` or just sleep.
    // 200ms is generous on loopback.
    std::thread::sleep(Duration::from_millis(200));

    // ─── sender: socat FILE TCP (in outer netns / alice's side) ─
    // This is THE test. The kernel TCP stack writes data into
    // tinc0; with TSO advertised it writes ≤64KB super-segments.
    // alice's daemon `drain()` returns `Super{..}`, `tso_split`
    // re-segments. If seqno is off, bob's kernel reassembles
    // wrong-order bytes → sha256 differs. If csum is off, bob's
    // kernel drops segments → TCP retransmit storm → timeout.
    // `connect-timeout=5`: the SYN/SYN-ACK handshake should
    // complete in microseconds on loopback. If it doesn't, the
    // GSO_NONE csum-completion path is wrong (SYN gets dropped).
    // No data-phase timeout: socat blocks until FIN; the nextest
    // slow-timeout (30s) catches a hang.
    let tx = Command::new("socat")
        .arg("-u")
        .arg(format!("FILE:{}", data_path.display()))
        .arg("TCP:10.42.0.2:18099,connect-timeout=5")
        .output()
        .expect("spawn tx socat");
    if !tx.status.success() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "socat tx failed: {:?}\nstderr: {}\n\
             The TCP connect either timed out (csum bug → SYN dropped) \
             or RST mid-stream (FIN-on-non-last in tso_split).\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}",
            tx.status,
            String::from_utf8_lossy(&tx.stderr),
        );
    }

    // ─── wait for rx + compare hashes ──────────────────────────
    // socat exits when it sees FIN. sha256sum exits when its stdin
    // closes. The rx Child completes when both are done.
    let rx_status = rx.wait_with_output().expect("wait for rx socat").status;
    assert!(rx_status.success(), "rx socat: {rx_status:?}");

    let rx_hash = std::fs::read_to_string(&rx_hash_path)
        .expect("read rx hash")
        .split_whitespace()
        .next()
        .expect("sha256sum output format")
        .to_owned();
    eprintln!("received  sha256: {rx_hash}");

    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    // The TSO-enabled log line. Proves the feature actually fired
    // (config parsed, ioctl succeeded). Without this, a green hash
    // could mean "ExperimentalGSO was silently ignored and we
    // tested the non-vnet path". The `tinc_device` log target
    // surfaces with `RUST_LOG=info` (no target filter → all crates).
    assert!(
        alice_stderr.contains("TSO ingest enabled"),
        "alice should log TUNSETOFFLOAD success. \
         If the assert fires but sha256 below matches anyway, the \
         feature works — just the log target/level is wrong. \
         stderr:\n{alice_stderr}"
    );
    // No `tso_split` warnings: every super-segment was successfully
    // re-segmented. A `TooManySegments` or `BadTcpHlen` warn here
    // means some traffic took the drop path (and TCP retransmitted
    // around it, masking the error). Zero warns = every packet went
    // through tso_split cleanly.
    assert!(
        !alice_stderr.contains("tso_split"),
        "tso_split logged a warning (some segment was dropped); \
         stderr:\n{alice_stderr}"
    );

    // THE ASSERT.
    assert_eq!(
        ref_hash, rx_hash,
        "sha256 mismatch — tso_split CORRUPTED THE STREAM. \
         Check seqno arithmetic (is it first_seq + i*gso_size?), \
         IPv4 totlen/csum (off-by-ETH_HLEN?), TCP csum (pseudo-header \
         length = tcp_hlen + payload, NOT including IP header).\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    drop(netns);
}
