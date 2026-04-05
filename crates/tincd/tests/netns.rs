//! Real kernel TUN inside an unprivileged user+net namespace.
//!
//! `first_packet_across_tunnel` (`two_daemons.rs`) uses `DeviceType =
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

use std::fmt::Write as _;
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
        // NixOS PATH lives at /run/current-system/sw/bin; the tmpfs
        // above wiped it. ip/ping/unshare survive (the dev shell
        // puts them at /nix/store paths in PATH), but dig/socat are
        // host-level packages — only there. ro-bind it back over the
        // tmpfs. Conditional: non-NixOS doesn't have it.
        .args(if std::path::Path::new("/run/current-system").exists() {
            &["--ro-bind", "/run/current-system", "/run/current-system"][..]
        } else {
            &[]
        })
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
    #[allow(clippy::unused_self)] // method form keeps the call ordered after NetNs::setup
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
    /// /32 in `hosts/NAME` `Subnet = ...`. The daemon's `route()`
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
    /// `hosts/OTHER`. `connect_to` toggles `ConnectTo` + Address.
    /// `DeviceType = tun` + `Interface = ...` (vs `two_daemons.rs`'s
    /// `dummy`/`fd`). Subnet always set.
    fn write_config(&self, other: &Node, connect_to: bool) {
        self.write_config_with(other, connect_to, "");
    }

    /// `extra` is appended verbatim to tinc.conf. Used by the
    /// sandbox tests for `Sandbox = normal\n`. Empty string for the
    /// common case (the wrapper above).
    fn write_config_with(&self, other: &Node, connect_to: bool, extra: &str) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        // tinc.conf — DeviceType=tun + Interface. AddressFamily=
        // ipv4 keeps the listener simple (no v6 dance).
        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = ipv4\n",
            self.name, self.iface
        );
        if connect_to {
            writeln!(tinc_conf, "ConnectTo = {}", other.name).unwrap();
        }
        tinc_conf.push_str("PingTimeout = 1\n");
        tinc_conf.push_str(extra);
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
            writeln!(other_cfg, "Address = 127.0.0.1 {}", other.port).unwrap();
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
/// 2. **The `vnet_hdr` drain path**: `linux.rs::Tun::drain` reads
///    `[virtio_net_hdr(10)][raw IP]` (`IFF_NO_PI | IFF_VNET_HDR`);
///    no eth header from the kernel. ICMP echo is `gso_type=NONE`,
///    so `drain()` strips the `vnet_hdr` and synthesizes the eth
///    header from the IP version nibble (`0x45` → `ETH_P_IP =
///    0x0800`); `route()` reads that ethertype and dispatches to
///    `route_ipv4`. The socketpair test used `FdTun` which reads at
///    `+14` and synthesizes the same way — but never touches the
///    `Tun::drain` override or the `vnet_hdr` layout.
/// 3. **Kernel checksums + TTL**: ping's ICMP echo has a real
///    checksum; the daemon doesn't touch it (just the route lookup
///    on `dst`); bob's kernel verifies it on receipt and replies.
///    The reply's checksum is also kernel-computed. The socketpair
///    test had a zero checksum that nothing verified.
/// 4. **fd→device binding survives netns move**: bob's daemon stays
///    in the outer netns (127.0.0.1 listeners), bob's TUN moves to
///    the child netns. Daemon writes to its fd; packets land in
///    child kernel's IP stack. The proof-of-concept during dev proved
///    this; the test pins it (ping wouldn't reply otherwise).
#[test]
#[allow(clippy::too_many_lines)] // test bodies are allowed to be long
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
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );

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
    // one: kernel writes `[vnet_hdr][ICMP]` into tinc0 → alice's
    // `Tun::drain` (gso_type=NONE: strip vnet_hdr, synth eth header
    // from IP version nibble → ethertype 0x0800) → `route()` reads
    // dst=10.42.0.2, finds bob's /32 → `Forward{to: bob}` →
    // `send_sptps_packet` → SPTPS record → UDP sendto(bob's
    // 127.0.0.1:PORT) → bob's `on_udp_recv` → SPTPS receive →
    // `route()` reads dst=10.42.0.2, finds OWN subnet →
    // `Forward{to: myself}` → `Tun::write` (stomps ethertype to a
    // zero vnet_hdr at `buf[4..]`, writes `[vnet_hdr=0][IP]`) →
    // bobside kernel ICMP layer → reply with dst=10.42.0.1 → back.
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

    // `Tun::open` doesn't log itself, but daemon::setup does:
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

// ═════════════════════════ chaos: tc netem ════════════════════════════════

/// `tc qdisc add dev DEV root netem SPEC...`. Drop guard `del`s it.
///
/// netem is egress-only (it's a qdisc). On `lo` that means EACH
/// direction takes a hit independently: alice→bob UDP egresses lo
/// once, bob→alice egresses lo once. So `loss 5%` ≈ 5% per direction,
/// not 10% round-trip on a single ICMP exchange (echo and reply are
/// independent draws).
///
/// `spec` is split on whitespace and passed verbatim. No shell.
struct Netem {
    dev: String,
}

impl Netem {
    fn apply(dev: &str, spec: &str) -> Self {
        let mut args = vec!["qdisc", "add", "dev", dev, "root", "netem"];
        args.extend(spec.split_whitespace());
        let out = Command::new("tc").args(&args).output().expect("spawn tc");
        assert!(
            out.status.success(),
            "tc {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Echo what got installed — netem normalizes args (adds
        // `seed`, `limit 1000`); useful in --nocapture failure logs.
        let show = Command::new("tc")
            .args(["qdisc", "show", "dev", dev])
            .output()
            .expect("tc qdisc show");
        eprintln!("netem: {}", String::from_utf8_lossy(&show.stdout).trim());
        Self { dev: dev.into() }
    }
}

impl Drop for Netem {
    fn drop(&mut self) {
        // Best-effort; the netns vanishes with the bwrap process
        // anyway. Explicit `del` is for tests that want to assert
        // post-chaos convergence (clear chaos, THEN poll).
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", &self.dev, "root"])
            .status();
    }
}

/// Bring up the two-daemon harness through validkey. Same dance as
/// `real_tun_ping` minus the actual ping. Factored because every
/// chaos test needs the same ~50 lines of setup before applying
/// netem; copy-paste of that block four times would obscure the
/// per-test variation (which is the whole signal).
///
/// Returns the daemon children so the test owns them — panic-path
/// stderr drainage stays at the call site (where the failing assert
/// knows what context to print).
struct ChaosRig {
    netns: NetNs,
    alice_child: Child,
    bob_child: Child,
    alice_ctl: Ctl,
    bob_ctl: Ctl,
}

impl ChaosRig {
    fn setup(netns: NetNs, tmp: &TmpGuard) -> Self {
        let alice = Node::new(tmp.path(), "alice", 0xCA, "tinc0", "10.42.0.1/32");
        let bob = Node::new(tmp.path(), "bob", 0xCB, "tinc1", "10.42.0.2/32");

        bob.write_config(&alice, false);
        alice.write_config(&bob, true);

        // `info` not `debug`: ~100-ping bursts at debug log a line
        // per packet per side. Not a pipe-fill risk at this volume
        // (~20 KiB), but `info` keeps the failure stderr readable.
        // The one debug line we DO want is `tincd::net`'s "Failed
        // to decode UDP packet ... BadSeqno" — that's the replay-
        // reject signal. Target-filter it through.
        let log = "tincd=info,tincd::net=debug";
        let mut bob_child = bob.spawn_with_log(log);
        assert!(
            wait_for_file(&bob.socket),
            "bob setup failed; stderr:\n{}",
            drain_stderr(bob_child)
        );
        let alice_child = alice.spawn_with_log(log);
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

        let mut alice_ctl = alice.ctl();
        let mut bob_ctl = bob.ctl();
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });

        // Kick + wait validkey. Same as real_tun_ping.
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.42.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });

        // ─── wait for udp_confirmed (status bit 7) ────────────
        // CRITICAL for the chaos tests. validkey alone means data
        // CAN go via UDP, but until PMTU probes confirm the path
        // (`txpath.rs:115`, `tunnel.rs:197`), `try_tx` falls back
        // to TCP-tunneling over the meta-conn. Kernel TCP dedups
        // and reorders silently — netem on `lo` would do nothing
        // visible to the SPTPS layer.
        //
        // Found the hard way: `chaos_replay_under_duplicate` saw
        // ZERO `BadSeqno` at 30% dup. Stderr had no "UDP address
        // confirmed" line. Data was riding TCP the whole time.
        //
        // Kick PMTU with traffic (probes are demand-driven via
        // `try_tx`, `txpath.rs:323`). A few pings get the probe/
        // reply round-trip done; udp_confirmed flips on the first
        // probe-reply (`txpath.rs:113-116`).
        poll_until(Duration::from_secs(5), || {
            let _ = Command::new("ping")
                .args(["-c", "1", "-W", "1", "10.42.0.2"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x80 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x80 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });

        Self {
            netns,
            alice_child,
            bob_child,
            alice_ctl,
            bob_ctl,
        }
    }

    /// `dump nodes` row → (`in_packets`, `out_packets`) for `name`.
    /// Tail-4, tail-2 of the row (`gossip.rs:947-950`).
    fn traffic(ctl: &mut Ctl, name: &str) -> (u64, u64) {
        ctl.dump(3)
            .iter()
            .find_map(|r| {
                let body = r.strip_prefix("18 3 ")?;
                let toks: Vec<&str> = body.split_whitespace().collect();
                if toks.first() != Some(&name) {
                    return None;
                }
                let n = toks.len();
                Some((toks[n - 4].parse().ok()?, toks[n - 2].parse().ok()?))
            })
            .expect("node row")
    }

    /// Kill both, return (`alice_stderr`, `bob_stderr`). Consumes self
    /// so the test can't accidentally poll a dead daemon.
    fn finish(mut self) -> (String, String) {
        drop(self.alice_ctl);
        drop(self.bob_ctl);
        let _ = self.bob_child.kill();
        let bob = drain_stderr(self.bob_child);
        let alice = drain_stderr(self.alice_child);
        drop(self.netns);
        (alice, bob)
    }
}

/// **Gate test.** 5% UDP loss on the daemon↔daemon transport. Ping
/// is ICMP-over-SPTPS-over-UDP: no daemon-layer retransmit (the
/// daemon just routes; ICMP is best-effort). So we EXPECT some
/// pings to drop. The signals:
///
/// - **Hang**: nextest timeout fires. The trace is the bug —
///   probably the `Failed to decode` → `send_req_key` arm in
///   `net.rs:495` triggering on something it shouldn't (loss isn't
///   a decode failure; the packet just never arrives).
/// - **Crash**: obvious.
/// - **Zero received**: 5% loss shouldn't zero a 30-ping burst.
///   ~85% should get through (loss applies independently to echo
///   AND reply: `0.95 * 0.95 ≈ 0.90`). Floor at 5/30 to allow for
///   netem RNG variance + the validkey-kick packet skew.
/// - **`BadSeqno` in stderr**: THE FINDING. Loss creates seqno
///   gaps but `ReplayWindow::check` (`state.rs:237-241`) handles
///   gaps fine: future packet arrives, gap marked `late[]`, no
///   reject. Dup/reorder reject; loss doesn't. If `BadSeqno`
///   appears under loss-only, the gap-marking arithmetic is wrong
///   (likely the `for i in self.inseqno..seqno` loop's modular
///   indexing).
#[test]
fn chaos_ping_under_loss() {
    let Some(netns) = enter_netns("chaos_ping_under_loss") else {
        return;
    };
    let tmp = tmp("chaos-loss");
    let mut rig = ChaosRig::setup(netns, &tmp);

    // ─── baseline counters BEFORE chaos ──────────────────────────
    // The validkey-kick + flush pings already bumped these.
    let (b_in_pre, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_pre) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");

    let _chaos = Netem::apply("lo", "loss 5%");

    // ─── the burst ───────────────────────────────────────────────
    // `-i 0.05`: 50ms gap. Slow enough that loss is the only
    // perturbation (no queue buildup → no incidental reorder).
    // `-W 1`: don't wait long for replies that won't come.
    let ping = Command::new("ping")
        .args(["-c", "30", "-i", "0.05", "-W", "1", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&ping.stdout);
    eprintln!("{stdout}");

    // Parse "X received" from the summary line.
    let received: u32 = stdout
        .lines()
        .find(|l| l.contains("received"))
        .and_then(|l| {
            l.split(',')
                .find(|f| f.contains("received"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("ping summary line");

    // ─── post-chaos counters ─────────────────────────────────────
    let (b_in_post, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_post) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");
    let alice_sent = a_out_post - a_out_pre;
    let bob_got = b_in_post - b_in_pre;
    eprintln!("alice sent {alice_sent} packets, bob accepted {bob_got}");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ─────────────────────────────────────────────────
    // Floor: 5/30. Expected ~27 (0.95² × 30), variance is wide at
    // N=30. Below 5 means something other than loss is dropping.
    assert!(
        received >= 5,
        "ping under 5% loss got {received}/30 — too low. \
         Either netem is dropping more than configured (check the \
         `netem:` line above), or the daemon's loss handling is \
         broken (req_key storm? check stderr below).\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    // THE check: zero replay rejects under loss-only. `BadSeqno`
    // is the `{e:?}` in `net.rs:488`'s debug log. Loss creates
    // gaps; gaps are NOT rejects (`state.rs:237-241` marks them
    // late). If this fires, the gap-marking is wrong.
    let bad_seqno_count = bob_stderr.matches("BadSeqno").count();
    assert_eq!(
        bad_seqno_count, 0,
        "loss-only chaos produced {bad_seqno_count} BadSeqno rejects. \
         Loss creates seqno GAPS, not dups/reorder. ReplayWindow::\
         check should mark the gap late and accept the future packet. \
         If this fires, suspect the `for i in inseqno..seqno` loop's \
         modular index (state.rs:239).\n\
         === bob stderr ===\n{bob_stderr}"
    );

    // Sanity: bob's accepted-count never exceeds what alice sent.
    // (Would mean a dup got past the replay check AND was
    // double-counted — but loss-only doesn't dup, so this firing
    // means netem is misconfigured or the counter is wrong.)
    assert!(
        bob_got <= alice_sent,
        "bob accepted {bob_got} but alice only sent {alice_sent}"
    );
}

/// `delay 5ms reorder 25% 50%`. netem holds packets in a delay
/// queue; 25% are sent immediately (out of order). Only works when
/// the queue is non-empty → needs a burst (`-i 0.01`, faster than
/// the 5ms delay).
///
/// **What's tested**: `ReplayWindow`'s `late[]` bitmap under
/// realistic out-of-order. The proptests in `state.rs` use random
/// seqnos; THIS uses kernel-generated near-monotonic-with-swaps,
/// which is what the bitmap was DESIGNED for.
///
/// `state.rs:228-245`: when seqno > inseqno (future), the gap
/// `[inseqno..seqno)` is marked `late[] |= bit`. When the late
/// packet later arrives (seqno < inseqno), `already = bit == 0`
/// is false (bit IS set) → accepted, bit cleared. So:
///
///   **Expected: zero `BadSeqno` under reorder-only.**
///
/// 256-packet window (replaywin=32 bytes); 5ms delay at 10ms
/// intervals means ≤1 packet skew, well inside. If `BadSeqno`
/// appears, the bitmap polarity is wrong ("1 = not seen" is
/// counterintuitive; easy to flip in a refactor).
#[test]
fn chaos_replay_under_reorder() {
    let Some(netns) = enter_netns("chaos_replay_under_reorder") else {
        return;
    };
    let tmp = tmp("chaos-reorder");
    let mut rig = ChaosRig::setup(netns, &tmp);

    let (b_in_pre, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");

    let _chaos = Netem::apply("lo", "delay 5ms reorder 25% 50%");

    // Burst: 100 pings at 10ms. The 5ms netem delay means ~every
    // packet sees the previous still queued; reorder probability
    // applies per-dequeue. Expect ~25 swapped pairs.
    let ping = Command::new("ping")
        .args(["-c", "100", "-i", "0.01", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&ping.stdout);
    eprintln!(
        "{}",
        stdout.lines().rev().take(3).collect::<Vec<_>>().join("\n")
    );

    let (b_in_post, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let bob_got = b_in_post - b_in_pre;
    eprintln!("bob accepted {bob_got} packets under reorder");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ─────────────────────────────────────────────────
    // Reorder-only: no loss, no dup. ALL pings should reply.
    // (netem reorder doesn't drop — it just shuffles dequeue
    // order.) Allow 2-packet slack for ping's own `-W` race.
    let received: u32 = stdout
        .lines()
        .find(|l| l.contains("received"))
        .and_then(|l| {
            l.split(',')
                .find(|f| f.contains("received"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("ping summary line");
    assert!(
        received >= 98,
        "reorder-only should not lose packets; got {received}/100. \
         The replay window is REJECTING reordered-but-valid packets \
         — the late[] bitmap accept path is broken.\n\
         === bob stderr ===\n{bob_stderr}"
    );

    // THE check.
    let bad_seqno_count =
        bob_stderr.matches("BadSeqno").count() + alice_stderr.matches("BadSeqno").count();
    assert_eq!(
        bad_seqno_count, 0,
        "reorder produced {bad_seqno_count} BadSeqno rejects. \
         The late[] bitmap (state.rs:228-245) should accept late-\
         but-in-window packets. Polarity bug? The C comment says \
         `1 = not seen` (state.rs:166); a refactor that flipped \
         that would reject every late arrival.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
}

/// `duplicate 30%`. netem clones egress packets. Dups carry the
/// same wire bytes → same SPTPS seqno → `ReplayWindow::check`
/// sees the bit already cleared (`state.rs:232`: `already = bit
/// == 0`) → `BadSeqno`. THIS IS CORRECT BEHAVIOR.
///
/// 30% not 10%: at 10% × 50 packets the binomial tail is wide
/// enough that a netem RNG seed plausibly gives zero dups; we
/// don't want a flaky positive control. 30% on 50 packets ≈ 15
/// expected; P(zero) is vanishing.
///
/// **What's tested**:
/// 1. Dups ARE rejected (the daemon doesn't double-deliver to the
///    TUN). The brief asks "Is the reject silent or does it log/
///    count?" — answer pinned here: logs at `debug` (`net.rs:488`),
///    no separate counter. `in_packets` is NOT bumped (the bump is
///    post-replay-check, `net.rs:2111`).
/// 2. The reject doesn't cascade. `net.rs:495` fires `send_req_key`
///    on decode failure, gated to once per 10s. A dup-reject is NOT
///    a decode failure semantically, but the code path is the same.
///    If `req_key` fires on every dup, that's a meta-conn storm under
///    realistic 1% network dup. The 10s gate should prevent it; the
///    burst here is ~2s, so we expect ≤1 `req_key` per side.
/// 3. Ping still works. The original (non-dup) packet got through;
///    only the clone is rejected.
#[test]
fn chaos_replay_under_duplicate() {
    let Some(netns) = enter_netns("chaos_replay_under_duplicate") else {
        return;
    };
    let tmp = tmp("chaos-dup");
    let mut rig = ChaosRig::setup(netns, &tmp);

    let (b_in_pre, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_pre) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");

    let _chaos = Netem::apply("lo", "duplicate 30%");

    // 50 pings at 20ms = 1s burst. 30% dup ≈ 15 dups expected.
    let ping = Command::new("ping")
        .args(["-c", "50", "-i", "0.02", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    eprintln!(
        "{}",
        String::from_utf8_lossy(&ping.stdout)
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    );

    let (b_in_post, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_post) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");
    let alice_sent = a_out_post - a_out_pre;
    let bob_got = b_in_post - b_in_pre;
    eprintln!("alice sent {alice_sent}, bob accepted {bob_got}");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ─────────────────────────────────────────────────
    // Ping must succeed (originals get through). dup-only doesn't
    // lose packets.
    assert!(
        ping.status.success(),
        "ping under dup-only failed. Originals should pass; only \
         clones reject. Exit: {:?}\n=== bob ===\n{bob_stderr}",
        ping.status
    );

    // Dups MUST be rejected (positive control: this test is
    // useless if netem didn't actually dup). 30% on 50 echoes +
    // 50 replies = ~30 expected dups across both directions.
    // Floor at 3: vanishing P(≤2) at this rate.
    //
    // The reject path: dup ciphertext → `open_data_into` decrypts
    // SUCCESSFULLY (same key, same nonce, same bytes) → `replay.
    // check` sees bit cleared → `BadSeqno` → `net.rs:488` log.
    // NOT DecryptFailed: AEAD doesn't reject re-decryption of
    // valid ciphertext.
    let bad_seqno =
        bob_stderr.matches("BadSeqno").count() + alice_stderr.matches("BadSeqno").count();
    assert!(
        bad_seqno >= 3,
        "expected ≥3 BadSeqno under 30% dup. Got {bad_seqno}. \
         Either netem didn't dup (check `netem:` line) or the \
         replay check is ACCEPTING dups — meaning double-delivery \
         to the TUN. Check `state.rs:232` `already` polarity.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
    eprintln!("BadSeqno rejects: {bad_seqno}");

    // in_packets must NOT count rejects. alice_sent is the upper
    // bound (out_packets counts at send time, pre-chaos; dups are
    // injected by netem AFTER the daemon's sendto). If bob_got >
    // alice_sent, a dup got past the replay check and was counted.
    assert!(
        bob_got <= alice_sent,
        "bob accepted {bob_got} > alice sent {alice_sent}. A dup \
         got past the replay window (state.rs:232 `already` check \
         is wrong, or the bit-clear at :245 races something)."
    );

    // ─── req_key cascade check (indirect) ────────────────────────────────────────
    // `net.rs:483` lumps `BadSeqno` with `DecryptFailed`: both
    // hit `send_req_key`. That's semantically wrong — a dup
    // doesn't mean keys are stale — but the 10s gate
    // (`net.rs:490-493`) saves it: `last_req_key` was set ~1s
    // ago by ChaosRig's validkey-kick, so the gate is CLOSED for
    // this entire burst. If it weren't, `send_req_key` would
    // RESET the tunnel (`gossip.rs:73-77`: `sptps = new`,
    // `validkey = false`) and the rest of the burst would
    // `DecryptFailed` against the new cipher.
    //
    // We can't grep for a "sending REQ_KEY" log (there isn't one;
    // `send_req_key` doesn't log). Instead: assert NO
    // `DecryptFailed` mid-burst. That's the smoking gun of a
    // tunnel-reset-under-dup.
    let decrypt_fail =
        bob_stderr.matches("DecryptFailed").count() + alice_stderr.matches("DecryptFailed").count();
    assert_eq!(
        decrypt_fail, 0,
        "DecryptFailed under dup-only → a BadSeqno-triggered \
         req_key reset the tunnel mid-burst. The 10s gate \
         (net.rs:490) should have held (last_req_key < 10s old). \
         Either the gate is comparing wrong, or something cleared \
         last_req_key.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
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
/// handshake, no validkey wait — just `route()` → Unreachable →
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
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );

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
/// Linux TUN unconditionally sets `IFF_VNET_HDR` (since `5cf9b12d`);
/// `Tun::open` then issues `TUNSETOFFLOAD(TUN_F_TSO4|6)`. Kernel TCP stops segmenting at the
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
///    segments. Each segment's seqno = first + i*`gso_size`. If the
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
///    the end of the transfer are `GSO_NONE` with `NEEDS_CSUM`. If we
///    don't complete the partial csum, bob drops the FIN → socat
///    waits for FIN → timeout.
///
/// ## Why 8 MiB
///
/// Large enough that the kernel definitely batches into super-
/// segments (it batches once cwnd opens, after ~10 RTTs of slow
/// start). At 8 MiB, ~5800 full-MSS frames + a short tail —
/// exercises both the even-split and short-tail paths in `tso_split`.
/// Small enough to finish in <2s on loopback (no `ChaCha20` release
/// build needed; dev profile is fine).
///
/// ## Why socat not iperf3
///
/// iperf3 measures throughput; we want INTEGRITY. socat pipes raw
/// bytes: `dd if=/dev/urandom | socat - TCP:bob` on one side,
/// `socat TCP-LISTEN | sha256sum` on the other. Compare hashes.
/// One process either side, no JSON parsing, deterministic.
#[test]
#[allow(clippy::too_many_lines)] // test bodies are allowed to be long
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
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
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
    // (TUNSETOFFLOAD succeeded). Without this, a green hash could
    // mean the kernel rejected the offload ioctl and we never saw
    // a super-segment (everything went through the GSO_NONE arm). The `tinc_device` log target
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

/// `Sandbox = normal` end-to-end. Same shape as `real_tun_ping` but
/// with the path allowlist active. Proves:
///
/// 1. **Daemon boots under Landlock.** `enter()` runs after
///    `Daemon::setup` (TUN open, listeners bound, tinc-up fired);
///    if the ruleset blocked any of those paths the daemon would
///    error out before the socket file appears.
/// 2. **Ping works.** Steady-state path access: cache/ write from
///    addrcache (alice's address-learn writes `cache/bob`); the
///    per-tunnel SPTPS only touches in-memory state.
/// 3. **Paths outside the allowlist EACCES.** A `host-up` script
///    with `#!/bin/sh` shebang fails: the daemon's exec of
///    confbase/host-up succeeds (Execute granted on confbase), but
///    the kernel's shebang-chase to /bin/sh hits a path NOT under
///    any `PathBeneath` rule → EACCES. This is the documented sharp
///    edge (sandbox.rs module doc): we don't port C's `open_exec_
///    paths` (/bin, /sbin, etc) because that's distro-specific.
///    The test pins the behavior so it's intentional.
///
/// **Self-skip if Landlock unavailable.** At `normal`, kernel-too-
/// old logs a warning and continues unrestricted (sandbox.rs
/// `RulesetStatus::NotEnforced` arm). The daemon STARTS but the
/// EACCES assert would fail (nothing's blocked). Check stderr for
/// "Entered sandbox"; absent → SKIP.
#[test]
fn sandbox_normal_ping() {
    use std::os::unix::fs::PermissionsExt;

    let Some(netns) = enter_netns("sandbox_normal_ping") else {
        return;
    };

    let tmp = tmp("sboxping");
    let alice = Node::new(tmp.path(), "alice", 0xAC, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBC, "tinc1", "10.42.0.2/32");

    bob.write_config_with(&alice, false, "Sandbox = normal\n");
    alice.write_config_with(&bob, true, "Sandbox = normal\n");

    // host-up reaching outside the allowlist via #!/bin/sh. The
    // body is irrelevant: the kernel never gets past the shebang.
    let host_up = alice.confbase.join("host-up");
    std::fs::write(&host_up, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perm = std::fs::metadata(&host_up).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&host_up, perm).unwrap();

    // ─── spawn (same as real_tun_ping) ────────────────────────
    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup: {}",
        drain_stderr(bob_child)
    );
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup: {}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // Kick + wait validkey.
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
        panic!(
            "validkey timeout;\n=== alice ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(bob_child)
        );
    }

    // ─── THE PING (under Landlock) ─────────────────────────────
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let bob_stderr = drain_stderr(bob_child);

    assert!(
        ping.status.success(),
        "ping failed under Sandbox=normal: {:?}\nstdout: {}\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
        ping.status,
        String::from_utf8_lossy(&ping.stdout),
    );
    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    // ─── Landlock actually entered (not silently no-op'd) ──────
    // sandbox::enter_impl logs "Entered sandbox at level Normal"
    // on RulesetStatus::{Fully,Partially}Enforced. Absent → either
    // kernel too old or LSM not enabled → the rest of this test
    // would be a tautology.
    if !alice_stderr.contains("Entered sandbox") {
        eprintln!(
            "SKIP sandbox_normal_ping: Landlock not enforced \
             (kernel <5.13 or lsm= boot param missing landlock). \
             alice stderr:\n{alice_stderr}"
        );
        drop(netns);
        return;
    }
    assert!(
        bob_stderr.contains("Entered sandbox"),
        "bob also under Landlock; stderr:\n{bob_stderr}"
    );

    // ─── host-up spawn failed (EACCES on /bin/sh shebang) ─────
    // THE LANDLOCK PROOF. periodic.rs::log_script logs spawn
    // failure at Error level ("Script host-up spawn failed: ...").
    // The error is the kernel's EACCES from the shebang chase.
    assert!(
        alice_stderr.contains("host-up spawn failed"),
        "host-up's #!/bin/sh shebang should EACCES under Landlock. \
         If this fires but ping above passed, either Landlock \
         partially-enforced and Execute wasn't handled, or someone \
         added a /bin rule. alice stderr:\n{alice_stderr}"
    );

    // (Dropped: addrcache write check. AddressCache::save fires in
    // Drop, but drain_stderr SIGKILLs → no Drop → cache/bob never
    // written. The host-up EACCES above is the Landlock proof; a
    // graceful-shutdown variant could prove the cache/ write but
    // that's a SIGTERM dance the existing real_tun_ping doesn't do
    // either. The MakeReg rule is exercised by sandbox::enter
    // pre-creating cache/ itself — which clearly worked since the
    // daemon entered FullyEnforced.)

    drop(netns);
}

/// `Sandbox = high` blocks ALL scripts via `can(StartProcesses)`.
/// The gate is intent-tracking (`sandbox::STATE` atomic), independent
/// of whether Landlock actually enforced — so this runs even on
/// kernels without Landlock, modulo the hard-fail check below.
///
/// Single daemon, no peer: the gate fires on tinc-down at
/// Daemon::Drop. If the witness file appears, `script::execute`'s
/// early-return is broken.
#[test]
fn sandbox_high_blocks_scripts() {
    use std::os::unix::fs::PermissionsExt;

    let Some(_netns) = enter_netns("sandbox_high_blocks_scripts") else {
        return;
    };

    let tmp = tmp("sboxhigh");
    let alice = Node::new(tmp.path(), "alice", 0xAD, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBD, "tinc1", "10.42.0.2/32");

    alice.write_config_with(&bob, false, "Sandbox = high\n");

    // tinc-down witness. At high, script::execute returns
    // Sandboxed BEFORE stat'ing the file. The shebang here would
    // ALSO fail under Landlock (same as sandbox_normal_ping's
    // host-up), but we're proving the EARLIER gate — the script
    // file is never touched. The witness-absent assert would catch
    // a regression where the can() check moved AFTER the spawn.
    let witness = alice.confbase.join("tinc-down-ran");
    let tinc_down = alice.confbase.join("tinc-down");
    std::fs::write(
        &tinc_down,
        format!("#!/bin/sh\ntouch '{}'\n", witness.display()),
    )
    .unwrap();
    let mut perm = std::fs::metadata(&tinc_down).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&tinc_down, perm).unwrap();

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        // Sandbox=high HARD-FAILS when Landlock is unavailable
        // (sandbox.rs enter_impl, the NotEnforced → Err arm).
        // Daemon never reaches the socket bind. SKIP.
        let stderr = drain_stderr(alice_child);
        if stderr.contains("Landlock is not available") {
            eprintln!("SKIP sandbox_high_blocks_scripts: {stderr}");
            return;
        }
        panic!("alice setup failed: {stderr}");
    }

    // tinc-up ALREADY RAN (before sandbox::enter, can()==true).
    // SIGTERM → RunOutcome::Clean → Daemon::Drop →
    // run_script("tinc-down") → gate. NOT child.kill() (SIGKILL):
    // that skips Drop entirely and the test would pass for the
    // wrong reason (tinc-down never even attempted).
    //
    // SAFETY: kill(2). We spawned this child; wait_for_file
    // confirmed it's alive and serving.
    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)] // pid_t fits a child PID
    unsafe {
        let rc = libc::kill(alice_child.id() as libc::pid_t, libc::SIGTERM);
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = alice_child.try_wait().unwrap() {
            break s;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "daemon didn't exit on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "daemon should exit 0 on SIGTERM");
    let stderr = {
        use std::io::Read;
        let mut s = String::new();
        alice_child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    };

    assert!(
        !witness.exists(),
        "tinc-down ran under Sandbox=high (witness file exists). \
         can(StartProcesses) gate failed. stderr:\n{stderr}"
    );

    // The debug-level log from periodic.rs::log_script. spawn()
    // sets RUST_LOG=tincd=debug.
    assert!(
        stderr.contains("tinc-down") && stderr.contains("Sandbox=high"),
        "expected 'Script tinc-down: skipped (Sandbox=high)' log; \
         stderr:\n{stderr}"
    );
}

// ═══════════════════════════ DNS stub ══════════════════════════════════════
//
// `dig @<magic-ip> bob.tinc.internal` against a real kernel.
//
// Same single-daemon shape as `real_tun_unreachable`: TUN read →
// intercept → TUN write, no peer needed. The kernel verifies the
// IPv4 header checksum AND the UDP checksum on the reply (silently
// drops if either is wrong); dig then verifies the DNS wire format.
// If `dig +short` prints `10.42.0.2`, the whole stack is correct.
//
// Subnet preload: `load_all_nodes` only adds other-node subnets to
// the tree under `StrictSubnets=yes` (no gossip to verify against
// here — single daemon). The rest of `dns.rs` is unit-tested; THIS
// test pins the IP/UDP wrap + the TUN-intercept hook + the kernel-
// level checksum verification.

#[test]
fn dns_stub_dig() {
    let Some(_netns) = enter_netns("dns_stub_dig") else {
        return;
    };

    // dig might not be in the bwrap'd PATH on minimal systems. SKIP
    // not FAIL — the unit tests cover the wire format already.
    if Command::new("dig").arg("-v").output().is_err() {
        eprintln!("SKIP dns_stub_dig: dig not found");
        return;
    }

    let tmp = tmp("dns");
    let alice = Node::new(tmp.path(), "alice", 0xAD, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBD, "tinc1", "10.42.0.2/32");

    // Single daemon, no ConnectTo — same as real_tun_unreachable.
    // `StrictSubnets=yes` forces `load_all_nodes` to preload bob's
    // /32 from `hosts/bob` (no gossip without a peer).
    // Magic IP: `10.42.0.53` — in the /24 the kernel routes to
    // tinc0, NOT any node's /32.
    alice.write_config_with(
        &bob,
        false,
        "StrictSubnets = yes\nDNSAddress = 10.42.0.53\nDNSSuffix = tinc.internal\n",
    );
    // hosts/bob: pubkey + Subnet so load_all_nodes picks up the /32.
    // The default write_config only puts Subnet in hosts/SELF.
    let bob_pub = tinc_crypto::b64::encode(&bob.pubkey());
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!("Ed25519PublicKey = {bob_pub}\nSubnet = 10.42.0.2/32\n"),
    )
    .unwrap();

    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF didn't bring carrier up; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // /24 → kernel routes 10.42.0.53 to tinc0. We DON'T add
    // 10.42.0.53 itself (the daemon answers for it via intercept;
    // adding it would make the kernel claim it locally and
    // shortcut via lo, never entering the TUN).
    run_ip(&["addr", "add", "10.42.0.1/24", "dev", "tinc0"]);
    run_ip(&["link", "set", "tinc0", "up"]);

    // ─── A query ─────────────────────────────────────────────────
    // `+short`: just the answer RDATA, no banner. `+tries=1
    // +timeout=2`: dig defaults to 3 tries × 5s; we want fast
    // fail. `+ignore`: don't retry over TCP if TC bit set (it
    // won't be — our answers are tiny — but belt and braces).
    let dig = Command::new("dig")
        .args([
            "@10.42.0.53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "+ignore",
            "bob.tinc.internal",
            "A",
        ])
        .output()
        .expect("spawn dig");

    let stdout = String::from_utf8_lossy(&dig.stdout);
    let stderr = String::from_utf8_lossy(&dig.stderr);
    eprintln!("dig A stdout: {stdout:?}\ndig A stderr: {stderr:?}");

    // dig exits 0 when it gets ANY response (including NXDOMAIN);
    // exit 9 = no reply at all (timeout). The latter means our
    // checksums are wrong — kernel dropped the reply silently.
    assert!(
        dig.status.success(),
        "dig timed out — reply never reached the kernel. \
         Either the IP checksum is wrong (ip_rcv drops silently), \
         the UDP checksum is wrong (udp_rcv drops silently), or \
         the intercept never matched (check the `tincd::dns` debug \
         log line). dig stderr: {stderr}\n\
         === alice ===\n{}",
        drain_stderr(alice_child)
    );
    assert_eq!(
        stdout.trim(),
        "10.42.0.2",
        "expected bob's /32; got {stdout:?}. \
         === alice ===\n{}",
        drain_stderr(alice_child)
    );

    // ─── PTR query ───────────────────────────────────────────────
    // `dig -x 10.42.0.2` is sugar for `2.0.42.10.in-addr.arpa PTR`.
    let dig_ptr = Command::new("dig")
        .args([
            "@10.42.0.53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "-x",
            "10.42.0.2",
        ])
        .output()
        .expect("spawn dig -x");

    let ptr_out = String::from_utf8_lossy(&dig_ptr.stdout);
    eprintln!("dig PTR stdout: {ptr_out:?}");
    assert!(dig_ptr.status.success(), "dig PTR timed out");
    // Trailing dot: dig prints FQDN form.
    assert_eq!(ptr_out.trim(), "bob.tinc.internal.");

    // ─── NXDOMAIN: name not in our suffix ────────────────────────
    // `+short` is empty for NXDOMAIN; check via the rcode in full
    // output. This proves we don't forward (forwarding would block
    // — there's no upstream resolver in the netns).
    let dig_nx = Command::new("dig")
        .args(["@10.42.0.53", "+tries=1", "+timeout=2", "google.com", "A"])
        .output()
        .expect("spawn dig nx");

    let nx_out = String::from_utf8_lossy(&dig_nx.stdout);
    assert!(dig_nx.status.success(), "dig NX timed out");
    assert!(
        nx_out.contains("NXDOMAIN"),
        "expected NXDOMAIN for non-suffix name (no forwarding); \
         got:\n{nx_out}"
    );

    // ─── daemon log: confirm the intercept fired ────────────────
    let alice_stderr = drain_stderr(alice_child);
    let dns_replies = alice_stderr.matches("tincd::dns").count();
    assert!(
        dns_replies >= 3,
        "expected ≥3 DNS log lines (A + PTR + NX); got {dns_replies}.\n\
         stderr:\n{alice_stderr}"
    );
}

/// IPv6: AAAA query over an IPv6 transport. Proves the v6 wrap
/// (mandatory UDP checksum, RFC 8200 §8.1 — kernel rejects zero).
///
/// Single daemon again. The TUN gets an fd00::/8 ULA prefix; the
/// magic DNS IP is `fd00::53`. Same kernel-verifies-checksum proof
/// as the v4 test, but the v6 UDP-over-pseudo-header sum is the
/// fiddly one (`dns.rs::wrap_v6` — the v4 sum is optional and
/// Linux accepts zero, so `wrap_v4_shape` could be silently wrong
/// and the v4 test would still pass).
#[test]
fn dns_stub_dig_v6() {
    let Some(_netns) = enter_netns("dns_stub_dig_v6") else {
        return;
    };

    if Command::new("dig").arg("-v").output().is_err() {
        eprintln!("SKIP dns_stub_dig_v6: dig not found");
        return;
    }

    let tmp = tmp("dns6");
    // The v4 /32 in the Node struct is unused here (the TUN gets
    // a v6 prefix only); we set it because `Node::new` wants one.
    let alice = Node::new(tmp.path(), "alice", 0xAE, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBE, "tinc1", "10.42.0.2/32");

    alice.write_config_with(
        &bob,
        false,
        "StrictSubnets = yes\nDNSAddress = fd00::53\nDNSSuffix = tinc.internal\n",
    );
    // hosts/bob: v6 /128. load_all_nodes preloads it.
    let bob_pub = tinc_crypto::b64::encode(&bob.pubkey());
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!("Ed25519PublicKey = {bob_pub}\nSubnet = fd00::2/128\n"),
    )
    .unwrap();

    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "carrier; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // ULA /64. fd00::53 falls inside; kernel routes it to tinc0.
    // `nodad`: skip Duplicate Address Detection (~1s probe before
    // the address goes ACTIVE); we own the netns, no neighbors.
    run_ip(&["addr", "add", "fd00::1/64", "dev", "tinc0", "nodad"]);
    run_ip(&["link", "set", "tinc0", "up"]);

    // ─── AAAA query, IPv6 transport ──────────────────────────────
    // The `@fd00::53` server address forces the v6 transport;
    // `match_v6` has to fire, `wrap_v6` has to checksum correctly.
    let dig = Command::new("dig")
        .args([
            "@fd00::53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "+ignore",
            "bob.tinc.internal",
            "AAAA",
        ])
        .output()
        .expect("spawn dig");

    let stdout = String::from_utf8_lossy(&dig.stdout);
    let stderr = String::from_utf8_lossy(&dig.stderr);
    eprintln!("dig AAAA stdout: {stdout:?}\nstderr: {stderr:?}");

    assert!(
        dig.status.success(),
        "dig timed out — v6 UDP checksum is mandatory (RFC 8200 \
         §8.1); the kernel drops zero or wrong sum SILENTLY. \
         wrap_v6's pseudo-header chaining is the suspect. \
         dig stderr: {stderr}\n=== alice ===\n{}",
        drain_stderr(alice_child)
    );
    // dig may print compressed (`fd00::2`) or expanded; normalize.
    let got: std::net::Ipv6Addr = stdout
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("dig output not an IPv6 addr: {stdout:?}"));
    let want: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
    assert_eq!(got, want, "=== alice ===\n{}", drain_stderr(alice_child));

    // ─── v6 PTR (32-nibble ip6.arpa) ─────────────────────────────
    let dig_ptr = Command::new("dig")
        .args([
            "@fd00::53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "-x",
            "fd00::2",
        ])
        .output()
        .expect("spawn dig -x v6");

    let ptr_out = String::from_utf8_lossy(&dig_ptr.stdout);
    eprintln!("dig PTR v6 stdout: {ptr_out:?}");
    assert!(dig_ptr.status.success(), "dig PTR v6 timed out");
    assert_eq!(ptr_out.trim(), "bob.tinc.internal.");

    drop(drain_stderr(alice_child));
}
