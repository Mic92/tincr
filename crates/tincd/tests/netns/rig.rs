use std::process::{Child, Command, Stdio};

use std::time::Duration;

use super::common::linux::run_ip;
pub(crate) use super::common::node::Node;

// ═════════════════════════ the bwrap re-exec wrapper ══════════════════════

/// Re-exec the current test binary inside bwrap. See module doc.
///
/// `Some(NetNs)` → we ARE inside; run the test body.
/// `None` → outer pass spawned-and-waited (or SKIP); body must not run.
pub(crate) fn enter_netns(test_name: &str) -> Option<NetNs> {
    enter_bwrap(test_name).then(NetNs::setup)
}

/// Just the bwrap re-exec, no `NetNs::setup` (no precreated TUNs,
/// no `bobside` child ns). Tests that build their own multi-netns
/// topology (e.g. `portmap::upnp_miniupnpd_gateway`) call this and
/// then [`make_child_netns`] / veth themselves.
///
/// `true` → inside bwrap, run body. `false` → outer pass done/SKIP.
pub(crate) fn enter_bwrap(test_name: &str) -> bool {
    if std::env::var_os("BWRAP_INNER").is_some() {
        // lo up: every topology needs it; cheap, idempotent.
        run_ip(&["link", "set", "lo", "up"]);
        std::fs::create_dir_all("/run/netns").expect("mkdir /run/netns");
        return true;
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
            return false;
        }
        Ok(out) if !out.status.success() => {
            let why = String::from_utf8_lossy(&out.stderr);
            eprintln!(
                "SKIP {test_name}: bwrap probe failed (unprivileged \
                 userns disabled?): {}",
                why.trim()
            );
            return false;
        }
        Ok(_) => {}
    }
    // /dev/net/tun must exist on the HOST (we dev-bind it).
    if !std::path::Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing (CONFIG_TUN=n?)");
        return false;
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
        // --exact with the FULL libtest path. Callers pass
        // "module::leaf" (e.g. "ping::real_tun_ping"). Previously
        // callers passed only the leaf name: zero matches, libtest
        // exit 0 (no tests is success), outer assert passes. Every
        // netns test was a silent no-op for months. The tell: <50ms
        // "PASS" for tests that build netns + spawn daemons + pipe
        // MiBs through them.
        //
        // Substring (no --exact) was tried; "dns_stub_dig" matched
        // "dns_stub_dig_v6" too → both ran in one bwrap → EBUSY on
        // tinc0. --exact + full path is correct. Watch for future
        // module renames silently re-breaking this.
        // `--include-ignored`: the outer pass already decided to run
        // THIS test (by name, via `--exact`); if it was `#[ignore]`d
        // and the outer libtest was given `--ignored`, the inner
        // libtest must not re-filter it. Harmless for non-ignored
        // tests (the flag is additive).
        .args([
            "--exact",
            test_name,
            "--nocapture",
            "--test-threads=1",
            "--include-ignored",
        ])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    false
}

/// One `unshare -n sleep` child netns, bind-mounted at
/// `/run/netns/NAME` so `ip netns exec NAME ...` works. Returns the
/// sleeper; killing it does NOT destroy the ns (mount keeps it),
/// but the whole bwrap exiting does. Same dance as `NetNs::setup`'s
/// `bobside`, generalised — `ip netns add` won't work in a userns
/// (it wants `mount --make-shared`).
pub(crate) fn make_child_netns(name: &str) -> Child {
    let sleeper = Command::new("unshare")
        .args(["-n", "sleep", "3600"])
        .spawn()
        .expect("spawn unshare sleeper");
    // Race: netns not ready until unshare(2) ran in the child.
    std::thread::sleep(Duration::from_millis(100));
    let target = format!("/run/netns/{name}");
    std::fs::write(&target, b"").expect("touch nsfd target");
    let st = Command::new("mount")
        .args(["--bind"])
        .arg(format!("/proc/{}/ns/net", sleeper.id()))
        .arg(&target)
        .status()
        .expect("spawn mount");
    assert!(st.success(), "mount --bind nsfd for {name}: {st:?}");
    run_ip(&["netns", "exec", name, "ip", "link", "set", "lo", "up"]);
    sleeper
}

/// `ip link add A type veth peer name B`, move each end into its
/// netns, addr+up. `addr` is `IP/PREFIX`. `(ns, ifname, addr)`.
pub(crate) fn veth_pair(a: (&str, &str, &str), b: (&str, &str, &str)) {
    run_ip(&["link", "add", a.1, "type", "veth", "peer", "name", b.1]);
    for (ns, ifc, ip) in [a, b] {
        run_ip(&["link", "set", ifc, "netns", ns]);
        run_ip(&["netns", "exec", ns, "ip", "addr", "add", ip, "dev", ifc]);
        run_ip(&["netns", "exec", ns, "ip", "link", "set", ifc, "up"]);
    }
}

/// Handle for the inner-side netns state. `setup()` brings up `lo`,
/// precreates persistent TUN devices, builds the child netns.
/// Dropping kills the child-netns sleeper (devices vanish with the
/// userns when the inner test process exits — no explicit teardown).
pub(crate) struct NetNs {
    /// Holds the child netns open. `unshare -n sleep <big>`. The
    /// nsfd is bind-mounted at `/run/netns/bobside` so `ip netns
    /// exec` works. Killing this DOESN'T destroy the netns (the
    /// mount keeps it alive); but the whole bwrap process exiting
    /// does.
    sleeper: Child,
}

impl NetNs {
    pub(crate) fn setup() -> Self {
        // lo up + /run/netns mkdir: done by `enter_bwrap`.

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
        let sleeper = make_child_netns("bobside");

        Self { sleeper }
    }

    /// Called AFTER both daemons have done TUNSETIFF (carrier up
    /// on both). Moves bob's TUN into the child netns and
    /// configures addresses on both. Moving an interface resets
    /// its UP state and flushes addresses, so configure AFTER move.
    #[expect(clippy::unused_self)] // method form keeps the call ordered after NetNs::setup
    pub(crate) fn place_devices(&self) {
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

/// netns-shaped node: real TUN attach + /32 subnet.
pub(crate) fn tun_node(
    tmp: &std::path::Path,
    name: &'static str,
    seed: u8,
    iface: &'static str,
    subnet: &'static str,
) -> Node {
    Node::new(tmp, name, seed).iface(iface).subnet(subnet)
}
