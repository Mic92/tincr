use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use std::time::Duration;

use super::common::linux::run_ip;
use super::common::{Ctl, alloc_port, pubkey_from_seed, tincd_cmd, write_ed25519_privkey};

// ═════════════════════════ the bwrap re-exec wrapper ══════════════════════

/// Re-exec the current test binary inside bwrap. See module doc.
///
/// `Some(NetNs)` → we ARE inside; run the test body.
/// `None` → outer pass spawned-and-waited (or SKIP); body must not run.
pub(crate) fn enter_netns(test_name: &str) -> Option<NetNs> {
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

pub(crate) struct Node {
    name: &'static str,
    seed: [u8; 32],
    pub(crate) confbase: PathBuf,
    pidfile: PathBuf,
    pub(crate) socket: PathBuf,
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
    pub(crate) fn new(
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

    pub(crate) fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    pub(crate) fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    /// Write `tinc.conf` + `hosts/NAME` + `ed25519_key.priv` +
    /// `hosts/OTHER`. `connect_to` toggles `ConnectTo` + Address.
    /// `DeviceType = tun` + `Interface = ...` (vs `two_daemons.rs`'s
    /// `dummy`/`fd`). Subnet always set.
    pub(crate) fn write_config(&self, other: &Node, connect_to: bool) {
        self.write_config_with(other, connect_to, "");
    }

    /// `extra` is appended verbatim to tinc.conf. Used by the
    /// sandbox tests for `Sandbox = normal\n`. Empty string for the
    /// common case (the wrapper above).
    pub(crate) fn write_config_with(&self, other: &Node, connect_to: bool, extra: &str) {
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
        // Linux TUN unconditionally uses IFF_VNET_HDR.
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

    pub(crate) fn spawn(&self) -> Child {
        self.spawn_with_log("tincd=debug")
    }

    /// Spawn with explicit `RUST_LOG`. The `tso_ingest_stream_
    /// integrity` test pushes 8 MiB through; at `debug` per-packet
    /// log volume the 64 KiB stderr pipe fills and the daemon
    /// blocks on `write(2, ...)`. Same issue throughput.rs hit
    /// (see `ChildWithLog`); here we just turn the volume down.
    pub(crate) fn spawn_with_log(&self, rust_log: &str) -> Child {
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
