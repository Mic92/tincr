//! Failing reproducer: simultaneous `REQ_KEY` initiation livelock.
//!
//! ## Symptom (production retiolum, Rust↔Rust)
//!
//! ```text
//! tincd[...]: Got REQ_KEY from irene while we already started a SPTPS session!
//! tincd[...]: Got REQ_KEY from eva while we already started a SPTPS session!
//! ```
//!
//! …recurring every ~30–90 s per peer in steady state. C tinc logs the
//! same line (`protocol_key.c::req_key_h`) but only on genuine
//! reconnect, never periodically. Our message is
//! `gossip.rs::on_req_key`: `"while SPTPS already started; restarting"`.
//!
//! ## Mechanism (hypothesis — NOT fixed here)
//!
//! Both ends have traffic for the other at the same instant, so both
//! hit `txpath::try_tx` → `!validkey && !waitingforkey` →
//! `send_req_key` (`Role::Initiator`) before either's `REQ_KEY` arrives.
//! Each side's `REQ_KEY` then lands in `on_req_key`, which
//! UNCONDITIONALLY resets the local SPTPS to `Role::Responder` and
//! clears `validkey`. Now both sides are Responder; nobody sends SIG;
//! after `try_tx`'s 10 s `last_req_key` debounce both restart as
//! Initiator again → loop. C tinc's `req_key_ext_h` has the same
//! reset, but its `try_tx` ladder and `last_req_key` bookkeeping
//! differ subtly enough that one side wins the second round.
//!
//! ## What this test does
//!
//! Two Rust `tincd` (alice ↔ bob), each `ConnectTo` the other. After
//! the meta handshake completes, fire `ping` from BOTH netns at the
//! same wall-clock moment so both `try_tx` paths fire `send_req_key`
//! before either `REQ_KEY` crosses. Then watch 30 s of steady state:
//!
//! - `validkey` reaches steady state and never flaps (sampled every
//!   200 ms via control socket).
//! - the peer never becomes `unreachable` again after the first
//!   dedup — i.e. the meta-conn dedup doesn't redial in a loop.
//! - `"SPTPS already started"` does NOT recur after `validkey`
//!   settles. Pre-`validkey` crossings are protocol-inherent (C
//!   tinc has them too, bounded by the 10 s `try_tx` retry); the
//!   pre-fix behaviour was unbounded steady-state recurrence
//!   driven by the dedup redial loop.
//!
//! Optional cross-check `reqkey_simultaneous_rust_c`: same topology,
//! bob = C `tincd` (`TINC_C_TINCD`). The C side does NOT recur →
//! proves regression, not protocol-inherent.
//!
//! Fixed by the `outgoing` transfer + name tie-break in
//! `connect.rs::on_ack` dedup (the redial loop was the actual
//! recurrence driver; `on_req_key` matches C and has no per-tunnel
//! tie-break). The Rust↔Rust case runs in CI; the Rust↔C control
//! stays `#[ignore]` (30 s wall + `TINC_C_TINCD` gate).
//!
//! ```sh
//! cargo test -p tincd --test reqkey_simultaneous -- --ignored --nocapture
//! ```

// Needs bwrap/netns + tc netem to reliably reproduce the REQ_KEY race.
#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::linux::{ChildWithLog, run_ip, wait_for_carrier};
use common::{
    Ctl, TmpGuard, alloc_port, node_status, poll_until, pubkey_from_seed, wait_for_file,
    write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("rqk", tag)
}

const VALIDKEY: u32 = 0x02;
const REACHABLE: u32 = 0x10;

/// The log line `on_req_key` emits when a peer's `REQ_KEY` arrives
/// after we already `send_req_key`'d. ONE occurrence per side on the
/// initial crossing is fine; recurrence is the bug.
const RESTART_MARKER: &str = "SPTPS already started";

// ═════════════════════════ bwrap re-exec ═════════════════════════════════
// Same trick as `netns/rig.rs` / `crossimpl.rs` (see those for the
// flag-by-flag rationale). Copied, not factored: the `--exact
// <test_name>` re-exec needs the name statically and the device
// names are namespaced per test file. Device names `tincR0/tincR1`,
// child netns `rbobside`.

fn enter_netns(test_name: &str) -> Option<NetNs> {
    if std::env::var_os("BWRAP_INNER").is_some() {
        return Some(NetNs::setup());
    }
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
            eprintln!(
                "SKIP {test_name}: bwrap probe failed (unprivileged userns disabled?): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        Ok(_) => {}
    }
    if !std::path::Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing");
        return None;
    }

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
        // `--include-ignored`: the Rust↔Rust test is no longer
        // `#[ignore]`, but the Rust↔C control is. The OUTER process
        // already decided to run (it was invoked with `--ignored` or
        // not); the inner re-exec must run whichever test name it was
        // handed regardless of its ignore attr.
        .args([
            "--exact",
            test_name,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    None
}

struct NetNs {
    sleeper: Child,
}

impl NetNs {
    fn setup() -> Self {
        run_ip(&["link", "set", "lo", "up"]);
        // 50 ms on lo: forces the REQ_KEYs to cross (bare loopback
        // is µs, no overlap). Both daemons run in the outer netns
        // and talk meta over 127.0.0.1; control sockets and TUN are
        // unaffected.
        let tc = Command::new("tc")
            .args([
                "qdisc", "add", "dev", "lo", "root", "netem", "delay", "50ms",
            ])
            .output()
            .expect("spawn tc");
        assert!(
            tc.status.success(),
            "tc netem on lo failed: {}",
            String::from_utf8_lossy(&tc.stderr)
        );
        run_ip(&["tuntap", "add", "mode", "tun", "name", "tincR0"]);
        run_ip(&["tuntap", "add", "mode", "tun", "name", "tincR1"]);
        run_ip(&["link", "set", "tincR0", "up"]);
        run_ip(&["link", "set", "tincR1", "up"]);

        std::fs::create_dir_all("/run/netns").expect("mkdir /run/netns");
        let sleeper = Command::new("unshare")
            .args(["-n", "sleep", "3600"])
            .spawn()
            .expect("spawn unshare sleeper");
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write("/run/netns/rbobside", b"").expect("touch nsfd target");
        let status = Command::new("mount")
            .args(["--bind"])
            .arg(format!("/proc/{}/ns/net", sleeper.id()))
            .arg("/run/netns/rbobside")
            .status()
            .expect("spawn mount");
        assert!(status.success(), "mount --bind nsfd: {status:?}");
        run_ip(&["netns", "exec", "rbobside", "ip", "link", "set", "lo", "up"]);
        Self { sleeper }
    }

    #[allow(clippy::unused_self)] // mirrors crossimpl.rs::NetNs API
    fn place_devices(&self) {
        run_ip(&["link", "set", "tincR1", "netns", "rbobside"]);
        run_ip(&["addr", "add", "10.44.0.1/24", "dev", "tincR0"]);
        run_ip(&["link", "set", "tincR0", "up"]);
        run_ip(&[
            "netns",
            "exec",
            "rbobside",
            "ip",
            "addr",
            "add",
            "10.44.0.2/24",
            "dev",
            "tincR1",
        ]);
        run_ip(&[
            "netns", "exec", "rbobside", "ip", "link", "set", "tincR1", "up",
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

#[derive(Clone, Copy)]
enum Impl {
    Rust,
    C,
}

struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    port: u16,
    iface: &'static str,
    subnet: &'static str,
    which: Impl,
}

impl Node {
    fn new(
        tmp: &std::path::Path,
        name: &'static str,
        seed_byte: u8,
        iface: &'static str,
        subnet: &'static str,
        which: Impl,
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
            which,
        }
    }

    fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    /// Both sides `ConnectTo` the other AND advertise their own
    /// subnet — symmetric config so both ends want the tunnel.
    /// `PingInterval = 2` so the periodic `try_tx` keepalive (the
    /// 10 s `last_req_key` restart in `txpath.rs`) ticks several
    /// times in the 30 s window.
    fn write_config(&self, other: &Node) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = ipv4\n",
            self.name, self.iface
        );
        let _ = writeln!(tinc_conf, "ConnectTo = {}", other.name);
        tinc_conf.push_str("PingInterval = 2\nPingTimeout = 5\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        std::fs::write(
            self.confbase.join("hosts").join(self.name),
            format!("Port = {}\nSubnet = {}\n", self.port, self.subnet),
        )
        .unwrap();

        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        std::fs::write(
            self.confbase.join("hosts").join(other.name),
            format!(
                "Ed25519PublicKey = {other_pub}\nAddress = 127.0.0.1 {}\nSubnet = {}\n",
                other.port, other.subnet
            ),
        )
        .unwrap();

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    fn spawn(&self) -> ChildWithLog {
        let child = match self.which {
            Impl::Rust => Command::new(common::tincd_bin())
                .arg("-D")
                .arg("-c")
                .arg(&self.confbase)
                .arg("--pidfile")
                .arg(&self.pidfile)
                .arg("--socket")
                .arg(&self.socket)
                .env("RUST_LOG", "tincd=debug")
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rust tincd"),
            Impl::C => {
                Command::new(std::env::var_os("TINC_C_TINCD").expect("TINC_C_TINCD gate checked"))
                    .arg("-D")
                    .arg("-d5")
                    .arg("-c")
                    .arg(&self.confbase)
                    .arg("--pidfile")
                    .arg(&self.pidfile)
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn C tincd")
            }
        };
        ChildWithLog::spawn(child)
    }
}

// ═══════════════════════════════ the tests ═════════════════════════════════

/// Count occurrences of `RESTART_MARKER` in a daemon's stderr. The
/// Rust side logs `"while SPTPS already started; restarting"`; the C
/// side logs `"while we already started a SPTPS session"`. Both
/// contain `RESTART_MARKER`.
fn count_restarts(log: &str) -> usize {
    log.matches(RESTART_MARKER).count()
}

fn run_reqkey_race(tag: &str, bob_impl: Impl, netns: NetNs) {
    let tmp = tmp(tag);
    let alice = Node::new(
        tmp.path(),
        "alice",
        0xAA,
        "tincR0",
        "10.44.0.1/32",
        Impl::Rust,
    );
    let bob = Node::new(tmp.path(), "bob", 0xBB, "tincR1", "10.44.0.2/32", bob_impl);

    alice.write_config(&bob);
    bob.write_config(&alice);

    // Both listen + dial. Spawn order is irrelevant for the race;
    // what matters is the simultaneous traffic kick AFTER both are
    // reachable. The 50 ms netem on lo means the meta handshake
    // takes ~500 ms instead of ~5 ms; `poll_until(10 s)` covers it.
    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        alice_child.kill_and_log()
    );
    let bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let al = alice_child.kill_and_log();
        panic!(
            "bob setup failed; stderr:\n{}\n=== alice ===\n{al}",
            bob_child.kill_and_log()
        );
    }

    if !wait_for_carrier("tincR0", Duration::from_secs(2)) {
        let al = alice_child.kill_and_log();
        let bl = bob_child.kill_and_log();
        panic!("alice TUNSETIFF;\n=== alice ===\n{al}\n=== bob ===\n{bl}");
    }
    assert!(
        wait_for_carrier("tincR1", Duration::from_secs(2)),
        "bob TUNSETIFF"
    );
    netns.place_devices();

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // ─── meta handshake ─────────────────────────────────────────
    // Mutual ConnectTo means TWO meta connections may form (one each
    // direction); the daemon dedups on ACK. We only care that both
    // see the other reachable. validkey is NOT yet set — TUN emits
    // no spontaneous traffic so neither side has hit `try_tx` yet.
    let meta = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & REACHABLE != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & REACHABLE != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if meta.is_err() {
        let al = alice_child.kill_and_log();
        let bl = bob_child.kill_and_log();
        panic!("meta handshake timed out;\n=== alice ===\n{al}\n=== bob ===\n{bl}");
    }

    // ─── THE SIMULTANEOUS KICK ──────────────────────────────────
    // Fire ping from BOTH netns at once so both `try_tx` →
    // `send_req_key` while the other's REQ_KEY is in flight.
    // bob's ping stops after 2 s: with C-faithful `on_req_key`
    // (no tie-break, both reset to Responder) the 10 s retry only
    // fires from the side with traffic. Symmetric continuous ping
    // would re-cross every 10 s — protocol-inherent, C has it too,
    // not what production sees.
    let mut ping_a = Command::new("ping")
        .args(["-i", "0.1", "-W", "1", "10.44.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping alice→bob");
    let mut ping_b = Command::new("ip")
        .args([
            "netns", "exec", "rbobside", "ping", "-c", "20", "-i", "0.1", "-W", "1",
        ])
        .arg("10.44.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping bob→alice");

    // ─── 30 s observation window ─────────────────────────────────
    // Sample validkey every 200 ms. Once both have it, snapshot the
    // restart count: any FURTHER restart after that point is the
    // bug (steady-state recurrence). Pre-validkey crossings are
    // protocol-inherent (C tinc has them too) and bounded by the
    // 10 s `try_tx` retry; we don't assert on those.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut steady_since: Option<Instant> = None;
    let mut validkey_flaps = 0u32;
    let mut last_both_valid = false;
    let mut restarts_at_steady: Option<(usize, usize)> = None;

    while Instant::now() < deadline {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_valid = node_status(&a, "bob").is_some_and(|s| s & VALIDKEY != 0);
        let b_valid = node_status(&b, "alice").is_some_and(|s| s & VALIDKEY != 0);
        let both = a_valid && b_valid;
        if both && steady_since.is_none() {
            steady_since = Some(Instant::now());
            restarts_at_steady = Some((
                count_restarts(&alice_child.log_snapshot()),
                count_restarts(&bob_child.log_snapshot()),
            ));
        }
        if last_both_valid && !both {
            validkey_flaps += 1;
        }
        last_both_valid = both;
        // Once steady for 10 s, stop early.
        if steady_since.is_some_and(|t| t.elapsed() >= Duration::from_secs(10)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let _ = ping_a.kill();
    let _ = ping_a.wait();
    let _ = ping_b.wait();

    let alice_log = alice_child.log_snapshot();
    let bob_log = bob_child.log_snapshot();
    let a_restarts = count_restarts(&alice_log);
    let b_restarts = count_restarts(&bob_log);

    eprintln!(
        "── reqkey_simultaneous summary ──\n\
         alice restarts: {a_restarts}, bob restarts: {b_restarts}\n\
         validkey flaps: {validkey_flaps}, steady_since: {steady_since:?}"
    );

    drop(alice_ctl);
    drop(bob_ctl);
    let alice_full = alice_child.kill_and_log();
    let bob_full = bob_child.kill_and_log();
    drop(netns);

    // ─── assertions ─────────────────────────────────────────────
    let a_unreach = alice_full.matches("became unreachable").count();
    let b_unreach = bob_full.matches("became unreachable").count();
    assert!(
        a_unreach <= 1 && b_unreach <= 1,
        "meta-conn dedup is redialling (alice {a_unreach}, bob {b_unreach} unreachable);\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );
    if let Some((a0, b0)) = restarts_at_steady {
        assert!(
            a_restarts == a0 && b_restarts == b0,
            "REQ_KEY restarted AFTER validkey settled \
             (alice {a0}\u{2192}{a_restarts}, bob {b0}\u{2192}{b_restarts});\n\
             === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
        );
    }
    assert!(
        steady_since.is_some(),
        "validkey never set on both sides within 30 s;\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );
    assert_eq!(
        validkey_flaps, 0,
        "validkey flapped {validkey_flaps}× during steady state;\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );
}

/// Rust ↔ Rust. Regression for the mutual-`ConnectTo` dedup redial
/// loop that drove recurring `REQ_KEY` crossings in production.
#[test]
fn reqkey_simultaneous_rust_rust() {
    let Some(netns) = enter_netns("reqkey_simultaneous_rust_rust") else {
        return;
    };
    run_reqkey_race("rr", Impl::Rust, netns);
}

/// Rust ↔ C control. Same topology, bob = C tincd. Should PASS
/// (≤1 restart per side) — proves the recurrence is our bug, not
/// protocol-inherent. Gated on `TINC_C_TINCD` like `crossimpl.rs`.
/// Also `#[ignore]` (30 s wall clock; opt-in only).
#[test]
#[ignore = "30 s wall-clock; cross-impl control for reqkey-race reproducer"]
fn reqkey_simultaneous_rust_c() {
    if std::env::var_os("TINC_C_TINCD").is_none() {
        eprintln!("SKIP reqkey_simultaneous_rust_c: TINC_C_TINCD not set");
        return;
    }
    let Some(netns) = enter_netns("reqkey_simultaneous_rust_c") else {
        return;
    };
    run_reqkey_race("rc", Impl::C, netns);
}
