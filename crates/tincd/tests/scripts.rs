//! Port of `test/integration/scripts.py`: prove `tincd` fires
//! `tinc-up`/`tinc-down`/`host-up`/`host-down`/`subnet-up`/
//! `subnet-down` in the **correct order** with the **correct env
//! vars**.
//!
//! ## Mechanism
//!
//! The Python suite spins up a notification socket and has each
//! script connect back with its env. We don't need that machinery:
//! `script::execute` (`script.rs:194`) blocks on `Command::output()`,
//! so scripts run **synchronously** in the daemon's thread. A 3-line
//! shell appender writing `script|timestamp|ENV=...` to one shared
//! log file is enough — append order IS execution order.
//!
//! ## What this caught
//!
//! Writing `tinc_up_then_own_subnet_up` revealed `daemon.rs::setup()`
//! ran `tinc-up` but skipped firing `subnet-up` for our OWN
//! configured subnets at startup. Same gap mirrored in `Drop`
//! (`subnet-down` should fire before `tinc-down`). Both are now
//! fixed; this file pins them.
//!
//! ## Skipped (vs the Python)
//!
//! - `NETNAME` env var: `periodic.rs:266` documents this isn't
//!   threaded through (it's a `-n` flag concern in `main.rs`).
//! - `DEBUG` env var: same deal.
//! - `invitation-created`/`invitation-accepted`: covered by the
//!   `tinc_join_against_real_daemon` test elsewhere.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{
    TmpGuard, alloc_port, drain_stderr, pubkey_from_seed, tincd_cmd,
    wait_for_file_with as wait_for_file, write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("scripts", tag)
}

/// Minimal node fixture. Dummy device only — no fd plumbing here.
struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    port: u16,
}

impl Node {
    fn new(tmp: &Path, name: &'static str, seed_byte: u8) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
        }
    }

    fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    /// Write config. `peer` for cross-registration (pubkey + maybe
    /// Address). `connect_to` adds `ConnectTo = peer`. `subnets` go
    /// into `hosts/SELF`. Dummy device always.
    fn write_config(&self, peer: Option<&Node>, connect_to: bool, subnets: &[&str]) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\n",
            self.name
        );
        if connect_to {
            let p = peer.expect("connect_to requires peer");
            let _ = writeln!(tinc_conf, "ConnectTo = {}", p.name);
        }
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port + Subnets.
        let mut self_cfg = format!("Port = {}\n", self.port);
        for s in subnets {
            let _ = writeln!(self_cfg, "Subnet = {s}");
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        // hosts/PEER — pubkey + maybe Address.
        if let Some(p) = peer {
            let pk = tinc_crypto::b64::encode(&p.pubkey());
            let mut cfg = format!("Ed25519PublicKey = {pk}\n");
            if connect_to {
                let _ = writeln!(cfg, "Address = 127.0.0.1 {}", p.port);
            }
            std::fs::write(self.confbase.join("hosts").join(p.name), cfg).unwrap();
        }

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    fn spawn(&self) -> Child {
        tincd_cmd()
            .arg("-c")
            .arg(&self.confbase)
            .arg("--pidfile")
            .arg(&self.pidfile)
            .arg("--socket")
            .arg(&self.socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }
}

// ═══════════════════════════════════════════════════════════════════
// Script appender + log parsing

/// Write a 3-line shell appender. ALL scripts write to one log file:
///
/// ```text
/// script-name|NAME=x|NODE=y|SUBNET=z|WEIGHT=w|REMOTEADDRESS=a|REMOTEPORT=p|INTERFACE=i
/// ```
///
/// `|`-separated; values never contain `|`. No timestamp needed:
/// scripts run synchronously (`script::execute` → `Command::status()`
/// blocks), so **append order IS firing order**.
///
/// Shebang required — `Command::output` is direct `execve()`, not
/// `sh -c`; a shebang-less script fails `ENOEXEC`.
fn write_script(confbase: &Path, name: &str, log: &Path) {
    let path = confbase.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    // `basename "$0"` gets just `tinc-up`/`bob-up`, not the full
    // path. The `hosts/` prefix is recovered at parse time by
    // matching against the known per-node script names.
    let body = format!(
        "#!/bin/sh\n\
         printf '%s|NAME=%s|NODE=%s|SUBNET=%s|WEIGHT=%s|REMOTEADDRESS=%s|REMOTEPORT=%s|INTERFACE=%s\\n' \
           \"$(basename \"$0\")\" \
           \"$NAME\" \"$NODE\" \"$SUBNET\" \"$WEIGHT\" \"$REMOTEADDRESS\" \"$REMOTEPORT\" \"$INTERFACE\" \
           >> '{}'\n",
        log.display()
    );
    std::fs::write(&path, body).unwrap();
    let mut perm = std::fs::metadata(&path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm).unwrap();
}

/// Install the full set: `tinc-up`/`tinc-down`/`host-up`/
/// `host-down`/`subnet-up`/`subnet-down` plus per-node
/// `hosts/{peer}-up` and `hosts/{peer}-down` if `peer` given.
fn write_all_scripts(confbase: &Path, log: &Path, peer: Option<&str>) {
    for s in &[
        "tinc-up",
        "tinc-down",
        "host-up",
        "host-down",
        "subnet-up",
        "subnet-down",
    ] {
        write_script(confbase, s, log);
    }
    if let Some(p) = peer {
        write_script(confbase, &format!("hosts/{p}-up"), log);
        write_script(confbase, &format!("hosts/{p}-down"), log);
    }
}

#[derive(Debug, Clone)]
struct Event {
    /// `tinc-up`, `host-up`, `bob-up` (per-node scripts log just
    /// the basename; `hosts/` prefix is gone).
    script: String,
    /// Unset env vars come through as empty strings (`"$FOO"` with
    /// FOO unset → empty in POSIX sh).
    env: HashMap<String, String>,
}

fn read_log(path: &Path) -> Vec<Event> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let mut parts = line.split('|');
            let script = parts.next().unwrap().to_owned();
            let env = parts
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            Event { script, env }
        })
        .collect()
}

/// Poll until `pred` matches the log, or timeout. Returns the
/// matched events.
fn wait_for_events<F>(log: &Path, timeout: Duration, pred: F) -> Vec<Event>
where
    F: Fn(&[Event]) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let events = read_log(log);
        if pred(&events) {
            return events;
        }
        if Instant::now() >= deadline {
            return events; // Let the caller's assert print what we DID get.
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ═══════════════════════════════════════════════════════════════════
// Test 1: tinc-up THEN subnet-up for OWN subnets at startup.
//
// `device_enable()` (= tinc-up) THEN subnet-up for every
// configured Subnet. The order matters: tinc-up typically does
// `ip addr add` / `ip link set up`; subnet-up scripts (which might
// add routes) assume the interface is configured.
//
// THIS WAS THE BUG: `daemon.rs::setup()` ran tinc-up but never
// looped subnet-up over `myself`'s subnets. Now fixed.

#[test]
fn tinc_up_then_own_subnet_up() {
    let tmp = tmp("startup");
    let log = tmp.path().join("events.log");

    let alice = Node::new(tmp.path(), "alice", 0xA1);
    // Two subnets: one v4 with non-default weight (`#5`), one v6
    // default weight. The Python `scripts.py` exercises both
    // (`SUBNETS_SERVER`).
    alice.write_config(None, false, &["10.0.1.0/24#5", "fec0::/64"]);
    write_all_scripts(&alice.confbase, &log, None);

    let alice_child = alice.spawn();
    // tinc-up + 2× subnet-up = 3 events. setup() runs them all
    // synchronously before binding the control socket.
    let events = wait_for_events(&log, Duration::from_secs(5), |e| e.len() >= 3);

    assert!(
        events.len() >= 3,
        "expected 3 events (tinc-up + 2× subnet-up), got {}: {events:#?}\nstderr:\n{}",
        events.len(),
        drain_stderr(alice_child)
    );

    // ─── Event 0: tinc-up
    // Base env only: NAME + INTERFACE (`periodic.rs::run_script`).
    // NODE/SUBNET/WEIGHT/REMOTEADDRESS unset → empty.
    assert_eq!(events[0].script, "tinc-up", "first event must be tinc-up");
    assert_eq!(events[0].env["NAME"], "alice");
    // `DeviceType = dummy` → `tinc-device::Dummy::iface()` → "dummy".
    assert_eq!(events[0].env["INTERFACE"], "dummy");
    assert_eq!(events[0].env["NODE"], "");
    assert_eq!(events[0].env["SUBNET"], "");

    // ─── Events 1..3: subnet-up for OWN subnets
    // NODE = our own name (`periodic.rs::run_subnet_script` sets
    // NODE=owner; here owner==myself). REMOTEADDRESS unset (the
    // `if owner != self.name` guard in `run_subnet_script` skips it).
    // Order between the two subnet-ups is iter order; don't pin it.
    let subnet_ups: Vec<&Event> = events[1..3].iter().collect();
    for ev in &subnet_ups {
        assert_eq!(ev.script, "subnet-up", "events: {events:#?}");
        assert_eq!(ev.env["NAME"], "alice");
        assert_eq!(ev.env["NODE"], "alice", "own subnet → NODE=self");
        assert_eq!(ev.env["INTERFACE"], "dummy");
        assert_eq!(ev.env["REMOTEADDRESS"], "", "own subnet has no remote");
    }
    let subnets: std::collections::HashSet<&str> = subnet_ups
        .iter()
        .map(|e| e.env["SUBNET"].as_str())
        .collect();
    // `Subnet::Display` strips `#weight`; `run_subnet_script`
    // strips it again defensively (`run_subnet_script`). Prefix
    // shown iff < max.
    assert_eq!(
        subnets,
        ["10.0.1.0/24", "fec0::/64"].into_iter().collect(),
        "events: {events:#?}"
    );
    // WEIGHT: per-subnet. 10.0.1.0/24#5 → "5"; fec0::/64 → "10"
    // (we always pass the integer; the C passes "" for default,
    // doc'd at `run_subnet_script`).
    for ev in &subnet_ups {
        match ev.env["SUBNET"].as_str() {
            "10.0.1.0/24" => assert_eq!(ev.env["WEIGHT"], "5"),
            "fec0::/64" => assert_eq!(ev.env["WEIGHT"], "10"),
            other => panic!("unexpected SUBNET={other}"),
        }
    }

    let _ = drain_stderr(alice_child);
}

// ═══════════════════════════════════════════════════════════════════
// Test 2: host-up → hosts/NAME-up → subnet-up ORDER on connect.
//
// When a node becomes reachable:
//   1. execute_script("host-up")
//   2. execute_script("hosts/NAME-up")
//   `:294`  subnet_update(n, NULL, true)  ─ loops subnet-up
//
// Our `gossip.rs` BecameReachable arm matches: `run_host_script`
// (which fires both host-up AND hosts/NAME-up, in that order —
// `run_host_script`) THEN the subnet loop.

#[test]
fn host_up_order_on_connect() {
    let tmp = tmp("connect");
    let alice_log = tmp.path().join("alice-events.log");

    let alice = Node::new(tmp.path(), "alice", 0xA2);
    let bob = Node::new(tmp.path(), "bob", 0xB2);

    alice.write_config(Some(&bob), true, &["10.0.1.0/24"]);
    bob.write_config(Some(&alice), false, &["10.0.2.0/24"]);
    write_all_scripts(&alice.confbase, &alice_log, Some("bob"));

    let bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket, Duration::from_secs(5)),
        "bob setup failed:\n{}",
        drain_stderr(bob_child)
    );
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket, Duration::from_secs(5)) {
        let _ = drain_stderr(bob_child);
        panic!("alice setup failed:\n{}", drain_stderr(alice_child));
    }

    // Startup: tinc-up + 1 own subnet-up = 2.
    // Connect:  host-up + bob-up + 1 subnet-up (bob's) = 3.
    // Total: 5. The connect sequence's last event is the subnet-up
    // for bob's subnet — wait for that specifically.
    let events = wait_for_events(&alice_log, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| {
            e.script == "subnet-up" && e.env.get("NODE").map(String::as_str) == Some("bob")
        })
    });

    let _ = drain_stderr(alice_child);
    let _ = drain_stderr(bob_child);

    // Find the connect-triggered events. Everything before host-up
    // is the startup sequence (already covered by test 1).
    let host_up_idx = events
        .iter()
        .position(|e| e.script == "host-up")
        .unwrap_or_else(|| panic!("no host-up; events: {events:#?}"));
    let per_node_idx = events
        .iter()
        .position(|e| e.script == "bob-up")
        .unwrap_or_else(|| panic!("no hosts/bob-up; events: {events:#?}"));
    let bob_subnet_idx = events
        .iter()
        .position(|e| e.script == "subnet-up" && e.env["NODE"] == "bob")
        .unwrap_or_else(|| panic!("no subnet-up for bob; events: {events:#?}"));

    // ─── ORDER
    assert!(
        host_up_idx < per_node_idx,
        "host-up must precede hosts/bob-up; got idx {host_up_idx} vs {per_node_idx}"
    );
    assert!(
        per_node_idx < bob_subnet_idx,
        "hosts/bob-up must precede subnet-up; got idx {per_node_idx} vs {bob_subnet_idx}"
    );

    // ─── host-up env (`periodic.rs::run_host_script`)
    let h = &events[host_up_idx];
    assert_eq!(h.env["NAME"], "alice");
    assert_eq!(h.env["NODE"], "bob");
    assert_eq!(h.env["INTERFACE"], "dummy");
    // REMOTEADDRESS/PORT: BecameReachable reads `nodes[bob].edge_addr`
    // — for direct peers that's bob's bound address.
    assert_eq!(h.env["REMOTEADDRESS"], "127.0.0.1");
    assert_eq!(h.env["REMOTEPORT"], bob.port.to_string());

    // ─── hosts/bob-up: same env as host-up (`run_host_script` reuses it)
    let p = &events[per_node_idx];
    assert_eq!(p.env["NODE"], "bob");
    assert_eq!(p.env["REMOTEADDRESS"], "127.0.0.1");
    assert_eq!(p.env["REMOTEPORT"], bob.port.to_string());

    // ─── subnet-up for bob's subnet
    let s = &events[bob_subnet_idx];
    assert_eq!(s.env["NODE"], "bob");
    assert_eq!(s.env["SUBNET"], "10.0.2.0/24");
    assert_eq!(s.env["WEIGHT"], "10"); // default
    // REMOTEADDRESS: `run_subnet_script` sets it for non-self owners
    // from `nodes[owner].edge_addr`.
    assert_eq!(s.env["REMOTEADDRESS"], "127.0.0.1");
    assert_eq!(s.env["REMOTEPORT"], bob.port.to_string());
}

// ═══════════════════════════════════════════════════════════════════
// Test 3: host-down → hosts/NAME-down → subnet-down on disconnect.
//
// Same path, `reachable=false`. Our gossip.rs BecameUnreachable arm: `run_host_script(false, ...)` then subnet
// loop. `run_host_script` itself does host-down THEN hosts/N-down.

#[test]
fn host_down_order_on_disconnect() {
    let tmp = tmp("disconnect");
    let alice_log = tmp.path().join("alice-events.log");

    let alice = Node::new(tmp.path(), "alice", 0xA3);
    let bob = Node::new(tmp.path(), "bob", 0xB3);

    alice.write_config(Some(&bob), true, &["10.0.1.0/24"]);
    bob.write_config(Some(&alice), false, &["10.0.2.0/24"]);
    write_all_scripts(&alice.confbase, &alice_log, Some("bob"));

    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket, Duration::from_secs(5)),
        "bob setup failed:\n{}",
        drain_stderr(bob_child)
    );
    let alice_child = alice.spawn();

    // Wait for the connect sequence to complete (subnet-up for bob).
    let connected = wait_for_events(&alice_log, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| {
            e.script == "subnet-up" && e.env.get("NODE").map(String::as_str) == Some("bob")
        })
    });
    assert!(
        connected
            .iter()
            .any(|e| e.script == "subnet-up" && e.env["NODE"] == "bob"),
        "never connected; events: {connected:#?}"
    );
    let pre_count = connected.len();

    // Kill bob. Alice's TCP connection sees EOF → terminate →
    // DEL_EDGE → graph diff → BecameUnreachable.
    let _ = bob_child.kill();
    let _ = bob_child.wait();

    // Wait for the down sequence: host-down + bob-down + subnet-down.
    let events = wait_for_events(&alice_log, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| {
            e.script == "subnet-down" && e.env.get("NODE").map(String::as_str) == Some("bob")
        })
    });

    let _ = drain_stderr(alice_child);

    // Only look at events AFTER the connect sequence.
    let down_events = &events[pre_count..];

    let host_down_idx = down_events
        .iter()
        .position(|e| e.script == "host-down")
        .unwrap_or_else(|| panic!("no host-down; down events: {down_events:#?}"));
    let per_node_idx = down_events
        .iter()
        .position(|e| e.script == "bob-down")
        .unwrap_or_else(|| panic!("no hosts/bob-down; down events: {down_events:#?}"));
    let subnet_down_idx = down_events
        .iter()
        .position(|e| e.script == "subnet-down" && e.env["NODE"] == "bob")
        .unwrap_or_else(|| panic!("no subnet-down for bob; down events: {down_events:#?}"));

    // ─── ORDER
    assert!(
        host_down_idx < per_node_idx,
        "host-down must precede hosts/bob-down; idx {host_down_idx} vs {per_node_idx}"
    );
    assert!(
        per_node_idx < subnet_down_idx,
        "hosts/bob-down must precede subnet-down; idx {per_node_idx} vs {subnet_down_idx}"
    );

    // ─── host-down env
    let h = &down_events[host_down_idx];
    assert_eq!(h.env["NODE"], "bob");
    // REMOTEADDRESS on host-down: BecameUnreachable reads the addr
    // BEFORE `reset_unreachable` clears it (script call precedes
    // `update_node_udp(n, NULL)`). For a direct peer that just
    // dropped, the
    // addr is still there.
    //
    // (If this ever flips to empty: `run_host_script` documents
    // the deliberate choice to OMIT rather than pass `"unknown"`.)
    assert_eq!(h.env["REMOTEADDRESS"], "127.0.0.1");

    // ─── subnet-down env
    let s = &down_events[subnet_down_idx];
    assert_eq!(s.env["NODE"], "bob");
    assert_eq!(s.env["SUBNET"], "10.0.2.0/24");
}

// ═══════════════════════════════════════════════════════════════════
// Test 4: subnet-down for OWN subnets THEN tinc-down on shutdown.
//
// On shutdown (`close_network_connections`):
//   1. own subnet-down
//   2. `device_disable()` → tinc-down
//
// Mirror of test 1's bug, in `Daemon::Drop`.

#[test]
fn tinc_down_on_shutdown() {
    let tmp = tmp("shutdown");
    let log = tmp.path().join("events.log");

    let alice = Node::new(tmp.path(), "alice", 0xA4);
    alice.write_config(None, false, &["10.0.1.0/24"]);
    write_all_scripts(&alice.confbase, &log, None);

    let mut alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket, Duration::from_secs(5)),
        "alice setup failed:\n{}",
        drain_stderr(alice_child)
    );

    // Startup events: tinc-up + 1 subnet-up.
    let started = wait_for_events(&log, Duration::from_secs(5), |e| e.len() >= 2);
    assert!(started.len() >= 2, "startup incomplete: {started:#?}");
    let pre_count = started.len();

    // SIGTERM → run() returns → Daemon::Drop. Can't use
    // `child.kill()` (= SIGKILL, no Drop).
    #[allow(clippy::cast_possible_wrap)] // child.id() is a real PID (< pid_max ≤ 2^22)
    let pid = nix::unistd::Pid::from_raw(alice_child.id() as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).expect("SIGTERM failed");
    let status = alice_child.wait().expect("wait");
    assert!(status.success(), "tincd exited non-zero: {status:?}");

    // Shutdown is synchronous in Drop; the log is final once
    // wait() returns.
    let events = read_log(&log);
    let down_events = &events[pre_count..];

    let subnet_down_idx = down_events
        .iter()
        .position(|e| e.script == "subnet-down" && e.env["NODE"] == "alice")
        .unwrap_or_else(|| {
            panic!("no subnet-down for own subnet on shutdown; events: {down_events:#?}")
        });
    let tinc_down_idx = down_events
        .iter()
        .position(|e| e.script == "tinc-down")
        .unwrap_or_else(|| panic!("no tinc-down; events: {down_events:#?}"));

    // ─── ORDER: own subnet-down BEFORE tinc-down
    // (subnet-down may `ip route del`; tinc-down brings the iface
    // down — routes referencing a downed iface vanish anyway, but
    // the C order is subnet-down first and that's what scripts in
    // the wild expect.)
    assert!(
        subnet_down_idx < tinc_down_idx,
        "subnet-down must precede tinc-down; idx {subnet_down_idx} vs {tinc_down_idx}; events: {down_events:#?}"
    );

    // ─── subnet-down env: NODE=self, SUBNET=ours.
    let s = &down_events[subnet_down_idx];
    assert_eq!(s.env["NODE"], "alice");
    assert_eq!(s.env["SUBNET"], "10.0.1.0/24");
    assert_eq!(s.env["REMOTEADDRESS"], "");

    // ─── tinc-down env: base only.
    let t = &down_events[tinc_down_idx];
    assert_eq!(t.env["NAME"], "alice");
    assert_eq!(t.env["INTERFACE"], "dummy");
    assert_eq!(t.env["NODE"], "");
}
