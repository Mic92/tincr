use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use super::common::linux::{run_ip, wait_for_carrier};
pub(crate) use super::common::node::Node;
use super::common::{TmpGuard, node_status, poll_until};

/// Re-exec this test inside bwrap and set up the standard two-TUN
/// topology. `Some` only in the inner (sandboxed) pass.
pub(crate) fn enter_netns(test_name: &str) -> Option<NetNs> {
    enter_bwrap(test_name).then(NetNs::setup)
}

/// Outer pass: probe for bwrap + unprivileged userns (SKIP if
/// missing), re-exec this binary with `--exact test_name` inside a
/// fresh user+net namespace, assert it passed, return `false`.
/// Inner pass (`BWRAP_INNER` set): bring `lo` up, return `true`.
pub(crate) fn enter_bwrap(test_name: &str) -> bool {
    if std::env::var_os("BWRAP_INNER").is_some() {
        run_ip(&["link", "set", "lo", "up"]);
        std::fs::create_dir_all("/run/netns").expect("mkdir /run/netns");
        return true;
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
            return false;
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "SKIP {test_name}: bwrap probe failed (unprivileged userns disabled?): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Ok(_) => {}
    }
    if !std::path::Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing");
        return false;
    }

    // `--tmpfs /dev` is load-bearing: TUNSETIFF checks that the
    // device node's mount is owned by our userns, which a plain
    // dev-bind of the host's /dev is not. `/proc/self/exe` is
    // resolved out here because inside it would point at bwrap.
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
        // NixOS keeps dig/socat/iptables under /run/current-system.
        .args(if std::path::Path::new("/run/current-system").exists() {
            &["--ro-bind", "/run/current-system", "/run/current-system"][..]
        } else {
            &[]
        })
        .arg("--")
        .arg(&self_exe)
        // `--exact` with the full `module::name`: a substring match
        // once ran two tests in one sandbox, and a non-matching name
        // runs zero tests and "passes".
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

/// A child netns reachable via `ip netns exec NAME`. `ip netns add`
/// needs shared mount propagation, which a userns root cannot set
/// up, so bind-mount an `unshare -n` sleeper's nsfd by hand.
pub(crate) fn make_child_netns(name: &str) -> Child {
    let sleeper = Command::new("unshare")
        .args(["-n", "sleep", "3600"])
        .spawn()
        .expect("spawn unshare sleeper");
    std::thread::sleep(Duration::from_millis(100));
    let target = format!("/run/netns/{name}");
    std::fs::write(&target, b"").expect("touch nsfd target");
    let status = Command::new("mount")
        .args(["--bind"])
        .arg(format!("/proc/{}/ns/net", sleeper.id()))
        .arg(&target)
        .status()
        .expect("spawn mount");
    assert!(status.success(), "mount --bind nsfd for {name}: {status:?}");
    run_ip(&["netns", "exec", name, "ip", "link", "set", "lo", "up"]);
    sleeper
}

/// veth pair with each end `(netns, ifname, addr/prefix)` moved,
/// addressed and up.
pub(crate) fn veth_pair(a: (&str, &str, &str), b: (&str, &str, &str)) {
    run_ip(&["link", "add", a.1, "type", "veth", "peer", "name", b.1]);
    for (ns, ifname, addr) in [a, b] {
        run_ip(&["link", "set", ifname, "netns", ns]);
        run_ip(&[
            "netns", "exec", ns, "ip", "addr", "add", addr, "dev", ifname,
        ]);
        run_ip(&["netns", "exec", ns, "ip", "link", "set", ifname, "up"]);
    }
}

pub(crate) fn ping(args: &[&str], dest: &str) -> Output {
    Command::new("ping")
        .args(args)
        .arg(dest)
        .output()
        .expect("spawn ping")
}

/// One quiet echo request; used to kick handshakes and PMTU probes.
pub(crate) fn ping_once(dest: &str) -> bool {
    Command::new("ping")
        .args(["-c", "1", "-W", "1", dest])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// "N received" from ping's summary line.
pub(crate) fn ping_received(output: &Output) -> u32 {
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.contains("received"))
        .and_then(|line| {
            line.split(',')
                .find(|field| field.contains("received"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no ping summary in:\n{stdout}"))
}

/// `(mtu, minmtu, maxmtu)` from a `dump nodes` row.
pub(crate) fn node_pmtu(rows: &[String], name: &str) -> Option<(u16, u16, u16)> {
    rows.iter().find_map(|row| {
        let toks: Vec<&str> = row.strip_prefix("18 3 ")?.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        Some((
            toks.get(14)?.parse().ok()?,
            toks.get(15)?.parse().ok()?,
            toks.get(16)?.parse().ok()?,
        ))
    })
}

/// `tc qdisc add dev DEV root netem SPEC`, removed on drop. netem is
/// egress-only, so on `lo` each direction is hit independently.
pub(crate) struct Netem {
    dev: String,
}

impl Netem {
    pub(crate) fn apply(dev: &str, spec: &str) -> Self {
        let mut args = vec!["qdisc", "add", "dev", dev, "root", "netem"];
        args.extend(spec.split_whitespace());
        let out = Command::new("tc").args(&args).output().expect("spawn tc");
        assert!(
            out.status.success(),
            "tc {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self { dev: dev.into() }
    }
}

impl Drop for Netem {
    fn drop(&mut self) {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", &self.dev, "root"])
            .status();
    }
}

/// Two persistent TUN devices plus a child netns `bobside`. Both
/// daemons run in the outer netns (listeners on 127.0.0.1), but
/// bob's TUN is moved into `bobside` after he attaches to it:
/// otherwise 10.42.0.1 and 10.42.0.2 would both be local addresses
/// and ping would short-circuit over `lo`.
pub(crate) struct NetNs {
    sleeper: Child,
}

impl NetNs {
    pub(crate) fn setup() -> Self {
        // Persistent so the test process (not just the daemon that
        // TUNSETIFFs it) may move tinc1 between namespaces. Admin-up
        // now because carrier is only reported on up devices.
        for dev in ["tinc0", "tinc1"] {
            run_ip(&["tuntap", "add", "mode", "tun", "name", dev]);
            run_ip(&["link", "set", dev, "up"]);
        }
        Self {
            sleeper: make_child_netns("bobside"),
        }
    }

    /// alice only: address tinc0 in the outer netns.
    #[expect(clippy::unused_self)]
    pub(crate) fn place_alice(&self) {
        assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
        run_ip(&["addr", "add", "10.42.0.1/24", "dev", "tinc0"]);
        run_ip(&["link", "set", "tinc0", "up"]);
    }

    /// Call after both daemons attached (carrier up). The fd→device
    /// binding survives the move; addresses do not, so configure
    /// afterwards.
    pub(crate) fn place_devices(&self) {
        self.place_alice();
        assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
        run_ip(&["link", "set", "tinc1", "netns", "bobside"]);
        let bobside = |args: &[&str]| {
            let mut full = vec!["netns", "exec", "bobside", "ip"];
            full.extend(args);
            run_ip(&full);
        };
        bobside(&["addr", "add", "10.42.0.2/24", "dev", "tinc1"]);
        bobside(&["link", "set", "tinc1", "up"]);
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
    }
}

pub(crate) fn tun_node(dir: &std::path::Path, name: &str, seed: u8, iface: &str) -> Node {
    let host = if name == "alice" { 1 } else { 2 };
    Node::new(dir, name, seed)
        .iface(iface)
        .subnet(&format!("10.42.0.{host}/32"))
        // The one debug line worth having everywhere is net's
        // "Failed to decode UDP packet … BadSeqno".
        .log_level("tincd=info,tincd::net=debug")
}

/// alice (tinc0, 10.42.0.1) dials bob (tinc1 in `bobside`,
/// 10.42.0.2), optionally through relays that the test wires itself.
pub(crate) struct TunPair {
    pub(crate) netns: NetNs,
    pub(crate) alice: Node,
    pub(crate) bob: Node,
}

impl TunPair {
    /// Nodes configured but not started; adjust `alice`/`bob` (e.g.
    /// `with_conf`) before `start()`.
    pub(crate) fn new(netns: NetNs, tmp: &TmpGuard, extra_conf: &str) -> Self {
        Self {
            netns,
            alice: tun_node(tmp.path(), "alice", 0xCA, "tinc0").with_conf(extra_conf),
            bob: tun_node(tmp.path(), "bob", 0xCB, "tinc1").with_conf(extra_conf),
        }
    }

    /// bob listens, alice dials; devices placed; both reachable.
    pub(crate) fn start(netns: NetNs, tmp: &TmpGuard, extra_conf: &str) -> Self {
        let mut pair = Self::new(netns, tmp, extra_conf);
        pair.start_direct();
        pair
    }

    pub(crate) fn start_direct(&mut self) {
        self.bob.write_config(&self.alice, false);
        self.bob.start();
        self.alice.write_config(&self.bob, true);
        self.alice.start();
        self.netns.place_devices();
        self.wait_reachable();
    }

    pub(crate) fn wait_reachable(&self) {
        self.wait_status_bit(0x10, Duration::from_secs(10));
    }

    /// Kick the per-tunnel handshake with one ping, wait for validkey.
    pub(crate) fn wait_validkey(&self) {
        ping_once("10.42.0.2");
        self.wait_status_bit(0x02, Duration::from_secs(5));
    }

    /// Until PMTU confirms UDP, data rides the TCP meta connection
    /// and netem on `lo` is invisible to SPTPS. Probes are
    /// demand-driven, so keep pinging.
    pub(crate) fn wait_udp_confirmed(&self) {
        poll_until(Duration::from_secs(5), || {
            ping_once("10.42.0.2");
            self.both_have_bit(0x80).then_some(())
        });
    }

    fn both_have_bit(&self, bit: u32) -> bool {
        node_status(&self.alice.ctl().dump(3), "bob").is_some_and(|s| s & bit != 0)
            && node_status(&self.bob.ctl().dump(3), "alice").is_some_and(|s| s & bit != 0)
    }

    fn wait_status_bit(&self, bit: u32, timeout: Duration) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(timeout, || self.both_have_bit(bit).then_some(()));
        }));
        assert!(
            result.is_ok(),
            "status bit {bit:#x} not reached\n=== alice ===\n{}\n=== bob ===\n{}",
            self.alice.log(),
            self.bob.log()
        );
    }

    /// `(in_packets, out_packets)` that `node` counts for its peer.
    pub(crate) fn traffic(node: &Node) -> (u64, u64) {
        let peer = if node.name == "alice" { "bob" } else { "alice" };
        // `dump traffic` row: `18 13 NAME in_pkts in_bytes out_pkts out_bytes`.
        node.ctl()
            .dump(13)
            .iter()
            .find_map(|row| {
                let mut fields = row.strip_prefix("18 13 ")?.split_whitespace();
                if fields.next()? != peer {
                    return None;
                }
                let in_packets = fields.next()?.parse().ok()?;
                let out_packets = fields.nth(1)?.parse().ok()?;
                Some((in_packets, out_packets))
            })
            .expect("peer row")
    }

    /// Stop both; `(alice_log, bob_log)`.
    pub(crate) fn finish(mut self) -> (String, String) {
        let bob = self.bob.stop();
        let alice = self.alice.stop();
        (alice, bob)
    }
}
