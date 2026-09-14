//! #100: a leaf behind a hub's NAT is gossiped at the hub's address.
//!
//! ```text
//!   leaf-ns 192.168.77.2 ─veth─ hub-ns 192.168.77.1 (forward + masquerade)
//!                                 │ 10.77.0.2
//!                               veth
//!                                 │ 10.77.0.1
//!   outer-ns: peer (second hub) and observer ("internet")
//! ```
//!
//! `leaf` has no `Address =` and dials both hubs. `hub` sees it at
//! 192.168.77.2, `peer` sees it masqueraded at 10.77.0.2 — the very
//! address hub listens on, since leaf and hub use the same port (655
//! everywhere in a real mesh). `observer` (`AutoConnect`) learns both
//! via `ADD_EDGE` gossip; before the fix it dialled hub's listener,
//! got hub's ID and logged `BadId(... is hub instead of leaf)` every
//! round.

use std::process::{Command, Stdio};
use std::time::Duration;

use super::common::linux::{run_ip, run_ip_in};
use super::common::{TmpGuard, tincd_bin, try_poll};
use super::rig::{ChildNetNs, Node, enter_bwrap, veth_pair};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Shared by hub and leaf: the collision needs equal ports. Not 655,
/// no `CAP_NET_BIND_SERVICE` in the userns.
const HUB_PORT: u16 = 6550;
const HUB_WAN: &str = "10.77.0.2";
const HUB_LAN: &str = "192.168.77.1";
const LEAF_LAN: &str = "192.168.77.2";
const OUTER: &str = "10.77.0.1";

fn nsexec(ns: &str, argv: &[&str]) {
    let out = Command::new("ip")
        .args(["netns", "exec", ns])
        .args(argv)
        .output()
        .expect("spawn ip netns exec");
    assert!(
        out.status.success(),
        "ip netns exec {ns} {argv:?}: {}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
}

/// `nft -f` in `ns`; `false` (logged as SKIP) when nfnetlink is not
/// usable from this userns.
fn load_nft(ns: &str, test_name: &str, path: &Path, rules: &str) -> bool {
    fs::write(path, rules).unwrap();
    let out = Command::new("ip")
        .args(["netns", "exec", ns, "nft", "-f"])
        .arg(path)
        .output()
        .expect("spawn nft");
    if !out.status.success() {
        eprintln!(
            "SKIP {test_name}: nft -f in {ns}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    out.status.success()
}

/// Start `node` inside `ns` (or the outer netns for `None`).
fn start_in(node: &mut Node, ns: Option<&str>) {
    let mut cmd = match ns {
        Some(ns) => {
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", ns]).arg(tincd_bin());
            cmd
        }
        None => Command::new(tincd_bin()),
    };
    cmd.arg("-D")
        .arg("-c")
        .arg(&node.confbase)
        .arg("--pidfile")
        .arg(&node.pidfile)
        .arg("--socket")
        .arg(&node.socket)
        .env("RUST_LOG", &node.rust_log)
        .stderr(Stdio::piped());
    node.start_command(cmd);
}

/// `Address = ip port` in `self_node`'s copy of `peer`'s host file.
fn set_address(self_node: &Node, peer: &Node, ip: &str, port: u16) {
    let path = self_node.confbase.join("hosts").join(&peer.name);
    let mut host = fs::read_to_string(&path).unwrap();
    writeln!(host, "Address = {ip} {port}").unwrap();
    fs::write(path, host).unwrap();
}

struct Mesh {
    _netns: [ChildNetNs; 2],
    hub: Node,
    peer: Node,
    leaf: Node,
    observer: Node,
}

impl Mesh {
    /// Wire the namespaces, masquerade in hub-ns, start all four.
    /// `observer_conf` is observer's whole dial policy (`ConnectTo`
    /// / `AutoConnect` lines); `observer_hubs` the names it must be
    /// connected to before the test proper. `None` if nft is
    /// unusable here.
    fn start(
        test_name: &str,
        tmp: &TmpGuard,
        observer_conf: &str,
        observer_hubs: &[&str],
    ) -> Option<Self> {
        let netns = [ChildNetNs::new("leaf"), ChildNetNs::new("hub")];
        veth_pair(
            ("leaf", "veth-l", &format!("{LEAF_LAN}/24")),
            ("hub", "veth-lan", &format!("{HUB_LAN}/24")),
        );
        // PID 1 in here is bwrap, so `netns 1` can't name the outer
        // ns: create the pair out here and move one end.
        run_ip(&[
            "link", "add", "veth-out", "type", "veth", "peer", "name", "veth-wan",
        ]);
        run_ip(&["link", "set", "veth-wan", "netns", "hub"]);
        run_ip(&["addr", "add", &format!("{OUTER}/24"), "dev", "veth-out"]);
        run_ip(&["link", "set", "veth-out", "up"]);
        run_ip_in(
            "hub",
            &["addr", "add", &format!("{HUB_WAN}/24"), "dev", "veth-wan"],
        );
        run_ip_in("hub", &["link", "set", "veth-wan", "up"]);
        run_ip_in("leaf", &["route", "add", "default", "via", HUB_LAN]);
        nsexec("hub", &["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"]);
        let hub_rules = "table inet nat {\n\
               chain postrouting {\n\
                 type nat hook postrouting priority 100; policy accept;\n\
                 oifname \"veth-wan\" masquerade\n\
               }\n\
             }\n";
        if !load_nft("hub", test_name, &tmp.path().join("hub.nft"), hub_rules) {
            return None;
        }

        let dir = tmp.path();
        let quiet = "AutoConnect = no\n";
        let mut hub = Node::new(dir, "hub", 0x01).with_conf(quiet);
        let mut peer = Node::new(dir, "peer", 0x02).with_conf(quiet);
        let mut leaf = Node::new(dir, "leaf", 0x03).with_conf(quiet);
        let mut observer = Node::new(dir, "observer", 0x04);
        hub.port = HUB_PORT;
        leaf.port = HUB_PORT;

        // Hubs first: peer's port is ephemeral, the others need it.
        hub.write_config_multi(&[&peer, &leaf, &observer], &[]);
        start_in(&mut hub, Some("hub"));
        peer.write_config_multi(&[&hub, &leaf, &observer], &[]);
        start_in(&mut peer, None);

        // `write_config_multi` would write `Address = 127.0.0.1`;
        // no ConnectTo there, hand-write the dial config instead.
        for (node, others, dials) in [
            (
                &leaf,
                [&hub, &peer, &observer],
                "ConnectTo = hub\nConnectTo = peer\n",
            ),
            (&observer, [&hub, &peer, &leaf], observer_conf),
        ] {
            node.write_config_multi(&others, &[]);
            let conf = node.confbase.join("tinc.conf");
            let mut text = fs::read_to_string(&conf).unwrap();
            text.push_str(dials);
            fs::write(conf, text).unwrap();
            set_address(node, &hub, HUB_WAN, HUB_PORT);
            set_address(node, &peer, OUTER, peer.port);
        }
        start_in(&mut leaf, Some("leaf"));
        start_in(&mut observer, None);

        for hubname in ["hub", "peer"] {
            leaf.wait_for_peer(hubname, true, Duration::from_secs(10));
        }
        for hubname in observer_hubs {
            observer.wait_for_peer(hubname, true, Duration::from_secs(10));
        }
        Some(Self {
            _netns: netns,
            hub,
            peer,
            leaf,
            observer,
        })
    }

    fn finish(mut self) -> String {
        let log = self.observer.stop();
        self.leaf.stop();
        self.peer.stop();
        self.hub.stop();
        log
    }
}

/// observer is connected to hub, so it already knows who answers at
/// `10.77.0.2:6550`: the edge-walk for leaf must not yield hub's
/// listener, nor lose the address hub itself reported (192.168.77.2).
#[test]
fn autoconnect_never_dials_leaf_at_hub_address() {
    let test_name = "nat_hub::autoconnect_never_dials_leaf_at_hub_address";
    if !enter_bwrap(test_name) {
        return;
    }
    let tmp = TmpGuard::new("nathub", "walk");
    let Some(mesh) = Mesh::start(
        test_name,
        &tmp,
        "ConnectTo = hub\nConnectTo = peer\nAutoConnect = yes\n",
        &["hub", "peer"],
    ) else {
        return;
    };

    let wanted = format!("Trying to connect to leaf ({LEAF_LAN}:{HUB_PORT})");
    let wrong = format!("Trying to connect to leaf ({HUB_WAN}:{HUB_PORT})");
    // observer has two meta conns (< 3) and leaf is reachable, not
    // connected: the next 5s tick dials it. Two rounds so a retry is
    // covered too.
    let log = try_poll(Duration::from_secs(40), || {
        let log = mesh.observer.log();
        (log.contains(&wrong) || log.matches(&wanted).count() >= 2).then_some(log)
    });
    let log = log.unwrap_or_else(|| mesh.observer.log());
    let hub_log = mesh.hub.log();
    mesh.finish();

    assert!(
        log.contains(&wanted),
        "observer never tried hub's view of leaf ({LEAF_LAN}):\n{log}"
    );
    assert!(
        !log.contains(&wrong),
        "observer dialled leaf at hub's listener:\n{log}"
    );
    assert!(!log.contains("ID rejected"), "wrong-endpoint dial:\n{log}");
    // The hub side of the same mistake: nothing but its two
    // legitimate peers ever completed an ID exchange with it.
    assert!(
        !hub_log.contains("Connection closed by observer"),
        "hub saw observer's misdirected dial:\n{hub_log}"
    );
}

/// observer has never talked to hub (only `peer`), so nothing rules
/// out `10.77.0.2:6550` up front. The one dial that comes back with
/// hub's `ID` must teach it: rejected once, never retried.
#[test]
fn wrong_peer_id_is_learnt_once() {
    let test_name = "nat_hub::wrong_peer_id_is_learnt_once";
    if !enter_bwrap(test_name) {
        return;
    }
    let tmp = TmpGuard::new("nathub", "learn");
    // `ConnectTo = leaf` with no `Address`: the slot is fed by the
    // edge-walk alone. `MaxTimeout` keeps the retry cadence at 5s.
    let Some(mesh) = Mesh::start(
        test_name,
        &tmp,
        "ConnectTo = peer\nConnectTo = leaf\nAutoConnect = no\nMaxTimeout = 5\n",
        &["peer"],
    ) else {
        return;
    };

    let wanted = format!("Trying to connect to leaf ({LEAF_LAN}:{HUB_PORT})");
    let wrong = format!("Trying to connect to leaf ({HUB_WAN}:{HUB_PORT})");
    let log = try_poll(Duration::from_secs(45), || {
        let log = mesh.observer.log();
        (log.matches(&wrong).count() >= 2 || log.matches(&wanted).count() >= 4).then_some(log)
    });
    let log = log.unwrap_or_else(|| mesh.observer.log());
    mesh.finish();

    assert!(
        log.matches(&wanted).count() >= 4,
        "fewer than four rounds with hub's view of leaf:\n{log}"
    );
    assert_eq!(
        log.matches(&wrong).count(),
        1,
        "hub's listener must be dialled exactly once for leaf:\n{log}"
    );
    assert_eq!(
        log.matches("is hub instead of leaf").count(),
        1,
        "one rejected ID expected:\n{log}"
    );
}
