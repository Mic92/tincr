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
//! `leaf` dials both hubs. `hub` sees it at 192.168.77.2, `peer` sees
//! it masqueraded at 10.77.0.2, which with equal ports is hub's own
//! listener. `observer` learns both via gossip and must not dial the
//! latter for leaf.

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
    // AutoConnect dials leaf within 5s; wait for two rounds.
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
    assert!(
        !hub_log.contains("Connection closed by observer"),
        "hub saw observer's misdirected dial:\n{hub_log}"
    );
}

/// observer has never talked to hub, so the wrong address is dialled
/// once, rejected by ID, and never retried.
#[test]
fn wrong_peer_id_is_learnt_once() {
    let test_name = "nat_hub::wrong_peer_id_is_learnt_once";
    if !enter_bwrap(test_name) {
        return;
    }
    let tmp = TmpGuard::new("nathub", "learn");
    // No `Address` for leaf: only the edge-walk feeds it.
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

const UDP_CONFIRMED: u32 = 0x80;
/// Where acheron's NAT maps styx's UDP after its uplink flaps.
const REBOUND_PORT: u16 = 20988;

fn ping_from(ns: &str, dst: &str) -> bool {
    Command::new("ip")
        .args(["netns", "exec", ns, "ping", "-c", "1", "-W", "1", dst])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `(status, nexthop)` of `peer` in `node`'s `dump nodes`.
fn peer_view(node: &Node, peer: &str) -> Option<(u32, String)> {
    node.ctl().dump(3).iter().find_map(|row| {
        let f: Vec<&str> = row.strip_prefix("18 3 ")?.split_whitespace().collect();
        (f.first() == Some(&peer)).then_some(())?;
        Some((
            u32::from_str_radix(f.get(10)?, 16).ok()?,
            (*f.get(11)?).to_owned(),
        ))
    })
}

/// `"host port"` of the `from -> to` edge in `node`'s `dump edges`.
fn edge_addr(node: &Node, from: &str, to: &str) -> Option<String> {
    node.ctl().dump(4).iter().find_map(|row| {
        let f: Vec<&str> = row.strip_prefix("18 4 ")?.split_whitespace().collect();
        (f.first() == Some(&from) && f.get(1) == Some(&to)).then_some(())?;
        Some(format!("{} {}", f.get(2)?, f.get(4)?))
    })
}

/// NAT gateway `ns` in front of a LAN: masquerade out of `wan` (with
/// `udp_port`, UDP leaves from that port) and drop everything unsolicited,
/// so only mappings the inside punched let UDP in.
fn gateway_rules(wan: &str, udp_port: Option<u16>, forward: &str) -> String {
    let udp = udp_port.map_or_else(String::new, |p| {
        format!("oifname \"{wan}\" meta l4proto udp masquerade to :{p}\n")
    });
    format!(
        "flush ruleset\n\
         table inet nat {{\n\
           chain postrouting {{\n\
             type nat hook postrouting priority 100; policy accept;\n\
             {udp}oifname \"{wan}\" masquerade\n\
           }}\n\
           chain input {{\n\
             type filter hook input priority 0; policy accept;\n\
             iifname \"{wan}\" drop\n\
           }}\n\
           chain forward {{\n\
             type filter hook forward priority 0; policy accept;\n\
             {forward}\n\
           }}\n\
         }}\n"
    )
}

/// 2026-11-18: styx sits behind acheron's NAT; coaxmetal behind a
/// port-restricted NAT has no meta connection to it. acheron's uplink
/// flaps and styx's UDP comes back from a new port. neoprism stays
/// UDP-confirmed and follows the move; its edge to styx, which coaxmetal
/// punches, must follow too.
#[test]
fn confirmed_udp_roam_is_readvertised() {
    let test_name = "nat_hub::confirmed_udp_roam_is_readvertised";
    if !enter_bwrap(test_name) {
        return;
    }
    let tmp = TmpGuard::new("nathub", "roam");
    let _netns = ["neo", "styx", "ach", "coax", "cgw"].map(ChildNetNs::new);
    veth_pair(
        ("styx", "s-eth", "192.168.44.2/24"),
        ("ach", "ach-lan", "192.168.44.1/24"),
    );
    veth_pair(
        ("coax", "c-eth", "192.168.55.2/24"),
        ("cgw", "cgw-lan", "192.168.55.1/24"),
    );
    for (ns, wan, outer, inner) in [
        ("neo", "neo-wan", "10.77.1.1/24", "10.77.1.2/24"),
        ("ach", "ach-wan", "10.77.2.1/24", "10.77.2.2/24"),
        ("cgw", "cgw-wan", "10.77.3.1/24", "10.77.3.2/24"),
    ] {
        let out = format!("o-{ns}");
        run_ip(&["link", "add", &out, "type", "veth", "peer", "name", wan]);
        run_ip(&["link", "set", wan, "netns", ns]);
        run_ip(&["addr", "add", outer, "dev", &out]);
        run_ip(&["link", "set", &out, "up"]);
        run_ip_in(ns, &["addr", "add", inner, "dev", wan]);
        run_ip_in(ns, &["link", "set", wan, "up"]);
        let gw = outer.replace("/24", "");
        run_ip_in(ns, &["route", "add", "default", "via", &gw]);
    }
    run_ip_in("styx", &["route", "add", "default", "via", "192.168.44.1"]);
    run_ip_in("coax", &["route", "add", "default", "via", "192.168.55.1"]);
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    for ns in ["ach", "cgw"] {
        nsexec(ns, &["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"]);
    }

    let dir = tmp.path();
    let conf = "AutoConnect = no\nLocalDiscovery = no\nPingInterval = 1\n\
                UDPDiscoveryTimeout = 3\nUDPDiscoveryKeepaliveInterval = 1\n\
                UDPDiscoveryInterval = 1\n";
    let mut eva = Node::new(dir, "eva", 0x05).with_conf(conf);
    let tun = |name, seed, iface, ip| {
        Node::new(dir, name, seed)
            .with_conf(conf)
            .iface(iface)
            .subnet(ip)
            .log_level("tincd=info,tincd::net=debug")
    };
    let mut neoprism = tun("neoprism", 0x06, "tinc2", "10.42.0.3/32");
    let mut styx = tun("styx", 0x07, "tinc1", "10.42.0.2/32");
    let mut coax = tun("coaxmetal", 0x08, "tinc0", "10.42.0.1/32");
    for node in [&mut eva, &mut neoprism, &mut styx, &mut coax] {
        node.reserve_port();
    }
    // eva relays meta only: what it learns from styx's UDP would be
    // a second way for coaxmetal to find styx.
    let ach_forward = format!("oifname \"ach-wan\" udp dport {} drop", eva.port);
    if !load_nft(
        "ach",
        test_name,
        &dir.join("ach.nft"),
        &gateway_rules("ach-wan", None, &ach_forward),
    ) || !load_nft(
        "cgw",
        test_name,
        &dir.join("cgw.nft"),
        &gateway_rules("cgw-wan", None, ""),
    ) {
        return;
    }

    for (node, others, dials) in [
        (&eva, [&neoprism, &styx, &coax], ""),
        (&neoprism, [&eva, &styx, &coax], ""),
        (
            &styx,
            [&eva, &neoprism, &coax],
            "ConnectTo = eva\nConnectTo = neoprism\n",
        ),
        (&coax, [&eva, &neoprism, &styx], "ConnectTo = eva\n"),
    ] {
        node.write_config_multi(&others, &[]);
        let path = node.confbase.join("tinc.conf");
        // The flap must not cost styx its meta connections.
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("PingTimeout = 1\n", "PingTimeout = 10\n");
        fs::write(path, text + dials).unwrap();
        if node.name != "eva" && node.name != "neoprism" {
            let ip = if node.name == "styx" {
                "10.77.2.1"
            } else {
                "10.77.3.1"
            };
            set_address(node, &eva, ip, eva.port);
            set_address(node, &neoprism, "10.77.1.2", neoprism.port);
        }
    }
    for (ns, dev) in [("neo", "tinc2"), ("styx", "tinc1"), ("coax", "tinc0")] {
        run_ip_in(ns, &["tuntap", "add", "mode", "tun", "name", dev]);
    }
    start_in(&mut eva, None);
    start_in(&mut neoprism, Some("neo"));
    start_in(&mut styx, Some("styx"));
    start_in(&mut coax, Some("coax"));
    for (ns, dev, ip) in [
        ("coax", "tinc0", "10.42.0.1/24"),
        ("styx", "tinc1", "10.42.0.2/24"),
        ("neo", "tinc2", "10.42.0.3/24"),
    ] {
        run_ip_in(ns, &["addr", "add", ip, "dev", dev]);
        run_ip_in(ns, &["link", "set", dev, "up"]);
    }

    let confirmed = |a: &Node, b: &str| peer_view(a, b).is_some_and(|v| v.0 & UDP_CONFIRMED != 0);
    let traffic = || {
        ping_from("neo", "10.42.0.2");
        ping_from("coax", "10.42.0.2");
    };
    let direct = || confirmed(&coax, "styx") && confirmed(&styx, "coaxmetal");
    let up = try_poll(Duration::from_secs(30), || {
        traffic();
        (direct() && confirmed(&neoprism, "styx")).then_some(())
    });
    let old_edge = edge_addr(&coax, "neoprism", "styx");
    if up.is_none() || old_edge != Some(format!("10.77.2.2 {}", styx.port)) {
        let logs = [coax.stop(), styx.stop(), neoprism.stop(), eva.stop()];
        panic!("no direct UDP to start from (edge {old_edge:?})\n{logs:#?}");
    }

    // The flap drops acheron's masquerade state; UDP comes back on a new port.
    run_ip_in("ach", &["link", "set", "ach-wan", "down"]);
    assert!(load_nft(
        "ach",
        test_name,
        &dir.join("ach2.nft"),
        &gateway_rules("ach-wan", Some(REBOUND_PORT), &ach_forward),
    ));
    run_ip_in("ach", &["link", "set", "ach-wan", "up"]);
    run_ip_in("ach", &["route", "replace", "default", "via", "10.77.2.1"]);

    let new_addr = format!("10.77.2.2:{REBOUND_PORT}");
    let neo_moved = try_poll(Duration::from_secs(15), || {
        traffic();
        neoprism
            .log()
            .lines()
            .any(|l| l.contains("UDP address of styx") && l.contains(&new_addr))
            .then_some(())
    });
    let rebound = format!("10.77.2.2 {REBOUND_PORT}");
    let readvertised = try_poll(Duration::from_secs(20), || {
        traffic();
        (edge_addr(&coax, "neoprism", "styx").as_deref() == Some(rebound.as_str())).then_some(())
    });
    let recovered = try_poll(Duration::from_secs(30), || {
        traffic();
        direct().then_some(())
    });
    let neo_kept = confirmed(&neoprism, "styx");
    let coax_edge = edge_addr(&coax, "neoprism", "styx");
    let coax_sees = peer_view(&coax, "styx");
    let neo_log = neoprism.stop();
    let neo_lost = neo_log.contains("UDP ping response from styx");
    let logs = format!(
        "=== coaxmetal ===\n{}\n=== styx ===\n{}\n=== neoprism ===\n{neo_log}\n=== eva ===\n{}",
        coax.stop(),
        styx.stop(),
        eva.stop()
    );
    assert!(
        neo_moved.is_some() && neo_kept,
        "neoprism did not follow styx to {new_addr} while confirmed\n{logs}"
    );
    assert!(
        !neo_lost,
        "neoprism lost UDP to styx, so this is not a roam\n{logs}"
    );
    assert!(
        readvertised.is_some(),
        "coaxmetal still has neoprism -> styx at {coax_edge:?}, not {rebound}\n{logs}"
    );
    assert!(
        recovered.is_some(),
        "no direct UDP coaxmetal <-> styx after the rebind ({coax_sees:?})\n{logs}"
    );
}
