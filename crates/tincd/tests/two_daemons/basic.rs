use std::time::Duration;

use nix::sys::signal::Signal;

use super::common::node::*;
use super::common::*;

fn node_names(rows: &[String]) -> Vec<&str> {
    rows.iter()
        .filter_map(|row| row.strip_prefix("18 3 ")?.split_whitespace().next())
        .collect()
}

/// Outgoing connect → ID → SPTPS → ACK → edges → graph on both sides;
/// then killing the dialer takes its edges and reachability with it.
#[test]
fn connect_reach_then_disconnect() {
    let tmp = tmp!("connect");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA);
    let mut bob = Node::new(tmp.path(), "bob", 0xBB);
    alice.start_dialing(&mut bob);

    let mut bob_ctl = bob.ctl();
    for ctl in [&mut alice.ctl(), &mut bob_ctl] {
        let nodes = ctl.dump(3);
        assert!(
            node_reachable(&nodes, "alice") && node_reachable(&nodes, "bob"),
            "{nodes:?}"
        );
        // own forward edge + synthesized reverse
        assert_eq!(ctl.dump(4).len(), 2);
    }
    assert!(
        alice
            .ctl()
            .dump(4)
            .iter()
            .any(|row| row.starts_with("18 4 alice bob 127.0.0.1 port "))
    );

    alice.stop();
    bob.wait_for_peer("alice", false, Duration::from_secs(10));
    let nodes = bob_ctl.dump(3);
    assert!(
        !node_reachable(&nodes, "alice") && node_reachable(&nodes, "bob"),
        "{nodes:?}"
    );
    assert_eq!(bob_ctl.dump(4).len(), 0);

    let log = bob.stop();
    for expected in [
        "Node alice became reachable",
        "Node alice became unreachable",
        "activated",
    ] {
        assert!(log.contains(expected), "{expected:?} missing:\n{log}");
    }
}

/// Dialer starts first, gets ECONNREFUSED, arms the 5s retry, and
/// connects once the listener appears.
#[test]
fn outgoing_retries_after_refused() {
    let tmp = tmp!("retry");
    // An inbound conn is timestamped with the loop's cached time (up
    // to 1s old); PingTimeout=1 would reap it before ID.
    let mut alice = Node::new(tmp.path(), "alice", 0xA1).with_conf("PingTimeout = 3\n");
    let mut bob = Node::new(tmp.path(), "bob", 0xB1).with_conf("PingTimeout = 3\n");

    bob.reserve_port();
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);
    alice.start();
    assert!(!alice.has_active_peer("bob"));

    bob.start();
    alice.wait_for_peer("bob", true, Duration::from_secs(15));

    let log = alice.stop();
    assert!(
        log.contains("Trying to re-establish outgoing connection in 5 seconds"),
        "{log}"
    );
    assert!(log.contains("Connected to bob"), "{log}");
}

/// PING/PONG keeps an idle connection alive; a `SIGSTOP`ped peer misses
/// its PONG and is dropped after `PingTimeout`; on `SIGCONT` it sees EOF
/// and its outgoing reconnects immediately.
#[test]
fn ping_timeout_drops_frozen_peer_then_reconnects() {
    let tmp = tmp!("pingpong");
    let conf = "PingInterval = 1\nPingTimeout = 3\n";
    let mut alice = Node::new(tmp.path(), "alice", 0xA8).with_conf(conf);
    let mut bob = Node::new(tmp.path(), "bob", 0xB8).with_conf(conf);
    alice.start_dialing(&mut bob);

    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            bob.has_active_peer("alice"),
            "PONG not clearing pinged bit?"
        );
    }

    alice.signal(Signal::SIGSTOP);
    bob.wait_for_peer("alice", false, Duration::from_secs(10));
    alice.signal(Signal::SIGCONT);
    bob.wait_for_peer("alice", true, Duration::from_secs(10));
}

/// Scripts are `execve`d directly, hence the shebang. The socket
/// appears before tinc-up runs, so poll for the marker.
#[test]
fn tinc_up_gets_interface_and_name() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tmp!("tincup");
    let mut alice = Node::new(tmp.path(), "alice", 0xA9);
    alice.write_config_multi(&[], &[]);
    let marker = tmp.path().join("tinc-up-ran");
    let script = alice.confbase.join("tinc-up");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"iface=$INTERFACE name=$NAME\" > '{}'\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    alice.start();
    assert!(
        wait_for_file(&marker),
        "tinc-up didn't run:\n{}",
        alice.stop()
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        "iface=dummy name=alice"
    );
}

/// Every valid name under hosts/ becomes a graph node at startup
/// (unreachable until an edge appears); editor droppings are skipped.
#[test]
fn hosts_dir_populates_graph() {
    let tmp = tmp!("loadall");
    let mut alice = Node::new(tmp.path(), "alice", 0xA9).with_conf("AutoConnect = no\n");
    let bob = Node::new(tmp.path(), "bob", 0xB9);
    alice.write_config(&bob, false);
    std::fs::write(
        alice.confbase.join("hosts/carol"),
        "Address = 127.0.0.1 1\n",
    )
    .unwrap();
    std::fs::write(alice.confbase.join("hosts/.swp"), "garbage\n").unwrap();

    alice.start();
    let nodes = alice.ctl().dump(3);
    let mut names = node_names(&nodes);
    names.sort_unstable();
    assert_eq!(names, ["alice", "bob", "carol"]);
    assert!(!node_reachable(&nodes, "carol"));
    assert!(!alice.stop().contains("Autoconnecting"));
}

/// With no `ConnectTo` but three hosts carrying an `Address`, autoconnect
/// dials one per 5s periodic tick until it has three connections.
#[test]
fn autoconnect_converges_to_three() {
    let tmp = tmp!("autoconnect");
    // Idle listeners only wake every 5s, so an inbound conn can be
    // stamped up to 5s stale; PingTimeout must exceed that.
    let mut alice = Node::new(tmp.path(), "alice", 0xA0).with_conf("PingTimeout = 10\n");
    let mut peers = ["bob", "carol", "dave"].map(|name| {
        Node::new(tmp.path(), name, name.as_bytes()[0])
            .with_conf("PingTimeout = 10\nAutoConnect = no\n")
            .log_level("tincd=info")
    });
    for peer in &mut peers {
        peer.write_config(&alice, false);
        peer.start();
    }
    alice.write_config_multi(&[], &[]);
    for peer in &peers {
        alice.write_host_file(peer, true);
    }
    alice.start();

    let active_peers = || {
        let conns = alice.ctl().dump(6);
        peers
            .iter()
            .filter(|peer| has_active_peer(&conns, &peer.name))
            .count()
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    while active_peers() < 3 {
        assert!(
            std::time::Instant::now() < deadline,
            "only {} conns; alice:\n{}\n{}",
            active_peers(),
            alice.log(),
            peers.iter().fold(String::new(), |mut logs, peer| {
                use std::fmt::Write;
                write!(logs, "--- {} ---\n{}", peer.name, peer.log()).unwrap();
                logs
            })
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(alice.stop().matches("Autoconnecting to ").count(), 3);
}
