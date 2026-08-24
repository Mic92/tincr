use std::time::Duration;

use super::common::node::*;
use super::common::*;

/// alice → mid ← bob. Three nodes because with two, killing the only
/// peer also kills the connection a `DEL_EDGE` would arrive on, and
/// we want alice to learn of bob's death via gossip.
fn chain_then_kill_bob(dir: &std::path::Path, alice_conf: &str) -> (Node, Node) {
    let mut alice = Node::new(dir, "alice", 0xA9).with_conf(alice_conf);
    let mut mid = Node::new(dir, "mid", 0xC9).with_conf("AutoConnect = no\n");
    let mut bob = Node::new(dir, "bob", 0xB9).with_conf("AutoConnect = no\n");

    mid.write_config_multi(&[&alice, &bob], &[]);
    mid.start();
    alice.write_config_multi(&[&mid, &bob], &[&mid]);
    alice.start();
    bob.write_config_multi(&[&mid, &alice], &[&mid]);
    bob.start();

    let mut alice_ctl = alice.ctl();
    poll_until(Duration::from_secs(10), || {
        let nodes = alice_ctl.dump(3);
        (nodes.len() == 3 && node_reachable(&nodes, "bob")).then_some(())
    });
    bob.stop();
    poll_until(Duration::from_secs(10), || {
        (!node_reachable(&alice_ctl.dump(3), "bob")).then_some(())
    });
    (alice, mid)
}

/// Unreachable nodes stay listed (no auto-purge, see issue #4) until
/// `REQ_PURGE`, which drops them when autoconnect is off.
#[test]
fn purge_removes_unreachable_node() {
    let tmp = tmp!("purge");
    let (alice, _mid) = chain_then_kill_bob(tmp.path(), "AutoConnect = no\n");
    let mut alice_ctl = alice.ctl();
    assert_eq!(alice_ctl.dump(3).len(), 3);
    for _ in 0..2 {
        assert_eq!(alice_ctl.purge(), 0);
        let nodes = alice_ctl.dump(3);
        assert_eq!(nodes.len(), 2, "{nodes:?}");
        assert!(node_reachable(&nodes, "alice") && node_reachable(&nodes, "mid"));
    }
}

/// Autoconnect wants dead nodes kept around to dial later, so purge
/// must not delete them under the default config.
#[test]
fn purge_keeps_nodes_when_autoconnect_on() {
    let tmp = tmp!("purge-ac");
    let (alice, _mid) = chain_then_kill_bob(tmp.path(), "");
    let mut alice_ctl = alice.ctl();
    assert_eq!(alice_ctl.purge(), 0);
    let nodes = alice_ctl.dump(3);
    assert_eq!(nodes.len(), 3, "{nodes:?}");
    assert!(!node_reachable(&nodes, "bob"));
}
