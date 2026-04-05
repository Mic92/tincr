use std::time::Duration;

use super::common::*;
use super::node::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("2d", tag)
}

/// `purge()` via `REQ_PURGE`.
///
/// Three daemons in a chain: alice — mid — bob. Kill bob; mid's
/// `terminate()` deletes the mid↔bob edges and gossips `DEL_EDGE` to
/// alice. Alice's `on_del_edge` runs `graph()` → bob unreachable.
///
/// Then send `REQ_PURGE` to alice. Pass 1 deletes bob's outgoing
/// edges (none — alice never had a bob→* edge, only mid→bob),
/// pass 2 sees no edge with `to == bob` (mid's `DEL_EDGE`
/// removed it), `!autoconnect` (we set `AutoConnect = no`), no
/// strictsubnets → `node_del`. `dump_nodes` goes from 3 rows to 2.
///
/// Why three daemons, not two: with two, killing alice's only peer
/// also kills the only meta-connection that `DEL_EDGE` could arrive
/// on. The `terminate()` path on the SURVIVING daemon's side does
/// the local `del_edge` directly (`connect.rs::terminate`), which doesn't
/// touch `on_del_edge` and so doesn't trigger our purge-on-del-edge
/// hook. `REQ_PURGE` works either way, but the `on_del_edge` hook (the
/// memory-growth fix) needs gossip to actually propagate.
///
/// We test BOTH triggers: alice's `on_del_edge` should auto-purge
/// bob (the `gossip.rs` hook); we then verify with `REQ_PURGE` that
/// the ctl arm replies `"18 8 0"` and is idempotent (already gone).
#[test]
fn purge_removes_unreachable_node() {
    use std::io::{BufRead, Write};

    let tmp = tmp("purge");
    // AutoConnect = no: pass 2's gate is `!autoconnect`. Default is
    // true, under which purge NEVER deletes nodes (it wants to dial
    // them).
    let alice = Node::new(tmp.path(), "alice", 0xA9).with_conf("AutoConnect = no\n");
    let mid = Node::new(tmp.path(), "mid", 0xC9).with_conf("AutoConnect = no\n");
    let bob = Node::new(tmp.path(), "bob", 0xB9).with_conf("AutoConnect = no\n");

    // Chain: alice ConnectTo mid; bob ConnectTo mid. mid is the hub.
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    alice.write_config_multi(&[&mid, &bob], &["mid"], None, None);
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, None);

    let mut mid_child = mid.spawn();
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        let _ = alice_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let mut alice_ctl = alice.ctl();

    // ─── wait: alice sees all three nodes, bob reachable ────────
    // bob is two hops away: alice—mid edge from alice's ACK,
    // mid—bob edge gossiped via ADD_EDGE from mid.
    poll_until(Duration::from_secs(10), || {
        let nodes = alice_ctl.dump(3);
        let bob_reachable = node_status(&nodes, "bob").is_some_and(|s| s & 0x10 != 0);
        (nodes.len() == 3 && bob_reachable).then_some(())
    });

    // ─── kill bob → mid gossips DEL_EDGE → alice purges ────────
    // mid's `terminate()` (`connect.rs`) sends DEL_EDGE for
    // mid→bob and bob→mid to alice. Alice's `on_del_edge` for the
    // mid→bob direction: deletes the edge, runs graph() → bob
    // unreachable, then our hook calls `purge()`. Pass 2 fires:
    // no edge points to bob anymore (both directions gone),
    // !autoconnect, !strictsubnets → node_del.
    let _ = bob_child.kill();
    let _ = bob_child.wait();

    // alice's view: bob GONE (not just unreachable). 2 rows.
    // EOF on the meta socket is immediate (SIGKILL → kernel sends
    // RST/FIN); mid's `terminate()` runs synchronously, broadcasts
    // DEL_EDGE, the `maybe_set_write_any` we added flushes it. One
    // loopback round trip.
    poll_until(Duration::from_secs(10), || {
        let nodes = alice_ctl.dump(3);
        let bob_row = nodes.iter().any(|r| {
            r.strip_prefix("18 3 ")
                .and_then(|b| b.split_whitespace().next())
                == Some("bob")
        });
        (nodes.len() == 2 && !bob_row).then_some(())
    });

    // ─── REQ_PURGE: ack `"18 8 0"`, idempotent ───────────────────
    // `control_ok(c, REQ_PURGE)` → `"18 8 0\n"`. bob is already
    // gone (auto-purge above); this proves the ctl arm is wired up
    // and handles the empty-purge case (
    // both `splay_each` loops just iterate zero unreachable nodes).
    writeln!(alice_ctl.w, "18 8").unwrap();
    let mut ack = String::new();
    alice_ctl.r.read_line(&mut ack).expect("purge ack");
    assert_eq!(ack.trim_end(), "18 8 0", "REQ_PURGE control_ok reply");

    // Still 2 rows; alice and mid both reachable.
    let nodes = alice_ctl.dump(3);
    assert_eq!(nodes.len(), 2, "idempotent: {nodes:?}");
    assert!(
        node_status(&nodes, "alice").is_some_and(|s| s & 0x10 != 0),
        "alice (myself) reachable: {nodes:?}"
    );
    assert!(
        node_status(&nodes, "mid").is_some_and(|s| s & 0x10 != 0),
        "mid reachable: {nodes:?}"
    );

    drop(alice_ctl);
    let _ = alice_child.kill();
    let _ = mid_child.kill();
    let _ = alice_child.wait();
    let _ = mid_child.wait();
}

/// `purge()` pass-2 early return: a single edge to ANY unreachable
/// node aborts ALL node deletions. The autoconnect
/// gate also prevents deletion (default config).
///
/// Same chain as `purge_removes_unreachable_node`, but alice runs
/// with `AutoConnect = yes` (the default). Kill bob → bob becomes
/// unreachable on alice. Auto-purge fires (the `on_del_edge` hook),
/// but pass 2's `!autoconnect` gate is false, so bob STAYS in the
/// node list. `dump_nodes`: still 3 rows, bob status `0x0`.
///
/// This proves we don't over-purge: the gate exists because
/// autoconnect WANTS dead nodes around — it dials them.
#[test]
fn purge_respects_autoconnect_gate() {
    use std::io::{BufRead, Write};

    let tmp = tmp("purge-ac");
    // No `AutoConnect = no` line → default true.
    let alice = Node::new(tmp.path(), "alice", 0xAA);
    let mid = Node::new(tmp.path(), "mid", 0xCA).with_conf("AutoConnect = no\n");
    let bob = Node::new(tmp.path(), "bob", 0xBA).with_conf("AutoConnect = no\n");

    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    alice.write_config_multi(&[&mid, &bob], &["mid"], None, None);
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, None);

    let mut mid_child = mid.spawn();
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        let _ = alice_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let mut alice_ctl = alice.ctl();

    poll_until(Duration::from_secs(10), || {
        let nodes = alice_ctl.dump(3);
        let bob_reachable = node_status(&nodes, "bob").is_some_and(|s| s & 0x10 != 0);
        (nodes.len() == 3 && bob_reachable).then_some(())
    });

    let _ = bob_child.kill();
    let _ = bob_child.wait();

    // bob unreachable but STILL PRESENT. 3 rows. Wait for the
    // unreachability transition (DEL_EDGE → graph() → status 0).
    poll_until(Duration::from_secs(10), || {
        let nodes = alice_ctl.dump(3);
        node_status(&nodes, "bob")
            .is_some_and(|s| s & 0x10 == 0)
            .then_some(())
    });

    // Explicit REQ_PURGE: still gated by autoconnect.
    writeln!(alice_ctl.w, "18 8").unwrap();
    let mut ack = String::new();
    alice_ctl.r.read_line(&mut ack).expect("purge ack");
    assert_eq!(ack.trim_end(), "18 8 0");

    let nodes = alice_ctl.dump(3);
    assert_eq!(
        nodes.len(),
        3,
        "autoconnect gate: bob should NOT be purged; {nodes:?}"
    );
    assert!(
        node_status(&nodes, "bob").is_some_and(|s| s & 0x10 == 0),
        "bob unreachable but present: {nodes:?}"
    );

    drop(alice_ctl);
    let _ = alice_child.kill();
    let _ = mid_child.kill();
    let _ = alice_child.wait();
    let _ = mid_child.wait();
}
