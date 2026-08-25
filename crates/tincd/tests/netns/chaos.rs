//! netem on `lo` perturbs the daemon↔daemon UDP transport; the
//! kernel ICMP inside the tunnel has no retransmit, so replay-window
//! behaviour shows up directly in ping loss and `BadSeqno` logs.

use super::common::TmpGuard;
use super::rig::{Netem, TunPair, enter_netns, ping, ping_received};

fn chaos_pair(name: &str) -> Option<(TmpGuard, TunPair)> {
    let netns = enter_netns(&format!("chaos::{name}"))?;
    let tmp = tmp!(name);
    let pair = TunPair::start(netns, &tmp, "");
    pair.wait_validkey();
    pair.wait_udp_confirmed();
    Some((tmp, pair))
}

fn bad_seqno_count(alice_log: &str, bob_log: &str) -> usize {
    alice_log.matches("BadSeqno").count() + bob_log.matches("BadSeqno").count()
}

/// Loss creates seqno gaps, which the replay window must accept
/// (marking the gap late), never reject.
#[test]
fn chaos_ping_under_loss() {
    let Some((_tmp, pair)) = chaos_pair("chaos_ping_under_loss") else {
        return;
    };
    let (bob_in_before, _) = TunPair::traffic(&pair.bob);
    let (_, alice_out_before) = TunPair::traffic(&pair.alice);

    let netem = Netem::apply("lo", "loss 5%");
    // 50ms spacing so loss is the only perturbation (no queueing).
    let received = ping_received(&ping(&["-c", "30", "-i", "0.05", "-W", "1"], "10.42.0.2"));
    drop(netem);

    let bob_accepted = TunPair::traffic(&pair.bob).0 - bob_in_before;
    let alice_sent = TunPair::traffic(&pair.alice).1 - alice_out_before;
    let (alice_log, bob_log) = pair.finish();

    // Expect ~27/30 (0.95² × 30); below 5 means something other
    // than netem is dropping.
    assert!(
        received >= 5,
        "{received}/30\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    assert_eq!(
        bad_seqno_count(&alice_log, &bob_log),
        0,
        "=== bob ===\n{bob_log}"
    );
    assert!(bob_accepted <= alice_sent, "{bob_accepted} > {alice_sent}");
}

/// Near-monotonic seqnos with single swaps: exactly what the `late[]`
/// bitmap is for. Reorder alone must neither lose nor reject.
#[test]
fn chaos_replay_under_reorder() {
    let Some((_tmp, pair)) = chaos_pair("chaos_replay_under_reorder") else {
        return;
    };
    let netem = Netem::apply("lo", "delay 5ms reorder 25% 50%");
    // Faster than the 5ms delay so the netem queue is never empty.
    let received = ping_received(&ping(&["-c", "100", "-i", "0.01", "-W", "2"], "10.42.0.2"));
    drop(netem);
    let (alice_log, bob_log) = pair.finish();

    assert!(received >= 98, "{received}/100\n=== bob ===\n{bob_log}");
    assert_eq!(
        bad_seqno_count(&alice_log, &bob_log),
        0,
        "=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
}

/// Duplicates carry an already-seen seqno and must be rejected
/// (`BadSeqno`) without being counted or delivered, and without the
/// decode-failure path resetting the tunnel (`DecryptFailed` would
/// follow). 30% on 100 packets makes zero dups practically impossible.
#[test]
fn chaos_replay_under_duplicate() {
    let Some((_tmp, pair)) = chaos_pair("chaos_replay_under_duplicate") else {
        return;
    };
    let (bob_in_before, _) = TunPair::traffic(&pair.bob);
    let (_, alice_out_before) = TunPair::traffic(&pair.alice);

    let netem = Netem::apply("lo", "duplicate 30%");
    let output = ping(&["-c", "50", "-i", "0.02", "-W", "2"], "10.42.0.2");
    drop(netem);

    let bob_accepted = TunPair::traffic(&pair.bob).0 - bob_in_before;
    let alice_sent = TunPair::traffic(&pair.alice).1 - alice_out_before;
    let (alice_log, bob_log) = pair.finish();

    assert!(output.status.success(), "=== bob ===\n{bob_log}");
    let rejected = bad_seqno_count(&alice_log, &bob_log);
    assert!(
        rejected >= 3,
        "{rejected} BadSeqno\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    assert!(
        bob_accepted <= alice_sent,
        "dup delivered: {bob_accepted} > {alice_sent}"
    );
    assert!(
        !alice_log.contains("DecryptFailed") && !bob_log.contains("DecryptFailed"),
        "tunnel reset under dup\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
}
