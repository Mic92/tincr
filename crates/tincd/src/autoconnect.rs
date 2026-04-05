//! `do_autoconnect` (`autoconnect.c`, 197 LOC). Pure decision logic —
//! converge to ~3 direct connections.
//!
//! Called every `5+jitter` seconds from `periodic_handler`. Takes a
//! snapshot of world state, returns ONE action
//! (or `Noop`). The daemon executes it.
//!
//! ## The 3-connection target
//!
//! Hardcoded magic number, not configurable. Rationale (inferred): 3
//! is enough redundancy that losing one peer doesn't isolate you, but
//! few enough that an N-node mesh has O(N) total conns, not O(N²). The
//! spanning-tree algorithms (sssp, mst) work on ANY connected graph;
//! this knob trades resilience for load.
//!
//! ## The four sub-decisions
//!
//! `do_autoconnect` is a priority dispatch. `nc` is the count of ALL active meta connections (inbound +
//! outbound — anything with `c->edge` set, i.e. past `ACK`):
//!
//! 1. `nc < 3` → `make_new_connection`: pick a random eligible node,
//!    try connecting. **Early return.**
//! 2. `nc > 3` → `drop_superfluous_outgoing_connection`: pick a random
//!    *outgoing* conn whose peer is multi-homed (`edge_count >= 2`, so
//!    dropping us doesn't disconnect them), drop it. NOT an early
//!    return — falls through to 3+4.
//! 3. `drop_superfluous_pending_connections`: cancel `Outgoing` slots
//!    that have no live conn (the retry timer is waiting). Fires
//!    whenever `nc >= 3` — including exactly 3. The C calls this
//!    unconditionally after the `< 3` early-return (`:194`).
//! 4. `connect_to_unreachable`: random ALL-node pick; if it's
//!    unreachable AND has-address AND not-connected AND not-us AND
//!    not-already-pending, try connecting. **The all-node randomization
//!    IS the back-off**: many reachable + few unreachable → low prob of
//!    picking; many unreachable → high prob. See [`decide`].
//!
//! ## "Exactly 3 still heals partitions"
//!
//! At `nc == 3` neither branch 1 nor 2 fires, but branch 4 does. So a
//! node that's happily 3-connected still occasionally pokes at
//! unreachable nodes. This is what knits a fragmented graph back
//! together — *every* node is doing this every 5s, with the
//! probabilistic back-off keeping the thundering herd off any single
//! unreachable node.
//!
//! ## RNG injection
//!
//! `prng()` calls in C (`chacha_prng.c`). We take `&mut impl RngCore`.
//! Tests seed deterministically.
//!
//! ## One action per tick (deviation from C)
//!
//! The C may do drop + cancel + connect in one tick (steps 2+3+4 all
//! fire). We return the FIRST non-`Noop`. The 5-second cadence means
//! convergence in ~15s instead of ~5s when over-connected, which is
//! fine. The daemon is free to loop `while decide() != Noop` if faster
//! convergence ever matters; the per-tick state mutation between calls
//! keeps it from looping forever.

#![forbid(unsafe_code)]

use rand_core::RngCore;

/// What `do_autoconnect` decided. The daemon executes.
#[derive(Debug, PartialEq, Eq)]
pub enum AutoAction {
    /// `<3` conns (`make_new_connection`) or `connect_to_unreachable`.
    /// Daemon: `lookup_or_add_node`, build `Outgoing`,
    /// `setup_outgoing_connection`.
    Connect { name: String },
    /// `>3` conns. Drop this outgoing + terminate its conn.
    Disconnect { name: String },
    /// Cancel a between-retries pending outgoing. Daemon: just
    /// remove from `outgoings` slotmap (no conn to terminate).
    CancelPending { name: String },
    /// Nothing to do this tick. Can mean: at exactly 3 with nothing to
    /// heal; or under 3 but no eligible nodes; or
    /// `connect_to_unreachable` rolled an ineligible index (the
    /// back-off in action).
    Noop,
}

/// Snapshot of one node's state. The daemon builds this from `Graph`
/// + `nodes: HashMap<String, NodeState>` + `conns`.
///
/// ## `has_address` — not yet wired
///
/// Upstream sets it in `load_all_nodes()`: walk `hosts/`, for each
/// file with `Address = `, set the bit. We don't `load_all_nodes`
/// yet — we read `hosts/` on demand in `id_h`. The
/// serial wire-up (chunk-11) needs either: (a) `load_all_nodes` at
/// setup, or (b) a cheap "does `hosts/{name}` have `Address`" probe.
/// **For this module: it's just a `bool`. How the daemon populates it
/// is the daemon's problem.**
///
/// ## `edge_count` is per-node, not per-connection
///
/// The *peer's* edge count from the gossiped graph. When
/// considering dropping our conn to
/// `node`, we ask: does `node` have other edges? If `edge_count < 2`,
/// our edge is its only one; dropping it isolates the peer.
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub name: String,
    /// `n->status.reachable`. From sssp.
    pub reachable: bool,
    /// `n->status.has_address`. We have a `hosts/` file with
    /// `Address = ` for this node — could connect to it directly.
    /// (vs. nodes we only know via gossip.)
    pub has_address: bool,
    /// `n->connection != NULL`. We have a direct meta conn (inbound OR
    /// outbound) to this node.
    pub directly_connected: bool,
    /// `n->edge_tree.count`. How many edges this node has in the
    /// gossiped graph. `:121` `< 2` means dropping our edge would
    /// isolate it.
    pub edge_count: usize,
}

/// `do_autoconnect`.
///
/// # Arguments
///
/// - `myself_name` — skip `n == myself` (`:34`, `:92`).
/// - `nodes` — ALL known nodes, including indirect/unreachable. May
///   include `myself` (it's filtered). Order matters for
///   `connect_to_unreachable` index-picking (use a stable iteration
///   order — the daemon should sort by name, matching C's splay tree).
/// - `active_outgoing_conns` — names of nodes we have an OUTGOING conn
///   to (active, past-ACK, `c->edge && c->outgoing`). NOT all conns:
///   inbound conns are someone else's choice, we don't unilaterally
///   close them (`:121` `!c->outgoing` skip).
/// - `pending_outgoings` — names with an `Outgoing` slot but NO conn.
///   The retry timer is waiting.
///
/// `nc` (the `<3`/`>3` decision) counts ALL direct conns (inbound +
/// outbound), derived from `nodes` where `directly_connected`. C
/// `:174-179` walks `connection_list` for `c->edge`.
///
/// # The `connect_to_unreachable` back-off
///
/// `:86` does `prng(node_tree.count)` — randomizes over ALL nodes,
/// **including ineligible ones**. If `r` lands on an ineligible node,
/// it's an immediate `return` (`:95`): `Noop` this tick. THIS IS THE
/// FEATURE. The probability of a `Connect` action is exactly
/// `count_eligible_unreachable / count_all_nodes`. Don't "fix" by
/// filtering first.
///
/// If 100 nodes are reachable and 1 is unreachable, every node in the
/// mesh has a ~1% chance per 5-second tick of trying to connect to it.
/// With 100 nodes ticking, that's ~1 attempt per tick mesh-wide —
/// natural rate limiting without coordination. If 4 of 5 are
/// unreachable, every node has an ~80% chance per tick: high effort
/// when the mesh is fragmented.
///
/// # `make_new_connection` already-pending → `Noop`
///
/// Even if eligible, if we already have a pending `Outgoing` for
/// the picked node, `break` — don't add a duplicate, but ALSO don't
/// pick another. Next tick will re-roll. We mirror
/// this: if the random pick is in `pending_outgoings`, return `Noop`.
#[must_use]
pub fn decide(
    myself_name: &str,
    nodes: &[NodeSnapshot],
    active_outgoing_conns: &[String],
    pending_outgoings: &[String],
    rng: &mut impl RngCore,
) -> AutoAction {
    // C :174-179. Count ALL active meta conns (c->edge != NULL),
    // inbound + outbound. One conn per peer in tinc, so this is just
    // "how many peers am I directly connected to".
    let nc = nodes
        .iter()
        .filter(|n| n.directly_connected && n.name != myself_name)
        .count();

    // C :183-186. < 3 → eagerly make a new one. EARLY RETURN.
    if nc < 3 {
        return make_new_connection(myself_name, nodes, pending_outgoings, rng);
    }

    // C :188-190. > 3 → try to drop a superfluous outgoing.
    // No early return in C, but we return-first-non-Noop.
    if nc > 3 {
        let act = drop_superfluous_outgoing(nodes, active_outgoing_conns, rng);
        if act != AutoAction::Noop {
            return act;
        }
    }

    // C :194. nc >= 3 (the < 3 branch returned). Cancel pending
    // outgoings: if we already have enough conns, no point keeping a
    // retry timer alive.
    if let Some(name) = pending_outgoings.first() {
        // Upstream cancels ALL of them in one tick (it's a list
        // walk). We return one; next tick gets the next one. The
        // 5-second cadence stretches this out, but pending outgoings
        // accumulating while at >=3 conns is itself rare.
        return AutoAction::CancelPending { name: name.clone() };
    }

    // C :196. Heal partitions. Fires even at nc == 3.
    connect_to_unreachable(myself_name, nodes, pending_outgoings, rng)
}

/// `make_new_connection`.
///
/// Eligible: not myself, not directly connected, AND
/// `(has_address || reachable)`. The reachable-but-no-address case:
/// we learned of this node via gossip and can route packets to it
/// indirectly, but maybe it's behind NAT and *it* could connect to
/// *us* if poked? Actually no — `setup_outgoing_connection` needs an
/// address. The C eligibility predicate `:34` includes `reachable` so
/// the address can come from a learned `via` edge. Either way: same
/// predicate.
///
/// C does count-then-re-walk (the splay tree gives no random access).
/// We can collect+index. Same distribution.
fn make_new_connection(
    myself_name: &str,
    nodes: &[NodeSnapshot],
    pending_outgoings: &[String],
    rng: &mut impl RngCore,
) -> AutoAction {
    let eligible: Vec<&NodeSnapshot> = nodes
        .iter()
        .filter(|n| {
            n.name != myself_name && !n.directly_connected && (n.has_address || n.reachable)
        })
        .collect();

    if eligible.is_empty() {
        // C :41-43. No eligible nodes. < 3 conns but nobody to call.
        // The C falls off the end of make_new_connection() and then
        // do_autoconnect() returns (the `< 3` branch is `return`, so
        // step 4 does NOT fire). We mirror: Noop.
        return AutoAction::Noop;
    }

    // C :45 prng(count) — uniform over [0, count).
    #[allow(clippy::cast_possible_truncation)] // eligible.len() ≤ node count (~thousands)
    let r = (rng.next_u32() % (eligible.len() as u32)) as usize;
    let pick = eligible[r];

    // C :59-71. Already have a pending outgoing for this node? Then
    // `break` — don't duplicate, don't re-roll. Noop this tick.
    if pending_outgoings.iter().any(|p| p == &pick.name) {
        return AutoAction::Noop;
    }

    AutoAction::Connect {
        name: pick.name.clone(),
    }
}

/// `connect_to_unreachable`.
///
/// **The all-node prng is the back-off.** See module docs.
///
/// `r = prng(node_tree.count)` — index into ALL nodes, NOT a filtered
/// list. Walk to the `r`th node. If that node is ineligible
/// (reachable, or no-address, or us, or connected, or
/// already-pending), return `Noop`. Don't pick another.
fn connect_to_unreachable(
    myself_name: &str,
    nodes: &[NodeSnapshot],
    pending_outgoings: &[String],
    rng: &mut impl RngCore,
) -> AutoAction {
    if nodes.is_empty() {
        return AutoAction::Noop;
    }

    // C :86. prng over ALL nodes. node_tree includes myself.
    #[allow(clippy::cast_possible_truncation)] // nodes.len() bounded by node count (≪ u32::MAX)
    let r = (rng.next_u32() % (nodes.len() as u32)) as usize;
    let n = &nodes[r];

    // C :94-96. Ineligible → return. NOT continue. THIS is the
    // back-off: ineligible (typically: reachable) nodes act as
    // probability mass that resolves to Noop.
    if n.name == myself_name || n.directly_connected || n.reachable || !n.has_address {
        return AutoAction::Noop;
    }

    // C :99-103. Already trying? Noop.
    if pending_outgoings.iter().any(|p| p == &n.name) {
        return AutoAction::Noop;
    }

    AutoAction::Connect {
        name: n.name.clone(),
    }
}

/// `drop_superfluous_outgoing_connection`.
///
/// Only OUTGOING conns are eligible: `!c->outgoing` skips
/// inbound. Inbound conns are someone else's `AutoConnect` decision;
/// we don't unilaterally close them.
///
/// Only conns to multi-homed peers: `:121` `edge_tree.count < 2`
/// skips. If the peer's only edge is us, dropping it isolates them.
fn drop_superfluous_outgoing(
    nodes: &[NodeSnapshot],
    active_outgoing_conns: &[String],
    rng: &mut impl RngCore,
) -> AutoAction {
    // C :119-126. Walk connection_list, filter to:
    // c->edge && c->outgoing && c->node && c->node->edge_tree.count >= 2.
    // We have active_outgoing_conns (already past-ACK, already outgoing).
    // Join against nodes for edge_count.
    let droppable: Vec<&str> = active_outgoing_conns
        .iter()
        .filter(|name| {
            nodes
                .iter()
                .find(|n| &n.name == *name)
                .is_some_and(|n| n.edge_count >= 2)
        })
        .map(String::as_str)
        .collect();

    if droppable.is_empty() {
        // C :128-130. Everyone's single-homed, can't drop without
        // isolating someone. Fall through.
        return AutoAction::Noop;
    }

    #[allow(clippy::cast_possible_truncation)] // droppable.len() bounded by conn count (≪ u32::MAX)
    let r = (rng.next_u32() % (droppable.len() as u32)) as usize;
    AutoAction::Disconnect {
        name: droppable[r].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn node(
        name: &str,
        reachable: bool,
        has_address: bool,
        directly_connected: bool,
        edge_count: usize,
    ) -> NodeSnapshot {
        NodeSnapshot {
            name: name.to_string(),
            reachable,
            has_address,
            directly_connected,
            edge_count,
        }
    }

    /// Exactly 3 conns, no pending, no unreachable → Noop.
    /// Neither <3 nor >3 fires; `cancel_pending` has nothing;
    /// `connect_to_unreachable` rolls but finds only reachable nodes.
    #[test]
    fn noop_at_exactly_3() {
        let nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        // Try several seeds: every roll should land on a reachable
        // node and return Noop.
        for seed in 0..20 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = decide(
                "me",
                &nodes,
                &["a".into(), "b".into(), "c".into()],
                &[],
                &mut rng,
            );
            assert_eq!(act, AutoAction::Noop, "seed {seed}");
        }
        // Silence unused.
        let _ = rng.next_u32();
    }

    /// 1 active conn, 5 eligible candidates. Must pick one of them.
    /// Seeded RNG → deterministic pick.
    #[test]
    fn connect_when_under_3() {
        let nodes = vec![
            node("me", true, true, false, 1),
            node("conn", true, true, true, 2), // already connected
            node("e1", true, true, false, 1),
            node("e2", true, true, false, 1),
            node("e3", false, true, false, 0),
            node("e4", true, false, false, 1), // reachable, no addr — still eligible
            node("e5", true, true, false, 1),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let act = decide("me", &nodes, &["conn".into()], &[], &mut rng);
        // 5 eligible: e1..e5. Seed 42 picks deterministically.
        match act {
            AutoAction::Connect { name } => {
                assert!(
                    ["e1", "e2", "e3", "e4", "e5"].contains(&name.as_str()),
                    "picked {name}"
                );
            }
            other => panic!("expected Connect, got {other:?}"),
        }
        // Seed determinism: same seed → same pick.
        let mut rng2 = ChaCha8Rng::seed_from_u64(42);
        let act2 = decide("me", &nodes, &["conn".into()], &[], &mut rng2);
        assert_eq!(
            act2,
            decide(
                "me",
                &nodes,
                &["conn".into()],
                &[],
                &mut ChaCha8Rng::seed_from_u64(42)
            )
        );
        let _ = act2;
    }

    /// Under 3, but nobody eligible: only us, one connected, one with
    /// neither address nor reachability. The <3 branch returns Noop
    /// (and DOES early-return — step 4 does not fire).
    #[test]
    fn connect_skips_ineligible() {
        let nodes = vec![
            node("me", true, true, false, 1),
            node("conn", true, true, true, 2),
            // Not reachable, no address: pure gossip node. Can't
            // connect.
            node("ghost", false, false, false, 0),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = decide("me", &nodes, &["conn".into()], &[], &mut rng);
        assert_eq!(act, AutoAction::Noop);
    }

    /// Under 3, the only eligible node is already in pending. C :63
    /// `break` — don't duplicate, don't re-roll. Noop. Next tick will
    /// (probably) roll the same and Noop again until either the
    /// pending succeeds or another node becomes eligible.
    #[test]
    fn connect_skips_already_pending() {
        let nodes = vec![
            node("me", true, true, false, 0),
            node("only", false, true, false, 0),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = decide("me", &nodes, &[], &["only".into()], &mut rng);
        assert_eq!(act, AutoAction::Noop);
    }

    /// 5 active outgoing conns, all peers multi-homed (`edge_count`
    /// >= 2). Must Disconnect one.
    #[test]
    fn disconnect_when_over_3() {
        let nodes = vec![
            node("me", true, true, false, 5),
            node("a", true, true, true, 3),
            node("b", true, true, true, 2),
            node("c", true, true, true, 4),
            node("d", true, true, true, 2),
            node("e", true, true, true, 3),
        ];
        let outgoing: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| (*s).into())
            .collect();
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let act = decide("me", &nodes, &outgoing, &[], &mut rng);
        match act {
            AutoAction::Disconnect { name } => {
                assert!(outgoing.contains(&name));
            }
            other => panic!("expected Disconnect, got {other:?}"),
        }
    }

    /// Over 3, but every peer has `edge_count` == 1 (we're their only
    /// link). Can't drop any without isolating. With no pending
    /// either, falls through to `connect_to_unreachable`, which finds
    /// only reachable nodes → Noop.
    #[test]
    fn disconnect_skips_single_homed() {
        let nodes = vec![
            node("me", true, true, false, 5),
            node("a", true, true, true, 1),
            node("b", true, true, true, 1),
            node("c", true, true, true, 1),
            node("d", true, true, true, 1),
            node("e", true, true, true, 1),
        ];
        let outgoing: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| (*s).into())
            .collect();
        for seed in 0..10 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = decide("me", &nodes, &outgoing, &[], &mut rng);
            assert_eq!(act, AutoAction::Noop, "seed {seed}");
        }
    }

    /// 4 active (over 3), all single-homed (can't drop), but 2 pending.
    /// → `CancelPending` fires.
    #[test]
    fn cancel_pending_when_over_3() {
        let nodes = vec![
            node("me", true, true, false, 4),
            node("a", true, true, true, 1),
            node("b", true, true, true, 1),
            node("c", true, true, true, 1),
            node("d", true, true, true, 1),
        ];
        let outgoing: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| (*s).into()).collect();
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = decide(
            "me",
            &nodes,
            &outgoing,
            &["p1".into(), "p2".into()],
            &mut rng,
        );
        assert_eq!(act, AutoAction::CancelPending { name: "p1".into() });
    }

    /// THE design intent test. 100 nodes, 1 unreachable. At exactly 3
    /// conns (so neither <3 nor >3 fires), `connect_to_unreachable` runs
    /// every tick. P(connect) = 1/100 per tick. 1000 ticks → expect
    /// ~10. Binomial(1000, 0.01): mean 10, σ ≈ 3.15. Loose bounds.
    #[test]
    fn connect_unreachable_backoff_low_prob() {
        let mut nodes = vec![node("me", true, true, false, 3)];
        // 3 connected (so nc == 3).
        for name in ["c1", "c2", "c3"] {
            nodes.push(node(name, true, true, true, 2));
        }
        // 95 reachable filler. Not connected, but reachable — so
        // ineligible for connect_to_unreachable (which wants
        // !reachable).
        for i in 0..95 {
            nodes.push(node(&format!("fill{i}"), true, false, false, 1));
        }
        // 1 unreachable, has address. The target.
        nodes.push(node("dark", false, true, false, 0));
        assert_eq!(nodes.len(), 100);

        let outgoing: Vec<String> = ["c1", "c2", "c3"].iter().map(|s| (*s).into()).collect();

        let mut hits = 0;
        for seed in 0..1000 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = decide("me", &nodes, &outgoing, &[], &mut rng);
            if act
                == (AutoAction::Connect {
                    name: "dark".into(),
                })
            {
                hits += 1;
            }
        }
        // Expect ~10. Allow [5, 20).
        assert!(
            (5..20).contains(&hits),
            "expected ~10 hits (1% of 1000), got {hits}"
        );
    }

    /// Inverse: 5 nodes, 4 unreachable. P(connect) per tick ≈ 4/5 if
    /// all 4 are eligible. But one slot is "me" (ineligible). So 4/5
    /// land on an eligible unreachable. ~80%. 100 ticks → expect ~80.
    #[test]
    fn connect_unreachable_backoff_high_prob() {
        // We need nc >= 3 to reach connect_to_unreachable. But the
        // scenario is "5 nodes, 4 unreachable". If 4 are unreachable
        // they're not directly_connected. So nc would be 0... and we'd
        // hit the <3 branch instead.
        //
        // Work around: make_new_connection's eligibility is
        // (has_address || reachable). Set the 4 unreachable nodes to
        // also have NO address: ineligible for make_new. Then <3
        // returns Noop and... wait, <3 early-returns even on Noop.
        // The C is `if(nc < 3) { make_new(); return; }`. So step 4
        // never fires when nc < 3.
        //
        // Real scenario: a node with 3 conns whose graph view shows
        // many unreachable nodes (the mesh is partitioned, but THIS
        // node is in the 3-connected fragment). Model that.
        let mut nodes = vec![node("me", true, true, false, 3)];
        // 3 connected (our fragment).
        for name in ["c1", "c2", "c3"] {
            nodes.push(node(name, true, true, true, 2));
        }
        // 16 unreachable, with address. The dark fragment.
        for i in 0..16 {
            nodes.push(node(&format!("dark{i}"), false, true, false, 0));
        }
        assert_eq!(nodes.len(), 20);
        // P(hit eligible unreachable) = 16/20 = 80%.

        let outgoing: Vec<String> = ["c1", "c2", "c3"].iter().map(|s| (*s).into()).collect();

        let mut hits = 0;
        for seed in 0..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            if let AutoAction::Connect { .. } = decide("me", &nodes, &outgoing, &[], &mut rng) {
                hits += 1;
            }
        }
        // Expect ~80. Binomial(100, 0.8): mean 80, σ = 4. Allow > 60.
        assert!(hits > 60, "expected ~80 hits (80% of 100), got {hits}");
    }

    /// Only node is myself. Every branch filters it out. Noop.
    #[test]
    fn myself_never_picked() {
        let nodes = vec![node("me", true, true, false, 0)];
        for seed in 0..50 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = decide("me", &nodes, &[], &[], &mut rng);
            assert_eq!(act, AutoAction::Noop, "seed {seed}");
        }
    }

    /// Exactly 3 conns, but a pending outgoing exists. C calls
    /// `drop_superfluous_pending` unconditionally after the <3
    /// early-return — so at nc==3 it fires. Cancel it.
    #[test]
    fn cancel_pending_at_exactly_3() {
        let nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = decide(
            "me",
            &nodes,
            &["a".into(), "b".into(), "c".into()],
            &["stale".into()],
            &mut rng,
        );
        assert_eq!(
            act,
            AutoAction::CancelPending {
                name: "stale".into()
            }
        );
    }

    /// Disconnect filters: an inbound conn (`directly_connected` but NOT
    /// in `active_outgoing_conns`) is never picked for Disconnect, even
    /// if multi-homed.
    #[test]
    fn disconnect_never_picks_inbound() {
        let nodes = vec![
            node("me", true, true, false, 5),
            // 4 outgoing, multi-homed → droppable.
            node("out1", true, true, true, 3),
            node("out2", true, true, true, 3),
            node("out3", true, true, true, 3),
            node("out4", true, true, true, 3),
            // 1 inbound, multi-homed. NOT in active_outgoing_conns.
            node("in1", true, true, true, 3),
        ];
        // nc = 5 (>3). active_outgoing_conns has only the 4 outgoing.
        let outgoing: Vec<String> = ["out1", "out2", "out3", "out4"]
            .iter()
            .map(|s| (*s).into())
            .collect();
        for seed in 0..50 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            match decide("me", &nodes, &outgoing, &[], &mut rng) {
                AutoAction::Disconnect { name } => {
                    assert_ne!(name, "in1", "seed {seed}: dropped inbound");
                    assert!(outgoing.contains(&name));
                }
                other => {
                    panic!("seed {seed}: expected Disconnect, got {other:?}")
                }
            }
        }
    }
}
