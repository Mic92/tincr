//! `do_autoconnect` (`autoconnect.c`, 197 LOC) plus a Rust-only
//! demand-driven "relay shortcut" layer. Pure decision logic — takes
//! a snapshot of world state, returns ONE action; the daemon executes.
//!
//! ## The 3-connection backbone (unchanged from C)
//!
//! Every node holds ~3 random meta connections. Random 3-regular
//! graphs are a.a.s. 3-connected expanders (Bollobás 1981); diameter
//! is `log₂ n` and per-event flood cost is `3n`. That is the
//! resilience floor and stays untouched.
//!
//! Called every `5+jitter` seconds from `periodic_handler`. `nc` is
//! the count of ALL active meta connections (inbound + outbound —
//! anything past `ACK`):
//!
//! 1. `nc < 3` → `make_new_connection`: random eligible node.
//!    **Early return.**
//! 2. `nc > 3` → `drop_superfluous_outgoing_connection`: random
//!    *outgoing* conn whose peer has `edge_count >= 2`. NOT an early
//!    return in C — falls through to 3+4.
//! 3. `drop_superfluous_pending_connections`: cancel `Outgoing` slots
//!    with no live conn. Fires whenever `nc >= 3`.
//! 4. `connect_to_unreachable`: random ALL-node pick; if unreachable
//!    AND has-address AND not-connected, dial. The all-node prng IS
//!    the back-off — see [`decide`].
//!
//! ## Relay shortcuts (Rust-only)
//!
//! The backbone is for the *control* plane. When UDP to a peer is
//! blackholed the *data* plane rides the meta graph (`SPTPS_PACKET`
//! over TCP via `nexthop`), and degree-3-random is oblivious to where
//! the bytes actually flow. Result in production: `blob64` sits two
//! TCP hops away forever because `nc==3` → `Noop`.
//!
//! Fix (Candidate A from `docs/design/autoconnect-theory.md`): keep
//! the random base, add up to `D_SHORTCUT` (default 2) extra outgoing
//! slots to the peers we're currently relaying the most bytes for.
//! Nebula/Tailscale/ZeroTier all dial-on-first-packet
//! (`docs/design/autoconnect-survey.md`); this is the same idea on a
//! 5-second EWMA instead of per-packet.
//!
//! Hysteresis: add at `relay_rate > RELAY_HI`, drop at `tx_rate <
//! RELAY_LO`. The drop test keys on `tx_rate` (any path), not
//! `relay_rate` — once the shortcut connects, `relay_rate→0` by
//! construction (the PACKET 17 short-circuit fires before
//! `send_sptps_data_relay`); `tx_rate` stays >0 while traffic flows.
//! That, plus a per-node `BACKOFF` after drop, is the oscillation
//! damper.
//!
//! No config knobs: `tools/autoconnect-sim` shows the Pareto front is
//! shallow (every `d_shortcut>0` cell meets all targets) so there is
//! no trade-off a user could meaningfully tune. See [`ShortcutKnobs`]
//! for how the constants were derived. `AutoConnect=no` is the
//! off-switch.
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
//! fine.

#![forbid(unsafe_code)]

use std::time::Instant;

use rand_core::RngCore;

use crate::outgoing::OutOrigin;

/// What `do_autoconnect` decided. The daemon executes.
#[derive(Debug, PartialEq, Eq)]
pub enum AutoAction {
    /// `<D_LO` (`make_new_connection`), shortcut-add, or
    /// `connect_to_unreachable`. Daemon: build `Outgoing` with the
    /// given `origin`, `setup_outgoing_connection`.
    Connect { name: String, origin: OutOrigin },
    /// `>D_HI` superfluous, or idle shortcut. Drop this outgoing +
    /// terminate its conn. `origin` echoed back so the daemon can
    /// stamp `last_auto_dropped` only for shortcuts.
    Disconnect { name: String, origin: OutOrigin },
    /// Cancel a between-retries pending outgoing.
    ///
    /// **`ConnectTo`-seeded slots are NOT exempt.** This matches
    /// upstream `drop_superfluous_pending_connections` (`autoconnect.c
    /// :150-168`), which walks the whole `outgoing_list` and deletes
    /// any entry lacking a `connection_t` — it does not check whether
    /// the slot came from `ConnectTo` or from autoconnect. Once we hit
    /// ≥3 active conns, a `ConnectTo` target that is currently
    /// unreachable stops being retried until SIGHUP re-reads the
    /// config. SIGALRM (`retry()`) only resets backoff on *existing*
    /// slots, so it does not resurrect the entry either. Intentional
    /// upstream behaviour, not a port bug; `OutOrigin` is now plumbed
    /// so this can be tightened later if desired.
    CancelPending { name: String },
    /// Nothing to do this tick.
    Noop,
}

/// Snapshot of one node's state. The daemon builds this from `Graph`
/// + `nodes` + `dp.tunnels` + `conns`.
///
/// ## `has_address`
///
/// Upstream sets it in `load_all_nodes()`: walk `hosts/`, for each
/// file with `Address =`, set the bit. **For this module: just a
/// `bool`. How the daemon populates it is the daemon's problem.**
///
/// ## `edge_count` is per-node, not per-connection
///
/// The *peer's* edge count from the gossiped graph. Dropping our conn
/// to a peer with `edge_count < 2` would isolate it.
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub name: String,
    /// `n->status.reachable`. From sssp.
    pub reachable: bool,
    /// We have a `hosts/` file with `Address =` for this node.
    pub has_address: bool,
    /// We have a direct meta conn (inbound OR outbound).
    pub directly_connected: bool,
    /// How many edges this node has in the gossiped graph.
    pub edge_count: usize,
    /// EWMA bytes/s we ORIGINATED for this node that left via a relay.
    /// 0 once a direct path exists (PACKET 17 short-circuit).
    pub relay_rate_bps: u64,
    /// EWMA bytes/s sent TO this node, any path. The shortcut drop
    /// test keys on this (see module doc).
    pub tx_rate_bps: u64,
    /// Don't re-add as a shortcut before this. Set on
    /// `Disconnect{AutoShortcut}` / `CancelPending` of a shortcut.
    pub backoff_until: Option<Instant>,
}

/// One outgoing slot: either past-ACK active (`c->edge &&
/// c->outgoing`) or pending-retry. Carries provenance so the drop arm
/// can tell shortcut from backbone and the add arm can count toward
/// the `d_shortcut` cap.
#[derive(Debug, Clone)]
pub struct OutgoingSnapshot {
    pub name: String,
    pub origin: OutOrigin,
}

/// Tunables. NOT user-configurable — the struct exists so unit tests
/// can isolate the upstream branches (`d_shortcut=0`) and probe band
/// edges. The daemon always passes [`ShortcutKnobs::default`].
///
/// ## How the defaults were computed
///
/// `tools/autoconnect-sim` runs a discrete-time model of [`decide`]
/// over N∈{30,100,300} nodes × P(UDP-broken)∈{0.05,0.2,0.5} × Zipf
/// ON/OFF traffic, 20 seeds, 1h sim, 1305 parameter cells. Full
/// Pareto table and sensitivity analysis in
/// `tools/autoconnect-sim/REPORT.md`. Summary:
///
/// | knob       | value | why                                         |
/// | ---------- | ----- | ------------------------------------------- |
/// | `D_LO`     | 3     | Bollobás 1981: min k for a.a.s. k-connected random regular |
/// | `D_SHORTCUT`| 2    | 1 strands the 2nd-hottest pair; 3 buys ≤4% hops for +6% flood |
/// | `D_HI`     | 6     | 1.22× flood vs 1.28× at 7; meets ≤1.2× target |
/// | `RELAY_HI` | 32 KiB/s | conv 2.2 vs 3.0 ticks at 64k; osc still <0.005/min/node |
/// | `RELAY_LO` | 4 KiB/s  | keep 8× ratio; flat sensitivity        |
/// | `BACKOFF`  | 60 s  | flat 30..120; matches gossipsub PRUNE-backoff |
/// | `α` (EWMA) | 0.3   | flat 0.2..0.5; τ≈15s at the 5s tick     |
///
/// Worst-case oscillation across the entire sweep is 0.012
/// changes/min/node (target was ≤0.2); convergence to 1-hop is 2.2
/// ticks (~11s, target ≤30s). The Pareto front is shallow — every
/// `d_shortcut>0` cell meets all targets — so there is no user-facing
/// trade-off worth a config knob. `AutoConnect=no` is the off-switch.
///
/// The sim also surfaces the one limit no knob can fix: shortcuts can
/// only dial peers with `has_address`, so a NAT-ed hot destination
/// stays multi-hop. Mitigated in practice by the reverse flow
/// triggering a dial-back from the NAT-ed side.
#[derive(Debug, Clone, Copy)]
pub struct ShortcutKnobs {
    pub d_lo: usize,
    pub d_shortcut: usize,
    pub d_hi: usize,
    pub relay_hi_bps: u64,
    pub relay_lo_bps: u64,
}

/// Don't re-add a peer as a shortcut for this long after dropping it.
/// Belt-and-braces (the `tx_rate`-keyed drop test already prevents
/// flap); sim shows flat sensitivity 30..120s.
pub const SHORTCUT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

impl Default for ShortcutKnobs {
    fn default() -> Self {
        Self {
            d_lo: 3,
            d_shortcut: 2,
            d_hi: 6,
            relay_hi_bps: 32 << 10,
            relay_lo_bps: 4 << 10,
        }
    }
}

/// `do_autoconnect`.
///
/// # Arguments
///
/// - `myself_name` — skip `n == myself`.
/// - `nodes` — ALL known nodes, including indirect/unreachable. May
///   include `myself` (filtered). Order matters for
///   `connect_to_unreachable` index-picking (the daemon sorts by
///   name, matching C's splay tree).
/// - `active_outgoing_conns` — OUTGOING conns past-ACK. Inbound conns
///   are someone else's choice; we don't unilaterally close them.
/// - `pending_outgoings` — `Outgoing` slots with NO live conn
///   (between retries or pre-ACK).
/// - `now` — for `backoff_until` comparison only.
///
/// # The `connect_to_unreachable` back-off
///
/// `prng(node_tree.count)` — randomizes over ALL nodes, **including
/// ineligible ones**. If `r` lands on an ineligible node, immediate
/// `Noop`. THIS IS THE FEATURE: P(connect) =
/// `count_eligible_unreachable / count_all_nodes`. Don't "fix" by
/// filtering first.
///
/// # `make_new_connection` already-pending → `Noop`
///
/// If the random pick is already in `pending_outgoings`, return
/// `Noop` (don't duplicate, don't re-roll).
#[allow(clippy::too_many_arguments)] // pure fn: every input is explicit world-state
#[must_use]
pub fn decide(
    myself_name: &str,
    nodes: &[NodeSnapshot],
    active_outgoing_conns: &[OutgoingSnapshot],
    pending_outgoings: &[OutgoingSnapshot],
    knobs: &ShortcutKnobs,
    now: Instant,
    rng: &mut impl RngCore,
) -> AutoAction {
    // C :174-179. Count ALL active meta conns (c->edge != NULL),
    // inbound + outbound.
    let nc = nodes
        .iter()
        .filter(|n| n.directly_connected && n.name != myself_name)
        .count();

    // C :183-186. < D_LO → eagerly make a new one. EARLY RETURN.
    if nc < knobs.d_lo {
        return make_new_connection(myself_name, nodes, pending_outgoings, rng);
    }

    // ─── shortcut add ────────────────────────────────────────────
    // `max_by` (not random): the heaviest relay is the one most
    // worth collapsing; ties broken by name for determinism. Count
    // active+pending shortcut slots toward the cap so a 3rd hot peer
    // doesn't get a slot while two are already (being) dialled.
    let n_sc = active_outgoing_conns
        .iter()
        .chain(pending_outgoings)
        .filter(|o| o.origin == OutOrigin::AutoShortcut)
        .count();
    if n_sc < knobs.d_shortcut && nc < knobs.d_hi {
        let cand = nodes
            .iter()
            .filter(|n| {
                n.name != myself_name
                    && !n.directly_connected
                    && n.has_address
                    && n.relay_rate_bps > knobs.relay_hi_bps
                    && n.backoff_until.is_none_or(|t| now >= t)
                    && !pending_outgoings.iter().any(|p| p.name == n.name)
            })
            .max_by(|a, b| {
                a.relay_rate_bps
                    .cmp(&b.relay_rate_bps)
                    .then_with(|| a.name.cmp(&b.name))
            });
        if let Some(n) = cand {
            return AutoAction::Connect {
                name: n.name.clone(),
                origin: OutOrigin::AutoShortcut,
            };
        }
    }

    // ─── drop ────────────────────────────────────────────────────
    // C :188-190. > D_HI → drop a superfluous outgoing. UNCHANGED
    // rule (random, edge_count>=2).
    if nc > knobs.d_hi {
        let act = drop_superfluous_outgoing(nodes, active_outgoing_conns, rng);
        if act != AutoAction::Noop {
            return act;
        }
    }

    // Idle shortcut reap. Only fires inside (D_LO, D_HI] — at D_LO
    // we'd rather keep the slot (it counts toward the resilience
    // floor too). Judge by tx_rate (any path), NOT relay_rate.
    if nc > knobs.d_lo {
        let idle: Vec<&OutgoingSnapshot> = active_outgoing_conns
            .iter()
            .filter(|o| {
                o.origin == OutOrigin::AutoShortcut
                    && nodes
                        .iter()
                        .find(|n| n.name == o.name)
                        .is_some_and(|n| n.edge_count >= 2 && n.tx_rate_bps < knobs.relay_lo_bps)
            })
            .collect();
        if !idle.is_empty() {
            #[allow(clippy::cast_possible_truncation)] // ≤ conn count
            let r = (rng.next_u32() % (idle.len() as u32)) as usize;
            return AutoAction::Disconnect {
                name: idle[r].name.clone(),
                origin: OutOrigin::AutoShortcut,
            };
        }
    }

    // C :194. nc >= D_LO. Cancel pending outgoings. Exempt shortcut
    // slots: at nc==D_LO the previous tick may have just returned
    // Connect{AutoShortcut}; the new slot is pending until the TCP
    // handshake completes, and cancelling it here would loop.
    // ConfigConnectTo slots are still cancellable — that's
    // intentional upstream parity, see [`AutoAction::CancelPending`].
    if let Some(p) = pending_outgoings
        .iter()
        .find(|p| p.origin != OutOrigin::AutoShortcut)
    {
        return AutoAction::CancelPending {
            name: p.name.clone(),
        };
    }

    // C :196. Heal partitions. Fires even at nc == D_LO.
    connect_to_unreachable(myself_name, nodes, pending_outgoings, rng)
}

/// `make_new_connection`.
///
/// Eligible: not myself, not directly connected, AND
/// `(has_address || reachable)`. The reachable-but-no-address case:
/// the address can come from a learned `via` edge.
///
/// C does count-then-re-walk (splay tree gives no random access). We
/// collect+index. Same distribution.
fn make_new_connection(
    myself_name: &str,
    nodes: &[NodeSnapshot],
    pending_outgoings: &[OutgoingSnapshot],
    rng: &mut impl RngCore,
) -> AutoAction {
    let eligible: Vec<&NodeSnapshot> = nodes
        .iter()
        .filter(|n| {
            n.name != myself_name && !n.directly_connected && (n.has_address || n.reachable)
        })
        .collect();

    if eligible.is_empty() {
        // C :41-43. The `< 3` branch is `return`, so step 4 does NOT
        // fire. Mirror: Noop.
        return AutoAction::Noop;
    }

    #[allow(clippy::cast_possible_truncation)] // eligible.len() ≤ node count (~thousands)
    let r = (rng.next_u32() % (eligible.len() as u32)) as usize;
    let pick = eligible[r];

    // C :59-71. Already pending? `break` — don't duplicate, don't
    // re-roll. Noop this tick.
    if pending_outgoings.iter().any(|p| p.name == pick.name) {
        return AutoAction::Noop;
    }

    AutoAction::Connect {
        name: pick.name.clone(),
        origin: OutOrigin::AutoBackbone,
    }
}

/// `connect_to_unreachable`. **The all-node prng is the back-off.**
fn connect_to_unreachable(
    myself_name: &str,
    nodes: &[NodeSnapshot],
    pending_outgoings: &[OutgoingSnapshot],
    rng: &mut impl RngCore,
) -> AutoAction {
    if nodes.is_empty() {
        return AutoAction::Noop;
    }

    #[allow(clippy::cast_possible_truncation)] // nodes.len() bounded by node count (≪ u32::MAX)
    let r = (rng.next_u32() % (nodes.len() as u32)) as usize;
    let n = &nodes[r];

    // Ineligible → return. NOT continue. THIS is the back-off.
    if n.name == myself_name || n.directly_connected || n.reachable || !n.has_address {
        return AutoAction::Noop;
    }
    if pending_outgoings.iter().any(|p| p.name == n.name) {
        return AutoAction::Noop;
    }

    AutoAction::Connect {
        name: n.name.clone(),
        origin: OutOrigin::AutoBackbone,
    }
}

/// `drop_superfluous_outgoing_connection`. Only OUTGOING + multi-homed.
fn drop_superfluous_outgoing(
    nodes: &[NodeSnapshot],
    active_outgoing_conns: &[OutgoingSnapshot],
    rng: &mut impl RngCore,
) -> AutoAction {
    let droppable: Vec<&OutgoingSnapshot> = active_outgoing_conns
        .iter()
        .filter(|o| {
            nodes
                .iter()
                .find(|n| n.name == o.name)
                .is_some_and(|n| n.edge_count >= 2)
        })
        .collect();

    if droppable.is_empty() {
        return AutoAction::Noop;
    }

    #[allow(clippy::cast_possible_truncation)] // droppable.len() ≤ conn count
    let r = (rng.next_u32() % (droppable.len() as u32)) as usize;
    AutoAction::Disconnect {
        name: droppable[r].name.clone(),
        origin: droppable[r].origin,
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
            relay_rate_bps: 0,
            tx_rate_bps: 0,
            backoff_until: None,
        }
    }

    fn out(name: &str, origin: OutOrigin) -> OutgoingSnapshot {
        OutgoingSnapshot {
            name: name.into(),
            origin,
        }
    }

    fn outs(names: &[&str]) -> Vec<OutgoingSnapshot> {
        names
            .iter()
            .map(|n| out(n, OutOrigin::AutoBackbone))
            .collect()
    }

    /// Legacy = `d_shortcut=0` so the shortcut-add and idle-drop arms
    /// are dead and the four C branches run unmodified. Not
    /// config-reachable; kept so the upstream-ported tests below stay
    /// independent of the new layer.
    const LEGACY: ShortcutKnobs = ShortcutKnobs {
        d_lo: 3,
        d_shortcut: 0,
        d_hi: 3,
        relay_hi_bps: 32 << 10,
        relay_lo_bps: 4 << 10,
    };

    fn legacy_decide(
        myself: &str,
        nodes: &[NodeSnapshot],
        outgoing: &[OutgoingSnapshot],
        pending: &[OutgoingSnapshot],
        rng: &mut impl RngCore,
    ) -> AutoAction {
        decide(
            myself,
            nodes,
            outgoing,
            pending,
            &LEGACY,
            Instant::now(),
            rng,
        )
    }

    // ═══════════════════════ legacy behaviour ════════════════════

    /// Exactly 3 conns, no pending, no unreachable → Noop.
    #[test]
    fn noop_at_exactly_3() {
        let nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
        ];
        for seed in 0..20 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = legacy_decide("me", &nodes, &outs(&["a", "b", "c"]), &[], &mut rng);
            assert_eq!(act, AutoAction::Noop, "seed {seed}");
        }
    }

    /// 1 active conn, 5 eligible candidates. Must pick one of them.
    #[test]
    fn connect_when_under_3() {
        let nodes = vec![
            node("me", true, true, false, 1),
            node("conn", true, true, true, 2),
            node("e1", true, true, false, 1),
            node("e2", true, true, false, 1),
            node("e3", false, true, false, 0),
            node("e4", true, false, false, 1), // reachable, no addr — still eligible
            node("e5", true, true, false, 1),
        ];
        for seed in 0..20 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            match legacy_decide("me", &nodes, &outs(&["conn"]), &[], &mut rng) {
                AutoAction::Connect { name, origin } => {
                    assert!(
                        ["e1", "e2", "e3", "e4", "e5"].contains(&name.as_str()),
                        "seed {seed}"
                    );
                    assert_eq!(origin, OutOrigin::AutoBackbone);
                }
                other => panic!("seed {seed}: expected Connect, got {other:?}"),
            }
        }
    }

    /// Under 3, nobody eligible → Noop (and DOES early-return).
    #[test]
    fn connect_skips_ineligible() {
        let nodes = vec![
            node("me", true, true, false, 1),
            node("conn", true, true, true, 2),
            node("ghost", false, false, false, 0),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = legacy_decide("me", &nodes, &outs(&["conn"]), &[], &mut rng);
        assert_eq!(act, AutoAction::Noop);
    }

    /// Under 3, only eligible is already pending → Noop.
    #[test]
    fn connect_skips_already_pending() {
        let nodes = vec![
            node("me", true, true, false, 0),
            node("only", false, true, false, 0),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = legacy_decide("me", &nodes, &[], &outs(&["only"]), &mut rng);
        assert_eq!(act, AutoAction::Noop);
    }

    /// 5 active outgoing, all multi-homed → `Disconnect` one.
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
        let outgoing = outs(&["a", "b", "c", "d", "e"]);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let act = legacy_decide("me", &nodes, &outgoing, &[], &mut rng);
        match act {
            AutoAction::Disconnect { name, .. } => {
                assert!(outgoing.iter().any(|o| o.name == name));
            }
            other => panic!("expected Disconnect, got {other:?}"),
        }
    }

    /// Over 3, every peer single-homed → can't drop → Noop.
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
        let outgoing = outs(&["a", "b", "c", "d", "e"]);
        for seed in 0..10 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = legacy_decide("me", &nodes, &outgoing, &[], &mut rng);
            assert_eq!(act, AutoAction::Noop, "seed {seed}");
        }
    }

    /// 4 active (over 3), all single-homed, 2 pending → `CancelPending`.
    #[test]
    fn cancel_pending_when_over_3() {
        let nodes = vec![
            node("me", true, true, false, 4),
            node("a", true, true, true, 1),
            node("b", true, true, true, 1),
            node("c", true, true, true, 1),
            node("d", true, true, true, 1),
        ];
        let outgoing = outs(&["a", "b", "c", "d"]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = legacy_decide("me", &nodes, &outgoing, &outs(&["p1", "p2"]), &mut rng);
        assert_eq!(act, AutoAction::CancelPending { name: "p1".into() });
    }

    /// 100 nodes, 1 unreachable. P(connect) = 1/100 per tick.
    #[test]
    fn connect_unreachable_backoff_low_prob() {
        let mut nodes = vec![node("me", true, true, false, 3)];
        for name in ["c1", "c2", "c3"] {
            nodes.push(node(name, true, true, true, 2));
        }
        for i in 0..95 {
            nodes.push(node(&format!("fill{i}"), true, false, false, 1));
        }
        nodes.push(node("dark", false, true, false, 0));
        assert_eq!(nodes.len(), 100);

        let outgoing = outs(&["c1", "c2", "c3"]);
        let mut hits = 0;
        for seed in 0..1000 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            if legacy_decide("me", &nodes, &outgoing, &[], &mut rng)
                == (AutoAction::Connect {
                    name: "dark".into(),
                    origin: OutOrigin::AutoBackbone,
                })
            {
                hits += 1;
            }
        }
        assert!(
            (5..20).contains(&hits),
            "expected ~10 hits (1% of 1000), got {hits}"
        );
    }

    /// 20 nodes, 16 unreachable. P(connect) = 80%.
    #[test]
    fn connect_unreachable_backoff_high_prob() {
        let mut nodes = vec![node("me", true, true, false, 3)];
        for name in ["c1", "c2", "c3"] {
            nodes.push(node(name, true, true, true, 2));
        }
        for i in 0..16 {
            nodes.push(node(&format!("dark{i}"), false, true, false, 0));
        }
        assert_eq!(nodes.len(), 20);

        let outgoing = outs(&["c1", "c2", "c3"]);
        let mut hits = 0;
        for seed in 0..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            if let AutoAction::Connect { .. } =
                legacy_decide("me", &nodes, &outgoing, &[], &mut rng)
            {
                hits += 1;
            }
        }
        assert!(hits > 60, "expected ~80 hits (80% of 100), got {hits}");
    }

    #[test]
    fn myself_never_picked() {
        let nodes = vec![node("me", true, true, false, 0)];
        for seed in 0..50 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = legacy_decide("me", &nodes, &[], &[], &mut rng);
            assert_eq!(act, AutoAction::Noop, "seed {seed}");
        }
    }

    #[test]
    fn cancel_pending_at_exactly_3() {
        let nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = legacy_decide(
            "me",
            &nodes,
            &outs(&["a", "b", "c"]),
            &outs(&["stale"]),
            &mut rng,
        );
        assert_eq!(
            act,
            AutoAction::CancelPending {
                name: "stale".into()
            }
        );
    }

    /// Inbound conn never picked for Disconnect.
    #[test]
    fn disconnect_never_picks_inbound() {
        let nodes = vec![
            node("me", true, true, false, 5),
            node("out1", true, true, true, 3),
            node("out2", true, true, true, 3),
            node("out3", true, true, true, 3),
            node("out4", true, true, true, 3),
            node("in1", true, true, true, 3), // NOT in outgoing
        ];
        let outgoing = outs(&["out1", "out2", "out3", "out4"]);
        for seed in 0..50 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            match legacy_decide("me", &nodes, &outgoing, &[], &mut rng) {
                AutoAction::Disconnect { name, .. } => {
                    assert_ne!(name, "in1", "seed {seed}: dropped inbound");
                }
                other => panic!("seed {seed}: expected Disconnect, got {other:?}"),
            }
        }
    }

    // ═══════════════════════ shortcut behaviour ══════════════════

    fn dflt(
        myself: &str,
        nodes: &[NodeSnapshot],
        outgoing: &[OutgoingSnapshot],
        pending: &[OutgoingSnapshot],
        rng: &mut impl RngCore,
    ) -> AutoAction {
        decide(
            myself,
            nodes,
            outgoing,
            pending,
            &ShortcutKnobs::default(),
            Instant::now(),
            rng,
        )
    }

    /// Core scenario: nc=3, one not-connected peer relaying 100 KiB/s
    /// → `Connect{that, AutoShortcut}`.
    #[test]
    fn shortcut_added_at_nc3_when_relaying() {
        let mut nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
            node("hot", true, true, false, 2),
        ];
        nodes[4].relay_rate_bps = 100_000;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = dflt("me", &nodes, &outs(&["a", "b", "c"]), &[], &mut rng);
        assert_eq!(
            act,
            AutoAction::Connect {
                name: "hot".into(),
                origin: OutOrigin::AutoShortcut
            }
        );
    }

    /// nc=6 (== `D_HI`), hot relay peer → falls through (NOT `Connect`).
    #[test]
    fn shortcut_not_added_past_d_hi() {
        let mut nodes = vec![node("me", true, true, false, 6)];
        for n in ["a", "b", "c", "d", "e", "f"] {
            nodes.push(node(n, true, true, true, 2));
        }
        let mut hot = node("hot", true, true, false, 2);
        hot.relay_rate_bps = 100_000;
        nodes.push(hot);
        let outgoing = outs(&["a", "b", "c", "d", "e", "f"]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = dflt("me", &nodes, &outgoing, &[], &mut rng);
        // nc==D_HI: shortcut-add gated (`nc < D_HI`), drop gated
        // (`nc > D_HI`), no idle shortcuts, no pending → Noop (or
        // unreachable miss).
        assert!(
            !matches!(act, AutoAction::Connect { .. }),
            "must not add shortcut at nc==D_HI; got {act:?}"
        );
    }

    /// nc=5, one `AutoShortcut` outgoing with `tx_rate`=2 KiB/s →
    /// `Disconnect{it}`.
    #[test]
    fn shortcut_dropped_when_idle() {
        let mut nodes = vec![
            node("me", true, true, false, 5),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
            node("d", true, true, true, 2),
            node("sc", true, true, true, 2),
        ];
        nodes[5].tx_rate_bps = 2_000; // < RELAY_LO
        let outgoing = vec![
            out("a", OutOrigin::AutoBackbone),
            out("b", OutOrigin::AutoBackbone),
            out("c", OutOrigin::AutoBackbone),
            out("d", OutOrigin::AutoBackbone),
            out("sc", OutOrigin::AutoShortcut),
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = dflt("me", &nodes, &outgoing, &[], &mut rng);
        assert_eq!(
            act,
            AutoAction::Disconnect {
                name: "sc".into(),
                origin: OutOrigin::AutoShortcut
            }
        );
    }

    /// Same as above but `tx_rate`=100 KiB/s, `relay_rate`=0 → NOT
    /// disconnected. THIS is the oscillation damper: once direct,
    /// `relay_rate` is 0 by construction; `tx_rate` keeps the slot.
    #[test]
    fn shortcut_kept_while_tx_hot() {
        let mut nodes = vec![
            node("me", true, true, false, 5),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
            node("d", true, true, true, 2),
            node("sc", true, true, true, 2),
        ];
        nodes[5].tx_rate_bps = 100_000;
        nodes[5].relay_rate_bps = 0;
        let outgoing = vec![
            out("a", OutOrigin::AutoBackbone),
            out("b", OutOrigin::AutoBackbone),
            out("c", OutOrigin::AutoBackbone),
            out("d", OutOrigin::AutoBackbone),
            out("sc", OutOrigin::AutoShortcut),
        ];
        for seed in 0..20 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = dflt("me", &nodes, &outgoing, &[], &mut rng);
            assert!(
                !matches!(
                    act,
                    AutoAction::Disconnect {
                        origin: OutOrigin::AutoShortcut,
                        ..
                    }
                ),
                "seed {seed}: dropped a hot shortcut: {act:?}"
            );
        }
    }

    /// Hot relay peer with `backoff_until` in the future → NOT connected.
    #[test]
    fn backoff_respected() {
        let now = Instant::now();
        let mut nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
            node("hot", true, true, false, 2),
        ];
        nodes[4].relay_rate_bps = 100_000;
        nodes[4].backoff_until = Some(now + std::time::Duration::from_secs(30));
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let act = decide(
            "me",
            &nodes,
            &outs(&["a", "b", "c"]),
            &[],
            &ShortcutKnobs::default(),
            now,
            &mut rng,
        );
        assert!(
            !matches!(
                act,
                AutoAction::Connect {
                    origin: OutOrigin::AutoShortcut,
                    ..
                }
            ),
            "must respect backoff; got {act:?}"
        );
    }

    /// nc=3, one pending `AutoShortcut` still handshaking → NOT
    /// `CancelPending`. Regression: unfiltered `first()` would cancel
    /// the slot the previous tick just added and loop.
    #[test]
    fn pending_shortcut_not_cancelled() {
        let mut nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
            node("hot", true, true, false, 2),
        ];
        nodes[4].relay_rate_bps = 100_000;
        let pending = vec![out("hot", OutOrigin::AutoShortcut)];
        for seed in 0..20 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = dflt("me", &nodes, &outs(&["a", "b", "c"]), &pending, &mut rng);
            assert_eq!(act, AutoAction::Noop, "seed {seed}: {act:?}");
        }
    }

    /// nc=3, three hot peers, 2 shortcut slots already dialling →
    /// NOT `Connect{AutoShortcut}`. The cap is `D_SHORTCUT`, not
    /// `D_HI`.
    #[test]
    fn shortcut_cap_enforced() {
        let mut nodes = vec![
            node("me", true, true, false, 3),
            node("a", true, true, true, 2),
            node("b", true, true, true, 2),
            node("c", true, true, true, 2),
        ];
        for h in ["hot1", "hot2", "hot3"] {
            let mut n = node(h, true, true, false, 2);
            n.relay_rate_bps = 100_000;
            nodes.push(n);
        }
        // 2 shortcuts already in flight (1 active, 1 pending).
        let active = vec![
            out("a", OutOrigin::AutoBackbone),
            out("b", OutOrigin::AutoBackbone),
            out("c", OutOrigin::AutoBackbone),
            out("hot1", OutOrigin::AutoShortcut),
        ];
        let pending = vec![out("hot2", OutOrigin::AutoShortcut)];
        // hot1 directly_connected so it's not re-picked anyway.
        nodes[4].directly_connected = true;
        for seed in 0..20 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let act = dflt("me", &nodes, &active, &pending, &mut rng);
            assert!(
                !matches!(
                    act,
                    AutoAction::Connect {
                        origin: OutOrigin::AutoShortcut,
                        ..
                    }
                ),
                "seed {seed}: D_SHORTCUT cap breached: {act:?}"
            );
        }
    }

    /// Open question 5 from the theory doc: at nc∈[`D_LO`,`D_HI`] with no
    /// shortcut candidate, `connect_to_unreachable` still fires.
    #[test]
    fn connect_to_unreachable_still_reachable() {
        let mut nodes = vec![node("me", true, true, false, 4)];
        for n in ["a", "b", "c", "d"] {
            nodes.push(node(n, true, true, true, 2));
        }
        // No relay traffic anywhere (no shortcut candidate). 6
        // unreachable → P(hit)=6/11≈55%.
        for i in 0..6 {
            nodes.push(node(&format!("dark{i}"), false, true, false, 0));
        }
        let outgoing = outs(&["a", "b", "c", "d"]);
        let mut hits = 0;
        for seed in 0..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            if let AutoAction::Connect {
                origin: OutOrigin::AutoBackbone,
                ..
            } = dflt("me", &nodes, &outgoing, &[], &mut rng)
            {
                hits += 1;
            }
        }
        assert!(
            hits > 30,
            "partition-heal must still fire inside the band; got {hits}"
        );
    }
}
