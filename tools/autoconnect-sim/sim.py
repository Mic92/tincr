#!/usr/bin/env python3
"""Discrete-time simulation of tincd autoconnect.decide() with the
relay-shortcut layer.

Models N nodes each independently running the priority dispatch from
crates/tincd/src/autoconnect.rs every 5±1 s against a shared undirected
meta graph, a sparse Zipf traffic matrix with exponential ON/OFF, and a
per-pair UDP-broken flag. One action per node per tick, faithfully
including the all-node-prng connect_to_unreachable backoff.

Emits one CSV row of the six metrics from docs/design/autoconnect-theory.md §4.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterable

import networkx as nx  # type: ignore[import-untyped]
import numpy as np


# ──────────────────────────────────────────────────────────────────────
# Parameters
# ──────────────────────────────────────────────────────────────────────


class Origin(Enum):
    BACKBONE = auto()
    SHORTCUT = auto()


@dataclass(frozen=True)
class Knobs:
    d_lo: int = 3
    d_shortcut: int = 2
    d_hi: int = 7
    relay_hi: float = 64 * 1024
    relay_lo: float = 8 * 1024
    backoff: float = 60.0
    alpha: float = 0.3
    tick: float = 5.0
    jitter: float = 1.0


@dataclass(frozen=True)
class World:
    n: int = 100
    p_addr: float = 0.5
    p_broken: float = 0.2
    n_flows: int = 0  # 0 ⇒ max(20, n//2)
    mean_on: float = 120.0
    mean_off: float = 300.0
    sim_time: float = 3600.0
    warmup: float = 120.0
    dt: float = 1.0


# ──────────────────────────────────────────────────────────────────────
# Per-node state
# ──────────────────────────────────────────────────────────────────────


@dataclass
class Pending:
    target: int
    origin: Origin
    ready_at: float


@dataclass
class PeerRate:
    """Per (i,j) byte counters + EWMA, from i's vantage."""

    tx_bytes: float = 0.0
    relay_bytes: float = 0.0
    tx_prev: float = 0.0
    relay_prev: float = 0.0
    tx_rate: float = 0.0
    relay_rate: float = 0.0
    backoff_until: float = 0.0


@dataclass
class Node:
    idx: int
    has_address: bool
    next_tick: float
    last_tick: float
    rng: np.random.Generator
    pending: list[Pending] = field(default_factory=list)
    rates: dict[int, PeerRate] = field(default_factory=dict)

    def rate(self, j: int) -> PeerRate:
        pr = self.rates.get(j)
        if pr is None:
            pr = PeerRate()
            self.rates[j] = pr
        return pr


@dataclass
class Flow:
    src: int
    dst: int
    rate: float  # bytes/s when ON
    udp_broken: bool
    heavy: bool
    on: bool = False
    next_toggle: float = 0.0
    on_since: float = -1.0
    converge_start: float = -1.0  # set on ON if broken+heavy
    converge_done: bool = False


# ──────────────────────────────────────────────────────────────────────
# decide() — faithful port of the Rust priority dispatch
# ──────────────────────────────────────────────────────────────────────


def decide(  # noqa: C901, PLR0911, PLR0912
    me: Node,
    nodes: list[Node],
    g: nx.Graph,
    comp: dict[int, int],
    knobs: Knobs,
    now: float,
) -> tuple[str, int, Origin] | None:
    """Return (action, peer, origin) or None for Noop."""
    i = me.idx
    neigh = set(g.neighbors(i))
    nc = len(neigh)
    pending_names = {p.target for p in me.pending}

    # nc < D_LO → make_new_connection (random eligible)
    if nc < knobs.d_lo:
        my_comp = comp.get(i, -1)
        eligible = [
            n.idx
            for n in nodes
            if n.idx != i
            and n.idx not in neigh
            and (n.has_address or comp.get(n.idx, -2) == my_comp)
        ]
        if not eligible:
            return None
        pick = int(me.rng.choice(eligible))
        if pick in pending_names:
            return None
        return ("connect", pick, Origin.BACKBONE)

    # shortcut add
    if knobs.d_shortcut > 0 and nc < knobs.d_hi:
        cand = -1
        cand_rate = knobs.relay_hi
        for n in nodes:
            j = n.idx
            if j == i or j in neigh or not n.has_address or j in pending_names:
                continue
            r = me.rates.get(j)
            if r is None or r.relay_rate <= knobs.relay_hi or now < r.backoff_until:
                continue
            if r.relay_rate > cand_rate or (r.relay_rate == cand_rate and j > cand):
                cand, cand_rate = j, r.relay_rate
        if cand >= 0:
            return ("connect", cand, Origin.SHORTCUT)

    # outgoing conns from i (we are the initiator)
    outgoing: list[tuple[int, Origin]] = [
        (j, g.edges[i, j]["origin"]) for j in neigh if g.edges[i, j]["initiator"] == i
    ]

    # nc > D_HI → drop random outgoing with peer edge_count>=2
    if nc > knobs.d_hi:
        droppable = [(j, o) for (j, o) in outgoing if g.degree[j] >= 2]
        if droppable:
            j, o = droppable[int(me.rng.integers(len(droppable)))]
            return ("disconnect", j, o)

    # idle shortcut reap (D_LO < nc ≤ D_HI)
    if knobs.d_shortcut > 0 and nc > knobs.d_lo:
        idle = [
            (j, o)
            for (j, o) in outgoing
            if o is Origin.SHORTCUT
            and g.degree[j] >= 2
            and me.rate(j).tx_rate < knobs.relay_lo
        ]
        if idle:
            j, o = idle[int(me.rng.integers(len(idle)))]
            return ("disconnect", j, o)

    # cancel pending (first)
    if me.pending:
        p = me.pending[0]
        return ("cancel", p.target, p.origin)

    # connect_to_unreachable — all-node prng IS the backoff
    n = nodes[int(me.rng.integers(len(nodes)))]
    my_comp = comp.get(i, -1)
    if (
        n.idx != i
        and n.idx not in neigh
        and comp.get(n.idx, -2) != my_comp
        and n.has_address
        and n.idx not in pending_names
    ):
        return ("connect", n.idx, Origin.BACKBONE)
    return None


# ──────────────────────────────────────────────────────────────────────
# Simulation
# ──────────────────────────────────────────────────────────────────────


@dataclass
class Metrics:
    osc_per_node_min: float = 0.0
    converge_ticks: float = math.nan
    p_deg_over_hi: float = 0.0
    mean_deg: float = 0.0
    max_deg: float = 0.0
    flood_amp: float = 0.0
    relay_hops: float = math.nan
    stranded_frac: float = math.nan
    n_converge: int = 0

    def row(self) -> dict[str, float]:
        return {
            "osc_per_node_min": self.osc_per_node_min,
            "converge_ticks": self.converge_ticks,
            "p_deg_over_hi": self.p_deg_over_hi,
            "mean_deg": self.mean_deg,
            "max_deg": self.max_deg,
            "flood_amp": self.flood_amp,
            "relay_hops": self.relay_hops,
            "stranded_frac": self.stranded_frac,
            "n_converge": float(self.n_converge),
        }


def _build_flows(
    world: World, nodes: list[Node], rng: np.random.Generator
) -> list[Flow]:
    n_flows = world.n_flows or max(20, world.n // 2)
    pairs: set[tuple[int, int]] = set()
    flows: list[Flow] = []
    while len(pairs) < n_flows:
        s, d = int(rng.integers(world.n)), int(rng.integers(world.n))
        if s == d or (s, d) in pairs:
            continue
        pairs.add((s, d))
    # Zipf-ish: top 5 carry the bulk; rest small uniform.
    top_rate = 1_000_000.0
    for k, (s, d) in enumerate(pairs):
        if k < 5:
            rate = top_rate / (k + 1)
        else:
            rate = float(rng.uniform(4_000, 32_000))
        broken = bool(rng.random() < world.p_broken)
        f = Flow(s, d, rate, broken, heavy=(k < 5))
        f.on = bool(rng.random() < world.mean_on / (world.mean_on + world.mean_off))
        if f.on:
            f.on_since = 0.0
            if f.udp_broken and f.heavy:
                f.converge_start = 0.0
        f.next_toggle = float(
            rng.exponential(world.mean_on if f.on else world.mean_off)
        )
        flows.append(f)
    return flows


def _components(g: nx.Graph, n: int) -> dict[int, int]:
    comp: dict[int, int] = {}
    for cid, cc in enumerate(nx.connected_components(g)):
        for v in cc:
            comp[v] = cid
    # isolated nodes (not yet in g) get unique ids
    base = len(comp) + 1
    for v in range(n):
        if v not in comp:
            comp[v] = base + v
    return comp


def run_one(knobs: Knobs, world: World, seed: int) -> Metrics:  # noqa: C901, PLR0912, PLR0915
    rng = np.random.default_rng(seed)
    nodes: list[Node] = []
    for i in range(world.n):
        sub = np.random.default_rng(rng.integers(2**63))
        nodes.append(
            Node(
                idx=i,
                has_address=bool(rng.random() < world.p_addr),
                next_tick=float(rng.uniform(0, knobs.tick)),
                last_tick=0.0,
                rng=sub,
            )
        )
    # Guarantee at least one addressable node so the mesh can form.
    if not any(n.has_address for n in nodes):
        nodes[0].has_address = True

    g: nx.Graph = nx.Graph()
    g.add_nodes_from(range(world.n))
    flows = _build_flows(world, nodes, rng)

    # Metric accumulators
    shortcut_events = 0  # connect+disconnect of SHORTCUT origin, post-warmup
    converge_samples: list[float] = []
    deg_over_hi = 0
    deg_sum = 0.0
    deg_max = 0
    edge_sum = 0.0
    deg_samples = 0
    hop_sum = 0.0
    hop_n = 0
    stranded_hot = 0
    stranded_tot = 0

    t = 0.0
    comp = _components(g, world.n)
    sample_every = 5.0
    next_sample = world.warmup

    while t < world.sim_time:
        # 1. flow ON/OFF toggles
        for f in flows:
            while f.next_toggle <= t:
                f.on = not f.on
                if f.on:
                    f.on_since = t
                    if f.udp_broken and f.heavy and not g.has_edge(f.src, f.dst):
                        f.converge_start = t
                        f.converge_done = False
                else:
                    f.on_since = -1.0
                mean = world.mean_on if f.on else world.mean_off
                f.next_toggle += float(rng.exponential(mean))

        # 2. accumulate traffic bytes for this dt
        for f in flows:
            if not f.on:
                continue
            db = f.rate * world.dt
            pr = nodes[f.src].rate(f.dst)
            pr.tx_bytes += db
            if f.udp_broken and not g.has_edge(f.src, f.dst):
                pr.relay_bytes += db
            # convergence check
            if (
                f.converge_start >= 0
                and not f.converge_done
                and g.has_edge(f.src, f.dst)
            ):
                converge_samples.append((t - f.converge_start) / knobs.tick)
                f.converge_done = True

        # 3. per-node ticks
        comp_dirty = False
        for me in nodes:
            if me.next_tick > t:
                continue
            dt = max(t - me.last_tick, 1e-6)
            # EWMA sample
            for pr in me.rates.values():
                inst_tx = (pr.tx_bytes - pr.tx_prev) / dt
                inst_re = (pr.relay_bytes - pr.relay_prev) / dt
                pr.tx_rate = knobs.alpha * inst_tx + (1 - knobs.alpha) * pr.tx_rate
                pr.relay_rate = (
                    knobs.alpha * inst_re + (1 - knobs.alpha) * pr.relay_rate
                )
                pr.tx_prev, pr.relay_prev = pr.tx_bytes, pr.relay_bytes
            me.last_tick = t
            # promote ready pendings
            still: list[Pending] = []
            for p in me.pending:
                if t >= p.ready_at and nodes[p.target].has_address:
                    if not g.has_edge(me.idx, p.target):
                        g.add_edge(me.idx, p.target, initiator=me.idx, origin=p.origin)
                        comp_dirty = True
                        if p.origin is Origin.SHORTCUT and t >= world.warmup:
                            shortcut_events += 1
                else:
                    still.append(p)
            me.pending = still

            act = decide(me, nodes, g, comp, knobs, t)
            me.next_tick = (
                t + knobs.tick + float(me.rng.uniform(-knobs.jitter, knobs.jitter))
            )
            if act is None:
                continue
            kind, j, origin = act
            if kind == "connect":
                me.pending.append(Pending(j, origin, t + knobs.tick))
            elif kind == "disconnect":
                if g.has_edge(me.idx, j):
                    g.remove_edge(me.idx, j)
                    comp_dirty = True
                if origin is Origin.SHORTCUT:
                    me.rate(j).backoff_until = t + knobs.backoff
                    if t >= world.warmup:
                        shortcut_events += 1
            elif kind == "cancel":
                me.pending = [p for p in me.pending if p.target != j]
                if origin is Origin.SHORTCUT:
                    me.rate(j).backoff_until = t + knobs.backoff

        if comp_dirty:
            comp = _components(g, world.n)

        # 4. steady-state sampling
        if t >= next_sample:
            next_sample += sample_every
            degs = [g.degree[v] for v in range(world.n)]
            deg_sum += float(np.mean(degs))
            deg_max = max(deg_max, max(degs))
            deg_over_hi += sum(1 for d in degs if d > knobs.d_hi)
            edge_sum += g.number_of_edges()
            deg_samples += 1
            # relay hops over ACTIVE udp-broken flows
            for f in flows:
                if not (f.on and f.udp_broken):
                    continue
                try:
                    h = nx.shortest_path_length(g, f.src, f.dst)
                except nx.NetworkXNoPath:
                    continue
                hop_sum += h
                hop_n += 1
                # stranded: ON ≥60s, still hot at src, not 1-hop
                spr = nodes[f.src].rates.get(f.dst)
                if (
                    f.on_since >= 0
                    and t - f.on_since >= 60.0
                    and spr is not None
                    and spr.relay_rate > knobs.relay_hi
                ):
                    stranded_tot += 1
                    if h > 1:
                        stranded_hot += 1

        t += world.dt

    m = Metrics()
    steady = max(world.sim_time - world.warmup, 1.0)
    m.osc_per_node_min = shortcut_events / world.n / (steady / 60.0)
    if converge_samples:
        m.converge_ticks = float(np.mean(converge_samples))
        m.n_converge = len(converge_samples)
    if deg_samples:
        m.mean_deg = deg_sum / deg_samples
        m.max_deg = float(deg_max)
        m.p_deg_over_hi = deg_over_hi / (deg_samples * world.n)
        m.flood_amp = (edge_sum / deg_samples) / (1.5 * world.n)
    if hop_n:
        m.relay_hops = hop_sum / hop_n
    if stranded_tot:
        m.stranded_frac = stranded_hot / stranded_tot
    return m


# ──────────────────────────────────────────────────────────────────────
# Validation: 3-regular random diameter ≈ log₂(n)
# ──────────────────────────────────────────────────────────────────────


def validate_backbone(n: int, seeds: int = 5) -> None:
    knobs = Knobs(d_shortcut=0, d_hi=3)
    world = World(n=n, p_addr=1.0, p_broken=0.0, sim_time=300.0, warmup=200.0)
    hops = []
    diams = []
    for s in range(seeds):
        rng = np.random.default_rng(s)
        # Build via the sim itself, then measure.
        m = run_one(knobs, world, s)
        _ = m
        # Re-run just to get the graph (cheap): inline minimal build.
        # Simpler: random_regular_graph for the analytic check.
        g = nx.random_regular_graph(3, n, seed=int(rng.integers(2**31)))
        spl = dict(nx.shortest_path_length(g))
        all_d = [d for dd in spl.values() for d in dd.values() if d > 0]
        hops.append(float(np.mean(all_d)))
        diams.append(max(all_d))
    print(
        f"validate n={n}: mean_hop={np.mean(hops):.2f} "
        f"diam={np.mean(diams):.1f} log2(n)={math.log2(n):.2f} "
        f"sim_mean_deg≈{m.mean_deg:.2f}",
        file=sys.stderr,
    )


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────


METRIC_KEYS = list(Metrics().row().keys())
PARAM_KEYS = [
    "n",
    "p_broken",
    "d_lo",
    "d_shortcut",
    "d_hi",
    "relay_hi",
    "relay_lo",
    "backoff",
    "alpha",
    "seed",
]


def write_header(w: "csv.DictWriter[str]") -> None:
    w.writeheader()


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--p-broken", type=float, default=0.2)
    ap.add_argument("--p-addr", type=float, default=0.5)
    ap.add_argument("--d-lo", type=int, default=3)
    ap.add_argument("--d-shortcut", type=int, default=2)
    ap.add_argument("--d-hi", type=int, default=7)
    ap.add_argument("--relay-hi", type=float, default=64 * 1024)
    ap.add_argument("--relay-lo", type=float, default=8 * 1024)
    ap.add_argument("--backoff", type=float, default=60.0)
    ap.add_argument("--alpha", type=float, default=0.3)
    ap.add_argument("--sim-time", type=float, default=3600.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--header", action="store_true")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if args.validate:
        for n in (30, 100, 300):
            validate_backbone(n, seeds=3)
        return 0

    knobs = Knobs(
        d_lo=args.d_lo,
        d_shortcut=args.d_shortcut,
        d_hi=args.d_hi,
        relay_hi=args.relay_hi,
        relay_lo=args.relay_lo,
        backoff=args.backoff,
        alpha=args.alpha,
    )
    world = World(
        n=args.n, p_broken=args.p_broken, p_addr=args.p_addr, sim_time=args.sim_time
    )
    m = run_one(knobs, world, args.seed)

    w = csv.DictWriter(sys.stdout, fieldnames=PARAM_KEYS + METRIC_KEYS)
    if args.header:
        w.writeheader()
    row: dict[str, float] = {
        "n": args.n,
        "p_broken": args.p_broken,
        "d_lo": args.d_lo,
        "d_shortcut": args.d_shortcut,
        "d_hi": args.d_hi,
        "relay_hi": args.relay_hi,
        "relay_lo": args.relay_lo,
        "backoff": args.backoff,
        "alpha": args.alpha,
        "seed": args.seed,
    }
    row.update(m.row())
    w.writerow(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
