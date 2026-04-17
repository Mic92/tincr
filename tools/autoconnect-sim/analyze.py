#!/usr/bin/env python3
"""Ad-hoc analysis of results.csv. Prints Pareto front + per-knob
sensitivity. Not part of the deliverables; helper for REPORT.md."""

from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict


def load(path: str) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with open(path) as fh:
        for r in csv.DictReader(fh):
            rows.append(
                {
                    k: float(v) if v not in ("", "nan") else math.nan
                    for k, v in r.items()
                }
            )
    return rows


def main() -> int:
    rows = load(sys.argv[1] if len(sys.argv) > 1 else "results.csv")
    base = {(r["n"], r["p_broken"]): r for r in rows if r["d_shortcut"] == 0}
    print("=== baselines (d_shortcut=0) ===")
    for k, r in sorted(base.items()):
        print(
            f"  n={int(k[0]):3d} pb={k[1]:.2f}  hops={r['relay_hops']:.2f} "
            f"mean_deg={r['mean_deg']:.2f} flood={r['flood_amp']:.2f}"
        )

    # Targets
    def ok(r: dict[str, float]) -> bool:
        return (
            r["d_shortcut"] > 0
            and r["osc_per_node_min"] <= 0.2
            and (math.isnan(r["converge_ticks"]) or r["converge_ticks"] <= 6.0)
            and r["flood_amp"] <= 1.2
            and r["p_deg_over_hi"] <= 0.01
        )

    feas = [r for r in rows if ok(r)]
    print(f"\n=== feasible cells (all targets met): {len(feas)}/{len(rows)} ===")

    # Relax flood_amp to see what's achievable
    for fmax in (1.2, 1.3, 1.5, 2.0):
        cnt = sum(
            1
            for r in rows
            if r["d_shortcut"] > 0
            and r["osc_per_node_min"] <= 0.2
            and r["flood_amp"] <= fmax
        )
        print(f"  flood_amp<={fmax}: {cnt} cells")

    # Focus n=100 pb=0.2, rank by (relay_hops, osc, flood)
    focus = sorted(
        (
            r
            for r in rows
            if r["n"] == 100 and r["p_broken"] == 0.2 and r["d_shortcut"] > 0
        ),
        key=lambda r: (r["flood_amp"], r["osc_per_node_min"]),
    )
    print("\n=== n=100 pb=0.2, sorted by flood_amp ===")
    print(
        f"{'d_sc':>4} {'d_hi':>4} {'r_hi':>7} {'r_lo':>6} {'bo':>4} {'a':>4} | "
        f"{'osc':>6} {'conv':>5} {'flood':>5} {'deg':>5} {'p>hi':>5} {'hops':>5} {'strd':>5}"
    )
    for r in focus[:25]:
        print(
            f"{int(r['d_shortcut']):4d} {int(r['d_hi']):4d} {int(r['relay_hi']):7d} "
            f"{int(r['relay_lo']):6d} {int(r['backoff']):4d} {r['alpha']:4.1f} | "
            f"{r['osc_per_node_min']:6.3f} {r['converge_ticks']:5.1f} "
            f"{r['flood_amp']:5.2f} {r['mean_deg']:5.2f} {r['p_deg_over_hi']:5.2f} "
            f"{r['relay_hops']:5.2f} {r['stranded_frac']:5.2f}"
        )

    # Per-knob sensitivity at n=100 pb=0.2: marginal mean of each metric
    print("\n=== sensitivity (n=100 pb=0.2, marginal means) ===")
    knobs = ["relay_hi", "relay_lo", "backoff", "alpha", "d_shortcut", "d_hi"]
    metrics = [
        "osc_per_node_min",
        "converge_ticks",
        "flood_amp",
        "relay_hops",
        "stranded_frac",
    ]
    sub = [
        r
        for r in rows
        if r["n"] == 100 and r["p_broken"] == 0.2 and r["d_shortcut"] > 0
    ]
    for k in knobs:
        groups: dict[float, list[dict[str, float]]] = defaultdict(list)
        for r in sub:
            groups[r[k]].append(r)
        print(f"  {k}:")
        for v in sorted(groups):
            g = groups[v]
            line = f"    {v:>8.0f}:"
            for m in metrics:
                vals = [x[m] for x in g if not math.isnan(x[m])]
                mean = sum(vals) / len(vals) if vals else math.nan
                line += f" {m[:4]}={mean:6.3f}"
            print(line)

    # Candidate cells across (n,pb)
    def show(tag: str, pred: dict[str, float]) -> None:
        print(f"\n=== {tag} across N,pb ===")
        for r in rows:
            if all(r[k] == v for k, v in pred.items()):
                b = base[(r["n"], r["p_broken"])]
                print(
                    f"  n={int(r['n']):3d} pb={r['p_broken']:.2f}  "
                    f"osc={r['osc_per_node_min']:.4f} conv={r['converge_ticks']:4.1f} "
                    f"flood={r['flood_amp']:.2f}({r['flood_amp'] / b['flood_amp']:.2f}x) "
                    f"deg={r['mean_deg']:.2f} max={r['max_deg']:.0f} "
                    f"p>hi={r['p_deg_over_hi']:.3f} "
                    f"hops={r['relay_hops']:.2f}({r['relay_hops'] / b['relay_hops']:.2f}x) "
                    f"strd={r['stranded_frac']:.2f}"
                )

    show(
        "recommended 32k/4k/60/0.3/2/6",
        {
            "relay_hi": 32768,
            "relay_lo": 4096,
            "backoff": 60,
            "alpha": 0.3,
            "d_shortcut": 2,
            "d_hi": 6,
        },
    )
    show(
        "alt 16k/2k/60/0.3/2/6",
        {
            "relay_hi": 16384,
            "relay_lo": 2048,
            "backoff": 60,
            "alpha": 0.3,
            "d_shortcut": 2,
            "d_hi": 6,
        },
    )

    # Current defaults cell
    print("\n=== current defaults (64k/8k/60/0.3/2/7) across N,pb ===")
    for r in rows:
        if (
            r["relay_hi"] == 65536
            and r["relay_lo"] == 8192
            and r["backoff"] == 60
            and r["alpha"] == 0.3
            and r["d_shortcut"] == 2
            and r["d_hi"] == 7
        ):
            print(
                f"  n={int(r['n']):3d} pb={r['p_broken']:.2f}  osc={r['osc_per_node_min']:.3f} "
                f"conv={r['converge_ticks']:.1f} flood={r['flood_amp']:.2f} "
                f"deg={r['mean_deg']:.2f} p>hi={r['p_deg_over_hi']:.3f} "
                f"hops={r['relay_hops']:.2f} strd={r['stranded_frac']:.2f}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
