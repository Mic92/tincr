#!/usr/bin/env python3
"""Parameter sweep driver for sim.py.

Runs the grid from the task spec across seeds with multiprocessing,
aggregates each cell to mean±std, writes results.csv.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import multiprocessing as mp
import sys
from collections.abc import Iterator

import numpy as np

import sim


def cells(ns: list[int], p_brokens: list[float]) -> Iterator[dict[str, float]]:
    relay_hi = [8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10]
    lo_div = [4, 8, 16]
    backoff = [15.0, 30.0, 60.0, 120.0]
    alpha = [0.1, 0.2, 0.3, 0.5]
    d_sc = [1, 2, 3, 4]
    d_hi_slack = [0, 1, 2, 3]
    d_lo = 3
    for n, pb, rh, ld, bo, al, ds, sl in itertools.product(
        ns, p_brokens, relay_hi, lo_div, backoff, alpha, d_sc, d_hi_slack
    ):
        yield {
            "n": n,
            "p_broken": pb,
            "d_lo": d_lo,
            "d_shortcut": ds,
            "d_hi": d_lo + ds + sl,
            "relay_hi": float(rh),
            "relay_lo": float(rh) / ld,
            "backoff": bo,
            "alpha": al,
        }
    # Baselines (d_shortcut=0) per (n, pb)
    for n, pb in itertools.product(ns, p_brokens):
        yield {
            "n": n,
            "p_broken": pb,
            "d_lo": d_lo,
            "d_shortcut": 0,
            "d_hi": d_lo,
            "relay_hi": 64 * 1024.0,
            "relay_lo": 8 * 1024.0,
            "backoff": 60.0,
            "alpha": 0.3,
        }


def _job(args: tuple[dict[str, float], int, float]) -> dict[str, float]:
    cell, seed, sim_time = args
    knobs = sim.Knobs(
        d_lo=int(cell["d_lo"]),
        d_shortcut=int(cell["d_shortcut"]),
        d_hi=int(cell["d_hi"]),
        relay_hi=cell["relay_hi"],
        relay_lo=cell["relay_lo"],
        backoff=cell["backoff"],
        alpha=cell["alpha"],
    )
    world = sim.World(n=int(cell["n"]), p_broken=cell["p_broken"], sim_time=sim_time)
    m = sim.run_one(knobs, world, seed)
    out = dict(cell)
    out["seed"] = seed
    out.update(m.row())
    return out


def aggregate(rows: list[dict[str, float]]) -> dict[str, float]:
    out = dict(rows[0])
    del out["seed"]
    for k in sim.METRIC_KEYS:
        vals = np.array([r[k] for r in rows], dtype=float)
        good = vals[~np.isnan(vals)]
        out[k] = float(np.mean(good)) if good.size else float("nan")
        out[k + "_std"] = float(np.std(good)) if good.size else float("nan")
    out["seeds"] = len(rows)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--sim-time", type=float, default=3600.0)
    ap.add_argument("--n", type=int, nargs="+", default=[100])
    ap.add_argument("--p-broken", type=float, nargs="+", default=[0.2])
    ap.add_argument("--quick", action="store_true", help="coarse grid for smoke test")
    ap.add_argument("--jobs", type=int, default=mp.cpu_count())
    ap.add_argument("-o", "--output", default="results.csv")
    args = ap.parse_args()

    grid = list(cells(args.n, args.p_broken))
    if args.quick:
        # Subsample: keep cells where most knobs are at default-ish.
        grid = [
            c
            for c in grid
            if c["backoff"] in (30.0, 60.0)
            and c["alpha"] in (0.2, 0.3)
            and c["relay_hi"] in (16 << 10, 32 << 10, 64 << 10)
            and c["relay_hi"] / c["relay_lo"] in (4, 8)
            and c["d_shortcut"] in (0, 1, 2, 3)
            and c["d_hi"] - 3 - c["d_shortcut"] in (1, 2)
        ] + [c for c in grid if c["d_shortcut"] == 0]

    jobs = [(c, s, args.sim_time) for c in grid for s in range(args.seeds)]
    print(f"{len(grid)} cells × {args.seeds} seeds = {len(jobs)} runs", file=sys.stderr)

    by_cell: dict[tuple[float, ...], list[dict[str, float]]] = {}
    with mp.Pool(args.jobs) as pool:
        for i, r in enumerate(pool.imap_unordered(_job, jobs, chunksize=4)):
            key = tuple(r[k] for k in sim.PARAM_KEYS if k != "seed")
            by_cell.setdefault(key, []).append(r)
            if i % 200 == 0:
                print(f"  {i}/{len(jobs)}", file=sys.stderr)

    fieldnames = (
        [k for k in sim.PARAM_KEYS if k != "seed"]
        + list(itertools.chain.from_iterable((k, k + "_std") for k in sim.METRIC_KEYS))
        + ["seeds"]
    )
    with open(args.output, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for rows in by_cell.values():
            w.writerow(aggregate(rows))
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
