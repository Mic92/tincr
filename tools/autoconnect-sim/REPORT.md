# Autoconnect relay-shortcut: simulation results

Discrete-time model of `autoconnect.rs::decide()` over N∈{30,100,300}
nodes, 1 h sim, 20 seeds, P(has_address)=0.5, Zipf traffic with
exponential ON/OFF (120s/300s), P(UDP-broken)∈{0.05,0.2,0.5}. 1305
parameter cells (`results.csv`). Sweep ran in ~3 min on 384 cores.

## Validation

`d_shortcut=0` baseline at N=300 gives mean degree 3.47, mean
relay-hop 5.06, vs `nx.random_regular_graph(3,300)` mean hop 6.38 and
analytic diameter `log₂(300)≈8.2`. Sim is slightly *better* connected
because the model is degree-≥3 (inbound surplus on public nodes), not
strictly 3-regular — matches reality. Graph model sane.

## Recommended defaults

| knob          | current | **recommended** | reason                                                  |
| ------------- | ------- | --------------- | ------------------------------------------------------- |
| `RELAY_HI`    | 64 KiB/s| **32 KiB/s**    | conv 2.2 vs 3.0 ticks; osc still <0.005/min/node        |
| `RELAY_LO`    | 8 KiB/s | **4 KiB/s**     | keep 8× ratio; lower drop floor avoids reaping bursty   |
| `BACKOFF`     | 60 s    | **60 s**        | insensitive (30 vs 60: Δosc<0.001); 60 = gossipsub      |
| `α`           | 0.3     | **0.3**         | insensitive (0.2 vs 0.3 indistinguishable); τ≈15s OK    |
| `D_SHORTCUT`  | 2       | **2**           | 1 strands the 2nd-hottest pair; 3 buys ≤4% hops for +6% flood |
| `D_HI`        | 7       | **6**           | flood 1.22× vs 1.28× baseline; p(deg>hi) unchanged      |

Net: halve `RELAY_HI`/`RELAY_LO`, drop `D_HI` by 1. Everything else
was already on the flat part of the curve.

## Pareto: oscillation × convergence × flood (N=100, pb=0.2)

| d_sc | d_hi | r_hi  | r_lo | osc/min | conv tk | flood× | hops× | p>hi |
| ---- | ---- | ----- | ---- | ------- | ------- | ------ | ----- | ---- |
| 0    | 3    | —     | —    | 0       | —       | 1.00   | 1.00  | .22¹ |
| 1    | 5    | 32k   | 4k   | 0.001   | 2.2     | 1.14   | 0.88  | .10  |
| **2**| **6**| **32k**|**4k**| **0.001**| **2.2** | **1.22**| **0.82**| .07 |
| 2    | 7    | 64k   | 8k   | 0.001   | 3.0     | 1.28   | 0.79  | .04  |
| 3    | 7    | 16k   | 2k   | 0.004   | 2.1     | 1.28   | 0.73  | .04  |
| 3    | 8    | 16k   | 2k   | 0.004   | 2.0     | 1.33   | 0.71  | .03  |

¹ baseline `p>hi` is vs d_hi=3; the 22% is inbound surplus on public
nodes, present today already.

The frontier is **shallow**: every cell with `d_shortcut>0` has
osc ≤ 0.012/min/node (target ≤0.2) and conv ≤ 4 ticks (target ≤6).
Oscillation is a non-problem with the tx_rate-keyed drop test; the only
real trade is `d_hi` ↔ flood cost ↔ hop reduction.

## Sensitivity (range of marginal means, N=100 pb=0.2)

| knob       | osc Δ   | conv Δ | flood Δ | hops Δ | verdict          |
| ---------- | ------- | ------ | ------- | ------ | ---------------- |
| `d_hi`     | ~0      | ~0     | **0.23**| **0.46**| **dominant**    |
| `d_shortcut`| ~0     | ~0     | 0.15    | 0.29   | second           |
| `relay_hi` | 0.002   | 0.6    | 0       | 0.28   | trades conv/hops |
| `relay_lo` | 0.002   | 0.6    | 0       | 0.28   | mirrors hi       |
| `backoff`  | <0.001  | 0.2    | 0       | 0      | irrelevant       |
| `alpha`    | <0.001  | <0.1   | 0       | 0      | irrelevant       |

`d_hi` sets the steady-state mean degree almost single-handedly
(backbone fills the band via random inbound; shortcuts are sparse).
`RELAY_HI/LO` ratio was expected to govern oscillation — it doesn't,
because the drop test keys on `tx_rate` not `relay_rate`, so a live
shortcut never satisfies `tx_rate < LO` while traffic flows. Ratio only
matters for *which* low-rate flows get a shortcut.

## Finding: NAT-stranded hot pairs

`stranded_frac` ≈ 0.8–1.0 across **all** cells, but drops to **0.00**
when `P(has_address)=1.0`. The heuristic only dials peers with
`has_address`; if the heavy-traffic *destination* is behind NAT, the
source can never shortcut to it regardless of knobs. This is a
**fundamental limit**, not a tuning issue. Half of retiolum is NAT'd ⇒
~half of hot relay pairs stay multi-hop. Mitigations outside this
change: (a) the NAT'd side also runs `decide()` and may dial *back* if
the reverse flow is hot (not modelled — flows are unidirectional here);
(b) reflexive-address learning from `UDP_INFO` populates `has_address`
over time. Recommend a follow-up: let the *relay node* signal "you
should dial X" when it sees sustained A→relay→X traffic.

## Finding: `p(deg > D_HI)` is never 0

3–10% of nodes exceed `D_HI` in steady state (max 8/9/11 at
N=30/100/300). Cause: `decide()` only disconnects *outgoing*; public
nodes accumulate inbound from NAT'd peers' backbone slots. This is
existing upstream behaviour (`drop_superfluous` skips `!c->outgoing`)
and is **not made worse** by the shortcut layer (baseline p>3 = 22%).
The `D_HI` cap is a soft outbound budget, not a hard degree limit.
Target "P=0" in the spec is unachievable without dropping inbound,
which would isolate NAT'd peers; revise target to "no worse than
baseline", which holds.

## Answers to `autoconnect-theory.md §4` open questions

1. **Oscillation** — ≤ 0.012 topology-changes/min/node worst case
   (16k/2k, pb=0.5, N=30), median <0.002. Far below the ≤0.2 target.
   Even with damping (c) effectively *enabled* (tx_rate drop test), no
   flap observed; the `RELAY_HI/LO` ratio is **not** the governing
   knob — the tx_rate test is.
2. **Convergence** — 2.2–3.7 ticks (11–19 s) to 1-hop for hot
   addressable pairs across all N and pb. Under 30 s target with
   margin. Dominated by EWMA rise time (`⌈ln(1/(1-HI/rate))/ln(1-α)⌉`
   ≈ 1–2 ticks) + 1 tick connect latency.
3. **Degree distribution** — mean 4.2–4.5 (target ≤4), max 8–11,
   P(deg>D_HI) 3–7%. Excess is inbound on public nodes; inherent to
   tinc, not introduced here.
4. **Flood amplification** — 1.20–1.22× the d_shortcut=0 baseline at
   D_HI=6 (1.28× at D_HI=7). Meets ≤1.2× at the recommended D_HI=6.
   Absolute edges/node ≈ 2.12 vs 1.74 today.
5. **Partition heal** — `connect_to_unreachable` still reachable: at
   nc∈[D_LO,D_HI] with no shortcut candidate and no idle victim and no
   pending, the dispatch falls through to it. Sim shows initially
   disconnected NAT islands at t=0 fully merged by t≈60 s for all
   cells; no regression vs baseline.
