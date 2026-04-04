# Differential fuzz: Rust vs C, same inputs, compare bytes

The Lean/Alloy proofs verified the *algorithms*. They can't see
transcription bugs — places where Rust does what the comment says, not
what the C does. These harnesses pit both impls against identical
inputs and compare outputs byte-for-byte.

## Targets

| Harness | Rust | C | Status |
|---|---|---|---|
| `replay_diff` | `ReplayWindow::check` | `sptps_check_seqno` | clean @ 10min |
| `subnet_cmp_diff` | `cmp_ipv4_fuzz` | `subnet_compare_ipv4` | 1 known finding |

## Running

```sh
# nixpkgs rustc lacks the ASAN runtime (`librustc-stable_rt.asan.a`).
# That's fine: we're catching assert_eq! divergences, not memory bugs.
# `-s none` disables the sanitizer; libFuzzer's coverage instrumentation
# (sancov) still drives toward branch edges.
#
# RUSTC_BOOTSTRAP unlocks -Z flags on stable.
RUSTC_BOOTSTRAP=1 nix develop --command \
  nix shell nixpkgs#cargo-fuzz --command \
  cargo fuzz run replay_diff -s none -- -max_total_time=600
```

Wrap in `pueue` — 10 minutes is the upper bound. If clean at 10min
with good coverage (`ft:` in the libFuzzer status line keeps
climbing), the transcription is likely sound; stop.

## Findings

### subnet_cmp_diff: weight-subtraction overflow (known, masked)

`subnet_parse.c:152` does `a->weight - b->weight`. With weights near
`i32::MAX/MIN` that wraps (under `-fwrapv`); Rust's `Ord::cmp` doesn't.
Reachable on the wire (`%d` parse, no clamp at `subnet_parse.c:250`).
Practical risk ~zero — weights are small in practice — but pinned in
`tincd::subnet_tree::tests::ipv4_ord_weight_at_i32_extremes`.

Masked in the harness so libFuzzer doesn't burn its budget rediscovering
it. Unmask if you fix the parser to clamp.

### subnet_cmp_diff: prefix-subtraction overflow (unreachable, not masked)

Same shape at `:140` (`b->prefixlength - a->prefixlength`), found in
<1s when prefix was unconstrained `i32`. But `str2net` rejects
out-of-range prefix at `:254` before the comparator ever runs. The
harness now constrains prefix to `0..=32`.

## Architecture

C functions are `static` in their TU. The shim `#include`s the `.c`
file directly (unity-build) and exports thin wrappers. See
`crates/tinc-ffi/csrc/replay_shim.c`.

Rust hooks are gated on `--cfg fuzzing` (set by cargo-fuzz, not a
cargo feature). The daemon build never sees them.
