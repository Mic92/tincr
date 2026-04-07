# Differential fuzz: Rust vs C, same inputs, compare bytes

The Lean/Alloy proofs verified the *algorithms*. They can't see
transcription bugs — places where Rust does what the comment says, not
what the C does. These harnesses pit both impls against identical
inputs and compare outputs byte-for-byte.

## Targets

| Harness | Rust | C | Status |
|---|---|---|---|
| `replay_diff` | `ReplayWindow::check` | `sptps_check_seqno` | clean @ 10min |

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

## Architecture

C functions are `static` in their TU. The shim `#include`s the `.c`
file directly (unity-build) and exports thin wrappers. See
`crates/tinc-ffi/csrc/replay_shim.c`.

Rust hooks are gated on `--cfg fuzzing` (set by cargo-fuzz, not a
cargo feature). The daemon build never sees them.
