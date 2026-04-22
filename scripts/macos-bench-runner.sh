#!/bin/sh
# Run the macOS-native throughput bench under sudo.
#
# utun open needs root; `cargo bench` itself doesn't, so build as the
# invoking user and re-exec only the bench binary under sudo. Keeps
# target/ ownership sane and avoids a root-owned Cargo cache.
#
# Usage:
#   scripts/macos-bench-runner.sh [-- FILTER...]
#   TINCD_PERF=1 scripts/macos-bench-runner.sh
#
# Extra args are forwarded to the bench (substring filters:
# rust_rust, c_c, rust_c, latency_<pairing>).

set -eu

cd "$(dirname "$0")/.."

if [ "$(uname -s)" != "Darwin" ]; then
    echo "macos-bench-runner: Darwin only (use 'cargo bench --bench throughput' on Linux)" >&2
    exit 1
fi

# Strip the conventional `--` separator cargo bench uses.
if [ "${1:-}" = "--" ]; then
    shift
fi

profile="${TINCD_BENCH_PROFILE:-release}"
if [ -n "${TINCD_PERF:-}" ]; then
    profile="profiling"
fi

echo "building bench (profile=$profile)..." >&2
cargo build --bench throughput_macos --profile "$profile"

# cargo emits bench binaries with a metadata hash suffix; pick the
# newest executable artefact (skip the .d depfile / .dSYM bundle).
out_dir="target/$profile"
if [ "$profile" = "dev" ]; then out_dir="target/debug"; fi
bin=""
for f in "$out_dir"/deps/throughput_macos-*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    case "$f" in *.d | *.dSYM) continue ;; esac
    if [ -z "$bin" ] || [ "$f" -nt "$bin" ]; then
        bin="$f"
    fi
done
if [ -z "$bin" ]; then
    echo "macos-bench-runner: built bench binary not found under $out_dir/deps" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    exec "$bin" --bench "$@"
fi

echo "re-exec under sudo: $bin" >&2
exec sudo --preserve-env=PATH,HOME,TMPDIR,TINCD_PERF,TINCD_PERF_DIR,TINCD_TRACE,TINC_C_TINCD,TINCD_BENCH_SPTPS_CIPHER \
    "$bin" --bench "$@"
