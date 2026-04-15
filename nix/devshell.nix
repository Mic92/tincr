# Dev shell: enough to run `make -f kat/Makefile && cargo test`.
# The C toolchain is needed for KAT regeneration, not for the
# Rust build itself (no build.rs/cc yet — that comes with the
# SPTPS FFI harness in Phase 0b).
{
  mkShell,
  cargo,
  cargo-nextest,
  rustc,
  clippy,
  rustfmt,
  gcc,
  gnumake,
  jq,
  meson,
  ninja,
  pkg-config,
  bubblewrap,
  iproute2,
  iputils,
  util-linux,
  iperf3,
  perf,
  # local
  tincd-c,
  sptps-test-c,
}:
mkShell {
  # Cross-impl tests (crates/tincd/tests/crossimpl.rs and
  # crates/tinc-tools/tests/self_roundtrip.rs) gate on these
  # env vars: unset → SKIP. The earlier comment at the
  # sptps-test-c derivation about "rebuilding the C binary on
  # every Rust-only change" was wrong about THIS dependency
  # edge: both filesets are src/-only, so a Rust edit does NOT
  # invalidate them — entering the shell after a Rust change
  # is free. A src/ edit DOES rebuild on entry (~10s warm),
  # which is correct: any C change should re-run cross-impl.
  #
  # The crossimpl.rs tests are THE wire-compat proof; they
  # need to run with the rest of the suite, not be opt-in.
  TINC_C_TINCD = "${tincd-c}/sbin/tincd";
  TINC_C_SPTPS_TEST = "${sptps-test-c}/bin/sptps_test";
  TINC_C_SPTPS_KEYPAIR = "${sptps-test-c}/bin/sptps_keypair";

  packages = [
    cargo
    cargo-nextest
    rustc
    clippy
    rustfmt
    gcc
    gnumake
    jq # vectors.json sanity-checking
    # tinc-tools cross-impl test wants a C sptps_test to talk
    # to. Building via meson is the path of least resistance —
    # the build graph is already correct. Nolegacy mode means
    # no openssl dep; same crypto subset tinc-crypto ported.
    meson
    ninja
    pkg-config
    # netns integration tests (crates/tincd/tests/netns.rs).
    # bwrap re-execs the test binary inside an unprivileged
    # user+net namespace; ip/unshare/mount build a child
    # netns for one TUN device so ping doesn't shortcut.
    bubblewrap
    iproute2
    iputils # ping
    util-linux # unshare(1), mount(8)
    # throughput gate (crates/tincd/benches/throughput.rs).
    # `cargo bench --bench throughput --profile profiling`.
    # iperf3 measures the tunnel; perf records the daemon
    # during the 5s window. perf is best-effort: if
    # `kernel.perf_event_paranoid >= 2` (Debian default)
    # the bench still measures throughput, just no profile.
    iperf3
    perf
  ];
}
