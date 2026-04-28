# Dev shell: enough to run `make -f kat/Makefile && cargo test`.
# The C toolchain is for KAT regeneration, not for the Rust build.
{
  mkShell,
  lib,
  stdenv,
  cargo,
  cargo-nextest,
  rustc,
  clippy,
  rustfmt,
  gnumake,
  jq,
  meson,
  ninja,
  pkg-config,
  bubblewrap ? null,
  iproute2 ? null,
  iputils ? null,
  util-linux ? null,
  miniupnpd-nftables ? null,
  nftables ? null,
  iperf3,
  perf ? null,
  # local
  tincd-c,
  sptps-test-c,
}:
mkShell {
  # Cross-impl tests (crates/tincd/tests/crossimpl.rs and
  # crates/tinc-tools/tests/self_roundtrip.rs) gate on these
  # env vars: unset → SKIP. They are THE wire-compat proof and
  # must run with the rest of the suite, not be opt-in.
  TINC_C_TINCD = "${tincd-c}/sbin/tincd";
  TINC_C_SPTPS_TEST = "${sptps-test-c}/bin/sptps_test";
  TINC_C_SPTPS_KEYPAIR = "${sptps-test-c}/bin/sptps_keypair";

  packages = [
    cargo
    cargo-nextest
    rustc
    clippy
    rustfmt
    gnumake
    jq # vectors.json sanity-checking
    # cross-impl tests need a C sptps_test to talk to; meson
    # builds it in nolegacy mode (no openssl).
    meson
    ninja
    pkg-config
    iperf3
  ]
  # Linux-only: netns integration tests need bwrap+userns,
  # throughput bench needs perf.
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    bubblewrap
    iproute2
    iputils # ping
    util-linux # unshare(1), mount(8)
    # portmap netns test: real IGD/NAT-PMP daemon + nft for the
    # DNAT rules it installs. nftables backend specifically — the
    # legacy libiptc build can't init inside an unprivileged
    # userns; nft can (per-netns tables). Test SKIPs if absent.
    miniupnpd-nftables
    nftables
    perf
  ];
}
