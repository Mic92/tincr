# Agent instructions for the tinc Rust rewrite

## Dev environment

Enter the dev shell before running anything (cargo, rustc, meson, bwrap
are all provided by Nix):

```sh
nix develop
# or, if direnv is set up:
direnv allow
```

## Running tests

We use **cargo-nextest**, not `cargo test`. It gives us per-test
timeouts (`.config/nextest.toml`) so a hung SPTPS handshake or a stuck
netns child kills itself instead of wedging CI.

```sh
# Full suite
cargo nextest run

# Single crate
cargo nextest run -p tinc-sptps

# Single test
cargo nextest run -p tincd netns::ping_across_tunnel

# CI profile (longer timeout, retries, JUnit output)
cargo nextest run --profile ci
```

A test that exceeds `slow-timeout.period` is logged as SLOW; after
`terminate-after` periods it is SIGTERM'd then SIGKILL'd. If a test
legitimately needs more time, bump its budget with a per-test override
in `.config/nextest.toml` rather than raising the global default.

### Tests that need extra setup

- **`crates/tincd/tests/netns.rs`** — needs `bwrap` and unprivileged
  user namespaces. Self-skips with a `SKIP:` line on stderr if either
  is missing (Debian disables userns by default). The dev shell
  provides `bwrap`; the kernel sysctl is on you.

- **`crates/tinc-tools/tests/self_roundtrip.rs`** — Rust↔Rust always
  runs. The Rust↔C cross-impl variants only run when
  `TINC_C_SPTPS_TEST` / `TINC_C_SPTPS_KEYPAIR` point at C binaries.
  Build those with `meson setup build && ninja -C build` from the repo
  root (the dev shell has meson/ninja).

## Lint & format

```sh
flake-fmt          # rustfmt + nixfmt via treefmt
cargo clippy --all-targets -- -D warnings
```

Do both before committing.
