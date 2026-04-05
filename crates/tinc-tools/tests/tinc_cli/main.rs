//! Integration tests for the `tinc` binary. Spawns it as a subprocess
//! via `CARGO_BIN_EXE_tinc`, same pattern as `self_roundtrip.rs`.
//!
//! ## What this proves over the unit tests in `cmd/init.rs`
//!
//! The unit tests call `cmd::init::run()` directly. They prove the
//! *function* works. They don't prove:
//!
//! - argv parsing (`-c` / `-n` / `--config=` glued form)
//! - the dispatch table finds `init`
//! - exit codes (success → 0, error → 1)
//! - error messages go to stderr, not stdout
//!
//! Those are the binary's job. Test the binary.
//!
//! ## Cross-impl: `tinc init` → upstream `sptps_test`
//!
//! `cross_init_key_loads_in_c` is the load-bearing test. It runs
//! `tinc init`, then takes the resulting `ed25519_key.priv` and uses
//! it as input to the *C* `sptps_test`. If the C binary can establish
//! an SPTPS session with that key, the PEM format and the 96-byte
//! blob layout are correct end-to-end.
//!
//! Why this matters more than `cross_pem_read` in `self_roundtrip.rs`:
//! that test uses keys from `sptps_keypair`, which writes PEM to a
//! standalone `.priv` file. `tinc init` writes the *same* PEM but
//! through a different code path (`cmd::init` uses `write_pem`
//! directly with mode 0600 + `O_EXCL`, not `keypair::write_pair`).
//! Same format, different writer — a future refactor that breaks one
//! but not the other would slip through `cross_pem_read` but get
//! caught here.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod argv;
mod config;
mod cross_impl;
mod ctl;
mod dump;
mod edit;
mod export_import;
mod fake_daemon;
mod fsck;
mod genkey;
mod info;
mod init;
mod invite_join;
mod sign_verify;
mod top_log_pcap;

pub(crate) fn bin(name: &str) -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_tinc") {
        // The env var Cargo sets is per-binary. Map name → var.
        // We only have three; hardcode.
        let var = match name {
            "tinc" => "CARGO_BIN_EXE_tinc",
            "sptps_test" => "CARGO_BIN_EXE_sptps_test",
            "sptps_keypair" => "CARGO_BIN_EXE_sptps_keypair",
            _ => panic!("unknown bin {name}"),
        };
        if let Ok(p) = std::env::var(var) {
            return PathBuf::from(p);
        }
        // Fall through to the path-based fallback.
        let _ = p;
    }
    // CARGO_BIN_EXE_* not set (rare; cargo always sets it for [[bin]]s
    // of the crate-under-test). Derive from the test binary's location:
    // tests run from target/{profile}/deps/, binaries are in
    // target/{profile}/.
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(name)
}

/// Run `tinc` with args, capture everything.
pub(crate) fn tinc(args: &[&str]) -> std::process::Output {
    Command::new(bin("tinc"))
        .args(args)
        // NETNAME from the parent env would change confbase resolution.
        // Strip it so tests are hermetic. We *do* test the env var, but
        // explicitly (by passing `.env("NETNAME", ...)` in that test).
        .env_remove("NETNAME")
        .output()
        .expect("spawn tinc")
}

/// Create a tempdir, run `tinc -c <tempdir>/vpn init NAME`. Returns the
/// dir guard, the confbase path, and the confbase as a String for argv.
/// Replaces the `tempdir → join("vpn") → init` boilerplate at ~20 sites.
pub(crate) fn init_dir(name: &str) -> (tempfile::TempDir, PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap().to_owned();
    let out = tinc(&["-c", &cb, "init", name]);
    assert!(
        out.status.success(),
        "init {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (dir, confbase, cb)
}

/// `tinc -c <bare tempdir>` for failure-mode tests where init was never
/// run. Returns the dir guard and the confbase string.
pub(crate) fn bare_dir() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().to_str().unwrap().to_owned();
    (dir, cb)
}

/// Run `tinc` with stdin fed from a byte slice. For `import`/`exchange`.
pub(crate) fn tinc_stdin(args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(bin("tinc"))
        .args(args)
        .env_remove("NETNAME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tinc");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    // Drop closes the pipe → child sees EOF → import loop ends.
    child.wait_with_output().expect("wait tinc")
}
