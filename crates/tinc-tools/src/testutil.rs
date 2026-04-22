//! Shared test fixtures: `ConfDir` (confbase builder) and
//! `scratch_file` (one-off tempfile). Replaces per-module
//! `paths_at` / `setup` / `fake_init` helpers.

// Fs-failure panics are fine in test helpers.
#![allow(clippy::missing_panics_doc)]

use crate::keypair;
use crate::names::{Paths, PathsInput};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tinc_crypto::b64;

pub struct ConfDir {
    dir: TempDir,
    confbase: PathBuf,
    paths: Paths,
}

/// Tempdir holding a single file. Keep `TempDir` alive for the
/// duration of the test.
#[must_use]
pub fn scratch_file(name: &str, content: impl AsRef<[u8]>) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(name);
    fs::write(&p, content).unwrap();
    (dir, p)
}

impl ConfDir {
    /// Empty confbase with `hosts/`. No tinc.conf, no keys.
    #[must_use]
    pub fn bare() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase.clone()),
            ..Default::default()
        });
        Self {
            dir,
            confbase,
            paths,
        }
    }

    /// `bare()` + `tinc.conf` with `Name = NAME` + empty `hosts/NAME`.
    #[must_use]
    pub fn with_name(name: &str) -> Self {
        let this = Self::bare();
        fs::write(this.paths.tinc_conf(), format!("Name = {name}\n")).unwrap();
        fs::write(this.paths.host_file(name), "").unwrap();
        this
    }

    /// Overwrite `hosts/NAME` with `content`.
    #[must_use]
    pub fn with_host(self, name: &str, content: &str) -> Self {
        fs::write(self.paths.host_file(name), content).unwrap();
        self
    }

    /// Append to `tinc.conf` (creating it if needed).
    #[must_use]
    pub fn append_conf(self, content: &str) -> Self {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.paths.tinc_conf())
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        self
    }

    /// Append to `hosts/NAME`.
    #[must_use]
    pub fn append_host(self, name: &str, content: &str) -> Self {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.paths.host_file(name))
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        self
    }

    /// Write `ed25519_key.priv` and append the pubkey line to
    /// `hosts/NAME`. Same shape as `cmd::init::run` produces.
    #[must_use]
    pub fn with_ed25519_key(self, name: &str) -> Self {
        let sk = keypair::generate();
        let mut buf = Vec::new();
        tinc_conf::pem::write_pem(&mut buf, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
        fs::write(self.confbase.join("ed25519_key.priv"), buf).unwrap();
        let line = format!("Ed25519PublicKey = {}\n", b64::encode(sk.public_key()));
        self.append_host(name, &line)
    }

    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    #[must_use]
    pub fn confbase(&self) -> &Path {
        &self.confbase
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}
