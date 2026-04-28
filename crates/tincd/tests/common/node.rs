//! One `Node` builder for all multi-daemon integration tests.
//!
//! Device shape is a builder field, not a `write_config_*` flavour:
//! `.iface()` → `DeviceType = tun`, `.fd()` → `DeviceType = fd`,
//! neither → `dummy`. `.subnet()` → `Subnet =` in `hosts/SELF`.
//! `.with_conf()` lines land BEFORE the `PingTimeout = 1` default
//! (tinc-conf is first-occurrence-wins).

use std::fmt::Write as _;
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

use super::{Ctl, alloc_port, pubkey_from_seed, tincd_at, write_ed25519_privkey};

pub struct Node {
    pub name: &'static str,
    pub seed: [u8; 32],
    pub confbase: PathBuf,
    pub pidfile: PathBuf,
    pub socket: PathBuf,
    /// Pre-allocated TCP port. Written into THIS node's `hosts/NAME`
    /// `Port = N` AND, for any `ConnectTo` target, the dialer's
    /// `hosts/NAME` `Address = 127.0.0.1 N`.
    pub port: u16,
    /// Extra lines appended to `tinc.conf` (before the default
    /// `PingTimeout = 1`). [`with_conf`](Self::with_conf) appends.
    pub extra_conf: String,
    /// Real-TUN attach name (`Interface = X`). netns tests precreate
    /// persistent `tincN` devices and set this.
    pub iface: Option<&'static str>,
    /// `Subnet = X` in `hosts/SELF`.
    pub subnet: Option<String>,
    /// Inherited socketpair fd number (`DeviceType = fd`).
    pub device_fd: Option<RawFd>,
}

impl Node {
    pub fn new(tmp: &Path, name: &'static str, seed_byte: u8) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
            extra_conf: String::new(),
            iface: None,
            subnet: None,
            device_fd: None,
        }
    }

    // ── chainable builder setters ────────────────────────────────
    #[must_use]
    pub fn with_conf(mut self, extra: &str) -> Self {
        self.extra_conf.push_str(extra);
        self
    }
    #[must_use]
    pub fn iface(mut self, iface: &'static str) -> Self {
        self.iface = Some(iface);
        self
    }
    #[must_use]
    pub fn subnet(mut self, s: &str) -> Self {
        self.subnet = Some(s.to_owned());
        self
    }
    #[must_use]
    pub fn fd(mut self, fd: RawFd) -> Self {
        self.device_fd = Some(fd);
        self
    }

    // ── derived ─────────────────────────────────────────────────
    pub fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }
    pub fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    // ── config emission ─────────────────────────────────────────

    /// Two-peer shorthand. The dominant test shape (~20 callers).
    pub fn write_config(&self, other: &Node, connect_to: bool) {
        let ct: &[&str] = if connect_to { &[other.name] } else { &[] };
        self.write_config_multi(&[other], ct);
    }

    /// N-peer config: `tinc.conf` (device shape from builder fields,
    /// `ConnectTo` per `connect_to`, `extra_conf`, default
    /// `PingTimeout = 1`), `hosts/SELF` (Port + Subnet), `hosts/PEER`
    /// per `peers` (pubkey; `Address = 127.0.0.1 PORT` iff a
    /// `ConnectTo` target), `ed25519_key.priv`.
    pub fn write_config_multi(&self, peers: &[&Node], connect_to: &[&str]) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!("Name = {}\nAddressFamily = ipv4\n", self.name);
        if let Some(iface) = self.iface {
            writeln!(tinc_conf, "DeviceType = tun\nInterface = {iface}").unwrap();
        } else if let Some(fd) = self.device_fd {
            writeln!(tinc_conf, "DeviceType = fd\nDevice = {fd}").unwrap();
        } else {
            tinc_conf.push_str("DeviceType = dummy\n");
        }
        for ct in connect_to {
            writeln!(tinc_conf, "ConnectTo = {ct}").unwrap();
        }
        tinc_conf.push_str(&self.extra_conf);
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        let mut self_cfg = format!("Port = {}\n", self.port);
        if let Some(s) = &self.subnet {
            writeln!(self_cfg, "Subnet = {s}").unwrap();
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        for peer in peers {
            let pk = tinc_crypto::b64::encode(&peer.pubkey());
            let mut cfg = format!("Ed25519PublicKey = {pk}\n");
            if connect_to.contains(&peer.name) {
                writeln!(cfg, "Address = 127.0.0.1 {}", peer.port).unwrap();
            }
            std::fs::write(self.confbase.join("hosts").join(peer.name), cfg).unwrap();
        }

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    // ── spawn ───────────────────────────────────────────────────

    pub fn spawn(&self) -> Child {
        self.spawn_with_log("tincd=info")
    }

    pub fn spawn_with_log(&self, rust_log: &str) -> Child {
        tincd_at(&self.confbase, &self.pidfile, &self.socket)
            .env("RUST_LOG", rust_log)
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }

    /// Spawn with an inherited fd. Clears CLOEXEC on `fd` so the
    /// child sees it; the child's `FdTun::open(Inherited(fd))`
    /// wraps it. The TEST process keeps the other socketpair end.
    /// Borrows `fd`: the child inherits it by number across
    /// `fork+exec`; the caller still owns the parent's copy and
    /// should `drop()` it once the child has spawned.
    pub fn spawn_with_fd(&self, fd: &OwnedFd) -> Child {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .expect("fcntl SETFD");
        self.spawn_with_log("tincd=debug")
    }
}

// ── ctl-dump row helpers (shared by two_daemons + netns) ─────────

/// Row format: `"18 6 NAME HOST port P OPTS_HEX FD STATUS_HEX"`.
/// Status bit 1 (`0x2`) is `active` (past ACK). Control conn has
/// bit 9 (`0x200`). Filter rows by name AND active bit.
pub fn has_active_peer(rows: &[String], peer_name: &str) -> bool {
    rows.iter().any(|r| {
        let Some(body) = r.strip_prefix("18 6 ") else {
            return false;
        };
        let mut t = body.split_whitespace();
        if t.next() != Some(peer_name) {
            return false;
        }
        let status = t.last().and_then(|s| u32::from_str_radix(s, 16).ok());
        status.is_some_and(|s| s & 0x2 != 0)
    })
}

/// Row format: `"18 5 SUBNET OWNER"`.
pub fn has_subnet(rows: &[String], subnet: &str, owner: &str) -> bool {
    rows.iter().any(|r| {
        let Some(body) = r.strip_prefix("18 5 ") else {
            return false;
        };
        let mut t = body.split_whitespace();
        t.next() == Some(subnet) && t.next() == Some(owner)
    })
}
