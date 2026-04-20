use std::fmt::Write as _;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::{Child, Stdio};

use super::common::{Ctl, alloc_port, pubkey_from_seed, tincd_at, write_ed25519_privkey};

/// One daemon's config bundle. Seeds are distinct per node so the
/// keys differ.
/// Row format: `"18 6 NAME HOST port P OPTS_HEX FD STATUS_HEX"`.
/// Status bit 1 (`0x2`) is `active` (past ACK — `c->edge !=
/// NULL`). Control conn has bit 9
/// (`0x200`). Filter rows by name AND active bit.
pub(crate) fn has_active_peer(rows: &[String], peer_name: &str) -> bool {
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

pub(crate) struct Node {
    pub(crate) name: &'static str,
    pub(crate) seed: [u8; 32],
    pub(crate) confbase: PathBuf,
    pub(crate) pidfile: PathBuf,
    pub(crate) socket: PathBuf,
    /// Pre-allocated TCP port. Written into THIS node's `hosts/NAME`
    /// `Port = N` AND the OTHER node's `hosts/NAME` `Address = 127.0.0.1 N`.
    pub(crate) port: u16,
    /// Extra lines appended to `tinc.conf`. `with_conf()` populates.
    pub(crate) extra_conf: String,
}

impl Node {
    /// Extra lines appended to `tinc.conf`. Empty by default.
    /// `ping_pong_keepalive` sets `PingInterval = 1` here.
    pub(crate) fn with_conf(mut self, extra: &str) -> Self {
        self.extra_conf.push_str(extra);
        self
    }

    pub(crate) fn new(tmp: &std::path::Path, name: &'static str, seed_byte: u8) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
            extra_conf: String::new(),
        }
    }

    /// Ed25519 pubkey for cross-registration.
    pub(crate) fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    /// Connect a control client. Thin wrapper so callsites stay
    /// `node.ctl()`.
    pub(crate) fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    /// Two-peer convenience wrapper over `write_config_multi`.
    /// `connect_to` adds `ConnectTo = other` + `Address` for it.
    /// `device_fd` adds `DeviceType = fd` and `Device = N` (the test
    /// process's socketpair end, inherited via fd inheritance — we
    /// just don't set CLOEXEC). `subnet` adds `Subnet = X` to
    /// hosts/SELF.
    pub(crate) fn write_config_with(
        &self,
        other: &Node,
        connect_to: bool,
        device_fd: Option<i32>,
        subnet: Option<&str>,
    ) {
        let ct: &[&str] = if connect_to { &[other.name] } else { &[] };
        self.write_config_multi(&[other], ct, device_fd, subnet);
    }

    /// N-peer config: write `tinc.conf` with `ConnectTo` for each
    /// name in `connect_to`, write `hosts/PEER` for each `peers`
    /// entry (pubkey + Address iff a `ConnectTo` target), write
    /// `hosts/SELF` with Port + Subnet, write `ed25519_key.priv`.
    ///
    /// `extra_conf` is emitted FIRST: tinc-conf's `lookup().next()`
    /// is first-occurrence-wins, so tests that set `PingTimeout` via
    /// `with_conf()` shadow the `PingTimeout = 1` default.
    pub(crate) fn write_config_multi(
        &self,
        peers: &[&Node],
        connect_to: &[&str],
        device_fd: Option<i32>,
        subnet: Option<&str>,
    ) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!("Name = {}\nAddressFamily = ipv4\n", self.name);
        if let Some(fd) = device_fd {
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
        if let Some(s) = subnet {
            writeln!(self_cfg, "Subnet = {s}").unwrap();
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        for peer in peers {
            let pk = tinc_crypto::b64::encode(&peer.pubkey());
            let mut cfg = format!("Ed25519PublicKey = {pk}\n");
            // Address only for ConnectTo targets.
            if connect_to.contains(&peer.name) {
                writeln!(cfg, "Address = 127.0.0.1 {}", peer.port).unwrap();
            }
            // The peer's Subnet must be in OUR copy of hosts/PEER
            // so `route()` knows to forward to them. The C reads
            // it from disk at ADD_SUBNET-gossip time? No — the C
            // gets it from the wire (ADD_SUBNET). We do too. So
            // no Subnet line needed here. (The pubkey is the only
            // host-file dependency for `read_ecdsa_public_key`.)
            std::fs::write(self.confbase.join("hosts").join(peer.name), cfg).unwrap();
        }

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    /// Two-peer dummy-device shorthand. The dominant test shape
    /// (8 callers); keeps callsites readable.
    pub(crate) fn write_config(&self, other: &Node, connect_to: bool) {
        self.write_config_with(other, connect_to, None, None);
    }

    /// Spawn with an inherited fd. Clears CLOEXEC on `fd` so the
    /// child sees it; the child's `FdTun::open(Inherited(fd))`
    /// wraps it. The TEST process keeps the other socketpair end.
    /// Borrows `fd`: the child inherits it by number across
    /// `fork+exec`; the caller still owns the parent's copy and
    /// should `drop()` it once the child has spawned.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn spawn_with_fd(&self, fd: &OwnedFd) -> Child {
        // Clear CLOEXEC so the fd survives `exec()`. Rust's `Command::
        // spawn` doesn't close inherited fds (only stdin/out/err are
        // managed). C tincd's `Device = N` mode assumes the parent
        // did this.
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .expect("fcntl SETFD");
        tincd_at(&self.confbase, &self.pidfile, &self.socket)
            .env("RUST_LOG", "tincd=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }

    pub(crate) fn spawn(&self) -> Child {
        tincd_at(&self.confbase, &self.pidfile, &self.socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }
}

/// given owner. Row format: `"18 5 SUBNET OWNER"`.
pub(crate) fn has_subnet(rows: &[String], subnet: &str, owner: &str) -> bool {
    rows.iter().any(|r| {
        let Some(body) = r.strip_prefix("18 5 ") else {
            return false;
        };
        let mut t = body.split_whitespace();
        t.next() == Some(subnet) && t.next() == Some(owner)
    })
}
