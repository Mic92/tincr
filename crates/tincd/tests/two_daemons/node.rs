use std::path::PathBuf;
use std::process::{Child, Stdio};

use super::common::{Ctl, alloc_port, pubkey_from_seed, tincd_cmd, write_ed25519_privkey};

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

    /// Write `tinc.conf` + `hosts/NAME` + `ed25519_key.priv` +
    /// `hosts/OTHER`. `connect_to` adds `ConnectTo = other` to
    /// tinc.conf and `Address = 127.0.0.1 OTHER_PORT` to hosts/OTHER.
    /// `device_fd` adds `DeviceType = fd` and `Device = N` (the test
    /// process's socketpair end, inherited via `Command::pre_exec`-
    /// less fd inheritance — we just don't set CLOEXEC). `subnet`
    /// adds `Subnet = X` to hosts/SELF.
    pub(crate) fn write_config_with(
        &self,
        other: &Node,
        connect_to: bool,
        device_fd: Option<i32>,
        subnet: Option<&str>,
    ) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        // tinc.conf
        let mut tinc_conf = format!("Name = {}\nAddressFamily = ipv4\n", self.name);
        if let Some(fd) = device_fd {
            tinc_conf.push_str(&format!("DeviceType = fd\nDevice = {fd}\n"));
        } else {
            tinc_conf.push_str("DeviceType = dummy\n");
        }
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        // `extra_conf` (e.g. `Compression = N`) before the default
        // PingTimeout: first-occurrence-wins in tinc-conf lookup.
        tinc_conf.push_str(&self.extra_conf);
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port + maybe Subnet.
        let mut self_cfg = format!("Port = {}\n", self.port);
        if let Some(s) = subnet {
            self_cfg.push_str(&format!("Subnet = {s}\n"));
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        // hosts/OTHER — pubkey + maybe Address.
        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
        if connect_to {
            other_cfg.push_str(&format!("Address = 127.0.0.1 {}\n", other.port));
        }
        std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    /// Three-node config: write `tinc.conf` with `ConnectTo` for
    /// each name in `connect_to`, write `hosts/PEER` for each
    /// `peers` entry (pubkey + maybe Address), write `hosts/SELF`
    /// with Port + Subnet. `device_fd`: same as `write_config_with`.
    ///
    /// Why a separate fn instead of generalizing `write_config_with`:
    /// the two-node case is the dominant test shape (8 callers);
    /// keeping it simple preserves readability there.
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
            tinc_conf.push_str(&format!("DeviceType = fd\nDevice = {fd}\n"));
        } else {
            tinc_conf.push_str("DeviceType = dummy\n");
        }
        for ct in connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {ct}\n"));
        }
        tinc_conf.push_str(&self.extra_conf);
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        let mut self_cfg = format!("Port = {}\n", self.port);
        if let Some(s) = subnet {
            self_cfg.push_str(&format!("Subnet = {s}\n"));
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        for peer in peers {
            let pk = tinc_crypto::b64::encode(&peer.pubkey());
            let mut cfg = format!("Ed25519PublicKey = {pk}\n");
            // Address only for ConnectTo targets.
            if connect_to.contains(&peer.name) {
                cfg.push_str(&format!("Address = 127.0.0.1 {}\n", peer.port));
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

    pub(crate) fn write_config(&self, other: &Node, connect_to: bool) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        // tinc.conf
        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\n",
            self.name
        );
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        // `extra_conf` FIRST: tinc-conf's `lookup().next()` is
        // first-occurrence-wins; tests that set PingTimeout via
        // `with_conf()` need to shadow the default below.
        tinc_conf.push_str(&self.extra_conf);
        // PingTimeout = 1 keeps the test fast (terminate-on-EOF is
        // immediate but the ping sweep also runs). Shadowed by
        // `extra_conf` if present.
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port. The pre-allocated port. The daemon
        // re-binds it; the race is benign (high-range, just-freed).
        std::fs::write(
            self.confbase.join("hosts").join(self.name),
            format!("Port = {}\n", self.port),
        )
        .unwrap();

        // hosts/OTHER — pubkey + maybe Address. Both sides need the
        // other's pubkey (id_h reads it). Only the initiator needs
        // Address.
        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
        if connect_to {
            other_cfg.push_str(&format!("Address = 127.0.0.1 {}\n", other.port));
        }
        std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    /// Spawn with an inherited fd. Clears CLOEXEC on `fd` so the
    /// child sees it; the child's `FdTun::open(Inherited(fd))`
    /// wraps it. The TEST process keeps the other socketpair end.
    pub(crate) fn spawn_with_fd(&self, fd: i32) -> Child {
        // Clear CLOEXEC so the fd survives `exec()`. Rust's `Command::
        // spawn` doesn't close inherited fds (only stdin/out/err are
        // managed). C tincd's `Device = N` mode assumes the parent
        // did this.
        // SAFETY: `fcntl(F_SETFD, 0)` clears the CLOEXEC bit. The fd
        // is valid (just from socketpair).
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            assert!(flags >= 0, "fcntl GETFD");
            assert_eq!(libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC), 0);
        }
        tincd_cmd()
            .arg("-c")
            .arg(&self.confbase)
            .arg("--pidfile")
            .arg(&self.pidfile)
            .arg("--socket")
            .arg(&self.socket)
            .env("RUST_LOG", "tincd=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }

    pub(crate) fn spawn(&self) -> Child {
        tincd_cmd()
            .arg("-c")
            .arg(&self.confbase)
            .arg("--pidfile")
            .arg(&self.pidfile)
            .arg("--socket")
            .arg(&self.socket)
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
