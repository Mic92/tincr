//! One `Node` = one tincd config directory plus, once started, its
//! process.
//!
//! Nodes listen on an ephemeral port (`Port = 0`); the real port is
//! read back from the pidfile after `start()`. A node that others
//! `ConnectTo` must therefore be started before their config is
//! written. A restarted node pins its previous port so peers'
//! `Address =` lines stay valid.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

use super::{
    ChildWithLog, Ctl, alloc_port, pubkey_from_seed, read_tcp_addr, tincd_at, wait_for_file,
    write_ed25519_privkey,
};

pub struct Node {
    pub name: String,
    pub seed: [u8; 32],
    pub confbase: PathBuf,
    pub pidfile: PathBuf,
    pub socket: PathBuf,
    /// TCP/UDP listen port; 0 until the first `start()`.
    pub port: u16,
    /// Extra `tinc.conf` lines. They precede the `PingTimeout = 1`
    /// default, and tinc-conf is first-occurrence-wins, so they can
    /// override it.
    pub extra_conf: String,
    /// `DeviceType = tun` + `Interface =`; netns tests precreate it.
    pub iface: Option<String>,
    /// `Subnet =` lines in `hosts/SELF`.
    pub subnets: Vec<String>,
    /// `DeviceType = fd`: inherited socketpair end.
    pub device_fd: Option<RawFd>,
    pub rust_log: String,
    pub daemon: Option<ChildWithLog>,
}

impl Node {
    pub fn new(dir: &Path, name: &str, seed: u8) -> Self {
        Self {
            name: name.to_owned(),
            seed: [seed; 32],
            confbase: dir.join(name),
            pidfile: dir.join(format!("{name}.pid")),
            socket: dir.join(format!("{name}.socket")),
            port: 0,
            extra_conf: String::new(),
            iface: None,
            subnets: Vec::new(),
            device_fd: None,
            rust_log: "tincd=info".to_owned(),
            daemon: None,
        }
    }

    /// Transitional: pre-allocated port for tests not yet converted to
    /// start-then-configure ordering.
    pub fn with_alloc_port(dir: &Path, name: &str, seed: u8) -> Self {
        let mut node = Self::new(dir, name, seed);
        node.port = alloc_port();
        node
    }

    #[must_use]
    pub fn with_conf(mut self, lines: &str) -> Self {
        self.extra_conf.push_str(lines);
        if !lines.is_empty() && !lines.ends_with('\n') {
            self.extra_conf.push('\n');
        }
        self
    }
    #[must_use]
    pub fn iface(mut self, iface: &str) -> Self {
        self.iface = Some(iface.to_owned());
        self
    }
    #[must_use]
    pub fn subnet(mut self, subnet: &str) -> Self {
        self.subnets.push(subnet.to_owned());
        self
    }
    #[must_use]
    pub fn fd(mut self, fd: RawFd) -> Self {
        self.device_fd = Some(fd);
        self
    }
    #[must_use]
    pub fn log_level(mut self, rust_log: &str) -> Self {
        rust_log.clone_into(&mut self.rust_log);
        self
    }

    pub fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    /// Two-node shorthand for [`write_config_multi`](Self::write_config_multi).
    pub fn write_config(&self, peer: &Node, connect_to: bool) {
        let dial: &[&Node] = if connect_to { &[peer] } else { &[] };
        self.write_config_multi(&[peer], dial);
    }

    /// Writes `tinc.conf`, `hosts/SELF`, `hosts/PEER` for each of
    /// `peers`, and the private key. `connect_to` nodes get a
    /// `ConnectTo` line and an `Address` in their hosts file, so they
    /// must already be listening.
    pub fn write_config_multi(&self, peers: &[&Node], connect_to: &[&Node]) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!("Name = {}\nAddressFamily = ipv4\n", self.name);
        match (&self.iface, self.device_fd) {
            (Some(iface), _) => writeln!(tinc_conf, "DeviceType = tun\nInterface = {iface}"),
            (None, Some(fd)) => writeln!(tinc_conf, "DeviceType = fd\nDevice = {fd}"),
            (None, None) => writeln!(tinc_conf, "DeviceType = dummy"),
        }
        .unwrap();
        for peer in connect_to {
            writeln!(tinc_conf, "ConnectTo = {}", peer.name).unwrap();
        }
        tinc_conf.push_str(&self.extra_conf);
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        let mut own_host = format!("Port = {}\n", self.port);
        for subnet in &self.subnets {
            writeln!(own_host, "Subnet = {subnet}").unwrap();
        }
        std::fs::write(self.confbase.join("hosts").join(&self.name), own_host).unwrap();

        for peer in peers {
            self.write_host_file(peer, connect_to.iter().any(|c| c.name == peer.name));
        }

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    /// (Re)write `hosts/PEER`; with `with_address`, include where to
    /// dial it.
    pub fn write_host_file(&self, peer: &Node, with_address: bool) {
        let mut host = format!(
            "Ed25519PublicKey = {}\n",
            tinc_crypto::b64::encode(&peer.pubkey())
        );
        if with_address {
            assert_ne!(
                peer.port, 0,
                "{} must be started before {} can ConnectTo it",
                peer.name, self.name
            );
            writeln!(host, "Address = 127.0.0.1 {}", peer.port).unwrap();
        }
        std::fs::write(self.confbase.join("hosts").join(&peer.name), host).unwrap();
    }

    fn command(&self) -> std::process::Command {
        let mut cmd = tincd_at(&self.confbase, &self.pidfile, &self.socket);
        cmd.env("RUST_LOG", &self.rust_log).stderr(Stdio::piped());
        cmd
    }

    /// Spawn and wait until the control socket is up. Panics with the
    /// daemon's stderr if it fails to come up.
    pub fn start(&mut self) -> &mut Self {
        self.start_command(self.command())
    }

    /// Like `start`, letting `fd` survive the exec so the daemon can
    /// use it as its device. Drop the caller's copy afterwards.
    pub fn start_with_fd(&mut self, fd: &OwnedFd) -> &mut Self {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear CLOEXEC");
        self.start()
    }

    pub fn start_command(&mut self, mut cmd: std::process::Command) -> &mut Self {
        assert!(self.daemon.is_none(), "{} already running", self.name);
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.pidfile);
        let daemon = ChildWithLog::spawn(cmd.spawn().expect("spawn tincd"));
        assert!(
            wait_for_file(&self.socket),
            "{}: tincd did not come up; stderr:\n{}",
            self.name,
            daemon.kill_and_log()
        );
        let port = read_tcp_addr(&self.pidfile).port();
        if self.port == 0 {
            // Pin it so a restart keeps peers' `Address =` lines valid.
            let own_host = self.confbase.join("hosts").join(&self.name);
            if let Ok(contents) = std::fs::read_to_string(&own_host) {
                std::fs::write(
                    own_host,
                    contents.replace("Port = 0\n", &format!("Port = {port}\n")),
                )
                .unwrap();
            }
        }
        self.port = port;
        self.daemon = Some(daemon);
        self
    }

    /// Learn a port without staying up: for tests where the listener
    /// must be down while a dialer already knows its address, or where
    /// two nodes `ConnectTo` each other. Same small reuse window as
    /// any released port, but restart pins it. Overwrites the config
    /// with a throwaway one; call `write_config*` afterwards.
    pub fn reserve_port(&mut self) -> u16 {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();
        std::fs::write(
            self.confbase.join("tinc.conf"),
            format!(
                "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\n",
                self.name
            ),
        )
        .unwrap();
        std::fs::write(self.confbase.join("hosts").join(&self.name), "Port = 0\n").unwrap();
        write_ed25519_privkey(&self.confbase, &self.seed);
        self.start().stop();
        self.port
    }

    /// Kill the daemon and return everything it wrote to stderr.
    pub fn stop(&mut self) -> String {
        self.daemon
            .take()
            .map(ChildWithLog::kill_and_log)
            .unwrap_or_default()
    }

    /// Wait for the daemon to exit by itself; panics on timeout.
    pub fn wait_exit(&mut self) -> std::process::ExitStatus {
        let name = self.name.clone();
        let mut daemon = self
            .daemon
            .take()
            .unwrap_or_else(|| panic!("{name} not started"));
        daemon
            .wait_exit(std::time::Duration::from_secs(5))
            .unwrap_or_else(|| panic!("{name} did not exit; stderr:\n{}", daemon.log_snapshot()))
    }

    pub fn is_running(&self) -> bool {
        self.daemon.is_some()
    }

    pub fn daemon(&self) -> &ChildWithLog {
        self.daemon
            .as_ref()
            .unwrap_or_else(|| panic!("{} not started", self.name))
    }

    pub fn daemon_mut(&mut self) -> &mut ChildWithLog {
        let name = &self.name;
        self.daemon
            .as_mut()
            .unwrap_or_else(|| panic!("{name} not started"))
    }

    /// Stderr so far; daemon keeps running.
    pub fn log(&self) -> String {
        self.daemon().log_snapshot()
    }

    pub fn pid(&self) -> nix::unistd::Pid {
        let raw = i32::try_from(self.daemon().pid()).expect("pid fits i32");
        nix::unistd::Pid::from_raw(raw)
    }

    pub fn signal(&self, sig: nix::sys::signal::Signal) {
        nix::sys::signal::kill(self.pid(), sig).expect("kill");
    }

    /// Panic with the log if the process has exited.
    pub fn assert_alive(&mut self) {
        let name = self.name.clone();
        let daemon = self.daemon_mut();
        if let Some(status) = daemon.child.try_wait().unwrap() {
            panic!(
                "{name} exited ({status}); stderr:\n{}",
                daemon.log_snapshot()
            );
        }
    }

    pub fn tcp_addr(&self) -> SocketAddr {
        assert_ne!(self.port, 0, "{} not started", self.name);
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    pub fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    /// Meta connection to `peer` is past ACK.
    pub fn has_active_peer(&self, peer: &str) -> bool {
        has_active_peer(&self.ctl().dump(6), peer)
    }

    /// Poll until the meta connection to `peer` is (in)active.
    pub fn wait_for_peer(&self, peer: &str, active: bool, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while self.has_active_peer(peer) != active {
            assert!(
                std::time::Instant::now() < deadline,
                "{}: connection to {peer} did not become {}; stderr:\n{}",
                self.name,
                if active { "active" } else { "inactive" },
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Start `listener`, point `self` at it with `ConnectTo`, start
    /// `self`, and wait until both ends see the connection.
    pub fn start_dialing(&mut self, listener: &mut Node) {
        if !listener.is_running() {
            listener.write_config(self, false);
            listener.start();
        }
        self.write_config(listener, true);
        self.start();
        self.wait_for_peer(&listener.name, true, Duration::from_secs(10));
        listener.wait_for_peer(&self.name, true, Duration::from_secs(10));
    }

    /// Transitional: raw child for tests not yet moved to `start()`.
    pub fn spawn(&self) -> Child {
        self.command().spawn().expect("spawn tincd")
    }
    pub fn spawn_with_log(&self, rust_log: &str) -> Child {
        self.command()
            .env("RUST_LOG", rust_log)
            .spawn()
            .expect("spawn tincd")
    }
    pub fn spawn_with_fd(&self, fd: &OwnedFd) -> Child {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear CLOEXEC");
        self.spawn_with_log("tincd=debug")
    }
}

/// `dump connections` row `18 6 NAME HOST port P OPTS FD STATUS`:
/// is there a connection to `peer` that is past ACK (status bit 1)?
pub fn has_active_peer(rows: &[String], peer: &str) -> bool {
    rows.iter().any(|row| {
        let Some(body) = row.strip_prefix("18 6 ") else {
            return false;
        };
        let mut fields = body.split_whitespace();
        fields.next() == Some(peer)
            && fields
                .last()
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .is_some_and(|status| status & 0x2 != 0)
    })
}

/// `dump subnets` row `18 5 SUBNET OWNER`.
pub fn has_subnet(rows: &[String], subnet: &str, owner: &str) -> bool {
    rows.iter().any(|row| {
        row.strip_prefix("18 5 ").is_some_and(|body| {
            let mut fields = body.split_whitespace();
            fields.next() == Some(subnet) && fields.next() == Some(owner)
        })
    })
}
