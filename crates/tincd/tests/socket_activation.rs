//! `LISTEN_PID`/`LISTEN_FDS` end-to-end. `systemd-socket-activate`
//! is the real activator, not a hand-rolled fork+dup2 — calling it
//! directly is the realistic test (and it's what catches drift when
//! systemd changes its fd-passing protocol).
//!
//! Self-skips when the binary isn't in PATH (non-systemd hosts) or
//! when it's too old for `--now` (added in systemd 258; without it
//! the activator is lazy — waits for the first connection before
//! exec — and `wait_for_file(&socket)` would hang because tincd
//! hasn't been exec'd yet).
//!
//! Why a separate file: the `which systemd-socket-activate` check
//! and the skip-on-absence pattern match `netns.rs`'s self-skip
//! shape (see AGENTS.md), and grouping it with `stop.rs` would muddy
//! that file's "daemon lifecycle" theme.

use std::process::{Command, Stdio};
use std::time::Duration;

mod common;
use common::{TmpGuard, alloc_port, tincd_bin, wait_for_file, write_ed25519_privkey};

/// Find `systemd-socket-activate` in PATH and verify it supports
/// `--now`. None → self-skip.
///
/// No `which` crate dep; PATH walk by hand (same pattern as
/// `netns.rs`'s `bwrap` check). The `--now` probe uses `--help`
/// rather than `--version`: the option name in help output is more
/// reliable than parsing the systemd version number out of a
/// free-form banner.
fn activator() -> Option<std::path::PathBuf> {
    let bin = std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|d| std::path::Path::new(d).join("systemd-socket-activate"))
        .find(|p| p.is_file())?;

    // `--now` (added systemd 258) execs immediately. Without it the
    // activator waits for a connection before exec — `wait_for_file`
    // on the control socket would just hang.
    let help = Command::new(&bin).arg("--help").output().ok()?;
    if !String::from_utf8_lossy(&help.stdout).contains("--now") {
        eprintln!("SKIP: systemd-socket-activate too old (no --now; need >=258)");
        return None;
    }
    Some(bin)
}

/// Minimal config. Port = 0 here is DELIBERATE noise: the activation
/// path must BYPASS it (`net_setup.c:1107` — the `.socket` unit IS
/// the bind config). The pidfile-port assertion below proves the
/// adopted port won, not this one.
fn write_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    // Port = 0 in the host config. If the activation branch is
    // broken and we fall through to build_listeners, the daemon
    // binds an ephemeral port, NOT the activator's port — the
    // pidfile assertion catches it.
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
    write_ed25519_privkey(confbase, &[0x42; 32]);
}

/// THE end-to-end proof: `systemd-socket-activate` execs tincd with
/// a TCP listener at fd 3, tincd adopts it, the pidfile reports
/// the activator's port (not the config's `Port = 0`), and a TCP
/// connect against that port succeeds.
///
/// Note no `-D` flag: socket activation should suppress detach
/// itself (C `tincd.c:579`). If our `LISTEN_PID` gate works, the
/// child stays foreground without us asking.
#[test]
fn socket_activation_adopts_tcp_fd() {
    let Some(activator) = activator() else {
        eprintln!("SKIP: systemd-socket-activate not in PATH");
        return;
    };

    let tmp = TmpGuard::new("sa", "adopt");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    // Port-TOCTOU: bind ephemeral, read it back, drop. The window
    // where someone else grabs it is sub-ms on loopback. If it ever
    // flakes, retry-on-EADDRINUSE in a loop; for now, live with it.
    let port = alloc_port();
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();

    // `-l ADDR` (lowercase L) = listen address. WITHOUT `-a`/
    // `--accept` (which would be inetd-mode: accept-then-exec
    // per-conn). `--now` = exec immediately.
    let mut child = Command::new(&activator)
        .arg("-l")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--now")
        .arg("--")
        .arg(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        // No -D: LISTEN_PID gate should force args.do_detach = false.
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("systemd-socket-activate should be runnable");

    // Daemon comes up: control socket appears.
    if !wait_for_file(&socket) {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        panic!(
            "tincd should start under socket activation; stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // tincd is listening on the systemd-provided port. The peer
    // protocol won't complete (no peer keys), but `connect()`
    // succeeding past the SYN/ACK proves the fd was adopted (kernel
    // completed the handshake against the listening socket's
    // backlog).
    let peer = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2));
    assert!(
        peer.is_ok(),
        "child should accept on inherited fd: {:?}",
        peer.err()
    );

    // Stronger check: pidfile addr line should mention the
    // activator's port. C `control.c:155`: pidfile line 1 =
    // `"PID COOKIE HOST port PORT"`. The HOST/PORT come from
    // `getsockname` on listeners[0] — which is the adopted fd.
    // If we'd fallen through to `build_listeners`, Port = 0 in
    // the config would give us an ephemeral port ≠ this one.
    let pidfile_contents = std::fs::read_to_string(&pidfile).unwrap();
    let first_line = pidfile_contents.lines().next().unwrap();
    assert!(
        first_line.ends_with(&format!("port {port}")),
        "pidfile should mention adopted port {port}; got: {first_line:?}"
    );

    // Stderr should mention "socket activation" (the log line from
    // `adopt_listeners`). The activator may print its own lines too;
    // grep loosely. Kill first, then drain.
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("socket activation"),
        "expected adoption log line; stderr:\n{stderr}"
    );
}

/// Detach is suppressed: `systemd-socket-activate`'s child does
/// NOT fork. If our `LISTEN_PID` gate is broken, tincd forks (default
/// `do_detach = true`), the parent exits, the activator sees its
/// child die. `try_wait()` → `Some(_)` would mean the child exited.
#[test]
fn socket_activation_suppresses_detach() {
    let Some(activator) = activator() else {
        eprintln!("SKIP: systemd-socket-activate not in PATH");
        return;
    };

    let tmp = TmpGuard::new("sa", "nodetach");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    let port = alloc_port();

    // No `-D` flag here. If LISTEN_PID gating works,
    // `args.do_detach` is forced false by the env check.
    let mut child = Command::new(&activator)
        .arg("-l")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--now")
        .arg("--")
        .arg(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    assert!(
        wait_for_file(&pidfile),
        "pidfile should appear (no detach → child writes it directly)"
    );

    // The pidfile's PID is the daemon's getpid(). If detach
    // happened, that's the GRANDCHILD's pid; `child` (the
    // activator's exec'd process) would have exited.
    // `try_wait()` → None means still running.
    let still_running = child.try_wait().unwrap().is_none();
    assert!(
        still_running,
        "activator's child exited — detach happened (LISTEN_PID gate broken)"
    );

    let _ = child.kill();
    let _ = child.wait();
}
