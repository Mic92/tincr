//! `LISTEN_FDS` end-to-end through the real `systemd-socket-activate`.
//! Self-skips when it is missing or predates `--now` (systemd 258;
//! without it tincd is only exec'd on the first connection).

use std::env;
use std::fs;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[macro_use]
mod common;
use common::{ChildWithLog, tincd_bin, wait_for_file, write_ed25519_privkey};

fn activator() -> Option<PathBuf> {
    let bin = env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| Path::new(dir).join("systemd-socket-activate"))
        .find(|path| path.is_file())?;
    let help = Command::new(&bin).arg("--help").output().ok()?;
    if !String::from_utf8_lossy(&help.stdout).contains("--now") {
        eprintln!("SKIP: systemd-socket-activate lacks --now (need >= 258)");
        return None;
    }
    Some(bin)
}

/// The activator cannot bind port 0, so pick a free one and retry if
/// it got taken in between.
fn spawn_activated(activator: &Path, tmp: &common::TmpGuard) -> (ChildWithLog, u16) {
    let (confbase, pidfile, socket) = tmp.std_paths();
    fs::create_dir_all(confbase.join("hosts")).unwrap();
    fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    // Must be ignored in favour of the inherited listener.
    fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);

    for _ in 0..5 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // No -D: LISTEN_PID alone must keep tincd in the foreground.
        let child: Child = Command::new(activator)
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
            .env("RUST_LOG", "tincd=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn systemd-socket-activate");
        let mut child = ChildWithLog::spawn(child);
        if wait_for_file(&socket) {
            return (child, port);
        }
        if child.wait_exit(Duration::from_secs(1)).is_some()
            && child.log_snapshot().contains("in use")
        {
            continue;
        }
        panic!("tincd did not come up:\n{}", child.kill_and_log());
    }
    panic!("no free port after 5 tries");
}

/// tincd adopts the activator's listener (pidfile reports that port,
/// connect succeeds) and does not detach (the activator's direct
/// child is still alive).
#[test]
fn adopts_listener_and_stays_foreground() {
    let Some(activator) = activator() else {
        eprintln!("SKIP: systemd-socket-activate not in PATH");
        return;
    };
    let tmp = tmp!("adopt");
    let (mut child, port) = spawn_activated(&activator, &tmp);
    let (_, pidfile, _) = tmp.std_paths();

    let addr = ([127, 0, 0, 1], port).into();
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    assert_eq!(common::read_tcp_addr(&pidfile), addr);
    assert!(child.wait_exit(Duration::ZERO).is_none(), "detached");
    let log = child.kill_and_log();
    assert!(log.contains("socket activation"), "{log}");
}
