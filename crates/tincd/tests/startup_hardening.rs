//! Startup hardening: pidfile vs. control-socket bind ordering, and
//! `TINC_UMBILICAL` fd validation. Black-box (spawns the binary).

use std::io::Read;
use std::process::{Child, Stdio};
use std::time::Duration;

#[macro_use]
mod common;
use common::{drain_stderr, read_cookie, tincd_at, wait_for_file};

fn write_min_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
    common::write_ed25519_privkey(confbase, &[0x42; 32]);
}

fn spawn(confbase: &std::path::Path, pidfile: &std::path::Path, socket: &std::path::Path) -> Child {
    tincd_at(confbase, pidfile, socket)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd")
}

/// `TINC_UMBILICAL=2` must be ignored (not write-NUL-then-close stderr).
#[test]
fn umbilical_rejects_stdio_fd() {
    let tmp = tmp!("umb");
    let (confbase, pidfile, socket) = tmp.std_paths();
    write_min_config(&confbase);

    let mut child = tincd_at(&confbase, &pidfile, &socket)
        .env("TINC_UMBILICAL", "2 0")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");
    assert!(
        wait_for_file(&socket),
        "setup failed; stderr: {}",
        drain_stderr(child)
    );

    // Stderr pipe is blocking; read in a thread so the secure case
    // (fd 2 untouched, pipe stays open) doesn't hang the test.
    let mut stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let jh = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut b = [0u8; 256];
        loop {
            match stderr.read(&mut b) {
                Ok(0) => break tx.send((buf, true)),
                Ok(n) => buf.extend_from_slice(&b[..n]),
                Err(_) => break tx.send((buf, false)),
            }
        }
    });
    let (got, eof) = rx
        .recv_timeout(Duration::from_millis(300))
        .unwrap_or_default();

    let alive = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    let _ = jh.join();

    assert!(alive);
    assert!(!got.contains(&0u8), "NUL on stderr: fd 2 was claimed");
    assert!(!eof, "stderr EOF while daemon alive: fd 2 was closed");
}

/// Second tincd on the same `--pidfile` + `--socket` must fail the
/// `AlreadyRunning` bind check **before** touching the pidfile.
#[test]
fn second_daemon_does_not_clobber_pidfile() {
    let tmp = tmp!("clob");
    let (confbase, pidfile, socket) = tmp.std_paths();
    write_min_config(&confbase);

    let mut a = spawn(&confbase, &pidfile, &socket);
    assert!(
        wait_for_file(&socket),
        "A setup failed; stderr: {}",
        drain_stderr(a)
    );
    let cookie_a = read_cookie(&pidfile);

    let confbase_b = tmp.path().join("vpn-b");
    write_min_config(&confbase_b);
    let b = tincd_at(&confbase_b, &pidfile, &socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!b.status.success(), "B should have failed AlreadyRunning");
    assert!(a.try_wait().unwrap().is_none(), "A died");

    let cookie_after = read_cookie(&pidfile);
    let _ = a.kill();
    let _ = a.wait();

    assert_eq!(cookie_after, cookie_a, "B overwrote live pidfile cookie");
}
