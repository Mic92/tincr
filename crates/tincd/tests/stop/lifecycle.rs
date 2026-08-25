use nix::sys::signal::Signal;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::common::{poll_until, read_cookie, read_tcp_addr, read_to_eof, tincd_at};
use super::testnode;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::thread;

/// Raw greeting: `0 ^COOKIE 0` → `0 testnode 17.7` + `4 0 PID`.
fn greet(socket: &UnixStream, cookie: &str) -> (String, String) {
    writeln!(&mut &*socket, "0 ^{cookie} 0").unwrap();
    let mut reader = BufReader::new(socket);
    let mut id_line = String::new();
    let mut ack_line = String::new();
    reader.read_line(&mut id_line).unwrap();
    reader.read_line(&mut ack_line).unwrap();
    (id_line, ack_line)
}

/// The same bytes `tinc-tools`' fake-daemon tests expect from the
/// other side; together they pin the control protocol.
#[test]
fn greeting_then_req_stop_exits_cleanly() {
    let tmp = tmp!("req-stop");
    let mut node = testnode(tmp.path());
    node.start();

    let cookie = read_cookie(&node.pidfile);
    assert_eq!(cookie.len(), 64);
    let socket = UnixStream::connect(&node.socket).unwrap();
    let (id_line, ack_line) = greet(&socket, &cookie);
    assert_eq!(id_line, "0 testnode 17.7\n");
    let ack: Vec<&str> = ack_line.split_whitespace().collect();
    assert_eq!(ack[..2], ["4", "0"], "{ack_line:?}");
    assert_eq!(ack[2].parse::<i32>().unwrap(), node.pid().as_raw());
    drop(socket);

    node.ctl().stop();
    assert!(node.wait_exit().success());
    assert!(!node.pidfile.exists());
    assert!(!node.socket.exists());
}

/// `tinc start` end to end: tinc-tools forks our tincd with
/// `TINC_UMBILICAL`, tincd signals readiness after setup, `start()`
/// returns. The daemon detaches, so it is stopped over the socket.
#[test]
fn tinc_start_waits_for_umbilical() {
    let tmp = tmp!("umbilical");
    let node = testnode(tmp.path());
    let pidfile = node.pidfile.clone();
    let input = tinc_tools::names::PathsInput {
        confbase: Some(node.confbase.clone()),
        pidfile: Some(pidfile.clone()),
        ..Default::default()
    };
    let mut paths = tinc_tools::names::Paths::for_cli(&input);
    paths.resolve_runtime(&input);
    let tincd = Path::new(env!("CARGO_BIN_EXE_tincd"));

    tinc_tools::cmd::start::start_with(&paths, &[], tincd).expect("tinc start");
    // Readiness is the umbilical's whole point: no polling here.
    assert!(paths.unix_socket().exists());
    assert!(pidfile.exists());

    tinc_tools::cmd::start::start_with(&paths, &[], tincd).expect("second start is a no-op");

    tinc_tools::cmd::ctl_simple::stop(&paths).expect("tinc stop");
    poll_until(Duration::from_secs(5), || (!pidfile.exists()).then_some(()));
}

/// `TINC_UMBILICAL` naming a stdio fd must be ignored rather than
/// getting the NUL-then-close treatment.
#[test]
fn umbilical_on_stderr_is_ignored() {
    let tmp = tmp!("umbilical-stderr");
    let mut node = testnode(tmp.path());
    let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
    cmd.env("TINC_UMBILICAL", "2 0").stderr(Stdio::piped());
    node.start_command(cmd);
    thread::sleep(Duration::from_millis(300));
    node.assert_alive();
    // Would also be EOF here had fd 2 been closed.
    assert!(!node.log().contains('\0'), "NUL on stderr");
    let _ = node.ctl().dump(3);
}

/// Daemon half only: we hold the other end of the umbilical and
/// expect exactly one NUL byte once setup is done.
#[test]
fn umbilical_gets_nul_after_setup() {
    let tmp = tmp!("umbilical-daemon");
    let mut node = testnode(tmp.path());
    let (mut test_end, daemon_end) = UnixStream::pair().unwrap();

    // Pass the daemon's end as stdin and dup it to fd 3 after fork;
    // clearing CLOEXEC in this process instead would leak the fd into
    // whatever another test thread spawns meanwhile.
    let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
    cmd.env("TINC_UMBILICAL", "3 0")
        .stdin(Stdio::from(OwnedFd::from(daemon_end)))
        .stderr(Stdio::piped());
    // SAFETY: dup2 is async-signal-safe.
    #[expect(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            if libc::dup2(0, 3) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    node.start_command(cmd);

    test_end
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buf = [0u8; 16];
    let n = io::Read::read(&mut test_end, &mut buf).expect("read umbilical");
    assert_eq!(&buf[..n], [0]);
    // No EOF check: fd 0 in the child still refers to the socket.

    node.ctl().stop();
    assert!(node.wait_exit().success());
}

#[test]
fn sigterm_exits_cleanly() {
    let tmp = tmp!("sigterm");
    let mut node = testnode(tmp.path());
    node.start();

    let pidfile_pid: i32 = fs::read_to_string(&node.pidfile)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(pidfile_pid, node.pid().as_raw());

    node.signal(Signal::SIGTERM);
    assert!(node.wait_exit().success());
    assert!(!node.pidfile.exists());
}

/// tinc 1.0 dumped state on USR1/USR2; scripts that still send them
/// must not kill a 1.1 daemon.
#[test]
fn usr1_usr2_winch_are_ignored() {
    let tmp = tmp!("sigusr");
    let mut node = testnode(tmp.path());
    node.start();

    for signal in [Signal::SIGUSR1, Signal::SIGUSR2, Signal::SIGWINCH] {
        node.signal(signal);
        thread::sleep(Duration::from_millis(100));
        node.assert_alive();
    }
    node.signal(Signal::SIGTERM);
    assert!(node.wait_exit().success());
}

/// The second daemon must fail on the socket bind before it gets to
/// (over)write the shared pidfile.
#[test]
fn second_daemon_on_same_socket_is_refused() {
    let tmp = tmp!("second");
    let mut first = testnode(tmp.path());
    first.start();
    let cookie = read_cookie(&first.pidfile);

    let second = tincd_at(&first.confbase, &first.pidfile, &first.socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(!second.status.success(), "{stderr}");
    assert!(stderr.contains("already in use"), "{stderr}");
    first.assert_alive();
    assert_eq!(read_cookie(&first.pidfile), cookie, "pidfile clobbered");
}

/// With `PingTimeout = 1` the periodic timer fires and re-arms within
/// 2s; a daemon that forgot to re-arm would block in poll forever and
/// stop answering the control socket.
#[test]
fn responsive_after_timer_rearm() {
    let tmp = tmp!("alive");
    let mut node = testnode(tmp.path());
    node.start();
    thread::sleep(Duration::from_secs(2));
    node.assert_alive();
    let _ = node.ctl().dump(3);
}

#[test]
fn wrong_cookie_is_dropped() {
    let tmp = tmp!("badcookie");
    let mut node = testnode(tmp.path());
    node.start();

    let socket = UnixStream::connect(&node.socket).unwrap();
    let (id_line, _) = greet(&socket, &"f".repeat(64));
    assert_eq!(id_line, "", "daemon answered a wrong cookie");
    drop(socket);

    let socket = UnixStream::connect(&node.socket).unwrap();
    let (id_line, _) = greet(&socket, &read_cookie(&node.pidfile));
    assert_eq!(id_line, "0 testnode 17.7\n");
}

/// The pidfile address is connectable (unspecified is rewritten to
/// loopback) and the cookie greeting is unix-socket only.
#[test]
fn tcp_listener_rejects_cookie_greeting() {
    let tmp = tmp!("tcp-cookie");
    let mut node = testnode(tmp.path()).log_level("tincd=debug");
    node.start();

    let tcp_addr = read_tcp_addr(&node.pidfile);
    assert!(tcp_addr.ip().is_loopback(), "{tcp_addr}");
    assert_ne!(tcp_addr.port(), 0);

    let cookie = read_cookie(&node.pidfile);
    let stream = TcpStream::connect(tcp_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&stream, "0 ^{cookie} 0").unwrap();
    assert_eq!(read_to_eof(&stream), Ok(vec![]), "cookie accepted over TCP");

    let started = Instant::now();
    node.ctl().stop();
    assert!(node.wait_exit().success());
    assert!(started.elapsed() < Duration::from_secs(5));
}
