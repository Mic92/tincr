use super::common::{Node, poll_until, read_cookie, tincd_at, wait_for_file};
use super::testnode;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn count_open_fds(pid: nix::unistd::Pid) -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .count()
    }
    #[cfg(target_os = "macos")]
    {
        // No lsof in the nix sandbox; a null buffer returns the list size.
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid.as_raw(),
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        assert!(bytes >= 0, "proc_pidinfo({pid})");
        #[expect(clippy::cast_sign_loss)]
        {
            bytes as usize / std::mem::size_of::<libc::proc_fdinfo>()
        }
    }
}

fn control_socket(node: &Node) -> (BufReader<UnixStream>, UnixStream) {
    let socket = UnixStream::connect(&node.socket).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&mut &socket, "0 ^{} 0", read_cookie(&node.pidfile)).unwrap();
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "0 testnode 17.7\n");
    reader.read_line(&mut line).unwrap();
    (reader, socket)
}

fn request_line(reader: &mut BufReader<UnixStream>, writer: &UnixStream, request: &str) -> String {
    writeln!(&mut &*writer, "{request}").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    reply
}

/// Garbage on the UDP port (a stale peer, a scanner) is read and
/// dropped; the daemon neither dies nor spins on a level-triggered fd
/// it never drains. UDP shares the TCP port number.
#[test]
fn stray_udp_is_drained() {
    let tmp = tmp!("udp-stray");
    let mut node = testnode(tmp.path());
    node.start();

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..5 {
        sender
            .send_to(b"not a tinc packet", node.tcp_addr())
            .unwrap();
    }
    std::thread::sleep(Duration::from_millis(100));

    node.assert_alive();
    let _ = node.ctl().dump(3);
    let log = node.stop();
    assert!(!log.contains("panicked"), "{log}");
}

/// Regression: purge before any peer or graph run took a path that
/// had no snapshot yet.
#[test]
fn purge_on_fresh_daemon_acks() {
    let tmp = tmp!("purge-fresh");
    let mut node = testnode(tmp.path());
    node.start();
    let (mut reader, writer) = control_socket(&node);
    assert_eq!(request_line(&mut reader, &writer, "18 8"), "18 8 0\n");
    let log = node.stop();
    assert!(!log.contains("panicked"), "{log}");
}

/// Requests before auth, bad cookies, an oversized line, every verb
/// with a garbage argument, and clients vanishing mid-dump: each only
/// costs that connection.
#[test]
fn control_abuse_keeps_serving() {
    let tmp = tmp!("ctl-abuse");
    let mut node = testnode(tmp.path());
    node.start();
    let cookie = read_cookie(&node.pidfile);
    let dropped = |greeting: &[u8]| {
        let socket = UnixStream::connect(&node.socket).unwrap();
        (&socket).write_all(greeting).unwrap();
        let mut reply = Vec::new();
        BufReader::new(&socket).read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty(), "{greeting:?} answered: {reply:?}");
    };
    dropped(b"18 0\n");
    for cookie in [&cookie[..32], "deadbeef", ""] {
        dropped(format!("0 ^{cookie} 0\n").as_bytes());
    }
    {
        let (mut reader, writer) = control_socket(&node);
        (&writer).write_all(&[b'x'; 4000]).unwrap();
        let mut reply = Vec::new();
        // EOF or ECONNRESET.
        let _ = reader.read_to_end(&mut reply);
    }
    {
        let (mut reader, writer) = control_socket(&node);
        // Not 0 (stop) or 9 (set_debug drops the conn on a bad level).
        for subtype in [1, 3, 4, 5, 6, 8, 10, 12, 13, 14, 15, 99, -1] {
            writeln!(&mut &writer, "18 {subtype} !!garbage!!").unwrap();
        }
        writeln!(&mut &writer, "18 6").unwrap();
        let mut line = String::new();
        while line != "18 6\n" {
            line.clear();
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "dropped after verb fuzz"
            );
        }
    }
    for _ in 0..10 {
        let (_, writer) = control_socket(&node);
        (&writer)
            .write_all(b"18 3\n18 4\n18 5\n18 6\n18 13\n")
            .unwrap();
    }
    assert!(!node.ctl().dump(3).is_empty());
}

/// `REQ_LOG` turns a control connection into a log sink that receives
/// records regardless of the stderr filter: with `RUST_LOG=warn` the
/// debug-level "Connection from" line still arrives.
#[test]
fn req_log_streams_records_below_stderr_level() {
    let tmp = tmp!("req-log");
    let mut node = testnode(tmp.path()).log_level("warn");
    node.start();

    let (mut log_reader, log_writer) = control_socket(&node);
    // level 2 ≈ debug, colour off; no ack.
    writeln!(&mut &log_writer, "18 15 2 0").unwrap();

    // Opening another control connection makes the daemon log.
    let _trigger = control_socket(&node);

    let mut seen = Vec::new();
    let found = (0..10).any(|_| {
        let mut header = String::new();
        assert_ne!(log_reader.read_line(&mut header).unwrap(), 0, "EOF");
        let len: usize = header
            .strip_prefix("18 15 ")
            .and_then(|rest| rest.trim_end().parse().ok())
            .unwrap_or_else(|| panic!("log header: {header:?}"));
        let mut body = vec![0u8; len];
        log_reader.read_exact(&mut body).unwrap();
        let message = String::from_utf8_lossy(&body).into_owned();
        let is_accept = message.contains("Connection from") && message.contains("(control)");
        seen.push(message);
        is_accept
    });
    assert!(found, "no accept record among {seen:#?}");
}

/// `REQ_SET_DEBUG N` replies with the previous level and then applies
/// N if it is non-negative; the level reverts when the connection
/// closes. A request without a level is a protocol error.
#[test]
fn set_debug_reports_previous_and_reverts_on_close() {
    let tmp = tmp!("set-debug");
    let mut node = testnode(tmp.path());
    let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
    cmd.env_remove("RUST_LOG")
        .stderr(std::process::Stdio::piped());
    node.start_command(cmd);

    let (mut reader, writer) = control_socket(&node);
    assert_eq!(request_line(&mut reader, &writer, "18 9 5"), "18 9 0\n");
    assert_eq!(request_line(&mut reader, &writer, "18 9 -1"), "18 9 5\n");
    assert_eq!(request_line(&mut reader, &writer, "18 9 2"), "18 9 5\n");
    assert_eq!(request_line(&mut reader, &writer, "18 9 -1"), "18 9 2\n");
    assert_eq!(request_line(&mut reader, &writer, "18 9"), "", "dropped");

    let (mut reader, writer) = control_socket(&node);
    assert_eq!(request_line(&mut reader, &writer, "18 9 -1"), "18 9 0\n");
}

/// Scripts inherit the daemon's cwd, and C tinc chdirs to confbase
/// early, so `tinc-up` scripts using relative `hosts/…` paths rely on
/// it. Launch from `/` to make the check meaningful.
#[test]
fn tinc_up_runs_in_confbase() {
    let tmp = tmp!("tinc-up-cwd");
    let mut node = testnode(tmp.path());
    let cwd_file = tmp.path().join("cwd.txt");
    let tinc_up = node.confbase.join("tinc-up");
    std::fs::write(
        &tinc_up,
        format!("#!/bin/sh\npwd > '{}'\n", cwd_file.display()),
    )
    .unwrap();
    std::fs::set_permissions(&tinc_up, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
    cmd.current_dir("/").stderr(std::process::Stdio::piped());
    node.start_command(cmd);
    // tinc-up runs after the socket appears.
    assert!(
        wait_for_file(&cwd_file),
        "tinc-up did not run:\n{}",
        node.stop()
    );
    node.stop();

    let script_cwd = std::fs::read_to_string(&cwd_file).unwrap();
    assert_eq!(
        std::path::Path::new(script_cwd.trim())
            .canonicalize()
            .unwrap(),
        node.confbase.canonicalize().unwrap()
    );
}

#[test]
fn control_connection_churn_leaks_no_fds() {
    let tmp = tmp!("fd-churn");
    let mut node = testnode(tmp.path());
    // Dumpable so /proc/PID/fd stays readable.
    let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
    cmd.env("TINCR_ALLOW_COREDUMP", "1")
        .stderr(std::process::Stdio::piped());
    node.start_command(cmd);

    let pid = node.pid();
    let baseline = count_open_fds(pid);
    for _ in 0..100 {
        let _ = control_socket(&node);
    }
    // +1 slack: read_dir's own dirfd shows up in the listing.
    let settled = poll_until(Duration::from_secs(5), || {
        let open = count_open_fds(pid);
        (open <= baseline + 1).then_some(open)
    });
    assert!(
        settled <= baseline + 1,
        "baseline={baseline} after={settled}"
    );
}
