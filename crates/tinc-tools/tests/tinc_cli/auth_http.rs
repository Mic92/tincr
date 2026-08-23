#![cfg(unix)]

use super::bin;
use super::fake_daemon::{fake_daemon_setup, serve_greeting};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct AuthProc {
    child: Child,
    sock: std::path::PathBuf,
}

impl Drop for AuthProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_auth(dir: &std::path::Path, cb: &str, pf: &str) -> AuthProc {
    let sock = dir.join("auth.socket");
    let child = Command::new(bin("tinc-auth"))
        .args([
            "-c",
            cb,
            "-n",
            "mesh",
            "--pidfile",
            pf,
            "--listen-socket",
            sock.to_str().unwrap(),
        ])
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
    AuthProc { child, sock }
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn request(sock: &std::path::Path, remote_addr: Option<&str>) -> Response {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET / HTTP/1.1\r\nHost: auth\r\nConnection: close\r\n").unwrap();
    if let Some(a) = remote_addr {
        write!(s, "Remote-Addr: {a}\r\n").unwrap();
    }
    write!(s, "\r\n").unwrap();

    let mut br = BufReader::new(&s);
    let mut line = String::new();
    br.read_line(&mut line).unwrap();
    let status: u16 = line.split_whitespace().nth(1).unwrap().parse().unwrap();

    let mut headers = Vec::new();
    loop {
        line.clear();
        br.read_line(&mut line).unwrap();
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let mut rest = Vec::new();
    let _ = br.read_to_end(&mut rest);
    Response { status, headers }
}

fn serve_subnet_dumps(
    listener: std::os::unix::net::UnixListener,
    cookie: String,
    n: usize,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..n {
            let (stream, _) = listener.accept().unwrap();
            let (mut br, mut w) = serve_greeting(&stream, &cookie);
            let mut req = String::new();
            br.read_line(&mut req).unwrap();
            assert_eq!(req.trim_end(), "18 5");
            writeln!(w, "18 5 10.0.0.0/24 alice").unwrap();
            writeln!(w, "18 5 10.0.0.2/32 bob").unwrap();
            writeln!(w, "18 5 ff:ff:ff:ff:ff:ff (broadcast)").unwrap();
            writeln!(w, "18 5").unwrap();
        }
    })
}

#[test]
fn auth_http_flow() {
    let (dir, cb, pf, listener, cookie) = fake_daemon_setup();
    let daemon = serve_subnet_dumps(listener, cookie, 3);
    let auth = spawn_auth(dir.path(), &cb, &pf);

    // longest prefix wins: 10.0.0.2 is bob's /32, not alice's /24
    let r = request(&auth.sock, Some("10.0.0.2"));
    assert_eq!(r.status, 204);
    assert_eq!(r.header("Tinc-Node"), Some("bob"));
    assert_eq!(r.header("Tinc-Net"), Some("mesh"));
    assert_eq!(r.header("Tinc-Subnet"), Some("10.0.0.2/32"));

    let r = request(&auth.sock, Some("10.0.0.7"));
    assert_eq!(r.status, 204);
    assert_eq!(r.header("Tinc-Node"), Some("alice"));
    assert_eq!(r.header("Tinc-Subnet"), Some("10.0.0.0/24"));

    let r = request(&auth.sock, Some("192.168.1.1"));
    assert_eq!(r.status, 401);
    assert_eq!(r.header("Tinc-Node"), None);

    daemon.join().unwrap();
}

#[test]
fn auth_http_bad_requests() {
    let (dir, cb, pf, listener, cookie) = fake_daemon_setup();
    drop(listener);
    let auth = spawn_auth(dir.path(), &cb, &pf);

    let r = request(&auth.sock, None);
    assert_eq!(r.status, 400);

    let r = request(&auth.sock, Some("not-an-ip"));
    assert_eq!(r.status, 401);

    // ctl socket gone: fail closed with 503
    let r = request(&auth.sock, Some("10.0.0.2"));
    assert_eq!(r.status, 503);

    let _ = cookie;
}
