//! `tinc-auth` as an nginx `auth_request` backend: `Remote-Addr` in,
//! `Tinc-*` headers out, decided by the daemon's route lookup.

use super::{AuthDaemon, Conf, HttpResponse};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

fn start(conf: &Conf, extra: &[&str]) -> (AuthDaemon, PathBuf) {
    let socket = conf.dir().join("auth.socket");
    let mut args = vec!["--listen-socket", socket.to_str().unwrap()];
    args.extend(extra);
    let mut auth = AuthDaemon::spawn(conf, &args);
    auth.wait_ready();
    (auth, socket)
}

fn request(socket: &Path, remote_addr: Option<&str>) -> HttpResponse {
    let mut stream = UnixStream::connect(socket).unwrap();
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: auth\r\nConnection: close\r\n"
    )
    .unwrap();
    if let Some(addr) = remote_addr {
        write!(stream, "Remote-Addr: {addr}\r\n").unwrap();
    }
    write!(stream, "\r\n").unwrap();
    HttpResponse::read(stream)
}

const ROUTES: &[(&str, &str)] = &[
    ("10.0.0.2", "10.0.0.2/32 bob"),
    ("10.0.0.7", "10.0.0.0/24 alice"),
    ("203.0.113.7", "0.0.0.0/0 gateway"),
];

/// Only host routes name a node unless `--min-prefix4` widens it, and
/// never /0. A miss in the daemon (no reachable owner) is a 401.
#[test]
fn auth_by_route_owner() {
    let conf = Conf::bare();
    conf.serve_lookup(ROUTES);
    let (_auth, socket) = start(&conf, &[]);

    // Without --map the user is the node name.
    let response = request(&socket, Some("10.0.0.2"));
    assert_eq!(response.status, 204);
    assert_eq!(response.header("Tinc-Node"), Some("bob"));
    assert_eq!(response.header("Tinc-User"), Some("bob"));
    assert_eq!(response.header("Tinc-Net"), Some("mesh"));
    assert_eq!(response.header("Tinc-Subnet"), Some("10.0.0.2/32"));

    for addr in ["10.0.0.7", "203.0.113.7", "192.168.1.1"] {
        let response = request(&socket, Some(addr));
        assert_eq!(response.status, 401, "{addr}");
        assert_eq!(response.header("Tinc-Node"), None);
    }

    let conf = Conf::bare();
    conf.serve_lookup(ROUTES);
    let (_auth, socket) = start(&conf, &["--min-prefix4", "24"]);
    let response = request(&socket, Some("10.0.0.7"));
    assert_eq!(response.status, 204);
    assert_eq!(response.header("Tinc-Node"), Some("alice"));
    assert_eq!(request(&socket, Some("203.0.113.7")).status, 401);
}

/// No control socket: fail closed.
#[test]
fn auth_bad_requests_and_daemon_down() {
    let conf = Conf::bare();
    let (_auth, socket) = start(&conf, &[]);
    assert_eq!(request(&socket, None).status, 400);
    assert_eq!(request(&socket, Some("not-an-ip")).status, 401);
    assert_eq!(request(&socket, Some("10.0.0.2")).status, 503);
}
