//! `tinc-auth` as an nginx `auth_request` backend: `Remote-Addr` in,
//! `Tinc-*` headers out, decided by the daemon's subnet table.

use super::{AuthDaemon, Conf, HttpResponse};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

fn start(conf: &Conf) -> (AuthDaemon, PathBuf) {
    let socket = conf.dir().join("auth.socket");
    let mut auth = AuthDaemon::spawn(conf, &["--listen-socket", socket.to_str().unwrap()]);
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

#[test]
fn auth_by_subnet_owner() {
    let conf = Conf::bare();
    conf.serve_forever(|ctl| {
        ctl.expect("18 5");
        ctl.send("18 5 10.0.0.0/24 alice");
        ctl.send("18 5 10.0.0.2/32 bob");
        ctl.send("18 5 ff:ff:ff:ff:ff:ff (broadcast)");
        ctl.send("18 5");
    });
    let (_auth, socket) = start(&conf);

    // Longest prefix wins; without --map the user is the node name.
    let response = request(&socket, Some("10.0.0.2"));
    assert_eq!(response.status, 204);
    assert_eq!(response.header("Tinc-Node"), Some("bob"));
    assert_eq!(response.header("Tinc-User"), Some("bob"));
    assert_eq!(response.header("Tinc-Net"), Some("mesh"));
    assert_eq!(response.header("Tinc-Subnet"), Some("10.0.0.2/32"));

    let response = request(&socket, Some("10.0.0.7"));
    assert_eq!(response.status, 204);
    assert_eq!(response.header("Tinc-Node"), Some("alice"));
    assert_eq!(response.header("Tinc-Subnet"), Some("10.0.0.0/24"));

    let response = request(&socket, Some("192.168.1.1"));
    assert_eq!(response.status, 401);
    assert_eq!(response.header("Tinc-Node"), None);
}

/// No control socket: fail closed.
#[test]
fn auth_bad_requests_and_daemon_down() {
    let conf = Conf::bare();
    let (_auth, socket) = start(&conf);
    assert_eq!(request(&socket, None).status, 400);
    assert_eq!(request(&socket, Some("not-an-ip")).status, 401);
    assert_eq!(request(&socket, Some("10.0.0.2")).status, 503);
}
