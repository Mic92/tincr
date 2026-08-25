//! alice → fake proxy → bob. The fakes assert on the exact request
//! bytes, so this checks our encoder against the RFC rather than
//! against our own decoder, plus the reply parsing that happens
//! before the first protocol line.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use super::common::{Node, TmpGuard};

fn relay(client: TcpStream, upstream: TcpStream) {
    let mut client_read = client.try_clone().unwrap();
    let mut upstream_write = upstream.try_clone().unwrap();
    let to_upstream = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let (mut upstream_read, mut client_write) = (upstream, client);
    let _ = std::io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = to_upstream.join();
}

/// One-shot proxy: `handshake` reads the request from the client and
/// returns the target; we dial it and relay.
fn spawn_proxy(
    handshake: fn(&mut BufReader<TcpStream>) -> SocketAddr,
    reply: &'static [u8],
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(client);
        let target = handshake(&mut reader);
        let mut upstream = TcpStream::connect(target).expect("upstream connect");
        // tinc pipelines its ID line right after the request.
        upstream.write_all(reader.buffer()).unwrap();
        let mut client = reader.into_inner();
        client.write_all(reply).unwrap();
        relay(client, upstream);
    });
    addr
}

/// RFC 1928 anonymous: greeting `05 01 00`, then CONNECT `05 01 00 01 ip port`.
fn socks5_handshake(reader: &mut BufReader<TcpStream>) -> SocketAddr {
    let mut greeting = [0u8; 3];
    reader.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    reader.get_mut().write_all(&[5, 0]).unwrap();
    let mut request = [0u8; 10];
    reader.read_exact(&mut request).unwrap();
    assert_eq!(request[..4], [5, 1, 0, 1]);
    let ip: [u8; 4] = request[4..8].try_into().unwrap();
    SocketAddr::from((ip, u16::from_be_bytes([request[8], request[9]])))
}

/// `CONNECT ip:port HTTP/1.1` followed by an empty line, no headers.
fn http_connect_handshake(reader: &mut BufReader<TcpStream>) -> SocketAddr {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let target = line
        .trim_end()
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.strip_suffix(" HTTP/1.1"))
        .unwrap_or_else(|| panic!("{line:?}"));
    let target = target.parse().unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "\r\n");
    target
}

fn connect_through(tag: &str, proxy_type: &str, proxy: SocketAddr) {
    let tmp = TmpGuard::new("proxy", tag);
    let mut alice = Node::new(tmp.path(), "alice", 0xA5).with_conf(&format!(
        "Proxy = {proxy_type} {} {}\n",
        proxy.ip(),
        proxy.port()
    ));
    let mut bob = Node::new(tmp.path(), "bob", 0xB5);
    alice.start_dialing(&mut bob);
}

/// The binary SOCKS reply must be consumed by length, not as a line.
#[test]
fn connects_through_socks5_proxy() {
    let proxy = spawn_proxy(socks5_handshake, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    connect_through("socks5", "socks5", proxy);
}

/// The status line and blank line must be skipped before the request
/// parser sees bob's ID line. C tinc breaks if the proxy adds headers,
/// so the fake sends none either.
#[test]
fn connects_through_http_proxy() {
    let proxy = spawn_proxy(http_connect_handshake, b"HTTP/1.1 200 OK\r\n\r\n");
    connect_through("httpproxy", "http", proxy);
}
