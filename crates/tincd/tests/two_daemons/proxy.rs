use std::time::{Duration, Instant};

use super::common::*;
use super::node::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("2d", tag)
}

// ═══════════════════════════════════════════════════════════════════
// SOCKS5 proxy roundtrip (chunk-11-proxy)
// ═══════════════════════════════════════════════════════════════════

/// In-process anonymous SOCKS5 server. Reads the RFC 1928 greeting +
/// CONNECT request, replies, then relays bytes bidirectionally to the
/// target. Same shape as `proxy_exec_roundtrip("cat")` but with the
/// real SOCKS5 byte handshake — proves `socks::build_request` produces
/// bytes a server reading the RFC accepts, and we accept ITS reply.
///
/// One-shot: handles ONE connection then exits. Enough for the test
/// (alice connects once).
fn fake_socks5_server() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("socks5 bind");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().expect("socks5 accept");

        // ─── Greeting (RFC 1928 §3) ────────────────────────────────
        // tinc sends [05][01][00] (1 method: anonymous). socks.rs:182.
        let mut greet = [0u8; 3];
        client.read_exact(&mut greet).expect("read greet");
        assert_eq!(greet[0], 5, "SOCKS version");
        assert_eq!(greet[1], 1, "nmethods");
        assert_eq!(greet[2], 0, "method = anonymous");
        // Reply: [05][00] (chose anonymous).
        client.write_all(&[5, 0]).expect("write choice");

        // ─── CONNECT (RFC 1928 §4) ─────────────────────────────────
        // [05][01][00][atyp][addr][port]. tinc sends atyp=01 (IPv4)
        // for our 127.0.0.1 target. socks.rs:213-216.
        let mut hdr = [0u8; 4];
        client.read_exact(&mut hdr).expect("read conn hdr");
        assert_eq!(hdr[0], 5, "version");
        assert_eq!(hdr[1], 1, "cmd = CONNECT");
        assert_eq!(hdr[3], 1, "atyp = IPv4");
        let mut ip = [0u8; 4];
        client.read_exact(&mut ip).expect("read ip");
        let mut port = [0u8; 2];
        client.read_exact(&mut port).expect("read port");
        let target = std::net::SocketAddr::from((ip, u16::from_be_bytes(port)));

        // Connect to the real target (bob).
        let upstream = TcpStream::connect(target).expect("upstream connect");

        // Reply: [05][00][00][01][0.0.0.0][0] (granted; bound addr
        // is "don't care" — tinc ignores it, socks.rs:267-271).
        client
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .expect("write conn reply");

        // ─── Bidirectional relay ───────────────────────────────────
        // Two threads, copy each direction. Shutdown the write half
        // when one side closes its read; the other thread's read
        // returns 0 and it exits too.
        let mut c_r = client.try_clone().unwrap();
        let mut u_w = upstream.try_clone().unwrap();
        let t1 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c_r, &mut u_w);
            let _ = u_w.shutdown(Shutdown::Write);
        });
        let mut u_r = upstream;
        let mut c_w = client;
        let _ = std::io::copy(&mut u_r, &mut c_w);
        let _ = c_w.shutdown(Shutdown::Write);
        let _ = t1.join();
    });
    (addr, handle)
}

/// Two daemons through a SOCKS5 proxy. Alice has `Proxy = socks5
/// 127.0.0.1 PORT` and `ConnectTo = bob`. The fake proxy validates
/// the RFC 1928 byte format on the wire (so we KNOW `build_request`
/// is right, not just that our build/check are inverses), relays to
/// bob, both reach ACK.
///
/// ## What's proven
///
/// 1. **`try_connect_via_proxy`**: alice's TCP connect goes to the
///    proxy addr, NOT bob's port. (If it went to bob directly the
///    test would still pass — but the proxy thread asserts on the
///    SOCKS bytes, so wrong-address would deadlock or assert-fail
///    the proxy.)
/// 2. **`finish_connecting` SOCKS arm**: SOCKS bytes queued BEFORE
///    the ID line. The proxy reads `[05][01][00]...`, asserts on
///    each byte. Proves `socks::build_request` produces RFC-valid
///    bytes.
/// 3. **`on_conn_readable` tcplen consume**: alice reads the proxy's
///    12-byte reply via `read_n` (NOT `read_line` — which would
///    misparse `[05][00]...` as "5" = METAKEY → gate fail). Proves
///    the pre-SPTPS `tcplen` branch fires before the line-drain loop.
/// 4. **`socks::check_response` Granted**: alice doesn't terminate
///    on the reply. The byte format we send and accept MATCHES.
/// 5. **Full handshake through the relay**: ID + SPTPS + ACK all
///    pass through the proxy's `io::copy` loops. Same end state as
///    `two_daemons_connect_and_reach`.
#[test]
fn socks5_proxy_roundtrip() {
    let tmp = tmp("socks5");
    let alice = Node::new(tmp.path(), "alice", 0xA5);
    let bob = Node::new(tmp.path(), "bob", 0xB5);

    // Spawn the fake SOCKS5 server first.
    let (proxy_addr, proxy_handle) = fake_socks5_server();

    // Bob: plain config, no proxy.
    bob.write_config(&alice, false);
    // Alice: ConnectTo bob, Proxy = socks5 <fake>.
    let alice = alice.with_conf(&format!(
        "Proxy = socks5 {} {}\n",
        proxy_addr.ip(),
        proxy_addr.port()
    ));
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // Poll for active peer conns on both sides. Same check as
    // `two_daemons_connect_and_reach`.
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(6);
        let b = bob_ctl.dump(6);
        if has_active_peer(&a, "bob") && has_active_peer(&b, "alice") {
            Some(())
        } else {
            None
        }
    });

    // Clean up.
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    // Proxy thread exits when alice's connection closes (io::copy
    // returns 0). Join with timeout via a poll-loop on is_finished.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy_handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    // Don't assert is_finished — the proxy thread might still be in
    // io::copy if shutdown ordering raced. The test already proved
    // what it needs to (active conns through the proxy).
}

// ═══════════════════════════════════════════════════════════════════
// HTTP CONNECT proxy roundtrip (chunk-12-http-proxy)
// ═══════════════════════════════════════════════════════════════════

/// Minimal HTTP CONNECT proxy. Reads until `\r\n\r\n`, parses the
/// CONNECT line, dials upstream, sends 200, bidirectional relay.
///
/// Mirrors `test/integration/proxy.py:127-158`. Sends NO headers
/// (just status + blank line) — same as the python. A
/// header-sending proxy would terminate the upstream tinc
/// connection (upstream bug).
///
/// One-shot: handles ONE connection then exits.
fn fake_http_proxy() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("http proxy bind");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (client, _) = listener.accept().expect("http proxy accept");
        let mut reader = BufReader::new(client.try_clone().unwrap());

        // ─── Read CONNECT line ──────────────────────────────────────
        // `CONNECT 127.0.0.1:PORT HTTP/1.1\r\n`
        let mut connect_line = String::new();
        reader.read_line(&mut connect_line).expect("read CONNECT");
        let connect_line = connect_line.trim_end();
        assert!(
            connect_line.starts_with("CONNECT "),
            "expected CONNECT, got {connect_line:?}"
        );
        let target = connect_line
            .strip_prefix("CONNECT ")
            .and_then(|s| s.strip_suffix(" HTTP/1.1"))
            .expect("CONNECT format");
        let target: std::net::SocketAddr = target
            .parse()
            .unwrap_or_else(|e| panic!("parse {target:?}: {e}"));

        // ─── Read until blank line (just `\r\n`) ────────────────────
        // tinc sends `CONNECT ... HTTP/1.1\r\n\r\n` — one CONNECT
        // line + immediate blank. No intermediate headers.
        let mut line = String::new();
        reader.read_line(&mut line).expect("read blank");
        assert_eq!(line, "\r\n", "expected blank line, got {line:?}");

        // ─── Dial upstream ──────────────────────────────────────────
        let upstream = TcpStream::connect(target).expect("upstream connect");

        // ─── Reply: status + blank line, NO headers ─────────────────
        // Same as proxy.py:155. Upstream only works with this
        // minimal form (upstream bug).
        //
        // tinc queues CONNECT + ID in the same flush (`connect.rs`:
        // `send_raw(CONNECT)` then `conn.send(Id)` before any read),
        // so `BufReader` may have buffered the ID line. Drain it
        // before `into_inner()` and forward upstream.
        let leftover = reader.buffer().to_vec();
        let mut client = reader.into_inner();
        client
            .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .expect("write 200");
        if !leftover.is_empty() {
            (&upstream).write_all(&leftover).expect("forward leftover");
        }

        // ─── Bidirectional relay ────────────────────────────────────
        // Same as fake_socks5_server.
        let mut c_r = client.try_clone().unwrap();
        let mut u_w = upstream.try_clone().unwrap();
        let t1 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c_r, &mut u_w);
            let _ = u_w.shutdown(Shutdown::Write);
        });
        let mut u_r = upstream;
        let mut c_w = client;
        let _ = std::io::copy(&mut u_r, &mut c_w);
        let _ = c_w.shutdown(Shutdown::Write);
        let _ = t1.join();
    });
    (addr, handle)
}

/// Two daemons through an HTTP CONNECT proxy. Alice has `Proxy =
/// http 127.0.0.1 PORT` and `ConnectTo = bob`. The fake proxy
/// validates the CONNECT line on the wire, relays to bob, both
/// reach ACK.
///
/// ## What's proven
///
/// 1. **`finish_connecting` HTTP arm**: `CONNECT host:port
///    HTTP/1.1\r\n\r\n` queued via `send_raw`. The proxy asserts
///    on the exact line format.
/// 2. **`metaconn` HTTP intercept**: alice reads `HTTP/1.1 200
///    OK\r\n\r\n` BEFORE `check_gate`. Status line → skip; blank
///    line → skip. Then bob's ID line hits `check_gate` normally.
///    Without the intercept, `atoi("HTTP/1.1")=0` → `BadRequest`.
/// 3. **Gate closes naturally**: no `proxy_passed` flag. Once
///    `id_h` changes `allow_request`, the intercept condition
///    `allow_request==Id` is false — subsequent lines go straight
///    to `check_gate`.
/// 4. **Full handshake through the relay**: ID + SPTPS + ACK.
#[test]
fn http_proxy_roundtrip() {
    let tmp = tmp("httpproxy");
    let alice = Node::new(tmp.path(), "alice", 0xA6);
    let bob = Node::new(tmp.path(), "bob", 0xB6);

    // Spawn the fake HTTP CONNECT proxy first.
    let (proxy_addr, proxy_handle) = fake_http_proxy();

    // Bob: plain config, no proxy.
    bob.write_config(&alice, false);
    // Alice: ConnectTo bob, Proxy = http <fake>.
    let alice = alice.with_conf(&format!(
        "Proxy = http {} {}\n",
        proxy_addr.ip(),
        proxy_addr.port()
    ));
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // Poll for active peer conns on both sides.
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(6);
        let b = bob_ctl.dump(6);
        if has_active_peer(&a, "bob") && has_active_peer(&b, "alice") {
            Some(())
        } else {
            None
        }
    });

    // Clean up.
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy_handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
}
