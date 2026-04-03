//! `outgoing_t` (`net.h:121-125`) + the connect-side half of
//! `net_socket.c`. The daemon initiates a TCP connection to each
//! `ConnectTo` peer; on failure, exponential backoff and retry.
//!
//! Ported: `do_outgoing_connection` (`:564-662`, the `goto begin`
//! loop), `setup_outgoing_connection` (`:664-681`), `retry_outgoing`
//! (`:405-417`), `finish_connecting` (`:419-426`), the connecting
//! branch of `handle_meta_io` (`:517-555`, the EINPROGRESS dance).
//!
//! ## The async-connect dance
//!
//! Nonblocking `connect()` returns `EINPROGRESS` immediately; you
//! `epoll` for WRITE; when writable, `send(fd, NULL, 0, 0)` probes
//! whether the connect actually succeeded. The C's platform-behavior
//! table (`:520-528`):
//!
//! | Event      | POSIX     | Linux       | Windows   |
//! |------------|-----------|-------------|-----------|
//! | Spurious   | ENOTCONN  | EWOULDBLOCK | ENOTCONN  |
//! | Failed     | ENOTCONN  | (cause)     | ENOTCONN  |
//! | Successful | (success) | (success)   | (success) |
//!
//! On `ENOTCONN`, `getsockopt(SO_ERROR)` retrieves the real cause
//! (`ECONNREFUSED`, `EHOSTUNREACH`, etc). socket2's `Socket::take_
//! error()` wraps this.
//!
//! ## socket2, no new shim
//!
//! Same call as `listen.rs`: socket2 gives the C's four-step shape
//! (`socket()` → `set_nonblocking` → `connect()` → register). All
//! used methods are ungated. The `Socket` is consumed into `OwnedFd`
//! after the connect probe succeeds — same as `configure_tcp`.
//!
//! ## Deferred
//!
//! - Proxy modes (`PROXY_EXEC`/`SOCKS4/5`/`HTTP`): ~100 LOC of
//!   socketpair+fork (`:588-598,601,631-639`). STUB(chunk-10).
//! - `bind_to_interface`/`bind_to_address` (`:624-625`): the
//!   `BindToAddress` config knob. Chunk 10.
//! - DNS at connect time: `addrcache.rs` doc says we take pre-
//!   resolved `SocketAddr` only. `try_outgoing_connections` resolves
//!   `Address = host port` lines via `to_socket_addrs()` at OPEN
//!   time (blocking DNS in setup, fine).

#![forbid(unsafe_code)]

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use slotmap::new_key_type;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::addrcache::AddressCache;

new_key_type! {
    /// `outgoing_t*`. Slotmap key for `Daemon.outgoings`. Carried
    /// in `TimerWhat::RetryOutgoing(OutgoingId)` and on
    /// `Connection.outgoing` so `terminate` knows to retry.
    pub struct OutgoingId;
}

/// `outgoing_t` (`net.h:121-125`). Three fields in C: `node_t *node`,
/// `int timeout`, `timeout_t ev`. We store the node NAME (not a
/// `NodeId` — outgoings are config-derived, the node might not exist
/// in the graph yet), the backoff seconds, and the address cache.
///
/// C hangs `address_cache` on `node_t` (`node.h:108`); only outgoings
/// ever read it. Per-outgoing is the natural home.
pub struct Outgoing {
    /// `outgoing->node->name`. The `ConnectTo = bob` value.
    pub node_name: String,
    /// `outgoing->timeout`. Exponential backoff seconds. `retry_
    /// outgoing` (`:406`) adds 5, caps at `maxtimeout` (default 900,
    /// `net_setup.c:533`). C: `int`, starts 0 (`xzalloc`).
    pub timeout: u32,
    /// `outgoing->node->address_cache`. Tries cached-recent then
    /// config `Address` lines. `next_addr()` walks; `reset()` on
    /// retry; `add_recent()` on connect success.
    pub addr_cache: AddressCache,
}

/// `MaxTimeout` default (`net_setup.c:533`). C: `maxtimeout = 900`.
/// 15 minutes. The retry backoff caps here.
pub const MAX_TIMEOUT_DEFAULT: u32 = 900;

impl Outgoing {
    /// `retry_outgoing` arithmetic (`net_socket.c:406-410`). Bumps
    /// `timeout += 5`, caps at `maxtimeout`. The TIMER ARM (`:412`)
    /// lives in the daemon (it owns `Timers`).
    ///
    /// Returns the new timeout for the caller to arm.
    pub fn bump_timeout(&mut self, maxtimeout: u32) -> u32 {
        // C `:406-410`: `outgoing->timeout += 5; if(> maxtimeout)
        // outgoing->timeout = maxtimeout`.
        self.timeout = (self.timeout + 5).min(maxtimeout);
        self.timeout
    }
}

/// Result of one connect attempt. The `goto begin` loop in
/// `do_outgoing_connection` (`:564-662`) expressed as an enum so the
/// daemon can drive the loop without `goto`.
#[derive(Debug)]
pub enum ConnectAttempt {
    /// `connect()` returned 0 OR `EINPROGRESS`. The socket is
    /// registered for WRITE; the connecting probe finishes it.
    /// C `:649-658`.
    Started { sock: Socket, addr: SocketAddr },
    /// This addr failed (socket creation or immediate connect
    /// error). C `:605-608,644-648`: `goto begin` to try next addr.
    /// The error is logged here; caller loops.
    Retry,
    /// Addr cache exhausted. C `:572-575`: `retry_outgoing`. Caller
    /// arms the backoff timer.
    Exhausted,
}

/// One iteration of `do_outgoing_connection`'s `goto begin` loop.
/// Creates a socket, sets nonblocking, calls `connect()`. The daemon
/// loops this until `Started` or `Exhausted`.
///
/// C `:564-662`, `proxytype == NONE` path only. Proxy modes are
/// chunk 10.
pub fn try_connect(addr_cache: &mut AddressCache, node_name: &str) -> ConnectAttempt {
    // C `:570`: `sa = get_recent_address(outgoing->node->address_cache)`.
    let Some(addr) = addr_cache.next_addr() else {
        // C `:572-575`: "Could not set up a meta connection".
        log::error!(target: "tincd::conn",
                    "Could not set up a meta connection to {node_name}");
        return ConnectAttempt::Exhausted;
    };

    // C `:580-581`: `c->hostname = sockaddr2hostname(&c->address)`.
    // Logged at `:583` as `"Trying to connect to %s (%s)"`.
    log::info!(target: "tincd::conn",
               "Trying to connect to {node_name} ({addr})");

    // C `:586`: `socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP)`.
    // socket2 auto-sets CLOEXEC (closes the C's `:611` FD_CLOEXEC fcntl).
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            // C `:605-608`: "Creating socket for %s failed".
            log::error!(target: "tincd::conn",
                        "Creating socket for {addr} failed: {e}");
            return ConnectAttempt::Retry;
        }
    };

    // C `:587`: `configure_tcp(c)`. NONBLOCK + NODELAY. NONBLOCK
    // BEFORE connect — that's what makes connect() return
    // EINPROGRESS instead of blocking. The C's `configure_tcp`
    // (`:71-76`) does it via fcntl; same effect.
    if let Err(e) = sock.set_nonblocking(true) {
        log::error!(target: "tincd::conn",
                    "set_nonblocking failed for {addr}: {e}");
        return ConnectAttempt::Retry;
    }
    if let Err(e) = sock.set_nodelay(true) {
        // C `:89` ignores the return value. Warn.
        log::warn!(target: "tincd::conn", "TCP_NODELAY: {e}");
    }

    // C `:616-621`: IPV6_V6ONLY for v6 sockets. We're CONNECTING,
    // not binding; V6ONLY only matters for dual-stack listeners.
    // The C sets it anyway (defensive against weird kernels). Match.
    if matches!(addr, SocketAddr::V6(_)) {
        let _ = sock.set_only_v6(true);
    }

    // STUB(chunk-10): bind_to_interface/bind_to_address (`:624-625`).
    // The `BindToAddress` config knob. Niche.

    // C `:630`: `connect(c->socket, &c->address.sa, salen)`.
    // socket2 wraps this. Nonblocking → returns EINPROGRESS for
    // anything other than loopback (which might connect synchronously).
    let sock_addr = SockAddr::from(addr);
    match sock.connect(&sock_addr) {
        Ok(()) => {
            // Immediate success. Loopback can do this. C `:641` —
            // `result == 0` falls through to `:649-658`.
        }
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
            // Normal nonblocking-connect-started. C `:641`:
            // `result == -1 && sockinprogress(sockerrno)` — the
            // `!` makes it FALSE, falls through to `:649-658`.
        }
        Err(e) => {
            // C `:642-648`: "Could not connect to %s (%s)".
            // `goto begin`. The error here is immediate (e.g.
            // ENETUNREACH for an unroutable addr).
            log::error!(target: "tincd::conn",
                        "Could not connect to {node_name} ({addr}): {e}");
            return ConnectAttempt::Retry;
        }
    }

    // C `:649-658`: register for IO_READ | IO_WRITE. The daemon
    // does the registration (it owns the EventLoop). We hand back
    // the socket + addr.
    ConnectAttempt::Started { sock, addr }
}

/// `handle_meta_io` connecting branch (`net_socket.c:517-555`). Probe
/// the async connect: `send(fd, NULL, 0, 0)` returns 0 on success,
/// `EWOULDBLOCK` on spurious wakeup (Linux), `ENOTCONN` on failure
/// (POSIX) — in which case `getsockopt(SO_ERROR)` gets the cause.
///
/// `Ok(true)` → connected; caller does `finish_connecting`.
/// `Ok(false)` → spurious wakeup, stay registered for WRITE.
///
/// # Errors
/// Connect failed (`ECONNREFUSED`, `EHOSTUNREACH`, etc). Caller
/// terminates and retries the next addr.
pub fn probe_connecting(sock: &Socket) -> io::Result<bool> {
    // C `:531`: `if(send(c->socket, NULL, 0, 0) != 0)`. socket2's
    // `send(&[])` does the same — a zero-byte write that touches
    // the connection state without sending data.
    match sock.send(&[]) {
        Ok(_) => {
            // C `:553-554`: `c->status.connecting = false`.
            // Connected. `_` not `0`: send() returns bytes sent;
            // we sent 0, so it's 0. Don't pin that.
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            // C `:533-535`: `if(sockwouldblock(sockerrno)) return`.
            // Linux-specific spurious wakeup. Stay registered.
            Ok(false)
        }
        Err(e) => {
            // C `:537-551`. Either the immediate error IS the cause
            // (Linux: ECONNREFUSED bubbles up directly), or it's
            // ENOTCONN and we read SO_ERROR for the real cause.
            //
            // C `:539`: `if(!socknotconn(sockerrno)) socket_error =
            // sockerrno`. socknotconn is `errno == ENOTCONN`.
            let cause = if e.raw_os_error() == Some(libc::ENOTCONN) {
                // C `:541-543`: `getsockopt(SOL_SOCKET, SO_ERROR)`.
                // socket2's `take_error()` wraps this. `Ok(None)`
                // means SO_ERROR was 0 — shouldn't happen here
                // (we got ENOTCONN from send, SOMETHING failed).
                // C `:545` checks `if(socket_error)`; if 0, falls
                // through to `:550 return` (no log, no terminate).
                // We treat it as spurious too.
                match sock.take_error() {
                    Ok(Some(cause)) => cause,
                    Ok(None) => return Ok(false), // C `:545` fallthrough
                    Err(ge) => ge,                // getsockopt itself failed; use that
                }
            } else {
                e
            };
            Err(cause)
        }
    }
}

/// Resolve `Address = host port` lines from `hosts/NAME` to
/// `SocketAddr`s. C `address_cache.c:154-199` does this lazily
/// inside `get_recent_address` via `str2addrinfo`; we do it
/// eagerly at open time. Blocking DNS in setup; fine.
///
/// `Address = 10.0.0.1 655` → one addr. `Address = bob.example.com
/// 655` → `to_socket_addrs()` resolves (may return v4+v6). `Address`
/// without a port defaults to 655 (`net_setup.c:789`).
///
/// Unparseable / unresolvable lines warn-and-skip. C: `getaddrinfo`
/// failure inside `str2addrinfo` returns NULL, the caller's loop
/// moves to the next config line.
#[must_use]
pub fn resolve_config_addrs(confbase: &Path, node_name: &str) -> Vec<SocketAddr> {
    let host_file = confbase.join("hosts").join(node_name);
    let Ok(entries) = tinc_conf::parse_file(&host_file) else {
        // No hosts/NAME file. The cache file (if any) is the only
        // source. C: `read_host_config` returns false; the address
        // cache walk falls through to `cache->cfg = NULL` and the
        // config phase yields nothing.
        log::warn!(target: "tincd::conn",
                   "hosts/{node_name} not readable; no Address config");
        return Vec::new();
    };
    let mut cfg = tinc_conf::Config::new();
    cfg.merge(entries);

    let mut addrs = Vec::new();
    for e in cfg.lookup("Address") {
        // C `address_cache.c:157-159`: `get_config_string(cfg,
        // &address); port = strchr(address, ' ')` — same `host port`
        // shape as everywhere else in tinc. Missing port → default
        // 655 (`:165-166` `if(!port) port = "655"`).
        let s = e.get_str();
        let mut parts = s.splitn(2, ' ');
        let host = parts.next().unwrap_or("");
        let port = parts.next().unwrap_or("655");
        // `to_socket_addrs()` is `getaddrinfo` with `AI_NUMERICSERV`
        // when port is numeric. Handles both numeric IPs (no DNS
        // hit) and hostnames (blocking DNS).
        match (host, port.parse::<u16>().ok()) {
            (h, Some(p)) if !h.is_empty() => match (h, p).to_socket_addrs() {
                Ok(iter) => addrs.extend(iter),
                Err(e) => {
                    log::warn!(target: "tincd::conn",
                               "Address = {s} for {node_name}: {e}");
                }
            },
            _ => {
                log::warn!(target: "tincd::conn",
                           "Address = {s} for {node_name}: bad format");
            }
        }
    }
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `retry_outgoing` arithmetic (`net_socket.c:406-410`): +5 each
    /// time, capped at `maxtimeout`. C `:406`: `outgoing->timeout
    /// += 5`. C `:408-410`: `if(> maxtimeout) = maxtimeout`.
    #[test]
    fn bump_timeout_backoff() {
        let mut o = Outgoing {
            node_name: "bob".into(),
            timeout: 0,
            addr_cache: AddressCache::new(vec![]),
        };
        // Starts at 0 (xzalloc). First bump: 5.
        assert_eq!(o.bump_timeout(900), 5);
        assert_eq!(o.bump_timeout(900), 10);
        assert_eq!(o.bump_timeout(900), 15);
        // Jump near the cap.
        o.timeout = 895;
        assert_eq!(o.bump_timeout(900), 900);
        // At cap: stays.
        assert_eq!(o.bump_timeout(900), 900);
        assert_eq!(o.bump_timeout(900), 900);
    }

    /// `Address = 127.0.0.1 12345` parses literally. No DNS.
    #[test]
    fn resolve_literal_v4() {
        let tmp = std::env::temp_dir().join(format!(
            "tincd-outgoing-resolve-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("hosts")).unwrap();
        std::fs::write(tmp.join("hosts").join("bob"), "Address = 127.0.0.1 12345\n").unwrap();

        let addrs = resolve_config_addrs(&tmp, "bob");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "127.0.0.1:12345".parse().unwrap());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `Address` without a port defaults to 655 (`net_setup.c:789`).
    #[test]
    fn resolve_default_port() {
        let tmp = std::env::temp_dir().join(format!(
            "tincd-outgoing-defport-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("hosts")).unwrap();
        std::fs::write(tmp.join("hosts").join("bob"), "Address = 127.0.0.1\n").unwrap();

        let addrs = resolve_config_addrs(&tmp, "bob");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "127.0.0.1:655".parse().unwrap());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Missing `hosts/NAME` → empty. C: `read_host_config` returns
    /// false; the config phase of `get_recent_address` yields nothing.
    #[test]
    fn resolve_missing_file() {
        let tmp = std::env::temp_dir().join(format!(
            "tincd-outgoing-missing-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // No hosts/ dir at all.

        let addrs = resolve_config_addrs(&tmp, "bob");
        assert!(addrs.is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `probe_connecting` on a freshly-connected loopback socket
    /// returns `Ok(true)`. socket2's `connect()` to a listening
    /// loopback addr usually succeeds synchronously (no EINPROGRESS).
    #[test]
    fn probe_connected_loopback() {
        // Listener on port 0.
        let listener =
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("socket");
        listener
            .bind(&SockAddr::from(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ))
            .expect("bind");
        listener.listen(1).expect("listen");
        let addr = listener.local_addr().unwrap().as_socket().expect("v4 addr");

        // Connect. Blocking (probe_connecting works on connected
        // sockets too — `send(fd, NULL, 0, 0)` is fine on any
        // connected stream).
        let client =
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("client socket");
        client.connect(&SockAddr::from(addr)).expect("connect");

        // Probe: should report connected.
        match probe_connecting(&client) {
            Ok(true) => {}
            other => panic!("expected Ok(true), got {other:?}"),
        }
    }

    /// `probe_connecting` on a refused connection returns `Err`. The
    /// error is `ECONNREFUSED` (Linux: bubbles up from `send` directly;
    /// POSIX: `ENOTCONN` then `SO_ERROR` reads ECONNREFUSED).
    #[test]
    fn probe_refused() {
        // Bind a port, get its number, close — nothing listens.
        let port = {
            let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            s.bind(&SockAddr::from(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ))
            .unwrap();
            s.local_addr().unwrap().as_socket().unwrap().port()
        };
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let client = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        client.set_nonblocking(true).unwrap();
        // Nonblocking connect to a closed port: EINPROGRESS, then
        // the kernel discovers RST and sets SO_ERROR.
        let _ = client.connect(&SockAddr::from(addr));

        // Spin: the RST might not have landed yet. Poll the probe
        // until it returns Err or we time out (rare on loopback).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match probe_connecting(&client) {
                Ok(false) => {
                    // Spurious / not yet. Retry.
                    assert!(
                        std::time::Instant::now() <= deadline,
                        "probe never resolved"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(true) => panic!("connected to a closed port?"),
                Err(e) => {
                    // ECONNREFUSED (Linux: 111). Don't pin the
                    // numeric value (BSD differs); pin the kind.
                    assert_eq!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused,
                        "expected refused, got {e:?}"
                    );
                    break;
                }
            }
        }
    }
}
