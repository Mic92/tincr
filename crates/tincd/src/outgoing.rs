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
//! ## PROXY_EXEC (`do_outgoing_pipe`, `:428-483`)
//!
//! `socketpair(AF_UNIX, SOCK_STREAM)` + `fork`. Child dup2's its end
//! to stdin/stdout, exec's `/bin/sh -c <cmd>`. Parent treats its end
//! as the TCP fd — the child IS the proxy. No byte-format handshake
//! (that's SOCKS4/5, `STUB(chunk-11-proxy)`).
//!
//! The ONE `unsafe` block in this module: `fork()`. Post-fork in a
//! multi-threaded program is hairy (only the calling thread survives;
//! held locks deadlock), so the child does **libc-only** until exec.
//! No `std`, no `format!`, no allocator. The C does the same dance.
//!
//! ## Deferred
//!
//! - SOCKS4/5/HTTP proxy: needs a connect-state machine in `conn.rs`
//!   (read `tcplen` bytes BEFORE the id_h dispatch). `socks.rs` has
//!   the byte format; the wiring is `STUB(chunk-11-proxy)`.
//! - `bind_to_interface`/`bind_to_address` (`:624-625`): the
//!   `BindToAddress` config knob. `STUB(chunk-11-proxy)`.
//! - DNS at connect time: `addrcache.rs` doc says we take pre-
//!   resolved `SocketAddr` only. `try_outgoing_connections` resolves
//!   `Address = host port` lines via `to_socket_addrs()` at OPEN
//!   time (blocking DNS in setup, fine).

// No `forbid(unsafe)`: do_outgoing_pipe needs fork(). The unsafe is
// scoped to one block; the rest of the module is still allocation-
// only. lib.rs has `deny(unsafe_code)`; the block has #[allow].

use std::ffi::CString;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{FromRawFd, OwnedFd};
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

    // STUB(chunk-11-proxy): bind_to_interface/bind_to_address
    // (`:624-625`). The `BindToAddress` config knob. Niche.

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

/// `proxytype_t` (`net.h:148-155`). Only `Exec` is wired; the rest
/// need a connect-time state machine (read N bytes before id_h —
/// `c->tcplen`). `socks.rs` has the byte formats.
#[derive(Debug, Clone)]
pub enum ProxyConfig {
    /// `PROXY_EXEC` (`net_socket.c:588`). `socketpair` + `fork` +
    /// `/bin/sh -c <cmd>`. The simple mode: no handshake bytes.
    Exec { cmd: String },
    // STUB(chunk-11-proxy): Socks4 { host, port, user },
    // Socks5 { host, port, user, pass }, Http { host, port }.
}

/// Parse `Proxy = type [args...]` (`net_setup.c:263-345`). Returns
/// `Ok(None)` for `Proxy = none` and missing config; `Err` for
/// unknown types and types we don't support yet (SOCKS/HTTP).
///
/// # Errors
/// String describing why the config is invalid (unknown type, missing
/// arg, or unsupported type). The caller (`setup()`) wraps this in
/// `SetupError::Config`.
pub fn parse_proxy_config(value: &str) -> Result<Option<ProxyConfig>, String> {
    // C `:266-271`: `space = strchr(proxy, ' '); if(space) *space++=0`.
    // First word is the type, rest is args.
    let mut parts = value.splitn(2, ' ');
    let kind = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("");

    match kind.to_ascii_lowercase().as_str() {
        "none" | "" => Ok(None),
        "exec" => {
            // C `:313-318`: `if(!space || !*space) ERR "Argument
            // expected"`.
            if args.is_empty() {
                return Err("Argument expected for Proxy = exec".into());
            }
            Ok(Some(ProxyConfig::Exec {
                cmd: args.to_owned(),
            }))
        }
        // STUB(chunk-11-proxy): socks4/socks4a/socks5/http need the
        // tcplen state machine in conn.rs (read N bytes before id_h).
        "socks4" | "socks4a" | "socks5" | "http" => Err(format!(
            "Proxy = {kind} not yet supported (only 'exec' is wired)"
        )),
        other => Err(format!("Unknown proxy type: {other}")),
    }
}

/// `do_outgoing_pipe` (`net_socket.c:428-483`). `socketpair(AF_UNIX,
/// SOCK_STREAM)` + `fork`. Child dup2's `sock[1]` to fds 0 and 1,
/// runs `/bin/sh -c <cmd>`. Parent gets `sock[0]` as an `OwnedFd`
/// that acts like a connected TCP socket.
///
/// `addr`/`node_name`/`my_name`: for the child's environment
/// (`REMOTEADDRESS`, `REMOTEPORT`, `NODE`, `NAME`). C `:455-465`.
/// The proxy script reads these to know where to connect.
///
/// ## Why `unsafe`
///
/// `fork()` in a multi-threaded program is dangerous: only the
/// calling thread survives in the child; if any other thread held a
/// lock at fork time (allocator, log buffer, anything), the child
/// inherits the locked state and deadlocks on first touch. The
/// standard mitigation is `exec()` immediately, before touching
/// any std/allocator state. The child here does exactly that:
/// libc-only (`close`, `dup2`, `setsid`, `setenv`, `execvp`,
/// `_exit`). The `CString` allocations happen in the PARENT before
/// the fork; the child only borrows their `.as_ptr()`.
///
/// The C `do_outgoing_pipe` doesn't have this problem (tincd is
/// single-threaded), but our test harness might be multi-threaded
/// (cargo-nextest spawns threads). We're paranoid for free.
///
/// # Errors
/// `socketpair` or `fork` syscall failure. The child's `exec`
/// failure is signaled via `_exit(1)` → the parent's read returns
/// EOF → normal terminate path.
///
/// # Panics
/// If `cmd`, `my_name`, or `node_name` contain interior NUL bytes
/// (`CString::new` panics). They're config-derived strings; NUL
/// would have been rejected by `tinc_conf` parsing already.
pub fn do_outgoing_pipe(
    cmd: &str,
    addr: SocketAddr,
    node_name: &str,
    my_name: &str,
) -> io::Result<OwnedFd> {
    // Pre-allocate ALL strings the child needs, BEFORE fork. The
    // child only does libc:: pointer ops. CString panics on interior
    // NUL; cmd is user config, node_name is `check_id`-validated,
    // my_name is `Name = ` from tinc.conf (also `check_id`).
    let sh = CString::new("/bin/sh").unwrap();
    let dash_c = CString::new("-c").unwrap();
    let cmd_c = CString::new(cmd).expect("proxy cmd has interior NUL");
    let argv = [
        sh.as_ptr(),
        dash_c.as_ptr(),
        cmd_c.as_ptr(),
        core::ptr::null(),
    ];

    // C `:455-460`: setenv("REMOTEADDRESS", host); setenv("REMOTEPORT",
    // port); etc. The child does these post-fork (it has its own env
    // copy). We pre-format the strings; child setenv's the pointers.
    let remote_addr = CString::new(addr.ip().to_string()).unwrap();
    let remote_port = CString::new(addr.port().to_string()).unwrap();
    let name_env = CString::new(my_name).expect("my_name has interior NUL");
    let node_env = CString::new(node_name).expect("node_name has interior NUL");
    let k_remote_addr = CString::new("REMOTEADDRESS").unwrap();
    let k_remote_port = CString::new("REMOTEPORT").unwrap();
    let k_name = CString::new("NAME").unwrap();
    let k_node = CString::new("NODE").unwrap();

    // SAFETY: see fn doc. The child does libc-only until exec.
    // Everything that allocates was done above, in the parent.
    #[allow(unsafe_code)]
    unsafe {
        // C `:432`: `socketpair(AF_UNIX, SOCK_STREAM, 0, fd)`.
        let mut fds = [-1i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let (parent_fd, child_fd) = (fds[0], fds[1]);

        // C `:437-442`: `if(fork()) { ... parent ... return; }`.
        // The C doesn't check for fork failure (`-1`); we do.
        match libc::fork() {
            -1 => {
                let e = io::Error::last_os_error();
                libc::close(parent_fd);
                libc::close(child_fd);
                Err(e)
            }
            0 => {
                // ────── CHILD ──────
                // libc-only until exec. NO std (locks could be held).

                // C `:444-449`: close(0), close(1), close(fd[0]),
                // dup2(fd[1], 0), dup2(fd[1], 1), close(fd[1]).
                libc::close(0);
                libc::close(1);
                libc::close(parent_fd);
                libc::dup2(child_fd, 0);
                libc::dup2(child_fd, 1);
                libc::close(child_fd);

                // C `:451`: `setsid()`. Detach from controlling tty.
                // The proxy script shouldn't get our SIGINT.
                libc::setsid();

                // C `:455-465`: setenv. NETNAME omitted (not threaded
                // through the daemon yet; same as run_script).
                libc::setenv(k_remote_addr.as_ptr(), remote_addr.as_ptr(), 1);
                libc::setenv(k_remote_port.as_ptr(), remote_port.as_ptr(), 1);
                libc::setenv(k_name.as_ptr(), name_env.as_ptr(), 1);
                libc::setenv(k_node.as_ptr(), node_env.as_ptr(), 1);

                // C `:469`: `system(command)` then `:477` `exit(result)`.
                // We use execvp (replaces the process image entirely;
                // no double-fork from system()'s internal fork).
                // `/bin/sh -c <cmd>` is what system() does anyway.
                libc::execvp(sh.as_ptr(), argv.as_ptr());

                // execvp returned → failed. _exit (NOT exit — exit()
                // runs atexit handlers, which might allocate).
                libc::_exit(1);
            }
            _pid => {
                // ────── PARENT ──────
                // C `:438-441`: `c->socket = fd[0]; close(fd[1]);
                // return`. Don't waitpid — the child is detached.
                // If it dies, parent's read returns EOF and the
                // normal terminate path fires. The zombie reaper:
                // SIGCHLD is SIG_DFL; init eventually reaps after
                // we exit. Same as the C (which also doesn't wait).
                libc::close(child_fd);
                // SAFETY: parent_fd is a valid fd from socketpair,
                // ownership not aliased (child_fd closed, child
                // process has its own copies via dup2).
                Ok(OwnedFd::from_raw_fd(parent_fd))
            }
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

    /// `Proxy = exec <cmd>` parses; `Proxy = socks5 ...` rejects
    /// (not yet wired); `Proxy = none` is `Ok(None)`.
    #[test]
    fn proxy_config_parse() {
        // exec with cmd.
        let r = parse_proxy_config("exec /usr/bin/foo --bar").unwrap();
        let Some(ProxyConfig::Exec { cmd }) = r else {
            panic!("expected Exec")
        };
        assert_eq!(cmd, "/usr/bin/foo --bar");

        // exec without cmd → error.
        assert!(parse_proxy_config("exec").is_err());
        assert!(parse_proxy_config("exec ").is_err()); // splitn gives ""

        // none / empty → None.
        assert!(parse_proxy_config("none").unwrap().is_none());
        assert!(parse_proxy_config("").unwrap().is_none());

        // case-insensitive.
        assert!(matches!(
            parse_proxy_config("EXEC cat").unwrap(),
            Some(ProxyConfig::Exec { .. })
        ));

        // unsupported (yet).
        assert!(parse_proxy_config("socks4 localhost 1080").is_err());
        assert!(parse_proxy_config("socks5 localhost 1080").is_err());
        assert!(parse_proxy_config("http localhost 8080").is_err());

        // unknown.
        assert!(parse_proxy_config("carrier-pigeon").is_err());
    }

    /// `do_outgoing_pipe("cat")`: write bytes, read them back.
    /// Proves the socketpair + fork + dup2 + exec chain. cat reads
    /// stdin (= sock[1]) and writes stdout (= sock[1]); the parent
    /// sees both directions on sock[0].
    #[test]
    fn proxy_exec_roundtrip() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;

        let fd = do_outgoing_pipe("cat", "127.0.0.1:655".parse().unwrap(), "bob", "alice")
            .expect("do_outgoing_pipe");

        // Wrap in a UnixStream for ergonomic read/write. SAFETY:
        // fd is a valid AF_UNIX SOCK_STREAM; UnixStream is the
        // right wrapper. The OwnedFd is consumed (no double-close).
        let raw = fd.as_raw_fd();
        std::mem::forget(fd); // UnixStream takes ownership of raw
        // SAFETY: raw is a valid AF_UNIX stream socket fd, just
        // returned from do_outgoing_pipe; ownership transferred
        // (fd was forgotten above so no double-close).
        #[allow(unsafe_code)]
        let mut stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw) };

        // Write → cat echoes → read back. Set a timeout so a hung
        // child (exec failed, fd half-open) doesn't wedge the test.
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        let payload = b"hello proxy exec\n";
        stream.write_all(payload).expect("write");

        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, payload);

        // Second roundtrip: proves the pipe stays open.
        stream.write_all(b"again\n").unwrap();
        let mut buf2 = [0u8; 6];
        stream.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2, b"again\n");
    }

    /// Env vars are set in the child. The cmd is a shell snippet
    /// that echoes them; we read them back through the pipe.
    #[test]
    fn proxy_exec_env() {
        use std::io::{BufRead, BufReader};
        use std::os::fd::AsRawFd;

        let fd = do_outgoing_pipe(
            "echo \"$NAME $NODE $REMOTEADDRESS $REMOTEPORT\"",
            "10.0.0.1:12345".parse().unwrap(),
            "bob",
            "alice",
        )
        .expect("do_outgoing_pipe");

        let raw = fd.as_raw_fd();
        std::mem::forget(fd);
        // SAFETY: same as proxy_exec_roundtrip.
        #[allow(unsafe_code)]
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw) };
        let mut r = BufReader::new(stream);
        let mut line = String::new();
        r.read_line(&mut line).expect("read env line");
        assert_eq!(line.trim_end(), "alice bob 10.0.0.1 12345");
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
