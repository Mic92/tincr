//! Outgoing TCP connections to `ConnectTo` peers, with the address
//! list, exponential backoff and the optional `PROXY_EXEC` subprocess
//! all in one place.
//!
//! Each peer has an `outgoing` slot that walks its configured address
//! list (resolved lazily through [`addrcache`](crate::addrcache)),
//! opens a non-blocking socket via `socket2`, optionally binds it via
//! [`apply_dial_sockopts`] (`bind_to_address`, `bind_to_interface`,
//! `SO_MARK`; failures are warn-only on the dial side) and then runs
//! the standard async-connect dance: `connect()` returns
//! `EINPROGRESS`, the loop arms a writable wakeup, and on wakeup it
//! either reads a fresh `SO_ERROR` via `getsockopt(SocketError)` or
//! treats a successful zero-byte probe as the connect having landed. On any
//! failure the slot advances to the next address, and once the list
//! is exhausted it sleeps with exponential backoff before retrying
//! from the top.
//!
//! `PROXY_EXEC` is the one place this module reaches for `unsafe`:
//! it creates a `socketpair`, `fork`s, and the child `dup2`s its end
//! onto stdin/stdout and `execve`s `/bin/sh -c <cmd>`, so the parent
//! ends up holding a plain stream socket whose other end is the proxy
//! process. The child path between `fork` and `exec` is libc-only
//! — no `std`, no allocator, no formatting — because the surviving
//! thread inherits arbitrary held locks from the multi-threaded
//! parent.

use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, getsockopt, send, sockopt};
use slotmap::new_key_type;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::addrcache::AddressCache;
use crate::listen::SockOpts;

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
/// Why this `Outgoing` slot exists. autoconnect's drop logic must
/// distinguish demand-driven shortcuts (eligible for idle-reap) from
/// the random degree-3 backbone (only dropped when `nc > D_HI`).
/// `ConfigConnectTo` is currently treated like `AutoBackbone` for
/// `CancelPending` (see `AutoAction::CancelPending` doc) — carrying
/// the provenance now lets that be tightened later without another
/// plumbing pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum OutOrigin {
    /// `ConnectTo =` in `tinc.conf` (setup or reload).
    #[default]
    ConfigConnectTo,
    /// `make_new_connection` / `connect_to_unreachable` — the random
    /// degree-3 resilience backbone.
    AutoBackbone,
    /// Demand-driven: peer we're actively relaying >`RELAY_HI` for.
    AutoShortcut,
}

/// C hangs `address_cache` on `node_t` (`node.h:108`); only outgoings
/// ever read it. Per-outgoing is the natural home.
pub(crate) struct Outgoing {
    /// `outgoing->node->name`. The `ConnectTo = bob` value.
    pub node_name: String,
    /// Provenance. Read by `decide_autoconnect`'s drop arm.
    pub origin: OutOrigin,
    /// `outgoing->timeout`. Exponential backoff seconds. `retry_
    /// outgoing` adds 5, caps at `maxtimeout` (default 900). Starts 0.
    pub timeout: u32,
    /// `outgoing->node->address_cache`. Tries cached-recent then
    /// config `Address` lines. `next_addr()` walks; `reset()` on
    /// retry; `add_recent()` on connect success.
    pub addr_cache: AddressCache,
}

/// `MaxTimeout` default: 900 = 15 minutes. The retry backoff caps here.
pub(crate) const MAX_TIMEOUT_DEFAULT: u32 = 900;

impl Outgoing {
    /// `retry_outgoing` arithmetic. Bumps `timeout += 5`, caps at
    /// `maxtimeout`. The TIMER ARM
    /// lives in the daemon (it owns `Timers`).
    ///
    /// Returns the new timeout for the caller to arm.
    pub(crate) fn bump_timeout(&mut self, maxtimeout: u32) -> u32 {
        self.timeout = (self.timeout + 5).min(maxtimeout);
        self.timeout
    }
}

/// Result of one connect attempt. The `goto begin` loop in
/// `do_outgoing_connection` (`:564-662`) expressed as an enum so the
/// daemon can drive the loop without `goto`.
#[derive(Debug)]
pub(crate) enum ConnectAttempt {
    /// `connect()` returned 0 OR `EINPROGRESS`. The socket is
    /// registered for WRITE; the connecting probe finishes it.
    Started { sock: Socket, addr: SocketAddr },
    /// This addr failed (socket creation or immediate connect
    /// error). `goto begin` to try next addr. The error is logged
    /// here; caller loops.
    Retry,
    /// Addr cache exhausted. `retry_outgoing`. Caller arms the
    /// backoff timer.
    Exhausted,
}

/// `configure_tcp:104-106` (`SO_MARK`) + `do_outgoing_connection:623`
/// (`SO_BINDTODEVICE`). Shared by direct dial + SOCKS/HTTP proxy dial
/// (the `if(proxytype != PROXY_EXEC)` gate covers both).
///
/// Best-effort: `bind_to_interface`'s return value is discarded on
/// the dial path (only listen hard-fails). We match —
/// log + continue. Policy-routing setups get a warning; the connect
/// proceeds (kernel picks via routing table, same as no-bind).
fn apply_dial_sockopts(sock: &Socket, sockopts: &SockOpts) {
    // `if(fwmark) setsockopt(SO_MARK)`. 0 = unset = skip.
    #[cfg(target_os = "linux")]
    if sockopts.fwmark != 0 {
        use nix::sys::socket::{setsockopt, sockopt};
        use std::os::fd::AsFd;
        if let Err(e) = setsockopt(&sock.as_fd(), sockopt::Mark, &sockopts.fwmark) {
            log::warn!(target: "tincd::conn",
                       "SO_MARK={}: {e}", sockopts.fwmark);
        }
    }
    #[cfg(not(target_os = "linux"))]
    if sockopts.fwmark != 0 {
        log::warn!(target: "tincd::conn",
                   "FWMark={} ignored: SO_MARK is Linux-only", sockopts.fwmark);
    }
    // `bind_to_interface(c->socket)`. Return discarded.
    if let Some(iface) = &sockopts.bind_to_interface
        && let Err(e) = crate::bind_to_interface(sock, iface)
    {
        log::warn!(target: "tincd::conn", "{e}");
    }
}

/// Shared socket-create + nonblocking-connect sequence used by both
/// `try_connect` (direct) and `try_connect_via_proxy`. `desc` feeds the
/// log lines so the two callers keep their distinct messages. NONBLOCK
/// is set BEFORE `connect()` so it returns `EINPROGRESS` instead of
/// blocking; V6ONLY is set defensively (C parity); `bind_to` is
/// best-effort (warn+continue) because the route-table source may still
/// work.
fn dial_nonblocking(
    target: SocketAddr,
    bind_to: Option<SocketAddr>,
    sockopts: &SockOpts,
    desc: &dyn std::fmt::Display,
) -> Option<Socket> {
    let domain = match target {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => {
            crate::set_nosigpipe(&s);
            s
        }
        Err(e) => {
            log::error!(target: "tincd::conn",
                        "Creating socket for {desc} failed: {e}");
            return None;
        }
    };
    if let Err(e) = sock.set_nonblocking(true) {
        log::error!(target: "tincd::conn",
                    "set_nonblocking failed for {desc}: {e}");
        return None;
    }
    if let Err(e) = sock.set_nodelay(true) {
        log::warn!(target: "tincd::conn", "TCP_NODELAY: {e}");
    }
    if matches!(target, SocketAddr::V6(_)) {
        let _ = sock.set_only_v6(true);
    }
    // SO_MARK + bind_to_interface. BEFORE bind_to_address.
    apply_dial_sockopts(&sock, sockopts);
    if let Some(local) = bind_to
        && let Err(e) = sock.bind(&SockAddr::from(local))
    {
        log::warn!(target: "tincd::conn", "Can't bind to {local}: {e}");
    }
    match sock.connect(&SockAddr::from(target)) {
        // Immediate success (loopback) or normal EINPROGRESS.
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(Errno::EINPROGRESS as i32) => {}
        Err(e) => {
            log::error!(target: "tincd::conn",
                        "Could not connect to {desc}: {e}");
            return None;
        }
    }
    Some(sock)
}

/// One iteration of `do_outgoing_connection`'s `goto begin` loop.
/// Creates a socket, sets nonblocking, calls `connect()`. The daemon
/// loops this until `Started` or `Exhausted`.
///
/// `proxytype == NONE` path only. Proxy modes are chunk 10.
pub(crate) fn try_connect(
    addr_cache: &mut AddressCache,
    node_name: &str,
    bind_to: Option<SocketAddr>,
    sockopts: &SockOpts,
) -> ConnectAttempt {
    let Some(addr) = addr_cache.next_addr() else {
        log::error!(target: "tincd::conn",
                    "Could not set up a meta connection to {node_name}");
        return ConnectAttempt::Exhausted;
    };
    log::info!(target: "tincd::conn",
               "Trying to connect to {node_name} ({addr})");
    match dial_nonblocking(
        addr,
        bind_to,
        sockopts,
        &format_args!("{node_name} ({addr})"),
    ) {
        Some(sock) => ConnectAttempt::Started { sock, addr },
        None => ConnectAttempt::Retry,
    }
}

/// `do_outgoing_connection` proxy branch. Connects to `proxy_addr`
/// (pre-resolved off-thread), not the peer; `peer_addr` is stashed as
/// `c->address` for the later SOCKS/HTTP CONNECT. The proxy is a
/// single global config so any failure is `Exhausted`, never `Retry`.
#[must_use]
pub(crate) fn try_connect_via_proxy(
    proxy_addr: SocketAddr,
    peer_addr: SocketAddr,
    node_name: &str,
    sockopts: &SockOpts,
) -> ConnectAttempt {
    log::info!(target: "tincd::conn",
               "Using proxy at {proxy_addr} for {node_name} ({peer_addr})");
    // Proxy path never binds to a local addr (C: only direct does).
    match dial_nonblocking(
        proxy_addr,
        None,
        sockopts,
        &format_args!("proxy {proxy_addr} for {node_name}"),
    ) {
        // `addr` is the PEER addr (what `c->address` holds in C);
        // the SOCKS CONNECT target is built from it later.
        Some(sock) => ConnectAttempt::Started {
            sock,
            addr: peer_addr,
        },
        None => ConnectAttempt::Exhausted,
    }
}

/// `handle_meta_io` connecting branch. Probe the async connect:
/// `send(fd, NULL, 0, 0)` returns 0 on success,
/// `EWOULDBLOCK` on spurious wakeup (Linux), `ENOTCONN` on failure
/// (POSIX) — in which case `getsockopt(SO_ERROR)` gets the cause.
///
/// `Ok(true)` → connected; caller does `finish_connecting`.
/// `Ok(false)` → spurious wakeup, stay registered for WRITE.
///
/// # Errors
/// Connect failed (`ECONNREFUSED`, `EHOSTUNREACH`, etc). Caller
/// terminates and retries the next addr.
///
/// Takes `BorrowedFd`, not `&Socket`: the connecting fd is owned by
/// `Connection.fd` (the ONE owner). An earlier shape kept a separate
/// `socket2::Socket` around just for this probe, dup'd the fd into
/// `Connection`, and registered the dup with epoll — two fds on one
/// open-file-description. epoll keys on the description, so closing
/// only the dup left a stale interest → 100% CPU busy-loop on
/// ERR|HUP. One fd, one owner, no aliasing hazard.
pub(crate) fn probe_connecting(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // `if(send(c->socket, NULL, 0, 0) != 0)`. nix's `send(fd, &[],
    // empty)` does the same — a zero-byte write that touches the
    // connection state without sending data.
    match send(fd.as_raw_fd(), &[], MsgFlags::empty()) {
        Ok(_) => {
            // Connected. `_` not `0`: send() returns bytes sent;
            // we sent 0, so it's 0. Don't pin that.
            Ok(true)
        }
        Err(Errno::EAGAIN | Errno::EINPROGRESS) => {
            // Linux-specific spurious wakeup. Stay registered.
            Ok(false)
        }
        Err(Errno::ENOTCONN) => {
            // POSIX path: send() says ENOTCONN, real cause is in
            // SO_ERROR. `if(!socknotconn(sockerrno)) socket_error =
            // sockerrno` — socknotconn is `errno == ENOTCONN`.
            //
            // `getsockopt(SOL_SOCKET, SO_ERROR)`. 0 means SO_ERROR
            // was clear — shouldn't happen here (we got ENOTCONN,
            // SOMETHING failed). C's `if(socket_error)` falls
            // through (no log, no terminate); we treat as spurious.
            match getsockopt(&fd, sockopt::SocketError) {
                Ok(0) => Ok(false),
                Ok(errno) => Err(io::Error::from_raw_os_error(errno)),
                Err(ge) => Err(ge.into()), // getsockopt itself failed
            }
        }
        // Linux: ECONNREFUSED etc bubble up directly from send().
        // macOS: EPIPE from send() on a reset socket. The real
        // error is in SO_ERROR; read it like the ENOTCONN path.
        #[cfg(target_os = "macos")]
        Err(Errno::EPIPE) => match getsockopt(&fd, sockopt::SocketError) {
            Ok(0) => Ok(false),
            Ok(errno) => Err(io::Error::from_raw_os_error(errno)),
            Err(ge) => Err(ge.into()),
        },
        Err(e) => Err(e.into()),
    }
}

/// `proxytype_t` (`net.h:148-155`). C has six (`NONE`/`SOCKS4`/
/// `SOCKS4A`/`SOCKS5`/`HTTP`/`EXEC`); we have four. `NONE` is
/// `Option::None` at the `DaemonSettings.proxy` level. `SOCKS4A` is
/// faithfully unimplemented ("not implemented yet" upstream too).
#[derive(Debug, Clone)]
pub enum ProxyConfig {
    /// `PROXY_EXEC`. `socketpair` + `fork` +
    /// `/bin/sh -c <cmd>`. The simple mode: no handshake bytes.
    Exec { cmd: String },
    /// `PROXY_SOCKS4`. Connect to `{host}:{port}`, then send a
    /// SOCKS4 CONNECT request (`socks::build_request`) with the PEER
    /// addr as target. `user` is the SOCKS4 "userid" string
    /// (optional, no password — SOCKS4 has no real auth).
    Socks4 {
        host: String,
        port: u16,
        user: Option<String>,
    },
    /// `PROXY_SOCKS5`. RFC 1928. Same connect-to-proxy-addr shape.
    /// `user`+`pass` are RFC 1929 password auth; both `None` →
    /// anonymous (`socks::build_request` handles the method choice).
    Socks5 {
        host: String,
        port: u16,
        user: Option<String>,
        pass: Option<String>,
    },
    /// `PROXY_HTTP`. `CONNECT host:port HTTP/1.1\r\n\r\n`. Response
    /// is line-based (NOT `tcplen`-exact like SOCKS): `protocol.c:
    /// 148-161` special-cases the `HTTP/1.1 ` prefix in `receive_
    /// request` BEFORE the normal dispatch. See `metaconn.rs::
    /// on_conn_readable` HTTP intercept: gating on `allow_request
    /// == Id` is sufficient (the gate closes naturally when `id_h`
    /// runs); no separate `proxy_passed` flag needed.
    Http { host: String, port: u16 },
}

impl ProxyConfig {
    /// The proxy server's address, for `try_connect_via_proxy`.
    /// `Exec` has no proxy addr (the pipe IS the connection).
    #[must_use]
    pub const fn proxy_addr(&self) -> Option<(&str, u16)> {
        match self {
            Self::Exec { .. } => None,
            Self::Socks4 { host, port, .. }
            | Self::Socks5 { host, port, .. }
            | Self::Http { host, port } => Some((host.as_str(), *port)),
        }
    }

    /// Map to `socks::ProxyType` for `build_request`/`check_response`.
    /// `None` for non-SOCKS variants (Exec has no handshake; HTTP is
    /// line-based).
    #[must_use]
    pub const fn socks_type(&self) -> Option<crate::socks::ProxyType> {
        match self {
            Self::Socks4 { .. } => Some(crate::socks::ProxyType::Socks4),
            Self::Socks5 { .. } => Some(crate::socks::ProxyType::Socks5),
            Self::Exec { .. } | Self::Http { .. } => None,
        }
    }

    /// `socks::Creds` for `build_request`. SOCKS4 uses only `user`
    /// (the userid string). SOCKS5 uses both for password auth; if
    /// either is missing, anonymous (`socks.rs:192` matches the C's
    /// `proxyuser && proxypass` check).
    #[must_use]
    pub fn socks_creds(&self) -> Option<crate::socks::Creds> {
        match self {
            Self::Socks4 { user, .. } => user.clone().map(|u| crate::socks::Creds {
                user: u,
                pass: None,
            }),
            Self::Socks5 { user, pass, .. } => user.clone().map(|u| crate::socks::Creds {
                user: u,
                pass: pass.clone(),
            }),
            Self::Exec { .. } | Self::Http { .. } => None,
        }
    }
}

/// Parse `Proxy = type [args...]`. Returns `Ok(None)` for
/// `Proxy = none` and missing config; `Err` for
/// unknown types and types we don't support yet (SOCKS/HTTP).
///
/// # Errors
/// String describing why the config is invalid (unknown type, missing
/// arg, or unsupported type). The caller (`setup()`) wraps this in
/// `SetupError::Config`.
pub(crate) fn parse_proxy_config(value: &str) -> Result<Option<ProxyConfig>, String> {
    // First word is the type, rest is args.
    let mut parts = value.splitn(2, ' ');
    let kind = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("");

    match kind.to_ascii_lowercase().as_str() {
        "none" | "" => Ok(None),
        "exec" => {
            // `if(!space || !*space) ERR "Argument expected"`.
            if args.is_empty() {
                return Err("Argument expected for Proxy = exec".into());
            }
            Ok(Some(ProxyConfig::Exec {
                cmd: args.to_owned(),
            }))
        }
        // SOCKS4/4A/5/HTTP all share the same parse shape: walk
        // through `host port [user [pass]]`. `socks4a`: "not
        // implemented yet" upstream. Reject.
        "socks4a" => {
            Err("Proxy type socks4a not implemented (upstream tinc doesn't either)".into())
        }
        "socks4" | "socks5" | "http" => {
            // Walk space-separated tokens. We split_whitespace (handles
            // multiple spaces, same effect for valid input).
            let mut toks = args.split_whitespace();
            let host = toks.next().filter(|s| !s.is_empty());
            let port = toks.next().and_then(|s| s.parse::<u16>().ok());
            let (Some(host), Some(port)) = (host, port) else {
                // "Host and port argument expected".
                return Err(format!(
                    "Host and port argument expected for Proxy = {kind}"
                ));
            };
            // user/pass optional. Empty string → None (`if(proxyuser
            // && *proxyuser)` — the pointer-nonnull AND
            // deref-nonNUL idiom).
            let user = toks.next().filter(|s| !s.is_empty()).map(str::to_owned);
            let pass = toks.next().filter(|s| !s.is_empty()).map(str::to_owned);
            let host = host.to_owned();
            match kind.to_ascii_lowercase().as_str() {
                "socks4" => Ok(Some(ProxyConfig::Socks4 { host, port, user })),
                "socks5" => Ok(Some(ProxyConfig::Socks5 {
                    host,
                    port,
                    user,
                    pass,
                })),
                "http" => Ok(Some(ProxyConfig::Http { host, port })),
                _ => unreachable!(),
            }
        }
        other => Err(format!("Unknown proxy type: {other}")),
    }
}

/// `do_outgoing_pipe`. `socketpair(AF_UNIX, SOCK_STREAM)` + `fork`. Child dup2's `sock[1]` to fds 0 and 1,
/// runs `/bin/sh -c <cmd>`. Parent gets `sock[0]` as an `OwnedFd`
/// that acts like a connected TCP socket.
///
/// `addr`/`node_name`/`my_name`: for the child's environment
/// (`REMOTEADDRESS`, `REMOTEPORT`, `NODE`, `NAME`). The proxy
/// script reads these to know where to connect.
///
/// ## Why `unsafe`
///
/// `fork()` in a multi-threaded program is dangerous: only the
/// calling thread survives in the child; if any other thread held a
/// lock at fork time (allocator, log buffer, libc env lock), the child
/// inherits the locked state and deadlocks on first touch. The
/// standard mitigation is `exec()` immediately, before touching
/// any std/allocator state. The child here does exactly that:
/// libc-only (`close`, `dup2`, `setsid`, `execve`,
/// `_exit`). The `CString` allocations happen in the PARENT before
/// the fork; the child only borrows their `.as_ptr()`.
///
/// Upstream `do_outgoing_pipe` doesn't have this problem (tincd is
/// single-threaded), but our test harness might be multi-threaded
/// (cargo-nextest spawns threads). We're paranoid for free.
///
/// # Errors
/// `socketpair` or `fork` syscall failure. The child's `exec`
/// failure is signaled via `_exit(1)` → the parent's read returns
/// EOF → normal terminate path.
///
/// Interior NUL in `cmd`, `my_name` or `node_name` returns
/// `InvalidInput` rather than panicking.
#[allow(clippy::missing_panics_doc)] // unwraps are on NUL-free literals
pub(crate) fn do_outgoing_pipe(
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
    let nul_err = |s: &str| io::Error::new(io::ErrorKind::InvalidInput, s);
    let cmd_c = CString::new(cmd).map_err(|_| nul_err("proxy cmd has interior NUL"))?;
    let argv = [
        sh.as_ptr(),
        dash_c.as_ptr(),
        cmd_c.as_ptr(),
        core::ptr::null(),
    ];

    // Build the full envp BEFORE fork (setenv post-fork is not
    // async-signal-safe). Inherit parent env, override our four keys.
    let name_env =
        CString::new(format!("NAME={my_name}")).map_err(|_| nul_err("my_name has interior NUL"))?;
    let node_env = CString::new(format!("NODE={node_name}"))
        .map_err(|_| nul_err("node_name has interior NUL"))?;
    let ours = [
        CString::new(format!("REMOTEADDRESS={}", addr.ip())).unwrap(),
        CString::new(format!("REMOTEPORT={}", addr.port())).unwrap(),
        name_env,
        node_env,
    ];
    let override_key = |kv: &[u8]| {
        ours.iter().any(|o| {
            let k = &o.as_bytes()[..=o.as_bytes().iter().position(|&b| b == b'=').unwrap()];
            kv.starts_with(k)
        })
    };
    let mut env_strs: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let mut kv = k.into_encoded_bytes();
            kv.push(b'=');
            kv.extend_from_slice(v.as_encoded_bytes());
            if override_key(&kv) {
                None
            } else {
                CString::new(kv).ok()
            }
        })
        .collect();
    env_strs.extend(ours);
    let mut envp: Vec<*const libc::c_char> = env_strs.iter().map(|s| s.as_ptr()).collect();
    envp.push(core::ptr::null());

    // `socketpair(AF_UNIX, SOCK_STREAM, 0, fd)`. nix returns the
    // pair already wrapped in `OwnedFd`, so the fork-failure path
    // below closes both via Drop with no manual `libc::close`.
    let (parent_fd, child_fd) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        // CLOEXEC: child dup2's what it needs to 0/1; originals shouldn't leak past exec.
        crate::sock_cloexec_flag(),
    )?;
    crate::set_cloexec(&parent_fd);
    crate::set_cloexec(&child_fd);
    // Snapshot the raw ints BEFORE fork: the child path below is
    // libc-only (see fn doc) and must not call into std, even for a
    // trivial `.as_raw_fd()` getter — keep it on plain integers.
    let (parent_raw, child_raw) = (parent_fd.as_raw_fd(), child_fd.as_raw_fd());

    // SAFETY: see fn doc. The child does libc-only until exec.
    // Everything that allocates was done above, in the parent.
    #[allow(unsafe_code)]
    unsafe {
        // `if(fork()) { ... parent ... return; }`. We check for
        // fork failure (`-1`).
        match libc::fork() {
            -1 => {
                // `parent_fd` + `child_fd` are OwnedFd; Drop closes.
                Err(io::Error::last_os_error())
            }
            0 => {
                // ────── CHILD ──────
                // libc-only until exec. NO std (locks could be held).

                // close(0), close(1), close(fd[0]),
                // dup2(fd[1], 0), dup2(fd[1], 1), close(fd[1]).
                libc::close(0);
                libc::close(1);
                libc::close(parent_raw);
                libc::dup2(child_raw, 0);
                libc::dup2(child_raw, 1);
                libc::close(child_raw);

                // `setsid()`. Detach from controlling tty.
                // The proxy script shouldn't get our SIGINT.
                libc::setsid();

                // execve with pre-built envp; no setenv in the child.
                // NETNAME omitted (not threaded through yet; same as run_script).
                libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());

                // execve returned → failed. _exit (NOT exit — exit()
                // runs atexit handlers, which might allocate).
                libc::_exit(1);
            }
            pid => {
                // ────── PARENT ──────
                // `c->socket = fd[0]; close(fd[1]); return`. Don't
                // waitpid here — the child is detached. Register the
                // pid with the script reaper so it's collected by
                // the periodic `reap_children()` sweep instead of
                // lingering as a zombie until process exit.
                drop(child_fd);
                crate::script::register_child(nix::unistd::Pid::from_raw(pid));
                Ok(parent_fd)
            }
        }
    }
}

/// Parse `Address = host port` lines from `hosts/NAME` into
/// **unresolved** `(host, port)` pairs. Resolve happens
/// lazily in `get_recent_address` (`:157-199`). We mirror that:
/// no DNS here, just string parsing. Literal IPs are parsed inline by
/// [`AddressCache::next_addr`]; hostnames are handed to
/// [`crate::bgresolve::DnsWorker`] via
/// [`AddressCache::unresolved_hosts`].
///
/// `Address = 10.0.0.1 655` → `("10.0.0.1", 655)`. `Address =
/// bob.example.com` (no port) → `("bob.example.com", 655)` (default).
///
/// Unparseable lines (bad port) warn-and-skip.
#[must_use]
pub(crate) fn resolve_config_addrs(confbase: &Path, node_name: &str) -> Vec<(String, u16)> {
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

    // C address_cache.c:165: bare-Address port falls back to
    // `lookup_config("Port")` before the 655 default.
    let default_port = cfg
        .lookup("Port")
        .next()
        .and_then(|e| e.get_str().parse::<u16>().ok())
        .unwrap_or(655);

    let mut addrs = Vec::new();
    for e in cfg.lookup("Address") {
        // `get_config_string(cfg, &address); port = strchr(address,
        // ' ')` — same `host port` shape as everywhere else in tinc.
        let s = e.get_str();
        let mut parts = s.splitn(2, ' ');
        let host = parts.next().unwrap_or("");
        let port = match parts.next() {
            None => Some(default_port),
            Some(p) => p.parse::<u16>().ok(),
        };
        match (host, port) {
            (h, Some(p)) if !h.is_empty() => addrs.push((h.to_string(), p)),
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
    use std::os::fd::AsFd;

    /// `apply_dial_sockopts`: `SO_BINDTODEVICE` to `lo` reads back
    /// correctly. Mirror of `listen.rs::open_bind_to_interface_lo`
    /// but on a bare dial socket (no bind/connect). Proves the
    /// outgoing path actually applies the sockopt.
    #[test]
    #[cfg(target_os = "linux")]
    fn dial_sockopts_bind_to_interface_lo() {
        use nix::sys::socket::{getsockopt, sockopt};
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let opts = SockOpts {
            bind_to_interface: Some("lo".into()),
            ..SockOpts::default()
        };
        apply_dial_sockopts(&sock, &opts);
        let got = getsockopt(&sock.as_fd(), sockopt::BindToDevice).unwrap();
        let got = got.to_string_lossy();
        assert_eq!(got.trim_end_matches('\0'), "lo");
    }

    /// `apply_dial_sockopts` is warn-only: bad interface doesn't
    /// panic, doesn't error. The socket survives (we'd `connect()`
    /// next).
    #[test]
    fn dial_sockopts_bad_iface_is_warn_only() {
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let opts = SockOpts {
            bind_to_interface: Some("nonexistent-iface-9z".into()),
            ..SockOpts::default()
        };
        apply_dial_sockopts(&sock, &opts); // would panic if not warn-only
        // Socket still usable: setting a benign opt proves it's open.
        sock.set_nodelay(true).unwrap();
    }

    /// `apply_dial_sockopts`: `SO_MARK` reads back. Needs
    /// `CAP_NET_ADMIN`; skip otherwise (matches `listen.rs::
    /// open_fwmark_set`).
    #[test]
    #[cfg(target_os = "linux")]
    fn dial_sockopts_fwmark() {
        use nix::sys::socket::{getsockopt, sockopt};
        let euid = nix::unistd::geteuid();
        if !euid.is_root() {
            eprintln!("SKIP dial_sockopts_fwmark: SO_MARK needs CAP_NET_ADMIN (euid={euid})");
            return;
        }
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let opts = SockOpts {
            fwmark: 0x1234,
            ..SockOpts::default()
        };
        apply_dial_sockopts(&sock, &opts);
        assert_eq!(getsockopt(&sock.as_fd(), sockopt::Mark).unwrap(), 0x1234);
    }

    /// `retry_outgoing` arithmetic: +5 each time, capped at
    /// `maxtimeout`.
    #[test]
    fn bump_timeout_backoff() {
        let mut o = Outgoing {
            node_name: "bob".into(),
            origin: OutOrigin::default(),
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

    /// `resolve_config_addrs` port precedence (C `address_cache.c:165`):
    /// inline `Address host port` > `Port =` directive > 655.
    #[test]
    fn resolve_address_port_precedence() {
        let cases: &[(&str, &[(&str, u16)])] = &[
            // No Port directive: bare → 655, inline literal preserved.
            (
                "Address = 127.0.0.1\nAddress = 127.0.0.2 12345\n",
                &[("127.0.0.1", 655), ("127.0.0.2", 12345)],
            ),
            // Port directive: bare → 4443, inline still wins.
            (
                "Port = 4443\nAddress = 10.0.0.1\nAddress = 10.0.0.2 7000\n",
                &[("10.0.0.1", 4443), ("10.0.0.2", 7000)],
            ),
        ];
        for (i, (body, want)) in cases.iter().enumerate() {
            let tmp = std::env::temp_dir().join(format!(
                "tincd-outgoing-resolve-{:?}-{i}",
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(tmp.join("hosts")).unwrap();
            std::fs::write(tmp.join("hosts").join("bob"), body).unwrap();

            let got = resolve_config_addrs(&tmp, "bob");
            let want: Vec<_> = want.iter().map(|(h, p)| (h.to_string(), *p)).collect();
            assert_eq!(got, want, "case {i}: {body:?}");

            let _ = std::fs::remove_dir_all(&tmp);
        }
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
        match probe_connecting(client.as_fd()) {
            Ok(true) => {}
            other => panic!("expected Ok(true), got {other:?}"),
        }
    }

    /// `Proxy =` config parsing: exec/socks4/socks5/http accept,
    /// none/empty → `Ok(None)`, socks4a + unknown reject.
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

        // SOCKS4: host port [user].
        match parse_proxy_config("socks4 10.0.0.1 1080").unwrap() {
            Some(ProxyConfig::Socks4 { host, port, user }) => {
                assert_eq!(host, "10.0.0.1");
                assert_eq!(port, 1080);
                assert!(user.is_none());
            }
            other => panic!("expected Socks4, got {other:?}"),
        }
        match parse_proxy_config("socks4 10.0.0.1 1080 alice").unwrap() {
            Some(ProxyConfig::Socks4 { user, .. }) => {
                assert_eq!(user.as_deref(), Some("alice"));
            }
            other => panic!("expected Socks4, got {other:?}"),
        }

        // SOCKS5: host port [user [pass]].
        match parse_proxy_config("socks5 proxy.example 1080 bob s3cret").unwrap() {
            Some(ProxyConfig::Socks5 {
                host,
                port,
                user,
                pass,
            }) => {
                assert_eq!(host, "proxy.example");
                assert_eq!(port, 1080);
                assert_eq!(user.as_deref(), Some("bob"));
                assert_eq!(pass.as_deref(), Some("s3cret"));
            }
            other => panic!("expected Socks5, got {other:?}"),
        }
        // Anonymous SOCKS5.
        match parse_proxy_config("socks5 127.0.0.1 1080").unwrap() {
            Some(ProxyConfig::Socks5 { user, pass, .. }) => {
                assert!(user.is_none());
                assert!(pass.is_none());
            }
            other => panic!("expected Socks5, got {other:?}"),
        }

        // HTTP: host port.
        match parse_proxy_config("http 10.0.0.1 8080").unwrap() {
            Some(ProxyConfig::Http { host, port }) => {
                assert_eq!(host, "10.0.0.1");
                assert_eq!(port, 8080);
            }
            other => panic!("expected Http, got {other:?}"),
        }

        // Missing host/port → error.
        assert!(parse_proxy_config("socks4").is_err());
        assert!(parse_proxy_config("socks5 localhost").is_err());
        assert!(parse_proxy_config("socks5 localhost notaport").is_err());
        assert!(parse_proxy_config("http localhost").is_err());

        // socks4a: faithfully unimplemented upstream.
        assert!(parse_proxy_config("socks4a localhost 1080").is_err());

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

        let fd = do_outgoing_pipe("cat", "127.0.0.1:655".parse().unwrap(), "bob", "alice")
            .expect("do_outgoing_pipe");

        // Wrap in a UnixStream for ergonomic read/write. fd is a
        // valid AF_UNIX SOCK_STREAM; `From<OwnedFd>` consumes it
        // (no double-close, no unsafe).
        let mut stream = std::os::unix::net::UnixStream::from(fd);

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

        let fd = do_outgoing_pipe(
            "echo \"$NAME $NODE $REMOTEADDRESS $REMOTEPORT\"",
            "10.0.0.1:12345".parse().unwrap(),
            "bob",
            "alice",
        )
        .expect("do_outgoing_pipe");

        let stream = std::os::unix::net::UnixStream::from(fd);
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
            match probe_connecting(client.as_fd()) {
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
