//! TCP/UDP listener setup. Ports `setup_listen_socket` (TCP) +
//! `setup_vpn_in_socket` (UDP) from `net_socket.c`, the no-config
//! default of `add_listen_address` from `net_setup.c`, and the
//! tarpit (`check_tarpit` + `tarpit()`).
//!
//! ## socket2, not hand-rolled setsockopt
//!
//! std's `TcpListener::bind` is atomic; no seam for `IPV6_V6ONLY`.
//! socket2 gives the C's four-step shape (`net_socket.c:196,210,
//! 214,254`). Not a shim-matrix row — it's "std with seams".
//!
//! Used (all ungated): `Socket::new` (auto-`SOCK_CLOEXEC`),
//! `set_reuse_address` (`:210`), `set_only_v6` (`:214` — load-
//! bearing for separate v4+v6 listeners), `set_nodelay`
//! (`configure_tcp:89`), `set_nonblocking`, `set_broadcast`
//! (`:332`), `accept` (uses `accept4(SOCK_CLOEXEC)` — closes a
//! small fd leak the C has), `SockAddr` (= C `sockaddr_t` union).
//!
//! Deferred sockopts: `IP_TOS`/`IPV6_TCLASS` (`configure_tcp:93-100`).
//!
//! ## getaddrinfo: skip it
//!
//! C `add_listen_address(NULL, NULL)` uses getaddrinfo as a per-
//! family probe (`0.0.0.0` then `::`, gcc-verified). We probe by
//! trying both binds; `Socket::new(Domain::IPV6, ...)` failing is
//! the same outcome. Bind failure is `continue` (C `:705-707`).
//! `BindToAddress` resolution lives in `daemon.rs` (it owns the
//! config tree); resolved `SocketAddr`s flow into
//! `open_listener_pair` here.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use nix::sys::socket::{setsockopt, sockopt};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Per-listener socket options driven by config keys. Threaded from
/// `daemon.rs` setup through `open_listeners` so the socket-creation
/// helpers stay free of config-tree dependencies.
///
/// All fields except `bind_to_interface` are best-effort: setsockopt
/// failure logs and continues, matching the C (`net_socket.c:248,
/// 264-290` — no return-value check on `SO_MARK`, warn-only on the
/// buffer ones).
#[derive(Debug, Clone)]
pub struct SockOpts {
    /// `udp_rcvbuf` (`net_socket.c:41`). C default `1024*1024` (1MB).
    /// 0 = skip the setsockopt entirely (`set_udp_buffer:264`: `if
    /// (!size) return`). Kernel default on Linux is ~200KB — the C
    /// bumps it to handle burst traffic. UDP-only.
    pub udp_rcvbuf: usize,
    /// `udp_sndbuf` (`net_socket.c:42`). Same shape as rcvbuf.
    pub udp_sndbuf: usize,
    /// `udp_{rcv,snd}buf_warnings` (`net_socket.c:43-44`). C sets this
    /// to true ONLY when the operator explicitly configured
    /// `UDPRcvBuf`/`UDPSndBuf` (`net_setup.c:895,904`). The 1MB
    /// default firing without the operator asking would be log noise
    /// on every boot (kernel almost always clamps 1MB).
    pub udp_buf_warnings: bool,
    /// `fwmark` (`net_socket.c:46`). `SO_MARK`. Linux netfilter mark
    /// for policy routing. 0 = unset = skip. Applied to TCP + UDP
    /// listeners (`:248`) AND outgoing TCP (`:383`, separate site).
    /// Public so `outgoing.rs` can reuse the same parsed value.
    pub fwmark: u32,
    /// `BindToInterface` config (`net_socket.c:111-142`).
    /// `SO_BINDTODEVICE`. Linux-only. `None` = skip. Unlike the
    /// other knobs, the C makes this a HARD failure (`:244,391`:
    /// `closesocket; return -1`) — if the operator says "bind to
    /// eth0" and eth0 doesn't exist, silently binding to the
    /// wrong interface defeats the security intent. We do the
    /// same: failure here propagates up, kills the listener pair.
    pub bind_to_interface: Option<String>,
}

impl Default for SockOpts {
    fn default() -> Self {
        Self {
            // C `net_socket.c:41-42`: `int udp_rcvbuf = 1024*1024`.
            udp_rcvbuf: 1024 * 1024,
            udp_sndbuf: 1024 * 1024,
            // C `:43-44`: `bool udp_rcvbuf_warnings;` (zero-init).
            udp_buf_warnings: false,
            // C `:46`: `int fwmark;` (zero-init = unset).
            fwmark: 0,
            bind_to_interface: None,
        }
    }
}

/// `set_udp_buffer` (`net_socket.c:262-290`). Set `SO_RCVBUF` or
/// `SO_SNDBUF`, then optionally read back and warn if the kernel
/// clamped. Linux DOUBLES the requested value internally (overhead
/// accounting) and caps at `net.core.{r,w}mem_max`; the readback
/// sees the doubled-then-capped figure. C `:287` checks `actual <
/// size` (not `!=`) — doubling alone doesn't trip the warning.
fn set_udp_buffer<O>(s: &Socket, opt: O, name: &str, size: usize, warn: bool)
where
    O: nix::sys::socket::SetSockOpt<Val = usize> + nix::sys::socket::GetSockOpt<Val = usize> + Copy,
{
    // `:264`: `if(!size) return`. 0 means "don't touch".
    if size == 0 {
        return;
    }
    if let Err(e) = setsockopt(&s.as_fd(), opt, &size) {
        log::warn!(target: "tincd::net", "Can't set UDP {name} to {size}: {e}");
        return;
    }
    if !warn {
        return;
    }
    // `:278-289`: readback. nix wraps the optlen dance.
    match nix::sys::socket::getsockopt(&s.as_fd(), opt) {
        Ok(actual) if actual < size => {
            log::warn!(
                target: "tincd::net",
                "Can't set UDP {name} to {size}, the system set it to {actual} instead"
            );
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!(target: "tincd::net", "Can't read back UDP {name}: {e}");
        }
    }
}

/// `bind_to_interface` (`net_socket.c:111-142`). `SO_BINDTODEVICE`.
/// Returns `Err` on failure (caller closes the socket) — unlike the
/// other sockopts, this is intentional: see `SockOpts.
/// bind_to_interface`. The C `:132-135` returns `false` and the
/// caller at `:391` does `closesocket; return -1`.
pub(crate) fn bind_to_interface(s: &Socket, iface: &str) -> io::Result<()> {
    let name = std::ffi::OsString::from(iface);
    setsockopt(&s.as_fd(), sockopt::BindToDevice, &name)
        .map_err(|e| io::Error::other(format!("Can't bind to interface {iface}: {e}")))
}

/// `MAXSOCKETS` (`net.h:47`). C comment: "Probably overkill...".
/// 8 listener pairs (TCP+UDP each). One v4, one v6, six spare for
/// `BindToAddress` entries.
pub const MAXSOCKETS: usize = 8;

/// `addressfamily` (`net_socket.c:38`). Which families to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddrFamily {
    /// `AF_UNSPEC`. Try v4 AND v6.
    #[default]
    Any,
    /// `AF_INET`. v4 only.
    Ipv4,
    /// `AF_INET6`. v6 only.
    Ipv6,
}

impl AddrFamily {
    /// Parse the `AddressFamily` config value. C `net_setup.c:538-548`.
    /// Returns `None` for unrecognized values; the C also does this
    /// (silent ignore — `addressfamily` stays at its default
    /// `AF_UNSPEC`).
    #[must_use]
    pub fn from_config(s: &str) -> Option<Self> {
        // C `strcasecmp`. The vars table normalizes case at parse time
        // but the C also re-checks here. Match.
        match s.to_ascii_lowercase().as_str() {
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "any" => Some(Self::Any),
            _ => None,
        }
    }

    pub(crate) fn try_v4(self) -> bool {
        matches!(self, Self::Any | Self::Ipv4)
    }
    pub(crate) fn try_v6(self) -> bool {
        matches!(self, Self::Any | Self::Ipv6)
    }
}

/// `listen_socket_t` (`net.h:110-116`). One TCP+UDP pair. C stores
/// `io_t tcp; io_t udp; sockaddr_t sa; bool bindto`. We store the
/// `Socket`s (own the fds) plus the local address (for the pidfile +
/// outgoing UDP source selection).
///
/// `bindto` distinguishes `BindToAddress` (use this addr for
/// outgoing connections too — `net_socket.c:624` source-addr
/// selection) from `ListenAddress` (listen-only). The no-config
/// default is `bindto = false`.
pub struct Listener {
    /// `listen_socket_t.bindto`. True iff this listener came from a
    /// `BindToAddress` config line (vs `ListenAddress` or the
    /// implicit wildcard). C `net_setup.c:1160` vs `:1169`. Consumed
    /// by outgoing-connect to pick a source address.
    pub bindto: bool,
    /// `listen_socket_t.tcp`. TCP listener, accepting peer conns.
    /// `Socket` owns the fd; Drop closes.
    pub tcp: Socket,
    /// `listen_socket_t.udp`. UDP socket, receives `vpn_packet_t`s.
    pub udp: Socket,
    /// `listen_socket_t.sa`. The local bound address. `SocketAddr`
    /// not `SockAddr` — we know it's v4 or v6 (we bound it), not
    /// AF_UNIX.
    pub local: SocketAddr,
}

impl Listener {
    /// Raw fds for `EventLoop::add`. TCP first, UDP second.
    #[must_use]
    pub fn fds(&self) -> (RawFd, RawFd) {
        (self.tcp.as_raw_fd(), self.udp.as_raw_fd())
    }

    /// `get_bound_port(sock->udp.fd)` (`net_setup.c:1194`). The UDP
    /// port, AFTER bind. With `bind_reusing_port` (`open_one`) this
    /// equals `local.port()` for the first listener; kept as a
    /// separate accessor because subsequent listeners on a system
    /// where the port is taken on UDP fall back to ephemeral
    /// (`open_one`'s retry path).
    #[must_use]
    pub fn udp_port(&self) -> u16 {
        self.udp
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .map_or(0, |a| a.port())
    }
}

// setup_listen_socket (TCP)

/// `setup_listen_socket` (`net_socket.c:191-262`). One TCP listener.
///
/// Four-step shape, matching the C:
/// 1. `socket(family, SOCK_STREAM, IPPROTO_TCP)` — `:196`
/// 2. `setsockopt` × N — `:210-247`
/// 3. `bind` — `:250` (via `try_bind`)
/// 4. `listen(backlog=3)` — `:254`
///
/// Backlog is 3. C `:254`: `listen(nfd, 3)`. tinc isn't a high-QPS
/// server; 3 pending accepts is plenty. We match.
///
/// # Errors
/// `socket`/`bind`/`listen` errors. `setsockopt` failures are LOGGED
/// but not propagated (`set_reuse_address` failing means `bind` will
/// fail too if the addr is in use; let `bind` produce the user-visible
/// error). C does the same — none of the `setsockopt` calls in
/// `setup_listen_socket` check the return value.
fn setup_tcp(addr: &SockAddr, opts: &SockOpts) -> io::Result<Socket> {
    let domain = Domain::from(i32::from(addr.family()));
    // `Socket::new` does `SOCK_CLOEXEC` on Linux/BSD. C `:203` does
    // separate `fcntl(F_SETFD, FD_CLOEXEC)`. Same effect, atomic.
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // `:210`: `setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)`. Restart
    // after crash without `EADDRINUSE` from TIME_WAIT.
    if let Err(e) = s.set_reuse_address(true) {
        log::warn!(target: "tincd::net", "SO_REUSEADDR: {e}");
    }

    // `:214`: `if(family == AF_INET6) setsockopt(IPV6_V6ONLY, 1)`.
    // Load-bearing: without this, the v6 socket grabs v4 traffic via
    // mapped addresses, and the v4 bind sees the port as taken.
    if domain == Domain::IPV6
        && let Err(e) = s.set_only_v6(true)
    {
        log::warn!(target: "tincd::net", "IPV6_V6ONLY: {e}");
    }

    // `:248`: SO_MARK. Linux netfilter mark for policy routing.
    // 0 = unset = skip (C: `if(fwmark)`). Best-effort — the C
    // doesn't check the return value.
    if opts.fwmark != 0
        && let Err(e) = setsockopt(&s.as_fd(), sockopt::Mark, &opts.fwmark)
    {
        log::warn!(target: "tincd::net", "SO_MARK={}: {e}", opts.fwmark);
    }

    // `:225-247`: SO_BINDTODEVICE. The C `setup_listen_socket` does
    // this inline (NOT via the `bind_to_interface` helper — that's
    // UDP-only at `:389`). Same semantics: hard failure (`:244`:
    // `closesocket; return -1`). Propagate; Socket's Drop closes.
    if let Some(iface) = &opts.bind_to_interface {
        bind_to_interface(&s, iface)?;
    }

    // `:250`: bind. C `try_bind` closes the fd on failure and logs;
    // we let `?` propagate. Socket's Drop closes.
    s.bind(addr)?;

    // `:254`: `listen(nfd, 3)`.
    s.listen(3)?;

    Ok(s)
}

// setup_vpn_in_socket (UDP)

/// `setup_vpn_in_socket` (`net_socket.c:292-399`). One UDP socket.
///
/// Same four-step shape as TCP but no `listen` (UDP doesn't have it)
/// and more sockopts (broadcast for LocalDiscovery, buffer sizes,
/// PMTU). Most deferred.
///
/// O_NONBLOCK is set HERE (`:308-316`), unlike TCP listeners (the
/// listener fd doesn't need non-blocking — `accept` blocking is fine
/// because we only call it when epoll says ready). UDP `recvfrom`
/// IS the data path; non-blocking is mandatory.
///
/// # Errors
/// `socket`/`bind` errors. `setsockopt` warnings logged.
fn setup_udp(addr: &SockAddr, opts: &SockOpts) -> io::Result<Socket> {
    let domain = Domain::from(i32::from(addr.family()));
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // `:308-316`: O_NONBLOCK. C does `fcntl(F_GETFL) | O_NONBLOCK`;
    // socket2 same.
    s.set_nonblocking(true)?;

    // `:331`: SO_REUSEADDR.
    if let Err(e) = s.set_reuse_address(true) {
        log::warn!(target: "tincd::net", "SO_REUSEADDR (udp): {e}");
    }

    // `:332`: SO_BROADCAST. For LocalDiscovery (probe peers on LAN).
    // We don't use it yet but setting it doesn't hurt and matching the
    // C's socket state means dump tools (`ss -tuln`) show identical
    // flags.
    if let Err(e) = s.set_broadcast(true) {
        log::warn!(target: "tincd::net", "SO_BROADCAST: {e}");
    }

    // `:341`: IPV6_V6ONLY. Same rationale as TCP.
    if domain == Domain::IPV6
        && let Err(e) = s.set_only_v6(true)
    {
        log::warn!(target: "tincd::net", "IPV6_V6ONLY (udp): {e}");
    }

    // `:349-378`: IP_MTU_DISCOVER / IPV6_MTU_DISCOVER = PMTUDISC_DO.
    // Forces DF on every datagram. Without this, oversized PMTU probes
    // get IP-fragmented and arrive successfully — pmtu.rs walks minmtu
    // up past the physical MTU, the kernel never populates its PMTU
    // cache (so choose_initial_maxmtu reads nothing), and EMSGSIZE
    // never reaches reduce_mtu. The whole PMTU machinery becomes
    // decorative. C gates on OPTION_PMTU_DISCOVERY (default ON unless
    // TCPOnly); we set unconditionally — if TCPOnly, this socket
    // carries no data anyway. Best-effort like the C: warn, don't bail.
    {
        let (level, optname, optval, label) = if domain == Domain::IPV6 {
            (
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_DO,
                "IPV6_MTU_DISCOVER",
            )
        } else {
            (
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
                "IP_MTU_DISCOVER",
            )
        };
        // SAFETY: fd is live (Socket owns it); optval is a stack c_int
        // whose address+len we pass for the duration of the call. The
        // syscall copies out before return.
        // truncation: size_of::<c_int>() == 4, fits socklen_t.
        #[allow(unsafe_code, clippy::cast_possible_truncation)]
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                level,
                optname,
                (&raw const optval).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            log::warn!(target: "tincd::net", "{label}: {}", io::Error::last_os_error());
        }
    }

    // `:334-335`: SO_RCVBUF/SO_SNDBUF via `set_udp_buffer`.
    // Default 1MB each (`net_socket.c:41-42`). Best-effort.
    set_udp_buffer(
        &s,
        sockopt::RcvBuf,
        "SO_RCVBUF",
        opts.udp_rcvbuf,
        opts.udp_buf_warnings,
    );
    set_udp_buffer(
        &s,
        sockopt::SndBuf,
        "SO_SNDBUF",
        opts.udp_sndbuf,
        opts.udp_buf_warnings,
    );

    // `:383-387` (UDP site): SO_MARK. Same as TCP `:248`.
    if opts.fwmark != 0
        && let Err(e) = setsockopt(&s.as_fd(), sockopt::Mark, &opts.fwmark)
    {
        log::warn!(target: "tincd::net", "SO_MARK={} (udp): {e}", opts.fwmark);
    }

    // `:389-392`: SO_BINDTODEVICE. Hard failure: propagate.
    if let Some(iface) = &opts.bind_to_interface {
        bind_to_interface(&s, iface)?;
    }

    s.bind(addr)?;

    Ok(s)
}

// add_listen_address

/// `add_listen_address(NULL, false)` — the no-config default
/// (`net_setup.c:1173`: `if(!cfgs) add_listen_address(address, NULL)`
/// where `address` is uninitialized → NULL).
///
/// C `:655-740`: `getaddrinfo(NULL, port, AI_PASSIVE)` returns
/// `0.0.0.0` then `::` (gcc-verified on a dual-stack Linux). Loop,
/// bind each, `continue` on bind failure (`:705-707`). Result: one
/// v4 listener, one v6 listener, both on `port`.
///
/// We skip getaddrinfo. The two addresses are KNOWN (`0.0.0.0:port`
/// and `[::]:port` — the AI_PASSIVE wildcards). The "is this family
/// supported on this system" probe is `Socket::new` failing for
/// AF_INET6 on a v6-disabled kernel. Same effect.
///
/// `family` filters which to try. Maps `AddressFamily` config →
/// the C's `hint.ai_family = addressfamily` at `:655`.
///
/// Returns 0, 1, or 2 listeners. Zero is an error in the caller
/// (`net_setup.c:1180`: `if(!listen_sockets) { ERR }`); we let the
/// caller check.
///
/// # Errors
/// Never returns `Err` — bind failures are warnings + skip, matching
/// C `:705-707` `continue`. The "no listeners" case is the caller's
/// problem (returns empty Vec).
#[must_use]
pub fn open_listeners(port: u16, family: AddrFamily, opts: &SockOpts) -> Vec<Listener> {
    let mut listeners = Vec::with_capacity(2);

    if family.try_v4() {
        let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
        if let Some(l) = open_one(addr, opts, None, false) {
            listeners.push(l);
        }
    }
    if family.try_v6() {
        let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
        // C `:700`: `from_fd = listen_socket[0].tcp.fd`. The v6
        // listener tries to reuse the v4 listener's port. With
        // `Port=0` this makes both families converge on one port.
        let reuse = listeners.first().map(|l| l.local.port());
        if let Some(l) = open_one(addr, opts, reuse, false) {
            listeners.push(l);
        }
    }

    listeners
}

/// `assign_static_port` (`net_setup.c:577-609`). If `addr.port()` is
/// 0 (dynamic), rewrite it to `reuse_port`. Otherwise leave it
/// alone (already static). C checks `sa.sa_family` and writes the
/// `sin_port` / `sin6_port` field; `SocketAddr::set_port` covers
/// both. C returns `false` on bad fd / unknown family; we encode
/// "nothing to do" as `reuse_port == None` and let the caller skip.
fn assign_static_port(mut addr: SocketAddr, reuse_port: Option<u16>) -> Option<SocketAddr> {
    let port = reuse_port?;
    // C `:590-601`: only overwrite if the existing port is zero.
    // A `BindToAddress = 10.0.0.1 5000` line has a static port;
    // don't clobber it with the first listener's ephemeral.
    if addr.port() == 0 {
        addr.set_port(port);
        Some(addr)
    } else {
        None
    }
}

/// `bind_reusing_port` (`net_setup.c:613-632`). Try `setup` with the
/// port stolen from an already-bound socket; on failure, fall back
/// to the original `addr` (port 0 → fresh ephemeral). The C threads
/// a function pointer (`bind_fn_t`); we take a closure.
///
/// Why fallback: with `Port=0` and multiple `BindToAddress` lines,
/// the first listener picks ephemeral X. The second listener
/// (different IP) usually CAN reuse X (different (addr,port) tuple),
/// but if X happens to be taken on that interface, we'd rather get
/// a working listener on a different port than no listener at all.
/// C `:629`: `if(fd < 0) fd = setup(sa)`.
fn bind_reusing_port<F>(addr: SocketAddr, reuse_port: Option<u16>, setup: F) -> io::Result<Socket>
where
    F: Fn(&SockAddr) -> io::Result<Socket>,
{
    // C `:621-624`: only attempt the reuse if assign_static_port
    // succeeded (i.e. addr had port 0 AND we have a port to steal).
    // Reuse failed (port taken on this interface) → fall through.
    if let Some(reused) = assign_static_port(addr, reuse_port)
        && let Ok(s) = setup(&SockAddr::from(reused))
    {
        return Ok(s);
    }
    // C `:629`: original address. With port 0 the kernel picks fresh.
    setup(&SockAddr::from(addr))
}

/// One TCP+UDP pair on `addr`. C `add_listen_address:698-736`.
/// Either both succeed or neither makes it into `listen_socket[]`
/// (`:717-720`: TCP succeeds, UDP fails → close TCP, continue).
///
/// `reuse_port`: with `Port=0`, the FIRST listener gets a kernel
/// port. Subsequent calls pass that port here so the whole daemon
/// converges on one port across all listeners (and TCP/UDP within
/// a pair). C `:700`: `int from_fd = listen_socket[0].tcp.fd`;
/// `:710-711`: after the first TCP bind, `from_fd = tcp_fd` so UDP
/// reuses the just-assigned TCP port.
///
/// `bindto`: stored on the result, see `Listener.bindto`.
///
/// Public for `daemon.rs`'s `BindToAddress` walk; the wildcard
/// default still goes through `open_listeners`.
#[must_use]
pub fn open_listener_pair(
    addr: SocketAddr,
    opts: &SockOpts,
    reuse_port: Option<u16>,
    bindto: bool,
) -> Option<Listener> {
    open_one(addr, opts, reuse_port, bindto)
}

fn open_one(
    addr: SocketAddr,
    opts: &SockOpts,
    reuse_port: Option<u16>,
    bindto: bool,
) -> Option<Listener> {
    // ─── TCP. C `:703`: `bind_reusing_port(sa, from_fd,
    // setup_listen_socket)`.
    let tcp = match bind_reusing_port(addr, reuse_port, |sa| setup_tcp(sa, opts)) {
        Ok(s) => s,
        Err(e) => {
            // C `:705`: `if(tcp_fd < 0) continue`. Log + skip.
            // Warn not Error: this is expected on a v6-disabled
            // system. The "no listeners at all" check in setup is
            // where the hard error lives.
            log::warn!(target: "tincd::net", "TCP bind on {addr}: {e}");
            return None;
        }
    };

    // C `:710-711`: `if(!from_fd) from_fd = tcp_fd`. The first
    // listener pair has no prior socket to steal from (`from_fd ==
    // listen_socket[0].tcp.fd == 0`), so it uses the just-bound TCP
    // socket as the port source for UDP. Subsequent pairs already
    // have `reuse_port` from listener[0], keep it.
    //
    // We collapse: ALWAYS try the TCP port we just got. If
    // `reuse_port` was Some(X) and TCP successfully reused X, this
    // is X anyway. If TCP fell back to a fresh ephemeral, we want
    // UDP to follow TCP (peers learn the port from the TCP meta-
    // connection and expect UDP there).
    let tcp_port = tcp
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .map(|a| a.port());

    // ─── UDP. C `:715`: `bind_reusing_port(sa, from_fd,
    // setup_vpn_in_socket)`.
    let udp = match bind_reusing_port(addr, tcp_port, |sa| setup_udp(sa, opts)) {
        Ok(s) => s,
        Err(e) => {
            // C `:718`: `closesocket(tcp_fd); continue`.
            // tcp drops here, fd closes.
            log::warn!(target: "tincd::net", "UDP bind on {addr}: {e}");
            return None;
        }
    };

    // `:734`: `memcpy(&sock->sa, aip->ai_addr, aip->ai_addrlen)`.
    // We want the BOUND addr (with the kernel-assigned port if
    // port was 0), not the bind-target addr. C does the wrong thing
    // here (stores the requested addr), but then patches `myport`
    // separately at `:1187` via `get_bound_port(tcp.fd)`. We collapse
    // the two: store the actual bound addr.
    let local = tcp
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .unwrap_or(addr);

    log::info!(target: "tincd::net", "Listening on {local}");

    Some(Listener {
        bindto,
        tcp,
        udp,
        local,
    })
}

// configure_tcp (per-connection, post-accept)

/// `configure_tcp` (`net_socket.c:68-108`). Set the accepted fd's
/// options: NONBLOCK + NODELAY. The C also does TOS/TCLASS/MARK
/// (deferred — see module doc).
///
/// Called from `handle_new_meta_connection` after `accept` returns.
/// The listener's options DON'T inherit to the accepted fd (NONBLOCK
/// in particular doesn't; it's why C `:71-76` does it again here).
///
/// Consumes `Socket`, returns `OwnedFd`. The conversion strips
/// socket2's wrapper; daemon.rs's `Connection` wants raw bytes via
/// `libc::read`/`write`, doesn't need the wrapper.
///
/// # Errors
/// `set_nonblocking` failing means the fd is broken; propagate.
/// `set_nodelay` failing is a warn — the connection works without it,
/// just with Nagle latency. C `:89` ignores the return value too.
pub fn configure_tcp(s: Socket) -> io::Result<OwnedFd> {
    // `:71-76`: O_NONBLOCK. The conn read path is non-blocking.
    s.set_nonblocking(true)?;

    // `:89`: TCP_NODELAY. Meta protocol is line-oriented (~80 bytes);
    // Nagle would batch lines into 200ms coalesce windows.
    if let Err(e) = s.set_nodelay(true) {
        log::warn!(target: "tincd::conn", "TCP_NODELAY: {e}");
    }

    // Deferred: IP_TOS=LOWDELAY (`:93`), IPV6_TCLASS=LOWDELAY (`:98`),
    // SO_MARK (`:103` — the LISTEN-side mark is set in setup_tcp; the
    // outgoing-connect mark at `net_socket.c:383` is separate).

    Ok(s.into())
}

// sockaddrunmap + is_local_connection

/// `sockaddrunmap` (`netutl.c:272-277`). v4-mapped v6 addr → plain v4.
///
/// `accept` on a v6 socket WITHOUT V6ONLY returns `::ffff:10.0.0.5`
/// for a v4 peer. We DO set V6ONLY so this never fires for our
/// listeners — but tarpit's `prev_sa` compare and the eventual
/// `sockaddr2hostname` log line want plain v4 for readability.
/// Harmless to canonicalize anyway.
///
/// std `Ipv6Addr::to_ipv4_mapped()` is `Some` iff the high 80 bits
/// are zero and the next 16 are `ffff`. Same condition as C
/// `IN6_IS_ADDR_V4MAPPED`. C `:274` writes the low 32 bits over
/// `sin_addr` and changes `sa_family` — net effect: a SocketAddrV4.
#[must_use]
pub fn unmap(sa: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = sa
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return (v4, v6.port()).into();
    }
    sa
}

/// `is_local_connection` (`netutl.c:304-319`): loopback peer check.
///
/// `handle_new_meta_connection` (`:751`) skips tarpit for local
/// connections — the tarpit defends against external scan/DoS, and
/// rate-limiting yourself is pointless.
///
/// C cases: AF_INET (high octet == 127), AF_INET6 (`IN6_IS_ADDR_
/// LOOPBACK` → `::1`), AF_UNIX (always true). We don't see AF_UNIX
/// here (TCP only); two cases.
///
/// std's `Ipv4Addr::is_loopback` is `127.0.0.0/8` (matches C's `>> 24
/// == 127`). `Ipv6Addr::is_loopback` is `::1` only (matches
/// `IN6_IS_ADDR_LOOPBACK`).
#[must_use]
pub fn is_local(sa: &SocketAddr) -> bool {
    match sa {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

// pidfile_addr — init_control's address-mapping

/// `init_control` lines :155-176: build the pidfile address string.
///
/// Take the first listener's bound addr, map `0.0.0.0` → `127.0.0.1`
/// and `::` → `::1` (a CLI on the same host needs a connectable addr,
/// not the wildcard), format as `"HOST port PORT"`.
///
/// The format is `sockaddr2hostname` (`netutl.c:188`): `"%s port %s"`.
/// std's `Display` for SocketAddr is `"host:port"`. The CLI's pidfile
/// parser (`tinc-tools/ctl.rs`) splits on `" port "`.
///
/// Why the unspecified→loopback mapping: the daemon binds `0.0.0.0`
/// (all interfaces). The CLI reads the pidfile, connects. `connect(
/// 0.0.0.0, port)` is undefined (Linux interprets it as 127.0.0.1
/// but BSD doesn't). C `:164-173` patches it.
///
/// On systems where v6 binds first (depends on getaddrinfo ordering,
/// which depends on /etc/gai.conf), `listeners[0]` is the v6 entry.
/// We bind v4 first deterministically, so `listeners[0]` is always
/// v4 IF v4 is enabled. If `AddressFamily = ipv6`, it's v6. The
/// mapping handles both.
#[must_use]
pub fn pidfile_addr(listeners: &[Listener]) -> String {
    // C `:161`: `if(getsockname(...))` failure → fall back to
    // `"127.0.0.1 port %s" % myport`. We've already done getsockname
    // in `open_one`; can't fail here.
    // No listeners: caller will error separately. C `:161` would fail
    // getsockname on fd=0 (stdin) and fall through to the printf.
    // Match the printf.
    let local = listeners
        .first()
        .map_or_else(|| (Ipv4Addr::LOCALHOST, 0).into(), |l| l.local);

    // C `:164-173`: 0.0.0.0 → 127.0.0.1, :: → ::1.
    let mapped = match local {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => (Ipv4Addr::LOCALHOST, v4.port()).into(),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => (Ipv6Addr::LOCALHOST, v6.port()).into(),
        x => x,
    };

    // C `:176`: `sockaddr2hostname(&sa)` → `"%s port %s"`.
    // SocketAddr::ip() Display is plain (no port, no brackets for v6).
    format!("{} port {}", mapped.ip(), mapped.port())
}

// Tarpit

/// `max_connection_burst` (`net_socket.c:45`). Leaky bucket capacity.
/// C default; the runtime value comes from `MaxConnectionBurst` config
/// via `Tarpit::new`. Tests use this to seed the default behaviour.
#[cfg(test)]
const MAX_BURST: u32 = 10;

/// `pits` array length (`net.c:97`). Ring buffer of tarpitted fds.
const PIT_SIZE: usize = 10;

/// `check_tarpit` (`net_socket.c:681-732`) + `tarpit` (`net.c:96-109`).
///
/// Two leaky buckets:
/// - same-host: `prev_sa` tracks the last peer; if THIS peer matches,
///   drain+refill the same-host bucket. `> MAX_BURST` → pit.
/// - all-host: drain+refill regardless of peer. `>= MAX_BURST` → pit.
///
/// The off-by-one between `>` and `>=` IS in the C (`:699` vs `:721`).
/// Same-host triggers at 11; all-host at 10. Port faithfully.
///
/// `pits[]`: ring buffer of fds we accepted but won't serve. They
/// stay open, doing nothing, until evicted by a NEWER pit (10 slots).
/// The peer's `connect()` succeeds (TCP handshake completes — kernel
/// did that before we called `accept`), but reads block forever.
/// Slows down scanners. C `net.c:96-109`.
///
/// C uses 5 statics (`prev_sa`, `samehost_burst`, `samehost_burst_
/// time`, `connection_burst`, `connection_burst_time`) + 2 more in
/// `tarpit` (`pits[]`, `next_pit`). Seven fields in one struct.
///
/// `now` is `tinc-event::Timers::now()` — the cached per-tick Instant.
/// The C uses `now.tv_sec` (the cached `struct timeval`). We compare
/// at second granularity (`.as_secs()`) to match C's `time_t`
/// arithmetic.
pub struct Tarpit {
    /// `prev_sa` (`:684`). The last peer's address, port-stripped.
    /// `None` is the initial state — first peer never matches.
    /// C uses `static sockaddr_t prev_sa = {0}` which is the zero
    /// addr; comparing against zero never matches a real peer either
    /// (`0.0.0.0` isn't a valid source). Explicit None is clearer.
    prev_addr: Option<SocketAddr>,

    /// `samehost_burst` (`:687`). Current bucket fill, same-host.
    samehost_burst: u32,
    /// `samehost_burst_time` (`:688`). Last refill time.
    samehost_time: Instant,

    /// `connection_burst` (`:709`). All-host bucket.
    allhost_burst: u32,
    /// `connection_burst_time` (`:710`).
    allhost_time: Instant,

    /// `max_connection_burst` (`net_socket.c:45`). Per-instance
    /// from config (`MaxConnectionBurst`); the C is a global. The
    /// `>` vs `>=` off-by-one (see struct doc) is preserved.
    max_burst: u32,

    /// `pits[10]` (`net.c:97`). Tarpitted fds. Ring buffer.
    /// Option because the slot is empty until first eviction.
    /// OwnedFd because Drop closes — the C does `closesocket(pits[
    /// next_pit])` on eviction (`net.c:100-101`); we get that via
    /// `mem::replace` dropping the old value.
    pits: [Option<OwnedFd>; PIT_SIZE],
    /// `next_pit` (`net.c:98`). Ring cursor.
    next_pit: usize,
}

impl Tarpit {
    /// Construct empty. `now` seeds `*_time` so the first leak doesn't
    /// drain epoch-seconds-worth (the C's `static time_t = 0` first-
    /// tick bug — same one we faithfully ported in `top.rs` — would
    /// happen here if we used `Duration::ZERO`. We don't, because
    /// `Instant` doesn't have a zero).
    #[must_use]
    pub fn new(now: Instant, max_burst: u32) -> Self {
        Self {
            prev_addr: None,
            samehost_burst: 0,
            samehost_time: now,
            allhost_burst: 0,
            allhost_time: now,
            max_burst,
            pits: Default::default(),
            next_pit: 0,
        }
    }

    /// `check_tarpit` (`:681-732`). Returns `true` if this connection
    /// should be pitted; the caller hands the fd to `pit()` and does
    /// NOT register the connection.
    ///
    /// Mutates self even on `false` — the buckets always update.
    ///
    /// `addr` should be `unmap()`ed and stripped of port. The C
    /// `sockaddrcmp_noport` (`netutl.c:228`) zeroes the port before
    /// `memcmp`. We use `SocketAddr` with port set to 0 by the caller
    /// (or compare just `.ip()` — but port-0 makes the test setup
    /// readable).
    ///
    /// `now` from `Timers::now()`. The drain is `(now - last).as_
    /// secs()` — second granularity to match C's `time_t`.
    pub fn check(&mut self, addr: SocketAddr, now: Instant) -> bool {
        // ─── same-host bucket
        // C `:686`: `if(!sockaddrcmp_noport(sa, &prev_sa))`. The `!`
        // is because `sockaddrcmp` is memcmp-style: 0 means equal.
        // Compare on .ip() — the caller's port-strip is just for
        // making test expected-values look nice.
        let same_host = self.prev_addr.is_some_and(|p| p.ip() == addr.ip());

        if same_host {
            // `:690-694`: leak. If MORE seconds elapsed than the
            // bucket holds, drain to zero. Else subtract elapsed.
            let elapsed = now.saturating_duration_since(self.samehost_time).as_secs();
            // C `if(elapsed > burst) burst = 0; else burst -= elapsed`.
            // saturating_sub is the same arithmetic (going below 0
            // means "would have drained"). C uses signed `time_t`;
            // a negative `elapsed` (clock went backwards) would
            // INCREASE burst. saturating_duration_since clamps that
            // to zero — STRICTER than C, harmless.
            #[allow(clippy::cast_possible_truncation)] // elapsed.as_secs()
            // fits in u32 unless the daemon's been up 136 years.
            // Truncation would just under-drain; bucket fills, peer
            // gets pitted. Same direction as the limit anyway.
            {
                self.samehost_burst = self.samehost_burst.saturating_sub(elapsed as u32);
            }
            self.samehost_time = now;
            self.samehost_burst += 1;

            // `:699`: `if(samehost_burst > max_connection_burst)`.
            // STRICTLY greater. Triggers at 11.
            if self.samehost_burst > self.max_burst {
                return true;
            }
        }

        // `:705`: `prev_sa = *sa`. Update AFTER the same-host check.
        // First connection from a new host doesn't tick the same-host
        // bucket (it's "different from prev"); SECOND connection does.
        self.prev_addr = Some(addr);

        // ─── all-host bucket
        // Same arithmetic, different bucket.
        let elapsed = now.saturating_duration_since(self.allhost_time).as_secs();
        #[allow(clippy::cast_possible_truncation)] // see above
        {
            self.allhost_burst = self.allhost_burst.saturating_sub(elapsed as u32);
        }
        self.allhost_time = now;
        self.allhost_burst += 1;

        // `:721`: `if(connection_burst >= max_connection_burst)`.
        // GREATER OR EQUAL. Triggers at 10. THEN clamps (`:722`:
        // `connection_burst = max_connection_burst`).
        //
        // The clamp means the all-host bucket never exceeds 10. So
        // the leak only needs to drain 1 to let the next conn in.
        // Same-host has no clamp (and `>` not `>=`), so it can go
        // to 11. Two seconds of leak to drain back to 9.
        //
        // I think the C author intended both to behave the same and
        // the off-by-one is accidental. Port faithfully — it's been
        // this way since 2013 (commit `efa42d92`) and nobody's
        // noticed.
        if self.allhost_burst >= self.max_burst {
            self.allhost_burst = self.max_burst;
            return true;
        }

        false
    }

    /// `tarpit` (`net.c:96-109`). Shove the fd into the pit ring.
    /// Evict-on-insert: if the slot is occupied, drop the old fd
    /// (closes it).
    ///
    /// The fd MUST NOT be registered with the event loop. We're
    /// silent-treatment-ing the peer: their `connect` succeeded (the
    /// kernel did the 3-way handshake before `accept` returned),
    /// reads block, writes succeed until the kernel buffer fills.
    /// They look connected but nothing happens.
    ///
    /// 10 slots = 10 simultaneous tarpitted peers. The 11th evicts
    /// the 1st (its `OwnedFd` drops, peer sees RST). Fixed memory.
    pub fn pit(&mut self, fd: OwnedFd) {
        // `net.c:100-101`: `if(pits[next_pit] != -1) closesocket(...)`.
        // Option::replace drops the old OwnedFd; Drop closes. The
        // returned old value is dropped immediately (we don't bind it).
        // `let _ =` so clippy knows the discard is intentional.
        let _ = self.pits[self.next_pit].replace(fd);
        // `net.c:104-108`: `next_pit++; if(next_pit >= 10) next_pit = 0`.
        self.next_pit = (self.next_pit + 1) % PIT_SIZE;
    }

    /// Test seam: how full are the buckets? Not in C (the statics
    /// aren't exposed); useful for asserting "9 connections is
    /// fine, 10th gets pitted" without spawning real sockets.
    #[cfg(test)]
    pub(crate) fn buckets(&self) -> (u32, u32) {
        (self.samehost_burst, self.allhost_burst)
    }
}

// sockaddr2hostname (the printable-address part)

/// `sockaddr2hostname` (`netutl.c:183-203`) — a subset. The C does
/// `getnameinfo` with `NI_NUMERICHOST | NI_NUMERICSERV`, which is
/// just printf for the addr (no DNS). std's `Display` for `IpAddr`
/// does the same.
///
/// Format: `"HOST port PORT"`. Appears in log lines and the pidfile.
/// `tinc-tools::Tok` parses this with `lit(" port ")`.
///
/// We DON'T do the `AF_UNKNOWN` case (`netutl.c:193`) — that's for
/// addresses round-tripped through the wire protocol's text format,
/// which our `SocketAddr` can't represent. `tinc-proto::addr` has
/// the full-generality version; this is for SOCKETS we own.
#[must_use]
pub fn fmt_addr(sa: &SocketAddr) -> String {
    // C `:202`: `xasprintf("%s port %s", host, port)`. The %s comes
    // from getnameinfo NI_NUMERICHOST. For v6 that's "::1" not "[::1]"
    // (NI_NUMERICHOST doesn't bracket). std's Ipv6Addr Display also
    // doesn't bracket. Match.
    format!("{} port {}", sa.ip(), sa.port())
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use nix::sys::socket::getsockopt;

    /// Shorthand for tests that don't care about sockopts.
    fn opts() -> SockOpts {
        SockOpts::default()
    }
    use std::net::{SocketAddrV4, SocketAddrV6};

    /// Reduce stutter. `addr("10.0.0.5", 0)` for v4, `addr("::1", 0)` for v6.
    fn addr(s: &str, port: u16) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), port)
    }

    // ─── unmap

    /// C `IN6_IS_ADDR_V4MAPPED`. `unmap(SocketAddr) -> SocketAddr` is
    /// ~5 lines; pin its full domain in one table.
    #[test]
    fn unmap_cases() {
        #[rustfmt::skip]
        let cases: &[(&str, &str)] = &[
            // v4-mapped → v4. THE conversion.
            ("[::ffff:10.0.0.5]:655", "10.0.0.5:655"),
            // `::ffff:0.0.0.0` IS a valid mapped addr (the v4 wildcard).
            // to_ipv4_mapped returns Some(0.0.0.0).
            ("[::ffff:0.0.0.0]:655",  "0.0.0.0:655"),
            // `::1` is NOT v4-mapped. Passes through unchanged.
            ("[::1]:655",             "[::1]:655"),
            // 2001:db8::1 — non-loopback, also unchanged.
            ("[2001:db8::1]:655",     "[2001:db8::1]:655"),
            // v4 already plain.
            ("10.0.0.5:655",          "10.0.0.5:655"),
        ];
        for (i, (input, expected)) in cases.iter().enumerate() {
            let sa: SocketAddr = input.parse().unwrap();
            let want: SocketAddr = expected.parse().unwrap();
            assert_eq!(unmap(sa), want, "case {i}: {input}");
        }
        // The first row's IS-v4 property (the conversion happened):
        assert!(unmap("[::ffff:10.0.0.5]:655".parse().unwrap()).is_ipv4());
    }

    // ─── is_local

    /// v4: 127.0.0.0/8 (C `:308`: `ntohl(...) >> 24 == 127`). Any
    /// addr in the /8, not just .0.0.1.
    /// v6: `::1` ONLY (C `IN6_IS_ADDR_LOOPBACK`), not the whole `::/8`.
    #[test]
    fn is_local_cases() {
        #[rustfmt::skip]
        let cases: &[(&str, bool)] = &[
            // ─── v4: the whole /8 (port doesn't matter)
            ("127.0.0.1",         true),
            ("127.255.255.255",   true),
            ("127.42.42.42",      true),
            // ─── v6: exactly ::1
            ("::1",               true),
            ("::2",               false),
            // ::ffff:127.0.0.1 — v4-mapped loopback. NOT a v6 loopback.
            // C `IN6_IS_ADDR_LOOPBACK` is exactly `::1`. The caller
            // should `unmap()` first; if they don't, this is `false`.
            ("::ffff:127.0.0.1",  false),
            // ─── nonlocal
            ("10.0.0.5",          false),
            ("192.168.1.1",       false),
            ("2001:db8::1",       false),
            // Unspecified isn't loopback.
            ("0.0.0.0",           false),
            ("::",                false),
        ];
        for (i, (ip, expected)) in cases.iter().enumerate() {
            assert_eq!(is_local(&addr(ip, 655)), *expected, "case {i}: {ip}");
        }
        // Port doesn't matter (re-check one row at port 0).
        assert!(is_local(&addr("127.0.0.1", 0)));
    }

    /// The `unmap → is_local` composition is the actual call shape
    /// in `handle_new_meta_connection`. v4-mapped loopback survives.
    #[test]
    fn unmap_then_is_local() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:655".parse().unwrap();
        assert!(is_local(&unmap(mapped)));
    }

    // ─── fmt_addr / pidfile_addr

    /// `sockaddr2hostname` format. The CLI's `Tok::lit(" port ")`
    /// parser expects exactly this. v6: NO brackets — C
    /// `getnameinfo NI_NUMERICHOST` doesn't bracket; std
    /// `Ipv6Addr::Display` doesn't either.
    #[test]
    fn fmt_addr_cases() {
        #[rustfmt::skip]
        let cases: &[(&str, u16, &str)] = &[
            ("10.0.0.5",     655, "10.0.0.5 port 655"),
            ("::1",          655, "::1 port 655"),         // no brackets
            ("2001:db8::1",  655, "2001:db8::1 port 655"), // no brackets
        ];
        for (i, (ip, port, expected)) in cases.iter().enumerate() {
            assert_eq!(fmt_addr(&addr(ip, *port)), *expected, "case {i}: {ip}");
        }
    }

    /// `pidfile_addr` does the unspec→loopback mapping. We can't
    /// test it directly without a real `Listener` (needs sockets),
    /// but the mapping logic is the same as `init_control:164-173`.
    /// Integration test (`stop.rs::tcp_connect_stop`) verifies via
    /// the actual pidfile.
    ///
    /// What we CAN test: empty slice → "127.0.0.1 port 0". The C
    /// `:161` getsockname-fail fallback.
    #[test]
    fn pidfile_addr_empty_fallback() {
        assert_eq!(pidfile_addr(&[]), "127.0.0.1 port 0");
    }

    // ─── AddrFamily

    /// C `net_setup.c:538-548`. strcasecmp.
    #[test]
    fn addr_family_parse() {
        assert_eq!(AddrFamily::from_config("ipv4"), Some(AddrFamily::Ipv4));
        assert_eq!(AddrFamily::from_config("IPv4"), Some(AddrFamily::Ipv4));
        assert_eq!(AddrFamily::from_config("IPV6"), Some(AddrFamily::Ipv6));
        assert_eq!(AddrFamily::from_config("any"), Some(AddrFamily::Any));
        // Unknown: C falls through, leaves addressfamily at default.
        assert_eq!(AddrFamily::from_config("both"), None);
        assert_eq!(AddrFamily::from_config(""), None);
    }

    #[test]
    fn addr_family_try() {
        assert!(AddrFamily::Any.try_v4());
        assert!(AddrFamily::Any.try_v6());
        assert!(AddrFamily::Ipv4.try_v4());
        assert!(!AddrFamily::Ipv4.try_v6());
        assert!(!AddrFamily::Ipv6.try_v4());
        assert!(AddrFamily::Ipv6.try_v6());
    }

    // ─── Tarpit: leaky bucket arithmetic
    //
    // Seeded `now` lets us control time. The pit-ring is tested
    // separately with real fds (devnull); the bucket math is pure.

    /// Advance time by N seconds. Kept tiny so test bodies read.
    fn after(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// 9 connections from DIFFERENT hosts in 0 seconds: all OK.
    /// 10th: pitted. The all-host bucket triggers at `>= 10`.
    /// (`net_socket.c:721`: `>=`.)
    #[test]
    fn tarpit_allhost_triggers_at_ten() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // 9 different /24 hosts, no time elapsed.
        for i in 1..=9u8 {
            let a = SocketAddr::V4(SocketAddrV4::new([10, 0, 0, i].into(), 0));
            assert!(!tp.check(a, t0), "conn {i} should pass");
        }
        let (_, allhost) = tp.buckets();
        assert_eq!(allhost, 9);

        // 10th: triggers.
        let a10 = addr("10.0.0.100", 0);
        assert!(tp.check(a10, t0), "10th should be pitted");
        // Bucket clamped at 10.
        let (_, allhost) = tp.buckets();
        assert_eq!(allhost, 10);
    }

    /// The same-host early-return. When same-host triggers, it returns
    /// BEFORE updating `prev_addr` or the all-host bucket. C `:699-702`:
    /// `if(samehost_burst > max) { tarpit(fd); return true; }` — the
    /// `return` is before `:705 prev_sa = *sa` and before the all-host
    /// section.
    ///
    /// Observable effect: once same-host triggers, the attacker's burst
    /// stops ticking all-host. The all-host bucket can leak. A legit
    /// different host arriving 1+ sec later might get through.
    ///
    /// Trace (all conns at t=0 unless noted):
    /// - conn 1 (A): prev=None, no match. sh=0. ah=1.
    /// - conn 2..9 (A): prev=A, match. sh ticks: 1,2,...,8. ah: 2..9.
    /// - conn 10 (A): sh=9. ah=10, >=10, PITTED by all-host. ah clamped
    ///   at 10. prev_addr was updated (prev_sa update is BEFORE the
    ///   all-host check, AFTER the same-host check).
    /// - conn 11 (A): sh=10. >10? no. ah: 10-0+1=11, >=10, PITTED by
    ///   all-host. Clamped at 10 again.
    /// - conn 12 (A): sh=11. >10? YES. PITTED BY SAME-HOST. Early
    ///   return: ah stays at 10, prev_addr stays A.
    /// - conn 13 (A): sh=12. Same-host pit again. ah STILL 10.
    /// - conn 14 (B) at t=2: prev=A, no match. sh stays 12. ah: 10-2=8,
    ///   refill to 9. PASSES.
    ///
    /// Observable difference vs no-early-return: `prev_addr` and
    /// `allhost_time` freeze. A subsequent DIFFERENT host's leak
    /// measures from the last pre-pit allhost timestamp, giving it
    /// MORE leak. Whether the C author intended this is unclear (the
    /// `>` vs `>=` and early-return placement look incidental). Port
    /// faithfully; this test pins the early-return-skips-allhost shape.
    #[test]
    fn tarpit_samehost_early_return() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        let attacker = addr("10.0.0.5", 0);

        // conn 1: prev=None, sh stays 0, ah=1.
        assert!(!tp.check(attacker, t0));
        assert_eq!(tp.buckets(), (0, 1));

        // conns 2..=9: sh and ah both tick. sh: 1..8, ah: 2..9.
        for i in 2..=9 {
            assert!(!tp.check(attacker, t0), "conn {i} passes");
        }
        assert_eq!(tp.buckets(), (8, 9));

        // conn 10: sh=9 (>10? no). ah hits 10, >=10, PIT. Clamp to 10.
        assert!(tp.check(attacker, t0), "conn 10: all-host pit");
        assert_eq!(tp.buckets(), (9, 10));

        // conn 11: sh=10 (>10? no, still pass to ah). ah=10→11→clamp.
        assert!(tp.check(attacker, t0), "conn 11: all-host pit again");
        assert_eq!(tp.buckets(), (10, 10));

        // conn 12: sh=11. >10? YES. SAME-HOST pit. Early return:
        // ah NOT touched.
        assert!(tp.check(attacker, t0), "conn 12: SAME-HOST pit");
        assert_eq!(tp.buckets(), (11, 10), "ah frozen — early return");

        // conn 13..15: same-host keeps firing. ah still frozen.
        for _ in 13..=15 {
            assert!(tp.check(attacker, t0));
        }
        let (sh, ah) = tp.buckets();
        assert_eq!(sh, 14, "sh keeps ticking");
        assert_eq!(ah, 10, "ah STILL frozen — the early-return proof");

        // ─── the part that's actually OBSERVABLE: prev_addr frozen
        // prev_addr is still `attacker` (last update was conn 11,
        // before same-host took over). A different host at t=2:
        // doesn't match prev (good), ah leaks from t=0 (allhost_time
        // also frozen at conn 11's timestamp).
        assert_eq!(tp.prev_addr, Some(attacker), "prev frozen too");
        // allhost_time was last updated at conn 11 (t=0). At t=2,
        // elapsed = 2, ah: 10-2=8, +1 = 9. Passes.
        let legit = addr("10.0.0.200", 0);
        assert!(!tp.check(legit, after(t0, 2)), "legit host passes");
        assert_eq!(tp.buckets().1, 9);
    }

    /// One more bucket-independence proof: alternating hosts. A→B→A→B
    /// never ticks the same-host bucket (each conn's prev is the OTHER
    /// host). Only all-host accumulates.
    ///
    /// This is realistic: a port scanner that walks IPs. The C tarpit
    /// catches it via all-host, not same-host.
    #[test]
    fn tarpit_alternating_hosts_only_allhost() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        let host_a = addr("10.0.0.1", 0);
        let host_b = addr("10.0.0.2", 0);

        // 9 alternating conns: A,B,A,B,A,B,A,B,A. sh stays 0
        // throughout (prev never matches the CURRENT conn:
        // A→prev=None→no, B→prev=A→no, A→prev=B→no, ...).
        // After conn 9 (A), prev = A.
        for i in 0..9 {
            let h = if i % 2 == 0 { host_a } else { host_b };
            assert!(!tp.check(h, t0));
            assert_eq!(tp.buckets().0, 0, "conn {}: sh stays 0", i + 1);
        }
        assert_eq!(tp.buckets().1, 9);

        // 10th: B (continuing the alternation; i=9 would be odd → B).
        // prev=A≠B, sh stays 0. ah hits 10, pitted by all-host.
        assert!(tp.check(host_b, t0));
        assert_eq!(tp.buckets(), (0, 10), "sh STILL 0; ah triggered");
    }

    /// Drain: wait long enough, bucket empties.
    #[test]
    fn tarpit_drain() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        let host_a = addr("10.0.0.1", 0);

        // Fill to 5 (different hosts to avoid samehost interaction).
        for i in 1..=5u8 {
            let a = SocketAddr::V4(SocketAddrV4::new([10, 0, 0, i].into(), 0));
            assert!(!tp.check(a, t0));
        }
        assert_eq!(tp.buckets().1, 5);

        // Wait 5 seconds. Next conn drains 5 (bucket → 0), refills 1.
        assert!(!tp.check(host_a, after(t0, 5)));
        assert_eq!(tp.buckets().1, 1);

        // Wait MORE than the bucket holds. saturating_sub clamps to 0.
        assert!(!tp.check(host_a, after(t0, 100)));
        assert_eq!(tp.buckets().1, 1, "drained to 0, refilled to 1");
    }

    /// `prev_addr` updates regardless of whether check returned true.
    /// (In the C, `:705 prev_sa = *sa` is BEFORE the all-host check.)
    /// So: pitted conn becomes the new prev. Next conn from a
    /// DIFFERENT host doesn't tick samehost.
    #[test]
    fn tarpit_prev_updates_on_pit() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // Fill all-host to threshold.
        for i in 1..=9u8 {
            let a = SocketAddr::V4(SocketAddrV4::new([10, 0, 0, i].into(), 0));
            assert!(!tp.check(a, t0));
        }
        // 10th: pitted. prev becomes 10.0.0.100.
        assert!(tp.check(addr("10.0.0.100", 0), t0));
        assert_eq!(tp.prev_addr, Some(addr("10.0.0.100", 0)));

        // Different host. After 10 sec, all-host drained.
        // Samehost bucket stays at 0 (10.0.0.200 != prev=10.0.0.100).
        let later = after(t0, 10);
        assert!(!tp.check(addr("10.0.0.200", 0), later));
        let (sh, _) = tp.buckets();
        assert_eq!(sh, 0, "different host, samehost untouched");
    }

    /// SAME-host check is on `.ip()`, port-agnostic. C
    /// `sockaddrcmp_noport`. Different ports from same IP = same host.
    #[test]
    fn tarpit_ignores_port() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // Seed prev.
        assert!(!tp.check(addr("10.0.0.5", 1000), t0));
        // Same IP, different port. Ticks samehost.
        assert!(!tp.check(addr("10.0.0.5", 2000), after(t0, 1)));
        assert_eq!(tp.buckets().0, 1, "same IP = same host");
    }

    /// v6 addresses too.
    #[test]
    fn tarpit_v6() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // 10 different v6 hosts.
        for i in 1..=9u16 {
            let a = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i),
                0,
                0,
                0,
            ));
            assert!(!tp.check(a, t0));
        }
        assert!(tp.check(addr("2001:db8::ffff", 0), t0));
    }

    // ─── Tarpit: pit ring buffer

    /// /dev/null fd. Dup'd because we want distinct OwnedFd's that
    /// each genuinely close on drop. `OwnedFd::try_clone` returns a
    /// fresh fd (dup).
    fn nullfd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    /// The ring wraps at 10. 11th eviction closes the 1st.
    /// We can't observe "fd closed" directly without leaking
    /// implementation details, but we CAN verify the cursor wraps
    /// and no panic occurs.
    #[test]
    fn pit_ring_wrap() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // Fill all 10 slots.
        for _ in 0..PIT_SIZE {
            tp.pit(nullfd());
        }
        assert_eq!(tp.next_pit, 0, "wrapped");
        // All slots Some.
        assert!(tp.pits.iter().all(Option::is_some));

        // 11th evicts slot 0 (the OLD fd drops here).
        tp.pit(nullfd());
        assert_eq!(tp.next_pit, 1);
    }

    /// Drop closes everything. We can verify the drop actually runs
    /// by counting open fds before/after, but that's brittle (other
    /// tests in the same process open fds). Instead: verify the
    /// destructure doesn't panic. The actual close is OwnedFd's
    /// contract (which std tests).
    #[test]
    fn pit_drop_is_clean() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        for _ in 0..5 {
            tp.pit(nullfd());
        }
        drop(tp);
        // No panic. OwnedFd dropped 5 fds.
    }

    // ─── open_listeners
    //
    // These bind real sockets. Port 0 (kernel-assigned) avoids clashes
    // between parallel test threads. The actual bind path is what the
    // integration test exercises; here we just verify the v4/v6/any
    // selection and that fds are CLOEXEC.

    /// `AddressFamily = ipv4`: one v4 listener, no v6.
    #[test]
    fn open_v4_only() {
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        assert_eq!(listeners.len(), 1);
        assert!(listeners[0].local.is_ipv4());
        // Port assigned by kernel.
        assert_ne!(listeners[0].local.port(), 0);
    }

    /// `AddressFamily = any`: one or two depending on system v6 support.
    /// CI might be v4-only; both outcomes are valid.
    #[test]
    fn open_any_one_or_two() {
        let listeners = open_listeners(0, AddrFamily::Any, &opts());
        assert!(
            listeners.len() == 1 || listeners.len() == 2,
            "got {} listeners",
            listeners.len()
        );
        // First is always v4 (we try v4 first).
        if !listeners.is_empty() {
            assert!(listeners[0].local.is_ipv4());
        }
    }

    /// CLOEXEC set. socket2 does this via SOCK_CLOEXEC. C does it
    /// via separate fcntl. Either way: `script.c` children don't
    /// inherit.
    #[test]
    fn open_cloexec() {
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        let (tcp_fd, udp_fd) = listeners[0].fds();

        // F_GETFD bit 0 = FD_CLOEXEC.
        for &fd in &[tcp_fd, udp_fd] {
            let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).unwrap());
            assert!(
                flags.contains(FdFlag::FD_CLOEXEC),
                "fd {fd} missing CLOEXEC"
            );
        }
    }

    /// V6ONLY set on v6 listener. Load-bearing for dual-stack.
    /// Skipped if system doesn't support v6.
    #[test]
    fn open_v6only_set() {
        let listeners = open_listeners(0, AddrFamily::Ipv6, &opts());
        // Might be empty on v6-disabled systems.
        let Some(l) = listeners.first() else {
            eprintln!("v6 unavailable, skipping");
            return;
        };
        // socket2 has `only_v6()` getter. Check it.
        assert!(l.tcp.only_v6().unwrap());
    }

    /// UDP socket is non-blocking. TCP listener doesn't need to be
    /// (accept-when-epoll-says-ready blocks on a ready fd, returns
    /// immediately).
    #[test]
    fn open_udp_nonblocking() {
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        let (_, udp_fd) = listeners[0].fds();
        let flags = OFlag::from_bits_truncate(fcntl(udp_fd, FcntlArg::F_GETFL).unwrap());
        assert!(flags.contains(OFlag::O_NONBLOCK));
    }

    /// `setup_udp` sets `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (and the v6
    /// analogue). Read it back. Can't test the actual PMTU behaviour
    /// here (the netns harness uses lo, MTU 65536) but we CAN prove
    /// the syscall fires. Regression for the gap-audit's #1 finding:
    /// without this, Linux defaults to `IP_PMTUDISC_WANT` and the
    /// pmtu.rs probes get L3-fragmented through.
    #[test]
    fn open_udp_pmtudisc_do() {
        fn get_mtu_discover(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> libc::c_int {
            let mut val: libc::c_int = -1;
            // SAFETY: fd is live (held by `listeners` for the test's
            // duration); val/len are stack locals.
            // truncation: size_of::<c_int>() == 4, fits socklen_t.
            #[allow(unsafe_code, clippy::cast_possible_truncation)]
            let rc = unsafe {
                let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                libc::getsockopt(
                    fd,
                    level,
                    optname,
                    (&raw mut val).cast::<libc::c_void>(),
                    &raw mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt: {}", io::Error::last_os_error());
            val
        }

        // v4: always available.
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        let (_, udp_fd) = listeners[0].fds();
        assert_eq!(
            get_mtu_discover(udp_fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            libc::IP_PMTUDISC_DO,
        );

        // v6: may be disabled. Skip if no listener.
        let listeners6 = open_listeners(0, AddrFamily::Ipv6, &opts());
        if let Some(l) = listeners6.first() {
            let (_, udp_fd) = l.fds();
            assert_eq!(
                get_mtu_discover(udp_fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
                libc::IPV6_PMTUDISC_DO,
            );
        }
    }

    /// Second listener pair on the same port: TCP bind fails (REUSEADDR
    /// only helps with TIME_WAIT, not active listeners). The fail is
    /// graceful — `open_one` returns `None`, no panic.
    ///
    /// This is the "EADDRINUSE → continue" path (`:705`).
    #[test]
    fn open_port_clash_is_graceful() {
        let first = open_listeners(0, AddrFamily::Ipv4, &opts());
        let port = first[0].local.port();

        // Same port. SO_REUSEADDR is set, but there's an active
        // listener — bind fails anyway.
        let second = open_listeners(port, AddrFamily::Ipv4, &opts());
        assert!(second.is_empty(), "second bind on port {port} should fail");
        drop(first);
    }

    /// `setup_udp` sets `SO_RCVBUF`/`SO_SNDBUF`. Read back. Linux
    /// doubles the requested value (overhead accounting) then caps at
    /// `net.core.{r,w}mem_max`. We can't predict the cap, but we CAN
    /// assert the value moved — kernel default is ~200KB, we ask for
    /// 1MB, so readback should be > the default for an unconfigured
    /// socket. Compare against a sibling socket with `udp_rcvbuf=0`
    /// (skip-the-setsockopt) to get the kernel baseline.
    #[test]
    fn open_udp_rcvbuf_set() {
        // Baseline: explicitly skip the setsockopt.
        let skip = SockOpts {
            udp_rcvbuf: 0,
            udp_sndbuf: 0,
            ..SockOpts::default()
        };
        let baseline = open_listeners(0, AddrFamily::Ipv4, &skip);
        let base_rcv = getsockopt(&baseline[0].udp.as_fd(), sockopt::RcvBuf).unwrap();
        let base_snd = getsockopt(&baseline[0].udp.as_fd(), sockopt::SndBuf).unwrap();

        // Default 1MB request.
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        let rcv = getsockopt(&listeners[0].udp.as_fd(), sockopt::RcvBuf).unwrap();
        let snd = getsockopt(&listeners[0].udp.as_fd(), sockopt::SndBuf).unwrap();

        // Even capped, the request should at least equal the kernel
        // default (sysctl `net.core.rmem_default` ≤ `rmem_max`).
        // Typically: base ≈ 212992, ours ≈ 425984 or 2097152.
        assert!(rcv >= base_rcv, "SO_RCVBUF: got {rcv}, baseline {base_rcv}");
        assert!(snd >= base_snd, "SO_SNDBUF: got {snd}, baseline {base_snd}");
        // And it definitely changed from "nothing was set".
        assert_ne!(rcv, 0);
    }

    /// `SO_BINDTODEVICE` to `lo`. Always exists. Read back.
    /// nix returns it with a trailing NUL — strip before compare.
    #[test]
    fn open_bind_to_interface_lo() {
        let o = SockOpts {
            bind_to_interface: Some("lo".into()),
            ..SockOpts::default()
        };
        let listeners = open_listeners(0, AddrFamily::Ipv4, &o);
        assert_eq!(listeners.len(), 1, "bind to lo should succeed");

        // Readback on the UDP fd (TCP would do too — both get it).
        let got = getsockopt(&listeners[0].udp.as_fd(), sockopt::BindToDevice).unwrap();
        let got = got.to_string_lossy();
        let got = got.trim_end_matches('\0');
        assert_eq!(got, "lo");
    }

    /// `SO_BINDTODEVICE` to a nonexistent interface: hard failure.
    /// `open_one` returns `None` (the C closes the fd at `:244,391`).
    /// No panic; the listener pair just doesn't materialize.
    #[test]
    fn open_bind_to_interface_bad_is_graceful() {
        let o = SockOpts {
            bind_to_interface: Some("nonexistent-iface-9z".into()),
            ..SockOpts::default()
        };
        let listeners = open_listeners(0, AddrFamily::Ipv4, &o);
        assert!(listeners.is_empty(), "bad interface should kill the pair");
    }

    /// `SO_MARK` requires `CAP_NET_ADMIN`. Skip unless root.
    /// (Gating on euid is crude but matches the netns harness's
    /// shape; the cap-aware check would be `prctl(PR_CAPBSET_READ)`
    /// but that's overkill for a unit test.)
    #[test]
    fn open_fwmark_set() {
        // SAFETY: geteuid is infallible, no pointers.
        #[allow(unsafe_code)]
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            eprintln!("SKIP open_fwmark_set: SO_MARK needs CAP_NET_ADMIN (euid={euid})");
            return;
        }
        let o = SockOpts {
            fwmark: 0x1234,
            ..SockOpts::default()
        };
        let listeners = open_listeners(0, AddrFamily::Ipv4, &o);
        assert_eq!(listeners.len(), 1);
        // Read back from BOTH sockets — TCP `:248` and UDP `:383`.
        let tcp_mark = getsockopt(&listeners[0].tcp.as_fd(), sockopt::Mark).unwrap();
        let udp_mark = getsockopt(&listeners[0].udp.as_fd(), sockopt::Mark).unwrap();
        assert_eq!(tcp_mark, 0x1234);
        assert_eq!(udp_mark, 0x1234);
    }

    /// `fwmark = 0` (default) means "don't set". Verify the syscall
    /// is skipped: SO_MARK readback is 0 even though we never called
    /// setsockopt. (Weak assertion — kernel default IS 0 — but
    /// proves we don't crash on the unprivileged path.)
    #[test]
    fn open_fwmark_zero_is_skip() {
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        let mark = getsockopt(&listeners[0].udp.as_fd(), sockopt::Mark).unwrap();
        assert_eq!(mark, 0);
    }

    /// `bind_reusing_port` (`net_setup.c:613-632`): with `Port=0`,
    /// TCP gets a kernel ephemeral, UDP reuses it. Before this
    /// landed, the two sockets got DIFFERENT kernel ports — peers
    /// connecting on TCP would learn port X, then send UDP to X
    /// where nobody's listening (UDP was on Y).
    #[test]
    fn open_port_zero_tcp_udp_same_port() {
        let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
        let l = &listeners[0];
        let tcp_port = l.local.port();
        let udp_port = l.udp_port();
        assert_ne!(tcp_port, 0, "kernel assigned a port");
        assert_eq!(tcp_port, udp_port, "UDP reused TCP's ephemeral");
    }

    /// With `Port=0` and `AddressFamily=any`, the v6 listener
    /// reuses the v4 listener's port (C `:700`: `from_fd =
    /// listen_socket[0].tcp.fd`). All four sockets (v4 tcp, v4 udp,
    /// v6 tcp, v6 udp) end up on the same port.
    #[test]
    fn open_port_zero_v4_v6_same_port() {
        let listeners = open_listeners(0, AddrFamily::Any, &opts());
        if listeners.len() < 2 {
            eprintln!("v6 unavailable, skipping cross-family port check");
            return;
        }
        let p = listeners[0].local.port();
        assert_ne!(p, 0);
        assert_eq!(listeners[0].udp_port(), p);
        assert_eq!(listeners[1].local.port(), p, "v6 TCP reused v4 port");
        assert_eq!(listeners[1].udp_port(), p, "v6 UDP too");
    }

    /// `assign_static_port`: only overwrite zero ports.
    /// C `net_setup.c:590-601`: `if(!sin_port) sin_port = htons(X)`.
    #[test]
    fn assign_static_port_cases() {
        // Port 0 + reuse → rewritten.
        assert_eq!(
            assign_static_port(addr("10.0.0.1", 0), Some(5000)),
            Some(addr("10.0.0.1", 5000))
        );
        // Port already static → leave alone (None = "nothing to do").
        assert_eq!(assign_static_port(addr("10.0.0.1", 655), Some(5000)), None);
        // No reuse port available → nothing to do.
        assert_eq!(assign_static_port(addr("10.0.0.1", 0), None), None);
        // v6 too (C has separate AF_INET6 case; set_port covers both).
        assert_eq!(
            assign_static_port(addr("::1", 0), Some(5000)),
            Some(addr("::1", 5000))
        );
    }

    /// `bind_reusing_port` fallback (C `:629`). Reuse port is
    /// already taken → fall through to the original addr (port 0
    /// → fresh ephemeral). Prove the listener still materializes.
    #[test]
    fn bind_reusing_port_fallback() {
        // Occupy a port. 127.42.x avoids racing two_daemons'
        // 127.0.0.1 alloc_port (bind-read-drop-rebind TOCTOU).
        let addr: SocketAddr = "127.42.4.1:0".parse().unwrap();
        let first = open_listener_pair(addr, &opts(), None, false).unwrap();
        let taken = first.local.port();

        // Ask for a NEW pair on the same addr reusing `taken`. TCP
        // can't bind (active listener on the same addr+port).
        // Fallback binds port 0 → fresh ephemeral. Listener exists.
        let l = open_listener_pair(addr, &opts(), Some(taken), false)
            .expect("fallback to fresh ephemeral");
        assert_ne!(l.local.port(), taken, "fell back, got a different port");
        assert_ne!(l.local.port(), 0);
        // UDP still followed TCP (the fallback's TCP port, not `taken`).
        assert_eq!(l.udp_port(), l.local.port());
        drop(first);
    }

    /// `open_listener_pair` with a static port: `assign_static_port`
    /// returns None (port is non-zero), `bind_reusing_port` skips
    /// straight to the original addr. Reuse hint never reaches the
    /// kernel. Proven via `assign_static_port` directly (the socket
    /// path is covered by the integration tests; doing
    /// bind-drop-rebind here would TOCTOU-race the parallel
    /// `alloc_port` calls in `tests/two_daemons.rs`).
    #[test]
    fn open_pair_bindto_flag_plumbed() {
        // 127.42.x avoids racing two_daemons' 127.0.0.1 alloc_port.
        let l =
            open_listener_pair("127.42.3.1:0".parse().unwrap(), &opts(), None, true).expect("bind");
        assert!(l.bindto, "bindto=true plumbed through");
        assert_eq!(l.udp_port(), l.local.port(), "port reuse within pair");
    }

    /// `SockOpts::default()` matches C globals at `net_socket.c:41-46`.
    #[test]
    fn sockopts_defaults_match_c() {
        let o = SockOpts::default();
        assert_eq!(o.udp_rcvbuf, 1024 * 1024);
        assert_eq!(o.udp_sndbuf, 1024 * 1024);
        assert!(!o.udp_buf_warnings);
        assert_eq!(o.fwmark, 0);
        assert!(o.bind_to_interface.is_none());
    }
}
