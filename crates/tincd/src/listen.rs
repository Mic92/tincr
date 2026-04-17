//! TCP/UDP listener setup. Ports `setup_listen_socket` (TCP) +
//! `setup_vpn_in_socket` (UDP) from `net_socket.c`, plus the
//! no-config default of `add_listen_address` from `net_setup.c`.
//! The tarpit lives in [`tarpit`].
//!
//! ## socket2, not hand-rolled setsockopt
//!
//! std's `TcpListener::bind` is atomic; no seam for `IPV6_V6ONLY`.
//! socket2 gives the four-step shape (socket/setsockopt/bind/
//! listen). Not a shim-matrix row — it's "std with seams".
//!
//! Used (all ungated): `Socket::new` (auto-`SOCK_CLOEXEC`),
//! `set_reuse_address` (`:210`), `set_only_v6` (`:214` — load-
//! bearing for separate v4+v6 listeners), `set_nodelay`
//! (`configure_tcp:89`), `set_nonblocking`, `set_broadcast`
//! `accept` (uses `accept4(SOCK_CLOEXEC)` — closes a small fd leak
//! upstream has), `SockAddr` (= the `sockaddr_t` union).
//!
//! Deferred sockopts: `IP_TOS`/`IPV6_TCLASS` (`configure_tcp:93-100`).
//!
//! ## getaddrinfo: skip it
//!
//! `add_listen_address(NULL, NULL)` uses getaddrinfo as a
//! per-family probe (`0.0.0.0` then `::`, gcc-verified). We probe
//! by trying both binds; `Socket::new(Domain::IPV6, ...)` failing
//! is the same outcome. Bind failure is `continue`.
//! `BindToAddress` resolution lives in `daemon.rs` (it owns the
//! config tree); resolved `SocketAddr`s flow into
//! `open_listener_pair` here.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(test)]
use std::os::fd::IntoRawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::bind_to_interface;
#[cfg(target_os = "linux")]
use crate::set_int_sockopt;
use nix::sys::socket::{setsockopt, sockopt};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Per-listener socket options driven by config keys. Threaded from
/// `daemon.rs` setup through `open_listeners` so the socket-creation
/// helpers stay free of config-tree dependencies.
///
/// All fields except `bind_to_interface` are best-effort: setsockopt
/// failure logs and continues (no return-value check on `SO_MARK`,
/// warn-only on the
/// buffer ones).
#[derive(Debug, Clone)]
pub struct SockOpts {
    /// `udp_rcvbuf`. Default `1024*1024` (1MB). 0 = skip the
    /// setsockopt entirely (`set_udp_buffer`: `if
    /// (!size) return`). Kernel default on Linux is ~200KB — the C
    /// bumps it to handle burst traffic. UDP-only.
    pub udp_rcvbuf: usize,
    /// `udp_sndbuf`. Same shape as rcvbuf.
    pub udp_sndbuf: usize,
    /// `udp_{rcv,snd}buf_warnings`. Set to true ONLY when the
    /// operator explicitly configured `UDPRcvBuf`/`UDPSndBuf`. The
    /// 1MB
    /// default firing without the operator asking would be log noise
    /// on every boot (kernel almost always clamps 1MB).
    pub udp_buf_warnings: bool,
    /// `fwmark`. `SO_MARK`. Linux netfilter mark
    /// for policy routing. 0 = unset = skip. Applied to TCP + UDP
    /// listeners (`:248`) AND outgoing TCP (`:383`, separate site).
    /// Public so `outgoing.rs` can reuse the same parsed value.
    pub fwmark: u32,
    /// `BindToInterface` config. `SO_BINDTODEVICE`. Linux-only. `None` = skip. Unlike the
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
            udp_rcvbuf: 1024 * 1024,
            udp_sndbuf: 1024 * 1024,
            udp_buf_warnings: false,
            fwmark: 0, // 0 = unset
            bind_to_interface: None,
        }
    }
}

/// `set_udp_buffer`. Set `SO_RCVBUF` or `SO_SNDBUF`, then
/// optionally read back and warn if the kernel
/// clamped. Linux DOUBLES the requested value internally (overhead
/// accounting) and caps at `net.core.{r,w}mem_max`; the readback
/// sees the doubled-then-capped figure. We check `actual < size`
/// (not `!=`) — doubling alone doesn't trip the warning.
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

/// Raw `getsockopt` sibling of [`set_int_sockopt`]. Test-only readback
/// for `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER`.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn get_int_sockopt(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    optname: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut val: libc::c_int = 0;
    // SAFETY: fd is borrowed; val/len are stack locals the kernel
    // writes through for the duration of the call.
    // truncation: size_of::<c_int>() == 4, fits socklen_t.
    #[allow(unsafe_code, clippy::cast_possible_truncation)]
    let rc = unsafe {
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            optname,
            (&raw mut val).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc == 0 {
        Ok(val)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `MAXSOCKETS` (`net.h:47`). C comment: "Probably overkill...".
/// 8 listener pairs (TCP+UDP each). One v4, one v6, six spare for
/// `BindToAddress` entries.
pub const MAXSOCKETS: usize = 8;

/// `addressfamily`. Which families to bind.
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
    /// Parse the `AddressFamily` config value. Returns `None` for
    /// unrecognized values; upstream also does this
    /// (silent ignore — `addressfamily` stays at its default
    /// `AF_UNSPEC`).
    #[must_use]
    pub fn from_config(s: &str) -> Option<Self> {
        // `strcasecmp`. The vars table normalizes case at parse
        // time but we also re-check here. Match.
        match s.to_ascii_lowercase().as_str() {
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "any" => Some(Self::Any),
            _ => None,
        }
    }

    pub(crate) const fn try_v4(self) -> bool {
        matches!(self, Self::Any | Self::Ipv4)
    }
    pub(crate) const fn try_v6(self) -> bool {
        matches!(self, Self::Any | Self::Ipv6)
    }
}

/// `listen_socket_t` (`net.h:110-116`). One TCP+UDP pair. C stores
/// `io_t tcp; io_t udp; sockaddr_t sa; bool bindto`. We store the
/// `Socket`s (own the fds) plus the local address (for the pidfile +
/// outgoing UDP source selection).
///
/// `bindto` distinguishes `BindToAddress` (use this addr for
/// outgoing connections too — source-addr selection) from
/// `ListenAddress` (listen-only). The no-config
/// default is `bindto = false`.
pub struct Listener {
    /// `listen_socket_t.bindto`. True iff this listener came from a
    /// `BindToAddress` config line (vs `ListenAddress` or the
    /// implicit wildcard). Consumed
    /// by outgoing-connect to pick a source address.
    pub bindto: bool,
    /// `listen_socket_t.tcp`. TCP listener, accepting peer conns.
    /// `Socket` owns the fd; Drop closes.
    pub tcp: Socket,
    /// `listen_socket_t.udp`. UDP socket, receives `vpn_packet_t`s.
    pub udp: Socket,
    /// `listen_socket_t.sa`. The local bound address. `SocketAddr`
    /// not `SockAddr` — we know it's v4 or v6 (we bound it), not
    /// `AF_UNIX`.
    pub local: SocketAddr,
}

impl Listener {
    /// Borrowed TCP listener fd for `EventLoop::add`.
    #[must_use]
    pub fn tcp_fd(&self) -> BorrowedFd<'_> {
        self.tcp.as_fd()
    }

    /// Borrowed UDP socket fd for `EventLoop::add`.
    #[must_use]
    pub fn udp_fd(&self) -> BorrowedFd<'_> {
        self.udp.as_fd()
    }

    /// `get_bound_port(sock->udp.fd)`. The UDP port, AFTER bind. With `bind_reusing_port` (`open_one`) this
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

/// Common best-effort sockopts shared by `setup_tcp` and `setup_udp`:
/// REUSEADDR, V6ONLY, `SO_MARK` (all warn-on-error), then
/// `SO_BINDTODEVICE` (hard error). `label` is appended to warnings
/// (`""` for TCP, `" (udp)"` for UDP) to keep the log lines
/// distinguishable.
fn apply_common_sockopts(
    s: &Socket,
    domain: Domain,
    opts: &SockOpts,
    label: &str,
) -> io::Result<()> {
    // SO_REUSEADDR: restart after crash without EADDRINUSE from TIME_WAIT.
    if let Err(e) = s.set_reuse_address(true) {
        log::warn!(target: "tincd::net", "SO_REUSEADDR{label}: {e}");
    }

    // IPV6_V6ONLY: load-bearing. Without this the v6 socket grabs v4
    // traffic via mapped addresses, and the v4 bind sees the port as taken.
    if domain == Domain::IPV6
        && let Err(e) = s.set_only_v6(true)
    {
        log::warn!(target: "tincd::net", "IPV6_V6ONLY{label}: {e}");
    }

    // SO_MARK: Linux netfilter mark for policy routing. 0 = unset = skip.
    #[cfg(target_os = "linux")]
    if opts.fwmark != 0
        && let Err(e) = setsockopt(&s.as_fd(), sockopt::Mark, &opts.fwmark)
    {
        log::warn!(target: "tincd::net", "SO_MARK={}{label}: {e}", opts.fwmark);
    }
    #[cfg(not(target_os = "linux"))]
    if opts.fwmark != 0 {
        log::warn!(target: "tincd::net",
                   "FWMark={} ignored: SO_MARK is Linux-only", opts.fwmark);
    }

    // SO_BINDTODEVICE: hard failure. Propagate; Socket's Drop closes.
    if let Some(iface) = &opts.bind_to_interface {
        bind_to_interface(s, iface)?;
    }

    Ok(())
}

// setup_listen_socket (TCP)

/// `setup_listen_socket`. One TCP listener.
///
/// Four-step shape, matching the C:
/// 1. `socket(family, SOCK_STREAM, IPPROTO_TCP)` — `:196`
/// 2. `setsockopt` × N — `:210-247`
/// 3. `bind` — `:250` (via `try_bind`)
/// 4. `listen(backlog=3)` — `:254`
///
/// Backlog is 3. tinc isn't a high-QPS server; 3 pending accepts is
/// plenty.
///
/// # Errors
/// `socket`/`bind`/`listen` errors. `setsockopt` failures are LOGGED
/// but not propagated (`set_reuse_address` failing means `bind` will
/// fail too if the addr is in use; let `bind` produce the user-visible
/// error). C does the same — none of the `setsockopt` calls in
/// `setup_listen_socket` check the return value.
fn setup_tcp(addr: &SockAddr, opts: &SockOpts) -> io::Result<Socket> {
    let domain = Domain::from(i32::from(addr.family()));
    // `Socket::new` does `SOCK_CLOEXEC` on Linux/BSD. Same effect
    // as separate `fcntl(F_SETFD, FD_CLOEXEC)`, atomic.
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    crate::set_nosigpipe(&s);

    apply_common_sockopts(&s, domain, opts, "")?;

    // bind. We let `?` propagate. Socket's Drop closes on failure.
    s.bind(addr)?;

    // `:254`: `listen(nfd, 3)`.
    s.listen(3)?;

    Ok(s)
}

// setup_vpn_in_socket (UDP)

/// systemd socket activation. Consume `n` TCP fds at
/// `start_fd..start_fd+n`, open a matching UDP socket
/// for each (C ONLY takes TCP from systemd; UDP is
/// `setup_vpn_in_socket(&sa)` against the same address).
///
/// **The fds are inherited, not opened.** They were `bind()`d and
/// `listen()`d by systemd. We just adopt them. `getsockname` tells
/// us what address systemd picked (we don't get to choose).
///
/// `bindto = false` for all: socket-activated listeners aren't
/// `BindToAddress` (which would mean "use this as outgoing-dial
/// source addr too"). The C path sets `listen_socket[i].sa` but
/// never sets `bindto` — C zero-init = false.
///
/// `start_fd` is `SD_LISTEN_FDS_START` (= 3) in production; the
/// parameter exists so unit tests can use a high fd and avoid
/// fd-3 races (nextest may share processes within a test binary;
/// fd 3 could be anything). Production callers use
/// [`adopt_listeners`].
///
/// # Errors
/// - `n > MAXSOCKETS`: hard error.
/// - `getsockname` failure: hard error. The fd
///   isn't a socket, or it's closed, or it's something we can't
///   handle (`AF_UNIX`).
/// - `setup_udp` failure: hard error.
pub(crate) fn adopt_listeners_from(
    start_fd: RawFd,
    n: usize,
    opts: &SockOpts,
) -> io::Result<Vec<Listener>> {
    // Cap. Upstream clamps and errors; we just error (clamp-then-
    // error is the same as just-error since the
    // returns false right after the clamp).
    if n > MAXSOCKETS {
        return Err(io::Error::other(format!(
            "Too many listening sockets: LISTEN_FDS={n} > MAXSOCKETS={MAXSOCKETS}"
        )));
    }

    // Wrap ALL inherited fds before doing any fallible work. If a
    // mid-loop `?` fired after wrapping fd i but before wrapping
    // fd i+1..n, the tail fds would leak (we already own them —
    // main.rs unset LISTEN_FDS so nobody else will close them).
    // Collecting into a Vec<OwnedFd> first means an early return
    // from the second loop drops every remaining fd.
    let owned: Vec<OwnedFd> = (0..n)
        .map(|i| {
            // `int tcp_fd = i + 3`. n ≤ MAXSOCKETS=8; RawFd is i32.
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let tcp_fd = start_fd + i as RawFd;
            // SAFETY: fd `start_fd..start_fd+n` was passed by
            // systemd, is open. Taking ownership is correct: no
            // other code in this process will use these fds (we're
            // the first and only consumer; main.rs read LISTEN_FDS
            // and unset it before calling us).
            #[allow(unsafe_code)]
            unsafe {
                OwnedFd::from_raw_fd(tcp_fd)
            }
        })
        .collect();

    let mut listeners = Vec::with_capacity(n);
    for fd in owned {
        let tcp_fd = fd.as_raw_fd();
        // `getsockname(tcp_fd, &sa, &salen)`. socket2 needs the fd
        // wrapped first; `Socket: From<OwnedFd>` (Socket's Drop
        // will close it, which is what we want).
        let tcp = Socket::from(fd);

        // getsockname via socket2. AF_UNIX would fail the
        // SocketAddr conversion below — that's fine, hard error.
        let local = tcp
            .local_addr()
            .and_then(|a| {
                a.as_socket().ok_or_else(|| {
                    io::Error::other(format!("LISTEN_FDS fd {tcp_fd}: not AF_INET/AF_INET6"))
                })
            })
            .map_err(|e| {
                io::Error::other(format!("Could not get address of listen fd {tcp_fd}: {e}"))
            })?;

        // `fcntl(tcp_fd, F_SETFD, FD_CLOEXEC)`. Modern systemd
        // already sets this (via O_CLOEXEC on the socket()
        // call), but C is defensive. Best-effort like the C (no
        // return-value check there either).
        if let Err(e) = nix::fcntl::fcntl(
            &tcp,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        ) {
            log::warn!(target: "tincd::net",
                       "fd {tcp_fd}: F_SETFD FD_CLOEXEC: {e}");
        }

        // `int udp_fd = setup_vpn_in_socket(&sa)`. UDP is OURS to
        // open, against the same address. systemd only
        // gives TCP (`ListenStream=` in the .socket unit; a
        // separate `ListenDatagram=` would put a UDP fd in the mix,
        // but tinc's protocol pairs TCP+UDP on the SAME addr —
        // easier to just open UDP ourselves than to de-interleave
        // systemd's fd list).
        let udp = setup_udp(&SockAddr::from(local), opts)
            .map_err(|e| io::Error::other(format!("UDP bind for listen fd {tcp_fd}: {e}")))?;

        log::info!(target: "tincd::net",
                   "Listening on {local} (socket activation)");

        // `bindto = false`: see fn doc. C zero-init.
        listeners.push(Listener {
            bindto: false,
            tcp,
            udp,
            local,
        });
    }

    Ok(listeners)
}

/// [`adopt_listeners_from`] with `start_fd = SD_LISTEN_FDS_START`
/// (= 3, after stdin/out/err). The production entry point.
///
/// # Errors
/// See [`adopt_listeners_from`].
#[inline]
pub(crate) fn adopt_listeners(n: usize, opts: &SockOpts) -> io::Result<Vec<Listener>> {
    /// `SD_LISTEN_FDS_START`. systemd passes fds starting at 3.
    const SD_LISTEN_FDS_START: RawFd = 3;
    adopt_listeners_from(SD_LISTEN_FDS_START, n, opts)
}

/// `setup_vpn_in_socket`. One UDP socket.
///
/// Same four-step shape as TCP but no `listen` (UDP doesn't have it)
/// and more sockopts (broadcast for `LocalDiscovery`, buffer sizes,
/// PMTU). Most deferred.
///
/// `O_NONBLOCK` is set HERE (`:308-316`), unlike TCP listeners (the
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

    // `:332`: SO_BROADCAST. For LocalDiscovery (probe peers on LAN).
    // We don't use it yet but setting it doesn't hurt and matching the
    // C's socket state means dump tools (`ss -tuln`) show identical
    // flags.
    if let Err(e) = s.set_broadcast(true) {
        log::warn!(target: "tincd::net", "SO_BROADCAST: {e}");
    }

    // `:349-378`: IP_MTU_DISCOVER / IPV6_MTU_DISCOVER = PMTUDISC_DO.
    // Linux-only: forces DF on every datagram for PMTU discovery.
    // macOS sets DF by default on UDP sockets.
    #[cfg(target_os = "linux")]
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
        if let Err(e) = set_int_sockopt(s.as_fd(), level, optname, optval) {
            log::warn!(target: "tincd::net", "{label}: {e}");
        }
    }

    // SO_RCVBUF/SO_SNDBUF via `set_udp_buffer`. Default 1MB each.
    // Best-effort.
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

    // REUSEADDR, V6ONLY, SO_MARK, BINDTODEVICE. All pre-bind,
    // idempotent, order-independent; BINDTODEVICE stays last
    // (right before bind).
    apply_common_sockopts(&s, domain, opts, " (udp)")?;

    s.bind(addr)?;

    Ok(s)
}

// add_listen_address

/// `add_listen_address(NULL, false)` — the no-config default.
///
/// `getaddrinfo(NULL, port, AI_PASSIVE)` returns `0.0.0.0` then
/// `::` (gcc-verified on a dual-stack Linux). Loop,
/// bind each, `continue` on bind failure (`:705-707`). Result: one
/// v4 listener, one v6 listener, both on `port`.
///
/// We skip getaddrinfo and try both wildcards directly — see
/// module doc "getaddrinfo: skip it".
///
/// `family` filters which to try. Maps `AddressFamily` config →
/// the C's `hint.ai_family = addressfamily` at `:655`.
///
/// Returns 0, 1, or 2 listeners. Zero is an error in the caller; we
/// let the caller check.
///
/// # Errors
/// Never returns `Err` — bind failures are warnings + skip
/// (`continue`). The "no listeners" case is the caller's problem
/// (returns empty Vec).
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
        // The v6 listener tries to reuse the v4 listener's port.
        // With
        // `Port=0` this makes both families converge on one port.
        let reuse = listeners.first().map(|l| l.local.port());
        if let Some(l) = open_one(addr, opts, reuse, false) {
            listeners.push(l);
        }
    }

    listeners
}

/// `assign_static_port`. If `addr.port()` is 0 (dynamic), rewrite
/// it to `reuse_port`. Otherwise leave it
/// alone (already static). C checks `sa.sa_family` and writes the
/// `sin_port` / `sin6_port` field; `SocketAddr::set_port` covers
/// both. C returns `false` on bad fd / unknown family; we encode
/// "nothing to do" as `reuse_port == None` and let the caller skip.
fn assign_static_port(mut addr: SocketAddr, reuse_port: Option<u16>) -> Option<SocketAddr> {
    let port = reuse_port?;
    // Only overwrite if the existing port is zero. A
    // `BindToAddress = 10.0.0.1 5000` line has a static port;
    // don't clobber it with the first listener's ephemeral.
    if addr.port() == 0 {
        addr.set_port(port);
        Some(addr)
    } else {
        None
    }
}

/// `bind_reusing_port`. Try `setup` with the port stolen from an
/// already-bound socket; on failure, fall back
/// to the original `addr` (port 0 → fresh ephemeral). The C threads
/// a function pointer (`bind_fn_t`); we take a closure.
///
/// Why fallback: with `Port=0` and multiple `BindToAddress` lines,
/// the first listener picks ephemeral X. The second listener
/// (different IP) usually CAN reuse X (different (addr,port) tuple),
/// but if X happens to be taken on that interface, we'd rather get
/// a working listener on a different port than no listener at all.
/// `if(fd < 0) fd = setup(sa)`.
fn bind_reusing_port<F>(addr: SocketAddr, reuse_port: Option<u16>, setup: F) -> io::Result<Socket>
where
    F: Fn(&SockAddr) -> io::Result<Socket>,
{
    // Only attempt the reuse if assign_static_port succeeded (i.e.
    // addr had port 0 AND we have a port to steal).
    // Reuse failed (port taken on this interface) → fall through.
    if let Some(reused) = assign_static_port(addr, reuse_port)
        && let Ok(s) = setup(&SockAddr::from(reused))
    {
        return Ok(s);
    }
    // Original address. With port 0 the kernel picks fresh.
    setup(&SockAddr::from(addr))
}

/// One TCP+UDP pair on `addr`.
/// Either both succeed or neither makes it into `listen_socket[]`
/// (`:717-720`: TCP succeeds, UDP fails → close TCP, continue).
///
/// `reuse_port`: with `Port=0`, the FIRST listener gets a kernel
/// port. Subsequent calls pass that port here so the whole daemon
/// converges on one port across all listeners (and TCP/UDP within
/// a pair). After the first TCP bind, `from_fd = tcp_fd` so UDP
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
    // ─── TCP. `bind_reusing_port(sa, from_fd,
    // setup_listen_socket)`.
    let tcp = match bind_reusing_port(addr, reuse_port, |sa| setup_tcp(sa, opts)) {
        Ok(s) => s,
        Err(e) => {
            // `if(tcp_fd < 0) continue`. Log + skip.
            // Warn not Error: this is expected on a v6-disabled
            // system. The "no listeners at all" check in setup is
            // where the hard error lives.
            log::warn!(target: "tincd::net", "TCP bind on {addr}: {e}");
            return None;
        }
    };

    // `if(!from_fd) from_fd = tcp_fd`. The first
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

    // ─── UDP. `bind_reusing_port(sa, from_fd,
    // setup_vpn_in_socket)`.
    let udp = match bind_reusing_port(addr, tcp_port, |sa| setup_udp(sa, opts)) {
        Ok(s) => s,
        Err(e) => {
            // `closesocket(tcp_fd); continue`.
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

/// `configure_tcp`. Set the accepted fd's
/// options: NONBLOCK + NODELAY. The C also does TOS/TCLASS/MARK
/// (deferred — see module doc).
///
/// Called from `handle_new_meta_connection` after `accept` returns.
/// The listener's options DON'T inherit to the accepted fd (NONBLOCK
/// in particular doesn't; it's why we do it again here).
///
/// Consumes `Socket`, returns `OwnedFd`. The conversion strips
/// socket2's wrapper; daemon.rs's `Connection` wants raw bytes via
/// `libc::read`/`write`, doesn't need the wrapper.
///
/// # Errors
/// `set_nonblocking` failing means the fd is broken; propagate.
/// `set_nodelay` failing is a warn — the connection works without it,
/// just with Nagle latency. The return value is ignored.
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
    // outgoing-connect mark is separate).

    Ok(s.into())
}

// sockaddrunmap + is_local_connection

/// `sockaddrunmap`. v4-mapped v6 addr → plain v4.
///
/// `accept` on a v6 socket WITHOUT V6ONLY returns `::ffff:10.0.0.5`
/// for a v4 peer. We DO set V6ONLY so this never fires for our
/// listeners — but tarpit's `prev_sa` compare and the eventual
/// `sockaddr2hostname` log line want plain v4 for readability.
/// Harmless to canonicalize anyway.
///
/// std `Ipv6Addr::to_ipv4_mapped()` is `Some` iff the high 80 bits
/// are zero and the next 16 are `ffff`. Same condition as C
/// `IN6_IS_ADDR_V4MAPPED`. Writes the low 32 bits over
/// `sin_addr` and changes `sa_family` — net effect: a `SocketAddrV4`.
#[must_use]
pub fn unmap(sa: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = sa
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return (v4, v6.port()).into();
    }
    sa
}

/// `is_local_connection`: loopback peer check.
///
/// `handle_new_meta_connection` (`:751`) skips tarpit for local
/// connections — the tarpit defends against external scan/DoS, and
/// rate-limiting yourself is pointless.
///
/// C cases: `AF_INET` (high octet == 127), `AF_INET6` (`IN6_IS_ADDR_
/// LOOPBACK` → `::1`), `AF_UNIX` (always true). We don't see `AF_UNIX`
/// here (TCP only); two cases.
///
/// std's `Ipv4Addr::is_loopback` is `127.0.0.0/8` (matches C's `>> 24
/// == 127`). `Ipv6Addr::is_loopback` is `::1` only (matches
/// `IN6_IS_ADDR_LOOPBACK`).
#[must_use]
pub const fn is_local(sa: &SocketAddr) -> bool {
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
/// The format is `sockaddr2hostname`: `"%s port %s"`.
/// std's `Display` for `SocketAddr` is `"host:port"`. The CLI's pidfile
/// parser (`tinc-tools/ctl.rs`) splits on `" port "`.
///
/// Why the unspecified→loopback mapping: the daemon binds `0.0.0.0`
/// (all interfaces). The CLI reads the pidfile, connects. `connect(
/// 0.0.0.0, port)` is undefined (Linux interprets it as 127.0.0.1
/// but BSD doesn't). We patch it.
///
/// On systems where v6 binds first (depends on getaddrinfo ordering,
/// which depends on /etc/gai.conf), `listeners[0]` is the v6 entry.
/// We bind v4 first deterministically, so `listeners[0]` is always
/// v4 IF v4 is enabled. If `AddressFamily = ipv6`, it's v6. The
/// mapping handles both.
#[must_use]
pub fn pidfile_addr(listeners: &[Listener]) -> String {
    // `if(getsockname(...))` failure → fall back to
    // `"127.0.0.1 port %s" % myport`. We've already done getsockname
    // in `open_one`; can't fail here.
    // No listeners: caller will error separately.
    // getsockname on fd=0 (stdin) and fall through to the printf.
    // Match the printf.
    let local = listeners
        .first()
        .map_or_else(|| (Ipv4Addr::LOCALHOST, 0).into(), |l| l.local);

    // 0.0.0.0 → 127.0.0.1, :: → ::1.
    let mapped = match local {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => (Ipv4Addr::LOCALHOST, v4.port()).into(),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => (Ipv6Addr::LOCALHOST, v6.port()).into(),
        x => x,
    };

    // `sockaddr2hostname(&sa)` → `"%s port %s"`.
    // SocketAddr::ip() Display is plain (no port, no brackets for v6).
    format!("{} port {}", mapped.ip(), mapped.port())
}

// sockaddr2hostname (the printable-address part)

/// `sockaddr2hostname` — a subset. `getnameinfo` with
/// `NI_NUMERICHOST | NI_NUMERICSERV`, which is
/// just printf for the addr (no DNS). std's `Display` for `IpAddr`
/// does the same.
///
/// Format: `"HOST port PORT"`. Appears in log lines and the pidfile.
/// `tinc-tools::Tok` parses this with `lit(" port ")`.
///
/// We DON'T do the `AF_UNKNOWN` case — that's for addresses
/// round-tripped through the wire protocol's text format,
/// which our `SocketAddr` can't represent. `tinc-proto::addr` has
/// the full-generality version; this is for SOCKETS we own.
#[must_use]
pub fn fmt_addr(sa: &SocketAddr) -> String {
    // `xasprintf("%s port %s", host, port)`. The %s comes from
    // getnameinfo NI_NUMERICHOST. For v6 that's "::1" not "[::1]"
    // (NI_NUMERICHOST doesn't bracket). std's Ipv6Addr Display also
    // doesn't bracket. Match.
    format!("{} port {}", sa.ip(), sa.port())
}

mod tarpit;
pub use tarpit::Tarpit;

#[cfg(test)]
mod tests;
