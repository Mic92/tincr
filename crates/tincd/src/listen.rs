//! TCP/UDP listener setup; the tarpit lives in [`tarpit`].
//!
//! Built on `socket2` so the setsockopt seam (notably `IPV6_V6ONLY`,
//! load-bearing for separate v4+v6 listeners) is exposed; std's
//! atomic `bind` hides it. We probe per-family by trying both binds
//! and ignoring failures, rather than gating on a getaddrinfo call.
//! `BindToAddress` resolution lives in `daemon.rs`; resolved
//! `SocketAddr`s arrive here through `open_listener_pair`.
//!
//! Deferred: `IP_TOS`/`IPV6_TCLASS`.

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
    /// UDP `SO_RCVBUF`. Default 1MB (kernel default on Linux is
    /// ~200KB; bumped to handle burst traffic). 0 = skip the
    /// setsockopt entirely.
    pub udp_rcvbuf: usize,
    /// UDP `SO_SNDBUF`. Same shape as rcvbuf.
    pub udp_sndbuf: usize,
    /// True only when the operator explicitly configured
    /// `UDPRcvBuf`/`UDPSndBuf`. Warning about the 1MB default without
    /// the operator asking would be log noise on every boot (the
    /// kernel almost always clamps 1MB).
    pub udp_buf_warnings: bool,
    /// `SO_MARK`: Linux netfilter mark for policy routing. 0 = unset
    /// = skip. Applied to TCP + UDP listeners and outgoing TCP.
    /// Public so `outgoing.rs` can reuse the same parsed value.
    pub fwmark: u32,
    /// `BindToInterface` config → `SO_BINDTODEVICE`. Linux-only.
    /// `None` = skip. Unlike the other knobs this is a HARD failure:
    /// if the operator says "bind to eth0" and eth0 doesn't exist,
    /// silently binding to the wrong interface defeats the security
    /// intent, so failure kills the listener pair.
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

/// Set `SO_RCVBUF` or `SO_SNDBUF`, then optionally read back and warn
/// if the kernel clamped. Linux DOUBLES the requested value internally
/// (overhead accounting) and caps at `net.core.{r,w}mem_max`; the
/// readback sees the doubled-then-capped figure. We check
/// `actual < size` (not `!=`) — doubling alone doesn't trip the
/// warning.
fn set_udp_buffer<O>(s: &Socket, opt: O, name: &str, size: usize, warn: bool)
where
    O: nix::sys::socket::SetSockOpt<Val = usize> + nix::sys::socket::GetSockOpt<Val = usize> + Copy,
{
    // 0 means "don't touch".
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

/// Max listener pairs (TCP+UDP each). One v4, one v6, six spare for
/// `BindToAddress` entries.
pub(crate) const MAXSOCKETS: usize = 8;

/// Which address families to bind (`AddressFamily` config).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddrFamily {
    /// Try v4 AND v6.
    #[default]
    Any,
    /// v4 only.
    Ipv4,
    /// v6 only.
    Ipv6,
}

impl AddrFamily {
    /// Parse the `AddressFamily` config value. Returns `None` for
    /// unrecognized values (caller keeps the default).
    #[must_use]
    pub fn from_config(s: &str) -> Option<Self> {
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

/// One TCP+UDP listener pair: the sockets (owning the fds) plus the
/// local address (for the pidfile + outgoing UDP source selection).
///
/// `bindto` distinguishes `BindToAddress` (use this addr for outgoing
/// connections too — source-addr selection) from `ListenAddress`
/// (listen-only). The no-config default is `bindto = false`.
pub(crate) struct Listener {
    /// True iff this listener came from a `BindToAddress` config line
    /// (vs `ListenAddress` or the implicit wildcard). Consumed by
    /// outgoing-connect to pick a source address; only read from tests
    /// today.
    #[allow(dead_code)]
    pub bindto: bool,
    /// TCP listener, accepting peer conns. `Socket` owns the fd; Drop
    /// closes.
    pub tcp: Socket,
    /// UDP socket, receives VPN packets.
    pub udp: Socket,
    /// The local bound address. `SocketAddr` not `SockAddr` — we know
    /// it's v4 or v6 (we bound it), not `AF_UNIX`.
    pub local: SocketAddr,
}

impl Listener {
    /// Borrowed TCP listener fd for `EventLoop::add`.
    #[must_use]
    pub(crate) fn tcp_fd(&self) -> BorrowedFd<'_> {
        self.tcp.as_fd()
    }

    /// Borrowed UDP socket fd for `EventLoop::add`.
    #[must_use]
    pub(crate) fn udp_fd(&self) -> BorrowedFd<'_> {
        self.udp.as_fd()
    }

    /// The UDP port, after bind. With `bind_reusing_port` (`open_one`)
    /// this equals `local.port()` for the first listener; kept as a
    /// separate accessor because subsequent listeners on a system
    /// where the port is taken on UDP fall back to ephemeral
    /// (`open_one`'s retry path).
    #[must_use]
    pub(crate) fn udp_port(&self) -> u16 {
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

/// Open one TCP listener: socket, sockopts, bind, listen.
///
/// Backlog is 3. tinc isn't a high-QPS server; 3 pending accepts is
/// plenty.
///
/// # Errors
/// `socket`/`bind`/`listen` errors. `setsockopt` failures are LOGGED
/// but not propagated (`set_reuse_address` failing means `bind` will
/// fail too if the addr is in use; let `bind` produce the user-visible
/// error).
fn setup_tcp(addr: &SockAddr, opts: &SockOpts) -> io::Result<Socket> {
    let domain = Domain::from(i32::from(addr.family()));
    // `Socket::new` sets `SOCK_CLOEXEC` on Linux/BSD atomically.
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    crate::set_nosigpipe(&s);

    apply_common_sockopts(&s, domain, opts, "")?;

    // Socket's Drop closes on failure.
    s.bind(addr)?;

    s.listen(3)?;

    Ok(s)
}

/// systemd socket activation. Consume `n` TCP fds at
/// `start_fd..start_fd+n`, open a matching UDP socket for each
/// (systemd only hands us TCP; the protocol pairs TCP+UDP on the same
/// address, so we open UDP ourselves).
///
/// **The fds are inherited, not opened.** They were `bind()`d and
/// `listen()`d by systemd. We just adopt them. `getsockname` tells
/// us what address systemd picked (we don't get to choose).
///
/// `bindto = false` for all: socket-activated listeners aren't
/// `BindToAddress` (which would mean "use this as outgoing-dial
/// source addr too").
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
            // n ≤ MAXSOCKETS=8; RawFd is i32.
            #[expect(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
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
        // Socket's Drop will close the fd, which is what we want.
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

        // FD_CLOEXEC. Modern systemd already sets this, but be
        // defensive; best-effort.
        if let Err(e) = nix::fcntl::fcntl(
            &tcp,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        ) {
            log::warn!(target: "tincd::net",
                       "fd {tcp_fd}: F_SETFD FD_CLOEXEC: {e}");
        }

        // UDP is ours to open, against the same address. systemd only
        // gives TCP (`ListenStream=` in the .socket unit; a separate
        // `ListenDatagram=` would put a UDP fd in the mix, but tinc's
        // protocol pairs TCP+UDP on the SAME addr — easier to open UDP
        // ourselves than to de-interleave systemd's fd list).
        let udp = setup_udp(&SockAddr::from(local), opts)
            .map_err(|e| io::Error::other(format!("UDP bind for listen fd {tcp_fd}: {e}")))?;

        log::info!(target: "tincd::net",
                   "Listening on {local} (socket activation)");

        // `bindto = false`: see fn doc.
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

/// Open one UDP socket.
///
/// Same shape as TCP but no `listen` and more sockopts (broadcast for
/// `LocalDiscovery`, buffer sizes, PMTU).
///
/// `O_NONBLOCK` is set here, unlike TCP listeners (the listener fd
/// doesn't need non-blocking — `accept` blocking is fine because we
/// only call it when epoll says ready). UDP `recvfrom` IS the data
/// path; non-blocking is mandatory.
///
/// # Errors
/// `socket`/`bind` errors. `setsockopt` warnings logged.
fn setup_udp(addr: &SockAddr, opts: &SockOpts) -> io::Result<Socket> {
    let domain = Domain::from(i32::from(addr.family()));
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    s.set_nonblocking(true)?;

    // SO_BROADCAST for LocalDiscovery (probe peers on LAN). Not used
    // yet, but setting it doesn't hurt.
    if let Err(e) = s.set_broadcast(true) {
        log::warn!(target: "tincd::net", "SO_BROADCAST: {e}");
    }

    // IP_MTU_DISCOVER / IPV6_MTU_DISCOVER = PMTUDISC_DO.
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

/// The no-config default: try both wildcard addresses directly (no
/// resolver), one v4 listener and one v6 listener on `port`.
///
/// `family` filters which to try.
///
/// Returns 0, 1, or 2 listeners. Zero is an error in the caller; we
/// let the caller check.
///
/// # Errors
/// Never returns `Err` — bind failures are warnings + skip. The "no
/// listeners" case is the caller's problem (returns empty Vec).
#[must_use]
pub(crate) fn open_listeners(port: u16, family: AddrFamily, opts: &SockOpts) -> Vec<Listener> {
    let mut listeners = Vec::with_capacity(2);

    if family.try_v4() {
        let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
        if let Some(l) = open_one(addr, opts, None, false) {
            listeners.push(l);
        }
    }
    if family.try_v6() {
        let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
        // The v6 listener tries to reuse the v4 listener's port. With
        // `Port=0` this makes both families converge on one port.
        let reuse = listeners.first().map(|l| l.local.port());
        if let Some(l) = open_one(addr, opts, reuse, false) {
            listeners.push(l);
        }
    }

    listeners
}

/// If `addr.port()` is 0 (dynamic), rewrite it to `reuse_port`.
/// Otherwise leave it alone (already static). "Nothing to do" is
/// encoded as `None`; the caller skips the reuse attempt.
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

/// Try `setup` with the port stolen from an already-bound socket; on
/// failure, fall back to the original `addr` (port 0 → fresh
/// ephemeral).
///
/// Why fallback: with `Port=0` and multiple `BindToAddress` lines,
/// the first listener picks ephemeral X. The second listener
/// (different IP) usually CAN reuse X (different (addr,port) tuple),
/// but if X happens to be taken on that interface, we'd rather get
/// a working listener on a different port than no listener at all.
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

/// One TCP+UDP pair on `addr`. Either both succeed or neither is kept
/// (TCP succeeds, UDP fails → close TCP, skip).
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
pub(crate) fn open_listener_pair(
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
    let tcp = match bind_reusing_port(addr, reuse_port, |sa| setup_tcp(sa, opts)) {
        Ok(s) => s,
        Err(e) => {
            // Warn not Error: this is expected on a v6-disabled
            // system. The "no listeners at all" check in setup is
            // where the hard error lives.
            log::warn!(target: "tincd::net", "TCP bind on {addr}: {e}");
            return None;
        }
    };

    // Always give UDP the port TCP just got. If `reuse_port` was
    // Some(X) and TCP successfully reused X, this is X anyway. If TCP
    // fell back to a fresh ephemeral, we want UDP to follow TCP
    // (peers learn the port from the TCP meta-connection and expect
    // UDP there).
    let tcp_port = tcp
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .map(|a| a.port());

    let udp = match bind_reusing_port(addr, tcp_port, |sa| setup_udp(sa, opts)) {
        Ok(s) => s,
        Err(e) => {
            // tcp drops here, fd closes.
            log::warn!(target: "tincd::net", "UDP bind on {addr}: {e}");
            return None;
        }
    };

    // Store the BOUND addr (with the kernel-assigned port if port was
    // 0), not the bind-target addr.
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

/// Set an accepted fd's options: NONBLOCK + NODELAY. TOS/TCLASS/MARK
/// deferred — see module doc.
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
pub(crate) fn configure_tcp(s: Socket) -> io::Result<OwnedFd> {
    // The conn read path is non-blocking.
    s.set_nonblocking(true)?;

    // TCP_NODELAY: the meta protocol is line-oriented (~80 bytes);
    // Nagle would batch lines into 200ms coalesce windows.
    if let Err(e) = s.set_tcp_nodelay(true) {
        log::warn!(target: "tincd::conn", "TCP_NODELAY: {e}");
    }

    // Deferred: IP_TOS/IPV6_TCLASS=LOWDELAY, SO_MARK (the listen-side
    // mark is set in setup_tcp; the outgoing-connect mark is separate).

    Ok(s.into())
}

/// v4-mapped v6 addr → plain v4.
///
/// `accept` on a v6 socket WITHOUT V6ONLY returns `::ffff:10.0.0.5`
/// for a v4 peer. We DO set V6ONLY so this never fires for our
/// listeners — but tarpit's `prev_sa` compare and the eventual
/// `sockaddr2hostname` log line want plain v4 for readability.
/// Harmless to canonicalize anyway.
#[must_use]
pub(crate) fn unmap(sa: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = sa
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return (v4, v6.port()).into();
    }
    sa
}

/// Loopback peer check. Accept skips the tarpit for local connections
/// — the tarpit defends against external scan/DoS, and rate-limiting
/// yourself is pointless.
#[must_use]
pub(crate) const fn is_local(sa: &SocketAddr) -> bool {
    match sa {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

/// Build the pidfile address string.
///
/// Take the first listener's bound addr, map `0.0.0.0` → `127.0.0.1`
/// and `::` → `::1` (a CLI on the same host needs a connectable addr,
/// not the wildcard), format as `"HOST port PORT"`. The CLI's pidfile
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
pub(crate) fn pidfile_addr(listeners: &[Listener]) -> String {
    // No listeners: caller will error separately; fall back to
    // localhost port 0.
    let local = listeners
        .first()
        .map_or_else(|| (Ipv4Addr::LOCALHOST, 0).into(), |l| l.local);

    // 0.0.0.0 → 127.0.0.1, :: → ::1.
    let mapped = match local {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => (Ipv4Addr::LOCALHOST, v4.port()).into(),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => (Ipv6Addr::LOCALHOST, v6.port()).into(),
        x => x,
    };

    // SocketAddr::ip() Display is plain (no port, no brackets for v6).
    format!("{} port {}", mapped.ip(), mapped.port())
}

/// Format an address as `"HOST port PORT"`, the form used in log lines
/// and the pidfile. `tinc-tools::Tok` parses this with `lit(" port ")`.
/// v6 addresses are unbracketed to match what C tinc's pidfile parser
/// and log format expect. `tinc-proto::addr` has the full-generality
/// wire-format version; this is for sockets we own.
#[must_use]
pub(crate) fn fmt_addr(sa: &SocketAddr) -> String {
    format!("{} port {}", sa.ip(), sa.port())
}

mod tarpit;
pub(crate) use tarpit::Tarpit;

#[cfg(test)]
mod tests;
