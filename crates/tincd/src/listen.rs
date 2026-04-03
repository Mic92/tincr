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
//! Deferred sockopts: `SO_MARK`/`SO_BINDTODEVICE` (`:225-247`, gated
//! on `all`), `SO_RCVBUF`/`SO_SNDBUF` (`:334-335`), `IP_MTU_DISCOVER`
//! (`:349-364`), `IP_TOS`/`IPV6_TCLASS` (`configure_tcp:93-100`).
//!
//! ## getaddrinfo: skip it
//!
//! C `add_listen_address(NULL, NULL)` uses getaddrinfo as a per-
//! family probe (`0.0.0.0` then `::`, gcc-verified). We probe by
//! trying both binds; `Socket::new(Domain::IPV6, ...)` failing is
//! the same outcome. Bind failure is `continue` (C `:705-707`).
//! `BindToAddress` deferred (DOES need name resolution).
//!
//! `bind_reusing_port` (`net_setup.c:613-632`) deferred: only
//! matters with multiple `BindToAddress` entries.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

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

    fn try_v4(self) -> bool {
        matches!(self, Self::Any | Self::Ipv4)
    }
    fn try_v6(self) -> bool {
        matches!(self, Self::Any | Self::Ipv6)
    }
}

/// `listen_socket_t` (`net.h:110-116`). One TCP+UDP pair. C stores
/// `io_t tcp; io_t udp; sockaddr_t sa; bool bindto`. We store the
/// `Socket`s (own the fds) plus the local address (for the pidfile +
/// outgoing UDP source selection).
///
/// `bindto` is the difference between `BindToAddress` (use this addr
/// for outgoing too) and `ListenAddress` (listen-only). Deferred; we
/// only do the no-config default which is `bindto = false`.
pub struct Listener {
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
    /// port, AFTER bind. With `Port = 0` (tests), TCP and UDP get
    /// DIFFERENT kernel-assigned ports until `bind_reusing_port`
    /// lands (chunk 10). `myport.udp` is THIS, not `local.port()`.
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
fn setup_tcp(addr: &SockAddr) -> io::Result<Socket> {
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

    // Deferred: SO_MARK (fwmark), SO_BINDTODEVICE (BindToInterface).

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
fn setup_udp(addr: &SockAddr) -> io::Result<Socket> {
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

    // Deferred: SO_RCVBUF/SO_SNDBUF (1MB each), IP_MTU_DISCOVER (PMTU),
    // SO_MARK, SO_BINDTODEVICE.

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
pub fn open_listeners(port: u16, family: AddrFamily) -> Vec<Listener> {
    let mut listeners = Vec::with_capacity(2);

    if family.try_v4() {
        let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
        if let Some(l) = open_one(addr) {
            listeners.push(l);
        }
    }
    if family.try_v6() {
        let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
        if let Some(l) = open_one(addr) {
            listeners.push(l);
        }
    }

    listeners
}

/// One TCP+UDP pair on `addr`. C `:698-736`. Either both succeed or
/// neither makes it into `listen_socket[]` (`:717-720`: TCP succeeds,
/// UDP fails → close TCP, continue).
///
/// `addr.port() == 0` is allowed (kernel picks). The TCP socket gets
/// a port; UDP gets a DIFFERENT port (no `bind_reusing_port` yet).
/// This is wrong vs the C but only matters for production; tests use
/// the TCP port from the pidfile and don't touch UDP.
fn open_one(addr: SocketAddr) -> Option<Listener> {
    let sa = SockAddr::from(addr);

    let tcp = match setup_tcp(&sa) {
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

    let udp = match setup_udp(&sa) {
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

    Some(Listener { tcp, udp, local })
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
    // SO_MARK (`:103`).

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
    pub fn new(now: Instant) -> Self {
        Self {
            prev_addr: None,
            samehost_burst: 0,
            samehost_time: now,
            allhost_burst: 0,
            allhost_time: now,
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
            if self.samehost_burst > MAX_BURST {
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
        if self.allhost_burst >= MAX_BURST {
            self.allhost_burst = MAX_BURST;
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
        let mut tp = Tarpit::new(t0);

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
        let mut tp = Tarpit::new(t0);
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
        let mut tp = Tarpit::new(t0);
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
        let mut tp = Tarpit::new(t0);
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
        let mut tp = Tarpit::new(t0);

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
        let mut tp = Tarpit::new(t0);

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
        let mut tp = Tarpit::new(t0);

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
        let mut tp = Tarpit::new(t0);

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
        let mut tp = Tarpit::new(t0);
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
        let listeners = open_listeners(0, AddrFamily::Ipv4);
        assert_eq!(listeners.len(), 1);
        assert!(listeners[0].local.is_ipv4());
        // Port assigned by kernel.
        assert_ne!(listeners[0].local.port(), 0);
    }

    /// `AddressFamily = any`: one or two depending on system v6 support.
    /// CI might be v4-only; both outcomes are valid.
    #[test]
    fn open_any_one_or_two() {
        let listeners = open_listeners(0, AddrFamily::Any);
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
        let listeners = open_listeners(0, AddrFamily::Ipv4);
        let (tcp_fd, udp_fd) = listeners[0].fds();

        // F_GETFD bit 0 = FD_CLOEXEC.
        for &fd in &[tcp_fd, udp_fd] {
            // SAFETY: fcntl(F_GETFD) on a valid fd. listeners owns
            // the fd; it's open until listeners drops at end of test.
            #[allow(unsafe_code)]
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "fcntl failed");
            assert!(flags & libc::FD_CLOEXEC != 0, "fd {fd} missing CLOEXEC");
        }
    }

    /// V6ONLY set on v6 listener. Load-bearing for dual-stack.
    /// Skipped if system doesn't support v6.
    #[test]
    fn open_v6only_set() {
        let listeners = open_listeners(0, AddrFamily::Ipv6);
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
        let listeners = open_listeners(0, AddrFamily::Ipv4);
        let (_, udp_fd) = listeners[0].fds();
        // SAFETY: fcntl(F_GETFL) on owned fd.
        #[allow(unsafe_code)]
        let flags = unsafe { libc::fcntl(udp_fd, libc::F_GETFL) };
        assert!(flags & libc::O_NONBLOCK != 0);
    }

    /// Second listener pair on the same port: TCP bind fails (REUSEADDR
    /// only helps with TIME_WAIT, not active listeners). The fail is
    /// graceful — `open_one` returns `None`, no panic.
    ///
    /// This is the "EADDRINUSE → continue" path (`:705`).
    #[test]
    fn open_port_clash_is_graceful() {
        let first = open_listeners(0, AddrFamily::Ipv4);
        let port = first[0].local.port();

        // Same port. SO_REUSEADDR is set, but there's an active
        // listener — bind fails anyway.
        let second = open_listeners(port, AddrFamily::Ipv4);
        assert!(second.is_empty(), "second bind on port {port} should fail");
        drop(first);
    }
}
