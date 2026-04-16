use super::*;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::socket::getsockopt;

/// Shorthand for tests that don't care about sockopts.
fn opts() -> SockOpts {
    SockOpts::default()
}

/// Reduce stutter. `addr("10.0.0.5", 0)` for v4, `addr("::1", 0)` for v6.
fn addr(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(s.parse().unwrap(), port)
}

// ─── unmap

/// `IN6_IS_ADDR_V4MAPPED`. `unmap(SocketAddr) -> SocketAddr` is
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

/// v4: 127.0.0.0/8 (`ntohl(...) >> 24 == 127`). Any addr in
/// the /8, not just .0.0.1.
/// v6: `::1` ONLY (`IN6_IS_ADDR_LOOPBACK`), not the whole `::/8`.
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
        // `IN6_IS_ADDR_LOOPBACK` is exactly `::1`. The caller
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

/// `strcasecmp`.
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

/// CLOEXEC set. socket2 does this via `SOCK_CLOEXEC`. C does it
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
    // v4: always available.
    let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
    assert_eq!(
        get_int_sockopt(listeners[0].udp.as_fd(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER).unwrap(),
        libc::IP_PMTUDISC_DO,
    );

    // v6: may be disabled. Skip if no listener.
    let listeners6 = open_listeners(0, AddrFamily::Ipv6, &opts());
    if let Some(l) = listeners6.first() {
        assert_eq!(
            get_int_sockopt(l.udp.as_fd(), libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER).unwrap(),
            libc::IPV6_PMTUDISC_DO,
        );
    }
}

/// Second listener pair on the same port: TCP bind fails (REUSEADDR
/// only helps with `TIME_WAIT`, not active listeners). The fail is
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
    let euid = nix::unistd::geteuid();
    if !euid.is_root() {
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
/// is skipped: `SO_MARK` readback is 0 even though we never called
/// setsockopt. (Weak assertion — kernel default IS 0 — but
/// proves we don't crash on the unprivileged path.)
#[test]
fn open_fwmark_zero_is_skip() {
    let listeners = open_listeners(0, AddrFamily::Ipv4, &opts());
    let mark = getsockopt(&listeners[0].udp.as_fd(), sockopt::Mark).unwrap();
    assert_eq!(mark, 0);
}

/// `bind_reusing_port`: with `Port=0`, TCP gets a kernel
/// ephemeral, UDP reuses it. Before this
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
/// reuses the v4 listener's port (`from_fd =
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
/// `if(!sin_port) sin_port = htons(X)`.
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

/// `bind_reusing_port` fallback. Reuse port is already taken →
/// fall through to the original addr (port 0
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
    let l =
        open_listener_pair(addr, &opts(), Some(taken), false).expect("fallback to fresh ephemeral");
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
    let l = open_listener_pair("127.42.3.1:0".parse().unwrap(), &opts(), None, true).expect("bind");
    assert!(l.bindto, "bindto=true plumbed through");
    assert_eq!(l.udp_port(), l.local.port(), "port reuse within pair");
}

/// `SockOpts::default()` matches upstream globals.
#[test]
fn sockopts_defaults_match_c() {
    let o = SockOpts::default();
    assert_eq!(o.udp_rcvbuf, 1024 * 1024);
    assert_eq!(o.udp_sndbuf, 1024 * 1024);
    assert!(!o.udp_buf_warnings);
    assert_eq!(o.fwmark, 0);
    assert!(o.bind_to_interface.is_none());
}

// ─── adopt_listeners (socket activation)

/// Put a TCP listener at a high fd (avoiding the fd-3 races
/// that nextest's shared-process model would cause), call
/// `adopt_listeners_from`, verify the address was discovered
/// and a UDP socket was opened on the same port.
///
/// The dup2-to-a-specific-fd dance is exactly what systemd
/// does (it dup2's the listening socket to fd 3 before exec).
/// Using a high fd (`dup` picks the lowest free; we re-dup
/// from there to a fixed slot) sidesteps collisions with
/// whatever the test harness has open at low numbers.
#[test]
fn adopt_listeners_from_high_fd() {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let want_addr = tcp.local_addr().unwrap();

    // dup() to get a fresh high fd. We don't care WHERE it
    // lands, just that it's distinct from `tcp`'s fd (so when
    // we drop `tcp`, the duped fd survives) and not fd 3.
    let high_fd = nix::unistd::dup(tcp.as_raw_fd()).expect("dup");
    // Original drops here; high_fd is the only handle now.
    drop(tcp);

    let listeners = adopt_listeners_from(high_fd, 1, &opts()).unwrap();
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].local, want_addr);
    assert!(!listeners[0].bindto, "socket-activated → bindto=false");

    // UDP got opened on the same port (`setup_vpn_in_socket(&sa)`).
    let udp_addr = listeners[0].udp.local_addr().unwrap().as_socket().unwrap();
    assert_eq!(udp_addr.port(), want_addr.port());

    // CLOEXEC was set. Probe via F_GETFD.
    let flags = fcntl(listeners[0].tcp.as_raw_fd(), FcntlArg::F_GETFD).unwrap();
    assert!(
        FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC),
        "adopted TCP fd should be CLOEXEC"
    );
}

/// `n > MAXSOCKETS` is the only pre-adoption guard.
#[test]
fn adopt_listeners_too_many() {
    let e = adopt_listeners_from(3, MAXSOCKETS + 1, &opts())
        .err()
        .expect("n > MAXSOCKETS should error")
        .to_string();
    assert!(e.contains("Too many"), "got: {e}");
}

/// Fd is not a socket → ENOTSOCK from getsockname → hard error.
#[test]
fn adopt_listeners_not_a_socket() {
    // /dev/null at a high fd. getsockname → ENOTSOCK.
    let f = std::fs::File::open("/dev/null").unwrap();
    let high_fd = nix::unistd::dup(f.as_raw_fd()).expect("dup");
    drop(f);

    // adopt_listeners_from took ownership of high_fd via
    // Socket::from_raw_fd; the error path drops the Socket,
    // which closes high_fd. No leak.
    let e = adopt_listeners_from(high_fd, 1, &opts())
        .err()
        .expect("expected ENOTSOCK")
        .to_string();
    assert!(e.contains("Could not get address"), "got: {e}");
}
