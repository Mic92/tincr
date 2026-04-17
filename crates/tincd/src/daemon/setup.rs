//! Daemon boot path: device open, listener bind, event-loop wiring,
//! and the giant `Daemon` struct literal. Everything here runs once.
//! `SetupError` lives in the parent so `settings.rs` and this file
//! both reach it via `super::` without a sibling cycle.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::AsFd;
use std::path::Path;
use std::time::{Duration, SystemTime};

use slotmap::SlotMap;
use tinc_crypto::sign::SigningKey;
use tinc_device::{Device, DeviceArena, GroBucket};
use tinc_event::{EventLoop, Io, SelfPipe, TimerId, Timers};
use tinc_graph::Graph;
use tinc_proto::Subnet;

use crate::compress;
use crate::control::{ControlSocket, generate_cookie, write_pidfile};
#[cfg(not(target_os = "linux"))]
use crate::egress::Portable;
use crate::egress::UdpEgress;
use crate::icmp;
use crate::inthash::IntHashMap;
use crate::invitation_serve;
use crate::keys::{PrivKeyError, read_ecdsa_private_key};
use crate::listen::{
    AddrFamily, Listener, MAXSOCKETS, SockOpts, Tarpit, open_listener_pair, open_listeners,
    pidfile_addr,
};
use crate::mac_lease;
use crate::node_id::NodeId6Table;
use crate::outgoing::{Outgoing, resolve_config_addrs};
use crate::proto::myself_options_from_config;
use crate::seen::SeenRequests;
use crate::subnet_tree::SubnetTree;

use super::settings::{
    DaemonSettings, RoutingMode, load_settings, parse_bind_addr, parse_connect_to_from_config,
    parse_subnets_from_config,
};
use super::{Daemon, IoWhat, ListenerSlot, SetupError, SignalWhat, TimerWhat, net};

/// For each `BindToAddress` line then each `ListenAddress` line,
/// resolve and create listener pair(s). If neither key is present,
/// fall through to the wildcard default (`open_listeners`).
///
/// Port reuse: the first listener picks an ephemeral with `Port=0`;
/// every subsequent bind tries to reuse it so the daemon advertises
/// ONE port to peers regardless of how many addresses it listens on.
///
/// `bindto`: `BindToAddress` listeners are also used as outgoing-
/// connect source addresses; `ListenAddress` listeners are listen-only.
fn build_listeners(
    config: &tinc_conf::Config,
    port: u16,
    family: AddrFamily,
    opts: &SockOpts,
) -> Vec<Listener> {
    let mut listeners: Vec<Listener> = Vec::new();
    // None until the first successful bind.
    let mut reuse_port: Option<u16> = if port == 0 { None } else { Some(port) };
    let mut cfgs = 0usize;
    // Dedup tracks the REQUESTED (pre-bind) addrs, not `l.local`
    // (that's post-bind with ephemeral filled in).
    let mut requested: Vec<SocketAddr> = Vec::new();

    let mut try_addr = |addr: SocketAddr, bindto: bool| {
        if requested.contains(&addr) {
            return;
        }
        requested.push(addr);
        if listeners.len() >= MAXSOCKETS {
            log::error!(target: "tincd::net", "Too many listening sockets");
            return;
        }
        if let Some(l) = open_listener_pair(addr, opts, reuse_port, bindto) {
            // First successful bind seeds the reuse port (only
            // meaningful when Port=0).
            if reuse_port.is_none() {
                reuse_port = Some(l.local.port());
            }
            listeners.push(l);
        }
    };

    for (key, bindto) in [("BindToAddress", true), ("ListenAddress", false)] {
        for e in config.lookup(key) {
            cfgs += 1;
            let s = e.get_str();
            let (host, p) = parse_bind_addr(s, port);
            // Synthesize wildcard addrs directly; skips the resolver.
            if host == "*" {
                if family.try_v4() {
                    try_addr((std::net::Ipv4Addr::UNSPECIFIED, p).into(), bindto);
                }
                if family.try_v6() {
                    try_addr((std::net::Ipv6Addr::UNSPECIFIED, p).into(), bindto);
                }
                continue;
            }
            // A hostname may resolve to multiple addrs (v4+v6); bind
            // each. to_socket_addrs doesn't take a family hint, so
            // filter post-resolve.
            match (host, p).to_socket_addrs() {
                Ok(iter) => {
                    for addr in iter {
                        let ok = match family {
                            AddrFamily::Any => true,
                            AddrFamily::Ipv4 => addr.is_ipv4(),
                            AddrFamily::Ipv6 => addr.is_ipv6(),
                        };
                        if ok {
                            try_addr(addr, bindto);
                        }
                    }
                }
                Err(e) => {
                    // Lenient: skip this entry, try the rest. If ALL
                    // fail, the empty-listeners check below catches it.
                    log::error!(target: "tincd::net",
                                "{key} = {s}: {e}");
                }
            }
        }
    }

    // No config → wildcard default.
    if cfgs == 0 {
        return open_listeners(port, family, opts);
    }

    listeners
}

/// `Name = $FOO` reads env var `FOO`. `Name = $HOST` falls back to
/// `gethostname(2)`. Thin wrapper over the shared implementation in
/// `tinc_conf::name` so the daemon and `tinc` CLI agree on the result
/// (previously they didn't — the CLI kept the domain part, the daemon
/// truncated at `.`, and exchanged host files mismatched).
#[allow(unsafe_code)] // libc::gethostname; nix `hostname` feature not enabled
fn expand_name(name: &str) -> Result<String, String> {
    tinc_conf::name::expand_name(
        name,
        |k| std::env::var(k).ok(),
        || {
            let mut buf = [0u8; 256];
            // SAFETY: buf is valid, len is correct. POSIX leaves
            // gethostname truncation unspecified - force-NUL the
            // last byte.
            let rc =
                unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
            if rc != 0 {
                return Err(format!(
                    "gethostname failed: {}",
                    io::Error::last_os_error()
                ));
            }
            *buf.last_mut().unwrap() = 0;
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
        },
    )
}

/// `setup()`: pure config→Device, no daemon state.
fn open_device(config: &tinc_conf::Config) -> Result<Box<dyn Device>, SetupError> {
    let device_type = config
        .lookup("DeviceType")
        .next()
        .map(|e| e.get_str().to_ascii_lowercase());
    let device: Box<dyn Device> = match device_type.as_deref() {
        None => {
            // Upstream defaults to the platform tun/tap driver. We
            // keep `dummy` as the default so the integration-test
            // suite (and `tinc fsck`/CI dry-runs) can boot the daemon
            // unprivileged without `/dev/net/tun`. But a fresh
            // `tinc init` + `tincd` then "works" with peers connected
            // and zero packets flowing, which is a baffling failure
            // mode — so shout about it. `warn!` lands in the default
            // log output; users following the quickstart will see it.
            log::warn!(target: "tincd",
                       "DeviceType not set; using dummy device — NO packets will flow. \
                        Set `DeviceType = tun` (or tap) in tinc.conf for a real tunnel.");
            Box::new(tinc_device::Dummy)
        }
        Some("dummy") => Box::new(tinc_device::Dummy),
        #[cfg(target_os = "linux")]
        Some("fd") => {
            // The fd comes from `Device = N` (inherited fd) or
            // `--device-fd N`. The integration test creates a
            // socketpair, writes one end's fd into `Device = N`,
            // and pumps IP packets through it. `FdTun` reads at
            // `+14` (raw IP, no tun_pi prefix) and synthesizes
            // the ethertype - the framing `route()` expects.
            let dev_str = config
                .lookup("Device")
                .next()
                .map(tinc_conf::Entry::get_str)
                .ok_or_else(|| SetupError::Config("DeviceType=fd requires Device = <fd>".into()))?;
            let fd: std::os::unix::io::RawFd = dev_str
                .parse()
                .map_err(|_| SetupError::Config(format!("Device = {dev_str} is not a valid fd")))?;
            let tun = tinc_device::FdTun::open(tinc_device::FdSource::Inherited(fd))
                .map_err(SetupError::Io)?;
            Box::new(tun)
        }
        #[cfg(target_os = "linux")]
        Some("tun") => {
            // Real kernel TUN via `/dev/net/tun` + TUNSETIFF.
            // Needs `CAP_NET_ADMIN`; the netns harness grants it
            // inside an unprivileged userns via bwrap.
            //
            // `Interface = NAME` → attach to a precreated
            // persistent device; unset → kernel picks `tun0`/etc.
            // The netns test precreates so it can move the device
            // into a child netns AFTER the daemon attaches (the
            // fd→device binding survives `ip link set netns`).
            let cfg = tinc_device::DeviceConfig {
                iface: config
                    .lookup("Interface")
                    .next()
                    .map(|e| e.get_str().to_owned()),
                ..Default::default()
            };
            let tun = tinc_device::Tun::open(&cfg).map_err(SetupError::Io)?;
            Box::new(tun)
        }
        #[cfg(target_os = "linux")]
        Some("tap") => {
            // TODO: auto-derive tap when Mode != router and
            // DeviceType is unset. We only handle the explicit
            // form here; the cross-impl test sets it explicitly.
            let cfg = tinc_device::DeviceConfig {
                iface: config
                    .lookup("Interface")
                    .next()
                    .map(|e| e.get_str().to_owned()),
                mode: tinc_device::Mode::Tap,
                ..Default::default()
            };
            let tun = tinc_device::Tun::open(&cfg).map_err(SetupError::Io)?;
            Box::new(tun)
        }
        #[cfg(target_os = "macos")]
        Some("tun") => {
            // Parse optional "Interface = utunN" → unit number N.
            // Unset → None → kernel picks the next available utun.
            let unit = config
                .lookup("Interface")
                .next()
                .map(tinc_conf::Entry::get_str)
                .and_then(|s| s.strip_prefix("utun"))
                .and_then(|n| n.parse::<u32>().ok());
            let tun = tinc_device::BsdTun::open_utun(unit).map_err(SetupError::Io)?;
            Box::new(tun)
        }
        #[cfg(target_os = "macos")]
        Some("tap") => {
            return Err(SetupError::Config(
                "DeviceType=tap is not supported on macOS (no vmnet backend). \
                 Use DeviceType=tun (utun) instead."
                    .into(),
            ));
        }
        Some(other) => {
            return Err(SetupError::Config(format!(
                "DeviceType={other} not supported yet; use dummy or fd"
            )));
        }
    };
    Ok(device)
}

/// Register each listener pair on the event loop and wrap into
/// `ListenerSlot`s. Factored from `setup()`: consumes the bare
/// `Listener`s and yields the daemon-side slots.
fn register_listeners(
    listeners: Vec<Listener>,
    ev: &mut EventLoop<IoWhat>,
) -> Result<Vec<ListenerSlot>, SetupError> {
    let mut listener_slots = Vec::with_capacity(listeners.len());
    for (i, l) in listeners.into_iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)] // MAXSOCKETS=8 fits in u8
        let i = i as u8;
        ev.add(l.tcp_fd(), Io::Read, IoWhat::Tcp(i))
            .map_err(SetupError::Io)?;
        ev.add(l.udp_fd(), Io::Read, IoWhat::Udp(i))
            .map_err(SetupError::Io)?;
        // On Linux, dup into `linux::Fast` (UDP_SEGMENT cmsg,
        // one sendmsg per batch).
        // No probe: kernel ≥4.18 floor; ENOPROTOOPT at
        // first batch → panic with a clear message (see
        // `egress/linux.rs::map_errno`). Non-Linux stays
        // `Portable` (count × sendto).
        //
        // The listener keeps its copy for `recvmmsg`; the egress
        // sends on the dup. Same file description → same bound
        // addr, same TOS (the daemon's `set_udp_tos` sets it on
        // the listener fd).
        #[cfg(target_os = "linux")]
        let egress: Box<dyn UdpEgress> =
            Box::new(crate::egress::linux::Fast::new(&l.udp).map_err(SetupError::Io)?);
        #[cfg(not(target_os = "linux"))]
        let egress: Box<dyn UdpEgress> = Box::new(Portable::new(&l.udp).map_err(SetupError::Io)?);
        listener_slots.push(ListenerSlot {
            listener: l,
            last_tos: 0,
            egress,
        });
    }
    Ok(listener_slots)
}

/// Parse `DNSAddress`/`DNSSuffix` into `DnsConfig`. Rust-only
/// extension. Off (returns `Ok(None)`) unless BOTH are set.
fn load_dns_config(
    config: &tinc_conf::Config,
) -> Result<Option<crate::dns::DnsConfig>, SetupError> {
    let mut a4 = None;
    let mut a6 = None;
    for e in config.lookup("DNSAddress") {
        match e.get_str().parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v)) => a4 = Some(v),
            Ok(std::net::IpAddr::V6(v)) => a6 = Some(v),
            Err(_) => {
                return Err(SetupError::Config(format!(
                    "DNSAddress = {}: not a valid IP address",
                    e.get_str()
                )));
            }
        }
    }
    let suffix = config
        .lookup("DNSSuffix")
        .next()
        .map(|e| e.get_str().trim_matches('.').to_owned());
    match (a4.is_some() || a6.is_some(), suffix) {
        (true, Some(suffix)) => {
            log::info!(target: "tincd::dns",
                       "DNS stub enabled: {} for *.{suffix}",
                       a4.map(|a| a.to_string())
                         .into_iter()
                         .chain(a6.map(|a| a.to_string()))
                         .collect::<Vec<_>>()
                         .join(" + "));
            Ok(Some(crate::dns::DnsConfig {
                dns_addr4: a4,
                dns_addr6: a6,
                suffix,
            }))
        }
        (true, None) => Err(SetupError::Config(
            "DNSAddress set but DNSSuffix missing".into(),
        )),
        (false, Some(_)) => Err(SetupError::Config(
            "DNSSuffix set but DNSAddress missing".into(),
        )),
        (false, None) => Ok(None),
    }
}

/// Register the four daemon-wide timers. Returns the handles in the
/// order `setup()` needs them for the `Daemon` struct literal.
fn register_timers(
    timers: &mut Timers<TimerWhat>,
    settings: &DaemonSettings,
) -> (TimerId, TimerId, TimerId, TimerId) {
    // ─── ping timer
    // Initial fire is `pingtimeout` seconds from now; the handler
    // re-arms at +1s. tinc-event re-arm is EXPLICIT - the match
    // arm calls `timers.set(pingtimer, ...)`.
    let pingtimer = timers.add(TimerWhat::Ping);
    timers.set(
        pingtimer,
        Duration::from_secs(u64::from(settings.pingtimeout)),
    );

    // ─── age_past_requests timer
    // Re-arms +10s. The eviction window is `pinginterval` (the
    // cache key TTL); the timer's 10s is just the sweep frequency.
    let age_timer = timers.add(TimerWhat::AgePastRequests);
    timers.set(age_timer, Duration::from_secs(10));

    // ─── periodic timer
    // Arm +5s directly: no contradictions exist at setup, counters
    // are zero, an immediate first call would just halve sleeptime
    // (10 → 5 → floored to 10) and re-arm.
    let periodictimer = timers.add(TimerWhat::Periodic);
    timers.set(periodictimer, Duration::from_secs(5));

    // ─── keyexpire timer
    // Arm unconditionally: SPTPS needs the rekey to bound the
    // ChaCha20 nonce counter (see `keylifetime` doc).
    let keyexpire_timer = timers.add(TimerWhat::KeyExpire);
    timers.set(
        keyexpire_timer,
        Duration::from_secs(u64::from(settings.keylifetime)),
    );

    (pingtimer, age_timer, periodictimer, keyexpire_timer)
}

/// Register the signal handlers and the self-pipe read end on `ev`.
/// TERM/QUIT/INT all map to Exit. HUP → Reload, ALRM → Retry.
fn register_signals(
    signals: &mut SelfPipe<SignalWhat>,
    ev: &mut EventLoop<IoWhat>,
) -> Result<(), io::Error> {
    signals.add(libc::SIGTERM, SignalWhat::Exit)?;
    signals.add(libc::SIGINT, SignalWhat::Exit)?;
    signals.add(libc::SIGQUIT, SignalWhat::Exit)?;
    signals.add(libc::SIGHUP, SignalWhat::Reload)?;
    signals.add(libc::SIGALRM, SignalWhat::Retry)?;

    // USR1/USR2/WINCH: ignore. C tinc 1.1 sets these to SIG_IGN in
    // detach() (process.c:205-207). Older 1.0.x dumped state on
    // USR1/USR2; that moved to the control socket. Left at default
    // disposition they terminate the process — a stray `kill -USR1`
    // from a monitoring script expecting the old behaviour would
    // kill the daemon.
    //
    // SAFETY: nix::signal is `unsafe` because the `Handler` variant
    // can install an arbitrary fn pointer; `SigIgn` carries none, so
    // there is no async-signal-safety concern. We are still single-
    // threaded at setup (called before the event loop runs).
    #[allow(unsafe_code)]
    unsafe {
        use nix::sys::signal::{SigHandler, Signal, signal};
        let _ = signal(Signal::SIGUSR1, SigHandler::SigIgn);
        let _ = signal(Signal::SIGUSR2, SigHandler::SigIgn);
        let _ = signal(Signal::SIGWINCH, SigHandler::SigIgn);
    }

    // Register the self-pipe read end.
    ev.add(signals.read_fd(), Io::Read, IoWhat::Signal)?;
    Ok(())
}

/// Add the hard-coded multicast/broadcast subnets and any from
/// `BroadcastSubnet=` config. Ownerless → `route_broadcast`. Without
/// these, kernel multicast (mDNS, NDP, DHCP) read from TUN hit
/// Unreachable and we ICMP-bounce our own kernel. Silent breakage —
/// mDNS doesn't surface ICMP. (`Mode = switch` unaffected: `route_mac`
/// floods on miss anyway.)
fn add_broadcast_subnets(subnets: &mut SubnetTree, config: &tinc_conf::Config) {
    for s in [
        "ff:ff:ff:ff:ff:ff",
        "255.255.255.255",
        "224.0.0.0/4",
        "ff00::/8",
    ] {
        subnets.add_broadcast(s.parse().expect("hard-coded broadcast subnet"));
    }
    for e in config.lookup("BroadcastSubnet") {
        match e.get_str().parse::<Subnet>() {
            Ok(s) => subnets.add_broadcast(s),
            Err(_) => {
                log::error!(target: "tincd",
                            "Invalid BroadcastSubnet = {}", e.get_str());
            }
        }
    }
}

// Daemon — the C-global state + the loop

impl Daemon {
    /// `confbase` is the `-c` argument (or `CONFDIR/tinc[/NETNAME]`
    /// resolved by main.rs). `pidfile`/`socket` are the runtime paths.
    ///
    /// # Errors
    /// Startup failures: tinc.conf missing/malformed, no `Name`,
    /// device open failed, pidfile write failed (permissions),
    /// socket bind failed (already running).
    ///
    /// # Panics
    /// `SelfPipe::new` panics if a `SelfPipe` already exists in this
    /// process (it's a singleton - see tinc-event/sig.rs). Can't
    /// happen here: setup is called once. Tests that call setup
    /// twice in one process are wrong; integration tests use
    /// subprocess.
    #[allow(clippy::too_many_lines)] // straight-line struct init; pulling 3 fields out makes it worse
    pub fn setup(
        confbase: &Path,
        pidfile: &Path,
        socket: &Path,
        cmdline_conf: &tinc_conf::Config,
        socket_activation: Option<usize>,
    ) -> Result<Self, SetupError> {
        // ─── read tinc.conf
        let mut config = tinc_conf::read_server_config(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;

        // ─── cmdline -o overrides
        // Merge order doesn't matter: Source::Cmdline sorts before
        // Source::File regardless. Empty cmdline_conf is a no-op.
        config.merge(cmdline_conf.entries().iter().cloned());

        // ─── Name
        let name = config
            .lookup("Name")
            .next()
            .map(tinc_conf::Entry::get_str)
            .ok_or_else(|| SetupError::Config("Name for tinc daemon required!".into()))?;
        let name = expand_name(name).map_err(SetupError::Config)?;
        log::info!(target: "tincd", "tincd starting, name={name}");

        // ─── read host config
        // Merge hosts/NAME into the same tree as tinc.conf. HOST-tagged
        // vars (Port, Subnet, PublicKey, etc) live there. Missing
        // hosts/NAME is not fatal: the only var we read from it here
        // is Port, which has a default. Hard failures (no key, no
        // subnets) come later.
        let host_file = confbase.join("hosts").join(&name);
        match tinc_conf::parse_file(&host_file) {
            Ok(entries) => config.merge(entries),
            Err(e) => {
                // Warn-level: MIGHT be intentional (freshly-init'd
                // daemon has no hosts/ yet) but more likely a Name typo.
                log::warn!(target: "tincd",
                           "hosts/{name} not read: {e}; using defaults");
            }
        }

        // ─── private key
        // Missing key is FATAL: we forbid legacy, so there is no RSA
        // fallback. The error message includes the gen-keys hint so
        // the user knows what to do.
        let mykey = read_ecdsa_private_key(&config, confbase).map_err(|e| {
            let hint = if matches!(e, PrivKeyError::Missing(_)) {
                "\n  (Create a key pair with `tinc generate-ed25519-keys`)"
            } else {
                ""
            };
            SetupError::Config(format!("{e}{hint}"))
        })?;

        // ─── surface unknown keys
        // The daemon never consults VARS for lookup (it asks for
        // specific names), so a typo'd key is otherwise just inert —
        // "typo ≡ unset" with no hint why. Warn once at startup.
        for e in config.entries() {
            if tinc_conf::lookup_var(&e.variable).is_none() {
                log::warn!(target: "tincd",
                           "Unknown configuration variable `{}' {}",
                           e.variable, e.source);
            }
        }

        // ─── settings
        let settings = load_settings(&config)?;

        // ─── device
        let device = open_device(&config)?;
        // Captured BEFORE the Box goes into the Daemon struct: the
        // `&dyn` trait borrow makes `&mut self` script call sites
        // awkward.
        let iface = device.iface().to_owned();
        let device_mode = device.mode();
        log::info!(target: "tincd",
                   "Device mode: {device_mode:?}, interface: {iface}");

        // TAP-ish device + Mode=router → kernel emits/expects eth
        // frames but our routing layer ignores MACs. The stamp writes
        // a valid dst-MAC on the way to the device.
        let overwrite_mac =
            device_mode == tinc_device::Mode::Tap && settings.routing_mode == RoutingMode::Router;
        // Locally-administered placeholder; SIOCGIFHWADDR seeds from
        // the kernel, the ARP/NDP snatch then keeps it fresh.
        let mymac = device.mac().unwrap_or([0xFE, 0xFD, 0, 0, 0, 0]);

        // ─── event loop scaffolding
        // tinc-event constructors. EventLoop::new can fail (epoll_
        // create); the others can't (BTreeMap, pipe).
        let mut ev = EventLoop::new().map_err(SetupError::Io)?;
        let mut timers = Timers::new();
        let mut signals = SelfPipe::new().map_err(SetupError::Io)?;

        // ─── signals
        register_signals(&mut signals, &mut ev).map_err(SetupError::Io)?;

        // ─── device fd
        // Dummy returns None; Tun/Fd/Raw/Bsd return Some(fd).
        if let Some(fd) = device.fd() {
            // tinc-device's trait-object accessor returns `RawFd`
            // (cross-crate, multi-backend). The fd is owned by
            // `device` and live for this call.
            #[allow(unsafe_code)]
            let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            ev.add(fd, Io::Read, IoWhat::Device)
                .map_err(SetupError::Io)?;
        }

        // ─── timers (ping, age_past_requests, periodic, keyexpire)
        let (pingtimer, age_timer, periodictimer, keyexpire_timer) =
            register_timers(&mut timers, &settings);

        // ─── listeners
        // Socket activation BYPASSES BindToAddress/ListenAddress
        // entirely (the .socket unit IS the bind config). Otherwise
        // walk BindToAddress, then ListenAddress, else wildcard.
        // Empty result is a hard error: the daemon can't function
        // without at least one listener.
        let listeners = if let Some(n) = socket_activation {
            crate::listen::adopt_listeners(n, &settings.sockopts)
                .map_err(|e| SetupError::Config(format!("socket activation: {e}")))?
        } else {
            build_listeners(
                &config,
                settings.port,
                settings.addressfamily,
                &settings.sockopts,
            )
        };
        // Always read back the bound port - same answer when port≠0
        // (kernel binds the requested port). `first()` not `[0]`:
        // the empty-check below still wants its own error message.
        let my_udp_port = listeners.first().map_or(0, Listener::udp_port);
        if listeners.is_empty() {
            return Err(SetupError::Config(
                "Unable to create any listening socket!".into(),
            ));
        }
        // Map listeners[0]'s bound addr 0.0.0.0→127.0.0.1, format
        // `"HOST port PORT"`. Pidfile format is fixed (the CLI on
        // Windows actually connects to this addr; Unix uses the unix
        // socket and ignores it). Computed before `listeners` is
        // consumed into `ListenerSlot`s.
        let address = pidfile_addr(&listeners);
        // Register each pair. Index `i` becomes `IoWhat::Tcp(i)` so
        // the dispatch arm can index back for the accept.
        let listener_slots = register_listeners(listeners, &mut ev)?;

        // ─── init_control
        // Bind (the AlreadyRunning check) BEFORE writing the pidfile,
        // so a second tincd fails before clobbering the live cookie.
        let control = ControlSocket::bind(socket).map_err(|e| match e {
            crate::control::BindError::AlreadyRunning => SetupError::Config(format!(
                "Control socket {} already in use",
                socket.display()
            )),
            crate::control::BindError::Io(err) => SetupError::Io(err),
        })?;
        let cookie = generate_cookie();
        write_pidfile(pidfile, &cookie, &address).map_err(SetupError::Io)?;
        ev.add(control.as_fd(), Io::Read, IoWhat::UnixListener)
            .map_err(SetupError::Io)?;

        // ─── graph: add myself
        // `Graph::add_node` defaults `reachable = true`.
        let mut graph = Graph::new();
        let myself = graph.add_node(&name);
        let mut node_ids = HashMap::new();
        node_ids.insert(name.clone(), myself);
        let mut id6_table = NodeId6Table::new();
        id6_table.add(&name, myself);

        // ─── Subnet
        // OUR subnets from `hosts/NAME` (HOST-tagged). `route()`
        // needs these to recognize packets destined for us. Parse
        // failures are logged + skipped (the bad subnet just isn't
        // routable).
        let mut subnets = SubnetTree::new();
        for s in parse_subnets_from_config(&config, &name) {
            subnets.add(s, name.clone());
        }

        // ─── DNS stub (Rust-only)
        // Tailscale-style TUN intercept. Off unless BOTH
        // `DNSAddress=` and `DNSSuffix=` are set. The magic IP must
        // also be added to the TUN in `tinc-up`. `DNSAddress` can be
        // repeated for v4+v6.
        let dns = load_dns_config(&config)?;

        // ─── BroadcastSubnet
        add_broadcast_subnets(&mut subnets, &config);

        // ─── ConnectTo
        // Collect names here; the actual connect is done below (it
        // needs `&mut self`). The mark-sweep (terminate connections
        // whose ConnectTo was removed) only matters on SIGHUP-reload.
        let connect_to = parse_connect_to_from_config(&config, &name);

        // ─── invitation key
        // `Ok(None)` if the file doesn't exist - not an error, just
        // no invites issued yet. `Err` for corrupt PEM.
        let invitation_key = invitation_serve::read_invitation_key(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;
        if invitation_key.is_some() {
            log::info!(target: "tincd", "Invitation key loaded");
        }

        log::info!(target: "tincd", "Ready");

        let mut daemon = Self {
            conns: SlotMap::with_key(),
            conn_io: slotmap::SecondaryMap::new(),
            device,
            control,
            listeners: listener_slots,
            // Seed with now: a zero seed would tarpit the first burst
            // window from epoch.
            tarpit: Tarpit::new(timers.now(), settings.max_connection_burst),
            cookie,
            pidfile: pidfile.to_path_buf(),
            name,
            mykey,
            confbase: confbase.to_path_buf(),
            myself_options: myself_options_from_config(&config),
            my_udp_port,
            graph,
            node_ids,
            myself,
            subnets,
            seen: SeenRequests::new(),
            nodes: IntHashMap::default(),
            edge_addrs: HashMap::new(),
            dp: super::DataPlane {
                tunnels: IntHashMap::default(),
                choose_udp_x: 0,
                compressor: compress::Compressor::new(),
                tx_priority: 0,
                tx_scratch: Vec::with_capacity(
                    12 + usize::from(crate::tunnel::MTU) + tinc_sptps::DATAGRAM_OVERHEAD,
                ),
                rx_scratch: Vec::with_capacity(14 + usize::from(crate::tunnel::MTU)),
                rx_fast_scratch: Vec::with_capacity(14 + usize::from(crate::tunnel::MTU)),
                udp_rx_batch: Some(net::UdpRxBatch::new()),
                gro_bucket: None,
                gro_bucket_spare: Some(GroBucket::new()),
                // Linux TUN: vnet_hdr is unconditional since `5cf9b12d`.
                // TAP/FdTun/BSD/Dummy: trait default returns Unsupported.
                // Gate here so we never `offer()` into a bucket whose
                // flush will fail at write — that would silently drop
                // every coalesced burst.
                #[cfg(target_os = "linux")]
                gro_enabled: device_mode == tinc_device::Mode::Tun,
                #[cfg(not(target_os = "linux"))]
                gro_enabled: false,
                device_arena: Some(DeviceArena::new(net::DEVICE_DRAIN_CAP)),
                // Lazy: only allocated on first `DrainResult::Super`.
                // TAP and non-Linux backends never produce Super,
                // never spend the 100KB.
                tso_scratch: None,
                tso_lens: vec![0usize; net::DEVICE_DRAIN_CAP].into_boxed_slice(),
                // None: the send site only stages when inside
                // `on_device_read`'s drain loop. The TxBatch itself
                // is built lazily on first drain (no point allocating
                // ~100KB on a tunnelserver that never sees device reads).
                tx_batch: None,
            },
            id6_table,
            contradicting_add_edge: 0,
            contradicting_del_edge: 0,
            graph_dirty: false,
            sleeptime: 10,
            started_at: timers.now(),
            icmp_ratelimit: icmp::IcmpRateLimit::new(),
            // Seed with now: the first `on_ping_tick` (after
            // `pingtimeout` seconds) sees a delta of `pingtimeout`,
            // well under the `2*30` suspend-detect threshold.
            last_periodic_run_time: timers.now(),
            iface,
            overwrite_mac,
            mymac,
            device_errors: 0,
            outgoings: SlotMap::with_key(),
            outgoing_timers: slotmap::SecondaryMap::new(),
            has_address: HashSet::new(),
            last_routes: std::sync::Arc::new(Vec::new()),
            last_mst: Vec::new(),
            mac_table: HashMap::new(),
            mac_leases: mac_lease::MacLeases::default(),
            mac_cap_warned: false,
            age_subnets_timer: None,
            dns,
            settings,
            // Set true by `device_enable()` after this struct is
            // built (when `!device_standby`); else false until the
            // first BecameReachable.
            device_enabled: false,
            invitation_key,
            // First SIGHUP compares against this. The delta to "end
            // of setup" is one event-loop turn (~ms).
            last_config_check: SystemTime::now(),
            ev,
            timers,
            signals,
            pingtimer,
            age_timer,
            periodictimer,
            keyexpire_timer,
            running: true,
            any_pcap: false,
            discovery: None,
            dht_hints: HashMap::new(),
            dht_probe_sent: HashSet::new(),
            tx_snap: None,
            tunnel_handles: IntHashMap::default(),
        };

        // ─── try_outgoing_connections - the actual setup
        // Done HERE (not above) because it needs `&mut self` for the
        // slotmap + graph + EventLoop.
        for peer in connect_to {
            // The node goes into the graph BEFORE we connect; an
            // ADD_EDGE arriving via some OTHER path can find it.
            daemon.lookup_or_add_node(&peer);
            let config_addrs = resolve_config_addrs(&daemon.confbase, &peer);
            let addr_cache =
                crate::addrcache::AddressCache::open(&daemon.confbase, &peer, config_addrs);
            let oid = daemon.outgoings.insert(Outgoing {
                node_name: peer,
                timeout: 0,
                addr_cache,
            });
            // Disarmed; `retry_outgoing` arms it.
            let tid = daemon.timers.add(TimerWhat::RetryOutgoing(oid));
            daemon.outgoing_timers.insert(oid, tid);
            daemon.setup_outgoing_connection(oid);
        }

        // The mark-sweep (terminate connections whose ConnectTo was
        // removed) is in `reload_configuration`. setup() never has
        // stale outgoings (it's first boot).

        // ─── load_all_nodes
        // Done after the ConnectTo loop - both add to the same
        // graph, order doesn't matter for correctness, but doing it
        // last keeps the "load every name from disk" step in one place.
        daemon.load_all_nodes();

        // ─── DHT discovery spawn (Rust extension). After listeners
        // (need `my_udp_port` resolved). Spawn failure is non-fatal.
        daemon.spawn_dht_discovery();

        // ─── tinc-up
        // The script typically does `ip addr add` / `ip link set up`
        // on the TUN. Base env only (no NODE/SUBNET). When standby,
        // the FIRST BecameReachable in `run_graph_and_log` fires it
        // instead.
        if !daemon.settings.device_standby {
            daemon.device_enable();
        }

        // Fire subnet-up for our OWN configured subnets. AFTER
        // tinc-up: subnet-up scripts (which add routes) assume the
        // iface is configured. Same loop shape as the BecameReachable
        // arm in gossip.rs.
        for s in &daemon.subnets.owned_by(&daemon.name) {
            daemon.run_subnet_script(true, &daemon.name, s);
        }

        // ─── TX fast-path snapshot. Built post-load_all_nodes so
        // `subnets` has our own configured subnets. routes/ns/tunnels
        // are still empty — tx_probe returns None at route_of()? until
        // the first run_graph_and_log refreshes them. That first call
        // happens on the first on_ack/ADD_EDGE (gossip.rs), well
        // before any TUN read can produce a Super.
        daemon.tx_snap = Some({
            use crate::node_id::NodeId6;
            // id6 prefix: [NULL ‖ myself]. Direct send always (probe
            // gates on via==to, which makes relay==to, which makes
            // the slow-path equivalent set dst_id = nullid).
            let src_id6 = daemon
                .id6_table
                .id_of(daemon.myself)
                .unwrap_or(NodeId6::NULL);
            let mut id6_prefix = [0u8; 12];
            id6_prefix[..6].copy_from_slice(NodeId6::NULL.as_bytes());
            id6_prefix[6..].copy_from_slice(src_id6.as_bytes());

            crate::shard::TxSnapshot {
                // any_pcap NOT folded — it flips at runtime via
                // `tinc pcap` (metaconn.rs sets, route.rs recomputes
                // on conn drop). Checked live at the call site
                // (device.rs) so the fast path bypasses pcap when
                // armed instead of silently shipping uncaptured.
                // overwrite_mac (Router+TAP) folded for the RX fast
                // path: send_packet_myself stamps the eth header
                // before TUN write. RX fast path inlines that write
                // without the stamp — fine for TUN (kernel ignores
                // eth), wrong for TAP. Spawn-const; fold here. TX
                // fast path doesn't write TUN, doesn't care; the
                // gate is shared so TAP loses TX fast-path too —
                // acceptable, TAP+Router is fringe.
                slowpath_all: daemon.dns.is_some()
                    || daemon.settings.routing_mode != RoutingMode::Router
                    || daemon.settings.priorityinheritance
                    || daemon.overwrite_mac,
                myself: daemon.myself,
                myself_options: daemon.myself_options.bits(),
                id6_prefix,
                myself_name: daemon.name.clone().into_boxed_str(),
                // load_all_nodes ran above; ConnectTo + hosts/ names
                // are already in id6_table. tx_snap_refresh_graph
                // re-clones on every BFS, so this initial clone is
                // mostly for symmetry — first packet doesn't arrive
                // until handshake done, by which time refresh_graph
                // has run at least once.
                id6: std::sync::Arc::new(daemon.id6_table.clone()),
                routes: std::sync::Arc::clone(&daemon.last_routes),
                subnets: std::sync::Arc::new(daemon.subnets.clone()),
                ns: std::sync::Arc::default(),
                tunnels: IntHashMap::default(),
            }
        });

        Ok(daemon)
    }

    /// Spawn the DHT discovery actor if enabled. Non-fatal on failure.
    /// After listeners: needs `my_udp_port` resolved.
    fn spawn_dht_discovery(&mut self) {
        if !self.settings.dht_discovery {
            return;
        }
        // SigningKey doesn't impl Clone by design.
        let key = SigningKey::from_blob(&self.mykey.to_blob());
        let bootstrap = if self.settings.dht_bootstrap.is_empty() {
            None
        } else {
            Some(self.settings.dht_bootstrap.as_slice())
        };
        match crate::discovery::Discovery::spawn(key, self.my_udp_port, bootstrap) {
            Ok(d) => {
                log::info!(target: "tincd::discovery",
                "DHT discovery enabled (port {}, bootstrap: {})",
                self.my_udp_port,
                bootstrap.map_or_else(
                    || "mainline".to_owned(),
                    |b| b.join(", ")
                ));
                self.discovery = Some(d);
            }
            Err(e) => {
                log::warn!(target: "tincd::discovery",
                           "DHT actor spawn failed (continuing \
                            without): {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a Config from `key = value` lines. Test-only.
    fn cfg_from(lines: &[&str]) -> tinc_conf::Config {
        let mut c = tinc_conf::Config::new();
        let entries: Vec<_> = lines
            .iter()
            .filter_map(|l| tinc_conf::parse_line(l, tinc_conf::Source::Cmdline { line: 0 }))
            .map(Result::unwrap)
            .collect();
        c.merge(entries);
        c
    }

    /// `build_listeners` no-config default = `open_listeners`.
    #[test]
    fn build_listeners_no_config_is_wildcard() {
        let cfg = cfg_from(&[]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1);
        assert!(ls[0].local.ip().is_unspecified());
        assert!(!ls[0].bindto, "wildcard default is bindto=false");
    }

    /// Two `BindToAddress` lines → two listener pairs. Port reuse:
    /// with `Port=0`, the second pair gets the first pair's port.
    #[test]
    fn build_listeners_two_bindto_shares_port() {
        // Two distinct loopback addrs. Use v4 + v6 loopback so this
        // is portable (macOS only has 127.0.0.1 on lo, not the full
        // 127/8). Different families also guarantees the second bind
        // on the reused port can't EADDRINUSE against the first.
        let cfg = cfg_from(&["BindToAddress = 127.0.0.1", "BindToAddress = ::1"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Any, &SockOpts::default());
        assert_eq!(ls.len(), 2, "two BindToAddress → two pairs");
        assert!(ls[0].bindto && ls[1].bindto);
        assert_eq!(ls[0].local.ip().to_string(), "127.0.0.1");
        assert_eq!(ls[1].local.ip().to_string(), "::1");

        let p = ls[0].local.port();
        assert_ne!(p, 0, "kernel assigned ephemeral");
        // The whole point of bind_reusing_port: every socket
        // converges on the first listener's port.
        assert_eq!(ls[0].udp_port(), p, "pair 0 UDP reused TCP");
        assert_eq!(ls[1].local.port(), p, "pair 1 TCP reused pair 0");
        assert_eq!(ls[1].udp_port(), p, "pair 1 UDP too");
    }

    /// `BindToAddress` vs `ListenAddress`: same plumbing, different
    /// `bindto` flag.
    #[test]
    fn build_listeners_bindto_vs_listen() {
        let cfg = cfg_from(&["BindToAddress = 127.0.0.1", "ListenAddress = ::1"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Any, &SockOpts::default());
        assert_eq!(ls.len(), 2);
        // BindToAddress walked first.
        assert!(ls[0].bindto, "BindToAddress → bindto=true");
        assert!(!ls[1].bindto, "ListenAddress → bindto=false");
    }

    /// `BindToAddress = *` → wildcard.
    #[test]
    fn build_listeners_wildcard_host() {
        let cfg = cfg_from(&["BindToAddress = *"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1);
        assert!(ls[0].local.ip().is_unspecified());
        // `*` via BindToAddress still gets bindto=true (vs the
        // no-config default which is false).
        assert!(ls[0].bindto);
    }

    /// Duplicate addresses skipped.
    #[test]
    fn build_listeners_dedups() {
        let cfg = cfg_from(&[
            "BindToAddress = 127.0.0.1",
            "BindToAddress = 127.0.0.1", // duplicate
        ]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1, "duplicate skipped");
    }

    /// `expand_name` $-expansion + sanitize.
    #[test]
    fn expand_name_passthrough() {
        // No `$` prefix → validated with check_id, returned as-is.
        assert_eq!(expand_name("node1").unwrap(), "node1");
        assert!(expand_name("my-host").is_err());
        assert!(expand_name("").is_err());
    }

    #[test]
    fn expand_name_envvar() {
        // `Name = $FOO` → getenv("FOO"). Non-alnum sanitized to `_`.
        // SAFETY: nextest runs each test in its own process by
        // default, so no concurrent env readers.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("TINC_TEST_NAME_PLAIN", "alpha42");
            std::env::set_var("TINC_TEST_NAME_DOTTED", "host.local");
            std::env::set_var("TINC_TEST_NAME_DASHED", "my-host");
        }
        assert_eq!(expand_name("$TINC_TEST_NAME_PLAIN").unwrap(), "alpha42");
        // Dot truncated (domain stripped); dash squashed to `_`.
        assert_eq!(expand_name("$TINC_TEST_NAME_DOTTED").unwrap(), "host");
        assert_eq!(expand_name("$TINC_TEST_NAME_DASHED").unwrap(), "my_host");
    }

    #[test]
    fn expand_name_unset_var_errors() {
        // Any unset var that isn't $HOST is fatal.
        let e = expand_name("$TINC_TEST_DEFINITELY_UNSET_XYZ").unwrap_err();
        assert!(e.contains("TINC_TEST_DEFINITELY_UNSET_XYZ"));
    }

    #[test]
    fn expand_name_host_fallback() {
        // `$HOST` falls back to gethostname() when unset. We can't
        // control the test machine's hostname, but we CAN assert:
        //   1. it succeeds
        //   2. result is non-empty
        //   3. result is fully alphanumeric (sanitized) — no `.`
        //      survived (stripped at first `.` then sanitized)
        // If $HOST happens to be set in env, that path is exercised
        // instead - same postconditions hold.
        let n = expand_name("$HOST").unwrap();
        assert!(!n.is_empty());
        assert!(n.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }
}
