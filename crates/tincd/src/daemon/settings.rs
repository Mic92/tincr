//! Reloadable config layer. Pure `tinc_conf::Config → DaemonSettings`;
//! NO event loop / device / socket deps. `load_settings` is the
//! setup-time entry point; `apply_reloadable_settings` is the
//! SIGHUP-time subset.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use tinc_proto::Subnet;

use crate::listen::{AddrFamily, SockOpts};
use crate::outgoing::{MAX_TIMEOUT_DEFAULT, ProxyConfig, parse_proxy_config};
use crate::tunnel::MTU;
use crate::{broadcast, compress, mac_lease};

use super::SetupError;
use crate::daemon::UpnpMode;
use crate::keys;
use crate::sandbox;
use crate::sandbox::Action;

/// Look up boolean config key `$key` and assign into `$field` on
/// success. Parse failures are logged inside [`get_bool`] and the
/// default is kept. Collapses ~10 identical 5-line `if let` blocks.
macro_rules! cfg_bool {
    ($cfg:expr, $key:literal => $field:expr) => {
        if let Some(e) = $cfg.lookup($key).next()
            && let Some(v) = get_bool(e)
        {
            $field = v;
        }
    };
}

/// Look up integer config key `$key`, narrow to `$ty`, then run
/// `$body` with the parsed value bound as `$v`. The body absorbs the
/// per-key clamping / `Some(..)` wrapping that varies between keys,
/// so the lookup/parse boilerplate stays single-sourced.
macro_rules! cfg_int {
    ($cfg:expr, $key:literal, $ty:ty, |$v:ident| $body:expr) => {
        if let Some(e) = $cfg.lookup($key).next()
            && let Some($v) = get_int_as::<$ty>(e)
        {
            $body;
        }
    };
}

/// `e.get_bool()`, but a parse failure is logged (with var/file/line) before
/// falling back to `None`, so `DecrementTTL = ture` is visibly a typo rather
/// than silently unset. Reload still keeps the default instead of failing.
fn get_bool(e: &tinc_conf::Entry) -> Option<bool> {
    e.get_bool()
        .inspect_err(|err| log::error!(target: "tincd", "{err}; using default"))
        .ok()
}

/// See [`get_bool`]. Same treatment for integer-typed keys.
fn get_int(e: &tinc_conf::Entry) -> Option<i32> {
    e.get_int()
        .inspect_err(|err| log::error!(target: "tincd", "{err}; using default"))
        .ok()
}

/// `get_int` then `T::try_from`. The narrowing failure (negative
/// into `u32`, etc.) is also logged with provenance so
/// `ReplayWindow = -1` doesn't silently become the default.
fn get_int_as<T>(e: &tinc_conf::Entry) -> Option<T>
where
    T: TryFrom<i32>,
{
    let v = get_int(e)?;
    T::try_from(v)
        .inspect_err(|_| {
            log::error!(target: "tincd",
                        "value {v} out of range for variable `{}' {}; using default",
                        e.variable, e.source);
        })
        .ok()
}

// Upper bound for duration-ish config values fed into Instant arithmetic.
const MAX_DURATION_SECS: u32 = 365 * 24 * 3600; // 1 year
const MAX_REPLAY_WINDOW: usize = 1 << 20;

/// Reloadable config knobs. Separate from `Daemon` so SIGHUP can
/// swap it wholesale. `Default` matches upstream tinc defaults.
#[derive(Debug, Clone)]
#[expect(clippy::struct_excessive_bools)] // each bool is an
// independent config knob; grouping into state enums would obscure
// the 1:1 config-key mapping.
pub struct DaemonSettings {
    /// Seconds between pings. Default 60.
    pub pinginterval: u32,
    /// Seconds to wait for PONG before assuming peer dead. Clamped
    /// to `pinginterval` when out of `[1, pinginterval]`. Default 5.
    pub pingtimeout: u32,
    /// The `Port` config (HOST-tagged: from `hosts/NAME` not
    /// tinc.conf). Default 655. 0 means "kernel picks" - valid for
    /// tests; the actual port is read back from `listeners[0]`.
    pub port: u16,
    /// Filters which address families `open_listeners` tries.
    /// Default `Any` means dual-stack.
    pub addressfamily: AddrFamily,
    /// Retry-backoff cap in seconds. Default 900 (15 min).
    /// `retry_outgoing` caps `outgoing.timeout` here.
    pub maxtimeout: u32,
    /// Seconds. The laptop-suspend detector triggers if the ping
    /// timer didn't run for `> 2*this` seconds: the daemon was
    /// asleep, every peer has given up on us, force-close all conns
    /// to avoid sending into stale SPTPS contexts. Default 30.
    pub udp_discovery_timeout: u32,
    /// `Compression = N` config knob. Advertised in `ANS_KEY`; peers
    /// compress TOWARDS us at this level. Default 0 (none). 1-9
    /// zlib, 10 LZO (vendored minilzo), 12 LZ4. 11 (LZO `_999`) is
    /// rejected at setup: minilzo can decompress it but not produce it.
    pub compression: u8,
    /// When set, `forward_packet` decrements TTL after the forward
    /// decision. Makes `traceroute` through the mesh show each hop.
    /// Off by default because it MUTATES forwarded packets (TTL +
    /// IPv4 checksum); some payloads (e.g. ESP) hash the IP header.
    pub decrement_ttl: bool,
    /// Seconds between UDP probe-request sends when
    /// `!udp_confirmed`. Default 2.
    pub udp_discovery_interval: u32,
    /// Seconds between probe sends when `udp_confirmed`. Default 10.
    /// Keeps NAT mappings alive.
    pub udp_discovery_keepalive_interval: u32,
    /// Hub mode: don't gossip indirect topology. `ADD/DEL_EDGE/SUBNET` with neither
    /// endpoint being us or a direct peer are dropped and not forwarded. Implies
    /// `strictsubnets` (applied after both are parsed).
    pub tunnelserver: bool,
    /// `hosts/NAME` files are the authority for subnet ownership: `ADD_SUBNET` for
    /// unlisted subnets is forwarded but not added, `DEL_SUBNET` for listed ones is
    /// ignored. Implied by `tunnelserver`; `load_all_nodes` preloads the authorised
    /// set so matching gossip is a silent no-op.
    pub strictsubnets: bool,
    /// Route-time gate: if `owner != via` (would relay), send ICMP
    /// `NET_ANO` instead. The relay path EXISTS and works; this knob
    /// lets the operator say "don't use it".
    pub directonly: bool,
    /// Copy the inner packet's TOS/TC byte to the outer UDP socket
    /// via `IP_TOS`/`IPV6_TCLASS` before send. Without it, all
    /// encrypted traffic gets default DSCP regardless of inner QoS
    /// marking.
    pub priorityinheritance: bool,
    /// `Off` drops packets not addressed to us (leaf-only mode).
    /// `Kernel` writes everything from a peer straight to TUN, lets
    /// the OS routing table decide. Checked at the top of
    /// `forward_packet`. Default `Internal`.
    pub forwarding_mode: ForwardingMode,
    /// Dispatch shape: `Router` → ethertype switch; `Switch` →
    /// `route_mac`; `Hub` → always broadcast. not reloadable -
    /// changing tun↔tap mid-run means re-opening the device.
    pub routing_mode: RoutingMode,
    /// The `RouteResult::Broadcast` arm dispatches on this. `None`
    /// drops all broadcasts; `Direct` only sends to one-hop
    /// neighbors (and only when we originated). Default `Mst`.
    pub broadcast_mode: broadcast::BroadcastMode,
    /// Seconds. Lease TTL for learned MACs. The `age_subnets` 10s
    /// timer is the SWEEP frequency; this is the LEASE duration.
    /// Default 600.
    pub macexpire: u64,
    /// Bytes. Random Early Drop threshold for the meta-connection
    /// TCP outbuf - under load, RED keeps the buffer from growing
    /// unbounded by probabilistically dropping data packets queued
    /// behind a slow TCP send. Default `10 * MTU`.
    pub maxoutbufsize: usize,
    /// Config var `InvitationExpire`. `serve_cookie` checks
    /// `mtime + this < now`. Default one week.
    pub invitation_lifetime: Duration,
    /// When set, `try_udp` sends a SECOND probe to the peer's LAN-
    /// side address (from `ADD_EDGE.local_address`) when
    /// `!udp_confirmed`. Faster convergence when both nodes are on
    /// the same LAN behind the same NAT - the WAN probe round-trips
    /// through the NAT (or hairpin-fails); the LAN probe goes direct.
    pub local_discovery: bool,
    /// `Shards = auto|N` (Rust extension, Linux-only, restart-only).
    /// Data-plane worker threads, each owning one multi-queue TUN fd
    /// and one reuseport UDP socket. `None` = auto:
    /// `min(available_parallelism, 4)` — four ≈5 Gbit/s shards
    /// saturate the ~20 Gbit/s per-queue kernel egress path. `1`
    /// disables sharding (single-thread datapath, today's code).
    pub shards: Option<u16>,
    /// When set, outgoing meta-connections `bind()` to this local
    /// address before `connect()`. Useful for multi-homed hosts
    /// where the default route doesn't go via the desired interface.
    /// Config: `BindToAddress = HOST PORT` (port 0 = any).
    pub bind_to_address: Option<SocketAddr>,
    /// `None` = direct connect. `Exec` is socketpair+fork (no
    /// handshake); `Socks4`/`Socks5` connect to the proxy then send
    /// `socks::build_request` bytes before the ID line and read the
    /// fixed-length reply via `conn.tcplen`. `Http` sends
    /// `CONNECT host:port` then intercepts the line-based response
    /// in `metaconn.rs` before `check_gate` while `allow_request==Id`.
    pub proxy: Option<ProxyConfig>,
    /// Default **true**. When set, `periodic_handler` runs
    /// `do_autoconnect` every 5s: converge to ~3 direct connections.
    /// Tests that don't want surprise connections (most of them) set
    /// `AutoConnect = no`.
    pub autoconnect: bool,
    /// Seconds. Debounce for `send_udp_info` (only when we
    /// originate). Default 5.
    pub udp_info_interval: u32,
    /// Seconds. Separate debounce from `UDP_INFO`. Default 5.
    pub mtu_info_interval: u32,
    /// Seconds between forced SPTPS rekeys of every `validkey` tunnel; default
    /// 3600. This is the nonce-reuse guard: `outseqno` is a u32 ChaCha20-Poly1305
    /// nonce with no wrap check, ≈9 hours at 1.5 Gbps, so an hourly rekey caps a
    /// key at ≈4.8e8 packets.
    pub keylifetime: u32,
    /// Per-listener sockopts. `UDPRcvBuf`/`UDPSndBuf`/`FWMark`/
    /// `BindToInterface` config keys. Non-reloadable: rebinding
    /// would mean closing all listeners. `fwmark` is also used by
    /// the outgoing-connect path (separate site, not yet wired).
    pub sockopts: SockOpts,
    /// `ScriptsInterpreter`. When `Some`, scripts are run as
    /// `<interp> <script>` instead of `<script>` directly. Unix
    /// shebang makes this redundant; useful for shebang-less hooks.
    pub scripts_interpreter: Option<String>,
    /// `ReplayWindow`. Datagram-mode anti-replay window size in
    /// packets. Passed to every `Sptps::start` for UDP tunnels.
    /// Default 32.
    pub replaywin: usize,
    /// `MaxConnectionBurst`. Tarpit leaky-bucket capacity. Same-host
    /// triggers at `> this`; all-host at `>= this`. Default 10.
    /// Non-reloadable: the tarpit is constructed once at setup.
    pub max_connection_burst: u32,
    /// `UDPDiscovery`. Master switch for the UDP probe machinery.
    /// Default true. When false, `try_udp` is a no-op and `try_mtu`
    /// skips the not-confirmed reset; the daemon falls back to
    /// TCP-only forwarding.
    pub udp_discovery: bool,
    /// Global `PMTU` from tinc.conf. Clamps all peers. Per-host
    /// `PMTU` also clamps (both apply, min wins).
    pub global_pmtu: Option<u16>,
    /// Global `SPTPSCipher` default. Per-peer override comes from
    /// `hosts/NAME`. Default `ChaCha20Poly1305` — the only value
    /// wire-compatible with C tinc 1.1.
    pub sptps_cipher: tinc_sptps::SptpsAead,
    /// Global `Weight` from tinc.conf. Fallback when per-host
    /// `Weight` is absent. Overrides the RTT measurement.
    pub global_weight: Option<i32>,
    /// `SPTPSKex` from tinc.conf: KEX mode for *all* SPTPS sessions
    /// (meta-connection and per-tunnel). Default `x25519` is wire-
    /// identical to C tinc; `x25519-mlkem768` adds the post-quantum
    /// leg. Per-host override (in `hosts/PEER`) takes precedence —
    /// see [`read_sptps_kex`]. Non-reloadable: changing it mid-run
    /// would desync the next rekey.
    pub sptps_kex: tinc_sptps::SptpsKex,
    /// `DeviceStandby`. When set, `tinc-up` is not fired at setup:
    /// the script defers until the first peer becomes reachable.
    /// Mirror for tinc-down: fired when the LAST peer becomes
    /// unreachable. For laptops that don't want a configured-but-
    /// unconnected tun0 hanging around. Non-reloadable.
    pub device_standby: bool,

    /// `UPnP = yes|udponly|no`. When
    /// not `No`, spawns a background thread that asks the LAN gateway
    /// (NAT-PMP first, then UPnP-IGD) to DNAT our listener port. Default off. Non-reloadable.
    pub upnp: UpnpMode,
    /// `UPnPDiscoverWait`. SSDP M-SEARCH wait. Default 5s.
    pub upnp_discover_wait: u32,
    /// `UPnPRefreshPeriod`. Re-add the mapping every N seconds;
    /// lease is 2×N so a missed refresh doesn't expire it. Default 60.
    pub upnp_refresh_period: u32,
    // Chunk 4+: ~32 more fields.
}

/// Three-way forwarding knob. `Internal` gates the `SPTPS_PACKET`
/// relay; `Kernel` is checked at the top of `forward_packet`:
/// anything from a peer goes straight to the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardingMode {
    /// Drop packets not addressed to us.
    Off,
    /// The daemon's `route()` does the forwarding decision.
    #[default]
    Internal,
    /// Write everything from a peer to TUN; let the OS routing
    /// table decide. Packets from our device still go through
    /// `route()` (we're the originator).
    Kernel,
}

/// Read once at setup; changing it would mean reopening the device. `Router`:
/// TUN, `route()` by ethertype. `Switch`: TAP, `route_mac()`. `Hub`: TAP,
/// always broadcast (no MAC learning; wired but untested).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingMode {
    /// IP-layer routing.
    #[default]
    Router,
    /// MAC-layer routing with learning.
    Switch,
    /// Always broadcast. No learning.
    Hub,
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            pinginterval: 60,
            pingtimeout: 5,
            port: 655,
            addressfamily: AddrFamily::Any,
            maxtimeout: MAX_TIMEOUT_DEFAULT,
            udp_discovery_timeout: 30,
            compression: 0,
            decrement_ttl: false,
            udp_discovery_interval: 2,
            udp_discovery_keepalive_interval: 10,
            tunnelserver: false,
            strictsubnets: false,
            directonly: false,
            priorityinheritance: false,
            forwarding_mode: ForwardingMode::Internal,
            routing_mode: RoutingMode::Router,
            broadcast_mode: broadcast::BroadcastMode::Mst,
            macexpire: mac_lease::DEFAULT_EXPIRE_SECS,
            maxoutbufsize: 10 * MTU as usize,
            invitation_lifetime: Duration::from_hours(168), // 1 week
            local_discovery: true,
            shards: None,
            bind_to_address: None,
            proxy: None,
            autoconnect: true,
            udp_info_interval: 5,
            mtu_info_interval: 5,
            keylifetime: 3600,
            sockopts: SockOpts::default(),
            scripts_interpreter: None,
            // 32 is strictly more tolerant of reordering than 16.
            replaywin: 32,
            max_connection_burst: 10,
            udp_discovery: true,
            global_pmtu: None,
            sptps_cipher: tinc_sptps::SptpsAead::default(),
            global_weight: None,
            sptps_kex: tinc_sptps::SptpsKex::default(),
            device_standby: false,
            upnp: UpnpMode::No,
            upnp_discover_wait: 5,
            upnp_refresh_period: 60,
        }
    }
}

/// Parse the reloadable subset of settings from `config`. Called
/// from `setup()` and `reload_configuration()`. Non-reloadable
/// settings (Port, `AddressFamily`, `DeviceType`) are not here - they
/// need re-bind / re-open which `setup()` does inline.
pub(crate) fn apply_reloadable_settings(config: &tinc_conf::Config, settings: &mut DaemonSettings) {
    cfg_int!(config, "PingInterval", u32, |v| if v >= 1 {
        settings.pinginterval = v.min(MAX_DURATION_SECS);
    });
    cfg_int!(config, "PingTimeout", u32, |v| settings.pingtimeout = v);
    // C parity: out-of-range snaps to pinginterval (not 1); applied
    // unconditionally so a small PingInterval pulls the default 5 down.
    if settings.pingtimeout < 1 || settings.pingtimeout > settings.pinginterval {
        settings.pingtimeout = settings.pinginterval;
    }
    // Per-host PMTU is read in dispatch.rs::handle_id; this is the
    // tinc.conf-level clamp.
    cfg_int!(config, "PMTU", u16, |v| settings.global_pmtu = Some(v));
    // Static AEAD selection. Reloadable in the sense that new tunnels
    // pick it up; existing sessions keep their negotiated-at-start
    // cipher until the next `KeyExpire` rekey restarts them.
    if let Some(e) = config.lookup("SPTPSCipher").next() {
        match tinc_sptps::SptpsAead::from_config_str(e.get_str()) {
            Some(a) => {
                settings.sptps_cipher = a;
                if a == tinc_sptps::SptpsAead::Aes256Gcm {
                    keys::warn_aes_no_hw_once();
                }
            }
            None => log::error!(target: "tincd::conf",
                "SPTPSCipher = {}: unknown value \
                 (want chacha20-poly1305 | aes-256-gcm); using default",
                e.get_str()),
        }
    }
    // Fallback when per-host Weight absent.
    cfg_int!(config, "Weight", i32, |v| settings.global_weight = Some(v));
    cfg_int!(config, "MaxTimeout", u32, |v| if v >= 1 {
        settings.maxtimeout = v.min(MAX_DURATION_SECS);
    });
    cfg_bool!(config, "DecrementTTL" => settings.decrement_ttl);
    cfg_bool!(config, "TunnelServer" => settings.tunnelserver);
    cfg_bool!(config, "StrictSubnets" => settings.strictsubnets);
    // tunnelserver implies strictsubnets. Applied after both parsed.
    settings.strictsubnets |= settings.tunnelserver;
    cfg_bool!(config, "LocalDiscovery" => settings.local_discovery);
    if let Some(e) = config.lookup("Shards").next() {
        match e.get_str() {
            "auto" => settings.shards = None,
            s => match s.parse::<u16>() {
                Ok(n @ 1..=64) => settings.shards = Some(n),
                _ => log::warn!(target: "tincd", "Shards = {s}: expected auto or 1..=64"),
            },
        }
    }
    cfg_bool!(config, "DirectOnly" => settings.directonly);
    cfg_bool!(config, "PriorityInheritance" => settings.priorityinheritance);
    cfg_bool!(config, "AutoConnect" => settings.autoconnect);
    // ScriptsExtension is not parsed (Windows-only).
    let new_interp = config
        .lookup("ScriptsInterpreter")
        .next()
        .map(|e| e.get_str().to_owned());
    if new_interp == settings.scripts_interpreter || sandbox::can(Action::UseNewPaths) {
        settings.scripts_interpreter = new_interp;
    } else {
        log::warn!(target: "tincd",
            "Ignoring ScriptsInterpreter change: not allowed at current sandbox level");
    }
    cfg_bool!(config, "UDPDiscovery" => settings.udp_discovery);
    cfg_int!(config, "UDPDiscoveryKeepaliveInterval", u32, |v| {
        settings.udp_discovery_keepalive_interval = v;
    });
    cfg_int!(config, "UDPDiscoveryInterval", u32, |v| {
        settings.udp_discovery_interval = v;
    });
    cfg_int!(config, "UDPDiscoveryTimeout", u32, |v| {
        settings.udp_discovery_timeout = v;
    });
    // timeout <= keepalive interval would demote every confirmed UDP
    // path to permanent TCP fallback. Keep the default 3:1 ratio.
    if settings.udp_discovery_timeout <= settings.udp_discovery_keepalive_interval {
        let clamped = settings.udp_discovery_keepalive_interval.saturating_mul(3);
        log::warn!(target: "tincd",
            "UDPDiscoveryTimeout {} is not above UDPDiscoveryKeepaliveInterval {}. Raising timeout to {clamped}",
            settings.udp_discovery_timeout, settings.udp_discovery_keepalive_interval);
        settings.udp_discovery_timeout = clamped;
    }
    // Keep default on <=0 (less harsh on reload typo); logged above.
    cfg_int!(config, "MaxConnectionBurst", u32, |v| if v >= 1 {
        settings.max_connection_burst = v;
    });
    cfg_int!(config, "ReplayWindow", usize, |v| {
        settings.replaywin = v.min(MAX_REPLAY_WINDOW);
    });
    cfg_int!(config, "UDPInfoInterval", u32, |v| settings
        .udp_info_interval =
        v);
    cfg_int!(config, "MTUInfoInterval", u32, |v| settings
        .mtu_info_interval =
        v);
    // Log + keep default on unknown (less harsh on reload typo).
    if let Some(e) = config.lookup("Broadcast").next() {
        settings.broadcast_mode = match e.get_str().to_ascii_lowercase().as_str() {
            "no" => broadcast::BroadcastMode::None,
            "yes" | "mst" => broadcast::BroadcastMode::Mst,
            "direct" => broadcast::BroadcastMode::Direct,
            v => {
                log::error!(target: "tincd",
                            "Broadcast = {v}: invalid (no|yes|mst|direct)");
                settings.broadcast_mode
            }
        };
    }
    cfg_int!(config, "MACExpire", u64, |v| {
        settings.macexpire = v.min(u64::from(MAX_DURATION_SECS));
    });
    cfg_int!(config, "MaxOutputBufferSize", usize, |v| settings
        .maxoutbufsize =
        v);
    cfg_int!(config, "InvitationExpire", u64, |v| {
        settings.invitation_lifetime = Duration::from_secs(v);
    });
    // Reloadable in C (`setup_myself_reloadable`).
    if let Some(e) = config.lookup("Forwarding").next() {
        match e.get_str().to_ascii_lowercase().as_str() {
            "off" => settings.forwarding_mode = ForwardingMode::Off,
            "internal" => settings.forwarding_mode = ForwardingMode::Internal,
            "kernel" => settings.forwarding_mode = ForwardingMode::Kernel,
            v => log::error!(target: "tincd",
                             "Forwarding = {v}: invalid (off|internal|kernel)"),
        }
    }
    cfg_int!(config, "KeyExpire", u32, |v| {
        // Ceiling 3600s: defense-in-depth for the counter-driven
        // nonce-reuse guard. No floor (tiny values only waste CPU).
        let clamped = v.clamp(1, 3600);
        if !(60..=3600).contains(&v) {
            log::warn!(target: "tincd",
                       "KeyExpire = {v} outside [60, 3600]; using {clamped}");
        }
        settings.keylifetime = clamped;
    });
}

/// Parse `Subnet =` lines for `myname` from `config`. Factored from
/// `setup()` so `reload_configuration()` can call the same parser.
pub(crate) fn parse_subnets_from_config(
    config: &tinc_conf::Config,
    myname: &str,
) -> HashSet<Subnet> {
    let mut subnets = HashSet::new();
    for e in config.lookup("Subnet") {
        match e.get_str().parse::<Subnet>() {
            Ok(s) => {
                subnets.insert(s);
            }
            Err(_) => {
                log::error!(target: "tincd",
                            "Invalid Subnet = {} in hosts/{myname}",
                            e.get_str());
            }
        }
    }
    subnets
}

/// Read `SPTPSKex` from `config` (host file or tinc.conf), falling
/// back to `default` when absent. Returns `Err(value)` on an
/// unparseable value so call sites can decide between hard-error
/// (tinc.conf at setup) and warn-and-default (per-host at handshake
/// time — a malformed peer host file shouldn't take the daemon down).
pub(crate) fn read_sptps_kex(
    config: &tinc_conf::Config,
    default: tinc_sptps::SptpsKex,
) -> Result<tinc_sptps::SptpsKex, String> {
    match config.lookup("SPTPSKex").next() {
        None => Ok(default),
        Some(e) => e.get_str().parse().map_err(|()| e.get_str().to_owned()),
    }
}

/// Parse `ConnectTo =` names from `config`. Filters invalid names
/// and self-reference.
pub(crate) fn parse_connect_to_from_config(
    config: &tinc_conf::Config,
    myname: &str,
) -> Vec<String> {
    config
        .lookup("ConnectTo")
        .map(|e| e.get_str().to_owned())
        .filter(|n| {
            if !tinc_proto::check_id(n) {
                log::error!(target: "tincd",
                            "Invalid name for outgoing connection: {n}");
                return false;
            }
            if n == myname {
                log::warn!(target: "tincd",
                            "ConnectTo = {n} is ourselves; skipping");
                return false;
            }
            true
        })
        .collect()
}

/// Parse `BindToAddress` / `ListenAddress` value: `"HOST [PORT]"`.
/// Split on first space; port half is optional (defaults to global
/// `Port`). `"*"` means the wildcard - `build_listeners` translates
/// it to the literal wildcard IP per requested family.
pub(super) fn parse_bind_addr(s: &str, default_port: u16) -> (&str, u16) {
    let mut parts = s.splitn(2, ' ');
    let host = parts.next().unwrap_or("");
    // Numeric only (no service-name resolution).
    let port = parts
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    (host, port)
}

/// Parse the non-reloadable settings from `config` into a fresh
/// `DaemonSettings`. Called once from `setup()`. Reloadable settings
/// are folded in via `apply_reloadable_settings`; the rest (Port,
/// `AddressFamily`, Mode, sockopts, Proxy, Compression,
/// `DeviceStandby`) need re-bind / re-open and are setup-only.
pub(super) fn load_settings(config: &tinc_conf::Config) -> Result<DaemonSettings, SetupError> {
    let mut settings = DaemonSettings::default();

    // Port. HOST-tagged. `Port = 0` is valid: kernel picks (tests
    // use this). Non-numeric Port (service-name resolution) not
    // supported; reject.
    if let Some(e) = config.lookup("Port").next() {
        settings.port = e.get_str().parse().map_err(|_| {
            SetupError::Config(format!("Port = {} is not a valid port number", e.get_str()))
        })?;
    }

    // AddressFamily. SERVER-tagged. Unknown values silently
    // ignored; stays at default.
    if let Some(e) = config.lookup("AddressFamily").next() {
        if let Some(af) = AddrFamily::from_config(e.get_str()) {
            settings.addressfamily = af;
        } else {
            log::warn!(target: "tincd",
                       "Unknown AddressFamily = {}, using default",
                       e.get_str());
        }
    }

    // Reloadable settings. Factored into a helper so
    // reload_configuration can call it too.
    // not Port/AddressFamily (those need re-bind, setup-only).
    apply_reloadable_settings(config, &mut settings);

    // BindToAddress for outgoing source-addr selection. Non-
    // reloadable. We only stash the first entry here for the
    // outgoing-connect bind; the FULL set is re-read below in the
    // listener-creation block.
    if let Some(e) = config.lookup("BindToAddress").next() {
        let s = e.get_str();
        let (host, port) = parse_bind_addr(s, 0);
        match (host, port).to_socket_addrs() {
            Ok(mut iter) => settings.bind_to_address = iter.next(),
            Err(e) => {
                log::warn!(target: "tincd",
                           "BindToAddress = {s}: {e}; not binding");
            }
        }
    }

    // UDPRcvBuf / UDPSndBuf. Warnings enabled only when the
    // operator explicitly configures - the 1MB default tripping
    // the kernel cap on every boot would be log noise.
    if let Some(e) = config.lookup("UDPRcvBuf").next()
        && let Some(v) = get_int(e)
    {
        match usize::try_from(v) {
            Ok(v) => {
                settings.sockopts.udp_rcvbuf = v;
                settings.sockopts.udp_buf_warnings = true;
            }
            Err(_) => {
                return Err(SetupError::Config("UDPRcvBuf cannot be negative!".into()));
            }
        }
    }
    if let Some(e) = config.lookup("UDPSndBuf").next()
        && let Some(v) = get_int(e)
    {
        match usize::try_from(v) {
            Ok(v) => {
                settings.sockopts.udp_sndbuf = v;
                settings.sockopts.udp_buf_warnings = true;
            }
            Err(_) => {
                return Err(SetupError::Config("UDPSndBuf cannot be negative!".into()));
            }
        }
    }

    // FWMark. 0 (default/unset) means "skip".
    cfg_int!(config, "FWMark", u32, |v| settings.sockopts.fwmark = v);

    // BindToInterface. Hoisted to setup-time; not reloadable
    // (sockets are already bound).
    if let Some(e) = config.lookup("BindToInterface").next() {
        settings.sockopts.bind_to_interface = Some(e.get_str().to_owned());
    }

    // Proxy. Non-reloadable: our outgoing-connection path reads
    // it at dial time; reload would need to re-dial existing conns.
    if let Some(e) = config.lookup("Proxy").next() {
        settings.proxy = parse_proxy_config(e.get_str()).map_err(SetupError::Config)?;
    }

    // Compression. HOST-tagged. Reject LzoHi (minilzo lacks `_999`
    // compress) and anything outside 0..=12.
    if let Some(e) = config.lookup("Compression").next()
        && let Some(raw) = get_int(e)
    {
        let v = u8::try_from(raw).unwrap_or(u8::MAX);
        match compress::Level::from_wire(v) {
            compress::Level::LzoHi => {
                return Err(SetupError::Config(format!(
                    "Compression = {}: LZO level 11 (lzo1x_999) is \
                     unavailable on this node",
                    e.get_str()
                )));
            }
            compress::Level::None if v != 0 => {
                return Err(SetupError::Config(format!(
                    "Compression = {} is unrecognized by this node",
                    e.get_str()
                )));
            }
            _ => settings.compression = v,
        }
    }

    // Mode. not in apply_reloadable_settings (device re-open).
    if let Some(e) = config.lookup("Mode").next() {
        settings.routing_mode = match e.get_str().to_ascii_lowercase().as_str() {
            "router" => RoutingMode::Router,
            "switch" => RoutingMode::Switch,
            "hub" => RoutingMode::Hub,
            v => {
                return Err(SetupError::Config(format!(
                    "Mode = {v}: invalid routing mode (router|switch|hub)"
                )));
            }
        };
    }

    // DeviceStandby. Non-reloadable: decides whether tinc-up
    // fires at setup vs first-peer.
    cfg_bool!(config, "DeviceStandby" => settings.device_standby);

    // SPTPSKex. Non-reloadable. Unknown values are a hard error,
    // not a silent default — a typo here would silently strip the PQ
    // leg the operator asked for.
    settings.sptps_kex = read_sptps_kex(config, tinc_sptps::SptpsKex::default()).map_err(|v| {
        SetupError::Config(format!("SPTPSKex = {v}: expected x25519|x25519-mlkem768"))
    })?;

    // UPnP. Non-reloadable (thread spawned once at setup).
    if let Some(e) = config.lookup("UPnP").next() {
        match UpnpMode::from_config(e.get_str()) {
            Some(m) => settings.upnp = m,
            None => {
                return Err(SetupError::Config(format!(
                    "UPnP = {}: expected yes|udponly|no",
                    e.get_str()
                )));
            }
        }
    }
    cfg_int!(config, "UPnPDiscoverWait", u32, |v| {
        settings.upnp_discover_wait = v.clamp(1, 60);
    });
    cfg_int!(config, "UPnPRefreshPeriod", u32, |v| {
        settings.upnp_refresh_period = v.clamp(1, MAX_DURATION_SECS);
    });

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse_bind_addr`: `"HOST [PORT]"`. Port optional, defaults
    /// to global.
    #[test]
    fn parse_bind_addr_cases() {
        // Both fields.
        assert_eq!(parse_bind_addr("10.0.0.1 5000", 655), ("10.0.0.1", 5000));
        // Port omitted → default.
        assert_eq!(parse_bind_addr("10.0.0.1", 655), ("10.0.0.1", 655));
        // Port 0 explicit (kernel picks).
        assert_eq!(parse_bind_addr("10.0.0.1 0", 655), ("10.0.0.1", 0));
        // Wildcard host. `*` handled by caller (build_listeners).
        assert_eq!(parse_bind_addr("* 5000", 655), ("*", 5000));
        // Unparseable port → default. We don't support service-name
        // resolution; fall back.
        assert_eq!(parse_bind_addr("10.0.0.1 http", 655), ("10.0.0.1", 655));
    }

    #[test]
    fn udp_discovery_timeout_clamped_above_keepalive() {
        let c = cfg(&[
            "UDPDiscoveryTimeout = 5",
            "UDPDiscoveryKeepaliveInterval = 10",
        ]);
        let mut s = DaemonSettings::default();
        apply_reloadable_settings(&c, &mut s);
        assert!(
            s.udp_discovery_timeout > s.udp_discovery_keepalive_interval,
            "timeout {} must exceed keepalive interval {}",
            s.udp_discovery_timeout,
            s.udp_discovery_keepalive_interval
        );

        // Keepalive raised past the default timeout also trips.
        let c = cfg(&["UDPDiscoveryKeepaliveInterval = 60"]);
        let mut s = DaemonSettings::default();
        apply_reloadable_settings(&c, &mut s);
        assert!(s.udp_discovery_timeout > s.udp_discovery_keepalive_interval);
    }

    fn cfg(lines: &[&str]) -> tinc_conf::Config {
        let mut c = tinc_conf::Config::default();
        for (i, l) in lines.iter().enumerate() {
            #[expect(clippy::cast_possible_truncation)]
            let e = tinc_conf::parse_line(
                l,
                tinc_conf::Source::File {
                    path: "test".into(),
                    line: i as u32,
                },
            )
            .unwrap()
            .unwrap();
            c.merge([e]);
        }
        c
    }

    #[test]
    fn compression_lzo_lo_accepted_hi_rejected() {
        let s = load_settings(&cfg(&["Compression = 10"]))
            .expect("LzoLo round-trips via vendored minilzo");
        assert_eq!(s.compression, 10);
        assert!(load_settings(&cfg(&["Compression = 11"])).is_err());
    }

    #[test]
    fn compression_out_of_range_error_quotes_input() {
        let err = load_settings(&cfg(&["Compression = -1"]))
            .expect_err("negative compression should be rejected");
        let SetupError::Config(msg) = err else {
            panic!("expected Config error, got {err:?}")
        };
        assert!(
            msg.contains("-1"),
            "error message should quote the user's value, got: {msg}"
        );
        assert!(
            !msg.contains("255"),
            "error message leaks the internal u8 sentinel: {msg}"
        );
    }

    #[test]
    fn forwarding_is_reloadable() {
        let mut s = DaemonSettings::default();
        assert_eq!(s.forwarding_mode, ForwardingMode::Internal);
        apply_reloadable_settings(&cfg(&["Forwarding = off"]), &mut s);
        assert_eq!(
            s.forwarding_mode,
            ForwardingMode::Off,
            "SIGHUP with Forwarding=off should take effect (C tinc parity)"
        );
    }

    #[test]
    fn pingtimeout_out_of_range_snaps_to_pinginterval() {
        let mut s = DaemonSettings::default();
        apply_reloadable_settings(&cfg(&["PingTimeout = 0"]), &mut s);
        assert_eq!(
            s.pingtimeout, s.pinginterval,
            "C tinc snaps out-of-range PingTimeout to pinginterval, not 1"
        );
        let mut s = DaemonSettings::default();
        apply_reloadable_settings(&cfg(&["PingInterval = 10", "PingTimeout = 30"]), &mut s);
        assert_eq!(s.pingtimeout, 10);
        let mut s = DaemonSettings::default();
        apply_reloadable_settings(&cfg(&["PingTimeout = 3"]), &mut s);
        assert_eq!(s.pingtimeout, 3);
    }

    #[test]
    fn keyexpire_clamped() {
        for (raw, want) in [("31536000", 3600), ("5", 5), ("1800", 1800)] {
            let mut s = DaemonSettings::default();
            apply_reloadable_settings(&cfg(&[&format!("KeyExpire = {raw}")]), &mut s);
            assert_eq!(s.keylifetime, want, "KeyExpire = {raw}");
        }
    }
}
