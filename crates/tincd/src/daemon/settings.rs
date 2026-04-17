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

// Upper bound for duration-ish config values fed into Instant arithmetic.
const MAX_DURATION_SECS: u32 = 365 * 24 * 3600; // 1 year
const MAX_REPLAY_WINDOW: usize = 1 << 20;

/// Reloadable config knobs. Separate from `Daemon` so SIGHUP can
/// swap it wholesale. `Default` matches upstream tinc defaults.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // each bool is an
// independent config knob; grouping into state enums would obscure
// the 1:1 config-key mapping.
pub struct DaemonSettings {
    /// Seconds between pings. Default 60.
    pub pinginterval: u32,
    /// Seconds to wait for PONG before assuming peer dead. Clamped
    /// to `[1, pinginterval]`. Default 5.
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
    /// zlib, 12 LZ4; 10-11 LZO (stubbed, rejected at setup).
    pub compression: u8,
    /// When set, `route_packet` decrements TTL after the forward
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
    /// Hub-mode: don't gossip indirect topology. Our direct peers
    /// learn each other only by us telling them; they can't learn
    /// each other's far-side neighbors. `ADD/DEL_EDGE/SUBNET` are
    /// filtered (drop if neither endpoint is us or a direct peer)
    /// and not forwarded.
    ///
    /// Implies `strictsubnets` (applied in `apply_reloadable_settings`
    /// after both are parsed): a hub doesn't gossip indirect topology
    /// AND doesn't trust direct peers to claim arbitrary subnets.
    pub tunnelserver: bool,
    /// The operator's `hosts/NAME` files become the AUTHORITY for
    /// which subnets each node owns. `ADD_SUBNET` gossip for subnets
    /// not in the file is ignored (forwarded, not added locally).
    /// `DEL_SUBNET` for subnets that ARE in the file is ignored.
    ///
    /// Implied by `tunnelserver`. `load_all_nodes` preloads the
    /// authorized subnets at startup; lookup-first means authorized
    /// gossip passes through silently (already-have-it noop).
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
    /// `route_packet`. Default `Internal`.
    pub forwarding_mode: ForwardingMode,
    /// Dispatch shape: `Router` → ethertype switch; `Switch` →
    /// `route_mac`; `Hub` → always broadcast. NOT reloadable -
    /// changing tun↔tap mid-run means re-opening the device.
    pub routing_mode: RoutingMode,
    /// The `RouteResult::Broadcast` arm dispatches on this. `None`
    /// drops all broadcasts; `Direct` only sends to one-hop
    /// neighbors (and only when WE originated). Default `Mst`.
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
    /// Seconds. Debounce for `send_udp_info` (only when WE
    /// originate). Default 5.
    pub udp_info_interval: u32,
    /// Seconds. Separate debounce from `UDP_INFO`. Default 5.
    pub mtu_info_interval: u32,
    /// Seconds. The `KeyExpire` timer fires at this interval and
    /// forces an SPTPS rekey on every tunnel with `validkey`.
    /// Default 3600.
    ///
    /// **Nonce-reuse guard.** SPTPS uses `outseqno: u32` as the
    /// ChaCha20-Poly1305 nonce; nothing checks for wraparound. At
    /// 1.5 Gbps / 1400-byte packets (≈134k pps), 2^32 packets is
    /// ≈9 hours to nonce reuse - catastrophic for ChaCha20-Poly1305.
    /// The 3600s timer caps any single key at ≈4.8e8 packets.
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
    /// Global `PMTU` from tinc.conf. Clamps ALL peers. Per-host
    /// `PMTU` also clamps (both apply, min wins).
    pub global_pmtu: Option<u16>,
    /// Global `Weight` from tinc.conf. Fallback when per-host
    /// `Weight` is absent. Overrides the RTT measurement.
    pub global_weight: Option<i32>,
    /// `DeviceStandby`. When set, `tinc-up` is NOT fired at setup:
    /// the script defers until the FIRST peer becomes reachable.
    /// Mirror for tinc-down: fired when the LAST peer becomes
    /// unreachable. For laptops that don't want a configured-but-
    /// unconnected tun0 hanging around. Non-reloadable.
    pub device_standby: bool,

    /// `DhtDiscovery` (Rust extension). BEP 42 port-probe for our public
    /// v4 + BEP 44 publish keyed by our Ed25519 pubkey. Off by default:
    /// publishing hands pubkey + candidate addrs to ~8 random DHT nodes
    /// in cleartext, and the keepalive holds a NAT hole open. For cold-
    /// start when you don't have one static `Address=`. Non-reloadable.
    pub dht_discovery: bool,

    /// `DhtBootstrap` (Rust extension). `host:port` seeds. Empty ⇒
    /// mainline's defaults. Replace, not augment: BEP 42 has no quorum
    /// threshold, so a single attacker-controlled bootstrap that wins
    /// the routing-table population race also fakes the port-probe echo
    /// (⇒ fakes the published `v4=`). NOT SAFE for invitations.
    pub dht_bootstrap: Vec<String>,
    // Chunk 4+: ~32 more fields.
}

/// Three-way forwarding knob. `Internal` gates the `SPTPS_PACKET`
/// relay; `Kernel` is checked at the top of `route_packet`:
/// anything from a peer goes straight to the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardingMode {
    /// Drop packets not addressed to us.
    Off,
    /// The daemon's `route()` does the forwarding decision.
    #[default]
    Internal,
    /// Write everything from a peer to TUN; let the OS routing
    /// table decide. Packets from OUR device still go through
    /// `route()` (we're the originator).
    Kernel,
}

/// Read once at setup, NOT reloadable (changing it mid-run would
/// mean re-opening the device tun→tap).
///
/// | Variant | Device | Dispatch |
/// |---|---|---|
/// | `Router` | TUN | `route()` ethertype switch |
/// | `Switch` | TAP | `route_mac()` |
/// | `Hub` | TAP | always `Broadcast` |
///
/// Hub mode broadcasts everything. No MAC learning, no subnet
/// table - pure flood. Niche; wired but untested.
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
            invitation_lifetime: Duration::from_secs(604_800), // 1 week
            local_discovery: true,
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
            global_weight: None,
            device_standby: false,
            dht_discovery: false,
            dht_bootstrap: Vec::new(),
        }
    }
}

/// Parse the reloadable subset of settings from `config`. Called
/// from `setup()` AND `reload_configuration()`. Non-reloadable
/// settings (Port, `AddressFamily`, `DeviceType`) are NOT here - they
/// need re-bind / re-open which `setup()` does inline.
pub(crate) fn apply_reloadable_settings(config: &tinc_conf::Config, settings: &mut DaemonSettings) {
    if let Some(e) = config.lookup("PingInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.pinginterval = v.min(MAX_DURATION_SECS);
    }
    // Clamped to [1, pinginterval].
    if let Some(e) = config.lookup("PingTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.pingtimeout = v.clamp(1, settings.pinginterval);
    }
    // Per-host PMTU is read in proto.rs::handle_id; this is the
    // tinc.conf-level clamp.
    if let Some(e) = config.lookup("PMTU").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u16::try_from(v)
    {
        settings.global_pmtu = Some(v);
    }
    // Fallback when per-host Weight absent.
    if let Some(e) = config.lookup("Weight").next()
        && let Ok(v) = e.get_int()
    {
        settings.global_weight = Some(v);
    }
    if let Some(e) = config.lookup("MaxTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.maxtimeout = v.min(MAX_DURATION_SECS);
    }
    if let Some(e) = config.lookup("DecrementTTL").next()
        && let Ok(v) = e.get_bool()
    {
        settings.decrement_ttl = v;
    }
    if let Some(e) = config.lookup("TunnelServer").next()
        && let Ok(v) = e.get_bool()
    {
        settings.tunnelserver = v;
    }
    if let Some(e) = config.lookup("StrictSubnets").next()
        && let Ok(v) = e.get_bool()
    {
        settings.strictsubnets = v;
    }
    // tunnelserver implies strictsubnets. Applied after BOTH parsed.
    settings.strictsubnets |= settings.tunnelserver;
    if let Some(e) = config.lookup("LocalDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.local_discovery = v;
    }
    if let Some(e) = config.lookup("DirectOnly").next()
        && let Ok(v) = e.get_bool()
    {
        settings.directonly = v;
    }
    if let Some(e) = config.lookup("PriorityInheritance").next()
        && let Ok(v) = e.get_bool()
    {
        settings.priorityinheritance = v;
    }
    if let Some(e) = config.lookup("AutoConnect").next()
        && let Ok(v) = e.get_bool()
    {
        settings.autoconnect = v;
    }
    // ScriptsExtension is NOT parsed (Windows-only).
    let new_interp = config
        .lookup("ScriptsInterpreter")
        .next()
        .map(|e| e.get_str().to_owned());
    if new_interp == settings.scripts_interpreter
        || crate::sandbox::can(crate::sandbox::Action::UseNewPaths)
    {
        settings.scripts_interpreter = new_interp;
    } else {
        log::warn!(target: "tincd",
            "Ignoring ScriptsInterpreter change: not allowed at current sandbox level");
    }
    if let Some(e) = config.lookup("UDPDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.udp_discovery = v;
    }
    if let Some(e) = config.lookup("UDPDiscoveryKeepaliveInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_discovery_keepalive_interval = v;
    }
    if let Some(e) = config.lookup("UDPDiscoveryInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_discovery_interval = v;
    }
    if let Some(e) = config.lookup("UDPDiscoveryTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_discovery_timeout = v;
    }
    // Silently keep default on <=0 (less harsh on reload typo).
    if let Some(e) = config.lookup("MaxConnectionBurst").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.max_connection_burst = v;
    }
    if let Some(e) = config.lookup("ReplayWindow").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = usize::try_from(v)
    {
        settings.replaywin = v.min(MAX_REPLAY_WINDOW);
    }
    if let Some(e) = config.lookup("UDPInfoInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_info_interval = v;
    }
    if let Some(e) = config.lookup("MTUInfoInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.mtu_info_interval = v;
    }
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
    if let Some(e) = config.lookup("MACExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u64::try_from(v)
    {
        settings.macexpire = v.min(u64::from(MAX_DURATION_SECS));
    }
    if let Some(e) = config.lookup("MaxOutputBufferSize").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = usize::try_from(v)
    {
        settings.maxoutbufsize = v;
    }
    if let Some(e) = config.lookup("InvitationExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u64::try_from(v)
    {
        settings.invitation_lifetime = Duration::from_secs(v);
    }
    if let Some(e) = config.lookup("KeyExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.keylifetime = v.min(MAX_DURATION_SECS);
    }
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
/// `AddressFamily`, Mode, sockopts, Proxy, Compression, Forwarding,
/// DHT, `DeviceStandby`) need re-bind / re-open and are setup-only.
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
    // NOT Port/AddressFamily (those need re-bind, setup-only).
    apply_reloadable_settings(config, &mut settings);

    // BindToAddress for outgoing source-addr selection. Non-
    // reloadable. We only stash the FIRST entry here for the
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

    // UDPRcvBuf / UDPSndBuf. Warnings enabled ONLY when the
    // operator explicitly configures - the 1MB default tripping
    // the kernel cap on every boot would be log noise.
    if let Some(e) = config.lookup("UDPRcvBuf").next()
        && let Ok(v) = e.get_int()
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
        && let Ok(v) = e.get_int()
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
    if let Some(e) = config.lookup("FWMark").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.sockopts.fwmark = v;
    }

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

    // Compression. HOST-tagged. The level WE want peers to
    // compress towards us at. Reject LZO (stubbed) and >12.
    if let Some(e) = config.lookup("Compression").next()
        && let Ok(v) = e.get_int()
    {
        let v = u8::try_from(v).unwrap_or(255);
        match compress::Level::from_wire(v) {
            compress::Level::LzoLo | compress::Level::LzoHi => {
                return Err(SetupError::Config(format!(
                    "Compression = {v}: LZO compression is \
                         unavailable on this node"
                )));
            }
            compress::Level::None if v != 0 => {
                // `from_wire` mapped >12 → None. Reject.
                return Err(SetupError::Config(format!(
                    "Compression = {v} is unrecognized by this node"
                )));
            }
            _ => settings.compression = v,
        }
    }

    // Mode. NOT in apply_reloadable_settings (device re-open).
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
    if let Some(e) = config.lookup("DeviceStandby").next()
        && let Ok(v) = e.get_bool()
    {
        settings.device_standby = v;
    }

    // Rust extension. Non-reloadable.
    if let Some(e) = config.lookup("DhtDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.dht_discovery = v;
    }
    settings.dht_bootstrap = config
        .lookup("DhtBootstrap")
        .map(|e| e.get_str().to_owned())
        .collect();

    if let Some(e) = config.lookup("Forwarding").next() {
        match e.get_str().to_ascii_lowercase().as_str() {
            "off" => settings.forwarding_mode = ForwardingMode::Off,
            "internal" => settings.forwarding_mode = ForwardingMode::Internal,
            "kernel" => settings.forwarding_mode = ForwardingMode::Kernel,
            v => {
                return Err(SetupError::Config(format!(
                    "Forwarding = {v}: invalid forwarding mode"
                )));
            }
        }
    }

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
}
