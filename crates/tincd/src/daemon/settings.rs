//! Reloadable config layer. Pure `tinc_conf::Config → DaemonSettings`;
//! NO event loop / device / socket deps. `load_settings` is the
//! setup-time entry point; `apply_reloadable_settings` is the
//! SIGHUP-time subset.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use tinc_proto::Subnet;

use crate::listen::{AddrFamily, SockOpts};
use crate::outgoing::{MAX_TIMEOUT_DEFAULT, ProxyConfig, parse_proxy_config};
use crate::tunnel::MTU;
use crate::{broadcast, compress, mac_lease};

use super::SetupError;

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

/// `e.get_bool()` but a parse failure is *logged* before falling
/// through to `None`. Previously the `&& let Ok(v) = e.get_bool()`
/// pattern silently discarded the `ParseError` (which carries
/// var/file/line), so `DecrementTTL = true` or `PingInterval = 60s`
/// quietly became "unset" — the user's typo was indistinguishable
/// from never having written the line. We still keep the default
/// (reload should not hard-fail on a typo), but the operator now
/// sees why.
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
    /// `forward_packet`. Default `Internal`.
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

    /// `UPnP = yes|udponly|no`. C parity (`net_setup.c:1202`). When
    /// not `No`, spawns a background thread that asks the LAN gateway
    /// (NAT-PMP first, then UPnP-IGD) to DNAT our listener port. The
    /// TCP mapping feeds `discovery.set_portmapped_tcp` → `tcp=` in
    /// the published record. Default off. Non-reloadable.
    pub upnp: crate::daemon::UpnpMode,
    /// `UPnPDiscoverWait`. SSDP M-SEARCH wait. Default 5s.
    pub upnp_discover_wait: u32,
    /// `UPnPRefreshPeriod`. Re-add the mapping every N seconds;
    /// lease is 2×N so a missed refresh doesn't expire it. Default 60.
    pub upnp_refresh_period: u32,

    /// `DhtSecretFile` (Rust extension). 32 bytes mixed into the
    /// BEP 44 salt+AEAD-key derive. With it, a reader needs
    /// `hosts/NAME` *and* this secret to find/decrypt the record;
    /// without it, `hosts/NAME` alone suffices (still hidden from DHT
    /// crawlers, who have neither). `None` = unset. Non-reloadable.
    ///
    /// File-only by design: an inline `DhtSecret = …` in `tinc.conf`
    /// would land in world-readable config dumps, `tinc info`
    /// output, and (on the NixOS module) the Nix store. Same
    /// rationale as `Ed25519PrivateKeyFile` having no inline form.
    pub dht_secret: Option<[u8; 32]>,

    /// `DhtBootstrap` (Rust extension). `host:port` seeds. Empty ⇒
    /// mainline's defaults. Replace, not augment: BEP 42 has no quorum
    /// threshold, so a single attacker-controlled bootstrap that wins
    /// the routing-table population race also fakes the port-probe echo
    /// (⇒ fakes the published `v4=`). NOT SAFE for invitations.
    pub dht_bootstrap: Vec<String>,
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
            sptps_cipher: tinc_sptps::SptpsAead::default(),
            global_weight: None,
            sptps_kex: tinc_sptps::SptpsKex::default(),
            device_standby: false,
            dht_discovery: false,
            dht_secret: None,
            upnp: crate::daemon::UpnpMode::No,
            upnp_discover_wait: 5,
            upnp_refresh_period: 60,
            dht_bootstrap: Vec::new(),
        }
    }
}

/// Parse the reloadable subset of settings from `config`. Called
/// from `setup()` AND `reload_configuration()`. Non-reloadable
/// settings (Port, `AddressFamily`, `DeviceType`) are NOT here - they
/// need re-bind / re-open which `setup()` does inline.
pub(crate) fn apply_reloadable_settings(config: &tinc_conf::Config, settings: &mut DaemonSettings) {
    cfg_int!(config, "PingInterval", u32, |v| if v >= 1 {
        settings.pinginterval = v.min(MAX_DURATION_SECS);
    });
    // Clamped to [1, pinginterval].
    cfg_int!(config, "PingTimeout", u32, |v| {
        settings.pingtimeout = v.clamp(1, settings.pinginterval);
    });
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
                    crate::keys::warn_aes_no_hw_once();
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
    // tunnelserver implies strictsubnets. Applied after BOTH parsed.
    settings.strictsubnets |= settings.tunnelserver;
    cfg_bool!(config, "LocalDiscovery" => settings.local_discovery);
    cfg_bool!(config, "DirectOnly" => settings.directonly);
    cfg_bool!(config, "PriorityInheritance" => settings.priorityinheritance);
    cfg_bool!(config, "AutoConnect" => settings.autoconnect);
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
/// `AddressFamily`, Mode, sockopts, Proxy, Compression, Forwarding,
/// DHT, `DeviceStandby`) need re-bind / re-open and are setup-only.
pub(super) fn load_settings(
    config: &tinc_conf::Config,
    confbase: &Path,
) -> Result<DaemonSettings, SetupError> {
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

    // Compression. HOST-tagged. The level WE want peers to
    // compress towards us at. Reject LZO (stubbed) and >12.
    if let Some(e) = config.lookup("Compression").next()
        && let Some(v) = get_int(e)
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
    cfg_bool!(config, "DeviceStandby" => settings.device_standby);

    // SPTPSKex. Non-reloadable. Unknown values are a hard error,
    // not a silent default — a typo here would silently strip the PQ
    // leg the operator asked for.
    settings.sptps_kex = read_sptps_kex(config, tinc_sptps::SptpsKex::default()).map_err(|v| {
        SetupError::Config(format!("SPTPSKex = {v}: expected x25519|x25519-mlkem768"))
    })?;

    // Rust extension. Non-reloadable.
    cfg_bool!(config, "DhtDiscovery" => settings.dht_discovery);
    // UPnP. Non-reloadable (thread spawned once at setup).
    if let Some(e) = config.lookup("UPnP").next() {
        match crate::daemon::UpnpMode::from_config(e.get_str()) {
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

    // DhtSecretFile. Read happens here in `setup()` *before*
    // `drop_privs` so a root:root 0600 file is reachable. No inline
    // form: a key in tinc.conf would leak via config dumps / the Nix
    // store. The file-missing case is fatal (don't silently publish
    // under a different key than the rest of the mesh).
    settings.dht_secret = match config.lookup("DhtSecretFile").next() {
        Some(e) => Some(read_dht_secret_file(e.get_str(), confbase)?),
        None => None,
    };

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

/// b64-decode the `DhtSecretFile` line form. Standard alphabet,
/// padding optional, must decode to exactly 32 bytes. Standard b64
/// (NOT `tinc_crypto::b64`): this is operator-facing, generated with
/// `openssl rand -base64 32`, not tinc's wire-compat bit-reversed
/// variant.
fn decode_dht_secret_b64(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    // Accept with or without `=` padding — `openssl rand -base64 32`
    // emits one trailing `=`, copy-paste shouldn't be a footgun.
    let s = s.trim().trim_end_matches('=');
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .map_err(|e| format!("DhtSecret: not valid base64: {e}"))?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| format!("DhtSecret: decoded to {} bytes, need 32", raw.len()))
}

/// Read `DhtSecretFile`. Relative paths resolve against `confbase`
/// (same rule as `Ed25519PrivateKeyFile`). Accepts either raw 32
/// bytes or one line of base64 decoding to 32 bytes — raw checked
/// first so a 32-byte blob that *happens* to be valid b64 isn't
/// mis-decoded to 24. Missing file / wrong length is fatal: silently
/// publishing under a different key than the rest of the mesh would
/// be a quiet partition.
///
/// # Errors
/// [`SetupError::Config`] on missing/unreadable file, non-UTF-8
/// non-32-byte content, or b64 that doesn't decode to 32 bytes.
pub fn read_dht_secret_file(path: &str, confbase: &Path) -> Result<[u8; 32], SetupError> {
    let p = Path::new(path);
    let p = if p.is_absolute() {
        p.to_path_buf()
    } else {
        confbase.join(p)
    };
    let raw = std::fs::read(&p)
        .map_err(|e| SetupError::Config(format!("DhtSecretFile {}: {e}", p.display())))?;
    if let Ok(a) = <[u8; 32]>::try_from(raw.as_slice()) {
        return Ok(a);
    }
    let s = std::str::from_utf8(&raw)
        .map_err(|_| SetupError::Config(format!("DhtSecretFile {}: not 32 bytes", p.display())))?;
    decode_dht_secret_b64(s)
        .map_err(|e| SetupError::Config(format!("DhtSecretFile {}: {e}", p.display())))
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
    fn dht_secret_b64_cases() {
        use base64::Engine;
        let want = [0x42u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(want);
        // Padding + surrounding whitespace tolerated (openssl emits both).
        assert_eq!(decode_dht_secret_b64(&format!("  {b64}\n")).unwrap(), want);
        // Wrong length.
        assert!(
            decode_dht_secret_b64("QUJDRA")
                .unwrap_err()
                .contains("4 bytes")
        );
        // Not b64.
        assert!(decode_dht_secret_b64("!!!").is_err());
    }

    use crate::testutil::tmpdir;

    #[test]
    fn dht_secret_file_cases() {
        use base64::Engine;
        let dir = tmpdir("dhtsecret");
        let want = [7u8; 32];

        // Raw 32 bytes.
        std::fs::write(dir.join("raw"), want).unwrap();
        assert_eq!(read_dht_secret_file("raw", &dir).unwrap(), want);

        // b64 line with trailing newline.
        let b64 = base64::engine::general_purpose::STANDARD.encode(want);
        std::fs::write(dir.join("b64"), format!("{b64}\n")).unwrap();
        assert_eq!(read_dht_secret_file("b64", &dir).unwrap(), want);

        // Absolute path.
        let abs = dir.join("raw");
        assert_eq!(
            read_dht_secret_file(abs.to_str().unwrap(), Path::new("/nonexistent")).unwrap(),
            want
        );

        // Wrong length → error, not silent zero-key.
        std::fs::write(dir.join("short"), [0u8; 16]).unwrap();
        assert!(read_dht_secret_file("short", &dir).is_err());

        // Missing file.
        assert!(read_dht_secret_file("nope", &dir).is_err());
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

    /// `Compression = 10` (LZO low) is rejected by [`load_settings`]
    /// even though `compress::Level::LzoLo` is fully implemented via
    /// vendored minilzo (both compress and decompress round-trip; see
    /// `compress::tests::lzo_lo_compresses`). The gate predates the
    /// minilzo vendoring and its comment ("LZO stubbed") is stale for
    /// level 10. Only level 11 (`lzo1x_999_compress`) is actually
    /// stubbed. The same stale gate in `gossip/keys.rs` drops a C
    /// peer's `ANS_KEY` when they ask for level 10, so the per-tunnel
    /// SPTPS handshake never completes — interop break with C tinc
    /// configured `Compression = 10`.
    #[test]
    #[ignore = "bug: LzoLo (level 10) works but settings/ANS_KEY gates reject it"]
    fn bug_compression_10_lzo_lo_rejected_despite_working() {
        // Precondition: LzoLo compress is functional (not stubbed).
        let mut comp = compress::Compressor::new();
        let src = vec![0x42u8; 256];
        let out = comp
            .compress(&src, compress::Level::LzoLo)
            .expect("LzoLo compress must work (vendored minilzo)");
        assert_eq!(
            comp.decompress(&out, compress::Level::LzoLo, 256).unwrap(),
            src
        );

        // Bug: load_settings rejects it anyway.
        let dir = tmpdir("compress10");
        let r = load_settings(&cfg(&["Compression = 10"]), &dir);
        assert!(
            r.is_ok(),
            "Compression = 10 should be accepted: LzoLo compress/decompress \
             both work via vendored minilzo; got {r:?}"
        );
    }

    /// `Compression = -1`: `get_int` yields `-1`, `u8::try_from(-1)`
    /// falls back to `255`, and the diagnostic reports the *clamped*
    /// value, not what the operator wrote. The error message lies.
    #[test]
    #[ignore = "bug: negative Compression reported as '255' in error message"]
    fn bug_compression_negative_error_message() {
        let err = load_settings(&cfg(&["Compression = -1"]), Path::new("/nonexistent"))
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

    /// C tinc reads `Forwarding` in `setup_myself_reloadable`
    /// (`net_setup.c:426`), so a SIGHUP picks up `Forwarding = off`.
    /// The Rust port parses it only in `load_settings` (setup-time),
    /// so `apply_reloadable_settings` silently ignores the change.
    #[test]
    #[ignore = "bug: Forwarding not applied on reload; C tinc reloads it"]
    fn bug_forwarding_not_reloadable() {
        let mut s = DaemonSettings::default();
        assert_eq!(s.forwarding_mode, ForwardingMode::Internal);
        apply_reloadable_settings(&cfg(&["Forwarding = off"]), &mut s);
        assert_eq!(
            s.forwarding_mode,
            ForwardingMode::Off,
            "SIGHUP with Forwarding=off should take effect (C tinc parity)"
        );
    }

    /// C tinc: `if(pingtimeout < 1 || pingtimeout > pinginterval)
    /// pingtimeout = pinginterval;` (`net_setup.c:1251`). So
    /// `PingTimeout = 0` becomes `pinginterval` (default 60). Rust
    /// `clamp(1, pinginterval)` yields 1 instead — a 60× tighter
    /// liveness deadline than the C daemon under the same config.
    #[test]
    #[ignore = "bug: PingTimeout=0 clamps to 1; C tinc clamps to pinginterval"]
    fn bug_pingtimeout_zero_divergence() {
        let mut s = DaemonSettings::default();
        apply_reloadable_settings(&cfg(&["PingTimeout = 0"]), &mut s);
        assert_eq!(
            s.pingtimeout, s.pinginterval,
            "C tinc snaps out-of-range PingTimeout to pinginterval, not 1"
        );
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
