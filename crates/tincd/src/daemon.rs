//! `Daemon` — the C globals as one struct, plus `main_loop()`.
//!
//! Ports `net.c::main_loop` (`:487-527`): `Timers::tick →
//! EventLoop::turn → match`. `timeout_handler` (`:180-266`)
//! degenerates to re-arm-self with zero peers. Signal handlers
//! (`:316-334`) set `running = false` for TERM/INT/QUIT.
//! `handle_new_unix_connection` (`net_socket.c:781-812`): accept,
//! allocate, register. `setup_network` (`net_setup.c:1235-1275`):
//! abridged call chain.
//!
//! `IoWhat` is the `W` in `EventLoop<W>` (six variants for six
//! C io callbacks). `run()` consumes `self`: C `main_loop()` runs
//! once, teardown is `Drop`.
//!
//! Logging: `target: "tincd"` for startup/shutdown, `"tincd::conn"`
//! for accept/terminate. See lib.rs for the full mapping.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand_core::OsRng;
use slotmap::{SlotMap, new_key_type};
use tinc_crypto::sign::SigningKey;
use tinc_device::Device;
use tinc_event::{EventLoop, Io, IoId, Ready, SelfPipe, TimerId, Timers};
use tinc_graph::{Graph, NodeId};
use tinc_proto::Request;

use crate::conn::{Connection, FeedResult};
use crate::control::{ControlSocket, generate_cookie, write_pidfile};
use crate::graph_glue::{Transition, run_graph};
use crate::keys::{PrivKeyError, read_ecdsa_private_key};
use crate::listen::{
    AddrFamily, Listener, Tarpit, configure_tcp, fmt_addr, is_local, open_listeners, pidfile_addr,
    unmap,
};
use crate::proto::{
    DispatchError, DispatchResult, IdCtx, IdOk, check_gate, handle_control, handle_id,
    myself_options_default, parse_ack, parse_add_edge, parse_add_subnet, parse_del_edge,
    parse_del_subnet, record_body, send_ack,
};
use crate::seen::SeenRequests;
use crate::subnet_tree::SubnetTree;

// dispatch enums — the W in EventLoop<W> / Timers<W> / SelfPipe<W>

new_key_type! {
    /// `connection_t*`. Generational: a stale `ConnId` for a slot
    /// that's been reused returns `None` from `conns.get(id)`. The
    /// C uses raw pointers and the io_tree.generation guard.
    pub struct ConnId;
}

/// Runtime annotation for one peer node. The (b)-path stub from
/// the chunk-4b plan: `tinc-graph::Node` is name+edges (topology);
/// this is which-conn-serves-it + the edge-metadata `ack_h` builds.
///
/// C `node_t` smushes both into one 200-byte struct. Splitting
/// means `tinc-graph` stays `#![no_std]`-compatible (no fd, no
/// `Instant`, no `SocketAddr` in the graph crate).
///
/// Chunk 5 cross-refs this to a `tinc_graph::NodeId` once the graph
/// is wired. For now: `ack_h` populates it, `dump_connections`
/// doesn't even read it (it walks `conns` not `nodes`). The dup-
/// conn check (`ack_h:975-990`) is the one consumer.
#[derive(Debug, Clone)]
pub struct NodeState {
    /// `n->connection`. Which meta connection currently serves this
    /// node. `None` if the node is known but not directly connected
    /// (transitively reachable, or just disconnected). Generational
    /// `ConnId`: a stale one returns `None` from `conns.get`.
    pub conn: Option<ConnId>,
    /// `c->edge->address`. Peer's TCP-connect-from addr with port
    /// rewritten to their UDP port (`ack_h:1024-1025`). The "how do
    /// I send data packets" addr. `None` only for hypothetical
    /// unix-socket peers (doesn't happen — peers come over TCP).
    pub edge_addr: Option<SocketAddr>,
    /// `c->edge->weight`. Average of our RTT estimate and theirs
    /// (`ack_h:1048`). Milliseconds.
    pub edge_weight: i32,
    /// `c->edge->options`. Intersected/unioned bitfield (`ack_h:
    /// 996-1001`). Top byte is the PEER's `PROT_MINOR`.
    pub edge_options: u32,
}

/// `IoWhat` — the daemon's choice of `W` for `EventLoop<W>`.
///
/// Six variants for six C `io_add` callbacks. The match body in
/// `Daemon::run` IS the dispatch table.
///
/// `Tcp`/`Udp` are stubs — variants exist (the enum is closed), the
/// match arms are `todo!()` until chunk 3. Gives the full enum shape
/// up front; `Daemon::run`'s match doesn't churn when listeners land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoWhat {
    /// `signalio_handler`. The self-pipe read end.
    Signal,
    /// `handle_new_unix_connection`. The control socket listener.
    UnixListener,
    /// `handle_device_data`. The TUN/TAP device. `Dummy` has
    /// `fd() → None` so this is never registered in skeleton.
    Device,
    /// `handle_meta_io`. A meta connection (control or peer).
    /// The ConnId indexes the slotmap.
    Conn(ConnId),
    /// `handle_new_meta_connection`. TCP listener `i`. Index into
    /// `listen_socket[MAXSOCKETS]`. u8 because MAXSOCKETS=16.
    Tcp(u8),
    /// `handle_incoming_vpn_data`. UDP listener `i`. Same indexing.
    Udp(u8),
}

/// Seven variants for seven C `timeout_add` callbacks. Skeleton has
/// one: `Ping`. Same up-front-shape rationale as `IoWhat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerWhat {
    /// `timeout_handler` (`net.c:180`). Ping timeout sweep. Re-arms +1s.
    Ping,
    /// `periodic_handler` (`net.c:268`). Contradiction counter check.
    /// Re-arms +5s. NOT in skeleton (no peers, no edges, no
    /// contradictions). Variant exists, arm is `todo!()`.
    #[allow(dead_code)]
    Periodic,
    /// `keyexpire_handler`. Re-arms `+keylifetime`.
    #[allow(dead_code)]
    KeyExpire,
    /// `age_past_requests` (`protocol.c:213-228`). Evicts seen-
    /// request cache entries older than `pinginterval`. Re-arms
    /// +10s (`:228`). Chunk 5: ARMED.
    AgePastRequests,
    /// `age_subnets`. Re-arms +10s.
    #[allow(dead_code)]
    AgeSubnets,
    /// `retry_outgoing_handler`. Per-outgoing. The `OutgoingId` is a
    /// future slotmap key (chunk 3+).
    #[allow(dead_code)]
    RetryOutgoing,
    /// `udp_probe_timeout_handler`. Per-node.
    #[allow(dead_code)]
    UdpPing,
}

/// Three variants for the signals. C registers 5 (`net.c:503-507`)
/// but TERM/QUIT/INT all map to `Exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalWhat {
    /// SIGHUP. `sighup_handler`: reopenlogger + reload_configuration.
    /// Skeleton: log and ignore.
    Reload,
    /// SIGTERM, SIGINT, SIGQUIT. `sigterm_handler`: `event_exit()`.
    Exit,
    /// SIGALRM. `sigalrm_handler`: `retry()`. Skeleton: ignore.
    Retry,
}

// DaemonSettings — the config knobs

/// The ~40 daemon-side settings globals from the census. Populated
/// by `setup_myself_reloadable` (`net_setup.c:252-575`). Skeleton
/// reads only `pinginterval`/`pingtimeout` and even those are
/// defaulted.
///
/// Separate from `Daemon` so reload can swap a fresh `DaemonSettings`
/// in without touching the arena. C `reload_configuration` walks and
/// patches; we'll do the same for the arena, but the SETTINGS are
/// just a struct swap.
///
/// `Default` matches C defaults. Each field documents its
/// `net_setup.c` source.
#[derive(Debug, Clone)]
pub struct DaemonSettings {
    /// `pinginterval`. C default 60 (`net_setup.c:1243`). Seconds
    /// between pings.
    pub pinginterval: u32,
    /// `pingtimeout`. C default 5 (`net_setup.c:1247-1248`). Seconds
    /// to wait for PONG before assuming peer dead. Clamped to
    /// `[1, pinginterval]` (`:1251-1253`).
    pub pingtimeout: u32,
    /// `myport.tcp` (`net_setup.c:788`). The Port config (HOST-tagged,
    /// from `hosts/NAME` not tinc.conf). C stores as a STRING (it goes
    /// through getaddrinfo which wants a service name); we convert to
    /// u16 here. Default 655 (`:789`). 0 means "kernel picks" — valid
    /// for tests; the actual port is read back from `listeners[0]`.
    pub port: u16,
    /// `addressfamily` (`net_socket.c:38`, set at `net_setup.c:538`).
    /// Filters which families `open_listeners` tries. Default
    /// `Any` (`AF_UNSPEC`) means dual-stack.
    pub addressfamily: AddrFamily,
    // Chunk 4+: ~33 more fields.
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            // C `net_setup.c:1243`: `else { pinginterval = 60; }`.
            pinginterval: 60,
            // C `net_setup.c:1248`: `pingtimeout = 5`.
            pingtimeout: 5,
            // C `net_setup.c:789`: `myport.tcp = xstrdup("655")`.
            port: 655,
            // C `net_socket.c:38`: `int addressfamily = AF_UNSPEC`.
            addressfamily: AddrFamily::Any,
        }
    }
}

// Daemon — the C globals + the loop

/// What `run()` returns. C `main_loop` returns `int` (0 or 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// `event_loop()` returned cleanly (`running` set false by a
    /// handler). C `main_loop` returns 0.
    Clean,
    /// `event_loop()` returned an error. C `main_loop` returns 1.
    PollError,
}

/// The daemon. C globals as fields; `run()` is `main_loop()`.
///
/// Why fields are `pub(crate)` not `pub`: the loop body matches on
/// `IoWhat` and reaches into ALL the fields. There's no encapsulation
/// to defend — the loop IS the daemon. Same as the C: every handler
/// can reach every global. The Rust gain is `&mut self` exclusivity
/// (no two handlers run concurrently — but they couldn't in the C
/// either, single-threaded loop. The gain is the COMPILER knows.).
pub struct Daemon {
    // ─── arena
    /// `connection_list`. Slotmap not `Vec<Option>` — generational
    /// keys. A `ConnId` from a closed connection is a different key
    /// than the next connection allocated in the same slot. The C's
    /// generation guard becomes `conns.get(stale_id) → None`.
    pub(crate) conns: SlotMap<ConnId, Connection>,

    /// Per-connection event-loop handle. `connection_t.io` in C.
    /// Parallel map because `Connection` doesn't know about
    /// `tinc-event` (layering). `IoId` is the EventLoop's slot
    /// index.
    ///
    /// (Could be a field on `Connection`. The argument for parallel
    /// map: `Connection` is testable without `EventLoop`; `conn.rs`
    /// tests don't construct one. The argument against: two-map
    /// coherence (every insert/remove touches both). For now: two
    /// maps, asserts on coherence in debug. Revisit if it bites.)
    pub(crate) conn_io: slotmap::SecondaryMap<ConnId, IoId>,

    // ─── substrate
    /// `devops` + `device_fd` + `iface`. The TUN/TAP. `Box<dyn>` —
    /// the variant (`Dummy`/`Tun`/`Fd`/`Raw`/`Bsd`) is chosen at
    /// setup time by the `DeviceType` config knob.
    ///
    /// `dead_code` allowed: skeleton never reads `device` (Dummy has
    /// `fd() → None`, never registered, `IoWhat::Device` never fires).
    /// But: KEEPING it in the struct keeps it ALIVE. For Tun/Fd/Raw,
    /// dropping the Device closes the fd. The struct field IS the
    /// usage. Chunk 3's `IoWhat::Device` arm reads it.
    #[allow(dead_code)]
    pub(crate) device: Box<dyn Device>,

    /// `unix_socket` (`control.c:29`). The control listener.
    pub(crate) control: ControlSocket,

    /// `listen_socket[MAXSOCKETS]` (`net_socket.c:48`). TCP+UDP
    /// pairs. `IoWhat::Tcp(i)` indexes here. Max 8 (we only fill 2
    /// in chunk 3: one v4, one v6).
    ///
    /// `Vec` not array because `Listener` doesn't impl `Default`
    /// (sockets aren't defaultable). The C uses `static listen_
    /// socket_t[8]` zero-init; we just push.
    pub(crate) listeners: Vec<Listener>,

    /// `check_tarpit` statics + `tarpit()` ring buffer. Seven C
    /// statics packed into one struct. Mutated on every TCP accept.
    pub(crate) tarpit: Tarpit,

    /// `controlcookie` (`control.c:35`). 64 hex chars. Compared in
    /// `handle_id`.
    pub(crate) cookie: String,

    /// `pidfilename`. Kept so `Drop` can unlink (`control.c:240`).
    pub(crate) pidfile: PathBuf,

    /// `myname` (`names.h:30`). Our node name from `tinc.conf:Name`.
    /// Appears in the `send_id` greeting and in dump output.
    pub(crate) name: String,

    /// `myself->connection->ecdsa` (`net_setup.c:803`). Our Ed25519
    /// private key. Loaded once at startup from `confbase/ed25519_
    /// key.priv` (or `Ed25519PrivateKeyFile`). Used for SPTPS auth:
    /// every peer handshake clones this via `to_blob`/`from_blob`
    /// (`SigningKey` deliberately isn't `Clone` — the roundtrip
    /// makes copies VISIBLE). Never reloaded (a key change is a
    /// daemon restart, not a SIGHUP — the C is the same).
    pub(crate) mykey: SigningKey,

    /// `confbase`. Kept so `id_h` peer-branch can resolve `hosts/
    /// NAME` paths. The C has it as a global (`names.c:24`); we
    /// thread it through `IdCtx`. Stored once here, borrowed into
    /// each `IdCtx`.
    pub(crate) confbase: PathBuf,

    /// `myself->options`. Bitfield (`connection.h:32-36` + PROT_MINOR
    /// in top byte). C builds in `setup_myself_reloadable` (`net_
    /// setup.c:383-453,800`). Chunk 4b: defaults only. Chunk 9
    /// reads `IndirectData`/`TCPOnly`/`PMTUDiscovery`/`ClampMSS`.
    pub(crate) myself_options: u32,

    /// `myport.udp`. C string (`net_setup.c:54,794`); we store the
    /// resolved u16. Read back from `listeners[0].udp_port()` after
    /// bind (the C does the same at `:1194` `get_bound_port`). With
    /// `Port = 0` (tests), TCP and UDP get DIFFERENT kernel-assigned
    /// ports until `bind_reusing_port` (chunk 10) lands. The ACK
    /// packet needs the UDP one specifically.
    pub(crate) my_udp_port: u16,

    /// `node_tree` topology half. Nodes + directed edges. What
    /// `sssp`/`mst` walk. The C `node_t` smushes topology AND
    /// runtime annotation (200-byte struct); we split — see
    /// `NodeState` doc.
    ///
    /// `myself` is added at setup (`net_setup.c:783`). Transitively-
    /// known nodes are added by `lookup_or_add_node` from ADD_EDGE/
    /// ADD_SUBNET handlers. The graph crate has no name→id reverse
    /// lookup — that's `node_ids` below.
    pub(crate) graph: Graph,

    /// name → `NodeId`. The reverse lookup `tinc-graph` doesn't
    /// have. C `lookup_node(name)` is a splay search on `node_tree`
    /// keyed by `strcmp(name)`; this IS that. Populated alongside
    /// `graph.add_node()` in `lookup_or_add_node`.
    ///
    /// Invariant: every entry's `NodeId` is a live slot in `graph`.
    /// Chunk 5 never deletes nodes (the C only does on `purge`);
    /// when del lands, it removes from here too.
    pub(crate) node_ids: HashMap<String, NodeId>,

    /// `myself` (`net_setup.c:783`: `myself = new_node()`). Our own
    /// `NodeId` in `graph`. The `from == myself` checks in the edge/
    /// subnet handlers (`protocol_edge.c:183`, `protocol_subnet.c:
    /// 98`) compare against this.
    pub(crate) myself: NodeId,

    /// `subnet_tree` (`subnet.c:32`). The routing table. ADD_SUBNET
    /// inserts, DEL_SUBNET removes, `route_ipv4` (chunk 7) reads.
    /// `dump subnets` walks.
    pub(crate) subnets: SubnetTree,

    /// `past_request_tree` (`protocol.c:89`). Anti-loop dedup for
    /// flooded ADD/DEL messages. Handlers call `seen.check(body)`
    /// before processing; `true` → dup, drop silently.
    /// `AgePastRequests` timer evicts old entries.
    pub(crate) seen: SeenRequests,

    /// Chunk-4b's runtime annotation. KEPT — graph topology vs
    /// runtime state are different things. `tinc-graph::Node` is
    /// name + edges; this is which-conn-serves-it + the edge
    /// metadata `ack_h` builds (the address, which `tinc-graph::
    /// Edge` doesn't carry).
    ///
    /// Only DIRECTLY-connected peers get a `NodeState` (via
    /// `on_ack`). Transitively-known nodes (learned from forwarded
    /// ADD_EDGE) are graph-only — no `NodeState`. C `node_t` doesn't
    /// distinguish (it's one struct for both); we make the split
    /// explicit. The dup-conn check (`ack_h:975-990`) is the one
    /// consumer of `conn`.
    pub(crate) nodes: HashMap<String, NodeState>,

    // ─── settings
    /// The config knobs. Reload swaps this.
    ///
    /// `dead_code` allowed: skeleton constructs but never reads (the
    /// `pinginterval`/`pingtimeout` defaults are inlined at the one
    /// use site). Chunk 3's `setup_myself_reloadable` populates it
    /// from config and the ping sweep reads it. Keeping the field
    /// avoids churn (remove now, re-add then). Same call as the
    /// `TimerWhat::Periodic` etc variants.
    #[allow(dead_code)]
    pub(crate) settings: DaemonSettings,

    // ─── event loop machinery
    /// `mio::Poll` + slot table. Generic over `IoWhat`.
    pub(crate) ev: EventLoop<IoWhat>,
    /// Timer wheel. Generic over `TimerWhat`.
    pub(crate) timers: Timers<TimerWhat>,
    /// Self-pipe + handler table. Generic over `SignalWhat`.
    pub(crate) signals: SelfPipe<SignalWhat>,
    /// `pingtimer` (`net.c:44`). Kept so the match arm can re-arm.
    pub(crate) pingtimer: TimerId,
    /// `past_request_timeout` (`protocol.c:92`). Re-arms +10s.
    pub(crate) age_timer: TimerId,

    /// `running` (`event.c:18`). The loop condition. C `event_exit()`
    /// sets `running = false`; `event_loop()` checks before each
    /// iteration. Same here.
    pub(crate) running: bool,
}

impl Daemon {
    /// `setup_network` (`net_setup.c:1235-1275`) + `init_control` +
    /// the parts of `setup_myself` we need (`net_setup.c:770-1100`).
    /// Heavily abridged: no listen sockets, no graph, no node tree.
    ///
    /// `confbase` is the `-c` argument (or `CONFDIR/tinc[/NETNAME]`
    /// resolved by main.rs). `pidfile`/`socket` are the runtime paths.
    ///
    /// Reads `tinc.conf` for `Name` and `DeviceType`. Everything
    /// else is defaulted.
    ///
    /// # Errors
    /// Startup failures: tinc.conf missing/malformed, no `Name`,
    /// device open failed, pidfile write failed (permissions),
    /// socket bind failed (already running).
    ///
    /// # Panics
    /// `SelfPipe::new` panics if a SelfPipe already exists in this
    /// process (it's a singleton — see tinc-event/sig.rs). Can't
    /// happen here: setup is called once. Tests that call setup
    /// twice in one process are wrong; integration tests use
    /// subprocess.
    #[allow(clippy::too_many_lines)] // setup_myself is one long
    // sequence in C too. Splitting it scatters the boot order.
    pub fn setup(confbase: &Path, pidfile: &Path, socket: &Path) -> Result<Self, SetupError> {
        // ─── read tinc.conf (tincd.c:590)
        let config = tinc_conf::read_server_config(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;

        // ─── Name (net_setup.c:775-779)
        // C: `name = get_name(); if(!name) { ERR }`.
        // `get_name()` does `lookup_config("Name")` + `check_id`.
        // Skeleton: just lookup. `check_id` (alphanumeric + `_`)
        // is the right validation but tinc-tools/names.rs has it,
        // not tinc-conf — and we don't dep on tinc-tools. Chunk 3+
        // hoists `check_id` to a shared place (probably tinc-proto;
        // it's wire-format-adjacent).
        let name = config
            .lookup("Name")
            .next()
            .map(|e| e.get_str().to_owned())
            .ok_or(SetupError::Config("Name for tinc daemon required!".into()))?;
        log::info!(target: "tincd", "tincd starting, name={name}");

        // ─── read_host_config (net_setup.c:786)
        // C: `read_host_config(&config_tree, name, true)`. Merges
        // hosts/NAME into the same tree as tinc.conf. The HOST-tagged
        // vars (Port, Subnet, PublicKey, etc) live there.
        //
        // C DOESN'T check the return value (`:786` is a bare call).
        // Missing hosts/NAME is not fatal at this stage; the only
        // var we read from it is Port, which has a default. The hard
        // failures (no key, no subnets) come later. We match: log
        // and continue. The daemon starts on port 655.
        //
        // Per tinc-conf/parse.rs:523: read_host_config is intentionally
        // not a function. It's two lines.
        let mut config = config;
        let host_file = confbase.join("hosts").join(&name);
        match tinc_conf::parse_file(&host_file) {
            Ok(entries) => config.merge(entries),
            Err(e) => {
                // C `read_config_file` would `fopen` fail and return
                // false. The caller ignores. Warn-level because it
                // MIGHT be intentional (a freshly-init'd daemon has
                // no hosts/ yet) but more likely is a typo in Name.
                log::warn!(target: "tincd",
                           "hosts/{name} not read: {e}; using defaults");
            }
        }

        // ─── read_ecdsa_private_key (net_setup.c:803-828)
        // C: `myself->connection->ecdsa = read_ecdsa_private_key(
        // &config_tree, NULL); experimental = ecdsa != NULL;`.
        //
        // The C has THREE attempts at `:803/814/822` interleaved with
        // `disable_old_keys` (a `tinc init` migration helper that
        // detects old-format keys and asks to convert). We forbid
        // legacy — the migration is meaningless. One attempt.
        //
        // Missing key is FATAL for us. C falls back to `myself->
        // connection->legacy = init_legacy_ctx(read_rsa_private_key
        // (...))` at `:831-842`. We don't. The error message includes
        // the gen-keys hint (C `keys.c:123-125`) so the user knows
        // what to do.
        let mykey = read_ecdsa_private_key(&config, confbase).map_err(|e| {
            // C `:123-125` prints the hint at INFO. We embed it in
            // the error — setup() callers (main.rs) print the error
            // to stderr and exit, so it's visible.
            let hint = if matches!(e, PrivKeyError::Missing(_)) {
                "\n  (Create a key pair with `tinc generate-ed25519-keys`)"
            } else {
                ""
            };
            SetupError::Config(format!("{e}{hint}"))
        })?;

        // ─── settings (net_setup.c:788, 538, 1239-1257)
        let mut settings = DaemonSettings::default();

        // Port (`:788-794`). HOST-tagged. C stores as a string
        // (goes through getaddrinfo); we parse to u16 here.
        // `Port = 0` is valid: kernel picks (tests use this).
        // Non-numeric Port (`:846-858`: service name resolution
        // via `service_to_port`): deferred. Reject for now.
        if let Some(e) = config.lookup("Port").next() {
            settings.port = e.get_str().parse().map_err(|_| {
                SetupError::Config(format!("Port = {} is not a valid port number", e.get_str()))
            })?;
        }

        // AddressFamily (`:538-548`). SERVER-tagged (in tinc.conf).
        // C silently ignores unknown values (no `else { ERR }`);
        // `addressfamily` stays at default. We match.
        if let Some(e) = config.lookup("AddressFamily").next() {
            if let Some(af) = AddrFamily::from_config(e.get_str()) {
                settings.addressfamily = af;
            } else {
                log::warn!(target: "tincd",
                           "Unknown AddressFamily = {}, using default",
                           e.get_str());
            }
        }

        // PingTimeout (`:1247-1253`). For tests: `PingTimeout = 1`
        // makes the 6-second integration test run in 2 seconds. Read
        // it now; the clamp (`:1251`: `[1, pinginterval]`) too.
        if let Some(e) = config.lookup("PingTimeout").next() {
            if let Ok(v) = e.get_int() {
                // C clamps `< 1 || > pinginterval` → default.
                // Match the clamp; reject negative (get_int returns
                // i32; u32::try_from rejects negative).
                if let Ok(v) = u32::try_from(v) {
                    settings.pingtimeout = v.clamp(1, settings.pinginterval);
                }
            }
        }

        // ─── device (net_setup.c:1061-1100)
        // C: `devops = os_devops; if DeviceType=dummy → dummy_devops;
        // ...; devops.setup()`.
        // We Box<dyn>. Skeleton: `dummy` always; chunk 3 reads the
        // `DeviceType` config and matches.
        let device_type = config
            .lookup("DeviceType")
            .next()
            .map(|e| e.get_str().to_ascii_lowercase());
        let device: Box<dyn Device> = match device_type.as_deref() {
            None | Some("dummy") => Box::new(tinc_device::Dummy),
            // Chunk 3: Some("tun") → Tun::open, Some("fd") → FdTun, etc.
            Some(other) => {
                return Err(SetupError::Config(format!(
                    "DeviceType={other} not supported in skeleton; use dummy"
                )));
            }
        };
        log::info!(target: "tincd",
                   "Device mode: {:?}, interface: {}",
                   device.mode(), device.iface());

        // ─── event loop scaffolding
        // tinc-event constructors. EventLoop::new can fail (epoll_
        // create); the others can't (BTreeMap, pipe).
        let mut ev = EventLoop::new().map_err(SetupError::Io)?;
        let mut timers = Timers::new();
        let mut signals = SelfPipe::new().map_err(SetupError::Io)?;

        // ─── signals (net.c:497-507)
        // C: signal_add for HUP/TERM/QUIT/INT/ALRM. We map TERM/
        // QUIT/INT all to Exit (same handler in C: `sigterm_handler`).
        // HUP → Reload, ALRM → Retry.
        signals
            .add(libc::SIGTERM, SignalWhat::Exit)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGINT, SignalWhat::Exit)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGQUIT, SignalWhat::Exit)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGHUP, SignalWhat::Reload)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGALRM, SignalWhat::Retry)
            .map_err(SetupError::Io)?;

        // Register the self-pipe read end. `signal.c:59`: `io_add(
        // &signalio, signalio_handler, NULL, pipefd[0], IO_READ)`.
        ev.add(signals.read_fd(), Io::Read, IoWhat::Signal)
            .map_err(SetupError::Io)?;

        // ─── device fd (net_setup.c:1100)
        // C: `if(device_fd >= 0) io_add(&device_io, ...)`.
        // Dummy returns None; Tun/Fd/Raw/Bsd return Some(fd).
        if let Some(fd) = device.fd() {
            ev.add(fd, Io::Read, IoWhat::Device)
                .map_err(SetupError::Io)?;
        }

        // ─── ping timer (net.c:489-491)
        // C: `timeout_add(&pingtimer, timeout_handler, ..., {
        // pingtimeout, jitter() })`. Initial fire is `pingtimeout`
        // seconds from now. The HANDLER re-arms at +1s (`net.c:264`
        // `timeout_set(data, &(struct timeval) { 1, jitter() })`).
        //
        // tinc-event's deliberate semantic difference: re-arm is
        // EXPLICIT. The match arm calls `timers.set(pingtimer, ...)`.
        let pingtimer = timers.add(TimerWhat::Ping);
        timers.set(
            pingtimer,
            Duration::from_secs(u64::from(settings.pingtimeout)),
        );

        // ─── age_past_requests timer (protocol.c:228)
        // C: `timeout_set(&past_request_timeout, &(struct timeval)
        // { 10, jitter() })`. Re-arms +10s. The eviction window is
        // `pinginterval` (the cache key TTL); the timer's 10s is
        // just the sweep frequency.
        let age_timer = timers.add(TimerWhat::AgePastRequests);
        timers.set(age_timer, Duration::from_secs(10));

        // ─── listeners (net_setup.c:1152-1183)
        // C: walk BindToAddress configs, then ListenAddress configs,
        // else `add_listen_address(NULL, NULL)` for the no-config
        // default. We only do the no-config default for now.
        //
        // C `:1180`: `if(!listen_sockets) { ERR; return false }`.
        // Hard error. The daemon can't function without at least one
        // listener (peers can't connect; we can't receive UDP).
        let listeners = open_listeners(settings.port, settings.addressfamily);
        // `net_setup.c:1187-1197`: `myport.udp = get_bound_port(
        // listen_socket[0].udp.fd)`. C gates on `!port_specified ||
        // atoi(myport) == 0`; we always read back — simpler, same
        // answer when port ≠ 0 (kernel binds the requested port).
        // `first()` not `[0]`: the empty-check below still wants
        // its own error message.
        let my_udp_port = listeners.first().map_or(0, Listener::udp_port);
        if listeners.is_empty() {
            return Err(SetupError::Config(
                "Unable to create any listening socket!".into(),
            ));
        }
        // Register each pair. C `:723-724`: `io_add(&sock->tcp, ...)`.
        // The index `i` becomes `IoWhat::Tcp(i)` so the dispatch arm
        // can index back into `listeners[i]` for the accept.
        for (i, l) in listeners.iter().enumerate() {
            let (tcp_fd, udp_fd) = l.fds();
            // u8 cast: MAXSOCKETS=8 fits trivially. The C uses int.
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u8;
            ev.add(tcp_fd, Io::Read, IoWhat::Tcp(i))
                .map_err(SetupError::Io)?;
            ev.add(udp_fd, Io::Read, IoWhat::Udp(i))
                .map_err(SetupError::Io)?;
        }

        // ─── init_control (net_setup.c:1263, control.c:148-231)
        let cookie = generate_cookie();

        // C `control.c:155-176`: get listeners[0]'s bound addr, map
        // 0.0.0.0→127.0.0.1, format `"HOST port PORT"`. The CLI on
        // Windows (no unix socket) actually CONNECTS to this addr.
        // On Unix the CLI uses the unix socket and ignores the addr,
        // but the pidfile format is fixed.
        let address = pidfile_addr(&listeners);
        write_pidfile(pidfile, &cookie, &address).map_err(SetupError::Io)?;

        let control = ControlSocket::bind(socket).map_err(|e| match e {
            crate::control::BindError::AlreadyRunning => SetupError::Config(format!(
                "Control socket {} already in use",
                socket.display()
            )),
            crate::control::BindError::Io(err) => SetupError::Io(err),
        })?;
        ev.add(control.fd(), Io::Read, IoWhat::UnixListener)
            .map_err(SetupError::Io)?;

        // ─── graph: add myself (net_setup.c:783)
        // C: `myself = new_node(name)`. The C `xzalloc` zeroes
        // `n->status.reachable`; `:1050` then sets `reachable =
        // true`. `Graph::add_node` defaults `reachable = true`
        // (steady state) so we get the same one-step.
        //
        // `node_ids` insert: the name→id reverse map. C `node_add`
        // (`node.c:96`) inserts into `node_tree` keyed on name; the
        // splay search IS the lookup. Our HashMap IS that.
        let mut graph = Graph::new();
        let myself = graph.add_node(&name);
        let mut node_ids = HashMap::new();
        node_ids.insert(name.clone(), myself);

        log::info!(target: "tincd", "Ready");

        Ok(Self {
            conns: SlotMap::with_key(),
            conn_io: slotmap::SecondaryMap::new(),
            device,
            control,
            listeners,
            // Tarpit::new wants a now seed (avoids the C's `static
            // time_t = 0` first-tick bug). Use the cached now.
            tarpit: Tarpit::new(timers.now()),
            cookie,
            pidfile: pidfile.to_path_buf(),
            name,
            mykey,
            confbase: confbase.to_path_buf(),
            myself_options: myself_options_default(),
            my_udp_port,
            graph,
            node_ids,
            myself,
            subnets: SubnetTree::new(),
            seen: SeenRequests::new(),
            nodes: HashMap::new(),
            settings,
            ev,
            timers,
            signals,
            pingtimer,
            age_timer,
            running: true,
        })
    }

    /// `main_loop()` (`net.c:487-527`) — the `while(running)` loop.
    /// `tinc-event` deliberately doesn't have this; `turn()` is one
    /// iteration. THIS is the stitch.
    ///
    /// Consumes `self` — the loop runs once, then teardown is `Drop`.
    ///
    /// Loop structure (per the C `event_loop` at `linux/event.c:111-
    /// 160` and the timer interleave at `event.c:112-130`):
    ///
    /// ```text
    /// while running:
    ///     timeout = timers.tick(fired_timers)      ─ C timeout_execute
    ///     for t in fired_timers: dispatch_timer(t) ─ C cb call
    ///     ev.turn(timeout, fired_io)               ─ C epoll_wait
    ///     for (w, ready) in fired_io: dispatch_io  ─ C cb call
    /// ```
    ///
    /// The C does timers FIRST (pingtimer might close a connection;
    /// that connection then doesn't show up as readable). We match.
    /// The "fire timers, THEN compute timeout" is the C `timeout_
    /// execute` order: `event.c:112` calls cbs, `event.c:130` returns
    /// the next deadline.
    ///
    /// PROVES C-is-WRONG #5 fixed: skeleton arms exactly one timer
    /// (Ping). After it fires and re-arms, `tick()` returns
    /// `Some(1s)`. If we DIDN'T re-arm (or the timer was del'd),
    /// `tick()` returns `None` → `turn(None)` blocks forever.
    /// C `linux/event.c:121` would `tv->tv_sec * 1000` on a NULL.
    ///
    /// Clippy `too_many_lines` allowed: the dispatch is one big
    /// match. Splitting it into helpers means passing `&mut self`
    /// to each helper, which means the helper can't borrow two
    /// fields at once. The C is one big function for the same
    /// reason (the cbs all reach the globals).
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn run(mut self) -> RunOutcome {
        // Reusable buffers. `tick`/`turn`/`drain` clear these
        // before pushing.
        let mut fired_timers = Vec::with_capacity(8);
        let mut fired_io = Vec::with_capacity(tinc_event::MAX_EVENTS_PER_TURN);
        let mut fired_signals = Vec::with_capacity(4);

        // C `linux/event.c:115`: `while(running)`.
        while self.running {
            // ─── timers (event.c:112-130)
            // tick() does: cache `now`, drain expired, return next
            // deadline. The C does the SAME order (`timeout_execute`
            // at `event.c:112` is called from `event_loop` BEFORE
            // `epoll_wait`).
            let timeout = self.timers.tick(&mut fired_timers);
            for &t in &fired_timers {
                match t {
                    TimerWhat::Ping => self.on_ping_tick(),
                    TimerWhat::AgePastRequests => self.on_age_past_requests(),
                    TimerWhat::Periodic
                    | TimerWhat::KeyExpire
                    | TimerWhat::AgeSubnets
                    | TimerWhat::RetryOutgoing
                    | TimerWhat::UdpPing => {
                        // Not armed in skeleton. Unreachable.
                        unreachable!("timer {t:?} not armed in skeleton")
                    }
                }
            }

            // ─── poll (linux/event.c:121-130)
            // C: `epoll_wait(fd, events, MAX_EVENTS, timeout_ms)`.
            // mio same. `timeout = None` → block forever (C-is-WRONG
            // #5: C derefs NULL here. mio handles None.).
            if let Err(e) = self.ev.turn(timeout, &mut fired_io) {
                // C `net.c:511`: log ERR, return 1.
                log::error!(target: "tincd",
                            "Error while waiting for input: {e}");
                return RunOutcome::PollError;
            }

            // ─── io dispatch (linux/event.c:131-159)
            for &(what, ready) in &fired_io {
                match what {
                    IoWhat::Signal => {
                        // `signalio_handler` (`signal.c:41-55`).
                        // drain reads ALL pending bytes (signals
                        // coalesce in the pipe).
                        self.signals.drain(&mut fired_signals);
                        for &s in &fired_signals {
                            self.on_signal(s);
                        }
                        fired_signals.clear();
                    }

                    IoWhat::UnixListener => {
                        // `handle_new_unix_connection`.
                        self.on_unix_accept();
                    }

                    IoWhat::Conn(id) => {
                        // `handle_meta_io`. The connection might
                        // have been terminated by an EARLIER event
                        // in this same batch (e.g., pingtimer closed
                        // it). slotmap returns None for stale keys —
                        // this is the generation guard.
                        if !self.conns.contains_key(id) {
                            continue;
                        }
                        // `net_socket.c:556-561`: write before read.
                        // tinc-event already orders WRITE-before-READ
                        // in the per-fd event pair, but the C also
                        // does this conditionally per-flag. Match.
                        if matches!(ready, Ready::Write) {
                            self.on_conn_writable(id);
                        } else {
                            self.on_conn_readable(id);
                        }
                    }

                    IoWhat::Device => {
                        // `handle_device_data`. Dummy never registers,
                        // so unreachable in skeleton. Chunk 3.
                        unreachable!("device fd not registered in skeleton")
                    }

                    IoWhat::Tcp(i) => {
                        // `handle_new_meta_connection`.
                        self.on_tcp_accept(i);
                    }

                    IoWhat::Udp(i) => {
                        // `handle_incoming_vpn_data`. The socket IS
                        // bound (UDP listener); a peer COULD send to
                        // it. But: no `node_tree` yet, no key state,
                        // no route. The packet is undecryptable
                        // garbage from our point of view. C
                        // `net_packet.c:1802` would `lookup_node_udp`,
                        // get NULL, `try_harder`, give up.
                        //
                        // We DON'T `unreachable!()` (the fd IS
                        // registered now). We don't read either:
                        // level-triggered means the socket stays
                        // readable, this arm fires every turn,
                        // burning CPU. Drain the socket and discard.
                        //
                        // Chunk 4+ replaces this with the real
                        // recv_from + decrypt + route.
                        self.on_udp_drain(i);
                    }
                }
            }
        }

        log::info!(target: "tincd", "Terminating");
        RunOutcome::Clean
    }

    // ─── timer handlers

    /// `timeout_handler` (`net.c:180-266`). With zero peers, the
    /// `for list_each(connection_t, c)` loop iterates control conns
    /// only. Control conns have `last_ping_time = now + 3600` (set
    /// by `handle_id`), so the timeout check `c->last_ping_time +
    /// pingtimeout <= now.tv_sec` is `now + 3600 + 5 <= now` =
    /// false. Nothing fires. The handler degenerates to: re-arm.
    ///
    /// This PROVES the explicit-re-arm design works. The C auto-
    /// deletes if cb didn't `timeout_set`; we MUST call `timers.set`
    /// or the timer stays disarmed and `tick()` returns `None`
    /// forever after.
    fn on_ping_tick(&mut self) {
        // C `net.c:263-265`: `timeout_set(data, &(struct timeval) {
        // 1, jitter() })`. Re-arm for 1 second from now (the cached
        // `now` in `tick()`, NOT a fresh `Instant::now()` — that's
        // the rate-based-timer property documented in tinc-event).
        // jitter() not ported (see lib.rs doc).
        self.timers.set(self.pingtimer, Duration::from_secs(1));

        // The actual sweep would go here. Chunk 3+.
    }

    /// `age_past_requests` (`protocol.c:213-228`). Evict seen-
    /// request entries older than `pinginterval` seconds, log the
    /// counts at DEBUG, re-arm +10s.
    ///
    /// C `:219` condition: `p->firstseen + pinginterval <=
    /// now.tv_sec`. The `<=` boundary is preserved by `seen.age`.
    /// C `:226` log: `"Aging past requests: deleted %d, left %d"`
    /// only when `left || deleted` (don't log 0/0 every 10s).
    fn on_age_past_requests(&mut self) {
        let now = self.timers.now();
        let max_age = Duration::from_secs(u64::from(self.settings.pinginterval));
        let (deleted, left) = self.seen.age(now, max_age);
        // C `:225-227`: gate the log on non-empty.
        if deleted > 0 || left > 0 {
            log::debug!(target: "tincd::proto",
                        "Aging past requests: deleted {deleted}, left {left}");
        }
        // C `:228`: `timeout_set(..., {10, jitter()})`. Re-arm.
        self.timers.set(self.age_timer, Duration::from_secs(10));
    }

    // ─── signal handlers

    /// `sigterm_handler` (`net.c:316-319`) for `Exit`;
    /// `sighup_handler` (`:321-328`) for `Reload`;
    /// `sigalrm_handler` (`:330-333`) for `Retry`.
    fn on_signal(&mut self, s: SignalWhat) {
        match s {
            SignalWhat::Exit => {
                // C: `logger(..., LOG_NOTICE, "Got %s signal");
                // event_exit()`. event_exit sets `running = false`.
                log::info!(target: "tincd", "Got signal, exiting");
                self.running = false;
            }
            SignalWhat::Reload => {
                // C: reopenlogger + reload_configuration. Skeleton:
                // log and ignore. reload needs the config tree walk,
                // the expire-mark sweep, all of `net.c:336-458`.
                log::info!(target: "tincd", "Got SIGHUP, reload not implemented");
            }
            SignalWhat::Retry => {
                // C: retry() (`net.c:460-485`). Walks outgoing_list,
                // sets each timeout to fire NOW. Skeleton has no
                // outgoings.
                log::info!(target: "tincd", "Got SIGALRM, retry not implemented");
            }
        }
    }

    // ─── io handlers

    /// `handle_new_meta_connection` (`net_socket.c:734-779`).
    /// accept on TCP listener `i`, tarpit-check, configure, allocate
    /// Connection, register with event loop.
    ///
    /// Same shape as `on_unix_accept` plus: `sockaddrunmap` (v4-mapped
    /// v6 → plain v4), `is_local`+tarpit (rate-limit non-loopback),
    /// `configure_tcp` (NONBLOCK + NODELAY).
    fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)];

        // C `:745`: `fd = accept(l->tcp.fd, &sa.sa, &len)`.
        // socket2 uses accept4(SOCK_CLOEXEC) on Linux/BSD — the C
        // doesn't set CLOEXEC on accepted fds (small leak into
        // script.c children, fixed for free).
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // The listener fd is NOT non-blocking but accept can
                // still spuriously return EAGAIN if a peer connect+
                // RST'd between epoll wake and our accept (TOCTOU).
                return;
            }
            Err(e) => {
                // C `:748`: `logger(ERR); return`. Nothing to clean.
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // ─── sockaddrunmap (`:751`)
        // V6ONLY is set so we shouldn't see mapped addrs in practice.
        // Canonicalize anyway: `fmt_addr` and the tarpit's prev-addr
        // compare want plain v4.
        //
        // `as_socket()` returns None for AF_UNIX (impossible here —
        // TCP accept returns AF_INET/AF_INET6). The `else` branch is
        // a kernel-bug-guard: log + dummy. `expect()` would crash
        // the whole daemon for one bizarre accept; not proportionate.
        // The dummy 0.0.0.0:0 won't match prev_addr (no false
        // tarpit), won't be is_local (no false exemption either).
        let peer = if let Some(sa) = peer_sockaddr.as_socket() {
            unmap(sa)
        } else {
            log::error!(target: "tincd::conn",
                        "accept returned non-IP family {:?}",
                        peer_sockaddr.family());
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };

        // ─── tarpit check (`:753`)
        // C: `if(!is_local_connection(&sa) && check_tarpit(&sa, fd))
        //   return`. The `&&` short-circuits: local conns never tick
        // the buckets. The pidfile address is loopback; `tinc start`
        // followed by 100 `tinc info` queries doesn't get tarpitted.
        if !is_local(&peer) {
            let now = self.timers.now();
            if self.tarpit.check(peer, now) {
                // C: `tarpit(fd); return true` from check → caller
                // returns. We do the pit() here; the C splits
                // check/pit because `check_tarpit` is `static bool`
                // and `tarpit` is `void`. Our struct fuses both.
                //
                // `sock.into()`: Socket → OwnedFd. The fd is NOT
                // configured (no NONBLOCK, no NODELAY) — we never
                // touch it again. The peer's reads block forever.
                self.tarpit.pit(sock.into());
                log::info!(target: "tincd::conn",
                           "Tarpitting connection from {peer}");
                return;
            }
        }

        // ─── configure_tcp (`:773`)
        // C ordering: new_connection (`:758`) BEFORE configure_tcp
        // (`:773`). We flip: configure first, THEN allocate. If
        // configure fails (set_nonblocking error), we don't have a
        // half-registered Connection to clean up. The C ordering
        // works because C errors don't unwind — `:73-75` just logs
        // and continues with a blocking fd. We're stricter.
        let fd = match configure_tcp(sock) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "configure_tcp failed for {peer}: {e}");
                return; // sock dropped (fd closed)
            }
        };

        // ─── allocate connection (`:758-776`)
        // C `:762`: `c->hostname = sockaddr2hostname(&sa)`. The
        // "10.0.0.5 port 50123" string. Never changes after this.
        // C `:749`: `memcpy(&c->address, &sa, salen)`. We pass the
        // `SocketAddr` (already unmapped) for `ack_h`'s edge build.
        let hostname = fmt_addr(&peer);
        let conn = Connection::new_meta(fd, hostname, peer, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:771`: `io_add(&c->io, handle_meta_io, c, c->socket,
        // IO_READ)`. Read-only initially. Same registration as unix.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                // C `:767`: `"Connection from %s", c->hostname`.
                log::info!(target: "tincd::conn",
                           "Connection from {peer}");
            }
            Err(e) => {
                // ev.add failed (out of fds?). Roll back.
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// Stub `handle_incoming_vpn_data`. Just drain the UDP socket so
    /// it doesn't stay readable and burn the event loop. Chunk 4+
    /// replaces this with the real `recvfrom` + decrypt + route.
    ///
    /// We use socket2's `recv_from` (not `libc::recvfrom`) here
    /// because we already have the wrapper. NO new unsafe. The
    /// `MaybeUninit` API is awkward but the data is discarded so we
    /// don't actually need to assume_init it.
    fn on_udp_drain(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)];
        // 1500 bytes is enough — anything bigger gets truncated
        // (MSG_TRUNC), still drains. We're not keeping the data.
        let mut buf = [std::mem::MaybeUninit::uninit(); 1500];
        // Loop: drain ALL pending datagrams. Level-triggered means
        // one datagram drained leaves the rest still ready, fires
        // again next turn. Draining the lot now reduces wake-churn.
        loop {
            match listener.udp.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    // Log at DEBUG — this is noise in production
                    // (every probe, every wrong-port packet).
                    log::debug!(target: "tincd::net",
                                "Dropping {n}-byte UDP packet from {addr:?} \
                                 (no route table yet)");
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::warn!(target: "tincd::net",
                               "UDP recv error on listener {i}: {e}");
                    break;
                }
            }
        }
    }

    /// `handle_new_unix_connection` (`net_socket.c:781-812`).
    /// accept, allocate Connection, register with event loop.
    fn on_unix_accept(&mut self) {
        // C `:789`: `fd = accept(io->fd, &sa.sa, &len)`.
        let stream = match self.control.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Spurious wakeup. Level-triggered: re-fires next
                // turn if still readable.
                return;
            }
            Err(e) => {
                // C `:792`: log ERR, return. Connection wasn't
                // accepted; nothing to clean up.
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // ─── allocate connection
        // C `:798-811`: `c = new_connection(); c->name = "<control>";
        // ...; io_add(); connection_add(c); c->allow_request = ID`.
        // Our `Connection::new_control` sets the same defaults.
        //
        // OwnedFd from UnixStream: `into()` works (UnixStream:
        // Into<OwnedFd> via std).
        let fd: OwnedFd = stream.into();
        let conn = Connection::new_control(fd, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:807`: `io_add(&c->io, handle_meta_io, c, c->socket,
        // IO_READ)`. Read-only initially; `send` adds WRITE.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                // C `:808`: `"Connection from %s", c->hostname`.
                // hostname is the literal `"localhost port unix"`.
                log::info!(target: "tincd::conn",
                           "Connection from {} (control)",
                           self.conns[id].hostname);
            }
            Err(e) => {
                // ev.add failed (out of fds?). Roll back.
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_meta_io` READ path (`net_socket.c:559-561` →
    /// `handle_meta_connection_data` → `receive_meta`).
    ///
    /// feed → loop read_line → check_gate → handler.
    ///
    /// `too_many_lines`: the C `receive_meta` + `receive_request`
    /// dispatch inlined (`meta.c:164-320` is 156 lines). Splitting
    /// would thread `id`/`conn`/`self` borrows through helpers.
    // TODO(chunk-4b): too_many_lines goes away with send_ack.
    #[allow(clippy::too_many_lines)]
    fn on_conn_readable(&mut self, id: ConnId) {
        // ─── feed (one recv)
        // C `meta.c:185`: `inlen = recv(...)`.
        // `OsRng`: feed() needs an rng for the SPTPS-mode receive
        // path. Only touched on rekey (HANDSHAKE record post-
        // initial-handshake). `OsRng` is zero-sized; passing `&mut`
        // is free.
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.feed(&mut OsRng) {
            FeedResult::WouldBlock => return,
            FeedResult::Dead => {
                self.terminate(id);
                return;
            }
            FeedResult::Data => {}
            FeedResult::Sptps(outs) => {
                // SPTPS-mode connection. Dispatch outputs.
                let needs_write = self.dispatch_sptps_outputs(id, outs);
                if !self.conns.contains_key(id) {
                    // dispatch terminated (e.g. HandshakeDone in 4a).
                    return;
                }
                if needs_write {
                    if let Some(&io_id) = self.conn_io.get(id) {
                        if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                            log::error!(target: "tincd::conn",
                                        "io_set failed for {id:?}: {e}");
                            self.terminate(id);
                        }
                    }
                }
                // Don't fall through to the line-drain loop —
                // SPTPS mode doesn't touch inbuf.
                return;
            }
        }

        // ─── drain inbuf (loop readline + dispatch)
        // C `meta.c:303-315`: `while(c->inbuf.len) { ... }`.
        // We loop until `read_line` returns None (incomplete).
        loop {
            let conn = self.conns.get_mut(id).expect("not terminated mid-loop");
            let Some(range) = conn.inbuf.read_line() else {
                break;
            };
            // The line bytes. `bytes_raw()` returns the full backing
            // slice; `range` indexes into it. We can't borrow
            // `bytes_raw()` and call `&mut self` methods, so: copy.
            //
            // The copy is cheap (control lines are <100 bytes). The
            // ALTERNATIVE is `read_line` returning a `Vec<u8>` —
            // same copy, hidden inside. Making it explicit means
            // chunk 4 can later avoid the copy for the SPTPS path
            // (which has 1500-byte frames and IS hot).
            let line: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();

            // ─── check_gate (protocol.c:164-178)
            let req = match check_gate(conn, &line) {
                Ok(r) => r,
                Err(e) => {
                    log::error!(target: "tincd::proto",
                                "Bad request from {}: {e:?}", conn.name);
                    self.terminate(id);
                    return;
                }
            };

            // ─── handler dispatch (protocol.c:180)
            // C: `entry->handler(c, request)`. We match. The match
            // arms are the request_entries[] table.
            let (result, needs_write) = match req {
                Request::Id => {
                    // `id_h`. The ctx fields come from `&self` — we
                    // can't borrow `&self.cookie` while holding `&mut
                    // conn` (both borrow `self`). The cookie+name are
                    // small — clone. mykey is borrowed (the BLOB-clone
                    // for sptps_start happens INSIDE handle_id, only
                    // on the peer branch). confbase: borrow into a
                    // PathBuf clone (same shape as the others).
                    //
                    // Hold on — `&self.mykey` while `&mut conn` is
                    // borrowed from `&mut self.conns`? Disjoint
                    // fields. The borrow checker allows
                    // `&self.mykey` and `&mut self.conns[id]`
                    // simultaneously. The `.get_mut(id)` borrow IS
                    // through `&mut self.conns` not `&mut self`.
                    //
                    // Except: `conn` was bound at the top of the
                    // loop body via `self.conns.get_mut`. That's
                    // `&mut self.conns`. `&self.mykey` is fine
                    // (different field). `&self.cookie` is fine.
                    // The clones aren't NEEDED for borrow reasons —
                    // they were a habit from earlier chunks. KEEP
                    // them for now (clones are cheap, refactor later
                    // if profiling says so).
                    let cookie = self.cookie.clone();
                    let my_name = self.name.clone();
                    let confbase = self.confbase.clone();
                    let ctx = IdCtx {
                        cookie: &cookie,
                        my_name: &my_name,
                        mykey: &self.mykey,
                        confbase: &confbase,
                    };
                    let now = self.timers.now();
                    match handle_id(conn, &line, &ctx, now, &mut OsRng) {
                        Ok(IdOk::Control { needs_write }) => (DispatchResult::Ok, needs_write),
                        Ok(IdOk::Peer { needs_write, init }) => {
                            // ─── SPTPS-start dispatch
                            // 1. Queue init Wire bytes (responder's KEX).
                            //    C `send_meta_sptps`: buffer_add to
                            //    outbuf. Our `send_raw`.
                            // 2. take_rest from inbuf, re-feed via
                            //    feed_sptps. The id-line piggyback.
                            // 3. Dispatch THOSE outputs too.
                            //
                            // For chunk 4a, step 3 (and the regular
                            // FeedResult::Sptps arm above) terminate
                            // on HandshakeDone — we don't have
                            // send_ack yet. The integration test
                            // proves the handshake completes; chunk
                            // 4b adds the ack.
                            let mut nw = needs_write;
                            for o in init {
                                if let tinc_sptps::Output::Wire { bytes, .. } = o {
                                    nw |= conn.send_raw(&bytes);
                                }
                                // Output::Record / HandshakeDone:
                                // unreachable from sptps_start (it
                                // only emits Wire). The match isn't
                                // exhaustive; we let other variants
                                // fall through silently. They're
                                // unreachable, and panicking would
                                // be noise.
                            }

                            // take_rest + re-feed. Factor as a
                            // method so the regular Sptps arm can
                            // call the same dispatch.
                            let leftover = conn.inbuf.take_rest();
                            // Self::feed_sptps borrows ONLY sptps,
                            // not conn. We can borrow sptps then
                            // dispatch the outputs (which need
                            // &mut conn.outbuf). Disjoint fields
                            // inside Connection — except: feed_sptps
                            // takes &mut Sptps via conn.sptps.
                            // as_deref_mut(), and send_raw is
                            // &mut self (Connection). Conflict.
                            //
                            // Same borrow problem as feed(). Same
                            // fix: feed_sptps is an associated fn
                            // taking &mut Sptps directly. We pull
                            // the deref out here.
                            let outs = if leftover.is_empty() {
                                // Fast path: no piggyback. Common.
                                Vec::new()
                            } else {
                                let sptps = conn
                                    .sptps
                                    .as_deref_mut()
                                    .expect("handle_id_peer just installed it");
                                match Connection::feed_sptps(
                                    sptps, &leftover, &conn.name, &mut OsRng,
                                ) {
                                    FeedResult::Sptps(outs) => outs,
                                    FeedResult::Dead => {
                                        // Piggybacked bytes were
                                        // garbage. Unusual (a real
                                        // peer's KEX is well-formed)
                                        // but possible (fuzzer).
                                        log::error!(
                                            target: "tincd::proto",
                                            "SPTPS error in piggyback from {}",
                                            conn.name
                                        );
                                        self.terminate(id);
                                        return;
                                    }
                                    // feed_sptps only returns
                                    // Sptps or Dead.
                                    _ => unreachable!(),
                                }
                            };

                            // Dispatch piggyback outputs. Same
                            // shape as the regular Sptps arm. For
                            // chunk 4a: terminate on HandshakeDone.
                            // (Reaching HandshakeDone in the
                            // PIGGYBACK is unlikely — needs the
                            // initiator's KEX AND SIG in the same
                            // segment as the ID line. Three writes
                            // coalesced. Possible on a slow link.)
                            if self.dispatch_sptps_outputs(id, outs) {
                                nw = true;
                            }
                            // dispatch_sptps_outputs may have
                            // terminated (HandshakeDone in 4a).
                            // Check.
                            if !self.conns.contains_key(id) {
                                return;
                            }

                            (DispatchResult::Ok, nw)
                        }
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "ID rejected from {}: {e:?}", conn.name);
                            (DispatchResult::Drop, false)
                        }
                    }
                }
                Request::Control => {
                    let (r, nw) = handle_control(conn, &line);
                    if r == DispatchResult::DumpSubnets {
                        // `dump_subnets` (`subnet.c:395-410`). Same
                        // borrow dance as DumpConnections: drop
                        // `conn`, walk the tree into a Vec, re-fetch.
                        // C: `"%d %d %s %s"` per row, terminator
                        // `"%d %d"`. `netstr` is `net2str` output
                        // (= `Subnet::Display`). Owner is the name
                        // or `"(broadcast)"` for ownerless (`subnet.
                        // c:406`: `subnet->owner ? ->name : "(
                        // broadcast)"` — we don't have ownerless
                        // subnets yet; chunk 8's broadcast subnets).
                        let rows: Vec<String> = self
                            .subnets
                            .iter()
                            .map(|(subnet, owner)| {
                                format!(
                                    "{} {} {} {}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_SUBNETS,
                                    subnet,
                                    owner
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator.
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_SUBNETS
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpConnections {
                        // `dump_connections` (`connection.c:166-175`).
                        // Walk ALL conns (including the one asking).
                        // C: `for list_each(connection_t, c, &list)
                        // send_request(cdump, "%d %d %s %s %x %d %x")`
                        // then a terminator `"%d %d"`.
                        //
                        // Borrow dance: `conn` borrows `self.conns`
                        // mutably. The walk needs `&self.conns`. Drop
                        // `conn`, walk into a Vec<String>, re-fetch
                        // `conn`, send. The Vec is one alloc per
                        // dump (not hot — control RPC).
                        let rows: Vec<String> = self
                            .conns
                            .values()
                            .map(|c| {
                                // `connection.c:168`: `"%d %d %s %s
                                // %x %d %x"`. `hostname` is the
                                // FUSED `"host port port"` string
                                // (one %s); the CLI splits it (`" port "`
                                // literal, `dump.rs::ConnRow::parse`).
                                format!(
                                    "{} {} {} {} {:x} {} {:x}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_CONNECTIONS,
                                    c.name,
                                    c.hostname,
                                    c.options,
                                    c.fd(),
                                    c.status_value()
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator: `"%d %d"` (`:173`). The CLI
                        // detects end-of-dump by a line with no
                        // body after the subtype int.
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_CONNECTIONS
                        ));
                        (DispatchResult::Ok, nw2)
                    } else {
                        (r, nw)
                    }
                }
                _ => {
                    // Any other request: skeleton doesn't handle.
                    // C would dispatch via the table; we Drop.
                    // (This shouldn't fire — `allow_request` gates
                    // to ID then CONTROL. But if a future chunk
                    // sets `allow_request = None` for some path
                    // and forgets to add the match arm, this is
                    // the catch.)
                    log::error!(target: "tincd::proto",
                                "Request {req:?} not implemented");
                    (DispatchResult::Drop, false)
                }
            };

            // ─── io_set (meta.c:95)
            if needs_write {
                if let Some(&io_id) = self.conn_io.get(id) {
                    if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                        log::error!(target: "tincd::conn",
                                    "io_set failed for {id:?}: {e}");
                        self.terminate(id);
                        return;
                    }
                }
            }

            match result {
                // Dump variants were already mapped to Ok above
                // (the Control arm rewrote them inline). Unreachable
                // here. Explicit-unreachable rather than `_` so a
                // new DispatchResult variant fails to compile.
                DispatchResult::DumpConnections | DispatchResult::DumpSubnets => {
                    unreachable!("Dump variants rewritten inline above")
                }
                DispatchResult::Ok => {}
                DispatchResult::Stop => {
                    // `event_exit()`. The reply is queued; we set
                    // running=false; the loop finishes THIS turn
                    // (so the WRITE event for the reply fires) then
                    // exits. Don't `return` — let the read_line loop
                    // exhaust inbuf (CLI might have sent more after
                    // STOP; unlikely but harmless).
                    self.running = false;
                }
                DispatchResult::Drop => {
                    self.terminate(id);
                    return;
                }
            }
        }
    }

    /// `receive_meta_sptps` (`meta.c:120-162`). Dispatch SPTPS
    /// outputs. Called from BOTH the regular `FeedResult::Sptps`
    /// arm AND the `IdOk::Peer` piggyback re-feed.
    ///
    /// Returns `true` if any output queued bytes to outbuf (io_set
    /// signal). May `terminate(id)` — caller must check `conns.
    /// contains_key(id)` after.
    ///
    /// Match arms map 1:1 to the C callback's branches:
    /// - `Wire` → `send_meta_sptps` (`meta.c:50`): outbuf raw.
    /// - `HandshakeDone` → `meta.c:129-135`: `if(allow == ACK)
    ///   send_ack(c) else return true`.
    /// - `Record` → `meta.c:153-161`: strip `\n`, `receive_
    ///   request(c, data)`. Same `check_gate` + handler match as
    ///   the cleartext line path; only the FRAMING differs (SPTPS
    ///   record vs `\n`-terminated line).
    fn dispatch_sptps_outputs(&mut self, id: ConnId, outs: Vec<tinc_sptps::Output>) -> bool {
        use tinc_sptps::Output;
        let mut needs_write = false;
        for o in outs {
            let Some(conn) = self.conns.get_mut(id) else {
                return needs_write;
            };
            match o {
                Output::Wire { bytes, .. } => {
                    // C `send_meta_sptps` (`meta.c:50`).
                    needs_write |= conn.send_raw(&bytes);
                }
                Output::HandshakeDone => {
                    // C `meta.c:129-135`: `if(type == SPTPS_
                    // HANDSHAKE) { if(c->allow_request == ACK)
                    // return send_ack(c); else return true; }`.
                    //
                    // `else return true`: outgoing conns send their
                    // ACK from `id_h` (`:453` `if(!c->outgoing) ...
                    // else send_ack(c)` — wait no, that's not
                    // right either. The C `:451-453` is `if(!c->
                    // outgoing) send_id(c)`. The outgoing-side
                    // send_ack is from the SAME `meta.c:131` arm.
                    // The `else` is for the initiator's SECOND
                    // HandshakeDone callback during rekey. Chunk
                    // 4b is responder-only, no rekey: always ACK.
                    log::info!(target: "tincd::auth",
                               "SPTPS handshake completed with {} ({})",
                               conn.name, conn.hostname);
                    if conn.allow_request == Some(Request::Ack) {
                        let now = self.timers.now();
                        needs_write |= send_ack(conn, self.my_udp_port, self.myself_options, now);
                    }
                    // No terminate. No sync-flush. The chunk-4a
                    // shortcut is gone; the connection STAYS UP.
                    // The ACK is queued in outbuf (encrypted via
                    // sptps_send_record inside conn.send); the
                    // regular WRITE event flushes it.
                }
                Output::Record { bytes, .. } => {
                    // C `meta.c:155-161`. Strip `\n`, dispatch.
                    // `record_type` is always 0 here (app data;
                    // SPTPS_HANDSHAKE became `HandshakeDone`).
                    // The C ignores `type` (`meta.c:153`: only
                    // checked against SPTPS_HANDSHAKE earlier).
                    let body = record_body(&bytes);

                    // ─── receive_request: same as cleartext
                    let req = match check_gate(conn, body) {
                        Ok(r) => r,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "Bad SPTPS request from {}: {e:?}", conn.name);
                            self.terminate(id);
                            return needs_write;
                        }
                    };

                    // Handler match. C `request_entries[]` table
                    // (`protocol.c:58-86`). The body is owned (a
                    // Vec inside `Output::Record`); the handlers
                    // need `&mut self` so we can't borrow `conn`
                    // across the call — already dropped above.
                    let result = match req {
                        Request::Ack => self.on_ack(id, body),
                        Request::AddSubnet => self.on_add_subnet(id, body),
                        Request::DelSubnet => self.on_del_subnet(id, body),
                        Request::AddEdge => self.on_add_edge(id, body),
                        Request::DelEdge => self.on_del_edge(id, body),
                        _ => {
                            // KEY_CHANGED/REQ_KEY/ANS_KEY/PING/PONG
                            // etc — chunk 7/8. The gate passed
                            // (allow_request = None post-ACK). C
                            // dispatches via the table; we Drop
                            // until handlers land.
                            log::warn!(target: "tincd::proto",
                                       "SPTPS request {req:?} not implemented — chunk 7/8");
                            self.terminate(id);
                            return needs_write;
                        }
                    };
                    match result {
                        Ok(nw) => needs_write |= nw,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "{req:?} from {id:?}: {e:?}");
                            self.terminate(id);
                            return needs_write;
                        }
                    }
                }
            }
        }
        needs_write
    }

    /// `lookup_node` + `new_node`/`node_add` fused (`node.c:74,96`).
    /// The C pattern from `add_edge_h:112-120` and `add_subnet_h:
    /// 86-89`: `n = lookup_node(name); if(!n) { n = new_node();
    /// node_add(n); }`.
    ///
    /// Adds to `graph` AND `node_ids` (the name→id map). Does NOT
    /// add a `NodeState` — only directly-connected peers get one
    /// (via `on_ack`). A node learned from a forwarded ADD_EDGE is
    /// transitive: in the graph, but no live connection.
    ///
    /// C `xzalloc` zeroes `reachable`; `Graph::add_node` defaults
    /// it `true`. We zero it back: a freshly-learned node IS
    /// unreachable until `run_graph` proves otherwise. The diff
    /// then emits `BecameReachable` and we get the host-up log.
    fn lookup_or_add_node(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.node_ids.get(name) {
            return id;
        }
        let id = self.graph.add_node(name);
        // C `node.c:75`: `xzalloc` → `reachable = false`. The
        // graph crate's `true` default is for the steady-state
        // "all nodes already known" tests; the daemon's reality
        // is "just learned this name, haven't run sssp yet".
        self.graph.set_reachable(id, false);
        self.node_ids.insert(name.to_owned(), id);
        id
    }

    /// Dedup gate for flooded messages. `seen_request` (`protocol.
    /// c:234-249`). Returns `true` if `body` was already seen —
    /// caller drops silently (return `Ok(false)`, don't process,
    /// don't forward).
    ///
    /// `body` is the FULL line (`\n` already stripped). C keys on
    /// `strcmp` of the whole `request` string; the dedup nonce
    /// (second `%x` token) makes identical-payload-different-origin
    /// messages distinct. We pass `body` as-is. The &[u8]→&str
    /// conversion: C `strcmp` is byte-compare; `seen.check` keys on
    /// `&str` (HashMap via `Borrow<str>`). Node names are `check_id`-
    /// gated to ASCII so the body IS valid UTF-8; `from_utf8` here
    /// is just a type cast.
    fn seen_request(&mut self, body: &[u8]) -> bool {
        // `from_utf8` failure: body has high bytes. Shouldn't
        // happen (the parsers already validated). Treat as not-
        // seen (don't dup-drop garbage — let the handler reject).
        let Ok(s) = std::str::from_utf8(body) else {
            return false;
        };
        self.seen.check(s, self.timers.now())
    }

    /// `graph()` (`graph.c:327-346`): sssp + diff + mst. Logs each
    /// transition. The script-spawn / sptps_stop / mtu-reset are
    /// chunk-7/8 deferrals; the LOG proves the diff fired.
    ///
    /// C `graph.c:261`: `"Node %s (%s) became reachable"` at INFO.
    /// We don't have the hostname (no `NodeState` for transitive
    /// nodes); log the name from the graph.
    fn run_graph_and_log(&mut self) {
        let (transitions, _mst) = run_graph(&mut self.graph, self.myself);
        // STUB(chunk-6): _mst feeds connection_t.status.mst (the
        // broadcast tree). One peer in chunk 5; mst is trivial.
        for t in transitions {
            match t {
                Transition::BecameReachable { node, via } => {
                    // `graph.c:261-262`: INFO. Look up the name —
                    // graph.node() is `Some` (just came from
                    // node_ids() inside diff_reachability).
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    let via_name = self
                        .graph
                        .node(via)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became reachable (via {via_name})");
                    // STUB(chunk-8): execute_script("host-up")
                    // (`graph.c:265-270`).
                    // STUB(chunk-7): update_node_udp (`graph.c:
                    // 291-320`).
                }
                Transition::BecameUnreachable { node } => {
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became unreachable");
                    // STUB(chunk-8): execute_script("host-down")
                    // (`graph.c:273`).
                    // STUB(chunk-7): sptps_stop(&n->sptps), reset
                    // mtuprobes/minmtu/maxmtu, kill mtu timer
                    // (`graph.c:275-289`).
                }
            }
        }
    }

    /// `add_subnet_h` mutation half (`protocol_subnet.c:43-140`).
    ///
    /// C path traced:
    /// - `:49-68` parse + check_id + str2net — `parse_add_subnet`
    /// - `:71` `seen_request(request)` — dup-drop
    /// - `:77` `lookup_node(name)` — `lookup_or_add_node`
    /// - `:79-84` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:86-89` `if(!owner) new_node` — fused into lookup
    /// - `:93` `lookup_subnet(owner, &s)` — SubnetTree::add is
    ///   idempotent, but the C returns early WITHOUT forward. We
    ///   match: `seen` already dedups the flood; `add` idempotent.
    /// - `:98-104` `if(owner == myself)` — retaliate — STUBBED
    /// - `:116-122` `strictsubnets` — STUBBED (deferred)
    /// - `:126-128` `subnet_add(owner, new)` — SubnetTree::add
    /// - `:130-132` `subnet_update` script — STUBBED (chunk 8)
    /// - `:136-138` `forward_request` — STUBBED
    /// - `:142-148` MAC fast-handoff — STUBBED (no MAC subnets yet)
    ///
    /// NO `graph()` — subnets don't change topology. The C calls
    /// `subnet_update` (`subnet.c:327-393`, script firing) not
    /// `graph()`.
    ///
    /// Returns the io_set signal. Always `false` in chunk 5
    /// (forward stubbed, retaliate stubbed). Kept for chunk 5b.
    fn on_add_subnet(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_add_subnet(body)?;

        // C `:71`: `if(seen_request(request)) return true`.
        if self.seen_request(body) {
            return Ok(false);
        }

        // C `:77,86-89`: lookup_node + conditional new_node.
        // STUB(chunk-9): tunnelserver mode (`:79-84`) filters
        // indirect registrations. Niche feature; defer.
        let owner = self.lookup_or_add_node(&owner_name);

        // C `:98-104`: `if(owner == myself)`. Peer is wrong about
        // us — they think we own a subnet we don't. C sends
        // DEL_SUBNET correction back.
        if owner == self.myself {
            let conn = self.conns.get(from_conn);
            log::warn!(target: "tincd::proto",
                       "Got ADD_SUBNET from {} for ourself ({subnet})",
                       conn.map_or("<gone>", |c| c.name.as_str()));
            // STUB(chunk-6): send_del_subnet(c, &s) (`:102`).
            // Needs the broadcast send machinery. Log + return Ok.
            return Ok(false);
        }

        // STUB(chunk-9): strictsubnets (`:116-122`). Deferred.

        // C `:126`: `subnet_add(owner, new)`. Idempotent on dup
        // (the C `:93` `if(lookup_subnet) return true` is
        // belt-and-braces over `seen_request`; our `add` is a
        // BTreeSet insert which is also idempotent).
        self.subnets.add(subnet, owner_name);

        // STUB(chunk-8): if owner reachable, subnet_update(..., true)
        // (`:130-132`). Script firing.

        // STUB(chunk-6): forward_request(c, request) (`:136-138`).
        // One peer in chunk 5; nobody to forward to. The integration
        // test doesn't see the difference.
        log::debug!(target: "tincd::proto",
                    "would forward ADD_SUBNET (one peer, no-op)");

        // STUB(chunk-7): MAC fast-handoff (`:142-148`). No TAP
        // mode yet.

        Ok(false)
    }

    /// `del_subnet_h` mutation half (`protocol_subnet.c:163-261`).
    ///
    /// C path traced:
    /// - `:163-188` parse — `parse_del_subnet`
    /// - `:191` `seen_request`
    /// - `:197` `lookup_node` — NOT lookup_or_add: DEL for an
    ///   unknown owner is a warn-and-drop (`:206-210`)
    /// - `:216` `lookup_subnet` — same: DEL for unknown subnet is
    ///   warn-and-drop (`:218-225`). Our `del()` returns `bool`.
    /// - `:231-236` `if(owner == myself)` retaliate ADD — STUBBED
    /// - `:244` `forward_request` — STUBBED
    /// - `:254-256` `subnet_update(..., false)` — STUBBED (chunk 8)
    /// - `:258` `subnet_del`
    fn on_del_subnet(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_del_subnet(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:197,206-210`: `lookup_node`. NOT lookup_or_add — a
        // DEL for a node we've never heard of is wrong. Warn,
        // return true (don't drop conn).
        let Some(&owner) = self.node_ids.get(&owner_name) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which is not in our node tree");
            return Ok(false);
        };

        // C `:231-236`: `if(owner == myself)`. Peer says we don't
        // own a subnet we DO own. C sends ADD_SUBNET correction.
        if owner == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for ourself ({subnet})");
            // STUB(chunk-6): send_add_subnet(c, find) (`:234`).
            return Ok(false);
        }

        // STUB(chunk-6): forward_request (`:244`).
        log::debug!(target: "tincd::proto",
                    "would forward DEL_SUBNET (one peer, no-op)");

        // STUB(chunk-8): subnet_update(owner, find, false) (`:255`).

        // C `:258`: `subnet_del`. The C does `lookup_subnet` at
        // `:216` first and warns at `:218` if not found. Our
        // `del()` returns the bool; same outcome, one fewer walk.
        if !self.subnets.del(&subnet, &owner_name) {
            // C `:218-225`: warn, return true.
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which does not appear in his subnet tree");
        }

        Ok(false)
    }

    /// `add_edge_h` mutation half (`protocol_edge.c:63-217`).
    ///
    /// C path traced:
    /// - `:77-92` parse — `parse_add_edge` (incl check_id, from≠to)
    /// - `:94` `seen_request`
    /// - `:99-100` `lookup_node(from/to)`
    /// - `:102-111` `tunnelserver` filter — STUBBED
    /// - `:112-120` `if(!from/to) new_node` — lookup_or_add
    /// - `:126-130` `str2sockaddr` — SKIPPED (graph doesn't store
    ///   addrs; AddrStr is opaque per Phase-1 finding)
    /// - `:134-183` `lookup_edge` exists branch:
    ///   - same weight+options → idempotent drop (`:145-148`)
    ///   - `from == myself` + different → send correction (`:150-
    ///     157`) — STUBBED
    ///   - different → update in place. tinc-graph has no edge
    ///     mutation; we del+add. Less efficient (two binary
    ///     searches in the per-node sorted vec) but correct.
    ///     Comment for the future.
    /// - `:184-196` `from == myself` + doesn't exist → contradiction.
    ///   C bumps `contradicting_add_edge`, sends DEL correction.
    ///   STUBBED.
    /// - `:197-205` `edge_add` — graph.add_edge
    /// - `:209-211` `forward_request` — STUBBED
    /// - `:215` `graph()` — run_graph_and_log
    #[allow(clippy::too_many_lines)] // C add_edge_h is 154 LOC; same
    fn on_add_edge(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let edge = parse_add_edge(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        // STUB(chunk-9): tunnelserver mode (`:102-111`).

        let from_id = self.lookup_or_add_node(&edge.from);
        let to_id = self.lookup_or_add_node(&edge.to);

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:134`: `e = lookup_edge(from, to)`.
        if let Some(existing) = self.graph.lookup_edge(from_id, to_id) {
            // C `:136-148`: same weight + options → idempotent.
            // (The C also compares address/local_address; we don't
            // store those on the graph edge. The address compare is
            // for the `update_node_udp` cache invalidation —
            // chunk-7 territory. For graph topology, weight+options
            // is what matters.)
            let e = self.graph.edge(existing).expect("just looked up");
            if e.weight == edge.weight && e.options == edge.options {
                // C `:145-148`: `return true`. No forward, no graph().
                return Ok(false);
            }

            // C `:150-157`: `from == myself` + edge exists with
            // different params. Peer's view of OUR edge is wrong.
            if from_id == self.myself {
                log::warn!(target: "tincd::proto",
                           "Got ADD_EDGE from {conn_name} for ourself \
                            which does not match existing entry");
                // STUB(chunk-6): send_add_edge(c, e) (`:153`).
                // Send back what WE think the edge is.
                return Ok(false);
            }

            // C `:159-183`: in-place update. The C splay_unlink/
            // reinsert for weight (`:179-182`) keeps the
            // edge_weight_tree sorted. tinc-graph has no edge
            // mutation — del+add. Less efficient (the per-node
            // sorted vec gets two binary searches; the weight-
            // order BTreeMap gets a remove+insert). Correct though.
            // Future: Graph::update_edge() if profiling cares.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} which does not \
                        match existing entry");
            self.graph.del_edge(existing);
            self.graph
                .add_edge(from_id, to_id, edge.weight, edge.options);
        } else if from_id == self.myself {
            // C `:184-196`: peer says WE have an edge we don't.
            // Contradiction. C bumps `contradicting_add_edge`
            // counter (read by periodic_handler `net.c:268`),
            // sends DEL_EDGE correction.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} for ourself \
                        which does not exist");
            // STUB(chunk-6): contradicting_add_edge++ (`:187`).
            // STUB(chunk-6): send_del_edge(c, e) (`:192`).
            return Ok(false);
        } else {
            // C `:197-205`: `edge_add`. The fresh-edge case.
            self.graph
                .add_edge(from_id, to_id, edge.weight, edge.options);
        }

        // STUB(chunk-6): forward_request(c, request) (`:209-211`).
        log::debug!(target: "tincd::proto",
                    "would forward ADD_EDGE (one peer, no-op)");

        // C `:215`: `graph()`.
        self.run_graph_and_log();

        Ok(false)
    }

    /// `del_edge_h` mutation half (`protocol_edge.c:225-322`).
    ///
    /// C path traced:
    /// - `:230-241` parse — `parse_del_edge`
    /// - `:244` `seen_request`
    /// - `:250-251` `lookup_node` (NOT lookup_or_add)
    /// - `:263-273` `from`/`to` not found → warn + return true
    /// - `:277-283` `lookup_edge` not found → warn + return true
    /// - `:285-291` `from == myself` → retaliate ADD — STUBBED
    /// - `:295-297` `forward_request` — STUBBED
    /// - `:301` `edge_del`
    /// - `:305` `graph()`
    /// - `:309-320` cleanup unreachable's reverse edge — STUBBED
    ///   (the daemon doesn't add reverse edges from on_ack yet;
    ///   the C's `lookup_edge(to, myself)` would find nothing)
    fn on_del_edge(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let edge = parse_del_edge(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:250-273`: `lookup_node`. Missing is warn-and-drop
        // (return true), NOT a new_node. A DEL for a node we've
        // never heard of means our view is already consistent.
        let Some(&from_id) = self.node_ids.get(&edge.from) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree (unknown from: {})", edge.from);
            return Ok(false);
        };
        let Some(&to_id) = self.node_ids.get(&edge.to) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree (unknown to: {})", edge.to);
            return Ok(false);
        };

        // C `:277-283`: `lookup_edge`. Missing is warn-and-drop.
        let Some(eid) = self.graph.lookup_edge(from_id, to_id) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree");
            return Ok(false);
        };

        // C `:285-291`: `from == myself`. Peer says we DON'T have
        // an edge we DO have. C sends ADD_EDGE correction.
        if from_id == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} for ourself");
            // STUB(chunk-6): contradicting_del_edge++ (`:288`).
            // STUB(chunk-6): send_add_edge(c, e) (`:289`).
            return Ok(false);
        }

        // STUB(chunk-6): forward_request (`:295-297`).
        log::debug!(target: "tincd::proto",
                    "would forward DEL_EDGE (one peer, no-op)");

        // C `:301`: `edge_del`.
        self.graph.del_edge(eid);

        // C `:305`: `graph()`.
        self.run_graph_and_log();

        // STUB(chunk-6): C `:309-320` reverse-edge cleanup. If `to`
        // became unreachable AND has an edge back to us, delete +
        // broadcast that too. With on_ack adding only ONE direction
        // (myself→peer) currently, `lookup_edge(to, myself)` finds
        // nothing. Chunk 6 adds bidi edges from on_ack.

        Ok(false)
    }

    /// `ack_h` mutation half (`protocol_auth.c:965-1064`). Parse
    /// done by `proto::parse_ack`; this does the world-model edits
    /// (which need `&mut self`).
    ///
    /// C path traced:
    /// - `:965-991` lookup_node / new_node / dup-conn handling
    /// - `:993-994` `n->connection = c; c->node = n`
    /// - `:996-999` PMTU intersection (BOTH sides must want it)
    /// - `:1001` `c->options |= options`
    /// - `:1003-1019` PMTU/ClampMSS per-host re-read — STUBBED
    /// - `:1023` `c->allow_request = ALL`
    /// - `:1028` `send_everything(c)` — walks empty trees, sends 0
    /// - `:1032-1051` edge_add: address+port, getsockname, weight avg
    /// - `:1055-1061` `send_add_edge` broadcast — STUBBED (no peers)
    /// - `:1065` `graph()` — STUBBED (chunk 5)
    ///
    /// Returns the io_set signal. (Always `false` in chunk 4b:
    /// `send_everything` iterates empty trees, `send_add_edge` is
    /// stubbed. Kept for chunk 5 when both fire.)
    fn on_ack(&mut self, id: ConnId, body: &[u8]) -> Result<bool, crate::proto::DispatchError> {
        let parsed = parse_ack(body)?;
        let conn = self.conns.get_mut(id).expect("caller checked");

        // C `:948-950`: `if(minor == 1) return upgrade_h(c, req)`.
        // We rejected minor < 2 in id_h. Unreachable.

        // ─── PMTU intersection (`:996-999`)
        // C: `if(!(c->options & options & PMTU)) { c->options &=
        // ~PMTU; options &= ~PMTU; }`. PMTU only sticks if BOTH
        // sides want it (the AND). If either's bit is clear, clear
        // both. Then OR in the rest.
        let mut his = parsed.his_options;
        if conn.options & his & crate::proto::OPTION_PMTU_DISCOVERY == 0 {
            conn.options &= !crate::proto::OPTION_PMTU_DISCOVERY;
            his &= !crate::proto::OPTION_PMTU_DISCOVERY;
        }
        conn.options |= his;

        // C `:1003-1019`: per-host PMTU/ClampMSS re-read. STUBBED
        // (config_tree not retained, see id_h doc).

        // C `:1023`: `c->allow_request = ALL`. Our `None`.
        conn.allow_request = None;

        log::info!(target: "tincd::conn",
                   "Connection with {} ({}) activated",
                   conn.name, conn.hostname);

        // ─── lookup_node / node_add (`:965-994`)
        // C: `n = lookup_node(c->name); if(!n) { n = new_node();
        // node_add(n); } else if(n->connection) { ... close old }`.
        //
        // The dup-conn case (`:975-990`): we already have a live
        // connection to this node, the new one wins, terminate the
        // old. The C reasons about `outgoing` ownership (which side
        // initiated which). Chunk 4b is responder-only — the dup
        // case is two simultaneous INBOUND conns from the same peer.
        // Possible (peer reboots, reconnects before we've timed out
        // the old). Handle it: terminate old, accept new.
        let name = conn.name.clone();
        let edge_addr = conn.address.map(|mut a| {
            // C `:1024-1025`: `sockaddrcpy(&edge->address, &c->
            // address); sockaddr_setport(&edge->address, hisport)`.
            // The peer's TCP-connect-from addr, but with the port
            // REWRITTEN to their UDP port. This is the "how do I
            // reach you for data packets" addr.
            a.set_port(parsed.his_udp_port);
            a
        });
        // C `:1048`: `c->edge->weight = (weight + c->estimated_
        // weight) / 2`. The arithmetic average. C `int /` truncates
        // toward zero; `i32::midpoint` rounds toward neg-inf. With
        // both weights non-negative (RTT in ms) they're identical,
        // but the OVERFLOW behavior differs: `(i32::MAX + i32::MAX)
        // /2` is UB in C, panics in debug Rust, wraps in release.
        // `i32::midpoint` doesn't overflow. The C is buggy at 24-
        // day RTT; we're not. The semantic divergence (rounding) is
        // unreachable. Take the no-overflow version.
        let edge_weight = i32::midpoint(parsed.his_weight, conn.estimated_weight);
        let edge_options = conn.options;

        // (drop conn borrow before touching self.nodes / terminate)
        if let Some(old) = self.nodes.get(&name) {
            if let Some(old_conn) = old.conn {
                if old_conn != id {
                    // C `:976-978`: "Established a second connection
                    // with X, closing old connection".
                    log::debug!(target: "tincd::conn",
                                "Established a second connection with {name}, \
                                 closing old connection");
                    self.terminate(old_conn);
                    // C `:989`: `graph()` after terminate. STUBBED.
                }
            }
        }

        // C `:993-994` + `:1032-1051`: NodeState records the edge
        // metadata (the address, which tinc-graph::Edge doesn't
        // carry — it's runtime annotation). The graph gets weight
        // + options below.
        self.nodes.insert(
            name.clone(),
            NodeState {
                conn: Some(id),
                edge_addr,
                edge_weight,
                edge_options,
            },
        );

        // C `:1032-1051`: `c->edge = new_edge(); ...; edge_add()`.
        // The bridge to the graph. `lookup_or_add_node` for the
        // peer (might already be in the graph if a transitive
        // ADD_EDGE arrived first — unlikely with chunk-5's single-
        // peer scope but the C handles it). Then `add_edge(myself
        // → peer)`.
        //
        // C builds a BIDIRECTIONAL pair via `e->reverse` linking
        // (`edge.c:59-73`). `Graph::add_edge` auto-links if the
        // twin exists. With ONE direction, sssp's `e->reverse`
        // check (`graph.c:159`) skips it — so the peer won't
        // become reachable until either (a) we add the reverse
        // here, or (b) the peer's ADD_EDGE for `peer→myself`
        // arrives. The C does (a) implicitly: `ack_h` runs on
        // BOTH sides, both add their `c->edge`, the first arrives
        // via the protocol and links. With chunk-5's stub forward
        // and no peer-initiated ADD_EDGE in tests, we add both
        // directions here. The C's `c->edge` is one direction;
        // the peer's `c->edge` (sent via ADD_EDGE) is the other.
        // We synthesize the reverse for the test to prove the
        // diff fires.
        let peer_id = self.lookup_or_add_node(&name);
        self.graph
            .add_edge(self.myself, peer_id, edge_weight, edge_options);
        // The reverse. C: comes from peer's send_add_edge. Chunk
        // 5 stub: synthesize. Same weight (the average is symmetric
        // when both sides compute it) but the C peer might have a
        // different `c->options` (depends on THEIR config). With
        // identical defaults: same. Real divergence is chunk-6.
        self.graph
            .add_edge(peer_id, self.myself, edge_weight, edge_options);

        // C `:1028`: `send_everything(c)`. Walks `node_tree`, for
        // each node walks `subnet_tree` and `edge_tree`, sends
        // ADD_SUBNET/ADD_EDGE for everything we know.
        //
        // STUB(chunk-6): the actual sending. `send_add_edge` needs
        // the edge address (`protocol_edge.c:42`: sockaddr2str on
        // `e->address`). tinc-graph::Edge doesn't store it;
        // NodeState.edge_addr does. Either parallel HashMap<EdgeId,
        // SocketAddr> or read NodeState. The latter is closer to
        // the C (`c->edge` IS connection-side state). For now: log
        // what WOULD be sent. With zero subnets and one edge (the
        // one we just added), it'd be one ADD_EDGE.
        let n_subnets = self.subnets.len();
        // Edges: count from the graph. Crude (no `Graph::n_edges`
        // public); walk node_ids and sum. Chunk 5b can add the
        // accessor.
        log::debug!(target: "tincd::proto",
                    "send_everything: would send {n_subnets} subnets, \
                     ~2 edges (STUB chunk-5b)");

        // STUB(chunk-6): C `:1055-1061` send_add_edge(everyone,
        // c->edge). Broadcast to all OTHER active conns. One peer
        // → `everyone` is empty after excluding self.

        // C `:1065`: `graph()`. THE FIRST TIME this does anything:
        // peer was added with reachable=false (lookup_or_add_node);
        // the bidi edge means sssp visits it; diff emits
        // BecameReachable.
        self.run_graph_and_log();

        Ok(false)
    }

    /// `handle_meta_io` WRITE path → `handle_meta_write`
    /// (`net_socket.c:486-511`).
    fn on_conn_writable(&mut self, id: ConnId) {
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.flush() {
            Ok(true) => {
                // outbuf empty. C `:509-511`: `io_set(&c->io, IO_READ)`.
                if let Some(&io_id) = self.conn_io.get(id) {
                    if let Err(e) = self.ev.set(io_id, Io::Read) {
                        log::error!(target: "tincd::conn",
                                    "io_set failed for {id:?}: {e}");
                        self.terminate(id);
                    }
                }
            }
            Ok(false) => {
                // More to send. Stay registered for WRITE.
            }
            Err(e) => {
                // C `:502-504`: log + terminate.
                log::info!(target: "tincd::conn",
                           "Connection write failed: {e}");
                self.terminate(id);
            }
        }
    }

    /// `terminate_connection` (`net.c:118-170`). Full version sends
    /// `del_edge`, runs `graph()`, retries outgoing. Chunk 4b: also
    /// clears the `NodeState.conn` back-ref (`:128-133` `c->node->
    /// connection = NULL`).
    fn terminate(&mut self, id: ConnId) {
        if let Some(conn) = self.conns.remove(id) {
            log::info!(target: "tincd::conn",
                       "Closing connection with {}", conn.name);
            // C `:128-133`: `if(c->node && c->node->connection == c)
            // c->node->connection = NULL`. The node OUTLIVES the
            // conn (peer goes down, comes back up → same node,
            // new conn). Don't remove from `nodes`; just clear the
            // back-ref so a stale ConnId isn't read.
            if let Some(ns) = self.nodes.get_mut(&conn.name) {
                if ns.conn == Some(id) {
                    ns.conn = None;
                }
            }
            // C `free_connection` (`connection.c:119-156`): closes
            // socket, frees buffers, etc. OwnedFd's Drop closes;
            // LineBuf's Drop frees. Nothing to do.
        }
        if let Some(io_id) = self.conn_io.remove(id) {
            // C `io_del`. tinc-event's del is idempotent.
            self.ev.del(io_id);
        }
        // Chunk 3+: edge_del, graph(), retry_outgoing.
    }
}

impl Drop for Daemon {
    /// `exit_control` (`control.c:233-240`): unlink pidfile + socket.
    /// `ControlSocket::drop` already unlinks the socket. We do the
    /// pidfile.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pidfile);
        // Signal handlers stay installed (SelfPipe::drop doesn't del
        // them — see tinc-event/sig.rs Drop doc). Process is exiting;
        // doesn't matter.
    }
}

/// Why `Daemon::setup` failed.
#[derive(Debug)]
pub enum SetupError {
    /// Config read/parse error, or required field missing.
    Config(String),
    /// OS resource: socket, file, epoll.
    Io(std::io::Error),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(s) => write!(f, "{s}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for SetupError {}

// tests
//
// `setup()` and `run()` are NOT unit-testable: SelfPipe is a process
// singleton, signal handlers are process-global. The integration test
// (tests/stop.rs) does the real thing in a subprocess.
//
// What IS testable here: the small pieces that don't touch signals.
// terminate's coherence (conns + conn_io stay in sync), the IoWhat/
// TimerWhat enum shapes.

#[cfg(test)]
mod tests {
    use super::*;

    /// `IoWhat` is `Copy`. `EventLoop<W: Copy>` requires it; this
    /// pins it. Adding a non-Copy field to `IoWhat` (like a String)
    /// fails here, before someone tries to use the daemon.
    #[test]
    fn iowhat_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<IoWhat>();
        assert_copy::<TimerWhat>();
        assert_copy::<SignalWhat>();
    }

    /// `ConnId` is `Copy` (slotmap keys are). `IoWhat::Conn(ConnId)`
    /// transitively needs this.
    #[test]
    fn connid_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ConnId>();
    }

    /// `DaemonSettings::default()` matches C defaults. `net_setup.c:
    /// 1243` (`pinginterval = 60`), `:1248` (`pingtimeout = 5`),
    /// `:789` (`myport = "655"`), `net_socket.c:38` (`addressfamily
    /// = AF_UNSPEC`).
    #[test]
    fn settings_defaults_match_c() {
        let s = DaemonSettings::default();
        assert_eq!(s.pinginterval, 60);
        assert_eq!(s.pingtimeout, 5);
        assert_eq!(s.port, 655);
        assert_eq!(s.addressfamily, AddrFamily::Any);
    }

    /// The IoWhat enum has all six variants. Census: `rg 'io_add\('
    /// src/*.c` finds exactly 6 distinct callbacks (signal.c's is
    /// internal, the rest are the variants here). If a 7th cb is
    /// added in C, this test serves as the documentation pointer.
    #[test]
    fn iowhat_variant_census() {
        // Just match exhaustively. Compiler check, not runtime.
        fn _exhaustive(w: IoWhat) {
            match w {
                IoWhat::Signal
                | IoWhat::UnixListener
                | IoWhat::Device
                | IoWhat::Conn(_)
                | IoWhat::Tcp(_)
                | IoWhat::Udp(_) => {}
            }
        }
        // 6 variants. Can't introspect the count at runtime in
        // stable Rust without a macro. The match-exhaustiveness IS
        // the test.
    }
}
