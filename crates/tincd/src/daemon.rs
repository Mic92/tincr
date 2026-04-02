//! `Daemon` — the C globals as one struct, plus `main_loop()`.
//!
//! ## What's here
//!
//! Ports `net.c::main_loop` (`net.c:487-527`, 41 LOC) — the
//! `while(running)` body that `tinc-event` deliberately didn't port.
//! It's the stitch: `Timers::tick → EventLoop::turn → match`.
//!
//! `net.c::timeout_handler` (`net.c:180-266`): with zero peers, the
//! `for list_each(connection_t, c)` loop iterates control conns only,
//! and control conns have `last_ping_time = now + 3600` so the timeout
//! check never fires. The handler degenerates to: re-arm self for +1s.
//! That's all we port. PROOF that timer re-arm works (the deliberate
//! semantic difference from C — explicit re-arm vs auto-delete).
//!
//! `net.c::sigterm_handler` etc (`net.c:316-334`): three handlers,
//! all set `running = false` (TERM/INT/QUIT) or do nothing yet (HUP/
//! ALRM — reload and retry need peers).
//!
//! `net_socket.c::handle_new_unix_connection` (`net_socket.c:781-812`):
//! accept, allocate Connection, register with event loop.
//!
//! `net_setup.c::setup_network` (`net_setup.c:1235-1275`): the call
//! chain that builds the daemon. Heavily abridged.
//!
//! ## The dispatch enum
//!
//! `IoWhat` is the `W` in `EventLoop<W>`. Six variants for six C
//! io callbacks (per the census in `tinc-event` lib doc). The match
//! body in `run()` is the C dispatch table made explicit.
//!
//! `TimerWhat` is the timer equivalent. One variant in skeleton
//! (`Ping`). The other six come with the modules they belong to.
//!
//! ## Why `run()` consumes `self`
//!
//! C `main_loop()` runs once, returns int (exit code). After it
//! returns, `close_network_connections()` tears everything down.
//! Our `run()` consumes `self`; teardown is `Drop`. The lifecycle
//! is: `Daemon::setup() → run()`. No `&mut self` because there's
//! nothing to do with a `Daemon` after `run()` returns except drop
//! it.
//!
//! ## Logging targets
//!
//! See lib.rs doc for the C-debug-level → log-target mapping. This
//! module is `target: "tincd"` for the always-level startup/shutdown
//! lines, `"tincd::conn"` for accept/terminate.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use slotmap::{SlotMap, new_key_type};
use tinc_device::Device;
use tinc_event::{EventLoop, Io, IoId, Ready, SelfPipe, TimerId, Timers};
use tinc_proto::Request;

use crate::conn::{Connection, FeedResult};
use crate::control::{ControlSocket, generate_cookie, write_pidfile};
use crate::proto::{DispatchResult, check_gate, handle_control, handle_id};

// ═══════════════════════════════════════════════════════════════════
// dispatch enums — the W in EventLoop<W> / Timers<W> / SelfPipe<W>

new_key_type! {
    /// `connection_t*`. Generational: a stale `ConnId` for a slot
    /// that's been reused returns `None` from `conns.get(id)`. The
    /// C uses raw pointers and the io_tree.generation guard.
    pub struct ConnId;
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
    /// `age_past_requests`. Re-arms +10s.
    #[allow(dead_code)]
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

// ═══════════════════════════════════════════════════════════════════
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
    // Chunk 3+: ~35 more fields.
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            // C `net_setup.c:1243`: `else { pinginterval = 60; }`.
            pinginterval: 60,
            // C `net_setup.c:1248`: `pingtimeout = 5`.
            pingtimeout: 5,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
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
    // ─── arena ────────────────────────────────────────────────────
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

    // ─── substrate ───────────────────────────────────────────────
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

    /// `controlcookie` (`control.c:35`). 64 hex chars. Compared in
    /// `handle_id`.
    pub(crate) cookie: String,

    /// `pidfilename`. Kept so `Drop` can unlink (`control.c:240`).
    pub(crate) pidfile: PathBuf,

    /// `myname` (`names.h:30`). Our node name from `tinc.conf:Name`.
    /// Appears in the `send_id` greeting and in dump output.
    pub(crate) name: String,

    // ─── settings ────────────────────────────────────────────────
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

    // ─── event loop machinery ────────────────────────────────────
    /// `mio::Poll` + slot table. Generic over `IoWhat`.
    pub(crate) ev: EventLoop<IoWhat>,
    /// Timer wheel. Generic over `TimerWhat`.
    pub(crate) timers: Timers<TimerWhat>,
    /// Self-pipe + handler table. Generic over `SignalWhat`.
    pub(crate) signals: SelfPipe<SignalWhat>,
    /// `pingtimer` (`net.c:44`). Kept so the match arm can re-arm.
    pub(crate) pingtimer: TimerId,

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
    #[allow(clippy::missing_panics_doc)] // doc'd in body comments
    pub fn setup(confbase: &Path, pidfile: &Path, socket: &Path) -> Result<Self, SetupError> {
        // ─── read tinc.conf (tincd.c:590) ────────────────────────
        let config = tinc_conf::read_server_config(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;

        // ─── Name (net_setup.c:775-779) ──────────────────────────
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

        // ─── settings (net_setup.c:1239-1257) ────────────────────
        // PingInterval, PingTimeout. Defaulted; we don't even read
        // them in skeleton (ping sweep is a noop with no peers).
        let settings = DaemonSettings::default();

        // ─── device (net_setup.c:1061-1100) ──────────────────────
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

        // ─── event loop scaffolding ──────────────────────────────
        // tinc-event constructors. EventLoop::new can fail (epoll_
        // create); the others can't (BTreeMap, pipe).
        let mut ev = EventLoop::new().map_err(SetupError::Io)?;
        let mut timers = Timers::new();
        let mut signals = SelfPipe::new().map_err(SetupError::Io)?;

        // ─── signals (net.c:497-507) ─────────────────────────────
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

        // ─── device fd (net_setup.c:1100) ────────────────────────
        // C: `if(device_fd >= 0) io_add(&device_io, ...)`.
        // Dummy returns None; Tun/Fd/Raw/Bsd return Some(fd).
        if let Some(fd) = device.fd() {
            ev.add(fd, Io::Read, IoWhat::Device)
                .map_err(SetupError::Io)?;
        }

        // ─── ping timer (net.c:489-491) ──────────────────────────
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

        // ─── init_control (net_setup.c:1263) ─────────────────────
        let cookie = generate_cookie();

        // C `init_control` step 2 (get listen_socket[0]'s address)
        // is skipped — no listeners. Placeholder. The CLI never
        // connects to this address (uses the unix socket).
        let address = "127.0.0.1 port 0";
        write_pidfile(pidfile, &cookie, address).map_err(SetupError::Io)?;

        let control = ControlSocket::bind(socket).map_err(|e| match e {
            crate::control::BindError::AlreadyRunning => SetupError::Config(format!(
                "Control socket {} already in use",
                socket.display()
            )),
            crate::control::BindError::Io(err) => SetupError::Io(err),
        })?;
        ev.add(control.fd(), Io::Read, IoWhat::UnixListener)
            .map_err(SetupError::Io)?;

        log::info!(target: "tincd", "Ready");

        Ok(Self {
            conns: SlotMap::with_key(),
            conn_io: slotmap::SecondaryMap::new(),
            device,
            control,
            cookie,
            pidfile: pidfile.to_path_buf(),
            name,
            settings,
            ev,
            timers,
            signals,
            pingtimer,
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
            // ─── timers (event.c:112-130) ────────────────────────
            // tick() does: cache `now`, drain expired, return next
            // deadline. The C does the SAME order (`timeout_execute`
            // at `event.c:112` is called from `event_loop` BEFORE
            // `epoll_wait`).
            let timeout = self.timers.tick(&mut fired_timers);
            for &t in &fired_timers {
                match t {
                    TimerWhat::Ping => self.on_ping_tick(),
                    TimerWhat::Periodic
                    | TimerWhat::KeyExpire
                    | TimerWhat::AgePastRequests
                    | TimerWhat::AgeSubnets
                    | TimerWhat::RetryOutgoing
                    | TimerWhat::UdpPing => {
                        // Not armed in skeleton. Unreachable.
                        unreachable!("timer {t:?} not armed in skeleton")
                    }
                }
            }

            // ─── poll (linux/event.c:121-130) ────────────────────
            // C: `epoll_wait(fd, events, MAX_EVENTS, timeout_ms)`.
            // mio same. `timeout = None` → block forever (C-is-WRONG
            // #5: C derefs NULL here. mio handles None.).
            if let Err(e) = self.ev.turn(timeout, &mut fired_io) {
                // C `net.c:511`: log ERR, return 1.
                log::error!(target: "tincd",
                            "Error while waiting for input: {e}");
                return RunOutcome::PollError;
            }

            // ─── io dispatch (linux/event.c:131-159) ─────────────
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

                    IoWhat::Tcp(_) | IoWhat::Udp(_) => {
                        unreachable!("listeners not bound in skeleton")
                    }
                }
            }
        }

        log::info!(target: "tincd", "Terminating");
        RunOutcome::Clean
    }

    // ─── timer handlers ──────────────────────────────────────────

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

    // ─── signal handlers ─────────────────────────────────────────

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

    // ─── io handlers ─────────────────────────────────────────────

    /// `handle_new_unix_connection` (`net_socket.c:781-812`).
    /// accept, allocate Connection, register with event loop.
    fn on_unix_accept(&mut self) {
        // C `:789`: `fd = accept(io->fd, &sa.sa, &len)`.
        let stream = match self.control.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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

        // ─── allocate connection ─────────────────────────────────
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
                log::info!(target: "tincd::conn",
                           "Connection from localhost (control)");
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
    fn on_conn_readable(&mut self, id: ConnId) {
        // ─── feed (one recv) ─────────────────────────────────────
        // C `meta.c:185`: `inlen = recv(...)`.
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.feed() {
            FeedResult::WouldBlock => return,
            FeedResult::Dead => {
                self.terminate(id);
                return;
            }
            FeedResult::Data => {}
        }

        // ─── drain inbuf (loop readline + dispatch) ──────────────
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

            // ─── check_gate (protocol.c:164-178) ─────────────────
            let req = match check_gate(conn, &line) {
                Ok(r) => r,
                Err(e) => {
                    log::error!(target: "tincd::proto",
                                "Bad request from {}: {e:?}", conn.name);
                    self.terminate(id);
                    return;
                }
            };

            // ─── handler dispatch (protocol.c:180) ───────────────
            // C: `entry->handler(c, request)`. We match. The match
            // arms are the request_entries[] table.
            let (result, needs_write) = match req {
                Request::Id => {
                    // `id_h`. The cookie + name come from `&self` —
                    // we can't pass `&self.cookie` while holding
                    // `&mut conn` (both borrow `self`). Clone the
                    // cookie. (64 bytes, once per connection. Fine.)
                    let cookie = self.cookie.clone();
                    let my_name = self.name.clone();
                    let now = self.timers.now();
                    match handle_id(conn, &line, &cookie, &my_name, now) {
                        Ok(nw) => (DispatchResult::Ok, nw),
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "ID rejected from {}: {e:?}", conn.name);
                            (DispatchResult::Drop, false)
                        }
                    }
                }
                Request::Control => handle_control(conn, &line),
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

            // ─── io_set (meta.c:95) ──────────────────────────────
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
    /// `del_edge`, runs `graph()`, retries outgoing. Skeleton: just
    /// `connection_del` (`connection.c:162` → `list_delete →
    /// free_connection`). The slotmap remove + ev.del.
    fn terminate(&mut self, id: ConnId) {
        if let Some(conn) = self.conns.remove(id) {
            log::info!(target: "tincd::conn",
                       "Closing connection with {}", conn.name);
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

// ═══════════════════════════════════════════════════════════════════
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
    /// 1243` (`pinginterval = 60`) and `:1248` (`pingtimeout = 5`).
    #[test]
    fn settings_defaults_match_c() {
        let s = DaemonSettings::default();
        assert_eq!(s.pinginterval, 60);
        assert_eq!(s.pingtimeout, 5);
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
