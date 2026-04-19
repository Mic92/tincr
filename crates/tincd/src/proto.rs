//! Protocol dispatch. Ports `protocol.c::receive_request` (`:147-195`),
//! `protocol_auth.c::id_h` (`:314-471`), `control.c::control_h` (`:45-145`).
//!
//! `conn.rs` is byte-level transport; this is line-level dispatch (the
//! C's `meta.c`/`protocol.c` split). Handler step 4 lives in `Daemon`
//! (handlers need `&mut Daemon`).

use std::path::Path;
use std::time::Instant;

use rand_core::RngCore;
use tinc_crypto::sign::{PUBLIC_LEN, SigningKey};
use tinc_proto::Request;
use tinc_proto::request::{PROT_MAJOR, PROT_MINOR};
use tinc_sptps::{Framing, Output, Role, Sptps};

use crate::conn::Connection;
use crate::keys::read_ecdsa_public_key;

bitflags::bitflags! {
    /// `OPTION_*` (`connection.h:32-36`). Wire bits (ACK `%x` field).
    /// Top byte carries `PROT_MINOR` (`OPTION_VERSION` macro, `:36`);
    /// Masked `& 0xffffff` before send.
    ///
    /// `from_bits_retain` everywhere — C accepts unknown bits, wire
    /// compat. The top byte is NOT a flag; use [`ConnOptions::prot_minor`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConnOptions: u32 {
        /// `OPTION_INDIRECT`: don't UDP-probe me directly, relay.
        const INDIRECT       = 0x0001;
        /// `OPTION_TCPONLY`: implies INDIRECT.
        const TCPONLY        = 0x0002;
        /// `OPTION_PMTU_DISCOVERY`: default on.
        const PMTU_DISCOVERY = 0x0004;
        /// `OPTION_CLAMP_MSS`: default on.
        const CLAMP_MSS      = 0x0008;
    }
}

impl ConnOptions {
    /// `OPTION_VERSION(x)` (`connection.h:36`). Top byte = `PROT_MINOR`.
    #[must_use]
    pub const fn prot_minor(self) -> u8 {
        (self.bits() >> 24) as u8
    }
    /// `connection.h:36` inverse: stamp `PROT_MINOR` into top byte.
    /// Preserves all flag bits + unknown low bits.
    #[must_use]
    pub fn with_minor(self, m: u8) -> Self {
        Self::from_bits_retain((self.bits() & 0x00FF_FFFF) | (u32::from(m) << 24))
    }
}

// Transitional `u32` aliases. `tinc-graph` (`Edge.options`, `Route
// .options`) and `tinc-proto` (`AddEdge.options`) stay `u32` (separate
// crates, separate change). The gate sites in `txpath.rs`/`udp_info.rs`/
// `net.rs` reading those `u32`s use these consts. The three storage
// sites (`Connection.options`, `Daemon.myself_options`, `NodeState
// .edge_options`) are `ConnOptions`; calls into the `u32` boundary go
// through `.bits()` / `from_bits_retain`. A follow-up cleans the gates
// after the udp-info-carry agent lands.
pub const OPTION_INDIRECT: u32 = ConnOptions::INDIRECT.bits();
pub const OPTION_TCPONLY: u32 = ConnOptions::TCPONLY.bits();
pub const OPTION_PMTU_DISCOVERY: u32 = ConnOptions::PMTU_DISCOVERY.bits();
pub const OPTION_CLAMP_MSS: u32 = ConnOptions::CLAMP_MSS.bits();

/// `myself->options` with all-defaults (no `IndirectData`/`TCPOnly`/etc
/// in tinc.conf). All-defaults falls through every `get_config_bool`:
/// PMTU + `CLAMP_MSS` + `PROT_MINOR`<<24. Daemon `setup()`
/// uses [`myself_options_from_config`]; this const is a test fixture.
#[cfg(test)]
fn myself_options_default() -> ConnOptions {
    (ConnOptions::PMTU_DISCOVERY | ConnOptions::CLAMP_MSS).with_minor(PROT_MINOR)
}

/// Build `myself->options` from global config. Called once at
/// `setup()`. Returns the GLOBAL defaults that per-host
/// `IndirectData`/`TCPOnly`/`ClampMSS` (read at `id_h` time,
/// `5ceb8011`) OR against in [`send_ack`].
///
/// Implication chain:
///   - `TCPOnly` → also INDIRECT
///   - `PMTUDiscovery` default = `!(options & OPTION_TCPONLY)`
///   - `ClampMSS` default = on
///
/// `.ok()` matches `get_config_bool`: parse-fail = absent (returns
/// `false`, doesn't write `*result`).
#[must_use]
pub(crate) fn myself_options_from_config(config: &tinc_conf::Config) -> ConnOptions {
    let mut opts = ConnOptions::empty().with_minor(PROT_MINOR);

    // `if(get_config_bool(...) && choice)`.
    if config
        .lookup("IndirectData")
        .next()
        .and_then(|e| e.get_bool().ok())
        == Some(true)
    {
        opts |= ConnOptions::INDIRECT;
    }
    // `if(TCPONLY) options |= INDIRECT`.
    if config
        .lookup("TCPOnly")
        .next()
        .and_then(|e| e.get_bool().ok())
        == Some(true)
    {
        opts |= ConnOptions::TCPONLY | ConnOptions::INDIRECT;
    }
    // `choice = !(options & TCPONLY); get_config_bool("PMTUDiscovery",
    // &choice); if(choice) options |= PMTU_DISCOVERY`. The default is
    // on UNLESS TCPOnly already set it to off.
    let pmtu_default = !opts.contains(ConnOptions::TCPONLY);
    if config
        .lookup("PMTUDiscovery")
        .next()
        .and_then(|e| e.get_bool().ok())
        .unwrap_or(pmtu_default)
    {
        opts |= ConnOptions::PMTU_DISCOVERY;
    }
    // `choice = true; get_config_bool("ClampMSS", &choice); if(choice)
    // options |= CLAMP_MSS`. Default on.
    if config
        .lookup("ClampMSS")
        .next()
        .and_then(|e| e.get_bool().ok())
        .unwrap_or(true)
    {
        opts |= ConnOptions::CLAMP_MSS;
    }

    opts
}

/// `control_common.h` request subtypes. Dup of
/// `tinc-tools::ctl::CtlRequest` (daemon doesn't dep on tinc-tools).
/// TODO: hoist to tinc-proto.
///
/// `Display` formats as the bare integer — wire format is
/// `"{Control as u8} {req} ..."` and must stay byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum CtlReq {
    Stop = 0,
    Reload = 1,
    DumpNodes = 3,
    DumpEdges = 4,
    DumpSubnets = 5,
    DumpConnections = 6,
    Purge = 8,
    SetDebug = 9,
    Retry = 10,
    Disconnect = 12,
    DumpTraffic = 13,
    Pcap = 14,
    Log = 15,
}

impl CtlReq {
    /// Parse the second int of a `CONTROL` line. `None` for unknown
    /// (incl. dead-upstream `Restart=2`/`DumpGraph=7`/`Connect=11`
    /// which the daemon never matches anyway).
    pub(crate) const fn from_i32(n: i32) -> Option<Self> {
        Some(match n {
            0 => Self::Stop,
            1 => Self::Reload,
            3 => Self::DumpNodes,
            4 => Self::DumpEdges,
            5 => Self::DumpSubnets,
            6 => Self::DumpConnections,
            8 => Self::Purge,
            9 => Self::SetDebug,
            10 => Self::Retry,
            12 => Self::Disconnect,
            13 => Self::DumpTraffic,
            14 => Self::Pcap,
            15 => Self::Log,
            _ => return None,
        })
    }
}

impl std::fmt::Display for CtlReq {
    /// Wire format: bare integer. `"{REQ_DUMP_NODES}"` → `"3"`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as i32)
    }
}

// `REQ_*` aliases: keep the C-style names at call sites (gossip/
// txpath/route format these into dump rows). Typed as `CtlReq`, so
// `send_dump`/`ctl_ack` no longer accept arbitrary `i32`.
pub(crate) const REQ_STOP: CtlReq = CtlReq::Stop;
pub(crate) const REQ_RELOAD: CtlReq = CtlReq::Reload;
pub(crate) const REQ_DUMP_NODES: CtlReq = CtlReq::DumpNodes;
pub(crate) const REQ_DUMP_EDGES: CtlReq = CtlReq::DumpEdges;
pub(crate) const REQ_DUMP_SUBNETS: CtlReq = CtlReq::DumpSubnets;
pub(crate) const REQ_DUMP_CONNECTIONS: CtlReq = CtlReq::DumpConnections;
pub(crate) const REQ_PURGE: CtlReq = CtlReq::Purge;
pub(crate) const REQ_SET_DEBUG: CtlReq = CtlReq::SetDebug;
pub(crate) const REQ_RETRY: CtlReq = CtlReq::Retry;
pub(crate) const REQ_DISCONNECT: CtlReq = CtlReq::Disconnect;
pub(crate) const REQ_DUMP_TRAFFIC: CtlReq = CtlReq::DumpTraffic;
pub(crate) const REQ_LOG: CtlReq = CtlReq::Log;
pub(crate) const REQ_PCAP: CtlReq = CtlReq::Pcap;
/// `control_common.h`: `REQ_INVALID = -1`. Reply-only sentinel, never
/// a request — stays a bare `i32`, not a `CtlReq` variant.
const REQ_INVALID: i32 = -1;

/// `TINC_CTL_VERSION_CURRENT` (`control_common.h:46`). Unchanged since 2007.
const CTL_VERSION: u8 = 0;

/// Result of dispatching one line. C handlers return `bool` (`false` =
/// drop); we disambiguate the `true` flavors that flip daemon state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    Ok,
    /// `event_exit()`. Loop finishes this turn then exits.
    Stop,
    /// `dump_connections(c)`. Daemon walks `conns` (we don't have the slotmap).
    DumpConnections,
    /// `dump_subnets(c)`.
    DumpSubnets,
    /// `dump_nodes(c)`.
    DumpNodes,
    /// `dump_edges(c)`.
    DumpEdges,
    /// `REQ_RELOAD`. Daemon reloads + replies `"18 1 <r>"`.
    Reload,
    /// `REQ_RETRY`. Daemon calls `retry()` then
    /// `control_ok` → `"18 10 0"`.
    Retry,
    /// `REQ_PURGE`. Daemon calls `purge()` then
    /// `control_ok` → `"18 8 0"`.
    Purge,
    /// `REQ_DISCONNECT`. `Some(name)` → walk
    /// conns, terminate matches, reply `"18 12 0"` if found else
    /// `"18 12 -2"`. `None` → sscanf failed (`:108`), reply `"18 12 -1"`.
    Disconnect(Option<String>),
    /// `dump_traffic(c)`. Walk nodes, emit
    /// `"18 13 NAME in_packets in_bytes out_packets out_bytes"`.
    DumpTraffic,
    /// `REQ_LOG`. `c->status.log = true`,
    /// `c->log_level = level`. C parses `level, colorize`; we parse
    /// the level and ignore colorize (no ANSI in the tap). `i32` is
    /// the C debug level (`-1..=10`); daemon maps to `log::Level`.
    Log(i32),
    /// `REQ_PCAP`. Daemon arms `conn.pcap` and
    /// the global `pcap` gate. Carries the parsed snaplen (`sscanf(
    /// "%*d %*d %d", &c->outmaclength)`); 0 means unparsed or full.
    /// NO `control_ok` reply (plain `return true`); the
    /// CLI starts reading pcap headers immediately.
    Pcap(u16),
    /// `REQ_SET_DEBUG`. Carries the parsed level. `None` → sscanf
    /// failed, terminate (`return false`).
    /// `Some(level)` → daemon replies with PREVIOUS level then
    /// updates (if level >= 0; negative is query-only).
    SetDebug(Option<i32>),
    /// Handler returned `false` (`receive_request:183-188`).
    Drop,
}

/// Why dispatch returned `Drop`. For logging; caller action is the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// `atoi()` failed or out of range.
    UnknownRequest,
    /// `c->allow_request != ALL && != reqno`. The gate keeping peers
    /// from sending CONTROL and fresh conns from sending anything but ID.
    Unauthorized,
    /// `id_h`: cookie mismatch / bad name / version reject.
    BadId(String),
    /// `ack_h`: sscanf `< 3`.
    BadAck(String),
    /// `add/del_subnet_h`: parse failed.
    BadSubnet(String),
    /// `add/del_edge_h`: parse failed.
    BadEdge(String),
    /// `req/ans_key_h`: parse failed.
    BadKey(String),
    /// `control_h`: unknown subtype. NOT a `Drop` (`control_h`
    /// returns `true`). Test-only variant.
    #[cfg(test)]
    UnknownControl,
}

/// `receive_request` step 1-3: parse reqno,
/// bounds check, `allow_request` gate. Handler match (step 4) is the
/// caller's. `line` has no trailing `\n`.
///
/// # Errors
/// `UnknownRequest` for bad/out-of-range reqno; `Unauthorized` if gated.
pub fn check_gate(conn: &Connection, line: &[u8]) -> Result<Request, DispatchError> {
    // `atoi(request)` then `if(reqno || *request == '0')`. STRICTER:
    // `atoi("18foo")` → 18 in C; we reject. C never sends that
    // (`send_request` always `"%d "`).
    let first = line
        .split(|&b| b.is_ascii_whitespace())
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(DispatchError::UnknownRequest)?;
    let s = std::str::from_utf8(first).map_err(|_| DispatchError::UnknownRequest)?;
    let reqno: i32 = s.parse().map_err(|_| DispatchError::UnknownRequest)?;

    // `is_valid_request` + handler-non-NULL.
    let req = Request::from_id(reqno).ok_or(DispatchError::UnknownRequest)?;

    // `allow_request != ALL && != reqno`. `None` = `ALL`.
    if let Some(allowed) = conn.allow_request
        && allowed != req
    {
        return Err(DispatchError::Unauthorized);
    }

    Ok(req)
}

/// SPTPS label for the TCP meta connection.
///
/// **TRAILING NUL IS WIRE-COMPAT.** `sizeof` of VLA `char label[25 +
/// strlen(a) + strlen(b)]` is one more than the snprintf'd content. The
/// NUL feeds SIG transcript + PRF seed; missing it →
/// `BadSig`. The invitation label (`:372`) does NOT have it (explicit
/// count, not VLA): historical accident, not policy.
///
/// Argument order: always (initiator, responder) (`:460-465`).
#[must_use]
pub(crate) fn tcp_label(initiator: &str, responder: &str) -> Vec<u8> {
    // Explicit push so the NUL is visible in source.
    let mut label = format!("tinc TCP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    debug_assert_eq!(label.len(), 25 + initiator.len() + responder.len()); // `25 + a + b`
    label
}

/// `check_id`: node names must be `[A-Za-z0-9_]+`.
///
/// SECURITY: load-bearing path-traversal gate. Peer name goes into
/// `hosts/NAME`. Called before `read_host_config`.
#[must_use]
fn check_id(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// What `handle_id` did. Peer/Invitation branches hand back the SPTPS
/// init outputs (`Sptps::start` emits KEX synchronously).
#[derive(Debug)]
pub enum IdOk {
    /// `^cookie` matched. id reply + ACK queued.
    Control { needs_write: bool },
    /// Peer ID accepted, SPTPS installed. Daemon must: queue `init` to
    /// outbuf, `inbuf.take_rest()` + re-feed (same TCP segment may carry
    /// initiator's KEX), then `IO_WRITE`. `needs_write` reflects ONLY the
    /// `send_id` line; OR with `send_raw`'s result.
    Peer {
        needs_write: bool,
        init: Vec<Output>,
    },
    /// `?` invitation. SPTPS installed (15-byte label, no NUL). Two
    /// plaintext lines queued. Same dispatch as `Peer`. Daemon must set
    /// `conn.invite = Some(WaitingCookie)`.
    Invitation {
        needs_write: bool,
        init: Vec<Output>,
    },
}

/// Daemon-side context for `handle_id`. Borrowed from `Daemon` to escape
/// the slotmap borrow. `mykey` is `&` not cloned: blob-roundtrip clone
/// happens inside the peer branch only.
pub struct IdCtx<'a> {
    pub cookie: &'a str,       // `controlcookie`, 64 hex chars
    pub my_name: &'a str,      // `myself->name`
    pub mykey: &'a SigningKey, // `myself->connection->ecdsa`
    pub confbase: &'a Path,    // for `read_ecdsa_public_key`
    /// `invitation_key`. `None` → `?` branch
    /// rejects (`:341-344`).
    pub invitation_key: Option<&'a SigningKey>,
    /// Global tinc.conf `PMTU`. Clamps in
    /// addition to per-host (both `&& mtu < n->mtu`, min wins).
    pub global_pmtu: Option<u16>,
}

/// `sptps_start(..., "tinc invitation", 15, ...)`.
/// **NO trailing NUL** — explicit count `15`, not `sizeof(VLA)`. See
/// [`tcp_label`] for the asymmetry.
const INVITE_LABEL: &[u8] = b"tinc invitation";

/// `id_h`. All three branches.
///
/// `sscanf("%*d " MAX_STRING " %2d.%3d", name, &major, &minor)`.
/// `< 2` → fail; `minor` optional (no `.` → sscanf returns 2, minor
/// stays 0). Dispatch on `name[0]`: `^`→control (`:325-338`),
/// `?`→invitation (`:340-373`), else peer (`:375-471`).
///
/// # Errors
/// `BadId`: malformed, cookie mismatch, bad name, peer==self, version
/// mismatch, no pubkey, rollback.
pub fn handle_id(
    conn: &mut Connection,
    line: &[u8],
    ctx: &IdCtx<'_>,
    now: Instant,
    rng: &mut impl RngCore,
) -> Result<IdOk, DispatchError> {
    let (name_tok, major, minor) = parse_id_line(line)?;

    // ─── Dispatch on name-token sigil. The three branches
    // share NOTHING after this point: control uses cookie + pid,
    // invitation uses the daemon-wide invitation key + a throwaway
    // pubkey from the joiner, peer uses hosts/NAME + mykey. Upstream
    // `id_h` keeps them inline; we split because the only thing they
    // shared was the `(major, minor)` parse above.
    if let Some(cookie) = name_tok.strip_prefix(b"^") {
        // Control is local-only: reject `^` unless accepted on the
        // unix socket. The cookie is filesystem-auth, not network-auth.
        if !conn.is_unix_ctl {
            return Err(DispatchError::BadId(format!(
                "control greeting on non-local connection ({})",
                conn.hostname
            )));
        }
        return id_control(conn, cookie, ctx, now);
    }
    if let Some(throwaway_b64) = name_tok.strip_prefix(b"?") {
        // Invitations are accept-side only; an outgoing ConnectTo peer
        // answering `?` is impersonating a joiner.
        if conn.outgoing.is_some() {
            return Err(DispatchError::BadId(format!(
                "invitation greeting on outgoing connection ({})",
                conn.hostname
            )));
        }
        return id_invitation(conn, throwaway_b64, ctx, rng);
    }

    // ─── BRANCH 3: bare name — peer (`:375-471`, legacy/bypass stripped)
    let name = std::str::from_utf8(name_tok)
        .ok()
        .filter(|s| check_id(s))
        .ok_or_else(|| {
            // `if(!check_id(name) || ...)`.
            DispatchError::BadId(format!(
                "invalid peer name {:?}",
                String::from_utf8_lossy(name_tok)
            ))
        })?;

    // `|| !strcmp(name, myself->name)`. Self-edge → infinite
    // gossip loop.
    if name == ctx.my_name {
        return Err(DispatchError::BadId(format!(
            "peer claims to be us ({name})"
        )));
    }

    // Outgoing? `c->name` already set by `ConnectTo`;
    // peer must confirm (DNS hijack / stale config / NAT confusion).
    let is_outgoing = conn.outgoing.is_some();
    if is_outgoing {
        if conn.name != name {
            return Err(DispatchError::BadId(format!(
                "peer {} is {} instead of {}",
                conn.hostname, name, conn.name
            )));
        }
    } else {
        conn.name = name.to_string();
    }

    // Major mismatch → hard reject (wire-breaking).
    if major != PROT_MAJOR {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) uses incompatible version {major}.{minor}",
            conn.name, conn.hostname
        )));
    }
    conn.protocol_minor = minor;

    // bypass_security, !experimental — SKIPPED (forbid both).

    // `if(minor && !ecdsa) minor = 1` — downgrade to
    // legacy. We forbid legacy: no pubkey → reject outright.
    let Some(ecdsa) = load_peer_host_config(conn, ctx, name) else {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) had unknown identity (no Ed25519 public key)",
            conn.name, conn.hostname
        )));
    };

    // `if(ecdsa_active && minor < 1)` — downgrade-attack
    // reject. STRICTER: we reject `< 2` (forbid legacy). A 1.1 peer for
    // whom we have a pubkey ALWAYS sends `>= 2`.
    if minor < 2 {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) tries to roll back protocol version to {major}.{minor}",
            conn.name, conn.hostname
        )));
    }

    // `allow_request = METAKEY` then `= ACK`. We skip
    // METAKEY (legacy-only).
    conn.allow_request = Some(Request::Ack);

    // `if(!c->outgoing) send_id(c)`. ORDER: this line
    // goes BEFORE SPTPS KEX bytes — peer's `receive_meta` reads our ID,
    // fires id_h, sets minor>=2, THEN reads KEX. KEX-first → readline
    // would parse ciphertext.
    let needs_write = if is_outgoing {
        false // initiator already sent in `finish_connecting`
    } else {
        conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id,
            ctx.my_name,
            PROT_MAJOR,
            PROT_MINOR
        ))
    };

    // `sptps_start(&c->sptps, c, c->outgoing, false, ...)`.
    // Label `:461-465`: always (initiator, responder).
    let label = if is_outgoing {
        tcp_label(ctx.my_name, name)
    } else {
        tcp_label(name, ctx.my_name)
    };

    // SigningKey deliberately isn't Clone; blob roundtrip makes copy visible.
    let mykey_clone = SigningKey::from_blob(&ctx.mykey.to_blob());

    let role = if is_outgoing {
        Role::Initiator
    } else {
        Role::Responder
    };
    let (sptps, init) = Sptps::start(
        role,
        Framing::Stream,
        mykey_clone,
        ecdsa,
        label,
        0, // replaywin: ignored in stream mode
        rng,
    );

    conn.sptps = Some(Box::new(sptps));

    log::info!(target: "tincd::auth",
               "Starting SPTPS handshake with {} ({})",
               conn.name, conn.hostname);

    Ok(IdOk::Peer { needs_write, init })
}

/// `sscanf("%*d %s %d.%d", name, &major, &minor)`. The `%*d` skips
/// the request number (already dispatched on). C's `< 2` check makes
/// major required but minor optional: control connections send `"0"`
/// (no dot), sscanf reads major=0, the `.` match fails, returns 2,
/// minor stays 0.
fn parse_id_line(line: &[u8]) -> Result<(&[u8], u8, u8), DispatchError> {
    let mut toks = line
        .split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let _reqno = toks.next(); // %*d — skip
    let name_tok = toks
        .next()
        .filter(|t| t.len() <= tinc_proto::MAX_STRING)
        .ok_or_else(|| DispatchError::BadId("no name token".into()))?;
    let ver = toks
        .next()
        .and_then(|t| std::str::from_utf8(t).ok())
        .ok_or_else(|| DispatchError::BadId("no version token".into()))?;
    let mut parts = ver.splitn(2, '.');
    let major = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| DispatchError::BadId(format!("bad major in {ver:?}")))?;
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok((name_tok, major, minor))
}

/// `id_h` `:325-338` — the `^cookie` control-connection branch.
/// Reachable only from the unix control socket: `handle_id` rejects
/// `^` when `!conn.is_unix_ctl`.
fn id_control(
    conn: &mut Connection,
    cookie: &[u8],
    ctx: &IdCtx<'_>,
    now: Instant,
) -> Result<IdOk, DispatchError> {
    use subtle::ConstantTimeEq;
    if cookie.ct_eq(ctx.cookie.as_bytes()).unwrap_u8() == 0 {
        return Err(DispatchError::BadId("cookie mismatch".into()));
    }

    conn.control = true;
    conn.allow_request = Some(Request::Control);
    // `:328`: `last_ping_time = now + 3600` — exempt from ping sweep.
    conn.last_ping_time = now + std::time::Duration::from_secs(3600);
    conn.name = "<control>".to_string();

    // `if(!c->outgoing) send_id(c)`: `"%d %s %d.%d"`.
    let needs_write = conn.send(format_args!(
        "{} {} {}.{}",
        Request::Id,
        ctx.my_name,
        PROT_MAJOR,
        PROT_MINOR
    ));
    // `"%d %d %d", ACK, CTL_VER, getpid()`.
    conn.send(format_args!(
        "{} {} {}",
        Request::Ack,
        CTL_VERSION,
        std::process::id()
    ));

    Ok(IdOk::Control { needs_write })
}

/// `id_h` `:340-373` — the `?`-prefixed invitation branch. Extracted
/// from `handle_id` because it shares no state with the peer branch:
/// it uses the daemon's *invitation* key (not `mykey`), the joiner's
/// throwaway pubkey (not a hosts/ entry), and a different SPTPS label.
/// Returning early from `handle_id` keeps the three ID-prefix cases
/// (`^` control, `?` invite, bare peer) symmetric.
fn id_invitation(
    conn: &mut Connection,
    throwaway_b64: &[u8],
    ctx: &IdCtx<'_>,
    rng: &mut impl RngCore,
) -> Result<IdOk, DispatchError> {
    // `if(!invitation_key)` → reject.
    let Some(inv_key) = ctx.invitation_key else {
        return Err(DispatchError::BadId(format!(
            "got invitation from {} but we don't have an invitation key",
            conn.hostname
        )));
    };

    // Decode joiner's THROWAWAY pubkey (NOT their node
    // identity — that's the later type-1 record).
    let throwaway: [u8; PUBLIC_LEN] = std::str::from_utf8(throwaway_b64)
        .ok()
        .and_then(tinc_crypto::b64::decode)
        .filter(|v| v.len() == PUBLIC_LEN)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            DispatchError::BadId(format!("got bad invitation from {}", conn.hostname))
        })?;

    // b64 of OUR invitation pubkey → line 2. Joiner
    // hashes + compares to URL slug (`fingerprint_hash`).
    let inv_pub_b64 = tinc_crypto::b64::encode(inv_key.public_key());

    // Line 1. PLAINTEXT (sptps not installed yet).
    let mut needs_write = conn.send(format_args!(
        "{} {} {}.{}",
        Request::Id,
        ctx.my_name,
        PROT_MAJOR,
        PROT_MINOR
    ));

    // Line 2, ACK with our invitation pubkey. Plaintext.
    needs_write |= conn.send(format_args!("{} {}", Request::Ack, inv_pub_b64));

    // Cosmetic for us (`feed()` checks `sptps.is_some()`).
    conn.protocol_minor = 2;

    // `sptps_start(..., false, false, ..., "tinc invitation", 15, ...)`.
    let inv_key_clone = SigningKey::from_blob(&inv_key.to_blob());
    let (sptps, init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        inv_key_clone,
        throwaway,
        INVITE_LABEL,
        0, // replaywin: ignored in stream mode
        rng,
    );
    conn.sptps = Some(Box::new(sptps));

    // `c->status.invitation = true`. Daemon sets
    // `conn.invite` at the IdOk dispatch site.

    log::info!(target: "tincd::auth",
               "Starting invitation handshake with {}", conn.hostname);

    Ok(IdOk::Invitation { needs_write, init })
}

/// Load `hosts/NAME`, extract the pubkey + the 5 keys `send_ack`/`ack_h`
/// later read, stash them on `conn`, return the pubkey.
///
/// Upstream retains `c->config_tree` through `ack_h`; we extract
/// eagerly so the `Config` `HashMap` drops here instead of riding the
/// connection. C distinguishes file-missing (`:428` "unknown identity")
/// from file-has-no-key; we collapse — either way you `tinc import`.
fn load_peer_host_config(
    conn: &mut Connection,
    ctx: &IdCtx<'_>,
    name: &str,
) -> Option<[u8; PUBLIC_LEN]> {
    let host_file = ctx.confbase.join("hosts").join(name);
    let mut host_config = tinc_conf::Config::default();
    if let Ok(entries) = tinc_conf::parse_file(&host_file) {
        host_config.merge(entries);
    }
    // Parse failure doesn't doom us yet — read_ecdsa_public_key
    // source 3 (raw PEM) gets a chance below.

    let ecdsa = read_ecdsa_public_key(&host_config, ctx.confbase, name);
    conn.ecdsa = ecdsa;

    // `.ok()` matches `get_config_bool` semantics: parse-fail =
    // absent (returns false, doesn't write `*result`).
    conn.host_indirect = host_config
        .lookup("IndirectData")
        .next()
        .and_then(|e| e.get_bool().ok());
    conn.host_tcponly = host_config
        .lookup("TCPOnly")
        .next()
        .and_then(|e| e.get_bool().ok());
    conn.host_clamp_mss = host_config
        .lookup("ClampMSS")
        .next()
        .and_then(|e| e.get_bool().ok());
    conn.host_weight = host_config
        .lookup("Weight")
        .next()
        .and_then(|e| e.get_int().ok());
    let host_pmtu = host_config
        .lookup("PMTU")
        .next()
        .and_then(|e| e.get_int().ok())
        .and_then(|v| u16::try_from(v).ok());
    // Per-host then global, both clamp (`&& mtu < n->mtu`). Compute
    // min here so connect.rs's single-cap clamp is correct.
    // `Option::min` returns None if EITHER is None (wrong: absent
    // should mean "no clamp", not "win"). `flatten().min()` skips
    // Nones — correct.
    conn.pmtu_cap = [host_pmtu, ctx.global_pmtu].into_iter().flatten().min();

    ecdsa
}

/// `send_ack`. Called on SPTPS `HandshakeDone` when
/// `allow_request == ACK`. Queues
/// `"%d %s %d %x"` = `ACK myport.udp weight options`. First line through
/// `sptps_send_record` (encrypted).
///
/// SIDE EFFECT: writes `conn.options` and `conn.estimated_weight` (read
/// by `ack_h` at `:996-999`, `:1048`).
///
/// `global_weight`: tinc.conf `Weight` —
/// fallback when per-host `Weight` absent. `None` = RTT wins.
pub fn send_ack(
    conn: &mut Connection,
    my_udp_port: u16,
    myself_options: ConnOptions,
    global_weight: Option<i32>,
    now: Instant,
) -> bool {
    // Legacy upgrade. Forbidden; id_h already rejected.
    debug_assert!(conn.protocol_minor >= 2);

    // RTT ms: C `(int)` wraps too
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let weight = now.saturating_duration_since(conn.start).as_millis() as i32;
    // Per-host config OR myself->options. Composes
    // bit-by-bit; the per-host fields were extracted at id_h.
    let mut opts = ConnOptions::empty();
    // IndirectData per-host (yes only) OR global.
    if conn.host_indirect == Some(true) || myself_options.contains(ConnOptions::INDIRECT) {
        opts |= ConnOptions::INDIRECT;
    }
    // TCPOnly implies INDIRECT.
    if conn.host_tcponly == Some(true) || myself_options.contains(ConnOptions::TCPONLY) {
        opts |= ConnOptions::TCPONLY | ConnOptions::INDIRECT;
    }
    // PMTU only if global says so AND we're not TCP-only
    // — this is the load-bearing bit. Without it, per-host TCPOnly
    // still left PMTU set, peer wastes udp_discovery_timeout probing
    // a path the user already told us is broken.
    if myself_options.contains(ConnOptions::PMTU_DISCOVERY) && !opts.contains(ConnOptions::TCPONLY)
    {
        opts |= ConnOptions::PMTU_DISCOVERY;
    }
    // Per-host ClampMSS OVERRIDES global (not OR'd).
    // `get_config_bool` writes through only on success, so absent =
    // global default sticks.
    if conn
        .host_clamp_mss
        .unwrap_or_else(|| myself_options.contains(ConnOptions::CLAMP_MSS))
    {
        opts |= ConnOptions::CLAMP_MSS;
    }
    conn.options = opts;

    // Per-host > global > RTT. `if(!get_host) get_global`
    // — fallback, not min. RTT (`:838`) loses to either config.
    let weight = conn.host_weight.or(global_weight).unwrap_or(weight);
    conn.estimated_weight = weight;

    // `"%d %s %d %x"`. `myport.udp` is a STRING upstream; same
    // wire bytes either way.
    let wire_options = conn.options.with_minor(PROT_MINOR).bits();
    conn.send(format_args!(
        "{} {} {} {:x}",
        Request::Ack,
        my_udp_port,
        weight,
        wire_options
    ))
}

/// What `ack_h` parsed. Mutation half (`node_add`/`edge_add`/`graph()`)
/// lives in the daemon (it owns the slotmap; C has globals).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckParsed {
    pub his_udp_port: u16,        // `%s` in C (string); everyone sends decimal
    pub his_weight: i32,          // averaged with ours for edge weight
    pub his_options: ConnOptions, // PROT_MINOR in top byte
}

/// `ack_h` parse half. `sscanf("%*d %s
/// %d %x")` (`:960`). Mutation half (`:965-1064`) lives in daemon.
///
/// # Errors
/// `BadAck` if sscanf would return `< 3`.
pub fn parse_ack(line: &[u8]) -> Result<AckParsed, DispatchError> {
    // STRICTER: `%s` reads any non-whitespace; we want u16. Never
    // sends non-numeric.
    let mut toks = line
        .split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let _reqno = toks.next(); // %*d
    let port = toks
        .next()
        .and_then(|t| std::str::from_utf8(t).ok())
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| DispatchError::BadAck("bad port".into()))?;
    let weight = toks
        .next()
        .and_then(|t| std::str::from_utf8(t).ok())
        .and_then(|s| s.parse::<i32>().ok())
        .ok_or_else(|| DispatchError::BadAck("bad weight".into()))?
        .max(0); // negative weight would bias MST/nexthop tie-breaks
    let options = toks // `%x`
        .next()
        .and_then(|t| std::str::from_utf8(t).ok())
        .and_then(|s| u32::from_str_radix(s, 16).ok())
        .ok_or_else(|| DispatchError::BadAck("bad options".into()))?;

    Ok(AckParsed {
        his_udp_port: port,
        his_weight: weight,
        his_options: ConnOptions::from_bits_retain(options),
    })
}

// Thin parse wrappers. Same parse/mutate split as parse_ack. Body has
// `\n` stripped; tinc-proto parsers do `check_id` + `from != to`.

/// `from_utf8` → tinc-proto parse, mapping both failures to the given
/// `DispatchError` variant with fixed message text.
fn parse_body<T, E>(
    body: &[u8],
    err: fn(String) -> DispatchError,
    parse: impl FnOnce(&str) -> Result<T, E>,
) -> Result<T, DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| err("not UTF-8".into()))?;
    parse(s).map_err(|_| err("parse failed".into()))
}

/// `add_subnet_h` parse. NB: `add_subnet_h`
/// does NOT `subnetcheck` (host bits zero) — relies on `lookup_subnet`
/// not finding non-canonical nets. We match.
///
/// # Errors
/// `BadSubnet`: not UTF-8 or `SubnetMsg::parse` failed.
pub fn parse_add_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    parse_body(body, DispatchError::BadSubnet, |s| {
        tinc_proto::msg::SubnetMsg::parse(s).map(|m| (m.owner, m.subnet))
    })
}

/// `del_subnet_h` parse. Same format as ADD.
///
/// # Errors
/// See [`parse_add_subnet`].
pub fn parse_del_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    parse_add_subnet(body)
}

/// `add_edge_h` parse.
///
/// # Errors
/// `BadEdge`: not UTF-8 or `AddEdge::parse` failed.
pub fn parse_add_edge(body: &[u8]) -> Result<tinc_proto::msg::AddEdge, DispatchError> {
    parse_body(
        body,
        DispatchError::BadEdge,
        tinc_proto::msg::AddEdge::parse,
    )
}

/// `del_edge_h` parse.
///
/// # Errors
/// `BadEdge`: not UTF-8 or `DelEdge::parse` failed.
pub fn parse_del_edge(body: &[u8]) -> Result<tinc_proto::msg::DelEdge, DispatchError> {
    parse_body(
        body,
        DispatchError::BadEdge,
        tinc_proto::msg::DelEdge::parse,
    )
}

/// Strip trailing `\n` from SPTPS record body.
/// C check is conditional; in practice `send_request` always appends.
#[must_use]
pub fn record_body(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

/// Nth whitespace-separated token of `line` as `&str` (skips empty tokens,
/// i.e. runs of whitespace collapse). Helper for `handle_control`'s
/// `sscanf("%*d %*d %d", ...)`-style parses.
fn nth_token(line: &[u8], n: usize) -> Option<&str> {
    line.split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty())
        .nth(n)
        .and_then(|t| std::str::from_utf8(t).ok())
}

/// `control_h`. Line: `"18 <subtype> [args...]"`. Never `Drop` —
/// `control_h` always returns `true`; CLI closes its end.
///
/// `single_match_else`: this is the `switch`; it grows arms.
#[allow(clippy::single_match_else)] // this is the C switch; arms accrete as ctl subcommands land
pub fn handle_control(conn: &mut Connection, line: &[u8]) -> (DispatchResult, bool) {
    // `sscanf("%*d %d", &type)`.
    let raw = nth_token(line, 1).and_then(|s| s.parse::<i32>().ok());

    match raw.and_then(CtlReq::from_i32) {
        // Daemon does the walk/reload (it has the slotmap).
        Some(REQ_RELOAD) => (DispatchResult::Reload, false),
        Some(REQ_DUMP_NODES) => (DispatchResult::DumpNodes, false),
        Some(REQ_DUMP_EDGES) => (DispatchResult::DumpEdges, false),
        Some(REQ_DUMP_SUBNETS) => (DispatchResult::DumpSubnets, false),
        Some(REQ_DUMP_CONNECTIONS) => (DispatchResult::DumpConnections, false),
        Some(REQ_RETRY) => (DispatchResult::Retry, false),
        Some(REQ_PURGE) => (DispatchResult::Purge, false),
        Some(REQ_SET_DEBUG) => {
            // `sscanf("%*d %*d %d", &new_level)`.
            // `!= 1` → `return false` (drop). The level is the 3rd
            // token. `%d` accepts negative — the CLI never sends
            // one, but the gate is `>= 0` so it's a
            // valid query-only path.
            let level = nth_token(line, 2).and_then(|s| s.parse::<i32>().ok());
            // Surface to daemon: it has the log_tap atomic. The
            // daemon arm Drops on None (`return false`).
            (DispatchResult::SetDebug(level), false)
        }
        Some(REQ_DISCONNECT) => {
            // `sscanf("%*d %*d " MAX_STRING, name)`. Third
            // whitespace token. `%s` stops at whitespace; we do too.
            let name = nth_token(line, 2)
                .filter(|s| s.len() <= tinc_proto::MAX_STRING && check_id(s))
                .map(str::to_owned);
            (DispatchResult::Disconnect(name), false)
        }
        Some(REQ_DUMP_TRAFFIC) => (DispatchResult::DumpTraffic, false),
        Some(REQ_LOG) => {
            // `int level = 0, colorize = 0;
            // sscanf("%*d %*d %d %d", &level, &colorize)`.
            // Default 0 if missing (C's local-init). Third token.
            // Colorize (4th) ignored: we send bare `args()` from
            // log_tap, no ANSI. `CLAMP(level, DEBUG_UNSET,
            // DEBUG_SCARY_THINGS)` = `[-1, 10]`. The daemon arm
            // maps to `log::Level`; clamp happens implicitly (the
            // C-to-Level table has a `_` arm).
            let level = nth_token(line, 2)
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
            (DispatchResult::Log(level), false)
        }
        Some(REQ_PCAP) => {
            // `sscanf("%*d %*d %d", &c->outmaclength)`.
            // sscanf failure leaves outmaclength untouched (0 from
            // xzalloc) — same here: missing/bad token → 0. Negative
            // snaplen makes no sense; %d would accept it but the
            // `outmaclength && outmaclength < len`
            // gate is harmless (negative-int < positive-len always true,
            // so it'd clip to a negative — BUT `send_meta` length is
            // `int` and would overflow). The CLI sends 0 or small
            // positive (`stream.rs:537`). We clamp negative → 0, and
            // saturate to u16 (snaplen > MTU is functionally ∞ anyway).
            let snaplen = nth_token(line, 2)
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&n| n > 0)
                .map_or(0u16, |n| u16::try_from(n).unwrap_or(u16::MAX));
            (DispatchResult::Pcap(snaplen), false)
        }
        Some(REQ_STOP) => {
            // `event_exit(); return control_ok(c, REQ_STOP)`
            // → `"18 0 0"`.
            log::info!(target: "tincd", "Got REQ_STOP, shutting down");
            let needs_write = conn.send(format_args!("{} {} 0", Request::Control, REQ_STOP));
            (DispatchResult::Stop, needs_write)
        }
        _ => {
            // default → `"%d %d", CONTROL, REQ_INVALID`.
            // Malformed (`subtype = None`) lands here too — same as C
            // (uninit `type` falls through to default).
            log::debug!(target: "tincd::proto",
                        "Unknown CONTROL subtype {raw:?} from {}", conn.name);
            let needs_write = conn.send(format_args!("{} {}", Request::Control, REQ_INVALID));
            (DispatchResult::Ok, needs_write)
        }
    }
}

#[cfg(test)]
mod tests;
