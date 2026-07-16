//! Protocol dispatch: request parsing, the ID handshake branches, and
//! CONTROL subtype handling.
//!
//! `conn.rs` is byte-level transport; this is line-level dispatch.
//! The mutating handler step lives in `Daemon` (handlers need
//! `&mut Daemon`).

use std::path::Path;
use std::time::Instant;

use rand_core::RngCore;
use tinc_crypto::sign::{PUBLIC_LEN, SigningKey};
use tinc_proto::Request;
use tinc_proto::request::{PROT_MAJOR, PROT_MINOR};
use tinc_sptps::{Framing, Output, Role, Sptps, SptpsKex, SptpsLabel};

use crate::conn::Connection;
use crate::keys::read_ecdsa_public_key;

bitflags::bitflags! {
    /// Connection option wire bits (ACK `%x` field). The top byte
    /// carries `PROT_MINOR`, not a flag; use [`ConnOptions::prot_minor`].
    ///
    /// `from_bits_retain` everywhere — unknown bits from peers must be
    /// preserved for wire compatibility.
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
    /// Protocol minor version carried in the top byte.
    #[must_use]
    pub const fn prot_minor(self) -> u8 {
        (self.bits() >> 24) as u8
    }
    /// Stamp `PROT_MINOR` into the top byte. Preserves all flag bits +
    /// unknown low bits.
    #[must_use]
    pub fn with_minor(self, m: u8) -> Self {
        Self::from_bits_retain((self.bits() & 0x00FF_FFFF) | (u32::from(m) << 24))
    }
}

// Transitional `u32` aliases. `tinc-graph` (`Edge.options`, `Route
// .options`) and `tinc-proto` (`AddEdge.options`) stay `u32` (separate
// crates, separate change). The gate sites in `tx_control.rs`/`udp_info.rs`/
// `net.rs` reading those `u32`s use these consts. The three storage
// sites (`Connection.options`, `Daemon.myself_options`, `NodeState
// .edge_options`) are `ConnOptions`; calls into the `u32` boundary go
// through `.bits()` / `from_bits_retain`. A follow-up cleans the gates
// after the udp-info-carry agent lands.
pub(crate) const OPTION_TCPONLY: u32 = ConnOptions::TCPONLY.bits();
pub(crate) const OPTION_CLAMP_MSS: u32 = ConnOptions::CLAMP_MSS.bits();

/// `myself->options` with all-defaults (no `IndirectData`/`TCPOnly`/etc
/// in tinc.conf). All-defaults falls through every `get_config_bool`:
/// PMTU + `CLAMP_MSS` + `PROT_MINOR`<<24. Daemon `setup()`
/// uses [`myself_options_from_config`]; this const is a test fixture.
#[cfg(test)]
fn myself_options_default() -> ConnOptions {
    (ConnOptions::PMTU_DISCOVERY | ConnOptions::CLAMP_MSS).with_minor(PROT_MINOR)
}

/// Build our own connection options from global config. Called once
/// at `setup()`. Returns the GLOBAL defaults that per-host
/// `IndirectData`/`TCPOnly`/`ClampMSS` OR against in [`send_ack`].
///
/// Implication chain:
///   - `TCPOnly` → also INDIRECT
///   - `PMTUDiscovery` default = `!(options & OPTION_TCPONLY)`
///   - `ClampMSS` default = on
///
/// `.ok()`: a value that fails to parse is treated as absent.
#[must_use]
pub(crate) fn myself_options_from_config(config: &tinc_conf::Config) -> ConnOptions {
    let mut opts = ConnOptions::empty().with_minor(PROT_MINOR);

    if config
        .lookup("IndirectData")
        .next()
        .and_then(|e| e.get_bool().ok())
        == Some(true)
    {
        opts |= ConnOptions::INDIRECT;
    }
    // TCPOnly implies INDIRECT.
    if config
        .lookup("TCPOnly")
        .next()
        .and_then(|e| e.get_bool().ok())
        == Some(true)
    {
        opts |= ConnOptions::TCPONLY | ConnOptions::INDIRECT;
    }
    // PMTUDiscovery defaults on, unless TCPOnly already turned it off.
    let pmtu_default = !opts.contains(ConnOptions::TCPONLY);
    if config
        .lookup("PMTUDiscovery")
        .next()
        .and_then(|e| e.get_bool().ok())
        .unwrap_or(pmtu_default)
    {
        opts |= ConnOptions::PMTU_DISCOVERY;
    }
    // ClampMSS defaults on.
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

/// Control-request subtypes. Dup of `tinc-tools::ctl::CtlRequest`
/// (daemon doesn't dep on tinc-tools). TODO: hoist to tinc-proto.
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
    /// (incl. obsolete `Restart=2`/`DumpGraph=7`/`Connect=11` which
    /// the daemon never handles).
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

// `REQ_*` aliases: protocol-style names for call sites (gossip/
// tx_control/route format these into dump rows). Typed as `CtlReq`, so
// `send_dump`/`ctl_ack` don't accept arbitrary `i32`.
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
/// Reply-only sentinel, never a request — stays a bare `i32`, not a
/// `CtlReq` variant.
const REQ_INVALID: i32 = -1;

/// Control-protocol version. Unchanged since 2007.
const CTL_VERSION: u8 = 0;

/// Result of dispatching one line. Variants distinguish the outcomes
/// that flip daemon state; `Drop` means terminate the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DispatchResult {
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
    /// `REQ_DISCONNECT`. `Some(name)` → walk conns, terminate matches,
    /// reply `"18 12 0"` if found else `"18 12 -2"`. `None` → name
    /// missing/invalid, reply `"18 12 -1"`.
    Disconnect(Option<String>),
    /// `dump_traffic(c)`. Walk nodes, emit
    /// `"18 13 NAME in_packets in_bytes out_packets out_bytes"`.
    DumpTraffic,
    /// `REQ_LOG`. Enable log streaming on this connection at the
    /// given tinc debug level (`-1..=10`); the daemon maps it to a
    /// `log::Level`. The colorize argument is ignored (no ANSI in the
    /// tap).
    Log(i32),
    /// `REQ_PCAP`. Daemon arms `conn.pcap` and the global `pcap` gate.
    /// Carries the parsed snaplen; 0 means unparsed or full. No ack
    /// reply; the CLI starts reading pcap headers immediately.
    Pcap(u16),
    /// `REQ_SET_DEBUG`. Carries the parsed level. `None` → parse
    /// failed, terminate. `Some(level)` → daemon replies with the
    /// PREVIOUS level then updates (if level >= 0; negative is
    /// query-only).
    SetDebug(Option<i32>),
    /// Handler failed; caller drops the connection.
    Drop,
}

/// Why dispatch returned `Drop`. For logging; caller action is the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DispatchError {
    /// Request number failed to parse or is out of range.
    UnknownRequest,
    /// Request not allowed in this connection state — the gate keeping
    /// peers from sending CONTROL and fresh conns from sending anything
    /// but ID.
    Unauthorized,
    /// `id_h`: cookie mismatch / bad name / version reject.
    BadId(String),
    /// ACK line malformed.
    BadAck(String),
    /// `ADD/DEL_SUBNET` parse failed.
    BadSubnet(String),
    /// `ADD/DEL_EDGE` parse failed.
    BadEdge(String),
    /// `REQ/ANS_KEY` parse failed.
    BadKey(String),
}

/// Parse the request number, bounds-check it, and apply the
/// `allow_request` gate. The handler match is the caller's. `line` has
/// no trailing `\n`.
///
/// # Errors
/// `UnknownRequest` for bad/out-of-range reqno; `Unauthorized` if gated.
pub(crate) fn check_gate(conn: &Connection, line: &[u8]) -> Result<Request, DispatchError> {
    // Stricter than C tinc's atoi (which would accept "18foo"), but
    // conforming senders always emit a bare decimal.
    let first = line
        .split(|&b| b.is_ascii_whitespace())
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(DispatchError::UnknownRequest)?;
    let s = std::str::from_utf8(first).map_err(|_| DispatchError::UnknownRequest)?;
    let reqno: i32 = s.parse().map_err(|_| DispatchError::UnknownRequest)?;

    let req = Request::from_id(reqno).ok_or(DispatchError::UnknownRequest)?;

    // `None` = all requests allowed.
    if let Some(allowed) = conn.allow_request
        && allowed != req
    {
        return Err(DispatchError::Unauthorized);
    }

    Ok(req)
}

/// SPTPS label for the TCP meta connection.
///
/// **TRAILING NUL IS WIRE-COMPAT.** C tinc includes the terminating
/// NUL in this label; it feeds the SIG transcript + PRF seed, and
/// omitting it makes the handshake fail with `BadSig`. The invitation
/// label ([`INVITE_LABEL`]) does NOT include a NUL — historical
/// accident in the C code, but it is the wire format.
///
/// Argument order: always (initiator, responder).
#[must_use]
pub(crate) fn tcp_label(initiator: &str, responder: &str) -> Vec<u8> {
    // Explicit push so the NUL is visible in source.
    let mut label = format!("tinc TCP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    debug_assert_eq!(label.len(), 25 + initiator.len() + responder.len());
    label
}

/// Node names must be `[A-Za-z0-9_]+`.
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
pub(crate) enum IdOk {
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
pub(crate) struct IdCtx<'a> {
    pub cookie: &'a str,       // control cookie, 64 hex chars
    pub my_name: &'a str,      // our node name
    pub mykey: &'a SigningKey, // our Ed25519 key
    pub confbase: &'a Path,    // for `read_ecdsa_public_key`
    /// Invitation key. `None` → `?` branch rejects.
    pub invitation_key: Option<&'a SigningKey>,
    /// Global tinc.conf `PMTU`. Clamps in addition to per-host (min
    /// wins).
    pub global_pmtu: Option<u16>,
    /// Global `SPTPSCipher` default. Per-peer override comes from
    /// `hosts/NAME` in [`load_peer_host_config`]; this is the fallback
    /// when the host file doesn't set one.
    pub sptps_cipher: tinc_sptps::SptpsAead,
    /// Global tinc.conf `SPTPSKex`. Per-host override is read in
    /// `load_peer_host_config` and stashed on the connection.
    pub sptps_kex: SptpsKex,
}

/// SPTPS label for invitation handshakes. **NO trailing NUL** — unlike
/// [`tcp_label`]; wire format.
const INVITE_LABEL: &[u8] = b"tinc invitation";

/// Handle an ID line, all three branches.
///
/// Format: `ID <name> <major>.<minor>`; minor is optional (defaults to
/// 0). Dispatch on the first byte of the name: `^`→control,
/// `?`→invitation, else peer.
///
/// # Errors
/// `BadId`: malformed, cookie mismatch, bad name, peer==self, version
/// mismatch, no pubkey, rollback.
pub(crate) fn handle_id(
    conn: &mut Connection,
    line: &[u8],
    ctx: &IdCtx<'_>,
    now: Instant,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<IdOk, DispatchError> {
    let (name_tok, major, minor) = parse_id_line(line)?;

    // Dispatch on name-token sigil. The three branches share nothing
    // after this point: control uses cookie + pid, invitation uses the
    // daemon-wide invitation key + a throwaway pubkey from the joiner,
    // peer uses hosts/NAME + mykey.
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

    id_peer(conn, name_tok, major, minor, ctx, rng)
}

/// Bare-name peer branch of the ID handshake (legacy protocol not
/// supported). The three sigil branches share only the
/// `(major, minor)` parse, so each lives in its own function and
/// `handle_id` is a sigil match.
fn id_peer(
    conn: &mut Connection,
    name_tok: &[u8],
    major: u8,
    minor: u8,
    ctx: &IdCtx<'_>,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<IdOk, DispatchError> {
    let name = std::str::from_utf8(name_tok)
        .ok()
        .filter(|s| check_id(s))
        .ok_or_else(|| {
            DispatchError::BadId(format!(
                "invalid peer name {:?}",
                String::from_utf8_lossy(name_tok)
            ))
        })?;

    // Self-edge → infinite gossip loop.
    if name == ctx.my_name {
        return Err(DispatchError::BadId(format!(
            "peer claims to be us ({name})"
        )));
    }

    // Outgoing: the name was already set by `ConnectTo`; peer must
    // confirm (DNS hijack / stale config / NAT confusion).
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

    // Legacy protocol is not supported: no pubkey → reject outright.
    let Some(ecdsa) = load_peer_host_config(conn, ctx, name) else {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) had unknown identity (no Ed25519 public key)",
            conn.name, conn.hostname
        )));
    };

    // Downgrade-attack reject: legacy protocol is forbidden, so any
    // peer for whom we have a pubkey must speak minor >= 2.
    if minor < 2 {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) tries to roll back protocol version to {major}.{minor}",
            conn.name, conn.hostname
        )));
    }

    conn.allow_request = Some(Request::Ack);

    // ORDER: our ID line must go BEFORE SPTPS KEX bytes — the peer
    // reads our ID, learns minor>=2, THEN reads KEX. KEX-first would
    // make its line reader parse ciphertext.
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

    // Label order: always (initiator, responder).
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
    let (sptps, init) = Sptps::start_with(
        role,
        Framing::Stream,
        conn.sptps_kex,
        mykey_clone,
        ecdsa,
        SptpsLabel::with_aead(label, conn.sptps_cipher),
        0, // replaywin: ignored in stream mode
        rng,
    );

    conn.sptps = Some(Box::new(sptps));

    log::info!(target: "tincd::auth",
               "Starting SPTPS handshake with {} ({})",
               conn.name, conn.hostname);

    Ok(IdOk::Peer { needs_write, init })
}

/// Parse `<reqno> <name> <major>[.<minor>]`. Major is required, minor
/// optional: control connections send `"0"` (no dot) and minor stays 0.
fn parse_id_line(line: &[u8]) -> Result<(&[u8], u8, u8), DispatchError> {
    let mut toks = line
        .split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let _reqno = toks.next(); // already dispatched on
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

/// The `^cookie` control-connection branch. Reachable only from the
/// unix control socket: `handle_id` rejects `^` when
/// `!conn.is_unix_ctl`.
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
    // Push last_ping_time an hour ahead so the ping sweep skips
    // control connections.
    conn.last_ping_time = now + std::time::Duration::from_secs(3600);
    conn.name = "<control>".to_string();

    let needs_write = conn.send(format_args!(
        "{} {} {}.{}",
        Request::Id,
        ctx.my_name,
        PROT_MAJOR,
        PROT_MINOR
    ));
    conn.send(format_args!(
        "{} {} {}",
        Request::Ack,
        CTL_VERSION,
        std::process::id()
    ));

    Ok(IdOk::Control { needs_write })
}

/// The `?`-prefixed invitation branch. Separate function because it
/// shares no state with the peer branch: it uses the daemon's
/// *invitation* key (not `mykey`), the joiner's throwaway pubkey (not
/// a hosts/ entry), and a different SPTPS label.
fn id_invitation(
    conn: &mut Connection,
    throwaway_b64: &[u8],
    ctx: &IdCtx<'_>,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<IdOk, DispatchError> {
    let Some(inv_key) = ctx.invitation_key else {
        return Err(DispatchError::BadId(format!(
            "got invitation from {} but we don't have an invitation key",
            conn.hostname
        )));
    };

    // Decode the joiner's THROWAWAY pubkey (NOT their node identity —
    // that's the later type-1 record).
    let throwaway: [u8; PUBLIC_LEN] = std::str::from_utf8(throwaway_b64)
        .ok()
        .and_then(tinc_crypto::b64::decode)
        .filter(|v| v.len() == PUBLIC_LEN)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            DispatchError::BadId(format!("got bad invitation from {}", conn.hostname))
        })?;

    // b64 of OUR invitation pubkey → line 2. The joiner hashes it and
    // compares to the URL slug.
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

    let inv_key_clone = SigningKey::from_blob(&inv_key.to_blob());
    let (sptps, init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        inv_key_clone,
        throwaway,
        // Invitations interoperate with C tinc by definition (the
        // invitee doesn't have a host file yet), so always the
        // default AEAD — which the bare-label `Into<SptpsLabel>` gives.
        INVITE_LABEL,
        0, // replaywin: ignored in stream mode
        rng,
    );
    conn.sptps = Some(Box::new(sptps));

    // Daemon sets `conn.invite` at the IdOk dispatch site.

    log::info!(target: "tincd::auth",
               "Starting invitation handshake with {}", conn.hostname);

    Ok(IdOk::Invitation { needs_write, init })
}

/// Load `hosts/NAME`, extract the pubkey + the per-host keys the ACK
/// exchange later reads, stash them on `conn`, return the pubkey.
///
/// Extracting eagerly lets the parsed `Config` drop here instead of
/// riding the connection. File-missing and file-has-no-key are
/// collapsed — either way you `tinc import`.
fn load_peer_host_config(
    conn: &mut Connection,
    ctx: &IdCtx<'_>,
    name: &str,
) -> Option<[u8; PUBLIC_LEN]> {
    let host_config = crate::keys::read_host_config(ctx.confbase, name);
    // Parse failure doesn't doom us yet — read_ecdsa_public_key can
    // still fall back to the raw PEM file below.

    let ecdsa = read_ecdsa_public_key(&host_config, ctx.confbase, name);
    conn.ecdsa = ecdsa;

    // `.ok()`: a value that fails to parse is treated as absent.
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
    // Per-peer AEAD override, falling back to the global default.
    // Unknown values are dropped (the daemon already warned at the
    // global parse if its own setting was bad; a bad per-peer value
    // surfaces as a `BadSig` against a correctly-configured peer,
    // which is the documented mismatch failure mode).
    conn.sptps_cipher =
        crate::keys::read_sptps_cipher(&host_config, name).unwrap_or(ctx.sptps_cipher);
    let host_pmtu = host_config
        .lookup("PMTU")
        .next()
        .and_then(|e| e.get_int().ok())
        .and_then(|v| u16::try_from(v).ok());
    // Per-host and global both clamp; take the min here so
    // connect.rs's single-cap clamp is correct. `Option::min` returns
    // None if EITHER is None (wrong: absent should mean "no clamp");
    // `flatten().min()` skips Nones — correct.
    conn.pmtu_cap = [host_pmtu, ctx.global_pmtu].into_iter().flatten().min();

    // Per-host override; tinc.conf default if absent. Warn-and-
    // default on parse error: a malformed `hosts/PEER` shouldn't be
    // fatal at handshake time (it wasn't for any other key above).
    conn.sptps_kex =
        crate::daemon::read_sptps_kex(&host_config, ctx.sptps_kex).unwrap_or_else(|v| {
            log::warn!(target: "tincd::auth",
                       "hosts/{name}: SPTPSKex = {v}: invalid, using {}", ctx.sptps_kex);
            ctx.sptps_kex
        });

    ecdsa
}

/// Called on SPTPS `HandshakeDone` when `allow_request == ACK`. Queues
/// `ACK <udp-port> <weight> <options-hex>` — the first line sent
/// encrypted.
///
/// SIDE EFFECT: writes `conn.options` and `conn.estimated_weight`
/// (read later when the peer's ACK arrives).
///
/// `global_weight`: tinc.conf `Weight` — fallback when per-host
/// `Weight` absent. `None` = RTT wins.
pub(crate) fn send_ack(
    conn: &mut Connection,
    my_udp_port: u16,
    myself_options: ConnOptions,
    global_weight: Option<i32>,
    now: Instant,
) -> bool {
    // Legacy protocol was already rejected in the ID handshake.
    debug_assert!(conn.protocol_minor >= 2);

    #[expect(clippy::cast_possible_truncation)] // RTT ms fits i32
    let weight = now.saturating_duration_since(conn.start).as_millis() as i32;
    // Per-host config OR global options, composed bit-by-bit; the
    // per-host fields were extracted during the ID handshake.
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
    // Per-host ClampMSS OVERRIDES global (not OR'd); absent = global
    // default sticks.
    if conn
        .host_clamp_mss
        .unwrap_or_else(|| myself_options.contains(ConnOptions::CLAMP_MSS))
    {
        opts |= ConnOptions::CLAMP_MSS;
    }
    conn.options = opts;

    // Per-host > global > RTT (fallback, not min).
    let weight = conn.host_weight.or(global_weight).unwrap_or(weight);
    conn.estimated_weight = weight;

    let wire_options = conn.options.with_minor(PROT_MINOR).bits();
    conn.send(format_args!(
        "{} {} {} {:x}",
        Request::Ack,
        my_udp_port,
        weight,
        wire_options
    ))
}

/// Parsed ACK line. The mutation half (node/edge/graph updates) lives
/// in the daemon, which owns the state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::struct_field_names)] // "his" = the peer's values
pub(crate) struct AckParsed {
    pub his_udp_port: u16,
    pub his_weight: i32,          // averaged with ours for edge weight
    pub his_options: ConnOptions, // PROT_MINOR in top byte
}

/// Parse an ACK line: `<reqno> <port> <weight> <options-hex>`.
///
/// # Errors
/// `BadAck` if any field is missing or malformed.
pub(crate) fn parse_ack(line: &[u8]) -> Result<AckParsed, DispatchError> {
    let mut toks = line
        .split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let _reqno = toks.next();
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
    let options = toks // hex
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

/// `from_utf8` → parse for the routed-message handlers. Returns the
/// decoded `&str` too because relay paths forward the original body.
///
/// # Errors
/// `BadKey` with `"non-UTF-8 {what}"` / `"{what} parse failed"`.
pub(crate) fn parse_key_msg<'a, T, E>(
    body: &'a [u8],
    what: &str,
    parse: impl FnOnce(&'a str) -> Result<T, E>,
) -> Result<(&'a str, T), DispatchError> {
    let s = std::str::from_utf8(body)
        .map_err(|_| DispatchError::BadKey(format!("non-UTF-8 {what}")))?;
    let m = parse(s).map_err(|_| DispatchError::BadKey(format!("{what} parse failed")))?;
    Ok((s, m))
}

/// Parse an `ADD_SUBNET` body. Host bits are not required to be zero;
/// non-canonical nets simply never match a lookup. This matches C tinc.
///
/// # Errors
/// `BadSubnet`: not UTF-8 or `SubnetMsg::parse` failed.
pub(crate) fn parse_add_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    parse_body(body, DispatchError::BadSubnet, |s| {
        tinc_proto::msg::SubnetMsg::parse(s).map(|m| (m.owner, m.subnet))
    })
}

/// Parse a `DEL_SUBNET` body. Same format as ADD.
///
/// # Errors
/// See [`parse_add_subnet`].
pub(crate) fn parse_del_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    parse_add_subnet(body)
}

/// Parse an `ADD_EDGE` body.
///
/// # Errors
/// `BadEdge`: not UTF-8 or `AddEdge::parse` failed.
pub(crate) fn parse_add_edge(body: &[u8]) -> Result<tinc_proto::msg::AddEdge, DispatchError> {
    parse_body(
        body,
        DispatchError::BadEdge,
        tinc_proto::msg::AddEdge::parse,
    )
}

/// Parse a `DEL_EDGE` body.
///
/// # Errors
/// `BadEdge`: not UTF-8 or `DelEdge::parse` failed.
pub(crate) fn parse_del_edge(body: &[u8]) -> Result<tinc_proto::msg::DelEdge, DispatchError> {
    parse_body(
        body,
        DispatchError::BadEdge,
        tinc_proto::msg::DelEdge::parse,
    )
}

/// Strip the trailing `\n` (if any) from an SPTPS record body.
#[must_use]
pub(crate) fn record_body(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

/// Nth whitespace-separated token of `line` as `&str` (runs of
/// whitespace collapse). Helper for `handle_control`'s parses.
fn nth_token(line: &[u8], n: usize) -> Option<&str> {
    line.split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty())
        .nth(n)
        .and_then(|t| std::str::from_utf8(t).ok())
}

/// Handle a CONTROL line: `"18 <subtype> [args...]"`.
pub(crate) fn handle_control(conn: &mut Connection, line: &[u8]) -> (DispatchResult, bool) {
    // Missing/bad subtype → drop the connection.
    let Some(raw) = nth_token(line, 1).and_then(|s| s.parse::<i32>().ok()) else {
        log::warn!(target: "tincd::proto", "Got bad CONTROL from {}", conn.name);
        return (DispatchResult::Drop, false);
    };

    match CtlReq::from_i32(raw) {
        // Daemon does the walk/reload (it has the slotmap).
        Some(REQ_RELOAD) => (DispatchResult::Reload, false),
        Some(REQ_DUMP_NODES) => (DispatchResult::DumpNodes, false),
        Some(REQ_DUMP_EDGES) => (DispatchResult::DumpEdges, false),
        Some(REQ_DUMP_SUBNETS) => (DispatchResult::DumpSubnets, false),
        Some(REQ_DUMP_CONNECTIONS) => (DispatchResult::DumpConnections, false),
        Some(REQ_RETRY) => (DispatchResult::Retry, false),
        Some(REQ_PURGE) => (DispatchResult::Purge, false),
        Some(REQ_SET_DEBUG) => {
            // Level is the 3rd token; negative values are a valid
            // query-only path (the daemon only applies levels >= 0).
            let level = nth_token(line, 2).and_then(|s| s.parse::<i32>().ok());
            // Surface to daemon: it has the log_tap atomic. The daemon
            // arm Drops on None.
            (DispatchResult::SetDebug(level), false)
        }
        Some(REQ_DISCONNECT) => {
            // Name is the 3rd token.
            let name = nth_token(line, 2)
                .filter(|s| s.len() <= tinc_proto::MAX_STRING && check_id(s))
                .map(str::to_owned);
            (DispatchResult::Disconnect(name), false)
        }
        Some(REQ_DUMP_TRAFFIC) => (DispatchResult::DumpTraffic, false),
        Some(REQ_LOG) => {
            // Level is the 3rd token, default 0 if missing. Colorize
            // (4th) ignored: we send bare `args()` from log_tap, no
            // ANSI. The daemon arm maps the tinc level to `log::Level`;
            // out-of-range values fall into a `_` arm.
            let level = nth_token(line, 2)
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
            (DispatchResult::Log(level), false)
        }
        Some(REQ_PCAP) => {
            // Snaplen is the 3rd token; missing/bad → 0 (= full).
            // Negative makes no sense → clamp to 0; saturate to u16
            // (snaplen > MTU is functionally ∞ anyway).
            let snaplen = nth_token(line, 2)
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&n| n > 0)
                .map_or(0u16, |n| u16::try_from(n).unwrap_or(u16::MAX));
            (DispatchResult::Pcap(snaplen), false)
        }
        Some(REQ_STOP) => {
            // Ack with "18 0 0", then the loop exits.
            log::info!(target: "tincd", "Got REQ_STOP, shutting down");
            let needs_write = conn.send(format_args!("{} {} 0", Request::Control, REQ_STOP));
            (DispatchResult::Stop, needs_write)
        }
        _ => {
            log::debug!(target: "tincd::proto",
                        "Unknown CONTROL subtype {raw} from {}", conn.name);
            let needs_write = conn.send(format_args!("{} {}", Request::Control, REQ_INVALID));
            (DispatchResult::Ok, needs_write)
        }
    }
}

#[cfg(test)]
mod tests;
