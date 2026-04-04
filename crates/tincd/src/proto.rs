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
    /// C masks `& 0xffffff` before send (`protocol_auth.c:867`).
    ///
    /// `from_bits_retain` everywhere — C accepts unknown bits, wire
    /// compat. The top byte is NOT a flag; use [`ConnOptions::prot_minor`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConnOptions: u32 {
        /// `OPTION_INDIRECT`: don't UDP-probe me directly, relay.
        const INDIRECT       = 0x0001;
        /// `OPTION_TCPONLY`: implies INDIRECT.
        const TCPONLY        = 0x0002;
        /// `OPTION_PMTU_DISCOVERY`: default on (`net_setup.c:442-446`).
        const PMTU_DISCOVERY = 0x0004;
        /// `OPTION_CLAMP_MSS`: default on (`net_setup.c:449-453`).
        const CLAMP_MSS      = 0x0008;
    }
}

impl ConnOptions {
    /// `OPTION_VERSION(x)` (`connection.h:36`). Top byte = `PROT_MINOR`.
    #[must_use]
    pub fn prot_minor(self) -> u8 {
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
/// in tinc.conf). `net_setup.c:800` after `:383-453` falls through every
/// `get_config_bool`: PMTU + CLAMP_MSS + PROT_MINOR<<24. Daemon `setup()`
/// uses [`myself_options_from_config`]; this const is a test fixture.
#[cfg(test)]
fn myself_options_default() -> ConnOptions {
    (ConnOptions::PMTU_DISCOVERY | ConnOptions::CLAMP_MSS).with_minor(PROT_MINOR)
}

/// Build `myself->options` from global config (`net_setup.c:383-393,
/// 442-453,800`). Called once at `setup()`. Returns the GLOBAL defaults
/// that per-host `IndirectData`/`TCPOnly`/`ClampMSS` (read at id_h time,
/// `5ceb8011`) OR against in [`send_ack`].
///
/// Implication chain matches C exactly:
///   - `:391` `TCPOnly` → also INDIRECT
///   - `:442` `PMTUDiscovery` default = `!(options & OPTION_TCPONLY)`
///   - `:449` `ClampMSS` default = on
///
/// `.ok()` matches C `get_config_bool`: parse-fail = absent (returns
/// `false`, doesn't write `*result`).
#[must_use]
pub(crate) fn myself_options_from_config(config: &tinc_conf::Config) -> ConnOptions {
    let mut opts = ConnOptions::empty().with_minor(PROT_MINOR);

    // C `:383-385`: `if(get_config_bool(...) && choice)`.
    if config
        .lookup("IndirectData")
        .next()
        .and_then(|e| e.get_bool().ok())
        == Some(true)
    {
        opts |= ConnOptions::INDIRECT;
    }
    // C `:387-389` + `:391-393` `if(TCPONLY) options |= INDIRECT`.
    if config
        .lookup("TCPOnly")
        .next()
        .and_then(|e| e.get_bool().ok())
        == Some(true)
    {
        opts |= ConnOptions::TCPONLY | ConnOptions::INDIRECT;
    }
    // C `:442-447`: `choice = !(options & TCPONLY); get_config_bool(
    // "PMTUDiscovery", &choice); if(choice) options |= PMTU_DISCOVERY`.
    // The default is on UNLESS TCPOnly already set it to off.
    let pmtu_default = !opts.contains(ConnOptions::TCPONLY);
    if config
        .lookup("PMTUDiscovery")
        .next()
        .and_then(|e| e.get_bool().ok())
        .unwrap_or(pmtu_default)
    {
        opts |= ConnOptions::PMTU_DISCOVERY;
    }
    // C `:449-453`: `choice = true; get_config_bool("ClampMSS", &choice);
    // if(choice) options |= CLAMP_MSS`. Default on.
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

/// `control_common.h`. Dup of `tinc-tools::ctl::CtlRequest` (daemon
/// doesn't dep on tinc-tools). TODO: hoist to tinc-proto.
pub(crate) const REQ_STOP: i32 = 0;
pub(crate) const REQ_RELOAD: i32 = 1;
pub(crate) const REQ_DUMP_NODES: i32 = 3;
pub(crate) const REQ_DUMP_EDGES: i32 = 4;
pub(crate) const REQ_DUMP_SUBNETS: i32 = 5;
pub(crate) const REQ_DUMP_CONNECTIONS: i32 = 6;
pub(crate) const REQ_PURGE: i32 = 8;
pub(crate) const REQ_SET_DEBUG: i32 = 9;
pub(crate) const REQ_RETRY: i32 = 10;
pub(crate) const REQ_DISCONNECT: i32 = 12;
pub(crate) const REQ_DUMP_TRAFFIC: i32 = 13;
/// `control_common.h:43`. `tincctl.c:649`: `level, use_color`.
pub(crate) const REQ_LOG: i32 = 15;
pub(crate) const REQ_PCAP: i32 = 14;
/// `control_common.h`: `REQ_INVALID = -1`.
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
    /// `dump_subnets(c)` (`subnet.c:395-410`).
    DumpSubnets,
    /// `dump_nodes(c)` (`node.c:201-223`).
    DumpNodes,
    /// `dump_edges(c)` (`edge.c:123-137`).
    DumpEdges,
    /// `REQ_RELOAD` (`control.c:56`). Daemon reloads + replies `"18 1 <r>"`.
    Reload,
    /// `REQ_RETRY` (`control.c:95-96`). Daemon calls `retry()` then
    /// `control_ok` → `"18 10 0"`.
    Retry,
    /// `REQ_PURGE` (`control.c:75-77`). Daemon calls `purge()` then
    /// `control_ok` → `"18 8 0"`.
    Purge,
    /// `REQ_DISCONNECT` (`control.c:102-122`). `Some(name)` → walk
    /// conns, terminate matches, reply `"18 12 0"` if found else
    /// `"18 12 -2"`. `None` → sscanf failed (`:108`), reply `"18 12 -1"`.
    Disconnect(Option<String>),
    /// `dump_traffic(c)` (`node.c:226-231`). Walk nodes, emit
    /// `"18 13 NAME in_packets in_bytes out_packets out_bytes"`.
    DumpTraffic,
    /// `REQ_LOG` (`control.c:133-140`). `c->status.log = true`,
    /// `c->log_level = level`. C parses `level, colorize`; we parse
    /// the level and ignore colorize (no ANSI in the tap). `i32` is
    /// the C debug level (`-1..=10`); daemon maps to `log::Level`.
    Log(i32),
    /// `REQ_PCAP` (`control.c:127-131`). Daemon arms `conn.pcap` and
    /// the global `pcap` gate. Carries the parsed snaplen (`sscanf(
    /// "%*d %*d %d", &c->outmaclength)`); 0 means unparsed or full.
    /// NO `control_ok` reply (C `:131` is plain `return true`); the
    /// CLI starts reading pcap headers immediately.
    Pcap(u16),
    /// `REQ_SET_DEBUG` (`control.c:79-93`). Carries the parsed level.
    /// `None` → sscanf failed (`:83`), terminate (C `return false`).
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
    /// `ack_h`: sscanf `< 3` (`protocol_auth.c:960-963`).
    BadAck(String),
    /// `add/del_subnet_h`: parse failed (`protocol_subnet.c:49-68`).
    BadSubnet(String),
    /// `add/del_edge_h`: parse failed (`protocol_edge.c:80-92`).
    BadEdge(String),
    /// `req/ans_key_h`: parse failed (`protocol_key.c:282-287`, `:431-435`).
    BadKey(String),
    /// `control_h`: unknown subtype. NOT a `Drop` (C `control.c:144`
    /// returns `true`). Test-only variant.
    #[cfg(test)]
    UnknownControl,
}

/// `receive_request` step 1-3 (`protocol.c:164-178`): parse reqno,
/// bounds check, `allow_request` gate. Handler match (step 4) is the
/// caller's. `line` has no trailing `\n`.
///
/// # Errors
/// `UnknownRequest` for bad/out-of-range reqno; `Unauthorized` if gated.
pub fn check_gate(conn: &Connection, line: &[u8]) -> Result<Request, DispatchError> {
    // C `atoi(request)` then `if(reqno || *request == '0')`. STRICTER:
    // `atoi("18foo")` → 18 in C; we reject. C never sends that
    // (`send_request` always `"%d "`).
    let first = line
        .split(|&b| b.is_ascii_whitespace())
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(DispatchError::UnknownRequest)?;
    let s = std::str::from_utf8(first).map_err(|_| DispatchError::UnknownRequest)?;
    let reqno: i32 = s.parse().map_err(|_| DispatchError::UnknownRequest)?;

    // C `is_valid_request` + handler-non-NULL (`protocol.c:167`).
    let req = Request::from_id(reqno).ok_or(DispatchError::UnknownRequest)?;

    // C `:175-178`: `allow_request != ALL && != reqno`. `None` = `ALL`.
    if let Some(allowed) = conn.allow_request
        && allowed != req
    {
        return Err(DispatchError::Unauthorized);
    }

    Ok(req)
}

/// `protocol_auth.c:458-465` SPTPS label for the TCP meta connection.
///
/// **TRAILING NUL IS WIRE-COMPAT.** C `sizeof` of VLA `char label[25 +
/// strlen(a) + strlen(b)]` is one more than the snprintf'd content. The
/// NUL feeds SIG transcript (`sptps.c:206`) + PRF seed; missing it →
/// `BadSig`. The invitation label (`:372`) does NOT have it (explicit
/// count, not VLA): historical accident, not policy.
///
/// Argument order: always (initiator, responder) (`:460-465`).
#[must_use]
pub(crate) fn tcp_label(initiator: &str, responder: &str) -> Vec<u8> {
    // Explicit push so the NUL is visible in source.
    let mut label = format!("tinc TCP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    debug_assert_eq!(label.len(), 25 + initiator.len() + responder.len()); // C `25 + a + b`
    label
}

/// `check_id` (`utils.c:216-226`): node names must be `[A-Za-z0-9_]+`.
///
/// SECURITY: load-bearing path-traversal gate. Peer name goes into
/// `hosts/NAME`. C `protocol_auth.c:376` calls before `:424 read_host_config`.
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
    /// initiator's KEX), then IO_WRITE. `needs_write` reflects ONLY the
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
    /// `invitation_key` (`protocol_auth.c:56`). `None` → `?` branch
    /// rejects (`:341-344`).
    pub invitation_key: Option<&'a SigningKey>,
    /// Global tinc.conf `PMTU` (`protocol_auth.c:1007`). Clamps in
    /// addition to per-host (both `&& mtu < n->mtu`, min wins).
    pub global_pmtu: Option<u16>,
}

/// `protocol_auth.c:372`: `sptps_start(..., "tinc invitation", 15, ...)`.
/// **NO trailing NUL** — explicit count `15`, not `sizeof(VLA)`. See
/// [`tcp_label`] for the asymmetry.
const INVITE_LABEL: &[u8] = b"tinc invitation";

/// `id_h` (`protocol_auth.c:314-471`). All three branches.
///
/// C `sscanf("%*d " MAX_STRING " %2d.%3d", name, &major, &minor)`.
/// `< 2` → fail; `minor` optional (no `.` → sscanf returns 2, minor
/// stays 0). Dispatch on `name[0]`: `^`→control (`:325-338`),
/// `?`→invitation (`:340-373`), else peer (`:375-471`).
///
/// # Errors
/// `BadId`: malformed, cookie mismatch, bad name, peer==self, version
/// mismatch, no pubkey, rollback.
///
/// `too_many_lines`: C `id_h` is one 158-line function; version-parse
/// and `send_id` are shared between branches. Splitting was worse.
#[allow(clippy::too_many_lines)]
pub fn handle_id(
    conn: &mut Connection,
    line: &[u8],
    ctx: &IdCtx<'_>,
    now: Instant,
    rng: &mut impl RngCore,
) -> Result<IdOk, DispatchError> {
    // C `:317`: `sscanf("%*d %s %d.%d", name, &major, &minor)`.
    let mut toks = line
        .split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let _reqno = toks.next(); // %*d — skip
    let name_tok = toks
        .next()
        .ok_or_else(|| DispatchError::BadId("no name token".into()))?;
    // C `:317` `< 2` → major required. Control sends `"0"` (no dot):
    // sscanf reads major=0, `.` fails, returns 2, minor stays 0.
    let (major, minor): (u8, u8) = {
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
        (major, minor)
    };

    // ─── BRANCH 1: `^cookie` — control connection (`:325-338`)
    if let Some(rest) = name_tok.strip_prefix(b"^") {
        // Not constant-time; mode-0600 secret + unix socket fs perms.
        if rest != ctx.cookie.as_bytes() {
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
            Request::Id as u8,
            ctx.my_name,
            PROT_MAJOR,
            PROT_MINOR
        ));
        // `"%d %d %d", ACK, CTL_VER, getpid()`.
        conn.send(format_args!(
            "{} {} {}",
            Request::Ack as u8,
            CTL_VERSION,
            std::process::id()
        ));

        return Ok(IdOk::Control { needs_write });
    }

    // ─── BRANCH 2: `?` — invitation (`:340-373`).
    if let Some(throwaway_b64) = name_tok.strip_prefix(b"?") {
        // C `:341-344`: `if(!invitation_key)` → reject.
        let Some(inv_key) = ctx.invitation_key else {
            return Err(DispatchError::BadId(format!(
                "got invitation from {} but we don't have an invitation key",
                conn.hostname
            )));
        };

        // C `:346-351`: decode joiner's THROWAWAY pubkey (NOT their node
        // identity — that's the later type-1 record).
        let throwaway: [u8; PUBLIC_LEN] = std::str::from_utf8(throwaway_b64)
            .ok()
            .and_then(tinc_crypto::b64::decode)
            .filter(|v| v.len() == PUBLIC_LEN)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                DispatchError::BadId(format!("got bad invitation from {}", conn.hostname))
            })?;

        // C `:354-357`: b64 of OUR invitation pubkey → line 2. Joiner
        // hashes + compares to URL slug (`fingerprint_hash`).
        let inv_pub_b64 = tinc_crypto::b64::encode(inv_key.public_key());

        // C `:360-362`: line 1. PLAINTEXT (sptps not installed yet).
        let mut needs_write = conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id as u8,
            ctx.my_name,
            PROT_MAJOR,
            PROT_MINOR
        ));

        // C `:364-366`: line 2, ACK with our invitation pubkey. Plaintext.
        needs_write |= conn.send(format_args!("{} {}", Request::Ack as u8, inv_pub_b64));

        // C `:370`: cosmetic for us (`feed()` checks `sptps.is_some()`).
        conn.protocol_minor = 2;

        // C `:372`: `sptps_start(..., false, false, ..., "tinc invitation", 15, ...)`.
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

        // C `:353`: `c->status.invitation = true`. Daemon sets
        // `conn.invite` at the IdOk dispatch site.

        log::info!(target: "tincd::auth",
                   "Starting invitation handshake with {}", conn.hostname);

        return Ok(IdOk::Invitation { needs_write, init });
    }

    // ─── BRANCH 3: bare name — peer (`:375-471`, legacy/bypass stripped)
    let name = std::str::from_utf8(name_tok)
        .ok()
        .filter(|s| check_id(s))
        .ok_or_else(|| {
            // C `:376`: `if(!check_id(name) || ...)`.
            DispatchError::BadId(format!(
                "invalid peer name {:?}",
                String::from_utf8_lossy(name_tok)
            ))
        })?;

    // C `:376`: `|| !strcmp(name, myself->name)`. Self-edge → infinite
    // gossip loop.
    if name == ctx.my_name {
        return Err(DispatchError::BadId(format!(
            "peer claims to be us ({name})"
        )));
    }

    // C `:383-393`: outgoing? `c->name` already set by `ConnectTo`;
    // peer must confirm (DNS hijack / stale config / NAT confusion).
    if conn.outgoing.is_some() {
        if conn.name != name {
            return Err(DispatchError::BadId(format!(
                "peer {} is {} instead of {}",
                conn.hostname, name, conn.name
            )));
        }
    } else {
        conn.name = name.to_string();
    }

    // C `:398-401`: major mismatch → hard reject (wire-breaking).
    if major != PROT_MAJOR {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) uses incompatible version {major}.{minor}",
            conn.name, conn.hostname
        )));
    }
    conn.protocol_minor = minor;

    // C `:404-419`: bypass_security, !experimental — SKIPPED (forbid both).

    // C `:421-435`: load pubkey. C retains `c->config_tree` through
    // ack_h; we extract the 5 keys send_ack/ack_h read and store on
    // the connection (lighter than retaining the whole HashMap).
    // C distinguishes
    // file-missing (`:428` "unknown identity") from file-has-no-key;
    // we collapse — either way you `tinc import`.
    let host_config = {
        let host_file = ctx.confbase.join("hosts").join(name);
        let mut cfg = tinc_conf::Config::default();
        if let Ok(entries) = tinc_conf::parse_file(&host_file) {
            cfg.merge(entries);
        }
        // Parse failure doesn't doom us yet — read_ecdsa_public_key
        // source 3 (raw PEM) gets a chance below.
        cfg
    };

    let ecdsa = read_ecdsa_public_key(&host_config, ctx.confbase, name);
    conn.ecdsa = ecdsa;

    // C `:424` config_tree retained for `:844-865` + `:1003-1019`.
    // Extract now; `host_config` drops at end of fn. `.ok()` matches
    // C `get_config_bool` semantics: parse-fail = absent (returns
    // false, doesn't write `*result`).
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
    // C `protocol_auth.c:1003-1009`: per-host then global, both clamp
    // (`&& mtu < n->mtu`). Compute min here so connect.rs's single-
    // cap clamp is correct. `Option::min` returns None if EITHER is
    // None (wrong: absent should mean "no clamp", not "win").
    // `flatten().min()` skips Nones — correct.
    conn.pmtu_cap = [host_pmtu, ctx.global_pmtu].into_iter().flatten().min();

    // C `:437-439`: `if(minor && !ecdsa) minor = 1` — downgrade to
    // legacy. We forbid legacy: no pubkey → reject outright.
    let Some(ecdsa) = ecdsa else {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) had unknown identity (no Ed25519 public key)",
            conn.name, conn.hostname
        )));
    };

    // C `:443-447`: `if(ecdsa_active && minor < 1)` — downgrade-attack
    // reject. STRICTER: we reject `< 2` (forbid legacy). A 1.1 peer for
    // whom we have a pubkey ALWAYS sends `>= 2`.
    if minor < 2 {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) tries to roll back protocol version to {major}.{minor}",
            conn.name, conn.hostname
        )));
    }

    // C `:449,456`: `allow_request = METAKEY` then `= ACK`. We skip
    // METAKEY (legacy-only).
    conn.allow_request = Some(Request::Ack);

    // C `:451-453`: `if(!c->outgoing) send_id(c)`. ORDER: this line
    // goes BEFORE SPTPS KEX bytes — peer's `receive_meta` reads our ID,
    // fires id_h, sets minor>=2, THEN reads KEX. KEX-first → readline
    // would parse ciphertext.
    let needs_write = if conn.outgoing.is_some() {
        false // initiator already sent in `finish_connecting`
    } else {
        conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id as u8,
            ctx.my_name,
            PROT_MAJOR,
            PROT_MINOR
        ))
    };

    // C `:455-468`: `sptps_start(&c->sptps, c, c->outgoing, false, ...)`.
    // Label `:461-465`: always (initiator, responder).
    let label = if conn.outgoing.is_some() {
        tcp_label(ctx.my_name, name)
    } else {
        tcp_label(name, ctx.my_name)
    };

    // SigningKey deliberately isn't Clone; blob roundtrip makes copy visible.
    let mykey_clone = SigningKey::from_blob(&ctx.mykey.to_blob());

    let role = if conn.outgoing.is_some() {
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

/// `send_ack` (`protocol_auth.c:826-868`). Called on SPTPS `HandshakeDone`
/// when `allow_request == ACK` (`meta.c:130-131`). Queues
/// `"%d %s %d %x"` = `ACK myport.udp weight options`. First line through
/// `sptps_send_record` (encrypted).
///
/// SIDE EFFECT: writes `conn.options` and `conn.estimated_weight` (read
/// by `ack_h` at `:996-999`, `:1048`).
///
/// `global_weight`: tinc.conf `Weight` (`protocol_auth.c:864`) —
/// fallback when per-host `Weight` absent. `None` = RTT wins.
pub fn send_ack(
    conn: &mut Connection,
    my_udp_port: u16,
    myself_options: ConnOptions,
    global_weight: Option<i32>,
    now: Instant,
) -> bool {
    // C `:827-829`: legacy upgrade. Forbidden; id_h already rejected.
    debug_assert!(conn.protocol_minor >= 2);

    // C `:838-840`: RTT ms. `as i32`: C `(int)` also wraps.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let weight = now.saturating_duration_since(conn.start).as_millis() as i32;
    // C `:844-865`: per-host config OR myself->options. C composes
    // bit-by-bit; the per-host fields were extracted at id_h.
    let mut opts = ConnOptions::empty();
    // C `:844-846`: IndirectData per-host (yes only) OR global.
    if conn.host_indirect == Some(true) || myself_options.contains(ConnOptions::INDIRECT) {
        opts |= ConnOptions::INDIRECT;
    }
    // C `:848-850`: TCPOnly implies INDIRECT.
    if conn.host_tcponly == Some(true) || myself_options.contains(ConnOptions::TCPONLY) {
        opts |= ConnOptions::TCPONLY | ConnOptions::INDIRECT;
    }
    // C `:852-854`: PMTU only if global says so AND we're not TCP-only
    // — this is the load-bearing bit. Without it, per-host TCPOnly
    // still left PMTU set, peer wastes udp_discovery_timeout probing
    // a path the user already told us is broken.
    if myself_options.contains(ConnOptions::PMTU_DISCOVERY) && !opts.contains(ConnOptions::TCPONLY)
    {
        opts |= ConnOptions::PMTU_DISCOVERY;
    }
    // C `:856-861`: per-host ClampMSS OVERRIDES global (not OR'd).
    // `get_config_bool` writes through only on success, so absent =
    // global default sticks.
    if conn
        .host_clamp_mss
        .unwrap_or(myself_options.contains(ConnOptions::CLAMP_MSS))
    {
        opts |= ConnOptions::CLAMP_MSS;
    }
    conn.options = opts;

    // C `:863-865`: per-host > global > RTT. `if(!get_host) get_global`
    // — fallback, not min. RTT (`:838`) loses to either config.
    let weight = conn.host_weight.or(global_weight).unwrap_or(weight);
    conn.estimated_weight = weight;

    // C `:867`: `"%d %s %d %x"`. `myport.udp` is a STRING in C; same
    // wire bytes either way.
    let wire_options = conn.options.with_minor(PROT_MINOR).bits();
    conn.send(format_args!(
        "{} {} {} {:x}",
        Request::Ack as u8,
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

/// `ack_h` parse half (`protocol_auth.c:948-962`). C `sscanf("%*d %s
/// %d %x")` (`:960`). Mutation half (`:965-1064`) lives in daemon.
///
/// # Errors
/// `BadAck` if sscanf would return `< 3`.
pub fn parse_ack(line: &[u8]) -> Result<AckParsed, DispatchError> {
    // STRICTER: C `%s` reads any non-whitespace; we want u16. C never
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
        .ok_or_else(|| DispatchError::BadAck("bad weight".into()))?;
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

/// `add_subnet_h` parse (`protocol_subnet.c:49-68`). NB: C `add_subnet_h`
/// does NOT `subnetcheck` (host bits zero) — relies on `lookup_subnet`
/// not finding non-canonical nets. We match.
///
/// # Errors
/// `BadSubnet`: not UTF-8 or `SubnetMsg::parse` failed.
pub fn parse_add_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadSubnet("not UTF-8".into()))?;
    let m = tinc_proto::msg::SubnetMsg::parse(s)
        .map_err(|_| DispatchError::BadSubnet("parse failed".into()))?;
    Ok((m.owner, m.subnet))
}

/// `del_subnet_h` parse (`protocol_subnet.c:163-188`). Same format as ADD.
///
/// # Errors
/// See [`parse_add_subnet`].
pub fn parse_del_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadSubnet("not UTF-8".into()))?;
    let m = tinc_proto::msg::SubnetMsg::parse(s)
        .map_err(|_| DispatchError::BadSubnet("parse failed".into()))?;
    Ok((m.owner, m.subnet))
}

/// `add_edge_h` parse (`protocol_edge.c:77-92`).
///
/// # Errors
/// `BadEdge`: not UTF-8 or `AddEdge::parse` failed.
pub fn parse_add_edge(body: &[u8]) -> Result<tinc_proto::msg::AddEdge, DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadEdge("not UTF-8".into()))?;
    tinc_proto::msg::AddEdge::parse(s).map_err(|_| DispatchError::BadEdge("parse failed".into()))
}

/// `del_edge_h` parse (`protocol_edge.c:230-241`).
///
/// # Errors
/// `BadEdge`: not UTF-8 or `DelEdge::parse` failed.
pub fn parse_del_edge(body: &[u8]) -> Result<tinc_proto::msg::DelEdge, DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadEdge("not UTF-8".into()))?;
    tinc_proto::msg::DelEdge::parse(s).map_err(|_| DispatchError::BadEdge("parse failed".into()))
}

/// `meta.c:155-158`: strip trailing `\n` from SPTPS record body.
/// C check is conditional; in practice `send_request` always appends.
#[must_use]
pub fn record_body(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

/// `control_h` (`control.c:45-145`). Line: `"18 <subtype> [args...]"`.
/// Never `Drop` — C `control_h` always returns `true`; CLI closes its end.
///
/// `single_match_else`: this is the C `switch` (`:58-144`); it grows arms.
#[allow(clippy::single_match_else)]
pub fn handle_control(conn: &mut Connection, line: &[u8]) -> (DispatchResult, bool) {
    // C `:50`: `sscanf("%*d %d", &type)`.
    let subtype = line
        .split(|&b| b.is_ascii_whitespace())
        .nth(1)
        .and_then(|t| std::str::from_utf8(t).ok())
        .and_then(|s| s.parse::<i32>().ok());

    match subtype {
        // C `:56-80`. Daemon does the walk/reload (it has the slotmap).
        Some(REQ_RELOAD) => (DispatchResult::Reload, false),
        Some(REQ_DUMP_NODES) => (DispatchResult::DumpNodes, false),
        Some(REQ_DUMP_EDGES) => (DispatchResult::DumpEdges, false),
        Some(REQ_DUMP_SUBNETS) => (DispatchResult::DumpSubnets, false),
        Some(REQ_DUMP_CONNECTIONS) => (DispatchResult::DumpConnections, false),
        Some(REQ_RETRY) => (DispatchResult::Retry, false),
        Some(REQ_PURGE) => (DispatchResult::Purge, false),
        Some(REQ_SET_DEBUG) => {
            // C `control.c:81-83`: `sscanf("%*d %*d %d", &new_level)`.
            // `!= 1` → `return false` (drop). The level is the 3rd
            // token. `%d` accepts negative — the CLI never sends
            // one, but C `control.c:88` gates on `>= 0` so it's a
            // valid query-only path.
            let level = line
                .split(|&b| b.is_ascii_whitespace())
                .filter(|t| !t.is_empty())
                .nth(2)
                .and_then(|t| std::str::from_utf8(t).ok())
                .and_then(|s| s.parse::<i32>().ok());
            // Surface to daemon: it has the log_tap atomic. The
            // daemon arm Drops on None (C `:83` `return false`).
            (DispatchResult::SetDebug(level), false)
        }
        Some(REQ_DISCONNECT) => {
            // C `:106`: `sscanf("%*d %*d " MAX_STRING, name)`. Third
            // whitespace token. C `%s` stops at whitespace; we do too.
            // `check_id` not in C here — it just strcmp's against the
            // conn-list — so don't add it (a bad name simply won't match).
            let name = line
                .split(|&b| b.is_ascii_whitespace())
                .filter(|t| !t.is_empty())
                .nth(2)
                .and_then(|t| std::str::from_utf8(t).ok())
                .filter(|s| s.len() <= tinc_proto::MAX_STRING)
                .map(str::to_owned);
            (DispatchResult::Disconnect(name), false)
        }
        Some(REQ_DUMP_TRAFFIC) => (DispatchResult::DumpTraffic, false),
        Some(REQ_LOG) => {
            // C `:134-135`: `int level = 0, colorize = 0;
            // sscanf("%*d %*d %d %d", &level, &colorize)`.
            // Default 0 if missing (C's local-init). Third token.
            // Colorize (4th) ignored: we send bare `args()` from
            // log_tap, no ANSI. C `:136`: `CLAMP(level, DEBUG_UNSET,
            // DEBUG_SCARY_THINGS)` = `[-1, 10]`. The daemon arm
            // maps to `log::Level`; clamp happens implicitly (the
            // C-to-Level table has a `_` arm).
            let level = line
                .split(|&b| b.is_ascii_whitespace())
                .filter(|t| !t.is_empty())
                .nth(2)
                .and_then(|t| std::str::from_utf8(t).ok())
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
            (DispatchResult::Log(level), false)
        }
        Some(REQ_PCAP) => {
            // C `control.c:128`: `sscanf("%*d %*d %d", &c->outmaclength)`.
            // sscanf failure leaves outmaclength untouched (0 from
            // xzalloc) — same here: missing/bad token → 0. Negative
            // snaplen makes no sense; %d would accept it but the
            // `route.c:1120` `outmaclength && outmaclength < len`
            // gate is harmless (negative-int < positive-len always true,
            // so it'd clip to a negative — BUT C `send_meta` length is
            // `int` and would overflow). The CLI sends 0 or small
            // positive (`stream.rs:537`). We clamp negative → 0, and
            // saturate to u16 (snaplen > MTU is functionally ∞ anyway).
            let snaplen = line
                .split(|&b| b.is_ascii_whitespace())
                .filter(|t| !t.is_empty())
                .nth(2)
                .and_then(|t| std::str::from_utf8(t).ok())
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&n| n > 0)
                .map_or(0u16, |n| u16::try_from(n).unwrap_or(u16::MAX));
            (DispatchResult::Pcap(snaplen), false)
        }
        Some(REQ_STOP) => {
            // C `:59-61`: `event_exit(); return control_ok(c, REQ_STOP)`
            // → `"18 0 0"`.
            log::info!(target: "tincd", "Got REQ_STOP, shutting down");
            let needs_write = conn.send(format_args!("{} {} 0", Request::Control as u8, REQ_STOP));
            (DispatchResult::Stop, needs_write)
        }
        _ => {
            // C `:143-144`: default → `"%d %d", CONTROL, REQ_INVALID`.
            // Malformed (`subtype = None`) lands here too — same as C
            // (uninit `type` falls through to default).
            log::debug!(target: "tincd::proto",
                        "Unknown CONTROL subtype {subtype:?} from {}", conn.name);
            let needs_write = conn.send(format_args!("{} {}", Request::Control as u8, REQ_INVALID));
            (DispatchResult::Ok, needs_write)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    /// `/dev/null` fd; handlers don't touch the fd, just need a valid conn.
    fn nullfd() -> OwnedFd {
        let f = std::fs::File::open("/dev/null").unwrap();
        let fd = std::os::fd::IntoRawFd::into_raw_fd(f);
        // SAFETY: fd from File, valid, ownership transferred.
        #[allow(unsafe_code)]
        unsafe {
            OwnedFd::from_raw_fd(fd)
        }
    }

    fn mkconn() -> Connection {
        Connection::test_with_fd(nullfd())
    }

    /// IdCtx for tests not reaching the peer pubkey load. `OnceLock`
    /// for `'static` lifetime. `confbase="."` → pubkey load fails;
    /// tests reaching it use `PeerSetup`.
    fn mkctx(cookie: &str) -> IdCtx<'_> {
        static DUMMY_KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
        let mykey = DUMMY_KEY.get_or_init(|| SigningKey::from_seed(&[0x99; 32]));
        IdCtx {
            cookie,
            my_name: "testd",
            mykey,
            confbase: Path::new("."),
            invitation_key: None,
            global_pmtu: None,
        }
    }

    use rand_core::OsRng;

    // ─── check_gate

    /// `DispatchError` isn't `PartialEq`-friendly; gate only yields these.
    #[derive(Debug, PartialEq)]
    enum GateExpect {
        Ok(Request),
        Unauthorized,
        UnknownRequest,
    }

    /// Full allow/deny matrix + malformed. Covers C `atoi`, `*request
    /// == '0'`, range check, gate.
    #[test]
    fn gate_cases() {
        use GateExpect::{Ok, Unauthorized, UnknownRequest};
        #[rustfmt::skip]
        let cases: &[(Option<Request>, &[u8], GateExpect)] = &[
            // ─── allows expected
            // new_control sets allow_request = Some(Id).
            (Some(Request::Id), b"0 ^abc 0",   Ok(Request::Id)),
            // ─── blocks unexpected
            // Fresh conn allows only ID (0). CONTROL (18) is gated.
            (Some(Request::Id), b"18 0",       Unauthorized),
            // ─── None = ALL
            (None,              b"18 0",       Ok(Request::Control)),
            (None,              b"0 foo 17.7", Ok(Request::Id)),
            (None,              b"8",          Ok(Request::Ping)),
            // ─── empty: `atoi("")` → 0 in C, but the `*request ==
            // '0'` check fails. We reject too: empty first token.
            (Some(Request::Id), b"",           UnknownRequest),
            (Some(Request::Id), b"  ",         UnknownRequest),
            // ─── out of range
            (None,              b"99 foo",     UnknownRequest),
            (None,              b"-1 foo",     UnknownRequest),
            // ─── STRICTER: `"18foo"` rejected; C `atoi` would parse 18
            (None,              b"18foo bar",  UnknownRequest),
        ];
        for (i, (allow, line, expected)) in cases.iter().enumerate() {
            let mut c = mkconn();
            c.allow_request = *allow;
            let got = match check_gate(&c, line) {
                Result::Ok(r) => Ok(r),
                Err(DispatchError::Unauthorized) => Unauthorized,
                Err(DispatchError::UnknownRequest) => UnknownRequest,
                Err(e) => panic!("case {i}: {line:?}: unexpected error: {e:?}"),
            };
            assert_eq!(got, *expected, "case {i}: {line:?}");
        }
    }

    // ─── handle_id
    //
    // Happy-path control auth covered by `tests/stop.rs::spawn_connect_stop`.
    // Rejection paths only

    #[test]
    fn id_cookie_mismatch() {
        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let bad = "b".repeat(64);
        let line = format!("0 ^{bad} 0");

        let r = handle_id(
            &mut c,
            line.as_bytes(),
            &mkctx(&cookie),
            Instant::now(),
            &mut OsRng,
        );
        assert!(matches!(r, Err(DispatchError::BadId(_))));
        // No state change on failure.
        assert!(!c.control);
        assert_eq!(c.allow_request, Some(Request::Id));
        assert!(c.outbuf.is_empty());
    }

    /// Early-reject paths: all bail BEFORE the pubkey load. `mkctx`
    /// (confbase=".") suffices; the Err proves we never hit the fs.
    #[test]
    fn id_early_rejects() {
        #[rustfmt::skip]
        let cases: &[(&[u8], &str)] = &[
            // C `:341-344`: `if(!invitation_key)` (mkctx has None)
            (b"0 ?somekey 17.7",     "invitation, no key"),
            // C `:376`: `!check_id(name)`. Path-traversal gate.
            (b"0 ../etc/passwd 17.7", "path traversal"),
            // C `:376`: `|| !strcmp(name, myself->name)`
            (b"0 testd 17.7",        "peer is self"),
            // C `sscanf` returns 0/1 (`< 2` fails)
            (b"0",                   "no name token"),
            (b"0 alice",             "no version token"),
        ];
        for (i, (line, label)) in cases.iter().enumerate() {
            let mut c = mkconn();
            let r = handle_id(&mut c, line, &mkctx("x"), Instant::now(), &mut OsRng);
            assert!(
                matches!(r, Err(DispatchError::BadId(_))),
                "case {i} ({label}): {line:?} → {r:?}"
            );
            // No state mutation on early reject.
            assert!(c.sptps.is_none(), "case {i} ({label}): sptps installed");
            assert_eq!(c.name, "<control>", "case {i} ({label}): name set");
            assert!(c.outbuf.is_empty(), "case {i} ({label}): outbuf written");
        }
    }

    // ─── id_h peer branch

    /// Tempdir + hosts/ layout for peer-branch tests.
    struct PeerSetup {
        tmp: std::path::PathBuf,
    }
    impl PeerSetup {
        fn new(tag: &str, peer_name: &str, peer_pub: &[u8; 32]) -> Self {
            let tid = std::thread::current().id();
            let tmp = std::env::temp_dir().join(format!("tincd-proto-{tag}-{tid:?}"));
            std::fs::create_dir_all(tmp.join("hosts")).unwrap();
            // Inline b64 (read_ecdsa_public_key source 1).
            let b64 = tinc_crypto::b64::encode(peer_pub);
            std::fs::write(
                tmp.join("hosts").join(peer_name),
                format!("Ed25519PublicKey = {b64}\n"),
            )
            .unwrap();
            Self { tmp }
        }
        fn confbase(&self) -> &Path {
            &self.tmp
        }
    }
    impl Drop for PeerSetup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }

    // Happy-path peer ID covered by `tests/stop.rs::peer_ack_exchange`
    // (full SPTPS handshake proves sptps installed + right pubkey).

    /// Major mismatch. C `:398-401`.
    #[test]
    fn id_peer_major_mismatch() {
        let mykey = SigningKey::from_seed(&[1; 32]);
        let peerkey = SigningKey::from_seed(&[2; 32]);
        let setup = PeerSetup::new("major", "alice", peerkey.public_key());

        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let ctx = IdCtx {
            cookie: &cookie,
            my_name: "testd",
            mykey: &mykey,
            confbase: setup.confbase(),
            invitation_key: None,
            global_pmtu: None,
        };

        // 18.7 — major 18, we're 17.
        let r = handle_id(&mut c, b"0 alice 18.7", &ctx, Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
        // Name set before version check (C `:389` before `:398`).
        assert_eq!(c.name, "alice");
        assert!(c.sptps.is_none());
    }

    /// Unknown identity: no `hosts/alice` file. C `:428` collapse.
    #[test]
    fn id_peer_unknown_identity() {
        let mykey = SigningKey::from_seed(&[1; 32]);
        // PeerSetup for a DIFFERENT name. hosts/alice doesn't exist.
        let setup = PeerSetup::new("unknown", "bob", &[0; 32]);

        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let ctx = IdCtx {
            cookie: &cookie,
            my_name: "testd",
            mykey: &mykey,
            confbase: setup.confbase(),
            invitation_key: None,
            global_pmtu: None,
        };

        let r = handle_id(&mut c, b"0 alice 17.7", &ctx, Instant::now(), &mut OsRng);
        let Err(DispatchError::BadId(msg)) = r else {
            panic!("expected BadId, got {r:?}");
        };
        assert!(msg.contains("alice"), "msg: {msg}");
        assert!(msg.contains("unknown identity"), "msg: {msg}");
        assert!(c.sptps.is_none());
    }

    /// Rollback: known peer sends minor=0. C `:443-447`. STRICTER:
    /// minor=1 also rejected (no legacy).
    #[test]
    fn id_peer_rollback_rejected() {
        let mykey = SigningKey::from_seed(&[1; 32]);
        let peerkey = SigningKey::from_seed(&[2; 32]);
        let setup = PeerSetup::new("rollback", "alice", peerkey.public_key());

        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let ctx = IdCtx {
            cookie: &cookie,
            my_name: "testd",
            mykey: &mykey,
            confbase: setup.confbase(),
            invitation_key: None,
            global_pmtu: None,
        };

        let r = handle_id(&mut c, b"0 alice 17.0", &ctx, Instant::now(), &mut OsRng);
        let Err(DispatchError::BadId(msg)) = r else {
            panic!("expected BadId, got {r:?}");
        };
        assert!(msg.contains("roll back"), "msg: {msg}");

        // minor=1: C would `send_metakey`. STRICTER reject.
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0 alice 17.1", &ctx, Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
    }

    /// `"17"` (no dot) → minor=0: parse SUCCEEDS, then SEMANTIC reject.
    /// Pins: "roll back" error, not "malformed" — same as C.
    #[test]
    fn id_peer_no_dot_minor_zero() {
        let mykey = SigningKey::from_seed(&[1; 32]);
        let peerkey = SigningKey::from_seed(&[2; 32]);
        let setup = PeerSetup::new("nodot", "alice", peerkey.public_key());

        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let ctx = IdCtx {
            cookie: &cookie,
            my_name: "testd",
            mykey: &mykey,
            confbase: setup.confbase(),
            invitation_key: None,
            global_pmtu: None,
        };

        let r = handle_id(&mut c, b"0 alice 17", &ctx, Instant::now(), &mut OsRng);
        let Err(DispatchError::BadId(msg)) = r else {
            panic!("expected BadId, got {r:?}");
        };
        assert!(msg.contains("roll back"), "msg: {msg}");
        // protocol_minor set BEFORE the reject (C `:399`).
        assert_eq!(c.protocol_minor, 0);
    }

    // ─── invitation `?` branch
    //
    // Happy path covered by `tests/two_daemons.rs::tinc_join_against_real_daemon`.

    /// `?` with garbage b64. C `:348-351`: `if(!c->ecdsa)` reject.
    #[test]
    fn id_invitation_bad_throwaway() {
        let mykey = SigningKey::from_seed(&[1; 32]);
        let inv_key = SigningKey::from_seed(&[0x77; 32]);

        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let ctx = IdCtx {
            cookie: &cookie,
            my_name: "alice",
            mykey: &mykey,
            confbase: Path::new("."),
            invitation_key: Some(&inv_key),
            global_pmtu: None,
        };

        // Too short (32 bytes b64 → 43 chars; this is 7).
        let r = handle_id(&mut c, b"0 ?garbage 17.7", &ctx, Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
        assert!(c.sptps.is_none());
        assert!(c.outbuf.is_empty());
    }

    /// `protocol_auth.c:372`: `"tinc invitation", 15` — explicit count,
    /// NOT `sizeof()`. NO trailing NUL (cf `tcp_label_has_trailing_nul`).
    #[test]
    fn invite_label_no_nul() {
        assert_eq!(INVITE_LABEL.len(), 15);
        assert_eq!(INVITE_LABEL, b"tinc invitation");
        assert!(!INVITE_LABEL.contains(&0));
    }

    // ─── tcp_label (the NUL)

    /// WIRE-COMPAT. gcc-verified: `labellen=33`, byte 32 = 0x00. Miss
    /// the NUL → `BadSig` against C tincd. Fast fail vs 100ms+
    /// `stop.rs::peer_handshake`.
    #[test]
    fn tcp_label_has_trailing_nul() {
        let label = tcp_label("alice", "bob");
        assert_eq!(label.len(), 25 + 5 + 3); // C `25 + strlen(a) + strlen(b)`
        assert_eq!(label.len(), 33);
        assert_eq!(label[32], 0);
        assert_eq!(label[31], b'b');
        assert_eq!(&label[..], b"tinc TCP key expansion alice bob\0");
    }

    /// C `:460-465`: always (initiator, responder). Swap → BadSig.
    #[test]
    fn tcp_label_order_matters() {
        let a = tcp_label("alice", "bob");
        let b = tcp_label("bob", "alice");
        assert_ne!(a, b);
        assert!(a.starts_with(b"tinc TCP key expansion alice "));
        assert!(b.starts_with(b"tinc TCP key expansion bob "));
    }

    /// Path-traversal gate. Pin security-relevant cases.
    #[test]
    fn check_id_security() {
        assert!(check_id("alice"));
        assert!(check_id("node_01"));
        assert!(check_id("A"));
        // Traversal: all must fail.
        assert!(!check_id("../etc"));
        assert!(!check_id("a/b"));
        assert!(!check_id("."));
        assert!(!check_id(".."));
        assert!(!check_id("a b")); // would break token split
        assert!(!check_id(""));
        assert!(!check_id("^abc")); // control sigil
    }

    /// `protocol_auth.c:328`: `last_ping_time = now + 3600` exempts
    /// control conns from ping sweep.
    #[test]
    fn id_bumps_ping_time() {
        let mut c = mkconn();
        let now = Instant::now();
        let cookie = "a".repeat(64);
        let line = format!("0 ^{cookie} 0");

        handle_id(&mut c, line.as_bytes(), &mkctx(&cookie), now, &mut OsRng).unwrap();

        assert!(c.last_ping_time > now + std::time::Duration::from_secs(3000));
    }

    // ─── handle_control
    //
    // `"18 0"` → Stop covered by `tests/stop.rs::spawn_connect_stop`.

    #[test]
    fn control_reload() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        let (r, nw) = handle_control(&mut c, b"18 1");
        assert_eq!(r, DispatchResult::Reload);
        // No write yet — daemon queues the reply after reload runs.
        assert!(!nw);
        assert!(c.outbuf.is_empty());
    }

    #[test]
    fn control_retry() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        let (r, nw) = handle_control(&mut c, b"18 10");
        assert_eq!(r, DispatchResult::Retry);
        // Daemon writes the `"18 10 0"` ack after `on_retry()` runs.
        assert!(!nw);
        assert!(c.outbuf.is_empty());
    }

    #[test]
    fn control_purge() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        let (r, nw) = handle_control(&mut c, b"18 8");
        assert_eq!(r, DispatchResult::Purge);
        // Daemon writes the `"18 8 0"` ack after `purge()` runs.
        assert!(!nw);
        assert!(c.outbuf.is_empty());
    }

    #[test]
    fn control_disconnect() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        // C `:106`: `"%*d %*d " MAX_STRING` — token 3 is the name.
        let (r, _) = handle_control(&mut c, b"18 12 bob");
        assert_eq!(r, DispatchResult::Disconnect(Some("bob".into())));

        // No third token → sscanf returns 0. C `:108` → -1 reply.
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 12");
        assert_eq!(r, DispatchResult::Disconnect(None));
    }

    #[test]
    fn control_dump_traffic() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        // C `control.c:124`: `case REQ_DUMP_TRAFFIC: return dump_traffic(c)`.
        let (r, nw) = handle_control(&mut c, b"18 13");
        assert_eq!(r, DispatchResult::DumpTraffic);
        assert!(!nw);
    }

    /// REQ_LOG: parse level. C `control.c:133-140`.
    #[test]
    fn control_log() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        // `tincctl.c:649`: `"18 15 <level> <use_color>"`. Level 5.
        let (r, nw) = handle_control(&mut c, b"18 15 5 0");
        assert_eq!(r, DispatchResult::Log(5));
        assert!(!nw);

        // Missing level: C's local-init defaults to 0.
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 15");
        assert_eq!(r, DispatchResult::Log(0));

        // -1 = DEBUG_UNSET ("use the daemon's level"). The CLI
        // sends this when no -d given (`tincctl.c:649`).
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 15 -1 1");
        assert_eq!(r, DispatchResult::Log(-1));
    }

    #[test]
    fn control_set_debug() {
        // C `control.c:79-93`. `"18 9 5"` — CONTROL SET_DEBUG level=5.
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, nw) = handle_control(&mut c, b"18 9 5");
        assert_eq!(r, DispatchResult::SetDebug(Some(5)));
        // Daemon arm sends, not proto.rs.
        assert!(!nw);
        assert!(c.outbuf.is_empty());

        // Missing level → None (C `:83`: sscanf fails → return false).
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 9");
        assert_eq!(r, DispatchResult::SetDebug(None));

        // Negative level → query-only. C accepts it (sscanf %d).
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 9 -1");
        assert_eq!(r, DispatchResult::SetDebug(Some(-1)));

        // Garbage level → None (parse fail, same as missing).
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 9 garbage");
        assert_eq!(r, DispatchResult::SetDebug(None));
    }

    #[test]
    fn control_pcap() {
        // C `control.c:127-131`. Snaplen present.
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, nw) = handle_control(&mut c, b"18 14 96");
        assert_eq!(r, DispatchResult::Pcap(96));
        // C `:131` is `return true` — NO control_ok reply.
        assert!(!nw);
        assert!(c.outbuf.is_empty());

        // Snaplen absent: sscanf fails, outmaclength stays 0.
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 14");
        assert_eq!(r, DispatchResult::Pcap(0));

        // Snaplen 0 explicit (CLI default "full packet").
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 14 0");
        assert_eq!(r, DispatchResult::Pcap(0));

        // Huge snaplen → saturate (functionally ∞: > MTU captures all).
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);
        let (r, _) = handle_control(&mut c, b"18 14 999999");
        assert_eq!(r, DispatchResult::Pcap(u16::MAX));
    }

    /// Unknown subtype (99). `REQ_INVALID` reply, connection stays.
    #[test]
    fn control_unknown_subtype() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        let (r, nw) = handle_control(&mut c, b"18 99");
        assert_eq!(r, DispatchResult::Ok);
        assert!(nw);
        assert_eq!(c.outbuf.live(), b"18 -1\n");
    }

    /// Malformed: no second token. Hits the `_` arm same as unknown.
    #[test]
    fn control_malformed() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        let (r, _) = handle_control(&mut c, b"18");
        assert_eq!(r, DispatchResult::Ok);
        assert_eq!(c.outbuf.live(), b"18 -1\n");
    }

    /// Belt-and-braces over tinc-proto's `protocol.h` pin.
    #[test]
    fn proto_version_pin() {
        assert_eq!(PROT_MAJOR, 17);
        assert_eq!(PROT_MINOR, 7);
        assert_eq!(CTL_VERSION, 0);
    }

    // ─── send_ack / parse_ack

    /// C `net_setup.c:442-453,800`: `0x0700000c`.
    #[test]
    fn myself_options_default_value() {
        let opts = myself_options_default();
        assert_eq!(opts.bits() & 0xff, 0x0c); // PMTU(4) | CLAMP(8)
        assert_eq!(opts.prot_minor(), PROT_MINOR);
        assert_eq!(opts.bits() & 0x00ff_ff00, 0);
        assert_eq!(opts.bits(), 0x0700_000c);
    }

    fn cfg(lines: &[&str]) -> tinc_conf::Config {
        let mut c = tinc_conf::Config::default();
        c.merge(lines.iter().enumerate().filter_map(|(i, l)| {
            tinc_conf::parse_line(
                l,
                tinc_conf::Source::File {
                    path: "tinc.conf".into(),
                    line: u32::try_from(i).unwrap() + 1,
                },
            )?
            .ok()
        }));
        c
    }

    /// `net_setup.c:383-453`: empty config = all `get_config_bool`
    /// fall-throughs. Same bits as `myself_options_default`.
    #[test]
    fn myself_options_empty_config() {
        let opts = myself_options_from_config(&tinc_conf::Config::default());
        assert_eq!(opts, myself_options_default());
    }

    /// `net_setup.c:387-393` + `:442`: `TCPOnly = yes` sets TCPONLY
    /// and INDIRECT (`:391` implication), and `:442` `choice =
    /// !(options & OPTION_TCPONLY)` makes the PMTU default off.
    /// ClampMSS unaffected (`:449` default on).
    #[test]
    fn myself_options_tcponly_implies_indirect_clears_pmtu() {
        let opts = myself_options_from_config(&cfg(&["TCPOnly = yes"]));
        assert!(opts.contains(ConnOptions::TCPONLY));
        assert!(opts.contains(ConnOptions::INDIRECT));
        assert!(!opts.contains(ConnOptions::PMTU_DISCOVERY));
        assert!(opts.contains(ConnOptions::CLAMP_MSS));
        // 0x0b = INDIRECT|TCPONLY|CLAMP_MSS, top byte PROT_MINOR.
        assert_eq!(opts.bits(), 0x0700_000b);
    }

    /// `net_setup.c:383-385` standalone: only INDIRECT, defaults
    /// otherwise. PMTU default `:442` is `!(options & TCPONLY)` =
    /// true; ClampMSS `:449` true.
    #[test]
    fn myself_options_indirect_only() {
        let opts = myself_options_from_config(&cfg(&["IndirectData = yes"]));
        assert!(opts.contains(ConnOptions::INDIRECT));
        assert!(!opts.contains(ConnOptions::TCPONLY));
        assert!(opts.contains(ConnOptions::PMTU_DISCOVERY));
        assert!(opts.contains(ConnOptions::CLAMP_MSS));
    }

    /// `net_setup.c:443`: explicit `PMTUDiscovery = yes` overrides
    /// the `!TCPONLY` default. The C reads `PMTUDiscovery` AFTER
    /// computing the default — explicit wins.
    #[test]
    fn myself_options_tcponly_but_pmtu_forced_on() {
        let opts = myself_options_from_config(&cfg(&["TCPOnly = yes", "PMTUDiscovery = yes"]));
        assert!(opts.contains(ConnOptions::TCPONLY));
        assert!(opts.contains(ConnOptions::PMTU_DISCOVERY));
    }

    /// `net_setup.c:449-453`: `ClampMSS = no` clears the bit.
    #[test]
    fn myself_options_clamp_mss_off() {
        let opts = myself_options_from_config(&cfg(&["ClampMSS = no"]));
        assert!(!opts.contains(ConnOptions::CLAMP_MSS));
        // PMTU still default-on.
        assert!(opts.contains(ConnOptions::PMTU_DISCOVERY));
    }

    // `send_ack` wire format (`"%d %s %d %x"` lowercase no-pad) covered
    // by `tests/stop.rs::peer_ack_exchange`.

    /// `protocol_auth.c:848-854`: per-host `TCPOnly = yes` sets
    /// TCPONLY|INDIRECT and CLEARS PMTU_DISCOVERY. The load-bearing
    /// fix from gap-audit `bcc5c3e3`: previously inherited PMTU bit
    /// stuck, peer wasted udp_discovery_timeout probing a path the
    /// user told us is broken.
    #[test]
    fn send_ack_per_host_tcponly_clears_pmtu() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        c.host_tcponly = Some(true);
        let now = Instant::now();
        send_ack(&mut c, 655, myself_options_default(), None, now);
        assert!(c.options.contains(ConnOptions::TCPONLY));
        assert!(c.options.contains(ConnOptions::INDIRECT));
        assert!(!c.options.contains(ConnOptions::PMTU_DISCOVERY));
        // ClampMSS unaffected (default on).
        assert!(c.options.contains(ConnOptions::CLAMP_MSS));
        // Wire bits: 0x0b = INDIRECT|TCPONLY|CLAMP_MSS, NOT 0x0c.
        let line = std::str::from_utf8(c.outbuf.live()).unwrap();
        assert!(line.ends_with(" 700000b\n"), "got {line:?}");
    }

    /// `protocol_auth.c:856-861`: ClampMSS per-host overrides global
    /// (not OR'd). `ClampMSS = no` in hosts/NAME clears it even though
    /// the daemon default is on.
    #[test]
    fn send_ack_per_host_clamp_mss_overrides() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        c.host_clamp_mss = Some(false);
        send_ack(&mut c, 655, myself_options_default(), None, Instant::now());
        assert!(!c.options.contains(ConnOptions::CLAMP_MSS));
        assert!(c.options.contains(ConnOptions::PMTU_DISCOVERY));
    }

    /// `protocol_auth.c:844-846`: `IndirectData = yes` per-host. C's
    /// `&& choice` means `= no` in hosts/NAME does NOT clear a global
    /// INDIRECT (asymmetric with ClampMSS).
    #[test]
    fn send_ack_per_host_indirect() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        c.host_indirect = Some(true);
        send_ack(&mut c, 655, myself_options_default(), None, Instant::now());
        assert!(c.options.contains(ConnOptions::INDIRECT));
        assert!(!c.options.contains(ConnOptions::TCPONLY));
        // PMTU stays on (only TCPONLY suppresses it).
        assert!(c.options.contains(ConnOptions::PMTU_DISCOVERY));

        // `IndirectData = no` per-host doesn't clear global INDIRECT.
        let mut c = mkconn();
        c.protocol_minor = 2;
        c.host_indirect = Some(false);
        send_ack(
            &mut c,
            655,
            ConnOptions::INDIRECT | ConnOptions::CLAMP_MSS,
            None,
            Instant::now(),
        );
        assert!(c.options.contains(ConnOptions::INDIRECT));
    }

    /// `protocol_auth.c:863-865`: per-host Weight overrides RTT.
    #[test]
    fn send_ack_per_host_weight() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        c.host_weight = Some(42);
        // RTT measure would be 0ms (start == now); per-host wins.
        let now = c.start;
        send_ack(&mut c, 655, myself_options_default(), None, now);
        assert_eq!(c.estimated_weight, 42);
        let line = std::str::from_utf8(c.outbuf.live()).unwrap();
        // "4 655 42 700000c\n"
        assert!(line.contains(" 42 "), "got {line:?}");
    }

    /// `protocol_auth.c:864`: global Weight fallback when per-host
    /// absent. `if(!get_host) get_global` — overrides RTT measure.
    #[test]
    fn send_ack_global_weight_fallback() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        // Per-host absent; RTT would be 0ms (start == now).
        let now = c.start;
        send_ack(&mut c, 655, myself_options_default(), Some(50), now);
        assert_eq!(c.estimated_weight, 50); // global wins over RTT
        let line = std::str::from_utf8(c.outbuf.live()).unwrap();
        assert!(line.contains(" 50 "), "got {line:?}");
    }

    /// `protocol_auth.c:863-865`: per-host suppresses global. Fallback
    /// chain, NOT min: per-host > global > RTT.
    #[test]
    fn send_ack_per_host_beats_global() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        c.host_weight = Some(42);
        let now = c.start;
        send_ack(&mut c, 655, myself_options_default(), Some(50), now);
        assert_eq!(c.estimated_weight, 42); // per-host wins
    }

    /// `protocol_auth.c:1003-1009`: per-host AND global PMTU both
    /// clamp (min wins). NOT a fallback. The match in handle_id.
    #[test]
    fn pmtu_cap_is_min_of_host_and_global() {
        // The `[a, b].into_iter().flatten().min()` idiom. Direct
        // unit test of the semantics; handle_id wiring is exercised
        // by the peer-branch integration tests.
        let cap = |h: Option<u16>, g: Option<u16>| [h, g].into_iter().flatten().min();
        assert_eq!(cap(Some(1200), Some(1400)), Some(1200));
        assert_eq!(cap(None, Some(1400)), Some(1400));
        assert_eq!(cap(Some(1400), Some(1200)), Some(1200));
        assert_eq!(cap(None, None), None);
        assert_eq!(cap(Some(1200), None), Some(1200));
    }

    /// No per-host overrides → inherit global. Regression: this is
    /// what the STUBBED code did; ensure the rewrite preserves it.
    #[test]
    fn send_ack_no_per_host_inherits_global() {
        let mut c = mkconn();
        c.protocol_minor = 2;
        send_ack(&mut c, 655, myself_options_default(), None, Instant::now());
        assert_eq!(
            c.options,
            ConnOptions::PMTU_DISCOVERY | ConnOptions::CLAMP_MSS
        );
    }

    #[test]
    fn parse_ack_roundtrip() {
        let line = b"4 655 50 700000c";
        let parsed = parse_ack(line).unwrap();
        assert_eq!(parsed.his_udp_port, 655);
        assert_eq!(parsed.his_weight, 50);
        assert_eq!(parsed.his_options.bits(), 0x0700_000c);
        assert_eq!(parsed.his_options.prot_minor(), 7);
        assert!(parsed.his_options.contains(ConnOptions::PMTU_DISCOVERY));
        assert!(parsed.his_options.contains(ConnOptions::CLAMP_MSS));
    }

    /// C `:960`: `sscanf < 3` → false.
    #[test]
    fn parse_ack_malformed() {
        assert!(matches!(
            parse_ack(b"4 655 50"),
            Err(DispatchError::BadAck(_))
        ));
        // STRICTER: C `%s` would read "http"; we reject up front.
        assert!(matches!(
            parse_ack(b"4 http 50 c"),
            Err(DispatchError::BadAck(_))
        ));
        // Negative weight: valid (i32, %d).
        let p = parse_ack(b"4 655 -1 c").unwrap();
        assert_eq!(p.his_weight, -1);
        assert!(matches!(
            parse_ack(b"4 655 50 0xZZ"),
            Err(DispatchError::BadAck(_))
        ));
    }

    /// C `meta.c:155-158`.
    #[test]
    fn record_body_strip() {
        assert_eq!(record_body(b"4 655 50 c\n"), b"4 655 50 c");
        assert_eq!(record_body(b"4 655 50 c"), b"4 655 50 c"); // no \n: unchanged
        assert_eq!(record_body(b""), b"");
        assert_eq!(record_body(b"\n"), b"");
    }
}
