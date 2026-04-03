//! Protocol dispatch for the daemon side. Ports `protocol.c::receive_
//! request` (49 LOC), `protocol_auth.c::id_h` `^` branch (14 LOC),
//! and `control.c::control_h` `REQ_STOP` only (~20 LOC).
//!
//! ## Why this is separate from `conn.rs`
//!
//! `Connection` is the byte-level transport (recv into inbuf, send
//! from outbuf). This module is the line-level protocol: dispatching
//! a complete line out of `inbuf` to its handler.
//!
//! The split mirrors the C: `meta.c` does the byte/line work,
//! `protocol.c::receive_request` dispatches the line to a handler,
//! `protocol_*.c` files have the handlers. We collapse `protocol_
//! auth.c` and `control.c` into this module since the skeleton only
//! handles two request types.
//!
//! ## The dispatch shape
//!
//! C `receive_request` (`protocol.c:147-195`):
//!
//! 1. `atoi(request)` → `reqno`. The first whitespace-delimited
//!    token is the request type integer. (`atoi` stops at the first
//!    non-digit, so `"18 0"` → `18`.)
//! 2. `is_valid_request` + handler-is-non-NULL check.
//! 3. `allow_request` gate: if `c->allow_request != ALL && c->allow_
//!    request != reqno`, "Unauthorized request", drop.
//! 4. Call handler. Handler returns `bool`; `false` → drop conn.
//!
//! `dispatch()` does 1-3. The handler match (4) lives in `Daemon`
//! because handlers need `&mut Daemon` (to set `running = false`,
//! to walk `node_tree` for dumps, etc).
//!
//! ## `id_h` for control (`protocol_auth.c:314-338`)
//!
//! Three branches on `name[0]`: `^` control (cookie check, ACK),
//! `?` invitation, else peer. We handle `^` and reject the rest.
//!
//! ## `control_h` for STOP (`control.c:45-145`)
//!
//! `case REQ_STOP: event_exit(); return control_ok(c, REQ_STOP)`
//! sends `"18 0 0"`. We return `DispatchResult::Stop`.

use std::path::Path;
use std::time::Instant;

use rand_core::RngCore;
use tinc_crypto::sign::SigningKey;
use tinc_proto::Request;
use tinc_proto::request::{PROT_MAJOR, PROT_MINOR};
use tinc_sptps::{Framing, Output, Role, Sptps};

use crate::conn::Connection;
use crate::keys::read_ecdsa_public_key;

// OPTION_* (`connection.h:32-36`)
//
// `tinc-graph` already exports `OPTION_INDIRECT` (the one bit BFS
// reads). We don't dep on tinc-graph yet (chunk 5). Same dup-don't-
// factor call as `check_id`: 4 lines, the right home is somewhere
// crate-shared (probably tinc-proto — they're WIRE bits, the ACK
// packet's `%x` field carries them), Phase-6 hoist.
//
// The C masks `& 0xffffff` before sending (`protocol_auth.c:867`)
// because the top byte carries `PROT_MINOR` (`OPTION_VERSION` macro,
// `connection.h:36`). The four flags fit in the low 4 bits with 20
// to spare; the mask is future-proofing.

/// `OPTION_INDIRECT`. Set if `IndirectData = yes` or `TCPOnly = yes`.
/// Means: don't UDP-probe me directly, go through a relay.
pub const OPTION_INDIRECT: u32 = 0x0001;
/// `OPTION_TCPONLY`. Set if `TCPOnly = yes`. Implies INDIRECT.
pub const OPTION_TCPONLY: u32 = 0x0002;
/// `OPTION_PMTU_DISCOVERY`. Default on (`net_setup.c:442-446`: on
/// unless `TCPOnly` or `PMTUDiscovery = no`).
pub const OPTION_PMTU_DISCOVERY: u32 = 0x0004;
/// `OPTION_CLAMP_MSS`. Default on (`net_setup.c:449-453`).
pub const OPTION_CLAMP_MSS: u32 = 0x0008;

/// `myself->options` defaults: PMTU + CLAMP_MSS, plus PROT_MINOR in
/// the top byte (`net_setup.c:800`). The C builds this from config
/// in `setup_myself_reloadable` (`:383-453`); we hardcode the
/// defaults until that lands (chunk 9). `IndirectData`/`TCPOnly`/
/// `PMTUDiscovery`/`ClampMSS` are NOT read yet — the per-host
/// overrides in `send_ack` are also stubbed (the `c->config_tree`
/// is not retained, see `handle_id` doc).
#[must_use]
pub(crate) const fn myself_options_default() -> u32 {
    // C: `OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS | (PROT_MINOR << 24)`.
    OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS | ((PROT_MINOR as u32) << 24)
}

/// `control_common.h`. Same enum as `tinc-tools::ctl::CtlRequest`
/// but daemon doesn't dep on tinc-tools (CLI pulls daemon, not
/// the other way). Phase-6 hoist to tinc-proto. `pub(crate)` for
/// daemon.rs's dump_connections format string.
pub(crate) const REQ_STOP: i32 = 0;
pub(crate) const REQ_DUMP_NODES: i32 = 3;
pub(crate) const REQ_DUMP_EDGES: i32 = 4;
pub(crate) const REQ_DUMP_SUBNETS: i32 = 5;
pub(crate) const REQ_DUMP_CONNECTIONS: i32 = 6;
/// `control_common.h`: `REQ_INVALID = -1`. The "unknown subtype" reply.
const REQ_INVALID: i32 = -1;

/// `TINC_CTL_VERSION_CURRENT` from `control_common.h:46`. Hasn't
/// changed since 2007. The CLI sends `0` in its ID line; we echo
/// `0` in the ACK. tinc-tools/ctl.rs checks for this.
const CTL_VERSION: u8 = 0;

/// Result of dispatching one line. The C handlers return `bool`
/// where `false` means "drop the connection". We disambiguate:
/// `false` is `Err`, but `true` has multiple flavors (sometimes
/// the handler also flipped a daemon-wide flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResult {
    /// Handler succeeded. Connection stays open.
    Ok,
    /// `event_exit()` was called. C `running = false`. The loop
    /// finishes this turn (drains the rest of the io events queued)
    /// then exits. The connection stays open until then — the
    /// `"18 0 0"` reply was queued before this returned.
    Stop,
    /// `dump_connections(c)`. The daemon walks `conns` and queues
    /// rows. Can't do it here (don't have the slotmap).
    DumpConnections,
    /// `dump_subnets(c)` (`subnet.c:395-410`). Same shape as
    /// DumpConnections: daemon walks `subnets`, queues rows.
    DumpSubnets,
    /// `dump_nodes(c)` (`node.c:201-223`). Daemon walks `node_ids`
    /// (the graph) + `last_routes` for nexthop/via/distance, queues
    /// 23-field rows.
    DumpNodes,
    /// `dump_edges(c)` (`edge.c:123-137`). Daemon walks per-node
    /// edge lists (the C nested-splay shape), queues 8-field rows.
    DumpEdges,
    /// Handler returned `false`. Drop the connection. C `receive_
    /// request:183-188` logs "Error while processing X" and the
    /// caller (`receive_meta`) returns `false` which causes
    /// `terminate_connection`.
    Drop,
}

/// Why dispatch returned `Drop`. Mostly for logging — the caller's
/// action is the same regardless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// `atoi()` failed or returned a number outside 0..LAST. C: log
    /// at DEBUG_META "Unknown request from X: Y".
    UnknownRequest,
    /// `c->allow_request != ALL && != reqno`. C: log at DEBUG_ALWAYS
    /// "Unauthorized request from X". This is the gate that keeps
    /// peers from sending CONTROL, and keeps fresh connections from
    /// sending anything but ID.
    Unauthorized,
    /// `id_h`: name doesn't start with `^` or cookie mismatch.
    /// (Skeleton: also covers `?` and peer names — we don't handle
    /// those yet.)
    BadId(String),
    /// `ack_h`: sscanf returned `< 3` (`protocol_auth.c:960-963`).
    /// C: `"Got bad ACK from %s (%s)"`.
    BadAck(String),
    /// `add_subnet_h`/`del_subnet_h`: sscanf < 2, bad name, or bad
    /// subnet string (`protocol_subnet.c:49-68`). C: `"Got bad %s
    /// from %s (%s)"`.
    BadSubnet(String),
    /// `add_edge_h`/`del_edge_h`: sscanf wrong count, bad name,
    /// or `from == to` (`protocol_edge.c:80-92`). C: `"Got bad %s
    /// from %s (%s)"`.
    BadEdge(String),
    /// `control_h`: unknown subtype. C `control.c:144` sends
    /// `REQ_INVALID` and returns `true` (connection stays). We do
    /// the same — this is NOT a `Drop`, see `handle_control`.
    /// Variant exists for testing the inner match.
    #[cfg(test)]
    UnknownControl,
}

/// `receive_request` step 1-3. Parse reqno, validate, check the
/// `allow_request` gate. Returns the parsed `Request` for the
/// caller's match (step 4).
///
/// `line` is one line WITHOUT the `\n` (LineBuf::read_line strips it).
///
/// C `protocol.c:164-178`.
///
/// # Errors
/// `UnknownRequest` for bad/out-of-range reqno.
/// `Unauthorized` if the gate blocks.
pub fn check_gate(conn: &Connection, line: &[u8]) -> Result<Request, DispatchError> {
    // C `int reqno = atoi(request)`. `atoi` reads decimal digits,
    // stops at the first non-digit, returns 0 on no-digits. The C
    // then does `if(reqno || *request == '0')` — so `0` is valid
    // (it's `Request::Id`), empty string / non-digit-first is not.
    //
    // We split on whitespace and parse the first token. STRICTER
    // than `atoi`: `atoi("18foo")` returns 18; `"18foo".parse()`
    // fails. The C never sends `"18foo"` — `send_request` always
    // uses `"%d "` with a trailing space. The strictness rejects
    // malformed peers, which is fine.
    //
    // STRICTER-than-C check: the line must be ASCII (control
    // protocol always is). If a peer sends non-UTF-8 in the first
    // token, that's nonsense; reject. The full line might have
    // non-ASCII later (node names with high bytes? no, `check_id`
    // forbids that). For the first token: digits only.
    let first = line
        .split(|&b| b.is_ascii_whitespace())
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(DispatchError::UnknownRequest)?;
    // ASCII digits → parse as i32. `from_utf8` is free here (digits
    // are ASCII); the `.parse()` does the actual work.
    let s = std::str::from_utf8(first).map_err(|_| DispatchError::UnknownRequest)?;
    let reqno: i32 = s.parse().map_err(|_| DispatchError::UnknownRequest)?;

    // C `is_valid_request(reqno)` — bounds check. `Request::from_id`
    // does this. Also checks the handler-non-NULL implicitly
    // (variants without handlers — STATUS, ERROR, REQ_PUBKEY,
    // ANS_PUBKEY — exist in the enum; the daemon match in chunk 4+
    // returns Drop for them. C does the same: `!get_request_entry(
    // reqno)->handler` at protocol.c:167).
    let req = Request::from_id(reqno).ok_or(DispatchError::UnknownRequest)?;

    // C `protocol.c:175-178`: the gate.
    // `c->allow_request != ALL && c->allow_request != reqno` → reject.
    // `ALL = -1` in C (`protocol.h:42`). Our `None` is `ALL`.
    if let Some(allowed) = conn.allow_request {
        if allowed != req {
            return Err(DispatchError::Unauthorized);
        }
    }

    Ok(req)
}

// Label construction (the trailing-NUL wire-compat finding)

/// `protocol_auth.c:458-465` SPTPS label for the TCP meta connection.
///
/// **THE TRAILING NUL IS WIRE-FORMAT-COMPAT.** Born in `65d6f023`
/// (2012): `sizeof` of the C VLA `char label[25 + strlen(a) +
/// strlen(b)]` is one more than the snprintf'd content. gcc-verified
/// `labellen = 33` for alice/bob; hex ends `...626f6200`. The NUL
/// feeds the SIG transcript (`sptps.c:206`) and PRF seed; missing
/// it → `BadSig`. The invitation label at `:372` does NOT have it
/// (string literal + count, not VLA): historical accident, not policy.
///
/// Argument order: always initiator, responder (C `:460-465`).
///
/// `pub(crate)` for unit tests and `tests/stop.rs`.
#[must_use]
pub(crate) fn tcp_label(initiator: &str, responder: &str) -> Vec<u8> {
    // `format!` doesn't include NUL. We push it explicitly. This
    // makes the NUL VISIBLE — a `format!("...\0")` would work too
    // but the trailing `\0` is easy to miss reading the source.
    let mut label = format!("tinc TCP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    // Postcondition: matches the C `25 + strlen(a) + strlen(b)`.
    debug_assert_eq!(label.len(), 25 + initiator.len() + responder.len());
    label
}

/// `check_id` (`utils.c:216-226`): node names must be `[A-Za-z0-9_]+`.
///
/// Dup'd from `tinc-tools/names.rs:495`. Same dup-don't-factor call
/// as `read_fd`/`write_fd`: 2-line fn, depending on `tinc-tools` for
/// it would pull the whole CLI command tree. The right home is
/// `tinc-proto` (it's wire-format-adjacent: names go in the protocol's
/// space-separated tokens) but that's a Phase-6 cleanup.
///
/// SECURITY: this is load-bearing. The peer name goes into a
/// filesystem path (`hosts/NAME`). A name with `/` would be path
/// traversal. `check_id` is the gate. C `protocol_auth.c:376` calls
/// it before `:424 read_host_config(..., c->name)`.
#[must_use]
fn check_id(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

// id_h

/// What `handle_id` did. Replaces the old `Result<bool, ...>` — the
/// peer branch needs to hand back the SPTPS init outputs (the
/// responder's KEX bytes, generated synchronously by `Sptps::start`).
#[derive(Debug)]
pub enum IdOk {
    /// `^cookie` matched. Control connection authenticated. Same
    /// state as the old `Ok(true)` — outbuf went empty→nonempty
    /// (id reply + ACK queued).
    ///
    /// `needs_write` is always `true` here in practice (outbuf was
    /// empty before — it's the first send on a fresh connection).
    /// Kept as a field for symmetry with `Peer`.
    Control { needs_write: bool },
    /// Peer ID accepted. SPTPS installed on `conn.sptps`. `init`
    /// has the responder's KEX wire bytes (`Sptps::start` always
    /// emits one `Output::Wire` — the C `sptps_start` calls
    /// `send_kex` synchronously).
    ///
    /// The caller (daemon) must:
    /// 1. Queue `init` outputs to `conn.outbuf` (→ `send_raw`).
    /// 2. `conn.inbuf.take_rest()` and re-feed via `feed_sptps`.
    ///    The same TCP segment that delivered the ID line might've
    ///    delivered the initiator's KEX too. See `LineBuf::take_rest`
    ///    doc.
    /// 3. Queue THOSE outputs too.
    /// 4. Register IO_WRITE if `needs_write`.
    ///
    /// `needs_write` reflects ONLY the `send_id` line. The init
    /// `Output::Wire` queued by step 1 doesn't change it (outbuf
    /// is already non-empty after `send_id`). Daemon should OR it
    /// with the result of step 1's `send_raw`.
    Peer {
        needs_write: bool,
        init: Vec<Output>,
    },
}

/// Daemon-side context for `handle_id`. Bundled to keep the
/// signature width sane (was 5 params, peer branch wants 4 more).
///
/// Fields are borrowed from `Daemon` — the daemon clones `cookie` and
/// `name` already (to escape the slotmap borrow); `mykey` and
/// `confbase` are added the same way. `mykey` is `&` not `clone()`
/// because the blob-roundtrip clone is INSIDE `handle_id_peer` (it
/// only happens on the peer branch, not for control conns).
pub struct IdCtx<'a> {
    /// `controlcookie`. 64 hex chars.
    pub cookie: &'a str,
    /// `myself->name`. The daemon's node name.
    pub my_name: &'a str,
    /// `myself->connection->ecdsa`. The daemon's private key. Only
    /// touched on the peer branch (`Sptps::start` clones via blob).
    pub mykey: &'a SigningKey,
    /// `confbase`. For `read_ecdsa_public_key` (peer's `hosts/NAME`).
    pub confbase: &'a Path,
}

/// `id_h` (`protocol_auth.c:314-471`). All three branches.
///
/// Line format: `"0 <name> <major>.<minor>"`. The C `sscanf("%*d "
/// MAX_STRING " %2d.%3d", name, &major, &minor)` skips the reqno,
/// reads `name`, then `major.minor`. `< 2` matches means `name` AND
/// `major` are required; `minor` is optional (the `.` won't match
/// if there's no minor, sscanf returns 2 not 3). Control conns send
/// `"0 ^<cookie> 0"` — no `.`, minor stays 0.
///
/// Dispatch:
/// - **`^cookie`** → control conn (`:325-338`). Cookie check, set
///   control flags, queue id+ACK.
/// - **`?b64key`** → invitation (`:340-373`). Chunk 4b+. We reject.
/// - **bare name** → peer (`:375-471`). check_id, version check,
///   load pubkey, start SPTPS as responder.
///
/// `rng`: only touched on peer branch (`Sptps::start`'s `send_kex`).
///
/// # Errors
/// `BadId` for: malformed line, cookie mismatch, `?` (NYI), invalid
/// peer name, peer == ourselves, version mismatch, no pubkey,
/// rollback attempt.
///
/// `too_many_lines` allowed: `id_h` in C is one 158-line function.
/// The three branches are distinct state machines; splitting into
/// `handle_id_control` / `handle_id_peer` was tried, but the version-
/// parse and `send_id` reply are SHARED between branches (control
/// and peer both queue the same `"0 myname 17.7\n"`). Factoring
/// those out left a 4-function group with awkward returns. One
/// function with explicit `// ─── branch ───` markers reads
/// cleaner. The C is one function for the same reason.
#[allow(clippy::too_many_lines)]
pub fn handle_id(
    conn: &mut Connection,
    line: &[u8],
    ctx: &IdCtx<'_>,
    now: Instant,
    rng: &mut impl RngCore,
) -> Result<IdOk, DispatchError> {
    // ─── sscanf (`:317`)
    // C: `sscanf("%*d %s %d.%d", name, &major, &minor)`. We split
    // tokens. `%s` reads non-whitespace (the whole `^abc...` or
    // `alice` or `?def...`). `%d.%d` reads decimal, `.`, decimal.
    let mut toks = line
        .split(|&b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let _reqno = toks.next(); // %*d — skip
    let name_tok = toks
        .next()
        .ok_or_else(|| DispatchError::BadId("no name token".into()))?;
    // major.minor parse. C `:317` `< 2` means major is REQUIRED.
    // If the third token is missing or unparseable, C `id_h` returns
    // false. We match — `"0 alice"` (no version) is BadId.
    //
    // Wait — the control branch (`"0 ^cookie 0"`) has `"0"` not
    // `"0.7"`. The C sscanf `%2d.%3d` reads major=0, the `.` fails
    // to match (next char is `\0` end-of-line), sscanf returns 2.
    // So major IS read (as 0), minor stays at xzalloc'd 0. The
    // `< 2` check passes (2 >= 2). FINE.
    //
    // For us: third token can be `"0"` or `"17.7"`. Split on `.`.
    let (major, minor): (u8, u8) = {
        let ver = toks
            .next()
            .and_then(|t| std::str::from_utf8(t).ok())
            .ok_or_else(|| DispatchError::BadId("no version token".into()))?;
        // `"17.7"` → (17, 7). `"0"` → (0, 0). `".7"` → BadId
        // (sscanf `%d` would fail on leading `.`). `"17."` →
        // C: minor unparsed, stays 0. We: (17, 0).
        let mut parts = ver.splitn(2, '.');
        let major = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| DispatchError::BadId(format!("bad major in {ver:?}")))?;
        // Minor optional. C `:317` returns 2 if `.` doesn't match;
        // `c->protocol_minor` stays xzalloc'd 0.
        let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        (major, minor)
    };

    // BRANCH 1: `^cookie` — control connection (`:325-338`)
    if let Some(rest) = name_tok.strip_prefix(b"^") {
        // C `!strcmp(name + 1, controlcookie)`. Not constant-time;
        // doesn't need to be (cookie is mode-0600 secret + unix
        // socket already authenticated by fs perms).
        if rest != ctx.cookie.as_bytes() {
            // C: condition is false, falls through to `check_id` at
            // `:376` which fails (`^` isn't alnum). Same outcome.
            return Err(DispatchError::BadId("cookie mismatch".into()));
        }

        // `c->status.control = true; c->allow_request = CONTROL;`
        conn.control = true;
        conn.allow_request = Some(Request::Control);
        // `c->last_ping_time = now.tv_sec + 3600`. Exempt from ping
        // timeout for an hour. Practically: forever.
        conn.last_ping_time = now + std::time::Duration::from_secs(3600);
        // `c->name = "<control>"`. Idempotent (new_control set it).
        // The C does it here because TCP-accepted control conns
        // (chunk 3) start as `<unknown>` (new_meta).
        conn.name = "<control>".to_string();

        // `if(!c->outgoing) send_id(c)`. For accepted conns: send
        // our greeting. `send_id`: `"%d %s %d.%d", ID, myname, 17, 7`.
        // `:99-100`: `experimental` is true → `minor = PROT_MINOR`.
        let needs_write = conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id as u8,
            ctx.my_name,
            PROT_MAJOR,
            PROT_MINOR
        ));
        // `return send_request(c, "%d %d %d", ACK, CTL_VER, getpid())`.
        conn.send(format_args!(
            "{} {} {}",
            Request::Ack as u8,
            CTL_VERSION,
            std::process::id()
        ));

        return Ok(IdOk::Control { needs_write });
    }

    // BRANCH 2: `?` — invitation (`:340-373`). Chunk 4b+.
    if name_tok.starts_with(b"?") {
        // C: `if(!invitation_key) { ERR "don't have invitation key";
        // return false }`. We don't have an invitation key yet (it's
        // loaded by `read_invitation_key` in `setup_myself_reloadable`
        // — chunk 4+). Same outcome: reject.
        return Err(DispatchError::BadId(
            "invitation request but invitation handling not implemented".into(),
        ));
    }

    // BRANCH 3: bare name — peer (`:375-471`, legacy/bypass stripped)
    // `name_tok` should be ASCII (check_id enforces alnum + `_`).
    // from_utf8 is the cheapest "bytes → &str" given we're about
    // to call check_id anyway.
    let name = std::str::from_utf8(name_tok)
        .ok()
        .filter(|s| check_id(s))
        .ok_or_else(|| {
            // C `:376`: `if(!check_id(name) || ...) { ERR "invalid
            // name"; return false }`. Same.
            DispatchError::BadId(format!(
                "invalid peer name {:?}",
                String::from_utf8_lossy(name_tok)
            ))
        })?;

    // C `:376`: `... || !strcmp(name, myself->name)`. Talking to
    // ourselves — the meta-graph cycle this would create is
    // infinite (we'd see our own ADD_EDGE come back via this
    // peer, re-broadcast, ...). C rejects early.
    if name == ctx.my_name {
        return Err(DispatchError::BadId(format!(
            "peer claims to be us ({name})"
        )));
    }

    // C `:383-393`: outgoing? check c->name == name. Else: c->name
    // = name. Chunk 4a is responder-only (we accepted, c->outgoing
    // = NULL). So: just set the name.
    conn.name = name.to_string();

    // ─── Version check (`:398-401`)
    // C: `c->protocol_major != myself->connection->protocol_major`.
    // `myself`'s major is PROT_MAJOR (set at startup). Mismatch →
    // "incompatible version". This is a HARD reject — major bumps
    // are wire-breaking by definition.
    if major != PROT_MAJOR {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) uses incompatible version {major}.{minor}",
            conn.name, conn.hostname
        )));
    }
    conn.protocol_minor = minor;

    // C `:404-419`: bypass_security, !experimental — SKIPPED. We
    // forbid both. (`bypass_security` is a debug knob; `experimental`
    // is true ⇔ we have an ecdsa key, which we always do.)

    // ─── Load peer's public key (`:421-435`)
    // C: `if(!c->config_tree) { config_tree = create();
    // read_host_config(tree, c->name); ... ecdsa = read_ecdsa_
    // public_key(&tree, c->name) }`. The config tree is per-
    // connection state; we don't keep it (we only need the pubkey,
    // and chunk 4b's `send_ack` re-reads `Weight`/`PMTU`/`ClampMSS`
    // — it can re-read the file then). YAGNI on caching `Config`.
    //
    // C `:428`: `read_host_config` failure logs "unknown identity"
    // and returns false. We collapse that with the pubkey-load
    // (read_ecdsa_public_key reads the file itself when source 3
    // fires). The log message differs: C says "unknown identity"
    // when the FILE is missing, we say "no public key known". The
    // C's distinction (file-missing vs file-has-no-key) isn't
    // actionable — either way you `tinc import` the peer's host
    // file. Collapse.
    //
    // BUT: source 1 (inline `Ed25519PublicKey` var) needs the
    // PARSED config. So we do parse hosts/NAME first — just don't
    // store the result on `conn`. The parse cost is one `read_to_
    // string` + line-split — microseconds. Once per peer
    // connection (which happens once per daemon lifetime per peer).
    let host_config = {
        let host_file = ctx.confbase.join("hosts").join(name);
        let mut cfg = tinc_conf::Config::default();
        if let Ok(entries) = tinc_conf::parse_file(&host_file) {
            cfg.merge(entries);
        }
        // Parse failure: same as the C's `:428` log-and-return-false.
        // But: read_ecdsa_public_key falls through to source 3 (open
        // the file as raw PEM) on an empty config. So a parse failure
        // here doesn't immediately doom us — the pubkey load below
        // gets a chance. The MORE likely case is "file doesn't exist"
        // and that DOES doom us (source 3 also fails). Either way:
        // the pubkey-load below is the gate.
        cfg
    };

    let ecdsa = read_ecdsa_public_key(&host_config, ctx.confbase, name);
    conn.ecdsa = ecdsa;

    // ─── Minor downgrade + rollback check (`:437-447`)
    // C `:437-439`: `if(minor && !ecdsa) minor = 1`. If peer
    // claims SPTPS-capable (minor>=2) but we don't have their
    // pubkey, downgrade to legacy (minor=1, the upgrade-to-SPTPS
    // mode). C `:469` would then `send_metakey` (RSA legacy).
    //
    // We forbid legacy. So: no pubkey → reject. The C's downgrade
    // path is dead for us. The error message matches what `:428`
    // would log if `read_host_config` had failed.
    let Some(ecdsa) = ecdsa else {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) had unknown identity (no Ed25519 public key)",
            conn.name, conn.hostname
        )));
    };

    // C `:443-447`: rollback check. `if(ecdsa_active && minor < 1)`.
    // We have their pubkey (proved capable of SPTPS) but they claim
    // ancient minor=0. Suspicious — might be a downgrade attack
    // (force us into weaker legacy crypto). C rejects.
    //
    // We're stricter: minor < 2 is reject (we forbid legacy at any
    // minor < 2). minor==1 in C means "legacy + upgrade negotiation"
    // (`send_upgrade`/`upgrade_h`). We don't do that either. The
    // STRICTER policy is intentional: a tinc 1.1 peer for whom we
    // have a pubkey will ALWAYS send minor>=2. minor<2 from such
    // a peer is either a downgrade attack or a config bug; either
    // way, refuse.
    if minor < 2 {
        return Err(DispatchError::BadId(format!(
            "peer {} ({}) tries to roll back protocol version to {major}.{minor}",
            conn.name, conn.hostname
        )));
    }

    // C `:449`: `c->allow_request = METAKEY`. Then `:456` sets
    // `= ACK` for the SPTPS path. We skip METAKEY (legacy-only).
    // C: METAKEY then ACK in two assignments. We: just ACK.
    conn.allow_request = Some(Request::Ack);

    // ─── send_id reply (`:451-453`)
    // C: `if(!c->outgoing) send_id(c)`. We accepted (responder),
    // so: send. SAME line as the control branch sends — the peer
    // sees our id reply, fires their `id_h`, version-checks us,
    // proceeds to their SPTPS initiator side.
    //
    // ORDER MATTERS: this line goes BEFORE the SPTPS KEX bytes.
    // The peer's `receive_meta` reads our `"0 myname 17.7\n"`,
    // fires id_h, sets `protocol_minor=7` (>= 2), next iteration
    // is SPTPS mode, gets our KEX. If we sent KEX first, the peer
    // would try to readline() it and fail (no `\n` in framed bytes,
    // or worse, find a stray `\n` mid-ciphertext and parse garbage).
    let needs_write = conn.send(format_args!(
        "{} {} {}.{}",
        Request::Id as u8,
        ctx.my_name,
        PROT_MAJOR,
        PROT_MINOR
    ));

    // ─── sptps_start (`:455-468`)
    // C: `sptps_start(&c->sptps, c, c->outgoing, false, mykey,
    // c->ecdsa, label, labellen, send_meta_sptps, receive_meta_sptps)`.
    //
    // `c->outgoing` = false → Role::Responder. `false` (4th arg) =
    // `datagram` = false → Framing::Stream. `replaywin = 0` (stream
    // mode ignores it; `sptps.c:720` `s->replaywin = sptps_replaywin`
    // (= 16) but stream mode never reads it).
    //
    // Label: see `tcp_label` doc. Chunk 4a is responder-only →
    // initiator is the peer (`name`), responder is us (`my_name`).
    let label = tcp_label(name, ctx.my_name);

    // mykey clone via blob roundtrip. See `tinc-tools/cmd/join.rs:
    // 1787` for the precedent. SigningKey deliberately isn't Clone;
    // the roundtrip makes the copy VISIBLE.
    let mykey_clone = SigningKey::from_blob(&ctx.mykey.to_blob());

    let (sptps, init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        mykey_clone,
        ecdsa,
        label,
        0, // replaywin: ignored in stream mode
        rng,
    );

    // Install. `Box`: see conn.rs module doc.
    conn.sptps = Some(Box::new(sptps));

    log::info!(target: "tincd::auth",
               "Starting SPTPS handshake with {} ({})",
               conn.name, conn.hostname);

    Ok(IdOk::Peer { needs_write, init })
}

// send_ack / ack_h (`protocol_auth.c:826-868, 948-1066`)

/// `send_ack` (`protocol_auth.c:826-868`). Called when SPTPS
/// `HandshakeDone` arrives and `allow_request == ACK` (`meta.c:
/// 130-131`). Queues `"%d %s %d %x"` = `ACK myport.udp weight
/// (options&0xffffff)|(PROT_MINOR<<24)` over the SPTPS-encrypted
/// path (this is the FIRST line that goes through `sptps_send_
/// record`, not `buffer_add` — `conn.send()` routes by `sptps.
/// is_some()`).
///
/// Weight is the RTT in ms since `c->start` (`send_id`). C: `(now
/// - c->start)` in microseconds / 1000. We use `Duration::as_millis`
/// (same arithmetic, no overflow until 24 days). The cast to i32
/// matches C `(int)` — wraps on absurd RTT, fine, the C also wraps.
///
/// `myself_options`: see `myself_options_default`. The C builds it
/// per-host (`:844-865` reads `IndirectData`/`TCPOnly`/`PMTU`/
/// `ClampMSS`/`Weight` from `c->config_tree`). We stubbed that
/// (config_tree not retained); pass the daemon-wide defaults. The
/// per-host overrides land with chunk 9's reloadable settings.
///
/// Returns the io_set signal (outbuf went empty→nonempty).
///
/// SIDE EFFECT: writes `conn.options` and `conn.estimated_weight`
/// (`ack_h` reads `c->options` for the PMTU intersection at
/// `:996-999` and `c->estimated_weight` for the average at `:1048`).
pub fn send_ack(
    conn: &mut Connection,
    my_udp_port: u16,
    myself_options: u32,
    now: Instant,
) -> bool {
    // C `:827-829`: `if(protocol_minor == 1) return send_upgrade(c)`.
    // Legacy upgrade path. We forbid; minor < 2 was rejected in
    // id_h. Debug-assert.
    debug_assert!(conn.protocol_minor >= 2);

    // C `:838-840`: weight = (now - c->start) in milliseconds. The
    // C does `(tv_sec - tv_sec)*1000 + (tv_usec - tv_usec)/1000`.
    // `as_millis` is the same. `as i32` cast: C `(int)` wraps;
    // RTT > 24 days is nonsense anyway.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let weight = now.saturating_duration_since(conn.start).as_millis() as i32;
    conn.estimated_weight = weight;

    // C `:844-865`: per-host config OR myself->options. STUBBED.
    // The per-host overrides need `c->config_tree` (deferred per
    // handle_id doc). Just take myself's. The four `if` blocks all
    // OR INTO `c->options`; with no per-host overrides they reduce
    // to `c->options = myself->options & 0x0f`.
    //
    // But: PMTU is `myself & PMTU && !(c & TCPONLY)` — the PMTU
    // bit doesn't stick if THIS connection is TCP-only. With
    // `c->options` starting at 0 (no per-host TCPOnly), the AND
    // is true. So: just inherit.
    conn.options = myself_options
        & (OPTION_INDIRECT | OPTION_TCPONLY | OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS);

    // C `:863-865`: per-host Weight override. STUBBED (same).

    // C `:867`: `"%d %s %d %x", ACK, myport.udp, weight, (options &
    // 0xffffff) | (experimental ? PROT_MINOR << 24 : 0)`.
    // `experimental` is always true for us. `myport.udp` is a
    // STRING in C (it goes through getaddrinfo); we have it as u16.
    // `%s` of a numeric string == `%d` of the int. Same wire bytes.
    let wire_options = (conn.options & 0x00ff_ffff) | (u32::from(PROT_MINOR) << 24);
    conn.send(format_args!(
        "{} {} {} {:x}",
        Request::Ack as u8,
        my_udp_port,
        weight,
        wire_options
    ))
}

/// What `ack_h` parsed. Returned to the daemon for the world-model
/// mutation (`node_add`, `edge_add`, `graph()`). The C does the
/// mutation INSIDE `ack_h` (it has the globals); we don't (the
/// daemon owns the slotmap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckParsed {
    /// `hisport`. Peer's UDP port (`%s` in C — string — because
    /// `myport.udp` is a string. Everyone sends decimal; parse u16.)
    pub his_udp_port: u16,
    /// Peer's RTT estimate. Averaged with ours for the edge weight.
    pub his_weight: i32,
    /// Peer's options bitfield (with their PROT_MINOR in top byte).
    pub his_options: u32,
}

/// `ack_h` parse half (`protocol_auth.c:948-962`). The MUTATION
/// half (`:965-1064`: node lookup, dup-conn handling, edge_add,
/// graph()) lives in the daemon — it touches `self.conns` and the
/// world model.
///
/// Line format: `"4 <port> <weight> <options-hex>"`. C `sscanf(
/// "%*d %s %d %x")` (`:960`). `%s` for the port (it's a string in
/// C, see `send_ack`); we parse u16.
///
/// `line` is the SPTPS record body, `\n` already stripped by
/// `record_body` (the C `meta.c:156` strips it).
///
/// # Errors
/// `BadAck` if the sscanf would have returned `< 3` (`:960-963`).
pub fn parse_ack(line: &[u8]) -> Result<AckParsed, DispatchError> {
    // STRICTER than C: `%s` for port reads any non-whitespace; we
    // want u16. The C never sends non-numeric (it formats `myport.
    // udp` which `:846-858` ensures is decimal). A peer sending
    // "http" here would crash our `sockaddr_setport` later anyway;
    // reject up front.
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
    // `%x` — hex without `0x` prefix.
    let options = toks
        .next()
        .and_then(|t| std::str::from_utf8(t).ok())
        .and_then(|s| u32::from_str_radix(s, 16).ok())
        .ok_or_else(|| DispatchError::BadAck("bad options".into()))?;

    Ok(AckParsed {
        his_udp_port: port,
        his_weight: weight,
        his_options: options,
    })
}

// ───────────────────────────────────────────────────────────────────
// chunk-5 handler parse fns
//
// Same parse/mutate split as parse_ack/on_ack. The parse fns take
// the SPTPS record body (`\n` already stripped by `record_body`),
// convert &[u8] → &str, delegate to tinc-proto's parsers (which
// already do `check_id` + `from != to`), wrap errors in our
// `DispatchError`.
//
// All four are thin wrappers. The C `sscanf` + `check_id` + name-
// equality is one block (`protocol_edge.c:77-92`, `protocol_subnet.
// c:49-68`); tinc-proto already does that block. We just glue.

/// `add_subnet_h` parse step (`protocol_subnet.c:49-68`). Returns
/// `(owner_name, subnet)`. `check_id` already enforced by
/// `SubnetMsg::parse`. The C also calls `subnetcheck` (`conf_net.c:
/// 17`, host bits must be zero) but `add_subnet_h` itself doesn't —
/// it relies on `str2net` accepting and the LATER `lookup_subnet`
/// just not finding `10.0.0.1/24` if `10.0.0.0/24` is what's stored.
/// We match: no `is_canonical` check here.
///
/// # Errors
/// `BadSubnet` if not UTF-8 (impossible from a real C peer; sscanf
/// `%s` reads bytes but node names are `check_id`-gated to ASCII)
/// or if `SubnetMsg::parse` fails (sscanf < 2, bad name, bad net).
pub fn parse_add_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadSubnet("not UTF-8".into()))?;
    let m = tinc_proto::msg::SubnetMsg::parse(s)
        .map_err(|_| DispatchError::BadSubnet("parse failed".into()))?;
    Ok((m.owner, m.subnet))
}

/// `del_subnet_h` parse step (`protocol_subnet.c:163-188`). Same
/// wire shape as ADD. Same parser.
///
/// # Errors
/// See [`parse_add_subnet`].
pub fn parse_del_subnet(body: &[u8]) -> Result<(String, tinc_proto::Subnet), DispatchError> {
    // Identical to add. The C `sscanf` is the same format string.
    // Separate fn for the daemon's match-arm clarity (and the error
    // message).
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadSubnet("not UTF-8".into()))?;
    let m = tinc_proto::msg::SubnetMsg::parse(s)
        .map_err(|_| DispatchError::BadSubnet("parse failed".into()))?;
    Ok((m.owner, m.subnet))
}

/// `add_edge_h` parse step (`protocol_edge.c:77-92`). `AddEdge::
/// parse` already does the 6-or-8 token check, `check_id` on both
/// names, and `from != to`.
///
/// # Errors
/// `BadEdge` if not UTF-8 or `AddEdge::parse` fails.
pub fn parse_add_edge(body: &[u8]) -> Result<tinc_proto::msg::AddEdge, DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadEdge("not UTF-8".into()))?;
    tinc_proto::msg::AddEdge::parse(s).map_err(|_| DispatchError::BadEdge("parse failed".into()))
}

/// `del_edge_h` parse step (`protocol_edge.c:230-241`).
///
/// # Errors
/// `BadEdge` if not UTF-8 or `DelEdge::parse` fails.
pub fn parse_del_edge(body: &[u8]) -> Result<tinc_proto::msg::DelEdge, DispatchError> {
    let s = std::str::from_utf8(body).map_err(|_| DispatchError::BadEdge("not UTF-8".into()))?;
    tinc_proto::msg::DelEdge::parse(s).map_err(|_| DispatchError::BadEdge("parse failed".into()))
}

/// `meta.c:155-158`: strip the trailing `\n` from an SPTPS record
/// body before dispatching to `receive_request`.
///
/// C: `if(data[length-1] == '\n') data[length-1] = 0`. The check
/// is conditional because pre-transition records (the PRF-derived
/// random bytes during early SPTPS development?) might not have
/// `\n`. In practice, `send_request` always appends one. We strip
/// if present, leave alone if not. Same.
#[must_use]
pub fn record_body(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

/// `control_h` (`control.c:45-145`). Second token is the subtype
/// (`REQ_STOP=0` etc). Skeleton handles STOP only; everything else
/// gets `REQ_INVALID` reply (C `control.c:144`).
///
/// Line format: `"18 <subtype> [args...]"`.
///
/// Returns `(result, needs_write)`. `needs_write` for the io_set;
/// `result` is `Stop` for REQ_STOP, `Ok` for REQ_INVALID-reply.
/// Never `Drop` — `control_h` always returns `true` in C; the
/// connection stays open. The CLI reads the reply then closes
/// from its end.
///
/// `single_match_else` allowed: this match is the C `switch` from
/// `control.c:58-144`. It WILL grow arms (REQ_RELOAD, REQ_DUMP_*,
/// REQ_DEBUG, ...). Rewriting as `if let` now means rewriting back
/// to `match` in chunk 3. The C is a switch; the Rust is a match.
#[allow(clippy::single_match_else)]
pub fn handle_control(conn: &mut Connection, line: &[u8]) -> (DispatchResult, bool) {
    // C `control.c:50`: `sscanf(request, "%*d %d", &type)`.
    // Second token, parse as int.
    let subtype = line
        .split(|&b| b.is_ascii_whitespace())
        .nth(1)
        .and_then(|t| std::str::from_utf8(t).ok())
        .and_then(|s| s.parse::<i32>().ok());

    match subtype {
        Some(REQ_DUMP_NODES) => {
            // `control.c:63`: `case REQ_DUMP_NODES: return
            // dump_nodes(c)`. Daemon walks the graph.
            (DispatchResult::DumpNodes, false)
        }
        Some(REQ_DUMP_EDGES) => {
            // `control.c:66`: `case REQ_DUMP_EDGES: return
            // dump_edges(c)`. Daemon walks per-node edge lists.
            (DispatchResult::DumpEdges, false)
        }
        Some(REQ_DUMP_SUBNETS) => {
            // `control.c:69`: `case REQ_DUMP_SUBNETS: return
            // dump_subnets(c)`. Daemon walks SubnetTree.
            (DispatchResult::DumpSubnets, false)
        }
        Some(REQ_DUMP_CONNECTIONS) => {
            // `control.c:80`: `case REQ_DUMP_CONNECTIONS: return
            // dump_connections(c)`. The walk-and-format is in
            // the daemon (it has the slotmap). Signal that.
            (DispatchResult::DumpConnections, false)
        }
        Some(REQ_STOP) => {
            // C `control.c:59-61`: `event_exit(); return control_ok(
            // c, REQ_STOP)`. `control_ok` is `control_return(c, type,
            // 0)` which is `send_request(c, "%d %d %d", CONTROL, type,
            // error)`. So: `"18 0 0"`.
            log::info!(target: "tincd", "Got REQ_STOP, shutting down");
            let needs_write = conn.send(format_args!("{} {} 0", Request::Control as u8, REQ_STOP));
            (DispatchResult::Stop, needs_write)
        }
        _ => {
            // C `control.c:143-144`: `default: return send_request(c,
            // "%d %d", CONTROL, REQ_INVALID)`. Connection stays open.
            // The `subtype = None` case (malformed) hits this too —
            // C: `sscanf` returns 1 (matched the `%*d` only), `type`
            // is uninitialized garbage, switch falls through to
            // default. We get the same outcome more deliberately.
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

    /// `/dev/null` as an OwnedFd. The proto handlers don't read
    /// from the fd (only `feed`/`flush` do); they just need a valid
    /// Connection.
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

    /// IdCtx for tests where the peer branch ISN'T the focus. The
    /// dummy key has a static lifetime (`OnceLock`) so we can return
    /// `IdCtx<'static>` — otherwise the key dies before the ctx and
    /// every test grows a `let mykey = ...` line. Same pattern as
    /// `mkconn` for the same reason.
    ///
    /// `confbase = "."` means peer-branch tests with `mkctx` will
    /// fail at the pubkey load (no `./hosts/NAME`). That's fine —
    /// tests that REACH the pubkey load use `PeerSetup` + a real ctx.
    /// `mkctx` is for tests that stop earlier (control branch,
    /// invitation reject, check_id reject, ...).
    fn mkctx(cookie: &str) -> IdCtx<'_> {
        static DUMMY_KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
        let mykey = DUMMY_KEY.get_or_init(|| SigningKey::from_seed(&[0x99; 32]));
        IdCtx {
            cookie,
            my_name: "testd",
            mykey,
            confbase: Path::new("."),
        }
    }

    use rand_core::OsRng;

    // ─── check_gate

    /// Named outcome for the gate table below. We can't use
    /// `DispatchError` directly: it's not `PartialEq` (the `BadId(
    /// String)` variant). The gate only ever produces these three.
    #[derive(Debug, PartialEq)]
    enum GateExpect {
        Ok(Request),
        Unauthorized,
        UnknownRequest,
    }

    /// `check_gate(allow, line) -> GateResult`. Full allow/deny
    /// matrix + malformed inputs. Covers C `:receive_request`'s
    /// `atoi`, `*request == '0'`, range check, and `allow_request`
    /// gate.
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
            // Leading whitespace, then nothing — same.
            (Some(Request::Id), b"  ",         UnknownRequest),
            // ─── out of range. `Request::from_id(99)` → None.
            (None,              b"99 foo",     UnknownRequest),
            (None,              b"-1 foo",     UnknownRequest),
            // ─── STRICTER than C `atoi`: `"18foo"` → reject. C would
            // parse 18. The C never sends this (always `"%d "`); a
            // peer that does is broken.
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

    /// The happy path. `tinc-tools/ctl.rs:491` sends `"0 ^<cookie> 0"`.
    /// We set the control fields and queue two reply lines.
    #[test]
    fn id_control_auth_ok() {
        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let line = format!("0 ^{cookie} 0");

        let r = handle_id(
            &mut c,
            line.as_bytes(),
            &mkctx(&cookie),
            Instant::now(),
            &mut OsRng,
        )
        .unwrap();

        let IdOk::Control { needs_write } = r else {
            panic!("expected Control, got {r:?}");
        };
        assert!(needs_write, "outbuf was empty → needs_write");
        assert!(c.control);
        assert_eq!(c.allow_request, Some(Request::Control));

        // Two lines queued. `tinc-tools/tests/tinc_cli.rs:1798` and
        // `:1799` expect EXACTLY this format.
        let our_pid = std::process::id();
        let expected = format!("0 testd 17.7\n4 0 {our_pid}\n");
        assert_eq!(c.outbuf.live(), expected.as_bytes());
    }

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

    /// Early-reject paths in `handle_id`: all branches that bail
    /// BEFORE the pubkey load. They share the property that
    /// `mkctx("x")` (dummy cookie, confbase=".") suffices — if any
    /// of these reached the filesystem, they'd error on missing
    /// `./hosts/NAME` instead of the intended error. The Err proves
    /// we didn't get that far.
    #[test]
    fn id_early_rejects() {
        #[rustfmt::skip]
        let cases: &[(&[u8], &str)] = &[
            // `?` prefix (invitation) — chunk 4a still rejects (no
            // invitation key loaded). C: `if(!invitation_key) return
            // false`.
            (b"0 ?somekey 17.7",     "invitation, no key"),
            // `check_id` reject: name with `/`. SECURITY: this is the
            // path-traversal gate. C `:376`: `!check_id(name)`. If
            // check_id failed and we still tried to load, we'd open
            // `./hosts/../etc/passwd` — traversal.
            (b"0 ../etc/passwd 17.7", "path traversal"),
            // Peer claims to be us. C `:376`: `|| !strcmp(name,
            // myself->name)`. Infinite-edge-loop prevention.
            // (mkctx my_name == "testd".)
            (b"0 testd 17.7",        "peer is self"),
            // Malformed: no second token. C `sscanf` returns 0
            // (`< 2` check fails), logs "Got bad ID", returns false.
            (b"0",                   "no name token"),
            // Malformed: no version token. C `sscanf` returns 1
            // (`< 2` fails).
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

    /// Tempdir + hosts/ layout for peer-branch tests. Same idiom as
    /// `keys.rs::tests::TmpDir`.
    struct PeerSetup {
        tmp: std::path::PathBuf,
    }
    impl PeerSetup {
        fn new(tag: &str, peer_name: &str, peer_pub: &[u8; 32]) -> Self {
            let tid = std::thread::current().id();
            let tmp = std::env::temp_dir().join(format!("tincd-proto-{tag}-{tid:?}"));
            std::fs::create_dir_all(tmp.join("hosts")).unwrap();
            // Write the peer's pubkey as inline b64 (source 1 in
            // read_ecdsa_public_key — simplest).
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

    /// Happy path: peer ID accepted, SPTPS started, init Wire
    /// returned. ALL the post-conditions.
    #[test]
    fn id_peer_ok() {
        let mykey = SigningKey::from_seed(&[1; 32]);
        let peerkey = SigningKey::from_seed(&[2; 32]);
        let setup = PeerSetup::new("peer-ok", "alice", peerkey.public_key());

        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let ctx = IdCtx {
            cookie: &cookie,
            my_name: "testd",
            mykey: &mykey,
            confbase: setup.confbase(),
        };

        let r = handle_id(&mut c, b"0 alice 17.7", &ctx, Instant::now(), &mut OsRng).unwrap();

        // Return type: Peer with needs_write + init outputs.
        let IdOk::Peer { needs_write, init } = r else {
            panic!("expected Peer, got {r:?}");
        };
        assert!(needs_write, "outbuf was empty → send_id signals");
        // sptps_start always emits one Wire (the responder's KEX).
        // C `sptps.c:send_kex` is called synchronously inside
        // `sptps_start`.
        assert_eq!(init.len(), 1);
        assert!(matches!(init[0], Output::Wire { .. }));

        // ─── conn state
        // C `:389`: `c->name = name`.
        assert_eq!(c.name, "alice");
        // C `:455` then `:456`: `allow_request = ACK`.
        assert_eq!(c.allow_request, Some(Request::Ack));
        // Minor parsed from `"17.7"`.
        assert_eq!(c.protocol_minor, 7);
        // Pubkey loaded.
        assert_eq!(c.ecdsa, Some(*peerkey.public_key()));
        // SPTPS installed.
        assert!(c.sptps.is_some());
        // NOT a control conn.
        assert!(!c.control);

        // ─── outbuf: ONLY the send_id line, NOT the KEX bytes
        // The init Wire bytes are RETURNED for the daemon to queue
        // via send_raw. handle_id doesn't queue them itself —
        // ownership of the dispatch lives in the daemon (consistent
        // with feed_sptps's outputs).
        assert_eq!(c.outbuf.live(), b"0 testd 17.7\n");
    }

    /// Major mismatch. C `:398-401`: hard reject. major bumps are
    /// wire-breaking.
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
        };

        // 18.7 — major 18, we're 17.
        let r = handle_id(&mut c, b"0 alice 18.7", &ctx, Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
        // The name DID get set (mutation before the version check).
        // C also does this — `:389` is before `:398`. Harmless;
        // the connection is dropped right after.
        assert_eq!(c.name, "alice");
        // SPTPS NOT installed.
        assert!(c.sptps.is_none());
    }

    /// Unknown identity: no `hosts/alice` file. The C's `:428`
    /// "unknown identity" + our "no pubkey" collapse.
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
        };

        let r = handle_id(&mut c, b"0 alice 17.7", &ctx, Instant::now(), &mut OsRng);
        let Err(DispatchError::BadId(msg)) = r else {
            panic!("expected BadId, got {r:?}");
        };
        // Error message mentions the name + "unknown identity"
        // (matching the spirit of C `:428`).
        assert!(msg.contains("alice"), "msg: {msg}");
        assert!(msg.contains("unknown identity"), "msg: {msg}");
        assert!(c.sptps.is_none());
    }

    /// Rollback attempt: known peer (have their pubkey) sends
    /// minor=0. C `:443-447`: reject. We're STRICTER: minor=1
    /// also rejected (we forbid legacy at any minor < 2).
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
        };

        // minor=0: C `:443` rejects (`ecdsa_active && minor < 1`).
        let r = handle_id(&mut c, b"0 alice 17.0", &ctx, Instant::now(), &mut OsRng);
        let Err(DispatchError::BadId(msg)) = r else {
            panic!("expected BadId, got {r:?}");
        };
        assert!(msg.contains("roll back"), "msg: {msg}");

        // minor=1: C would `send_metakey` (legacy). We reject.
        // STRICTER. The error message is the same (we don't
        // distinguish 0 from 1; both are < 2).
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0 alice 17.1", &ctx, Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
    }

    /// Minor parse: `"17"` (no dot) → minor=0. C sscanf `%d.%d`
    /// reads major, `.` fails, returns 2, minor stays xzalloc'd 0.
    /// Then minor=0 < 2 → rollback reject (we have the key).
    ///
    /// This pins the parse: `"17"` is NOT a parse error. It's a
    /// successful parse with minor=0, then a SEMANTIC reject. The
    /// distinction matters: a peer that genuinely sends `"0 alice
    /// 17"` (no minor) gets a "roll back" error, not a "malformed"
    /// error — same as C.
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
        };

        let r = handle_id(&mut c, b"0 alice 17", &ctx, Instant::now(), &mut OsRng);
        let Err(DispatchError::BadId(msg)) = r else {
            panic!("expected BadId, got {r:?}");
        };
        // "roll back" not "malformed" — the parse SUCCEEDED.
        assert!(msg.contains("roll back"), "msg: {msg}");
        // protocol_minor was set to the parsed 0 BEFORE the reject.
        // (Same as C: `:399` `c->protocol_minor = ...` is implicit
        // in the sscanf to `&c->protocol_minor`, before any check.)
        assert_eq!(c.protocol_minor, 0);
    }

    // ─── tcp_label (the NUL)

    /// THE WIRE-COMPAT TEST. The label includes a trailing NUL.
    /// gcc-verified C output for `("alice", "bob")`:
    ///   labellen = 33, strlen = 32, byte 32 = 0x00
    /// Hex: `74696e63...626f6200`.
    ///
    /// If this test fails, the SPTPS handshake against a real C
    /// tincd will fail at SIG verify (`SptpsError::BadSig`). The
    /// integration test (`stop.rs::peer_handshake`) catches the
    /// SAME failure but takes 100ms+ to run; this is the fast
    /// fail.
    #[test]
    fn tcp_label_has_trailing_nul() {
        let label = tcp_label("alice", "bob");
        // The C `25 + strlen("alice") + strlen("bob")`.
        assert_eq!(label.len(), 25 + 5 + 3);
        assert_eq!(label.len(), 33);
        // Last byte is NUL.
        assert_eq!(label[32], 0);
        // Penultimate byte is `b'b'` (last char of "bob").
        assert_eq!(label[31], b'b');
        // The exact bytes (gcc output, hex-decoded).
        assert_eq!(&label[..], b"tinc TCP key expansion alice bob\0");
    }

    /// Label argument order: ALWAYS initiator, responder. C `:460-
    /// 465`: outgoing→(myself, peer), inbound→(peer, myself).
    /// The two calls produce DIFFERENT labels (and thus different
    /// keys). If we get the order wrong, the SIG transcripts won't
    /// match (initiator hashes one label, responder hashes the
    /// other → BadSig).
    #[test]
    fn tcp_label_order_matters() {
        let a = tcp_label("alice", "bob");
        let b = tcp_label("bob", "alice");
        assert_ne!(a, b);
        // Both have the prefix.
        assert!(a.starts_with(b"tinc TCP key expansion alice "));
        assert!(b.starts_with(b"tinc TCP key expansion bob "));
    }

    /// `check_id` is the path-traversal gate. Same fn as
    /// `tinc-tools/names.rs:495`. Pin the security-relevant cases.
    #[test]
    fn check_id_security() {
        // Valid names.
        assert!(check_id("alice"));
        assert!(check_id("node_01"));
        assert!(check_id("A")); // single char

        // Traversal attempts. ALL must fail.
        assert!(!check_id("../etc")); // contains `/` AND `.`
        assert!(!check_id("a/b"));
        assert!(!check_id(".")); // `.` isn't alnum
        assert!(!check_id(".."));
        // Space (would break wire-protocol token splitting).
        assert!(!check_id("a b"));
        // Empty.
        assert!(!check_id(""));
        // The `^` prefix (control sigil) — not a valid PEER name.
        assert!(!check_id("^abc"));
    }

    /// `protocol_auth.c:328`: `c->last_ping_time = now.tv_sec + 3600`.
    /// Control conns are exempt from the ping timeout sweep for an
    /// hour. The sweep checks `last_ping_time + pingtimeout <= now`;
    /// pushing last_ping_time AHEAD by 3600 means `now + 3600 + 5
    /// <= now` is never true.
    #[test]
    fn id_bumps_ping_time() {
        let mut c = mkconn();
        let now = Instant::now();
        let cookie = "a".repeat(64);
        let line = format!("0 ^{cookie} 0");

        handle_id(&mut c, line.as_bytes(), &mkctx(&cookie), now, &mut OsRng).unwrap();

        // last_ping_time is now + 3600s. We can't compare Instants
        // directly with literals, but: it's > now + 3000s for sure.
        assert!(c.last_ping_time > now + std::time::Duration::from_secs(3000));
    }

    // ─── handle_control

    #[test]
    fn control_stop() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control); // post-id_h state

        let (r, nw) = handle_control(&mut c, b"18 0");
        assert_eq!(r, DispatchResult::Stop);
        assert!(nw);
        assert_eq!(c.outbuf.live(), b"18 0 0\n");
    }

    /// `REQ_RELOAD` (1) — not implemented in skeleton. Returns
    /// `REQ_INVALID` reply, connection stays open.
    #[test]
    fn control_unknown_subtype() {
        let mut c = mkconn();
        c.allow_request = Some(Request::Control);

        let (r, nw) = handle_control(&mut c, b"18 1");
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

    /// `PROT_MAJOR/PROT_MINOR` pin. tinc-proto already pins these
    /// against `protocol.h`; this is a redundant assertion that
    /// the greeting format would change if they did. Belt-and-
    /// braces: if PROT_MINOR bumps to 8, this test fails AND
    /// `id_control_auth_ok`'s `expected` string fails.
    #[test]
    fn proto_version_pin() {
        assert_eq!(PROT_MAJOR, 17);
        assert_eq!(PROT_MINOR, 7);
        assert_eq!(CTL_VERSION, 0);
    }

    // ─── send_ack / parse_ack

    /// `myself->options` default. C `net_setup.c:442-453,800`. PMTU
    /// on (no TCPOnly), ClampMSS on, PROT_MINOR=7 in top byte.
    /// `0x0700000c`.
    #[test]
    fn myself_options_default_value() {
        let opts = myself_options_default();
        // Low byte: PMTU(4) | CLAMP(8) = 0xc.
        assert_eq!(opts & 0xff, 0x0c);
        // Top byte: PROT_MINOR.
        assert_eq!(opts >> 24, u32::from(PROT_MINOR));
        // The other 16 bits are 0.
        assert_eq!(opts & 0x00ff_ff00, 0);
        // Full value (pins the literal; if PROT_MINOR bumps, fail).
        assert_eq!(opts, 0x0700_000c);
    }

    /// `send_ack` wire format. C `:867`: `"%d %s %d %x"`. The
    /// connection has SPTPS installed (post-HandshakeDone) so this
    /// goes through `sptps_send_record` — we DON'T have a real
    /// post-handshake SPTPS in a unit test (needs the full dance).
    /// So: test the PRE-SPTPS path (sptps=None). The format
    /// arguments are identical; only the framing differs.
    ///
    /// (The post-handshake path IS tested by the integration test
    /// `peer_ack_exchange` which gets the ACK over a real SPTPS.)
    #[test]
    fn send_ack_format() {
        let mut c = mkconn();
        // Fake `start` 50ms ago. weight = 50. `Instant - Duration`
        // panics if `now` < boot+50ms; checked_sub is the explicit
        // form. Tests run > 50ms after boot, so unwrap is safe.
        let now = Instant::now();
        c.start = now
            .checked_sub(std::time::Duration::from_millis(50))
            .unwrap();
        c.protocol_minor = 7; // pass the debug_assert

        let nw = send_ack(&mut c, 655, myself_options_default(), now);
        assert!(nw);

        // C: "4 655 50 700000c\n". %x is lowercase, no padding,
        // no 0x prefix.
        let line = std::str::from_utf8(c.outbuf.live()).unwrap();
        // Weight depends on the actual elapsed time. We faked
        // start = now - 50ms; saturating_duration_since gives
        // exactly 50ms. as_millis = 50. (Instant arithmetic is
        // exact on the monotonic clock; no flake.)
        assert_eq!(line, "4 655 50 700000c\n");
        // Side effects.
        assert_eq!(c.estimated_weight, 50);
        assert_eq!(c.options, OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS);
    }

    /// `parse_ack` round-trip. The peer's send_ack → our parse.
    #[test]
    fn parse_ack_roundtrip() {
        // What a peer sends. PROT_MINOR=7, PMTU+CLAMP set.
        let line = b"4 655 50 700000c";
        let parsed = parse_ack(line).unwrap();
        assert_eq!(parsed.his_udp_port, 655);
        assert_eq!(parsed.his_weight, 50);
        assert_eq!(parsed.his_options, 0x0700_000c);
        // The PMTU/CLAMP bits.
        assert_eq!(
            parsed.his_options & 0xff,
            OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS
        );
    }

    /// `parse_ack` malformed cases. C `:960`: `sscanf < 3` → false.
    #[test]
    fn parse_ack_malformed() {
        // Missing options.
        assert!(matches!(
            parse_ack(b"4 655 50"),
            Err(DispatchError::BadAck(_))
        ));
        // Non-numeric port. C `%s` would read it; we reject.
        // STRICTER. The C would later crash in `sockaddr_setport`
        // (which does `service_to_port` → fail → NULL); we fail
        // earlier with a typed error.
        assert!(matches!(
            parse_ack(b"4 http 50 c"),
            Err(DispatchError::BadAck(_))
        ));
        // Weight: negative is fine (i32, %d). Unlikely but valid.
        let p = parse_ack(b"4 655 -1 c").unwrap();
        assert_eq!(p.his_weight, -1);
        // Options: bad hex.
        assert!(matches!(
            parse_ack(b"4 655 50 0xZZ"),
            Err(DispatchError::BadAck(_))
        ));
    }

    /// `record_body` strips trailing `\n` (C `meta.c:155-158`).
    #[test]
    fn record_body_strip() {
        // Normal case: send_request appends \n, we strip.
        assert_eq!(record_body(b"4 655 50 c\n"), b"4 655 50 c");
        // No \n: leave alone (the C check is conditional).
        assert_eq!(record_body(b"4 655 50 c"), b"4 655 50 c");
        // Empty.
        assert_eq!(record_body(b""), b"");
        // Just \n.
        assert_eq!(record_body(b"\n"), b"");
    }
}
