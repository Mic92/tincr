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
//! ## What `id_h` does for control
//!
//! `protocol_auth.c:314-338` — the FIRST thing any connection sends.
//! Three branches on `name[0]`:
//!
//! - `^` (`:325`): control. Check cookie, set `status.control = true`,
//!   `allow_request = CONTROL`, send back `send_id` + ACK.
//! - `?` (`:340`): invitation. Not in skeleton.
//! - else (`:380`): peer. Check `check_id`, look up node, etc.
//!   Not in skeleton.
//!
//! We handle `^` and reject the rest with a log line.
//!
//! ## What `control_h` does for STOP
//!
//! `control.c:45-145` — second token is the `CtlRequest` discriminant
//! (REQ_STOP=0, REQ_RELOAD=1, etc). For STOP:
//!
//! ```c
//! case REQ_STOP:
//!     event_exit();
//!     return control_ok(c, REQ_STOP);  // sends "18 0 0"
//! ```
//!
//! `event_exit` sets `running = false`; the loop exits after
//! finishing this turn. We return a `DispatchResult::Stop` to signal
//! the same.

use std::path::Path;
use std::time::Instant;

use rand_core::RngCore;
use tinc_crypto::sign::SigningKey;
use tinc_proto::Request;
use tinc_proto::request::{PROT_MAJOR, PROT_MINOR};
use tinc_sptps::{Framing, Output, Role, Sptps};

use crate::conn::Connection;
use crate::keys::read_ecdsa_public_key;

/// `control_common.h`: `REQ_STOP = 0`. Module-private; chunk 3+
/// adds the rest of the `CtlRequest` enum (or imports from
/// `tinc-tools::ctl::CtlRequest` if we resolve the layering).
const REQ_STOP: i32 = 0;
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
/// **THE TRAILING NUL IS WIRE-FORMAT-COMPAT.** Born in commit
/// `65d6f023` (2012-02-25, "Use SPTPS"): `char label[25 + strlen(a)
/// + strlen(b)]` is a VLA whose `sizeof` is the bracket expression.
/// `"tinc TCP key expansion "` is 23 chars; with `a`, `" "`, `b`
/// appended that's `24 + strlen(a) + strlen(b)` chars. The VLA
/// size is `25 + ...` = one byte more. `snprintf` writes a NUL
/// at `[labellen - 1]`. That NUL goes into `sptps_start` via
/// `(label, sizeof(label))`.
///
/// gcc-verified (`"alice"`, `"bob"`): `labellen = 33`, `strlen(label)
/// = 32`, `label[32] = 0x00`. Hex dump ends `...626f6200`.
///
/// The NUL feeds into the SIG transcript (`sptps.c:206`: `memcpy(msg,
/// s->label, s->labellen)`) and the PRF seed (`:258`). Both sides
/// must agree on `labellen` byte-for-byte or the SIG verify fails.
/// Missing the NUL → `SptpsError::BadSig` at handshake time.
///
/// The pre-`65d6f023` code (`8132be8f`, 2011) used `xasprintf` +
/// `strlen(seed)` — NO NUL. The switch to VLA+sizeof was for
/// stack allocation, not crypto; the NUL was a side effect. tinc
/// 1.1pre1 (2012-06) onwards has it.
///
/// Contrast: the invitation label `("tinc invitation", 15)` at
/// `protocol_auth.c:372` does NOT have the NUL — `strlen("tinc
/// invitation") == 15`. String literal + explicit count instead of
/// VLA + sizeof. So this is NOT a deliberate "NUL is part of every
/// label" policy. It's a historical accident at one call site.
///
/// Argument order: ALWAYS initiator-name, responder-name. C `:460-
/// 465`: `if(outgoing) myself, c->name; else c->name, myself`. The
/// initiator is whoever called `connect()`. Chunk 4a is responder-
/// only (we accepted), so the caller passes `(peer, me)`.
///
/// `pub(crate)` for the unit tests in this module and the
/// integration test in `tests/stop.rs`.
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

    #[test]
    fn gate_allows_expected() {
        let c = mkconn();
        // new_control sets allow_request = Some(Id).
        assert_eq!(check_gate(&c, b"0 ^abc 0").unwrap(), Request::Id);
    }

    #[test]
    fn gate_blocks_unexpected() {
        let c = mkconn();
        // Fresh conn allows only ID (0). CONTROL (18) is gated.
        assert!(matches!(
            check_gate(&c, b"18 0"),
            Err(DispatchError::Unauthorized)
        ));
    }

    #[test]
    fn gate_none_allows_all() {
        let mut c = mkconn();
        c.allow_request = None; // ALL
        assert_eq!(check_gate(&c, b"18 0").unwrap(), Request::Control);
        assert_eq!(check_gate(&c, b"0 foo 17.7").unwrap(), Request::Id);
        assert_eq!(check_gate(&c, b"8").unwrap(), Request::Ping);
    }

    /// `atoi("")` → 0 in C, but the `*request == '0'` check fails.
    /// We reject too: empty first token.
    #[test]
    fn gate_empty_line() {
        let c = mkconn();
        assert!(matches!(
            check_gate(&c, b""),
            Err(DispatchError::UnknownRequest)
        ));
        // Leading whitespace, then nothing — same.
        assert!(matches!(
            check_gate(&c, b"  "),
            Err(DispatchError::UnknownRequest)
        ));
    }

    /// Out of range. `Request::from_id(99)` → None.
    #[test]
    fn gate_out_of_range() {
        let mut c = mkconn();
        c.allow_request = None;
        assert!(matches!(
            check_gate(&c, b"99 foo"),
            Err(DispatchError::UnknownRequest)
        ));
        assert!(matches!(
            check_gate(&c, b"-1 foo"),
            Err(DispatchError::UnknownRequest)
        ));
    }

    /// STRICTER than C `atoi`: `"18foo"` → reject. C would parse 18.
    /// The C never sends this (always `"%d "`); a peer that does
    /// is broken.
    #[test]
    fn gate_stricter_than_atoi() {
        let mut c = mkconn();
        c.allow_request = None;
        assert!(matches!(
            check_gate(&c, b"18foo bar"),
            Err(DispatchError::UnknownRequest)
        ));
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

    /// `?` prefix (invitation) — chunk 4a still rejects (no
    /// invitation key loaded). C: `if(!invitation_key) return false`.
    #[test]
    fn id_invitation_rejected_no_key() {
        let mut c = mkconn();
        let r = handle_id(
            &mut c,
            b"0 ?somekey 17.7",
            &mkctx("x"),
            Instant::now(),
            &mut OsRng,
        );
        assert!(matches!(r, Err(DispatchError::BadId(_))));
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

    /// `check_id` reject: name with `/`. SECURITY: this is the
    /// path-traversal gate. C `:376`: `!check_id(name)`.
    #[test]
    fn id_peer_name_traversal_rejected() {
        let mut c = mkconn();
        let r = handle_id(
            &mut c,
            b"0 ../etc/passwd 17.7",
            &mkctx("x"),
            Instant::now(),
            &mut OsRng,
        );
        // BadId, AND we never touched the filesystem. (PeerSetup
        // wasn't created — confbase points at ".", which doesn't
        // have hosts/. If check_id failed and we still tried to
        // load, we'd open `./hosts/../etc/passwd` — traversal.
        // The Err proves we didn't get that far.)
        assert!(matches!(r, Err(DispatchError::BadId(_))));
        // No state mutation.
        assert!(c.sptps.is_none());
        assert_eq!(c.name, "<control>"); // mkconn's default
    }

    /// Peer claims to be us. C `:376`: `|| !strcmp(name, myself->
    /// name)`. Infinite-edge-loop prevention.
    #[test]
    fn id_peer_is_self_rejected() {
        let mut c = mkconn();
        // my_name == peer name == "testd".
        let r = handle_id(
            &mut c,
            b"0 testd 17.7",
            &mkctx("x"),
            Instant::now(),
            &mut OsRng,
        );
        assert!(matches!(r, Err(DispatchError::BadId(_))));
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

    /// Malformed: no second token. The C `sscanf` returns 0 (`< 2`
    /// check fails), logs "Got bad ID", returns false.
    #[test]
    fn id_malformed_no_name() {
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0", &mkctx("x"), Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
    }

    /// Malformed: no version token. C `sscanf` returns 1 (`< 2` fails).
    #[test]
    fn id_malformed_no_version() {
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0 alice", &mkctx("x"), Instant::now(), &mut OsRng);
        assert!(matches!(r, Err(DispatchError::BadId(_))));
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
}
