//! Protocol dispatch for the daemon side. Ports `protocol.c::receive_
//! request` (49 LOC), `protocol_auth.c::id_h` `^` branch (14 LOC),
//! and `control.c::control_h` `REQ_STOP` only (~20 LOC).
//!
//! ## Why this is separate from `conn.rs`
//!
//! `Connection` is the byte-level transport (recv into inbuf, send
//! from outbuf). This module is the line-level protocol: a complete
//! line came out of `inbuf`, what now?
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

use std::time::Instant;

use tinc_proto::Request;
use tinc_proto::request::{PROT_MAJOR, PROT_MINOR};

use crate::conn::Connection;

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

/// `id_h` (`protocol_auth.c:314-338`), control branch only.
///
/// Line format: `"0 ^<cookie> 0"` where the trailing `0` is
/// `TINC_CTL_VERSION_CURRENT`. The C `sscanf("%*d %s %d.%d")`
/// reads: skip the request number, read `name` (which for control
/// is `^<64-hex>`), read `protocol_major.protocol_minor` (which
/// for control is `0` — wait, the CLI sends `"0 ^<cookie> 0\n"`
/// per `tinc-tools/ctl.rs:491`. The `%d.%d` reads `0` for major,
/// fails on `.` for minor since there's no `.`. `sscanf` returns
/// 2 (matched two of four), the `< 2` check passes. Minor stays
/// at whatever `c->protocol_minor` was (0, from `xzalloc`). FINE.)
///
/// We parse: second token starts with `^`, rest is cookie, compare.
///
/// On success: set `control = true`, `allow_request = CONTROL`,
/// queue `send_id` + ACK responses. On failure: `BadId`.
///
/// Returns `true` if outbuf went empty→non-empty (caller registers
/// IO_WRITE). The C does this implicitly via `send_request →
/// send_meta → io_set`.
///
/// # Errors
/// `BadId` if not `^`, or cookie mismatch, or malformed.
pub fn handle_id(
    conn: &mut Connection,
    line: &[u8],
    cookie: &str,
    my_name: &str,
    now: Instant,
) -> Result<bool, DispatchError> {
    // Second token. C: `sscanf("%*d %s %d.%d", name, ...)`.
    // The `%s` reads non-whitespace — so `^abc...` whole.
    let name_tok = line
        .split(|&b| b.is_ascii_whitespace())
        .nth(1)
        .ok_or_else(|| DispatchError::BadId("no name token".into()))?;

    // ─── `^` branch (protocol_auth.c:325-338) ────────────────────
    let Some(rest) = name_tok.strip_prefix(b"^") else {
        // Skeleton: `?` (invitation) and bare names (peers) are
        // NOT YET. Log and drop. C would proceed to `check_id` and
        // the auth handshake.
        let prefix = name_tok.first().copied().unwrap_or(b' ');
        return Err(DispatchError::BadId(format!(
            "non-control ID (prefix {prefix:?}); peer/invite not implemented"
        )));
    };

    // C `!strcmp(name + 1, controlcookie)`. Cookie is 64 hex chars,
    // ASCII. Constant-time compare? The C uses strcmp (NOT constant
    // time). The cookie is mode-0600 secret + the daemon is on a
    // unix socket (already authenticated by fs perms). Timing attack
    // is not in the threat model. `==` on `[u8]` is fine.
    if rest != cookie.as_bytes() {
        // C: `id_h` returns `false` if `^` but bad cookie? NO —
        // C: `if(name[0] == '^' && !strcmp(...))` — if `^` but
        // strcmp fails, the condition is false, falls through to
        // `check_id(name)` at :395 which fails (`^` isn't alnum),
        // logs "Invalid name", returns false. Same outcome for us.
        return Err(DispatchError::BadId("cookie mismatch".into()));
    }

    // ─── Auth OK. Set the control fields. ────────────────────────
    // `c->status.control = true; c->allow_request = CONTROL;`
    conn.control = true;
    conn.allow_request = Some(Request::Control);
    // `c->last_ping_time = now.tv_sec + 3600`. Exempt from ping
    // timeout for an hour. Practically: forever (the CLI disconnects
    // when done; nobody holds a control conn for an hour).
    conn.last_ping_time = now + std::time::Duration::from_secs(3600);
    // `free(c->name); c->name = xstrdup("<control>")`. Already set
    // by `new_control`, but the C does it here because the same
    // `connection_t` is used for peers (which set name to the peer's
    // node name). Idempotent for us.

    // ─── Send replies. ────────────────────────────────────────────
    // C `if(!c->outgoing) send_id(c)` — for accepted connections
    // (which all unix-socket conns are; `outgoing` is NULL),
    // send our own ID greeting. `send_id` (`protocol_auth.c:116`):
    // `send_request(c, "%d %s %d.%d", ID, my_name, PROT_MAJOR, minor)`.
    // For control conns `experimental` is set (we have an ecdsa key)
    // so `minor = PROT_MINOR`.
    let needs_write = conn.send(format_args!(
        "{} {} {}.{}",
        Request::Id as u8,
        my_name,
        PROT_MAJOR,
        PROT_MINOR
    ));

    // C `return send_request(c, "%d %d %d", ACK, TINC_CTL_VERSION_
    // CURRENT, getpid())`.
    conn.send(format_args!(
        "{} {} {}",
        Request::Ack as u8,
        CTL_VERSION,
        std::process::id()
    ));

    // `needs_write` is `true` if outbuf was empty before the FIRST
    // send. Second send returned `false` (outbuf already had line 1).
    // We only care about the empty→non-empty transition.
    Ok(needs_write)
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

    // ─── check_gate ───────────────────────────────────────────────

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

    // ─── handle_id ────────────────────────────────────────────────

    /// The happy path. `tinc-tools/ctl.rs:491` sends `"0 ^<cookie> 0"`.
    /// We set the control fields and queue two reply lines.
    #[test]
    fn id_control_auth_ok() {
        let mut c = mkconn();
        let cookie = "a".repeat(64);
        let line = format!("0 ^{cookie} 0");

        let nw = handle_id(&mut c, line.as_bytes(), &cookie, "testd", Instant::now()).unwrap();

        assert!(nw, "outbuf was empty → needs_write");
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

        let r = handle_id(&mut c, line.as_bytes(), &cookie, "testd", Instant::now());
        assert!(matches!(r, Err(DispatchError::BadId(_))));
        // No state change on failure.
        assert!(!c.control);
        assert_eq!(c.allow_request, Some(Request::Id));
        assert!(c.outbuf.is_empty());
    }

    /// `?` prefix (invitation) — skeleton rejects. C would proceed
    /// to invitation key check.
    #[test]
    fn id_invitation_rejected_in_skeleton() {
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0 ?somekey 17.7", "x", "testd", Instant::now());
        assert!(matches!(r, Err(DispatchError::BadId(_))));
    }

    /// Bare name (peer) — skeleton rejects.
    #[test]
    fn id_peer_rejected_in_skeleton() {
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0 alice 17.7", "x", "testd", Instant::now());
        assert!(matches!(r, Err(DispatchError::BadId(_))));
    }

    /// Malformed: no second token. The C `sscanf` returns 0 (`< 2`
    /// check fails), logs "Got bad ID", returns false.
    #[test]
    fn id_malformed_no_name() {
        let mut c = mkconn();
        let r = handle_id(&mut c, b"0", "x", "testd", Instant::now());
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

        handle_id(&mut c, line.as_bytes(), &cookie, "testd", now).unwrap();

        // last_ping_time is now + 3600s. We can't compare Instants
        // directly with literals, but: it's > now + 3000s for sure.
        assert!(c.last_ping_time > now + std::time::Duration::from_secs(3000));
    }

    // ─── handle_control ───────────────────────────────────────────

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
