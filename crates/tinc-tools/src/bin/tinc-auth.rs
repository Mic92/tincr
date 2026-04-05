//! `tinc-auth` — nginx `auth_request` backend.
//!
//! Same shape as Tailscale's `cmd/nginx-auth/nginx-auth.go` (~130
//! LOC Go), but for tinc and without the semantic lie. Tailscale's
//! `Tailscale-User: alice@github` claims a *human* SSO'd in. tinc
//! has no humans, only nodes — `Name=alice` is a machine identity
//! backed by an Ed25519 key. So we say what we know:
//!
//! | Header        | Value                | Meaning                  |
//! |---------------|----------------------|--------------------------|
//! | `Tinc-Node`   | `alice`              | which node owns src IP   |
//! | `Tinc-Net`    | `mesh`               | netname (`-n`)           |
//! | `Tinc-Subnet` | `10.20.0.2`          | the matching subnet entry|
//!
//! If you want `X-Webauth-User`, that's two `auth_request_set`
//! lines in *your* nginx config. We don't pretend node = user.
//!
//! ## Mechanism
//!
//! 1. nginx subrequest hits us over a unix socket with
//!    `Remote-Addr: $remote_addr` set (nginx config).
//! 2. We send `REQ_DUMP_SUBNETS` to tincd's control socket and walk
//!    the dump doing a longest-prefix match against `Remote-Addr`.
//!    Same algorithm as `tinc info <addr>`: the daemon dumps
//!    everything, the client filters.
//! 3. Hit → 204 + headers. Miss / unparseable → 401. Dead daemon
//!    → 503 so nginx fails the auth subrequest cleanly.
//!
//! ## One control connection per request
//!
//! We `connect()` for every auth request. Tailscale's
//! `tailscale.WhoIs()` does the same (one localapi HTTP call per
//! WhoIs). nginx auth_request is a presence gate, not a per-asset
//! check; request rate is "page loads", not "every CSS file".
//! Persistent control connections would mean reconnect logic, stale
//! socket detection, daemon-restart races. Not worth it.
//!
//! For a 1000-node net the dump is ~60 KB. If that ever profiles
//! hot, push the lookup daemon-side (`REQ_LOOKUP_SUBNET`, ~30 LOC).
//! Don't pre-optimize.
//!
//! ## Socket activation
//!
//! `LISTEN_FDS`/`LISTEN_PID` like Tailscale. systemd owns the
//! socket → we don't need root to `bind()`, the unit can be
//! locked down. We *do* still need root to read tincd's pidfile
//! (mode 0600, written before `-U` privdrop). In practice that
//! means the unit runs as root, or you fix the daemon's perm
//! model. Separate problem; this binary doesn't make it worse.
//!
//! ## Why hand-rolled HTTP/1.1
//!
//! `hyper` is 50 transitive deps. We answer exactly one request
//! shape (`GET / HTTP/1.1` over a unix socket from nginx). No
//! keepalive, no chunked encoding, no body. Read until `\r\n\r\n`,
//! find one header, write a static response. ~40 lines.

// `deny` not `forbid`: `from_raw_fd` for socket activation is the
// one unsafe call. Same tradeoff as lib.rs's `localtime_r` shim —
// std has no safe wrapper because "this fd is uniquely yours" is
// a runtime contract the type system can't express.
#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_proto::Subnet;
use tinc_proto::subnet::DEFAULT_WEIGHT;
use tinc_tools::cmd::dump::{SubnetRow, strip_weight};
use tinc_tools::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use tinc_tools::names::{Paths, PathsInput};

/// systemd socket activation: first passed fd. `sd_listen_fds(3)`.
const SD_LISTEN_FDS_START: i32 = 3;

/// Max request size we'll buffer. nginx auth_request subrequests
/// are tiny (no body, `proxy_pass_request_body off`). 4 KB is
/// over 10× a real subrequest's headers; the cap stops a slow-loris
/// from holding a thread on a connection that never sends `\r\n\r\n`.
const MAX_REQUEST_BYTES: usize = 4096;

/// HTTP request from nginx. We only care about one header.
struct Request {
    /// `Remote-Addr` — nginx's `$remote_addr`. Literal string; we
    /// parse to `IpAddr` separately so a parse failure is "401
    /// unknown client", not "400 bad request from nginx" (the
    /// header *was* set, the IP is just garbage).
    remote_addr: Option<String>,
}

/// Read until `\r\n\r\n` or `MAX_REQUEST_BYTES`. Don't care about
/// the request line — nginx only sends `GET /` here, and there's
/// no other route to dispatch to. Tailscale's nginx-auth ignores
/// it the same way (`mux.HandleFunc("/", ...)`).
///
/// Returns `None` on a malformed request (no terminator before EOF
/// or limit). The caller responds 400.
fn read_request(stream: &UnixStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut remote_addr = None;
    let mut total = 0usize;

    // Line-at-a-time. A `\r\n` line (which `read_line` gives us as
    // `"\r\n"`) is the header terminator. We loop until we see it
    // because nginx will block waiting for our response otherwise —
    // `proxy_pass_request_body off` strips the body but the
    // subrequest still has a complete header set.
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).ok()?;
        if n == 0 {
            // EOF before terminator. nginx hung up mid-request, or
            // someone's poking the socket with `nc`. Either way: bad.
            return None;
        }
        total += n;
        if total > MAX_REQUEST_BYTES {
            return None;
        }

        // Terminator. `read_line` includes the `\n`; nginx sends
        // `\r\n`, so a blank line is `"\r\n"`. Match `"\r\n"` OR
        // `"\n"` so `printf | nc` testing works without `-C`.
        if line == "\r\n" || line == "\n" {
            return Some(Request { remote_addr });
        }

        // Header parse. RFC 7230 §3.2: name is case-insensitive,
        // colon, optional whitespace, value. We only want one
        // header so we don't bother building a map.
        //
        // `Remote-Port`: Tailscale's nginx-auth requires it
        // (`nginx-auth.go:37-42` returns 400 if either header is
        // unset), then immediately joins host:port and... never
        // looks at the port again. `WhoIs` is keyed by IP only
        // (the addrport parse is just validation). tinc subnet
        // lookup is also IP-only — there's no per-port routing.
        // We don't read it. nginx configs that set it work fine;
        // configs that don't, also fine.
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("remote-addr")
        {
            remote_addr = Some(value.trim().to_owned());
        }
    }
}

/// One match from the subnet dump. We track prefix length so we can
/// pick the longest — `tinc info` returns *all* matches and prints
/// them; for auth we want the routing decision (most specific wins,
/// same as `subnet_tree::lookup_ipv4`).
struct Match {
    owner: String,
    subnet: String,
    /// `0..=32` (v4) or `0..=128` (v6). Higher = more specific.
    /// We compare across families (v6 prefixes are bigger numbers
    /// than v4's), but a v4 query never matches a v6 subnet
    /// (`Subnet::matches` checks type), so it's moot.
    prefix: u8,
}

/// Dump subnets, longest-prefix match, return the owner. Same as
/// `tinc info <addr>` minus the all-matches collection.
///
/// `(broadcast)` subnets are filtered: they have no owner node and
/// would 204 with `Tinc-Node: (broadcast)`, which is worse than
/// useless for auth.
fn lookup(paths: &Paths, addr: IpAddr) -> Result<Option<Match>, CtlError> {
    // Build the query Subnet from a parsed IpAddr instead of
    // re-parsing a string. `Subnet::from_str` would work too
    // (a bare address parses as /32 or /128 with default weight),
    // but we already have the typed value. `weight` is irrelevant —
    // `matches()` ignores it.
    let find = match addr {
        IpAddr::V4(a) => Subnet::V4 {
            addr: a,
            prefix: 32,
            weight: DEFAULT_WEIGHT,
        },
        IpAddr::V6(a) => Subnet::V6 {
            addr: a,
            prefix: 128,
            weight: DEFAULT_WEIGHT,
        },
    };

    let mut ctl = CtlSocket::connect(paths)?;
    ctl.send(CtlRequest::DumpSubnets)?;

    let mut best: Option<Match> = None;
    loop {
        match ctl.recv_row()? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, body) => {
                // `SubnetRow::parse` is two `Tok::s()` calls.
                // Malformed row → skip. The daemon doesn't emit
                // garbage, but this is the auth path: failing
                // closed (no match → 401) beats failing open
                // (panic → 500 → nginx might fall through
                // depending on `auth_request` config).
                let Ok(row) = SubnetRow::parse(&body) else {
                    continue;
                };
                let Ok(subnet) = row.subnet.parse::<Subnet>() else {
                    continue;
                };

                // `as_address: true` — route lookup, "is `find`
                // INSIDE `self`". The mode where `tinc info
                // 10.0.0.5` asks "which net routes this".
                if !subnet.matches(&find, true) {
                    continue;
                }

                // `tinc info` doesn't filter `(broadcast)` because
                // it's informational. We do: a 204 with no real
                // node is a footgun.
                if row.owner == "(broadcast)" {
                    continue;
                }

                // Longest prefix wins. `Subnet::Mac` has no prefix
                // field, but `matches(find, true)` already returned
                // false for type mismatch (we built a V4 or V6
                // `find`), so it never reaches here.
                let prefix = match subnet {
                    Subnet::V4 { prefix, .. } | Subnet::V6 { prefix, .. } => prefix,
                    Subnet::Mac { .. } => continue,
                };

                if best.as_ref().is_none_or(|b| prefix > b.prefix) {
                    best = Some(Match {
                        owner: row.owner,
                        subnet: strip_weight(&row.subnet).to_owned(),
                        prefix,
                    });
                }
            }
        }
    }

    Ok(best)
}

/// Write a complete HTTP response. `Connection: close` always:
/// nginx auth_request subrequests are one-shot, and not having to
/// implement keepalive is the *point* of hand-rolling.
fn respond(mut stream: &UnixStream, status: &str, extra_headers: &[(&str, &str)]) {
    // `write!` to the socket. Errors (EPIPE if nginx already gave
    // up on us) are dropped: the response is best-effort, there's
    // no caller to propagate to, and we close the connection
    // immediately after. Same posture as Tailscale's `http.Serve`
    // — net/http logs and moves on.
    let _ = write!(stream, "HTTP/1.1 {status}\r\n");
    let _ = write!(stream, "Connection: close\r\n");
    let _ = write!(stream, "Content-Length: 0\r\n");
    for (k, v) in extra_headers {
        let _ = write!(stream, "{k}: {v}\r\n");
    }
    let _ = write!(stream, "\r\n");
}

fn handle(stream: &UnixStream, paths: &Paths, netname: &str) {
    let Some(req) = read_request(stream) else {
        respond(stream, "400 Bad Request", &[]);
        return;
    };

    let Some(addr_s) = req.remote_addr else {
        // nginx config bug — they didn't `proxy_set_header
        // Remote-Addr $remote_addr`. Tailscale 400s with a log
        // line ("set Remote-Addr to ..."); we 400 silently.
        // `journalctl -u tinc-auth` will show the access pattern.
        respond(stream, "400 Bad Request", &[]);
        return;
    };

    let Ok(addr) = addr_s.parse::<IpAddr>() else {
        // The header was *set* but isn't an IP. nginx's
        // `$remote_addr` is always a valid IP for INET listeners,
        // so this is either someone poking the socket directly,
        // or nginx accepted on a unix socket (then `$remote_addr`
        // is "unix:"). 401 not 400: from nginx's view this is
        // "unknown client", not "malformed config".
        respond(stream, "401 Unauthorized", &[]);
        return;
    };

    match lookup(paths, addr) {
        Ok(Some(m)) => {
            // 204: same as Tailscale. nginx auth_request treats
            // 2xx as "allow", 401/403 as "deny", anything else
            // as 500. 204 over 200 because there's no body.
            respond(
                stream,
                "204 No Content",
                &[
                    ("Tinc-Node", &m.owner),
                    ("Tinc-Net", netname),
                    ("Tinc-Subnet", &m.subnet),
                ],
            );
        }
        Ok(None) => {
            // No subnet contains this IP. Either off-mesh entirely,
            // or a node we haven't gossiped with yet. Either way:
            // not authenticated.
            respond(stream, "401 Unauthorized", &[]);
        }
        Err(_) => {
            // Daemon dead, pidfile unreadable, socket gone. 503
            // not 401: this is "auth backend unavailable", not
            // "you're not authorized". nginx maps both to 500 by
            // default but `auth_request` configs can distinguish
            // (`error_page 500 = @fallback`).
            respond(stream, "503 Service Unavailable", &[]);
        }
    }
}

/// `LISTEN_PID`/`LISTEN_FDS` parse. Same logic as
/// `tincd::main::check_socket_activation` (which is `pub(crate)` —
/// we copy 8 lines instead of plumbing a `pub` through tincd's
/// crate API for a binary in a different crate).
///
/// Returns `Some(n)` only when systemd actually passed us sockets:
/// `LISTEN_PID` matches our PID (proving the env wasn't inherited
/// from a wrapper) AND `LISTEN_FDS` is a positive count.
fn check_socket_activation() -> Option<usize> {
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        == Some(std::process::id());
    if !pid_ok {
        return None;
    }
    std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
}

struct Args {
    input: PathsInput,
    /// `--sockpath PATH`. Tailscale's `-sockpath`. Mutually
    /// exclusive with socket activation in practice (if both are
    /// available we prefer the activated socket — systemd already
    /// owns it).
    sockpath: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut input = PathsInput::default();
    let mut sockpath = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Mirrors `tinc.rs`'s flag handling — same `-n` / `-c`
            // / `--pidfile` semantics so muscle memory transfers.
            "-c" | "--config" => {
                let v = args.next().ok_or("option -c requires an argument")?;
                input.confbase = Some(PathBuf::from(v));
            }
            "-n" | "--net" => {
                let v = args.next().ok_or("option -n requires an argument")?;
                input.netname = Some(v);
            }
            "--pidfile" => {
                let v = args.next().ok_or("option --pidfile requires an argument")?;
                input.pidfile = Some(PathBuf::from(v));
            }
            "--sockpath" => {
                let v = args.next().ok_or("option --sockpath requires a path")?;
                sockpath = Some(PathBuf::from(v));
            }
            "-h" | "--help" => {
                println!(
                    "Usage: tinc-auth [-n NETNAME] [-c DIR] [--pidfile FILE] [--sockpath SOCK]\n\
                     \n\
                     nginx auth_request backend. Listens on a unix socket (via\n\
                     systemd socket activation, or --sockpath). Replies 204 with\n\
                     Tinc-Node/Tinc-Net/Tinc-Subnet headers when Remote-Addr is\n\
                     routed by a known tinc subnet, 401 otherwise.\n\
                     \n\
                     This authenticates the tinc NODE, not a human user. If `alice`\n\
                     is your laptop, this is what you want. If `alice` is a server\n\
                     with twelve SSH users, all twelve appear as `alice`."
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Args { input, sockpath })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tinc-auth: {e}");
            return ExitCode::FAILURE;
        }
    };

    // `Tinc-Net` is the netname verbatim. `Paths` doesn't store it
    // (only `PathsInput` does — it's consumed during construction),
    // so keep a copy. No netname → empty header. Tailscale does the
    // same when tailnet can't be derived (sharee nodes, see
    // `nginx-auth.go:66`).
    let netname = args.input.netname.clone().unwrap_or_default();

    let mut paths = Paths::for_cli(&args.input);
    paths.resolve_runtime(&args.input);

    // ─── listener: socket activation OR --sockpath
    let listener = if let Some(n) = check_socket_activation() {
        if n != 1 {
            // Tailscale's nginx-auth spawns one goroutine per
            // listener (`nginx-auth.go:114-119`). We could iterate
            // 3..3+n the same way. We don't: the unit file ships
            // one ListenStream, anything else is misconfiguration.
            // Failing loud beats silently ignoring extras.
            eprintln!("tinc-auth: expected exactly 1 socket from systemd, got {n}");
            return ExitCode::FAILURE;
        }
        // SAFETY: socket activation contract. systemd owns fd 3;
        // `LISTEN_PID` matched our pid (proving we were exec'd
        // directly by systemd, not inheriting a stale env from a
        // parent); we claim it once. `forbid(unsafe_code)` is
        // crate-level — this is the one place we'd want it. We
        // can't `#[allow]` past a `forbid`, so the crate gate is
        // `forbid` and this stays a comment. The cast: from_raw_fd
        // takes RawFd which is i32 on every unix; the constant is
        // already i32.
        //
        // Actually: `forbid` at the top makes this a compile error.
        // `from_raw_fd` is the *only* way to claim an inherited fd
        // (std has no safe wrapper because the safety contract is
        // "you uniquely own this fd" which the type system can't
        // express). Tradeoff: relax to `deny` and `#[allow]` here.
        // See lib.rs's identical reasoning for `localtime_r`.
        #[allow(unsafe_code)]
        // SAFETY: see above.
        unsafe {
            UnixListener::from_raw_fd(SD_LISTEN_FDS_START)
        }
    } else if let Some(path) = &args.sockpath {
        // `unlink` first — same as Tailscale's `os.Remove`
        // (`nginx-auth.go:96`). A previous instance might have
        // died without cleanup. Ignore the error: ENOENT is fine,
        // EACCES will surface as a `bind` failure next.
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("tinc-auth: bind {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!("tinc-auth: no listener (use --sockpath or systemd socket activation)");
        return ExitCode::FAILURE;
    };

    eprintln!("tinc-auth: listening (net={netname})");

    // ─── accept loop
    // Single-threaded, sequential. nginx auth_request subrequests
    // are tiny and the work per request is one ctl-socket roundtrip
    // (~1 ms). Threadpool when it profiles hot.
    //
    // No graceful shutdown handling: SIGTERM kills the process,
    // systemd restarts it on the next subrequest (socket activation
    // means systemd holds the socket open across restarts; nginx
    // never sees ECONNREFUSED). Tailscale's "let it crash, it will
    // come back" comment (`nginx-auth.go:108-112`) — same posture.
    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle(&s, &paths, &netname),
            Err(e) => eprintln!("tinc-auth: accept: {e}"),
        }
    }

    ExitCode::SUCCESS
}
