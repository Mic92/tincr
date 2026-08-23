//! `tinc-auth` is an nginx `auth_request` backend, same shape as
//! Tailscale's `cmd/nginx-auth`. tinc has no humans, only nodes, so
//! the headers name the node, not a user:
//!
//! | Header        | Value       | Meaning                   |
//! |---------------|-------------|---------------------------|
//! | `Tinc-Node`   | `alice`     | which node owns src IP    |
//! | `Tinc-Net`    | `mesh`      | netname (`-n`)            |
//! | `Tinc-Subnet` | `10.20.0.2` | the matching subnet entry |
//!
//! nginx sets `Remote-Addr: $remote_addr` on a subrequest over a
//! unix socket. We longest-prefix match it against a fresh
//! `REQ_DUMP_SUBNETS` dump, same algorithm as `tinc info <addr>`.
//! Hit → 204 + headers, miss → 401, dead daemon → 503 (fail
//! closed). One control connection per request. The `auth_request`
//! rate is "page loads", not per-asset.

// `deny` not `forbid`: `from_raw_fd` for socket activation is the
// one unsafe call.
#![deny(unsafe_code)]

use std::net::IpAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_proto::Subnet;
use tinc_proto::subnet::DEFAULT_WEIGHT;
use tinc_tools::ctl::rows::{SubnetRow, strip_weight};
use tinc_tools::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use tinc_tools::names::{Paths, PathsInput};
use tiny_http::{Header, Response, Server};

const SD_LISTEN_FDS_START: RawFd = 3;

struct Match {
    owner: String,
    subnet: String,
    prefix: u8,
}

/// Dump subnets, longest-prefix match, return the owner. Filters
/// `(broadcast)`: it has no owner node and must not authenticate.
fn lookup(paths: &Paths, addr: IpAddr) -> Result<Option<Match>, CtlError> {
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
                // Malformed rows are skipped, not fatal: on the auth
                // path failing closed (401) beats a 500.
                let Ok(row) = SubnetRow::parse(&body) else {
                    continue;
                };
                let Ok(subnet) = row.subnet.parse::<Subnet>() else {
                    continue;
                };
                if !subnet.matches(&find, true) {
                    continue;
                }
                if row.owner == "(broadcast)" {
                    continue;
                }
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

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header name")
}

fn handle(req: tiny_http::Request, paths: &Paths, netname: &str) {
    let remote_addr = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Remote-Addr"))
        .map(|h| h.value.as_str().trim().to_owned());

    let Some(addr_s) = remote_addr else {
        // nginx config bug: missing `proxy_set_header Remote-Addr`.
        let _ = req.respond(Response::empty(400));
        return;
    };

    let Ok(addr) = addr_s.parse::<IpAddr>() else {
        // Header set but not an IP (e.g. nginx on a unix listener
        // sends "unix:"): unknown client, not malformed config.
        let _ = req.respond(Response::empty(401));
        return;
    };

    let resp = match lookup(paths, addr) {
        Ok(Some(m)) => Response::empty(204)
            .with_header(header("Tinc-Node", &m.owner))
            .with_header(header("Tinc-Net", netname))
            .with_header(header("Tinc-Subnet", &m.subnet)),
        Ok(None) => Response::empty(401),
        Err(_) => Response::empty(503),
    };
    let _ = req.respond(resp);
}

/// `LISTEN_PID`/`LISTEN_FDS`, same logic as tincd's
/// `check_socket_activation`.
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
    /// The socket nginx connects to. NOT tincd's control socket,
    /// which is derived from `--pidfile` like the `tinc` CLI does.
    listen_socket: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut input = PathsInput::default();
    let mut listen_socket = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let v = args.next().ok_or("option -c requires an argument")?;
                input.confbase = Some(PathBuf::from(v));
            }
            s if s.starts_with("--config=") => {
                input.confbase = Some(PathBuf::from(&s["--config=".len()..]));
            }
            "-n" | "--net" => {
                let v = args.next().ok_or("option -n requires an argument")?;
                input.netname = Some(v);
            }
            s if s.starts_with("--net=") => {
                input.netname = Some(s["--net=".len()..].to_owned());
            }
            "--pidfile" => {
                let v = args.next().ok_or("option --pidfile requires an argument")?;
                input.pidfile = Some(PathBuf::from(v));
            }
            s if s.starts_with("--pidfile=") => {
                input.pidfile = Some(PathBuf::from(&s["--pidfile=".len()..]));
            }
            // `--sockpath` kept as an alias for existing unit files.
            "--listen-socket" | "--sockpath" => {
                let v = args
                    .next()
                    .ok_or("option --listen-socket requires a path")?;
                listen_socket = Some(PathBuf::from(v));
            }
            s if s.starts_with("--listen-socket=") => {
                listen_socket = Some(PathBuf::from(&s["--listen-socket=".len()..]));
            }
            s if s.starts_with("--sockpath=") => {
                listen_socket = Some(PathBuf::from(&s["--sockpath=".len()..]));
            }
            "-h" | "--help" => {
                println!(
                    "Usage: tinc-auth [-n NETNAME] [-c DIR] [--pidfile FILE] [--listen-socket SOCK]\n\
                     \n\
                     nginx auth_request backend. Listens on a unix socket (via\n\
                     systemd socket activation, or --listen-socket). Replies 204 with\n\
                     Tinc-Node/Tinc-Net/Tinc-Subnet headers when Remote-Addr is\n\
                     routed by a known tinc subnet, 401 otherwise.\n\
                     \n\
                     --listen-socket is the socket nginx connects to. tincd's control\n\
                     socket is located via --pidfile (or -n/-c), same as `tinc`.\n\
                     \n\
                     This authenticates the tinc NODE, not a human user. If `alice`\n\
                     is your laptop, this is what you want. If `alice` is a server\n\
                     with twelve SSH users, all twelve appear as `alice`."
                );
                std::process::exit(0);
            }
            "--version" => {
                println!("tinc-auth {} (Rust)", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Args {
        input,
        listen_socket,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tinc-auth: {e}");
            return ExitCode::FAILURE;
        }
    };

    let netname = args.input.netname.clone().unwrap_or_default();

    let mut paths = Paths::for_cli(&args.input);
    paths.resolve_runtime(&args.input);

    let listener = if let Some(n) = check_socket_activation() {
        if n != 1 {
            eprintln!("tinc-auth: expected exactly 1 socket from systemd, got {n}");
            return ExitCode::FAILURE;
        }
        // SAFETY: socket activation contract. `LISTEN_PID` matched
        // our pid, so we were exec'd by systemd and fd 3 is ours
        // alone. We claim it exactly once.
        #[allow(unsafe_code)]
        let owned = unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) };
        UnixListener::from(owned)
    } else if let Some(path) = &args.listen_socket {
        // A previous instance might have died without cleanup.
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("tinc-auth: bind {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!("tinc-auth: no listener (use --listen-socket or systemd socket activation)");
        return ExitCode::FAILURE;
    };

    let server = match Server::from_listener(listener, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tinc-auth: {e}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("tinc-auth: listening (net={netname})");

    // Sequential: the work per request is one ctl roundtrip (~1 ms).
    // No graceful shutdown. systemd holds the activated socket open
    // across restarts.
    for req in server.incoming_requests() {
        handle(req, &paths, &netname);
    }

    ExitCode::SUCCESS
}
