//! `tinc-auth` is an nginx `auth_request` backend, same shape as
//! Tailscale's `cmd/nginx-auth`. tinc has no humans, only nodes, so
//! the headers name the node, not a user:
//!
//! | Header        | Value       | Meaning                   |
//! |---------------|-------------|---------------------------|
//! | `Tinc-Node`   | `alice`     | which node owns src IP    |
//! | `Tinc-User`   | `alice`     | account per `--map`, else the node name |
//! | `Remote-User` | `alice`     | same as `Tinc-User`, for generic consumers |
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

use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tinc_proto::Subnet;
use tinc_proto::subnet::DEFAULT_WEIGHT;
use tinc_tools::ctl::rows::{SubnetRow, strip_weight};
use tinc_tools::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use tinc_tools::idp::{self, Idp};
use tinc_tools::names::{Paths, PathsInput};
use tiny_http::{Header, Method, Response, Server};

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

/// Node to account mapping from `--map`. Nodes without an entry map
/// to their own name.
type UserMap = HashMap<String, String>;

fn map_user<'a>(map: &'a UserMap, node: &'a str) -> &'a str {
    map.get(node).map_or(node, String::as_str)
}

fn handle(req: tiny_http::Request, paths: &Paths, netname: &str, map: &UserMap) {
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
            .with_header(header("Tinc-User", map_user(map, &m.owner)))
            .with_header(header("Remote-User", map_user(map, &m.owner)))
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
    /// The socket nginx connects to. Not tincd's control socket,
    /// which is derived from `--pidfile` like the `tinc` CLI does.
    listen_socket: Option<PathBuf>,
    idp_listen: Option<SocketAddr>,
    issuer: Option<String>,
    clients: Option<PathBuf>,
    groups: Option<PathBuf>,
    map: Option<PathBuf>,
    email_domain: Option<String>,
    id_token_ttl: Duration,
    access_token_ttl: Duration,
}

fn parse_ttl(s: &str) -> Result<Duration, String> {
    let (num, mult) = match s.as_bytes().last() {
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b's') => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .map(|n| Duration::from_secs(n * mult))
        .map_err(|_| format!("invalid duration: {s}"))
}

fn parse_args() -> Result<Args, String> {
    let mut input = PathsInput::default();
    let mut listen_socket = None;
    let mut idp_listen = None;
    let mut issuer = None;
    let mut clients = None;
    let mut groups = None;
    let mut map = None;
    let mut email_domain = None;
    let mut id_token_ttl = idp::DEFAULT_ID_TOKEN_TTL;
    let mut access_token_ttl = idp::DEFAULT_ACCESS_TOKEN_TTL;
    let mut args = std::env::args().skip(1);

    let next_val = |args: &mut dyn Iterator<Item = String>, flag: &str, glued: Option<&str>| {
        glued.map_or_else(
            || {
                args.next()
                    .ok_or(format!("option {flag} requires an argument"))
            },
            |v| Ok(v.to_owned()),
        )
    };

    while let Some(arg) = args.next() {
        let (flag, glued) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        match flag.as_str() {
            "--idp-listen" => {
                let v = next_val(&mut args, "--idp-listen", glued.as_deref())?;
                idp_listen = Some(v.parse().map_err(|_| format!("invalid address: {v}"))?);
                continue;
            }
            "--issuer" => {
                issuer = Some(next_val(&mut args, "--issuer", glued.as_deref())?);
                continue;
            }
            "--clients" => {
                clients = Some(PathBuf::from(next_val(
                    &mut args,
                    "--clients",
                    glued.as_deref(),
                )?));
                continue;
            }
            "--groups" => {
                groups = Some(PathBuf::from(next_val(
                    &mut args,
                    "--groups",
                    glued.as_deref(),
                )?));
                continue;
            }
            "--map" => {
                map = Some(PathBuf::from(next_val(
                    &mut args,
                    "--map",
                    glued.as_deref(),
                )?));
                continue;
            }
            "--email-domain" => {
                email_domain = Some(next_val(&mut args, "--email-domain", glued.as_deref())?);
                continue;
            }
            "--id-token-ttl" => {
                id_token_ttl =
                    parse_ttl(&next_val(&mut args, "--id-token-ttl", glued.as_deref())?)?;
                continue;
            }
            "--access-token-ttl" => {
                access_token_ttl = parse_ttl(&next_val(
                    &mut args,
                    "--access-token-ttl",
                    glued.as_deref(),
                )?)?;
                continue;
            }
            _ => {}
        }
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
                     \x20               [--idp-listen ADDR --issuer URL --clients FILE]\n\
                     \x20               [--groups FILE] [--map FILE] [--email-domain DOMAIN]\n\
                     \x20               [--id-token-ttl 5m] [--access-token-ttl 1h]\n\
                     \n\
                     nginx auth_request backend. Listens on a unix socket (via\n\
                     systemd socket activation, or --listen-socket). Replies 204 with\n\
                     Tinc-Node/Tinc-Net/Tinc-Subnet headers when Remote-Addr is\n\
                     routed by a known tinc subnet, 401 otherwise.\n\
                     \n\
                     --listen-socket is the socket nginx connects to. tincd's control\n\
                     socket is located via --pidfile (or -n/-c), same as `tinc`.\n\
                     \n\
                     With --idp-listen the binary also serves an OIDC provider on a\n\
                     mesh address. The bind address must belong to this node. See\n\
                     docs/AUTH.md.\n\
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
        idp_listen,
        issuer,
        clients,
        groups,
        map,
        email_domain,
        id_token_ttl,
        access_token_ttl,
    })
}

fn load_map(path: Option<&PathBuf>) -> Result<UserMap, String> {
    match path {
        None => Ok(UserMap::new()),
        Some(p) => std::fs::read(p)
            .map_err(|e| format!("{}: {e}", p.display()))
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", p.display()))),
    }
}

fn whois(paths: &Paths, addr: IpAddr, map: &UserMap) -> idp::Whois {
    match lookup(paths, addr) {
        Ok(Some(m)) => Ok(Some(idp::Node {
            user: map_user(map, &m.owner).to_owned(),
            name: m.owner,
            subnet: m.subnet,
        })),
        Ok(None) => Ok(None),
        Err(_) => Err(()),
    }
}

fn build_idp(args: &Args, paths: &Paths, netname: &str) -> Result<Idp, String> {
    let issuer = args
        .issuer
        .clone()
        .ok_or("--idp-listen requires --issuer")?;
    let clients_path = args
        .clients
        .as_ref()
        .ok_or("--idp-listen requires --clients")?;
    let clients = std::fs::read(clients_path)
        .map_err(|e| format!("{}: {e}", clients_path.display()))
        .and_then(|b| {
            serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", clients_path.display()))
        })?;
    let groups: HashMap<String, Vec<String>> = match &args.groups {
        None => HashMap::new(),
        Some(p) => std::fs::read(p)
            .map_err(|e| format!("{}: {e}", p.display()))
            .and_then(|b| {
                serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", p.display()))
            })?,
    };
    let key = idp::load_or_create_key(&paths.confbase.join("idp/oidc-key.pem"))?;
    Ok(Idp::new(
        idp::Config {
            issuer,
            netname: netname.to_owned(),
            clients,
            groups,
            email_domain: args.email_domain.clone(),
            id_token_ttl: args.id_token_ttl,
            access_token_ttl: args.access_token_ttl,
        },
        key,
    ))
}

fn handle_idp(req: tiny_http::Request, idp: &Idp, paths: &Paths, map: &UserMap) {
    let now = idp::now_unix();
    let url = req.url().to_owned();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let auth_header = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().to_owned());

    let resp = match (req.method(), path) {
        (Method::Get, "/.well-known/openid-configuration") => idp.discovery(),
        (Method::Get, "/.well-known/jwks.json") => idp.jwks(),
        (Method::Get | Method::Post, "/authorize") => {
            let peer = req.remote_addr().map(SocketAddr::ip);
            let who = peer.map_or(Err(()), |ip| whois(paths, ip, map));
            let query = query.to_owned();
            idp.authorize(&query, who, now)
        }
        (Method::Post, "/token") => {
            let mut req = req;
            let mut body = String::new();
            let _ = req.as_reader().take(64 * 1024).read_to_string(&mut body);
            let resp = idp.token(&body, auth_header.as_deref(), now);
            respond_idp(req, resp);
            return;
        }
        (Method::Get, "/userinfo") => idp.userinfo(auth_header.as_deref(), now),
        _ => idp::HttpResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        },
    };
    idp.sweep(now);
    respond_idp(req, resp);
}

fn respond_idp(req: tiny_http::Request, resp: idp::HttpResponse) {
    let mut r = Response::from_data(resp.body).with_status_code(resp.status);
    for (k, v) in &resp.headers {
        r.add_header(header(k, v));
    }
    let _ = req.respond(r);
}

fn check_idp_bind(paths: &Paths, addr: SocketAddr) -> Result<(), String> {
    let name = tinc_tools::cmd::exchange::get_my_name(paths)
        .map_err(|e| format!("reading Name from tinc.conf: {e}"))?;
    match lookup(paths, addr.ip()) {
        Ok(Some(m)) if m.owner == name => Ok(()),
        Ok(Some(m)) => Err(format!(
            "{} belongs to node {}, not to this node ({name})",
            addr.ip(),
            m.owner
        )),
        Ok(None) => Err(format!("{} is not inside a mesh subnet", addr.ip())),
        Err(e) => Err(format!("cannot verify {} against tincd: {e}", addr.ip())),
    }
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
        Some(UnixListener::from(owned))
    } else if let Some(path) = &args.listen_socket {
        // A previous instance might have died without cleanup.
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("tinc-auth: bind {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    } else if args.idp_listen.is_some() {
        None
    } else {
        eprintln!("tinc-auth: no listener (use --listen-socket or systemd socket activation)");
        return ExitCode::FAILURE;
    };

    let map = match load_map(args.map.as_ref()) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("tinc-auth: {e}");
            return ExitCode::FAILURE;
        }
    };

    let idp_thread = match &args.idp_listen {
        None => None,
        Some(addr) => {
            let idp = match build_idp(&args, &paths, &netname) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("tinc-auth: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = check_idp_bind(&paths, *addr) {
                eprintln!("tinc-auth: refusing to serve the IdP: {e}");
                return ExitCode::FAILURE;
            }
            let server = match Server::http(addr) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("tinc-auth: bind {addr}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Some(bound) = server.server_addr().to_ip() {
                eprintln!("tinc-auth: IdP listening on {bound}");
            }
            let paths = paths.clone();
            let idp = Arc::new(idp);
            let map = Arc::clone(&map);
            Some(std::thread::spawn(move || {
                for req in server.incoming_requests() {
                    handle_idp(req, &idp, &paths, &map);
                }
            }))
        }
    };

    let server = match listener {
        Some(l) => match Server::from_listener(l, None) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("tinc-auth: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    eprintln!("tinc-auth: listening (net={netname})");

    // Sequential: the work per request is one ctl roundtrip (~1 ms).
    // No graceful shutdown. systemd holds the activated socket open
    // across restarts.
    if let Some(server) = server {
        for req in server.incoming_requests() {
            handle(req, &paths, &netname, &map);
        }
    } else if let Some(t) = idp_thread {
        let _ = t.join();
    }

    ExitCode::SUCCESS
}
