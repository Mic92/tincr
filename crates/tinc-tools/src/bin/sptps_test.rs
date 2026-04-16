//! `sptps_test [-d] [-q] [-r] [-w] [-v] [-4|-6] MYKEY HISKEY [HOST] PORT`
//!
//! SPTPS over a real socket, stdin → wire → stdout. Minus the
//! dev-only knobs (`--tun`, `--packet-loss`, `--special`, Windows
//! stdin-thread).
//!
//! ## Why this exists
//!
//! `tinc-sptps/tests/vs_c.rs` proves byte-identity in-process with a
//! seeded RNG. This proves it on a real socket with `OsRng`: TCP can
//! split records mid-frame, UDP can deliver out of order, the kernel
//! gets involved. Nothing here is *new* code — it's a `poll()` loop
//! glued to `Sptps` — but it's the first time the Rust SPTPS touches
//! a file descriptor.
//!
//! `test/integration/sptps_basic.py` drives this binary. With one side
//! C and one side Rust, it's a cross-impl test on a live socket.
//!
//! ## Argument shape (load-bearing for `sptps_basic.py`)
//!
//! - 3 positional args (`mykey hiskey port`) → **listener/responder**
//! - 4 positional args (`mykey hiskey host port`) → **connector/initiator**
//!
//! The role is implied by argc, not a flag.
//!
//! ## Stderr line that's API
//!
//! `"Listening on {port}...\n"` — `sptps_basic.py` regexes this to
//! find the bound port (it passes port `0` to get an ephemeral one).
//! Don't reword.

#![forbid(unsafe_code)]
// All the `as` casts are `usize ↔ ssize_t` on `read()`/`write()`
// returns, and `i32` fd extractions. Monotone, never wrap in practice.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::PathBuf;
use std::process::ExitCode;

use rand_core::OsRng;

use tinc_sptps::{Framing, Output, Role, Sptps};
use tinc_tools::keypair;

// Args. Hand-rolled — `clap` would be ~10× the dependency footprint
// for what is six bool flags and four positionals. We implement the
// short-flag subset that `sptps_basic.py` actually uses.

// CLI flags are inherently boolean. The lint's advice ("consider a
// state machine") doesn't apply — these are five independent toggles,
// not encoding of one state.
#[allow(clippy::struct_excessive_bools)] // CLI flags: each bool maps to a -d/-q/-r/-w/-v switch
struct Args {
    datagram: bool,
    quit_on_eof: bool,
    readonly: bool,
    writeonly: bool,
    verbose: bool,
    family: AddrFamily,
    my_key: PathBuf,
    his_key: PathBuf,
    /// Some → connect to here, initiator. None → listen, responder.
    connect_to: Option<String>,
    port: String,
}

#[derive(Clone, Copy)]
enum AddrFamily {
    Any,
    V4,
    V6,
}

fn usage(prog: &str) {
    eprintln!(
        "Usage: {prog} [options] my_ed25519_key_file his_ed25519_key_file [host] port\n\
         \n\
         Options:\n  \
         -d  Enable datagram mode.\n  \
         -q  Quit when EOF occurs on stdin.\n  \
         -r  Only send data from the socket to stdout.\n  \
         -w  Only send data from stdin to the socket.\n  \
         -v  Display debug messages.\n  \
         -4  Use IPv4.\n  \
         -6  Use IPv6."
    );
}

fn parse_args() -> Result<Args, String> {
    let mut argv: Vec<String> = std::env::args().collect();
    let prog = argv.remove(0);

    let mut datagram = false;
    let mut quit_on_eof = false;
    let mut readonly = false;
    let mut writeonly = false;
    let mut verbose = false;
    let mut family = AddrFamily::Any;
    let mut pos = Vec::new();

    for a in argv {
        // Single-char flags only. The integration test uses short
        // forms (`-4`, `-q`, `-dq`); bundled short flags need per-char
        // handling.
        if let Some(chars) = a.strip_prefix('-') {
            if chars == "-help" || chars == "h" {
                usage(&prog);
                std::process::exit(0);
            }
            for c in chars.chars() {
                match c {
                    'd' => datagram = true,
                    'q' => quit_on_eof = true,
                    'r' => readonly = true,
                    'w' => writeonly = true,
                    'v' => verbose = true,
                    '4' => family = AddrFamily::V4,
                    '6' => family = AddrFamily::V6,
                    _ => return Err(format!("unknown option -{c}")),
                }
            }
        } else {
            pos.push(a);
        }
    }

    let (my_key, his_key, connect_to, port) = match pos.len() {
        3 => (pos.remove(0), pos.remove(0), None, pos.remove(0)),
        4 => (
            pos.remove(0),
            pos.remove(0),
            Some(pos.remove(0)),
            pos.remove(0),
        ),
        _ => {
            usage(&prog);
            return Err("wrong number of arguments".into());
        }
    };

    Ok(Args {
        datagram,
        quit_on_eof,
        readonly,
        writeonly,
        verbose,
        family,
        my_key: my_key.into(),
        his_key: his_key.into(),
        connect_to,
        port,
    })
}

/// Unifies TCP and UDP sockets for the I/O loop — the loop body
/// wants one `recv`/`send` pair.
enum Sock {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Sock {
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(s) => s.as_fd(),
            Self::Udp(s) => s.as_fd(),
        }
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Udp(s) => s.recv(buf),
        }
    }
    fn send_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(buf),
            // UDP: `send()` on a connected socket. One datagram. A
            // partial UDP send means EMSGSIZE — the datagram didn't
            // go. Surface it, don't retry.
            Self::Udp(s) => {
                let n = s.send(buf)?;
                if n != buf.len() {
                    return Err(io::Error::other(format!(
                        "UDP short send: {n} of {}",
                        buf.len()
                    )));
                }
                Ok(())
            }
        }
    }
}

/// `getaddrinfo` + AF filter. std's `to_socket_addrs` doesn't take an
/// `ai_family` hint, so post-filter.
fn resolve(host: &str, port: &str, family: AddrFamily) -> io::Result<SocketAddr> {
    let addrs = (
        host,
        port.parse::<u16>()
            .map_err(|_| io::Error::other("bad port"))?,
    )
        .to_socket_addrs()?;
    for a in addrs {
        match (family, a) {
            (AddrFamily::Any, _)
            | (AddrFamily::V4, SocketAddr::V4(_))
            | (AddrFamily::V6, SocketAddr::V6(_)) => return Ok(a),
            _ => {}
        }
    }
    Err(io::Error::other("no matching address family"))
}

/// Listener bind address. `-4` is what `sptps_basic.py` passes, so
/// V4 is the tested path.
fn listen_addr(port: &str, family: AddrFamily) -> io::Result<SocketAddr> {
    let port: u16 = port.parse().map_err(|_| io::Error::other("bad port"))?;
    Ok(match family {
        // Any → V6 wildcard (dual-stack on Linux). Doesn't matter
        // for the integration test (it passes -4).
        AddrFamily::Any | AddrFamily::V6 => {
            SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port)
        }
        AddrFamily::V4 => SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port),
    })
}

fn setup_socket(args: &Args) -> io::Result<Sock> {
    if let Some(host) = &args.connect_to {
        // Initiator: connect.
        let addr = resolve(host, &args.port, args.family)?;
        if args.datagram {
            // No datagram sent yet — the first KEX packet from
            // `sptps_start` is what wakes the listener's `peek_from`.
            let s = UdpSocket::bind(match addr {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            })?;
            s.connect(addr)?;
            eprintln!("Connected");
            Ok(Sock::Udp(s))
        } else {
            let s = TcpStream::connect(addr)?;
            eprintln!("Connected");
            Ok(Sock::Tcp(s))
        }
    } else {
        // Responder: listen + accept.
        let addr = listen_addr(&args.port, args.family)?;
        if args.datagram {
            udp_accept(addr)
        } else {
            let listener = TcpListener::bind(addr)?;
            // *** API LINE *** — sptps_basic.py regex: r"Listening on (\d+)\.\.\."
            eprintln!("Listening on {}...", listener.local_addr()?.port());
            let (s, _) = listener.accept()?;
            eprintln!("Connected");
            Ok(Sock::Tcp(s))
        }
    }
}

/// UDP has no `accept()`; we fake one with `peek_from` (`MSG_PEEK`)
/// to learn the client address, then `connect()` to it. The peeked
/// datagram stays in the socket's buffer — the main loop's first
/// `recv()` reads it for real. `connect()` filters subsequent
/// `recv()`s to that peer.
fn udp_accept(addr: SocketAddr) -> io::Result<Sock> {
    let s = UdpSocket::bind(addr)?;
    // *** API LINE *** — same regex.
    eprintln!("Listening on {}...", s.local_addr()?.port());

    // We don't care about the bytes — `connect()` is the side effect
    // we want, and the datagram will be re-read in the main loop. But
    // `peek_from` needs *somewhere* to put them. A datagram larger
    // than 65536 is unroutable anyway.
    let mut buf = vec![0u8; 65536];
    let (_, peer) = s.peek_from(&mut buf)?;
    s.connect(peer)?;

    eprintln!("Connected");
    Ok(Sock::Udp(s))
}

// The poll loop is one function: two arms (sock readable, stdin
// readable) share six pieces of mutable state. The body is one
// `loop` with two `if`s.
fn run(args: &Args, mut sock: Sock, mut s: Sptps) -> io::Result<()> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    // Hold the `Stdin` handle for the loop's lifetime so `as_fd()`
    // borrows are valid. `io::stdin()` returns a fresh guard each call;
    // borrowing one and dropping it would dangle.
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    // Stdin polling is gated on `established && !readonly`. We watch
    // for `Output::HandshakeDone` to flip `established`.
    let mut established = false;
    let mut readonly = args.readonly;
    let writeonly = args.writeonly;

    let mut buf = vec![0u8; 65535];

    // Drain `Vec<Output>` into the world. Factored out because both
    // `start()` (the initial KEX) and the loop body produce them.
    let drain = |outputs: Vec<Output>,
                 sock: &mut Sock,
                 stdout: &mut io::StdoutLock<'_>,
                 established: &mut bool|
     -> io::Result<()> {
        for o in outputs {
            match o {
                Output::Wire { record_type, bytes } => {
                    if args.verbose {
                        eprintln!(
                            "Sending {} bytes of data (type {record_type}):\n{}",
                            bytes.len(),
                            hex(&bytes)
                        );
                    }
                    sock.send_all(&bytes)?;
                }
                Output::Record { record_type, bytes } => {
                    if args.verbose {
                        eprintln!(
                            "Received type {record_type} record of {} bytes",
                            bytes.len()
                        );
                    }
                    if !writeonly {
                        stdout.write_all(&bytes)?;
                        stdout.flush()?;
                    }
                }
                Output::HandshakeDone => {
                    if args.verbose {
                        eprintln!("Handshake complete");
                    }
                    *established = true;
                }
            }
        }
        Ok(())
    };

    loop {
        // Hit when stdin EOF (without -q) flips `readonly` true and
        // `-w` was already on. Degenerate; preserved.
        if writeonly && readonly {
            break;
        }

        // Build the pollset fresh each iteration. `poll()` mutates
        // `revents`; rebuilding is cleaner than clearing. Stack array
        // [PollFd; 2] would be nicer but the optional second slot makes
        // a `Vec` simpler than `MaybeUninit` gymnastics.
        //
        // The `BorrowedFd` from `sock.fd()` borrows `sock` immutably
        // — fine, we don't `recv()` until after `poll()` returns and
        // the PollFds are dropped. Re-borrow inside the `if sock_ready`
        // block.
        let stdin_polled = !readonly && established;
        let mut fds: Vec<PollFd> = Vec::with_capacity(2);
        fds.push(PollFd::new(sock.fd(), PollFlags::POLLIN));
        if stdin_polled {
            fds.push(PollFd::new(stdin.as_fd(), PollFlags::POLLIN));
        }

        let n = poll(&mut fds, PollTimeout::NONE).map_err(io::Error::from)?;
        if n <= 0 {
            // EINTR (no timeout set). Benign; loop.
            continue;
        }

        // ─── Socket readable
        let sock_ready = fds[0].revents().is_some_and(|r| {
            r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        });
        let stdin_ready = stdin_polled
            && fds[1]
                .revents()
                .is_some_and(|r| r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP));
        // Drop fds now — it holds a `BorrowedFd` borrowing `sock`, and
        // the recv branch wants `&mut sock`.
        drop(fds);

        if sock_ready {
            let n = sock.recv(&mut buf)?;
            if n == 0 {
                eprintln!("Connection terminated by peer.");
                break;
            }
            if args.verbose {
                eprintln!("Received {n} bytes of data:\n{}", hex(&buf[..n]));
            }

            // One-record-per-call loop. Stream mode genuinely needs
            // this — a single TCP `recv()` can land multiple SPTPS
            // records (or a partial one, buffered inside `Sptps`).
            // Datagram mode consumes whole-or-nothing per call, so the
            // loop iterates once. Same code handles both.
            let mut off = 0;
            while off < n {
                match s.receive(&buf[off..n], &mut OsRng) {
                    Ok((0, _)) => {
                        // Ok(0) = partial record buffered, no progress
                        // this call. Datagram mode never returns 0 (it
                        // consumes all-or-Err). Stream mode: "I
                        // buffered a partial; feed me more" — but we
                        // already gave it everything we have. Next
                        // recv() resumes.
                        break;
                    }
                    Ok((consumed, outputs)) => {
                        drain(outputs, &mut sock, &mut stdout, &mut established)?;
                        off += consumed;
                    }
                    Err(e) => {
                        // Decrypt failure, MAC mismatch, bad record
                        // type, etc. Fatal for stream; drop and
                        // continue for datagram (next packet might be
                        // fine).
                        if args.datagram {
                            if args.verbose {
                                eprintln!("Dropping bad datagram: {e:?}");
                            }
                            break; // out of the inner while; main loop continues
                        }
                        return Err(io::Error::other(format!("sptps receive: {e:?}")));
                    }
                }
            }
        }

        // ─── Stdin readable
        if stdin_ready {
            // 1460 is an MTU-ish chunk size so each stdin read becomes
            // one reasonably-sized datagram. Stream mode reads big.
            let readsize = if args.datagram { 1460 } else { buf.len() };
            // Raw `read()` on fd 0 — `Stdin::lock().read()` goes
            // through a `BufReader` that'd buffer past what we asked
            // for, breaking the readsize=1460 datagram chunking. The
            // fd is alive: we own `stdin: Stdin` for the loop's
            // lifetime.
            let n = nix::unistd::read(&stdin, &mut buf[..readsize])
                .map_err(io::Error::from)?;

            if n == 0 {
                // EOF on stdin. With `-q` (which `sptps_basic.py`
                // passes for the client), exit cleanly. Without, stop
                // polling stdin but keep reading the socket — useful
                // for half-duplex tests.
                if args.quit_on_eof {
                    break;
                }
                readonly = true;
                continue;
            }

            // Type 0 always — we dropped the `--special` type-1 hack.
            // Upstream sends an *empty* record for a bare newline; we
            // don't bother, bare newline is one byte of data.
            match s.send_record(0, &buf[..n]) {
                Ok(outputs) => drain(outputs, &mut sock, &mut stdout, &mut established)?,
                Err(e) => {
                    // Only reachable error is `InvalidState` (called
                    // before handshake done) — but we gate stdin on
                    // `established`, so this is a logic bug if it
                    // fires. Surface it.
                    return Err(io::Error::other(format!("sptps send: {e:?}")));
                }
            }
        }
    }

    // `Sptps` zeroes secrets in `Drop` (cipher contexts are
    // `Zeroizing`). Nothing to do.
    Ok(())
}

/// Hex dump for verbose mode: lowercase, no separators.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap());
    }
    s
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    // Load keys before touching the network — fail fast on the common
    // mistakes (wrong path, swapped pub/priv).
    let mykey = match keypair::read_private(&args.my_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let hiskey = match keypair::read_public(&args.his_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let mut sock = match setup_socket(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Socket setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The label "sptps_test" (10 bytes, no NUL) feeds the PRF. Both
    // sides must agree — it's not a comment, it's key derivation
    // input. `replaywin` 16 is the default; we don't expose `-W`.
    let role = if args.connect_to.is_some() {
        Role::Initiator
    } else {
        Role::Responder
    };
    let framing = if args.datagram {
        Framing::Datagram
    } else {
        Framing::Stream
    };
    let (s, init_out) = Sptps::start(
        role,
        framing,
        mykey,
        hiskey,
        b"sptps_test".to_vec(),
        16,
        &mut OsRng,
    );

    // The initial KEX. Drain it now, before entering the loop. For
    // the *responder* this is also a KEX (both sides send KEX
    // unconditionally on start; the protocol is symmetric until SIG).
    for o in init_out {
        if let Output::Wire { record_type, bytes } = o {
            if args.verbose {
                eprintln!(
                    "Sending {} bytes of data (type {record_type}):\n{}",
                    bytes.len(),
                    hex(&bytes)
                );
            }
            if let Err(e) = sock.send_all(&bytes) {
                eprintln!("Error sending initial KEX: {e}");
                return ExitCode::FAILURE;
            }
        }
        // `start()` only ever emits `Wire`; the other variants are
        // post-handshake. Silently ignore if that ever changes — the
        // loop's `drain` handles them properly.
    }

    if let Err(e) = run(&args, sock, s) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
