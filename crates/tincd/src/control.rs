//! Control socket setup. Ports `pidfile.c::write_pidfile` (13 LOC) +
//! `control.c::init_control` unix-socket bits (`control.c:186-227`,
//! 42 LOC).
//!
//! ## What `init_control` does
//!
//! C `control.c:148-231`:
//!
//! 1. Generate 32-byte random cookie, hex-encode to 64 chars
//! 2. Get the address+port of `listen_socket[0]` for the pidfile's
//!    "what to connect to" field. Maps `0.0.0.0` → `127.0.0.1` and
//!    `::` → `::1` (you can't connect to a wildcard).
//! 3. `write_pidfile` — pid, cookie, address. Mode 0600 via umask.
//! 4. Unix socket: socket → connect-probe (refuse if something's
//!    already listening) → unlink stale → bind → listen.
//! 5. Register with event loop.
//!
//! Step 2 is skipped here — no `listen_socket`. We write a fixed
//! `"127.0.0.1 port 0"` placeholder. The CLI never connects to that
//! address (it uses the unix socket); the field is for `tinc dump
//! reachability` which prints it. Chunk 3 fixes it.
//!
//! Step 5 isn't here either — `bind()` returns the listener and the
//! caller registers it. Separation: this module knows about sockets,
//! not about the event loop.
//!
//! ## The umask dance
//!
//! Three places in C tinc use `umask(0); umask(mask | 077)` to
//! atomically create a mode-0600 file:
//!
//! - `pidfile.c:28` — the pidfile (this is the auth boundary; whoever
//!   can read the cookie can control the daemon)
//! - `control.c:213` — the unix socket (same reason)
//! - `keys.c` — private key files
//!
//! `OpenOptions::mode(0o600)` sets the mode at create, BUT it's still
//! ANDed with the inverse of umask. If umask is `022`, `mode(0o600)`
//! gives `0o600 & ~0o022 = 0o600` — fine. If umask is `0o077`, same.
//! But if umask is `0o000`, `mode(0o600)` gives `0o600` — also fine.
//! Wait, `0o600 & ~umask` for any `umask` ≤ `0o077` gives `0o600`.
//! And umasks > `0o077` (like `0o177`) are unusual but would give
//! `0o400` — owner can't write back.
//!
//! ACTUALLY: `mode()` sets the requested bits; umask removes bits.
//! `0o600 & ~0o022 = 0o600` (no overlap). The umask dance in C is
//! to ensure group/other bits are STRIPPED even if `fopen()` would
//! default to `0o666`. We're setting `0o600` explicitly, so as long
//! as umask doesn't ADD bits (it can't, it only removes), we're
//! safe. `OpenOptions::mode(0o600)` is sufficient. The C dance is
//! belt-and-braces.
//!
//! For the **unix socket**: `bind()` honors umask (the socket file's
//! perms are `0o777 & ~umask`). std `UnixListener::bind` doesn't
//! expose mode. So for the socket we DO need the umask dance. One
//! `umask` call, scoped.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;

use rand_core::{OsRng, RngCore};

/// 32 random bytes → 64 hex chars. C `controlcookie[65]` (the +1 is
/// the C string NUL). `control.c:149-150`: `randomize(32 bytes);
/// bin2hex(32 bytes)`.
pub const COOKIE_BYTES: usize = 32;
pub const COOKIE_HEX_LEN: usize = COOKIE_BYTES * 2;

/// `randomize` + `bin2hex`. The cookie is the auth secret; reading
/// it from the pidfile is how `tinc` proves it's allowed to control
/// the daemon. The pidfile is mode 0600 = filesystem-based auth,
/// same model as ssh-agent's socket.
///
/// `bin2hex` uses lowercase (`"0123456789abcdef"`, `utils.c:43`).
/// `format!("{:02x}")` matches.
///
/// # Panics
/// Only via `OsRng::fill_bytes`, only if `/dev/urandom` (or
/// `getrandom(2)`) is unavailable. At that point the daemon can't
/// generate session keys either; aborting is correct. Same as
/// `randomize` (`random.c:48` `abort()`).
#[must_use]
pub fn generate_cookie() -> String {
    let mut bytes = [0u8; COOKIE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(COOKIE_HEX_LEN);
    for b in bytes {
        use std::fmt::Write;
        write!(hex, "{b:02x}").expect("String write infallible");
    }
    hex
}

/// `write_pidfile` (`pidfile.c:26-38`). The format is:
///
/// ```text
/// <pid> <cookie> <host> port <port>\n
/// ```
///
/// `tinc-tools::Pidfile::read` parses this. The C `fscanf` format
/// is `"%20d %64s %128s port %128s"` — `port` is a literal in the
/// format string. We match: `host port portnum` is one space-joined
/// `address` arg in C (`fprintf(f, "%d %s %s\n", pid, cookie,
/// address)` where `address = "127.0.0.1 port 655"`).
///
/// Mode 0600 via `OpenOptions::mode`. See module doc for why this
/// is sufficient (umask only removes bits).
///
/// # Errors
/// `io::Error` from create/write. Permission denied (running as
/// non-root, pidfile path is in `/var/run`) is the common one; the
/// caller logs and exits.
pub fn write_pidfile(path: &Path, cookie: &str, address: &str) -> io::Result<()> {
    // C `pidfile.c:28-29`: umask(0); umask(mask | 077); fopen("w").
    // We OpenOptions::mode(0o600). create+truncate is `fopen("w")`.
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // C `fprintf(f, "%d %s %s\n", getpid(), cookie, address)`.
    writeln!(f, "{} {} {}", std::process::id(), cookie, address)?;
    // C `return !fclose(f)`. fclose flushes; we let Drop close, but
    // sync_data to catch ENOSPC/EIO before the caller assumes success.
    // Actually no: `sync_data` is overkill (the C doesn't fsync). The
    // pidfile is read by another process; the write must be visible
    // to a subsequent open() in another process. Kernel page cache
    // guarantees that without fsync. Let Drop close.
    Ok(())
}

/// `init_control` unix socket bits (`control.c:186-227`). socket →
/// connect-probe → unlink → umask-bind → listen.
///
/// The connect-probe: before unlinking the stale socket file, try
/// connecting to it. If connect succeeds, there's a live daemon
/// already listening — REFUSE to start (`control.c:205-208`). This
/// is the "second tincd" guard. If connect fails (`ECONNREFUSED` =
/// stale socket file from a crashed daemon), unlink and proceed.
///
/// Returns the listener; caller does `EventLoop::add(fd, READ,
/// IoWhat::UnixListener)`.
pub struct ControlSocket {
    listener: UnixListener,
    /// Kept so `drop` can unlink. C `exit_control` (`control.c:233-
    /// 240`) unlinks both pidfile and socket; our drop does just
    /// the socket (pidfile is the daemon's responsibility, see
    /// `Daemon::drop`).
    path: std::path::PathBuf,
}

/// The `EADDRINUSE` distinguishing case for `bind()`. We've already
/// proven (via the connect-probe) that nothing is listening. If
/// bind STILL fails with EADDRINUSE after the unlink, something
/// raced us — another tincd starting in parallel.
#[derive(Debug)]
pub enum BindError {
    /// Connect-probe succeeded — a live daemon is on the socket.
    AlreadyRunning,
    /// `socket()`/`bind()`/`listen()` failed.
    Io(io::Error),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "control socket already in use"),
            Self::Io(e) => write!(f, "control socket bind failed: {e}"),
        }
    }
}

impl std::error::Error for BindError {}

impl ControlSocket {
    /// `init_control` lines 186-227.
    ///
    /// # Errors
    /// `AlreadyRunning` if the connect-probe succeeds (second daemon).
    /// `Io` for socket/bind/listen failures.
    pub fn bind(path: &Path) -> Result<Self, BindError> {
        // ─── connect-probe (control.c:205-208)
        // C: socket(); strncpy sun_path; if(connect() >= 0) ERROR.
        // We `UnixStream::connect`. If it succeeds, something's
        // there. If `ECONNREFUSED` (or `ENOENT` — no socket file
        // at all), good, proceed.
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(BindError::AlreadyRunning);
        }
        // The error case is the happy path. We don't inspect WHICH
        // error — ECONNREFUSED, ENOENT, EACCES all mean "nothing
        // is healthily listening there", which is what we want.

        // ─── unlink stale (control.c:210)
        // C: `unlink(unixsocketname)`. Errors ignored (`ENOENT` is
        // expected on first run; if it's something else, bind will
        // fail and we'll see why).
        let _ = std::fs::remove_file(path);

        // ─── bind with umask 077 (control.c:212-214)
        // C: `mask = umask(0); umask(mask | 077); bind(); umask(mask)`.
        // The socket file's perms come from `0o777 & ~umask`. With
        // `umask | 077`, group/other bits are stripped → `0o700`.
        //
        // `UnixListener::bind` doesn't take a mode arg. So: umask
        // dance. The race window (umask is process-global, another
        // thread might create a file with the wrong perms during
        // these three lines) doesn't apply — daemon is single-
        // threaded, this runs at boot before the event loop.
        //
        // SAFETY: `umask(2)` is the documented way to set the
        // process umask. The wrapper is in `libc::umask`, not nix
        // (nix has it under `sys::stat::umask` actually but with
        // a Mode type — same call, different ergonomics; we're
        // already linking libc directly for read/send).
        #[allow(unsafe_code)]
        let old_mask = unsafe { libc::umask(0o077) };
        let bind_result = UnixListener::bind(path);
        // Restore unconditionally, even if bind failed.
        #[allow(unsafe_code)]
        unsafe {
            libc::umask(old_mask);
        }

        let listener = bind_result.map_err(BindError::Io)?;

        // ─── listen(3) (control.c:222)
        // `UnixListener::bind` already calls `listen()` internally
        // with backlog 128 (std's default). C uses backlog 3. The
        // backlog is "max pending accept() queue length"; 128 is
        // fine, control connections are rare.

        // ─── nonblocking
        // mio is level-triggered; the listener fd needs O_NONBLOCK
        // so accept() returns EWOULDBLOCK when the queue is empty
        // instead of blocking the loop. C doesn't set this — it
        // relies on accept-only-when-epoll-says-READ, which works
        // but is fragile under spurious wakeups. We're stricter.
        listener.set_nonblocking(true).map_err(BindError::Io)?;

        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// `accept()` wrapper. Non-blocking; returns `WouldBlock` if no
    /// connection pending (spurious wakeup).
    ///
    /// `handle_new_unix_connection` (`net_socket.c:781-812`) does
    /// `accept()` and constructs a `connection_t`. We do just the
    /// `accept()` part — connection construction is the daemon's job
    /// (it owns the slotmap).
    ///
    /// The accepted stream is set non-blocking before return —
    /// `Connection::feed` does `read()` and expects EWOULDBLOCK on
    /// empty.
    ///
    /// # Errors
    /// `io::Error` from `accept()`. `WouldBlock` is normal (spurious
    /// wakeup or another thread raced us — but we're single-threaded).
    /// Anything else is an actual problem.
    pub fn accept(&self) -> io::Result<std::os::unix::net::UnixStream> {
        let (stream, _addr) = self.listener.accept()?;
        // O_NONBLOCK on the new fd. accept4(SOCK_NONBLOCK) would
        // do this atomically, but std's accept() doesn't expose
        // accept4 flags. The non-atomic gap is fine: nothing reads
        // from this fd between accept and set_nonblocking.
        stream.set_nonblocking(true)?;
        Ok(stream)
    }

    /// Raw fd for `EventLoop::add`.
    #[must_use]
    pub fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.listener.as_raw_fd()
    }
}

impl Drop for ControlSocket {
    /// `exit_control` (`control.c:235`). Unlink the socket file so
    /// the next daemon's connect-probe doesn't get a false positive
    /// from a stale file. The C also unlinks the pidfile (`:240`);
    /// we let `Daemon` own that (it created it).
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;

    /// Unique tempdir per test. Same pattern as the rest of the
    /// workspace: thread id in the name, no `tempfile` dep.
    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tincd-control-{}-{:?}",
            tag,
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cookie_is_64_lowercase_hex() {
        let c = generate_cookie();
        assert_eq!(c.len(), COOKIE_HEX_LEN);
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()));
        // bin2hex uses lowercase. `utils.c:43`.
        assert_eq!(c, c.to_lowercase());
    }

    /// Two cookies differ. (Probability of collision: 2^-256.
    /// If this fails, OsRng is broken.)
    #[test]
    fn cookies_differ() {
        assert_ne!(generate_cookie(), generate_cookie());
    }

    /// Pidfile format matches what `tinc-tools::Pidfile::read`
    /// expects. The fscanf is `"%20d %64s %128s port %128s"`.
    #[test]
    fn pidfile_format() {
        let dir = tmpdir("pidfile");
        let path = dir.join("tinc.pid");
        let cookie = "a".repeat(64);
        write_pidfile(&path, &cookie, "127.0.0.1 port 655").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let our_pid = std::process::id();
        assert_eq!(content, format!("{our_pid} {cookie} 127.0.0.1 port 655\n"));

        // Mode 0600. The C umask dance produces this; our
        // OpenOptions::mode does too (see module doc for why).
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Bind, then a second bind on the same path returns
    /// `AlreadyRunning`. The connect-probe at work.
    #[test]
    fn second_bind_refused() {
        let dir = tmpdir("second-bind");
        let path = dir.join("tinc.socket");

        let first = ControlSocket::bind(&path).expect("first bind");
        let second = ControlSocket::bind(&path);
        assert!(matches!(second, Err(BindError::AlreadyRunning)));

        // Cleanup: first drops, unlinks socket.
        drop(first);
        // Now a third bind works.
        let third = ControlSocket::bind(&path).expect("third bind after drop");
        drop(third);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Stale socket file from a crashed daemon: bind succeeds. The
    /// connect-probe gets ECONNREFUSED, unlink clears it.
    ///
    /// Simulating a crash: bind a raw `UnixListener`, drop it. std
    /// closes the fd but does NOT unlink the socket file (the kernel
    /// has no listener, the file is just a path-layer artifact).
    /// `ControlSocket::bind`'s connect-probe sees ECONNREFUSED,
    /// unlinks, re-binds.
    #[test]
    fn stale_socket_recovered() {
        let dir = tmpdir("stale");
        let path = dir.join("tinc.socket");

        // Stale: std bind + drop. fd closed, file stays.
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists(), "std UnixListener leaves file on drop");

        // ControlSocket::bind cleans it up.
        let cs = ControlSocket::bind(&path).expect("bind over stale");
        drop(cs);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Socket file is mode 0700 (or stricter) after bind. The
    /// umask dance.
    #[test]
    fn socket_perms() {
        let dir = tmpdir("perms");
        let path = dir.join("tinc.socket");

        let cs = ControlSocket::bind(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // `0o777 & ~0o077 = 0o700`. The S_IFSOCK bits are in the
        // high bits; mask to perm bits.
        assert_eq!(
            mode & 0o077,
            0,
            "group/other bits must be stripped; got {mode:o}"
        );

        drop(cs);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Accept works. Round-trip a byte through the listener to
    /// prove the stream is connected and non-blocking.
    #[test]
    fn accept_roundtrip() {
        let dir = tmpdir("accept");
        let path = dir.join("tinc.socket");

        let cs = ControlSocket::bind(&path).unwrap();

        // Client connect from another thread? No — single-threaded
        // is fine: connect, then accept (the kernel queues the
        // pending connection).
        let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let server = cs.accept().unwrap();

        // Non-blocking is set: read with no data returns WouldBlock.
        let mut buf = [0u8; 1];
        let err = (&server).read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // Round-trip a byte.
        (&client).write_all(b"x").unwrap();
        // Spin until readable (no event loop here). In practice
        // the kernel delivers immediately on localhost.
        let mut tries = 100;
        loop {
            match (&server).read(&mut buf) {
                Ok(1) => break,
                Ok(_) => panic!("unexpected read"),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tries -= 1;
                    assert!(tries > 0, "timed out");
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(buf[0], b'x');

        drop(cs);
        std::fs::remove_dir_all(&dir).ok();
    }
}
