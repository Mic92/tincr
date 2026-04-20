//! Control socket setup: `write_pidfile` + `init_control`
//! unix-socket bits.
//!
//! ## What `init_control` does
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
//! C uses `umask(0); umask(mask | 077)` for mode-0600 creation.
//! For files: `OpenOptions::mode(0o600)` is sufficient — umask only
//! removes bits, never adds, and `0o600 & ~umask` has no overlap
//! with sane umasks. The C dance defended against `fopen()`'s
//! `0o666` default; we don't need it.
//!
//! For the unix socket: `bind()` honors umask and `UnixListener::
//! bind` doesn't expose mode. The C uses a process-global umask
//! dance; we `chmod()` the socket inode immediately after bind
//! instead — same outcome, no global state.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

use rand_core::{OsRng, RngCore};

/// 32 random bytes → 64 hex chars.
pub const COOKIE_BYTES: usize = 32;
pub const COOKIE_HEX_LEN: usize = COOKIE_BYTES * 2;

/// `randomize` + `bin2hex`. The cookie is the auth secret; reading
/// it from the pidfile is how `tinc` proves it's allowed to control
/// the daemon. The pidfile is mode 0600 = filesystem-based auth,
/// same model as ssh-agent's socket.
///
/// `bin2hex` uses lowercase. `format!("{:02x}")` matches.
///
/// # Panics
/// Only via `OsRng::fill_bytes`, only if `/dev/urandom` (or
/// `getrandom(2)`) is unavailable. At that point the daemon can't
/// generate session keys either; aborting is correct.
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

/// `write_pidfile`. The format is:
///
/// ```text
/// <pid> <cookie> <host> port <port>\n
/// ```
///
/// `tinc-tools::Pidfile::read` parses this. The `fscanf` format is
/// `"%20d %64s %128s port %128s"` — `port` is a literal in the
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
    // create+truncate is `fopen("w")`. O_NOFOLLOW: this runs as root
    // pre-privdrop; following a planted symlink would be an
    // arbitrary-file truncate+write.
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    // `.mode()` only applies on create; force 0600 on a pre-existing
    // file too (cookie is the auth secret).
    nix::sys::stat::fchmod(&f, nix::sys::stat::Mode::from_bits_truncate(0o600))
        .map_err(io::Error::from)?;
    writeln!(f, "{} {} {}", std::process::id(), cookie, address)?;
    // fclose flushes; we let Drop close. `sync_data` is overkill. The
    // pidfile is read by another process; the write must be visible
    // to a subsequent open() in another process. Kernel page cache
    // guarantees that without fsync. Let Drop close.
    Ok(())
}

/// `init_control` unix socket bits. socket → connect-probe → unlink
/// → bind → chmod → listen.
///
/// The connect-probe: before unlinking the stale socket file, try
/// connecting to it. If connect succeeds, there's a live daemon
/// already listening — REFUSE to start. This is the "second tincd"
/// guard. If connect fails (`ECONNREFUSED` =
/// stale socket file from a crashed daemon), unlink and proceed.
///
/// Returns the listener; caller does `EventLoop::add(fd, READ,
/// IoWhat::UnixListener)`.
pub struct ControlSocket {
    listener: UnixListener,
    /// Kept so `drop` can unlink. `exit_control` unlinks both
    /// pidfile and socket; our drop does just the socket (pidfile
    /// is the daemon's responsibility, see
    /// `Daemon::drop`).
    path: std::path::PathBuf,
}

/// The `EADDRINUSE` distinguishing case for `bind()`. We've already
/// proven (via the connect-probe) that nothing is listening. If
/// bind STILL fails with EADDRINUSE after the unlink, something
/// raced us — another tincd starting in parallel.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// Connect-probe succeeded — a live daemon is on the socket.
    #[error("control socket already in use")]
    AlreadyRunning,
    /// `socket()`/`bind()`/`listen()` failed.
    #[error("control socket bind failed: {0}")]
    Io(#[source] io::Error),
}

impl ControlSocket {
    /// `init_control` lines 186-227.
    ///
    /// # Errors
    /// `AlreadyRunning` if the connect-probe succeeds (second daemon).
    /// `Io` for socket/bind/listen failures.
    pub fn bind(path: &Path) -> Result<Self, BindError> {
        // ─── connect-probe
        // `UnixStream::connect`: if it succeeds, something's
        // there. If `ECONNREFUSED` (or `ENOENT` — no socket file
        // at all), good, proceed.
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(BindError::AlreadyRunning);
        }
        // The error case is the happy path. We don't inspect WHICH
        // error — ECONNREFUSED, ENOENT, EACCES all mean "nothing
        // is healthily listening there", which is what we want.

        // ─── unlink stale (only if it's actually a socket)
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = std::fs::remove_file(path);
        }

        // ─── bind, then chmod 0700
        // chmod-after-bind instead of the C's process-global umask
        // dance: thread-safe (cargo test runs this on a pool). The
        // brief pre-chmod inode is 0o755 — no w bit, connect(2)
        // already refused on Linux/BSD.
        let listener = UnixListener::bind(path).map_err(BindError::Io)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(BindError::Io)?;

        // ─── listen
        // `UnixListener::bind` already calls `listen()` internally
        // with backlog 128 (std's default). The
        // backlog is "max pending accept() queue length"; 128 is
        // fine, control connections are rare.

        // ─── nonblocking
        // epoll is level-triggered; the listener fd needs O_NONBLOCK
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
    /// `handle_new_unix_connection` does `accept()` and constructs a
    /// `connection_t`. We do just the `accept()` part — connection
    /// construction is the daemon's job
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
}

impl std::os::fd::AsFd for ControlSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.listener)
    }
}

impl Drop for ControlSocket {
    /// Unlink the socket file so the next daemon's connect-probe
    /// doesn't get a false positive from a stale file. `exit_control`
    /// also unlinks the pidfile;
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
        // bin2hex uses lowercase.
        assert_eq!(c, c.to_lowercase());
    }

    /// Two cookies differ. (Probability of collision: 2^-256.
    /// If this fails, `OsRng` is broken.)
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

    #[test]
    fn pidfile_fchmod_on_existing() {
        let dir = tmpdir("pidfile-chmod");
        let path = dir.join("tinc.pid");
        std::fs::write(&path, "stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        write_pidfile(&path, &"a".repeat(64), "127.0.0.1 port 0").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pidfile_nofollow() {
        let dir = tmpdir("pidfile-symlink");
        let target = dir.join("target");
        let path = dir.join("tinc.pid");
        std::fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = write_pidfile(&path, "c", "a").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::Error::ELOOP as i32));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
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

    /// A non-socket at the path is left alone; bind fails instead.
    #[test]
    fn bind_preserves_non_socket() {
        let dir = tmpdir("nonsock");
        let path = dir.join("tinc.socket");
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(matches!(ControlSocket::bind(&path), Err(BindError::Io(_))));
        assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Socket file is mode 0700 (or stricter) after bind. The
    /// post-bind `chmod()`.
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
