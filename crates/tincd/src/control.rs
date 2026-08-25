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
//! bind` doesn't expose mode. We bracket `bind()` with a tightened
//! `umask(0o077)` so the inode is never observable with group/other
//! bits, then `chmod()` 0700 for good measure.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

use rand_core::Rng;
use std::fs;
use std::fs::Permissions;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tinc_crypto::os_rng;

/// 32 random bytes → 64 hex chars.
pub(crate) const COOKIE_BYTES: usize = 32;
pub(crate) const COOKIE_HEX_LEN: usize = COOKIE_BYTES * 2;

/// Random cookie, lowercase hex. Reading it from the 0600 pidfile is how `tinc`
/// proves it may control the daemon (filesystem auth, like ssh-agent's socket).
///
/// # Panics
/// Only if the OS RNG is unavailable, at which point session keys can't be
/// generated either.
#[must_use]
pub(crate) fn generate_cookie() -> String {
    let mut bytes = [0u8; COOKIE_BYTES];
    os_rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(COOKIE_HEX_LEN);
    for b in bytes {
        write!(hex, "{b:02x}").expect("String write infallible");
    }
    hex
}

/// Write the pidfile: `<pid> <cookie> <host> port <port>\n`, mode 0600 (umask
/// can only remove bits). `port` is a literal token, so the address reads
/// `127.0.0.1 port 655`; `tinc-tools::Pidfile::read` parses it.
///
/// # Errors
/// create/write failure, typically permission denied on `/var/run` as non-root;
/// the caller logs and exits.
pub(crate) fn write_pidfile(path: &Path, cookie: &str, address: &str) -> io::Result<()> {
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

/// Control socket: socket, connect-probe, unlink, bind, chmod, listen. The
/// probe is the second-tincd guard: if connecting to the existing path succeeds
/// a daemon is live and we refuse to start; `ECONNREFUSED` means a stale file
/// from a crash, so unlink and proceed. The caller registers the listener with
/// the event loop.
pub(crate) struct ControlSocket {
    listener: UnixListener,
    /// Kept so `drop` can unlink. `exit_control` unlinks both
    /// pidfile and socket; our drop does just the socket (pidfile
    /// is the daemon's responsibility, see
    /// `Daemon::drop`).
    path: PathBuf,
}

/// The `EADDRINUSE` distinguishing case for `bind()`. We've already
/// proven (via the connect-probe) that nothing is listening. If
/// bind still fails with EADDRINUSE after the unlink, something
/// raced us — another tincd starting in parallel.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BindError {
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
    pub(crate) fn bind(path: &Path) -> Result<Self, BindError> {
        // connect-probe.
        // `UnixStream::connect`: if it succeeds, something's
        // there. If `ECONNREFUSED` (or `ENOENT` — no socket file
        // at all), good, proceed.
        if UnixStream::connect(path).is_ok() {
            return Err(BindError::AlreadyRunning);
        }
        // The error case is the happy path. We don't inspect WHICH
        // error — ECONNREFUSED, ENOENT, EACCES all mean "nothing
        // is healthily listening there", which is what we want.

        // unlink stale (only if it's actually a socket).
        if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = fs::remove_file(path);
        }

        // bind under umask 0077.
        // `UnixListener::bind` listens internally → no fchmod window;
        // tighten umask so the inode is born 0700. Process-global, but
        // tightening only strips bits → fails safe for other threads.
        // SAFETY: umask(2) cannot fail.
        #[expect(unsafe_code)]
        let listener = unsafe {
            let prev = libc::umask(0o077);
            let r = UnixListener::bind(path);
            libc::umask(prev);
            r.map_err(BindError::Io)?
        };
        // Backstop in case the umask bracket is ever refactored away.
        fs::set_permissions(path, Permissions::from_mode(0o700)).map_err(BindError::Io)?;

        // `UnixListener::bind` already listened (backlog 128, plenty). Set O_NONBLOCK
        // so accept() returns EWOULDBLOCK on an empty queue instead of blocking the
        // loop on a spurious wakeup; C relies on epoll alone.
        listener.set_nonblocking(true).map_err(BindError::Io)?;

        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// Non-blocking `accept()`; the daemon constructs the connection (it owns the
    /// slotmap). The accepted stream is made non-blocking since `Connection::feed`
    /// expects EWOULDBLOCK on empty.
    ///
    /// # Errors
    /// `accept()` errors. `WouldBlock` is a normal spurious wakeup; anything else
    /// is real.
    pub(crate) fn accept(&self) -> io::Result<UnixStream> {
        let (stream, _addr) = self.listener.accept()?;
        // O_NONBLOCK on the new fd. accept4(SOCK_NONBLOCK) would
        // do this atomically, but std's accept() doesn't expose
        // accept4 flags. The non-atomic gap is fine: nothing reads
        // from this fd between accept and set_nonblocking.
        stream.set_nonblocking(true)?;
        Ok(stream)
    }
}

impl AsFd for ControlSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        AsFd::as_fd(&self.listener)
    }
}

impl Drop for ControlSocket {
    /// Unlink the socket file so the next daemon's connect-probe
    /// doesn't get a false positive from a stale file. `exit_control`
    /// also unlinks the pidfile;
    /// we let `Daemon` own that (it created it).
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};

    use crate::testutil::tmpdir;
    use std::fs;
    use std::fs::Permissions;
    use std::os::unix::net::UnixListener;
    use std::os::unix::net::UnixStream;
    use std::process;
    use std::thread;
    use std::time::Duration;

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

        let content = fs::read_to_string(&path).unwrap();
        let our_pid = process::id();
        assert_eq!(content, format!("{our_pid} {cookie} 127.0.0.1 port 655\n"));

        // Mode 0600. The C umask dance produces this; our
        // OpenOptions::mode does too (see module doc for why).
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn pidfile_fchmod_on_existing() {
        let dir = tmpdir("pidfile-chmod");
        let path = dir.join("tinc.pid");
        fs::write(&path, "stale").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o666)).unwrap();

        write_pidfile(&path, &"a".repeat(64), "127.0.0.1 port 0").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn pidfile_nofollow() {
        let dir = tmpdir("pidfile-symlink");
        let target = dir.join("target");
        let path = dir.join("tinc.pid");
        fs::write(&target, "x").unwrap();
        symlink(&target, &path).unwrap();

        let err = write_pidfile(&path, "c", "a").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::Error::ELOOP as i32));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
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
    }

    /// Stale socket file from a crashed daemon: bind a raw `UnixListener` and drop
    /// it (std closes the fd but leaves the path). `ControlSocket::bind`'s probe
    /// gets ECONNREFUSED, unlinks, re-binds.
    #[test]
    fn stale_socket_recovered() {
        let dir = tmpdir("stale");
        let path = dir.join("tinc.socket");

        // Stale: std bind + drop. fd closed, file stays.
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists(), "std UnixListener leaves file on drop");

        // ControlSocket::bind cleans it up.
        let cs = ControlSocket::bind(&path).expect("bind over stale");
        drop(cs);
    }

    /// A non-socket at the path is left alone; bind fails instead.
    #[test]
    fn bind_preserves_non_socket() {
        let dir = tmpdir("nonsock");
        let path = dir.join("tinc.socket");
        fs::write(&path, b"not a socket").unwrap();
        assert!(matches!(ControlSocket::bind(&path), Err(BindError::Io(_))));
        assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    }

    /// Socket file is mode 0700 (or stricter) after bind. The
    /// post-bind `chmod()`.
    #[test]
    fn socket_perms() {
        let dir = tmpdir("perms");
        let path = dir.join("tinc.socket");

        let cs = ControlSocket::bind(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        // `0o777 & ~0o077 = 0o700`. The S_IFSOCK bits are in the
        // high bits; mask to perm bits.
        assert_eq!(
            mode & 0o077,
            0,
            "group/other bits must be stripped; got {mode:o}"
        );

        drop(cs);
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
        let client = UnixStream::connect(&path).unwrap();
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
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(buf[0], b'x');

        drop(cs);
    }
}
