//! Minimal `sd_notify` for systemd `Type=notify` services.
//!
//! Replaces `linux/watchdog.c` from C tinc, but **without** linking
//! libsystemd. The notify protocol is just a Unix datagram to the socket
//! named by `$NOTIFY_SOCKET`; the payload is newline-separated `KEY=value`
//! pairs. See `sd_notify(3)`. We implement only the subset tinc needs:
//! `READY=1`, `STOPPING=1`, `WATCHDOG=1`.
//!
//! All functions are no-ops when `NOTIFY_SOCKET` is unset (i.e. when not
//! running under systemd), matching the C behaviour and the explicit
//! advice in `man sd_notify.3` to ignore errors. Callers therefore do
//! not need to gate on platform or service-manager presence.
//!
//! Call sites (`main.rs`, periodic timer) are intentionally **not** wired
//! here; another agent owns that surgery. This module exposes the building
//! blocks and nothing more.

#![cfg(unix)]

use std::env;
use std::ffi::OsStr;
use std::io;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

/// Env var systemd sets to the notification socket path.
const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

/// Env var systemd sets to the watchdog timeout in microseconds.
const WATCHDOG_USEC: &str = "WATCHDOG_USEC";

/// Send a raw notification (`READY=1` etc.) to systemd. Unset `NOTIFY_SOCKET`
/// is `Ok(())` by contract. Pathname and abstract (`@` → leading NUL) sockets
/// both work.
///
/// # Errors
/// I/O binding or sending; callers should ignore them (module doc), and the
/// typed wrappers do.
pub fn notify(state: &str) -> io::Result<()> {
    let Some(path) = env::var_os(NOTIFY_SOCKET) else {
        return Ok(());
    };
    notify_to(&path, state)
}

/// Core send, factored out so tests can target a socket directly without
/// the inherent unsafety of mutating process env from multiple threads.
fn notify_to(path: &OsStr, state: &str) -> io::Result<()> {
    let bytes = path.as_bytes();

    // sd_notify(3): the path must be absolute or abstract. Reject
    // anything else rather than guessing — systemd never sets a
    // relative path, so this is a misconfiguration.
    let addr = match bytes.first() {
        Some(b'/') => SocketAddr::from_pathname(path)?,
        Some(b'@') => {
            // Abstract socket: '@' on the env-var side becomes a NUL
            // byte on the wire. std's `from_abstract_name` wants the
            // name *without* the leading NUL.
            #[cfg(target_os = "linux")]
            {
                SocketAddr::from_abstract_name(&bytes[1..])?
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "abstract NOTIFY_SOCKET on non-Linux",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET must start with '/' or '@'",
            ));
        }
    };

    let sock = UnixDatagram::unbound()?;
    let n = sock.send_to_addr(state.as_bytes(), &addr)?;
    if n != state.len() {
        // Datagram sockets don't short-write, but be defensive: if we
        // ever see this, the kernel did something very strange.
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short sd_notify datagram",
        ));
    }
    Ok(())
}

/// Tell systemd the daemon is fully initialised. Call once, after all
/// listeners are bound and tinc-up has run. Mirrors `watchdog_start()`'s
/// `sd_notify(false, "READY=1")` from C.
pub fn notify_ready() {
    let _ = notify("READY=1");
}

/// Tell systemd the daemon is shutting down. Call from the shutdown path.
/// Mirrors `watchdog_stop()`'s `sd_notify(false, "STOPPING=1")`.
pub fn notify_stopping() {
    let _ = notify("STOPPING=1");
}

/// Send a single watchdog keepalive. The periodic timer should call this.
pub fn notify_watchdog() {
    let _ = notify("WATCHDOG=1");
}

/// If systemd armed a watchdog (`WATCHDOG_USEC` positive), the ping interval:
/// half the timeout so one missed ping isn't fatal. `None` means don't arm a
/// timer. `WATCHDOG_PID` isn't checked; tinc never forks a supervised child
/// that could inherit a stale value.
#[must_use]
pub fn watchdog_interval() -> Option<Duration> {
    parse_watchdog_usec(env::var(WATCHDOG_USEC).ok().as_deref())
}

/// Pure parse step, split out so tests don't have to mutate process env
/// (the crate is `#![deny(unsafe_code)]` and `set_var` is unsafe in
/// edition 2024).
fn parse_watchdog_usec(raw: Option<&str>) -> Option<Duration> {
    let usec: u64 = raw?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    // Integer halving; sub-microsecond precision is meaningless here.
    Some(Duration::from_micros(usec / 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;

    /// Bind a datagram socket at a unique filesystem path and return both
    /// ends of the conversation. We don't use a tempdir crate (per the
    /// project rule against NamedTempFile-style helpers); a pid+nanos
    /// suffix is plenty for a test that cleans up after itself.
    struct Unlink(OsString);
    impl Drop for Unlink {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn bound_socket() -> (UnixDatagram, Unlink) {
        let path = format!(
            "/tmp/tincd-sdnotify-test.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        let sock = UnixDatagram::bind(&path).expect("bind test socket");
        (sock, Unlink(OsString::from(path)))
    }

    #[test]
    fn datagram_body_is_exact_state_string() {
        let (rx, path) = bound_socket();

        notify_to(&path.0, "READY=1").expect("send READY=1");

        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn multiple_states_arrive_as_separate_datagrams() {
        let (rx, path) = bound_socket();

        // The C code sends READY then immediately a first WATCHDOG ping;
        // make sure we don't accidentally coalesce.
        notify_to(&path.0, "READY=1").unwrap();
        notify_to(&path.0, "WATCHDOG=1").unwrap();

        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abstract_socket_at_prefix_maps_to_nul() {
        // Abstract namespace: no filesystem entry, no cleanup needed.
        // The receiving side binds with the raw name; the sending side
        // uses the '@'-prefixed env-var form. They must meet.
        let name = format!("tincd-sdnotify-abs-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx = UnixDatagram::bind_addr(&addr).unwrap();

        let env_form = OsString::from_vec({
            let mut v = vec![b'@'];
            v.extend_from_slice(name.as_bytes());
            v
        });
        notify_to(&env_form, "STOPPING=1").unwrap();

        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1");
    }

    #[test]
    fn relative_path_is_rejected() {
        let err = notify_to(OsStr::new("relative/path"), "READY=1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn watchdog_interval_halves_the_timeout() {
        // 30s -> ping every 15s.
        assert_eq!(
            parse_watchdog_usec(Some("30000000")),
            Some(Duration::from_secs(15))
        );
        // Odd number: integer halving, we don't care about the lost half-micro.
        assert_eq!(
            parse_watchdog_usec(Some("3")),
            Some(Duration::from_micros(1))
        );
    }

    #[test]
    fn watchdog_interval_absent_or_garbage_is_none() {
        assert!(parse_watchdog_usec(None).is_none());
        assert!(parse_watchdog_usec(Some("")).is_none());
        assert!(parse_watchdog_usec(Some("nope")).is_none());
        assert!(parse_watchdog_usec(Some("0")).is_none()); // zero = disabled
    }
}
