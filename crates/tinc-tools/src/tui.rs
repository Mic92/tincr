//! The seven escape sequences `tinc top` actually needs.
//!
//! ncurses footprint, exhaustively:
//!
//! | curses call | What it does | Here |
//! |---|---|---|
//! | `initscr()` + `endwin()` | Alt screen + raw mode + restore | [`RawMode`] RAII |
//! | `timeout(ms)` + `getch()` | Read 1 byte or timeout | [`getch_timeout`] |
//! | `mvprintw(r, c, ...)` | Positioned printf | [`goto`] then `write!` |
//! | `attrset(A_BOLD)` | Bold on | [`BOLD`] |
//! | `attrset(A_DIM)` | Dim on | [`DIM`] |
//! | `attrset(A_REVERSE)` | Reverse video | [`REVERSE`] |
//! | `attrset(A_NORMAL)` | Reset | [`RESET`] |
//! | `chgat(-1, A_REVERSE, ...)` | Reverse-video rest of line | `REVERSE` + [`CLEAR_EOL`] + `RESET` |
//! | `refresh()` | Flush | `stdout.flush()` |
//! | `move(r, c)` | Position cursor | [`goto`] |
//! | `scanw("%f")` | Read a float in cooked mode | [`RawMode::with_cooked`] |
//! | clip to `LINES` | Don't write past height | [`winsize`] |
//!
//! ratatui is a widget framework with ~35 transitive deps; we need
//! 7 escape sequences and `tcsetattr`. `nix` has what we need.
//!
//! What we lose vs curses: terminfo (we emit ANSI X3.64 directly —
//! every terminal since VT100 speaks it), implicit row clipping
//! (caller checks `winsize()` instead), and `KEY_BREAK` (Windows-
//! only, we're `#[cfg(unix)]`).

#![cfg(unix)]

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::io::AsFd;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::termios::{self, LocalFlags, SetArg, SpecialCharacterIndices, Termios};
use nix::unistd;

// Escape sequences — ANSI X3.64 / ECMA-48. CSI is `ESC [` aka
// `\x1b[`; SGR is `CSI Ps m`. Universal since VT100.

/// `CSI K` — erase from cursor to end of line. Cleared cells take
/// the current SGR, so `REVERSE` + `CLEAR_EOL` paints the rest of
/// the line in reverse video (curses' `chgat(-1, A_REVERSE, ...)`).
pub(crate) const CLEAR_EOL: &str = "\x1b[K";

/// `CSI 1 m` — bold. Nodes with traffic this tick.
pub(crate) const BOLD: &str = "\x1b[1m";
/// `CSI 2 m` — dim. Nodes that disappeared since last dump.
pub(crate) const DIM: &str = "\x1b[2m";
/// `CSI 7 m` — reverse video. Column header bar.
pub(crate) const REVERSE: &str = "\x1b[7m";
/// `CSI 0 m` — reset all attributes. Between rows; stops bleed.
pub(crate) const RESET: &str = "\x1b[0m";

/// `CSI ? 1049 h` / `l` — alternate screen buffer. What makes
/// `top` go away cleanly on quit without trashing scrollback.
const ALT_SCREEN_ENTER: &str = "\x1b[?1049h";
const ALT_SCREEN_LEAVE: &str = "\x1b[?1049l";

/// `CSI ? 25 l` / `h` — hide/show cursor. A blinking cursor
/// parked at (0,0) between redraws looks broken.
const CURSOR_HIDE: &str = "\x1b[?25l";
const CURSOR_SHOW: &str = "\x1b[?25h";

/// `CSI {row} ; {col} H` — cursor position. Args are 0-indexed
/// (top-left `(0,0)`); VT100 escapes are 1-indexed, so we add 1.
/// Returns `String` for inline `write!`; one alloc per row at 1Hz.
#[must_use]
pub(crate) fn goto(row: u16, col: u16) -> String {
    format!("\x1b[{};{}H", row + 1, col + 1)
}

// winsize — TIOCGWINSZ

/// Terminal dimensions. Curses silently clips `mvprintw` past
/// `LINES`; we'd scroll the terminal. Caller clips explicitly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Winsize {
    pub rows: u16,
    #[expect(dead_code)] // populated from TIOCGWINSZ; rows is the only field top.rs reads today
    pub cols: u16,
}

/// `TIOCGWINSZ` on stdout, falling back to 24×80 if it isn't a tty or the ioctl
/// fails. `nix::ioctl_read_bad!` yields an `unsafe fn` only because ioctl is
/// variadic in C.
#[expect(unsafe_code)]
#[must_use]
pub(crate) fn winsize() -> Winsize {
    // Macro generates `unsafe fn tiocgwinsz(fd, *mut winsize)`.
    // Types/constants come from `nix::libc` so this module has no
    // direct `libc` dependency — `nix` already pins the version.
    mod ioctl {
        nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);
    }

    let mut ws = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `STDOUT_FILENO` is valid or the ioctl fails with EBADF; `&raw mut
    // ws` is a valid aligned `*mut winsize` the kernel writes and never reads. A
    // SIGWINCH race costs one tick at the old size.
    let ok = unsafe { ioctl::tiocgwinsz(io::stdout().as_raw_fd(), &raw mut ws) };

    match ok {
        // 0×0 means "the tty doesn't know" (some serial consoles).
        Ok(_) if ws.ws_row > 0 && ws.ws_col > 0 => Winsize {
            rows: ws.ws_row,
            cols: ws.ws_col,
        },
        // Not a tty, or 0×0. VT100 default — likely wrong but
        // better than crashing. RawMode::enter already checked
        // isatty so this is dead in practice.
        _ => Winsize { rows: 24, cols: 80 },
    }
}

/// Raw-mode RAII guard (`initscr`/`endwin`): Drop restores the terminal even if
/// `top`'s loop panics, instead of leaving the shell without echo. SIGINT still
/// bypasses it (known gap). No `StdoutLock` is held, since that would block the
/// cooked-mode `read_line`.
pub(crate) struct RawMode {
    /// The termios as it was before we touched it. Drop restores.
    original: Termios,
}

impl RawMode {
    /// Enter raw mode (ECHO, ICANON, ISIG off — Ctrl-C arrives as byte 0x03, hence
    /// the `'q'` key), alt screen, hidden cursor; hardcoded ANSI instead of
    /// terminfo. `OPOST` stays on so stray output keeps its `\r\n`.
    ///
    /// # Errors
    /// Stdin isn't a tty.
    pub(crate) fn enter() -> io::Result<Self> {
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        // Preflight isatty: tcgetattr would ENOTTY anyway, but
        // "stdin is not a terminal" beats "Inappropriate ioctl".
        // (`nix::Errno` → `io::Error` via nix's From; bare `?` works.)
        if !unistd::isatty(fd)? {
            return Err(io::Error::other("stdin is not a terminal"));
        }

        // Snapshot before mutation.
        let original = termios::tcgetattr(fd)?;

        // Mutate
        let mut raw = original.clone();
        raw.local_flags &= !(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG);
        // `VMIN=1, VTIME=0`: `read()` blocks for 1 byte. poll()
        // handles our timeout, but with ICANON off the inherited
        // VMIN/VTIME are unspecified — set them explicitly.
        //
        // `SpecialCharacterIndices` not `VMIN`: nix's enum
        // normalizes the linux-sparc64 quirk where `VMIN == VEOF`.
        // Free portability insurance; same value everywhere else.
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;

        // TCSANOW: apply immediately, nothing to drain yet.
        termios::tcsetattr(fd, SetArg::TCSANOW, &raw)?;

        // Alt screen + cursor after tcsetattr: if that had failed
        // we'd return with nothing to undo. `print!` per struct doc.
        print!("{ALT_SCREEN_ENTER}{CURSOR_HIDE}");
        io::stdout().flush()?;

        Ok(Self { original })
    }

    /// Temporarily restore cooked mode (cursor shown, still on the alt screen), run
    /// `f`, re-enter raw. Used for the `'s'` delay prompt.
    ///
    /// # Errors
    /// `tcsetattr` or `f`'s error; re-entering raw is best-effort (Drop retries).
    pub(crate) fn with_cooked<T>(
        &self,
        f: impl FnOnce(&mut dyn io::BufRead) -> io::Result<T>,
    ) -> io::Result<T> {
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        // Show cursor before tcsetattr: ECHO comes back with it,
        // so any immediate typing is visible.
        print!("{CURSOR_SHOW}");
        io::stdout().flush()?;
        termios::tcsetattr(fd, SetArg::TCSANOW, &self.original)?;

        // Lock held for f's duration only; released before re-raw.
        let result = f(&mut stdin.lock());

        // Re-raw (best-effort; same flags as enter())
        let mut raw = self.original.clone();
        raw.local_flags &= !(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG);
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
        let _ = termios::tcsetattr(fd, SetArg::TCSANOW, &raw);
        print!("{CURSOR_HIDE}");
        let _ = io::stdout().flush();

        result
    }
}

impl Drop for RawMode {
    /// Leave alt screen, show cursor, restore termios. In that
    /// order: if termios restore somehow fails the user at least
    /// has their scrollback and cursor back. Errors swallowed —
    /// Drop can't return Result and there's nothing the caller
    /// could do anyway.
    fn drop(&mut self) {
        print!("{ALT_SCREEN_LEAVE}{CURSOR_SHOW}{RESET}");
        let _ = io::stdout().flush();
        let _ = termios::tcsetattr(io::stdin().as_fd(), SetArg::TCSANOW, &self.original);
    }
}

/// Poll stdin with a deadline: `None` on timeout, `Some(byte)` on key. No
/// keycode decoding (arrow keys arrive as three bytes that `top` ignores). EOF
/// maps to `Some(b'q')` so a closed stdin quits instead of spinning.
///
/// # Errors
/// Real stdin I/O errors; EINTR (e.g. SIGWINCH) is `None`.
pub(crate) fn getch_timeout(ms: u16) -> io::Result<Option<u8>> {
    let stdin = io::stdin();
    let fd = stdin.as_fd();

    let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];

    // u16 → PollTimeout: never -1 (forever), max ~65s. Plenty.
    match poll(&mut fds, PollTimeout::from(ms)) {
        // 0 ready → timeout. EINTR (SIGWINCH mid-poll) → also
        // timeout: next tick redraws at the new size. Different
        // meanings, same response — hence the or-pattern.
        Ok(0) | Err(nix::errno::Errno::EINTR) => Ok(None),

        Ok(_) => {
            // `unistd::read` on the raw fd, not `Stdin::read`:
            // std's BufReader may hold stale bytes left by
            // `with_cooked`'s `read_line`. Raw fd bypasses that.
            let mut c = [0u8; 1];
            match unistd::read(&stdin, &mut c) {
                Ok(1) => Ok(Some(c[0])),
                Ok(0) => Ok(Some(b'q')), // EOF → quit (see doc)
                Ok(_) => unreachable!("read into 1-byte buffer"),
                Err(nix::errno::Errno::EINTR) => Ok(None),
                // `io::Error::from` not `.into()`: with two
                // unanchored conversions in the chain inference
                // hits E0282. One explicit `from` anchors both.
                Err(e) => Err(io::Error::from(e)),
            }
        }

        Err(e) => Err(e.into()),
    }
}

// Tests — only `goto()` is testable; the tty bits ENOTTY under
// `cargo test`. Those get manual smoke via `tinc top`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goto_adjusts_to_one_indexed() {
        assert_eq!(goto(0, 0), "\x1b[1;1H");
        assert_eq!(goto(2, 0), "\x1b[3;1H");
        assert_eq!(goto(24, 79), "\x1b[25;80H"); // bottom-right of 25×80
    }
}
