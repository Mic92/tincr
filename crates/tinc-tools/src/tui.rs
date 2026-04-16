//! The seven escape sequences `tinc top` actually needs.
//!
//! ncurses footprint, exhaustively:
//!
//! | curses call | What it does | Here |
//! |---|---|---|
//! | `initscr()` + `endwin()` | Alt screen + raw mode + restore | [`RawMode`] RAII |
//! | `timeout(ms)` + `getch()` | Read 1 byte OR timeout | [`getch_timeout`] |
//! | `erase()` | Clear screen | [`CLEAR`] |
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
use std::os::unix::io::AsFd;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::termios::{self, LocalFlags, SetArg, SpecialCharacterIndices, Termios};
use nix::unistd;

// Escape sequences — ANSI X3.64 / ECMA-48. CSI is `ESC [` aka
// `\x1b[`; SGR is `CSI Ps m`. Universal since VT100.

/// `CSI 2 J` — erase entire screen. No buffer/diff: at 1Hz × ~3KB
/// a full redraw is cheaper than the bookkeeping. `goto(0,0)` is
/// separate; this doesn't home the cursor.
pub const CLEAR: &str = "\x1b[2J";

/// `CSI K` — erase from cursor to end of line. Cleared cells take
/// the current SGR, so `REVERSE` + `CLEAR_EOL` paints the rest of
/// the line in reverse video (curses' `chgat(-1, A_REVERSE, ...)`).
pub const CLEAR_EOL: &str = "\x1b[K";

/// `CSI 1 m` — bold. Nodes with traffic this tick.
pub const BOLD: &str = "\x1b[1m";
/// `CSI 2 m` — dim. Nodes that disappeared since last dump.
pub const DIM: &str = "\x1b[2m";
/// `CSI 7 m` — reverse video. Column header bar.
pub const REVERSE: &str = "\x1b[7m";
/// `CSI 0 m` — reset all attributes. Between rows; stops bleed.
pub const RESET: &str = "\x1b[0m";

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
pub fn goto(row: u16, col: u16) -> String {
    format!("\x1b[{};{}H", row + 1, col + 1)
}

// winsize — TIOCGWINSZ

/// Terminal dimensions. Curses silently clips `mvprintw` past
/// `LINES`; we'd scroll the terminal. Caller clips explicitly.
#[derive(Debug, Clone, Copy)]
pub struct Winsize {
    pub rows: u16,
    pub cols: u16,
}

/// `TIOCGWINSZ` on stdout. Falls back to 24×80 if stdout isn't
/// a tty (shouldn't happen — `RawMode::enter` already failed)
/// or the ioctl fails.
///
/// `nix::ioctl_read_bad!` generates an `unsafe fn` because ioctl
/// is variadic at the C level — `nix` can't prove the third arg
/// type matches the request. The macro IS the safe-usage pattern;
/// the `unsafe` is the FFI calling convention, not the logic.
#[allow(unsafe_code)]
#[must_use]
pub fn winsize() -> Winsize {
    // Macro generates `unsafe fn tiocgwinsz(fd, *mut winsize)`.
    #[allow(clippy::items_after_statements)] // one-use ioctl: hoisting puts it 100 lines from its only call
    mod ioctl {
        nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);
    }

    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY:
    //   - `STDOUT_FILENO` is a valid fd (or the ioctl fails with
    //     EBADF, which is the `Err` arm).
    //   - `&mut ws` is a valid aligned `*mut winsize` to writable
    //     memory of the right size.
    //   - `TIOCGWINSZ` reads no memory from us, writes the struct.
    //     The macro picked `_IOR` direction, kernel agrees.
    //   - Thread-safe: ioctl on the FD, no global state. A SIGWINCH
    //     race → one tick at the old size. Harmless.
    // `&raw mut ws` not `&mut ws`: the macro takes `*mut T`. `&mut`
    // would auto-coerce; `&raw mut` makes it explicit no Rust borrow
    // ever exists (silences `clippy::borrow_as_ptr`). Same machine code.
    let ok = unsafe { ioctl::tiocgwinsz(libc::STDOUT_FILENO, &raw mut ws) };

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

// RawMode — RAII termios restore

/// `initscr()` + `endwin()` as a Drop guard. The point of RAII
/// here is **panic safety**: if `top`'s loop panics, Drop fires
/// during unwind and the terminal is restored. Without it the
/// user's shell is left in raw mode — no echo, no line buffering,
/// `stty sane` to recover.
///
/// Ctrl-C → SIGINT → process death → kernel doesn't restore
/// termios. KNOWN GAP. The fix is a `signal_hook` SIGINT handler
/// that drops the guard; deferred until someone Ctrl-C's it and
/// complains.
///
/// We don't hold a `StdoutLock` — it would block cooked-mode
/// `read_line`. Writes lock per-call via `print!`; fine at 1Hz.
pub struct RawMode {
    /// The termios as it was before we touched it. Drop restores.
    original: Termios,
}

impl RawMode {
    /// Enter raw mode + alt screen + hide cursor. Everything
    /// `initscr()` does, minus terminfo (hardcoded ANSI).
    ///
    /// "Raw mode" here = `ECHO` off (no key echo), `ICANON` off
    /// (`read` per-byte not per-line), `ISIG` off (Ctrl-C is byte
    /// 0x03, not SIGINT — hence `case 'q'` not a signal handler).
    ///
    /// `cfmakeraw` would also clear `OPOST`, killing `\n` → `\r\n`
    /// translation. We leave it on so stray output stays readable.
    ///
    /// # Errors
    /// Stdin isn't a tty. Caller maps to `CmdError`.
    pub fn enter() -> io::Result<Self> {
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        // Preflight isatty: tcgetattr would ENOTTY anyway, but
        // "stdin is not a terminal" beats "Inappropriate ioctl".
        // (`nix::Errno` → `io::Error` via nix's From; bare `?` works.)
        if !unistd::isatty(&fd)? {
            return Err(io::Error::other("stdin is not a terminal"));
        }

        // Snapshot BEFORE mutation.
        let original = termios::tcgetattr(fd)?;

        // ─── Mutate
        let mut raw = original.clone();
        raw.local_flags &= !(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG);
        // `VMIN=1, VTIME=0`: `read()` blocks for 1 byte. poll()
        // handles our timeout, but with ICANON off the inherited
        // VMIN/VTIME are unspecified — set them explicitly.
        //
        // `SpecialCharacterIndices` not `libc::VMIN`: nix's enum
        // normalizes the linux-sparc64 quirk where `VMIN == VEOF`.
        // Free portability insurance; same value everywhere else.
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;

        // TCSANOW: apply immediately, nothing to drain yet.
        termios::tcsetattr(fd, SetArg::TCSANOW, &raw)?;

        // Alt screen + cursor AFTER tcsetattr: if that had failed
        // we'd return with nothing to undo. `print!` per struct doc.
        print!("{ALT_SCREEN_ENTER}{CURSOR_HIDE}");
        io::stdout().flush()?;

        Ok(Self { original })
    }

    /// Temporarily restore cooked mode, run `f`, re-enter raw.
    /// Used for the `'s'` key prompt (`read_line` + parse).
    ///
    /// Stays on alt screen; cursor shown so the user sees where
    /// they're typing.
    ///
    /// # Errors
    /// `tcsetattr` failure or `f`'s errors propagate. The re-raw
    /// `tcsetattr` is best-effort (Drop will try again).
    pub fn with_cooked<T>(
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

        // ─── Re-raw (best-effort; same flags as enter())
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

// getch_timeout — poll + read

/// `timeout(delay)` + `getch()`: poll stdin with a deadline,
/// return `None` on timeout, `Some(byte)` on key.
///
/// **No keycode decoding.** Arrow keys arrive as 3 separate
/// `Some` returns (`ESC`, `[`, `A`); `top` only binds single
/// ASCII keys so the switch no-ops them. Harmless.
///
/// **EOF → `Some(b'q')`.** Returning `None` would spin (poll
/// says readable, read says 0, repeat); mapping to `'q'` fires
/// the existing quit path.
///
/// # Errors
/// Real I/O errors on stdin. EINTR maps to `None` (treated as
/// timeout — next tick redraws, e.g. after SIGWINCH).
pub fn getch_timeout(ms: u16) -> io::Result<Option<u8>> {
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
            // `unistd::read` on the raw fd, NOT `Stdin::read`:
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
