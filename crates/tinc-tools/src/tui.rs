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
use std::os::unix::io::{AsFd, AsRawFd};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::termios::{self, LocalFlags, SetArg, SpecialCharacterIndices, Termios};
use nix::unistd;

// Escape sequences — ANSI X3.64 / ECMA-48
//
// CSI is `ESC [`, written `\x1b[`. SGR (Select Graphic Rendition)
// is `CSI Ps m` where Ps is the parameter. The five SGR codes here
// are universal: every terminal since the VT100 understands them.

/// `CSI 2 J` — erase entire screen.
///
/// NOT `CSI H CSI 2J` (home + clear) — `goto(0,0)` is separate.
/// We have no buffer; we emit clear then redraw everything. ncurses
/// would diff and emit only changed cells, but for `top`'s 1Hz
/// refresh of ~50 rows × ~60 cols = 3KB/tick, the savings don't
/// matter.
pub const CLEAR: &str = "\x1b[2J";

/// `CSI K` — erase from cursor to end of line. Used for
/// "reverse-video the rest of the line": `REVERSE` + `CLEAR_EOL`
/// (the cleared cells take the current SGR). Same as what curses
/// emits for `chgat(-1, A_REVERSE, ...)`.
pub const CLEAR_EOL: &str = "\x1b[K";

/// `CSI 1 m` — bold. Nodes with traffic this tick.
pub const BOLD: &str = "\x1b[1m";

/// `CSI 2 m` — faint/dim. Nodes that disappeared (`!known` — were
/// in last dump, not this one).
pub const DIM: &str = "\x1b[2m";

/// `CSI 7 m` — reverse video (swap fg/bg). The column header row;
/// looks like a "selected" bar.
pub const REVERSE: &str = "\x1b[7m";

/// `CSI 0 m` — reset all attributes. Between rows so each row's
/// attribute doesn't bleed.
pub const RESET: &str = "\x1b[0m";

/// `CSI ? 1049 h` — switch to alternate screen buffer (xterm
/// extension, universally supported). `initscr()` does this.
/// Paired with `\x1b[?1049l` to restore.
///
/// The alt screen is what makes `top` "go away cleanly" on quit:
/// the main screen's scrollback isn't trashed. `htop`, `vim`,
/// `less` all use it.
const ALT_SCREEN_ENTER: &str = "\x1b[?1049h";
const ALT_SCREEN_LEAVE: &str = "\x1b[?1049l";

/// `CSI ? 25 l` — hide cursor. `initscr()` doesn't do this, but
/// every TUI does — a blinking cursor at row 0 col 0 between
/// redraws looks broken. Paired with `\x1b[?25h` to show.
const CURSOR_HIDE: &str = "\x1b[?25l";
const CURSOR_SHOW: &str = "\x1b[?25h";

/// `CSI {row} ; {col} H` — cursor position. 1-indexed (the VT100
/// inheritance). `mvprintw(r, c, ...)` is this then printf.
///
/// Returns a `String` because the caller `write!`s it inline.
/// The alloc is once-per-row at 1Hz.
///
/// Args are 0-indexed (top-left is `(0,0)`); we add 1 for the
/// escape.
#[must_use]
pub fn goto(row: u16, col: u16) -> String {
    format!("\x1b[{};{}H", row + 1, col + 1)
}

// winsize — TIOCGWINSZ

/// Terminal dimensions. Needed to clip the data-row loop — curses
/// no-ops `mvprintw` past `LINES`; for us it'd write past the
/// visible area and the terminal would scroll. Explicit clip.
#[derive(Debug, Clone, Copy)]
pub struct Winsize {
    pub rows: u16,
    pub cols: u16,
}

/// `TIOCGWINSZ` on stdout. Falls back to 24×80 if stdout isn't
/// a tty (which shouldn't happen — `RawMode::enter` already
/// failed) or the ioctl fails (which means a kernel from before
/// 1985).
///
/// `nix::ioctl_read_bad!` generates an `unsafe fn` (because ioctl
/// is variadic at the C level — `nix` can't prove the third arg
/// type matches the request). We need ONE more `#[allow(unsafe_
/// code)]` for it. Same justification as `localtime_r`: `nix` did
/// the heavy lifting (the `ioctl_read_bad!` macro IS the safe-
/// usage pattern), the unsafe is the FFI calling convention not
/// the logic.
#[allow(unsafe_code)]
#[must_use]
pub fn winsize() -> Winsize {
    // `libc::winsize` is `{ ws_row: u16, ws_col: u16, ws_xpixel:
    // u16, ws_ypixel: u16 }` on every Unix. The macro generates
    // `unsafe fn tiocgwinsz(fd, *mut winsize) -> nix::Result<i32>`.
    //
    // `clippy::items_after_statements`: the `ioctl_read_bad!`
    // expansion is a fn item, but it lives next to its only call.
    // Hoisting to module scope would put a one-use ioctl 100
    // lines from where it's understood. Same reasoning as info.rs's
    // mid-function `const PROT_MAJOR`.
    #[allow(clippy::items_after_statements)] // one-use ioctl: hoisting puts it 100 lines from its call
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
    //     memory of the right size. Same as `localtime_r`'s tm.
    //   - `TIOCGWINSZ` reads no memory from us, writes the struct.
    //     The macro picked `_IOR` direction, kernel agrees.
    //   - Thread-safe: the ioctl is on the FD, not on global state.
    //     SIGWINCH races (resize between this call and the next
    //     redraw) → we draw at the old size for one tick. Harmless.
    // `&raw mut ws` not `&mut ws`: same `borrow_as_ptr` lint as
    // info.rs's `localtime_r` shim. The ioctl macro takes `*mut T`;
    // `&mut ws` auto-coerces, `&raw mut` is the explicit form. (The
    // macro signature is `unsafe fn(fd, *mut winsize)`.) Same machine
    // code; clearer that no Rust borrow ever exists.
    let ok = unsafe { ioctl::tiocgwinsz(libc::STDOUT_FILENO, &raw mut ws) };

    match ok {
        // 0×0 means "the tty doesn't know" (some serial consoles).
        // Fall through to default.
        Ok(_) if ws.ws_row > 0 && ws.ws_col > 0 => Winsize {
            rows: ws.ws_row,
            cols: ws.ws_col,
        },
        // Not a tty, or ancient kernel, or 0×0. The VT100 default.
        // `top` will draw 21 data rows and clip nothing — likely
        // wrong, but better than crashing. Never happens in
        // practice (RawMode::enter already verified isatty).
        _ => Winsize { rows: 24, cols: 80 },
    }
}

// RawMode — RAII termios restore

/// `initscr()` + `endwin()` as a Drop guard. The point of RAII
/// here is **panic safety**: if `top`'s loop panics (parse error,
/// integer overflow in the rate math, whatever), Drop fires during
/// unwind and the terminal is restored. Without it, the user's
/// shell is left in raw mode — no echo, no line buffering, every
/// keystroke goes straight to the next process. The fix is `stty
/// sane`, but the user shouldn't have to know that.
///
/// Ctrl-C → SIGINT → process death → kernel doesn't restore
/// termios. KNOWN GAP. The fix is a `signal_hook` SIGINT handler
/// that drops the guard; deferred until someone Ctrl-C's it and
/// complains.
///
/// Field order matters for Drop: `original` is restored, `_stdout`
/// is just to prove we held a handle (we don't actually use it
/// after enter — writes go through `io::stdout()` fresh each time
/// because `StdoutLock` would prevent the cooked-mode `read_line`).
pub struct RawMode {
    /// The termios as it was before we touched it. Drop restores.
    original: Termios,
}

impl RawMode {
    /// Enter raw mode + alt screen + hide cursor. Everything
    /// `initscr()` does, minus the terminfo dance (we're hardcoded
    /// ANSI).
    ///
    /// "Raw mode" specifically means: no echo (`ECHO` off — typed
    /// chars don't print), no canonical mode (`ICANON` off — `read`
    /// returns per-byte, not per-line), no signals (`ISIG` off —
    /// Ctrl-C is just byte 0x03, not SIGINT). The last one is why
    /// `top.c` has `case 'q'` not a SIGINT handler.
    ///
    /// `nix::termios::cfmakeraw` would set MORE flags (the full
    /// POSIX raw — `IXON` off, `OPOST` off, etc.). We only need
    /// the three. `OPOST` off would stop `\n` → `\r\n` translation;
    /// keeping it on means the rest of the program's output works
    /// normally if it sneaks through.
    ///
    /// # Errors
    /// Stdin isn't a tty (piped, redirected). Caller maps to
    /// `CmdError`.
    pub fn enter() -> io::Result<Self> {
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        // Preflight: stdin a tty? `tcgetattr` would fail with
        // ENOTTY anyway, but "stdin is not a terminal" is a better
        // user message than "Inappropriate ioctl for device".
        //
        // `nix::Errno` → `io::Error` via `From` (`errno.rs:183`
        // in nix 0.29: `impl From<Errno> for io::Error { from_raw_
        // os_error(err as i32) }`). Bare `?` does the conversion;
        // no manual `.map_err(|e| from_raw_os_error(e as i32))`.
        // Found by grepping nix's source after writing the
        // boilerplate four times — the impl is always-on (not
        // feature-gated). The `Errno as i32` cast lives in nix
        // where the repr is known; on our side it'd trip
        // `clippy::cast_possible_truncation`.
        if !unistd::isatty(fd.as_raw_fd())? {
            return Err(io::Error::other("stdin is not a terminal"));
        }

        // Snapshot BEFORE mutation. tcgetattr after isatty can't
        // fail with ENOTTY (we checked), but EBADF is still
        // possible if something weird closed the fd between calls.
        let original = termios::tcgetattr(fd)?;

        // ─── Mutate
        let mut raw = original.clone();
        raw.local_flags &= !(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG);
        // `VMIN=1, VTIME=0`: `read()` blocks until 1 byte. We don't
        // actually use blocking read (poll() does the timeout), but
        // setting these makes the semantics explicit. Without them,
        // ICANON-off `read` behavior depends on whatever VMIN/VTIME
        // were before (probably 1/0, the usual default, but).
        //
        // `SpecialCharacterIndices` not `libc::VMIN`: nix's enum
        // normalizes the linux-sparc64 quirk where `VMIN == VEOF`
        // (`termios.rs:459` in nix 0.29: `pub const VMIN: SCI =
        // SCI::VEOF` on those targets). The `as usize` cast is what
        // nix's own examples use (`termios.rs:29`). On every other
        // Unix the enum and `libc::VMIN` are the same value; the
        // enum is free portability insurance.
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;

        // `TCSANOW`: apply immediately. (`TCSADRAIN` would wait for
        // output to flush — we haven't written anything yet.)
        termios::tcsetattr(fd, SetArg::TCSANOW, &raw)?;

        // ─── Alt screen + cursor
        // AFTER tcsetattr succeeds: if it had failed, we'd return
        // without an alt-screen-enter to undo. Ordering matters for
        // partial-failure cleanliness.
        //
        // `print!` not `write!(stdout, ...)`: we're not holding a
        // lock (see struct doc — cooked-mode read_line needs it).
        // The `print!` macros lock per-call. For 1Hz that's fine.
        print!("{ALT_SCREEN_ENTER}{CURSOR_HIDE}");
        io::stdout().flush()?;

        Ok(Self { original })
    }

    /// Temporarily restore cooked mode, run `f`, re-enter raw.
    /// Used for the `'s'` key prompt: restore termios, `read_line`,
    /// re-raw.
    ///
    /// Stays on alt screen — the prompt appears AT the cursor
    /// position. Cursor shown for the duration so the user sees
    /// where they're typing.
    ///
    /// `f` gets a `BufRead` over stdin. Caller does `read_line`
    /// + `.trim().parse::<f32>()` (or whatever).
    ///
    /// # Errors
    /// `tcsetattr` failure (unlikely — it worked once). `f`'s
    /// errors propagate. The re-raw `tcsetattr` failure is
    /// suppressed (best-effort — we're already past the point
    /// where bailing helps; Drop will try again).
    pub fn with_cooked<T>(
        &self,
        f: impl FnOnce(&mut dyn io::BufRead) -> io::Result<T>,
    ) -> io::Result<T> {
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        // ─── Restore cooked
        // Show cursor BEFORE tcsetattr: if the user starts typing
        // immediately, ECHO is back on and they see their input.
        print!("{CURSOR_SHOW}");
        io::stdout().flush()?;
        termios::tcsetattr(fd, SetArg::TCSANOW, &self.original)?;

        // ─── Call
        // `stdin.lock()` for BufRead. The lock is held for `f`'s
        // duration only — released before we re-raw.
        let result = f(&mut stdin.lock());

        // ─── Re-raw
        // Best-effort. Same flags as `enter()`. We DON'T re-snapshot
        // `original` (it's still the original-original; nothing
        // changed it). If this fails, Drop will try the same thing.
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
    /// Leave alt screen, show cursor, restore termios. In that order: if termios restore fails
    /// (it won't — `tcsetattr` to a valid `Termios` on a valid
    /// fd doesn't fail), the user at least sees their cursor and
    /// their scrollback.
    ///
    /// Best-effort: errors swallowed. Drop can't return Result,
    /// and what would the caller do anyway? The terminal is as
    /// fixed as it's going to get.
    fn drop(&mut self) {
        // Leave alt screen first: the user sees their old screen
        // restored even if everything else fails.
        print!("{ALT_SCREEN_LEAVE}{CURSOR_SHOW}{RESET}");
        let _ = io::stdout().flush();
        let _ = termios::tcsetattr(io::stdin().as_fd(), SetArg::TCSANOW, &self.original);
    }
}

// getch_timeout — poll + read

/// `timeout(delay)` + `getch()`: poll stdin with a deadline,
/// return `None` on timeout, `Some(byte)` on key.
///
/// **No keycode decoding.** Curses turns `\x1b[A` (up arrow,
/// 3 bytes) into `KEY_UP` (one int). We don't — `top` only has
/// single-byte ASCII keys. Arrow keys would come through as ESC
/// then `[` then `A`, three separate `Some` returns, and the
/// switch would no-op all three. Harmless. If a future command
/// needs arrows, that's a state machine here.
///
/// **EOF (`read` returns 0) → `Some(b'q')`.** Stdin closed mid-
/// `top` (the tty went away, or someone piped EOF in). The right
/// answer is "quit cleanly". Returning `None` would make the
/// loop spin (poll says readable, read says 0, repeat). Mapping
/// to `'q'` makes the existing quit case fire.
///
/// # Errors
/// I/O errors on stdin (fd closed under us, etc.). EINTR is NOT
/// an error — mapped to `None` (treated as timeout; one missed
/// tick on SIGWINCH, the loop redraws).
pub fn getch_timeout(ms: u16) -> io::Result<Option<u8>> {
    let stdin = io::stdin();
    let fd = stdin.as_fd();

    // `PollFd` borrows the fd for the duration. `POLLIN`: readable.
    let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];

    // ─── poll
    // `PollTimeout::from(ms)` — nix wraps the `int timeout` arg.
    // 0 means "don't block" (immediate); -1 means "forever" (we
    // never want that — `top`'s minimum delay is 100ms). u16 max
    // is 65535ms = ~65s, plenty.
    match poll(&mut fds, PollTimeout::from(ms)) {
        // 0 fds ready → timeout. The `getch() == ERR` case.
        //
        // OR: EINTR on poll itself — SIGWINCH between `redraw()`
        // and here. Treat as timeout: one missed tick on resize,
        // the loop redraws at the new size next iteration.
        //
        // (Different MEANINGS, same RESPONSE. `clippy::match_same_
        // arms` saw two arms with identical bodies; the or-pattern
        // makes the structural sameness explicit while the comments
        // keep the semantic difference. The earlier draft had them
        // separate — the prose earned its keep but the lint is
        // pedantic-level enforced.)
        Ok(0) | Err(nix::errno::Errno::EINTR) => Ok(None),

        // ≥1 ready → readable. Go read.
        Ok(_) => {
            // ─── read
            // poll said POLLIN; read won't block. ICANON is off
            // (raw mode); read returns per-byte. 1-byte buffer.
            //
            // `nix::unistd::read(RawFd, &mut [u8])` direct. NOT
            // `Stdin::read` — that goes through std's `BufReader`
            // machinery, which buffers. After `with_cooked`'s
            // `read_line` the buffer might have stale bytes (the
            // newline that ended the line, plus whatever the user
            // typed after). Reading the raw fd bypasses that.
            //
            // (Earlier draft had a `PipeRead` extension trait
            // wrapping this. Deleted: `unistd::read` is already
            // the safe wrapper — takes `RawFd` + `&mut [u8]`, the
            // `unsafe { libc::read }` is inside nix. The trait was
            // a wrapper around a wrapper.)
            let mut c = [0u8; 1];
            match unistd::read(stdin.as_raw_fd(), &mut c) {
                // 1 byte. The key.
                Ok(1) => Ok(Some(c[0])),
                // 0 bytes: EOF. Map to quit (see doc).
                Ok(0) => Ok(Some(b'q')),
                // >1: impossible (1-byte buffer).
                Ok(_) => unreachable!("read into 1-byte buffer"),
                // EINTR mid-read: SIGWINCH, probably. Treat as
                // timeout — next tick redraws at new size. Match
                // `Errno::EINTR` directly (nix gives the typed
                // errno; `e.kind() == Interrupted` would need an
                // `io::Error` conversion first).
                Err(nix::errno::Errno::EINTR) => Ok(None),
                // `io::Error::from` not `.into()`: the outer match
                // arm at the bottom also uses `.into()`, and with
                // two unanchored conversions in the chain inference
                // can't see through to the function signature
                // (E0282). One explicit `From::from` at the leaf
                // anchors both. (`From<Errno> for io::Error` is
                // nix's impl either way.)
                Err(e) => Err(io::Error::from(e)),
            }
        }

        // Anything else → io::Error via `From<Errno>` (nix's
        // `errno.rs:183`). `.into()` not the manual `from_raw_os_
        // error(e as i32)` — nix's impl does exactly that, but the
        // `Errno as i32` cast lives in nix where the repr is known.
        Err(e) => Err(e.into()),
    }
}

// Tests
//
// What's testable here: `goto()`'s 0→1 index arithmetic. What
// isn't: anything touching the tty (RawMode, getch_timeout,
// winsize). `cargo test` doesn't have a tty; `tcgetattr(stdin)`
// returns ENOTTY. Those get manual smoke via `tinc top` against
// a real daemon.

#[cfg(test)]
mod tests {
    use super::*;

    /// `goto(0,0)` → `\x1b[1;1H`. The 0-indexed → 1-indexed
    /// adjustment (VT100 escape sequences are 1-indexed).
    #[test]
    fn goto_adjusts_to_one_indexed() {
        assert_eq!(goto(0, 0), "\x1b[1;1H");
        assert_eq!(goto(2, 0), "\x1b[3;1H");
        assert_eq!(goto(24, 79), "\x1b[25;80H"); // bottom-right of 25×80
    }
}
