//! Streaming control commands: `log` and `pcap`.
//!
//! C: `tincctl.c:590-669` (`pcap()`, `log_control()`).
//!
//! Both commands subscribe-and-loop-forever:
//!
//! ```text
//!   client → daemon:  "18 N <args>\n"      (subscribe)
//!   daemon → client:  "18 N <len>\n"       (header, per-event)
//!                     <len raw bytes>      (data, no \n after)
//!                     ... repeats until client disconnects
//! ```
//!
//! Unlike `dump`, these are PUSHES with no terminator. The daemon
//! sets `c->status.log = true` (`control.c:137`); every `logger()`
//! call thereafter `send_request`s to subscribers (`logger.c:213`).
//! The CLI loops until daemon EOF or Ctrl-C.
//!
//! ## The wire shape (recvdata vs recvline)
//!
//! Daemon-side:
//!
//! ```text
//!   logger.c:213:  send_request(c, "%d %d %lu", CONTROL, REQ_LOG, len);
//!   logger.c:214:  send_meta(c, pretty, msglen);
//!
//!   route.c:1124:  send_request(c, "%d %d %d", CONTROL, REQ_PCAP, len);
//!   route.c:1125:  send_meta(c, DATA(packet), len);
//! ```
//!
//! `send_request` is line-framed (printf + `\n`). `send_meta` is
//! raw bytes, NO `\n`. The data IS arbitrary bytes — pcap data is
//! Ethernet frames, log data may have embedded `\n`s (if the log
//! message itself does — rare, but `logger.c` doesn't filter). So:
//!
//!   - Parse the header with `recv_line` (line-framed)
//!   - Read the data with `recv_data` (length-framed, raw bytes)
//!
//! The C `recvdata` (`tincctl.c:536`) does the second. It shares
//! the buffer with `recvline` because `recvline`'s `recv()` might
//! over-read past the `\n` into the start of the data block. See
//! `ctl.rs`'s `CtlSocket` doc-comment for why `BufReader` is that
//! shared buffer.
//!
//! ## The SIGINT handler — NOT ported
//!
//! C `tincctl.c:1533-1541` installs a SIGINT handler that
//! `shutdown(fd, SHUT_RDWR)`s so the loop exits cleanly with code 0
//! instead of 130. NOT ported: the daemon doesn't care (kernel
//! closes the socket either way, connection-reaper handles it),
//! `tinc log` is interactive so nobody checks `$?`, and the static-fd
//! signal-handler dance has hairy failure modes. Exit codes for
//! streaming commands aren't a contract.
//!
//! ## pcap headers: native-endian
//!
//! `tincctl.c:594-616` writes pcap headers via `fwrite(&struct)` —
//! native-endian. This is by design: libpcap's magic `0xa1b2c3d4`
//! is the endianness marker, readers byte-swap as needed. We use
//! `to_ne_bytes()` per-field to match. The C structs are all-u32
//! (no padding); we write field-by-field so no padding question.

#![allow(clippy::doc_markdown)]

use std::io::{Read, Write};
use std::time::SystemTime;

use crate::ctl::{CtlError, CtlRequest, CtlSocket};
use crate::names::Paths;

use super::CmdError;

// Shared header parse + size limits

/// Max log line. `tincctl.c:651`: `char data[1024]`. Daemon-side
/// `pretty[1024]` in `logger.c` (the format buffer). Log lines that
/// somehow exceed this would be silently truncated by the daemon's
/// `snprintf`; we'd never see len>1024 on the wire. The check is
/// defense against a buggy daemon, same as the C.
const LOG_DATA_MAX: usize = 1024;

/// Max packet capture. `tincctl.c:592`: `char data[9018]`. 9000-byte
/// jumbo MTU + Ethernet header (14) + a few for slop. Daemon-side
/// `vpn_packet_t` is `MAXSIZE` (9018, `net.h`). The check is the
/// SAME defense — a daemon bug saying len=2^32 would alloc 4GiB
/// without this. The C protects a stack buffer; we protect the
/// heap-alloc.
const PCAP_DATA_MAX: usize = 9018;

/// Parse `"18 N len"` header. The shared header shape for both
/// streams. `tincctl.c:656`, `629`: `sscanf("%d %d %d")` then
/// `code != CONTROL || req != REQ_X` checks.
///
/// Returns `Some(len)` if header is well-formed and the request
/// type matches. `None` for malformed or wrong type — the caller
/// breaks. (The C `tincctl.c:658-660`: `n != 3 || code != ... →
/// break`. SILENT exit.)
///
/// `kind`: which stream. `CtlRequest::Log` or `::Pcap`. The header
/// echoes the subscription type — a `REQ_LOG` subscriber sees
/// `"18 15 N"` headers, a `REQ_PCAP` subscriber sees `"18 14 N"`.
/// Why check it: the daemon's connection mux means a bug COULD
/// cross-send. Unlikely; defense.
///
/// `max`: per-stream size limit. `len > max → None`. The C
/// inlines this in the same `if` (`len > sizeof(data)`).
///
/// `len < 0 → None` for log (`tincctl.c:658`: `len < 0 || ... >
/// sizeof(data)`); pcap uses `%lu` (unsigned, `:629`). We parse as
/// `usize` for both — `parse::<usize>()` rejects negative AND the
/// `%lu` overflow case. The pcap `%lu` vs log `%d` is a C-ism
/// (printf format-string type-safety theatre); the WIRE is ASCII
/// digits either way.
fn parse_header(line: &str, kind: CtlRequest, max: usize) -> Option<usize> {
    // `"18 15 7"`. Three space-separated ints.
    let mut it = line.split(' ');
    let code = it.next()?;
    let req = it.next()?;
    let len = it.next()?;
    // No `it.next().is_none()` check — `sscanf("%d %d %d")` ignores
    // trailing. The daemon won't send any (`logger.c:213` is exactly
    // `"%d %d %lu"`), but match the C's slack.

    // `tincctl.c:658`: `code != CONTROL`. CONTROL = 18.
    if code != "18" {
        return None;
    }
    // `req != REQ_LOG`. Compare as ASCII (the wire is ASCII).
    // `kind as u8 → string`: 15 → "15" or 14 → "14". A formatted
    // const would be a compile-time `format!` (which doesn't exist).
    // Per-call alloc is fine; this runs once per log line, the
    // syscall to read the line dominates.
    //
    // (Can't use `parse + ==` because `req as i32` would compare
    // `15i32 == 15i32` but require parsing. The string compare
    // skips a parse; both correct.)
    if req != (kind as u8).to_string() {
        return None;
    }
    // `%d` / `%lu` → usize. Rejects negative and too-large.
    let len: usize = len.parse().ok()?;
    if len > max {
        return None;
    }
    Some(len)
}

// `tinc log [LEVEL]` — stream daemon's logger() output
//
// `tincctl.c:649-669`. Subscribe with `(level, use_color)`, then
// loop: header, data, write data + `\n` to stdout.
//
// `level` is the FILTER, not the daemon's debug level. The daemon
// CLAMPs it (`control.c:136`) into `c->log_level`, and `logger.c
// :205` checks `level > c->log_level → continue` per-connection.
// `-1` (`DEBUG_UNSET`) means "use the daemon's own debug level".
// Higher numbers = more verbose.
//
// `use_color`: pass-through to the daemon's `format_pretty`.
// `console.c:5-11`: `isatty(fileno(out)) && getenv("TERM") &&
// strcmp(TERM, "dumb")`. Per-subscriber: the daemon formats the
// SAME log line both colored and uncolored if it has subscribers
// of both kinds. (`logger.c:209`.)

/// `DEBUG_UNSET`. `logger.h:27`. The "use daemon's level" sentinel.
/// `tincctl.c:1559`: `argc > 1 ? atoi(argv[1]) : DEBUG_UNSET`.
const DEBUG_UNSET: i32 = -1;

/// `console.c:5-11` for stdout.
///
/// ```text
///   bool is_tty = isatty(fileno(out));
///   const char *term = getenv("TERM");
///   return is_tty && term && strcmp(term, "dumb");
/// ```
///
/// Three checks: stdout IS a tty, TERM is set, TERM isn't `"dumb"`.
/// `strcmp(term, "dumb")` returns 0 (false) on match — so the C
/// reads "TERM != dumb". The double negative is C-idiomatic;
/// our `!=` is the same thing.
///
/// `tincctl.c:1559` calls this for STDOUT specifically (`log_control
/// (fd, stdout, ...)`). Hard-coded stdout. The daemon writes
/// log lines to OUR stdout via the socket; if we're piped
/// (`tinc log | less`), color escapes look like garbage in less
/// without `-R`. `isatty(stdout)` is false then → no color.
///
/// Why not check `NO_COLOR` env var (the modern convention): the C
/// doesn't. `tinc log | tee` users who want color can `tinc log
/// 2>&1 | tee` no wait that doesn't work either. `script -c "tinc
/// log"` is the answer (PTY in between). Same as every isatty-gated
/// colorizer.
fn use_ansi_escapes_stdout() -> bool {
    // `isatty(STDOUT_FILENO)`. `std::io::IsTerminal` is the Rust
    // 1.70+ way. (`nix::unistd::isatty` works too but takes RawFd
    // and we'd `as_raw_fd()`; std's trait is cleaner.)
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return false;
    }
    // `getenv("TERM")`. Empty string is "set" in the C sense
    // (`getenv` returns non-NULL for `TERM=`). `env::var` returns
    // `Ok("")` for that, which is `!= "dumb"`, so colors on. Same
    // as the C: `term && strcmp(term, "dumb")` — `term` is non-NULL
    // (truthy), `strcmp("", "dumb")` is nonzero (truthy). Colors on.
    // Probably wrong (TERM= means "no terminfo"), but C-compat.
    match std::env::var("TERM") {
        Ok(term) => term != "dumb",
        Err(_) => false, // unset, or non-UTF-8 (unlikely)
    }
}

/// The main loop. `tincctl.c:649-669`. Generic over the output
/// `Write` so the test can pass a `Vec`. Production passes stdout's
/// lock.
///
/// `level`: the filter. `None` → `DEBUG_UNSET` (-1). `Some(n)` →
/// the user's `tinc log 5`. The daemon CLAMPs out-of-range, so we
/// don't validate.
///
/// `use_color`: precomputed by the caller (it's an isatty check on
/// stdout, which the caller has). Passed in so the test doesn't
/// fight with stdout's tty-ness.
///
/// Runs forever. Returns when:
///   - daemon closes socket (`recv_line → None`): `Ok(())`, clean
///   - I/O error mid-read: `Err(CtlError::Io(_))`
///   - malformed header: `Ok(())`, clean (the C breaks silently)
///
/// The clean-on-malformed is `tincctl.c:660`: `break;`. No message.
/// Daemon's broken; user sees the prompt again.
///
/// # Errors
/// Socket I/O. The output Write's errors too — `tinc log | head`
/// closes stdout after 10 lines, our `out.write_all()` gets EPIPE,
/// we bubble it up. The binary's SIGPIPE-ignore means we DON'T die
/// on the signal; we get the error and exit. (See the SIGPIPE
/// section in the binary's main.)
pub fn log_loop<S, W>(
    ctl: &mut CtlSocket<S>,
    out: &mut W,
    level: Option<i32>,
    use_color: bool,
) -> Result<(), CtlError>
where
    S: Read + Write,
    W: Write,
{
    // ─── Subscribe
    // `tincctl.c:649`: `sendline(fd, "%d %d %d %d", CONTROL, REQ_
    // LOG, level, use_color)`. Daemon's `control.c:135` `sscanf
    // (%*d %*d %d %d)` reads both. The bool prints as 0/1; the
    // daemon reads as int and treats nonzero as true (`c->status.
    // log_color = colorize` then later `c->status.log_color` as
    // a bool). `i32::from(bool)` is 0/1.
    ctl.send_int2(
        CtlRequest::Log,
        level.unwrap_or(DEBUG_UNSET),
        i32::from(use_color),
    )?;

    // ─── Receive loop
    // `tincctl.c:653-669`. Reused buffer; `clear` + `resize`
    // per-iteration. The C uses a stack `char[1024]`; we heap
    // (resize doesn't shrink capacity, so after the first message
    // we never re-alloc).
    //
    // `with_capacity` for the FIRST message: pre-size to max so
    // even the first iteration doesn't grow. Log lines are usually
    // <200 bytes; 1024 is plenty and matches the C buffer.
    let mut buf: Vec<u8> = Vec::with_capacity(LOG_DATA_MAX);

    // `while(recvline(...))`. `recv_line → Some` is the C's `true`.
    // `None` is EOF (daemon closed) — `Ok(())` clean exit.
    while let Some(line) = ctl.recv_line()? {
        // Parse header. Malformed → break (silent, C-compat).
        let Some(len) = parse_header(&line, CtlRequest::Log, LOG_DATA_MAX) else {
            break;
        };

        // `tincctl.c:662`: `recvdata(fd, data, len)`. Exactly `len`
        // raw bytes after the header line. `resize` (NOT `reserve`)
        // because `recv_data` writes into `&mut [u8]` — we need
        // initialized length, not just capacity.
        //
        // `resize(len, 0)`: fills new positions with 0. Those
        // zeroes get OVERWRITTEN by `recv_data`. The init is
        // wasted work. There's no safe resize-uninit (`set_len`
        // would do it but `unsafe` for a 1024-byte memset is
        // silly). The memset is one cache line; the syscall
        // dominates by 10000×.
        buf.clear();
        buf.resize(len, 0);
        // `if(!recvdata) break`. Mid-data EOF → silent exit.
        // (`tincctl.c:664`.) `recv_data` returns `Err` on short
        // read; we bubble it (slightly noisier than C, but the
        // daemon dying mid-stream is rare and a message helps).
        ctl.recv_data(&mut buf)?;

        // `tincctl.c:666-668`: `fwrite(data, len, 1, out); fputc
        // ('\n', out); fflush(out);`. The data is the FORMATTED
        // log line (priority prefix, timestamp, message). It
        // doesn't include a trailing `\n` — `format_pretty`
        // doesn't add one, `send_meta` doesn't add one. We add
        // it. Then flush (line-buffered output for interactive
        // viewing).
        //
        // `write_all` not `write`: partial writes happen (pipe
        // full); `write_all` retries. The C's `fwrite` does the
        // same internally.
        //
        // EPIPE: the binary's `signal(SIGPIPE, SIG_IGN)` means we
        // get the error not the signal. Bubble it; main exits.
        out.write_all(&buf).map_err(CtlError::Io)?;
        out.write_all(b"\n").map_err(CtlError::Io)?;
        out.flush().map_err(CtlError::Io)?;
    }

    Ok(())
}

/// CLI entry: `tinc log [LEVEL]`. `tincctl.c:1544-1567`.
///
/// `LEVEL` is `atoi`'d in C (`:1559`). `atoi("garbage")` is 0
/// (silently). We use `parse::<i32>()` which errors. STRICTER
/// than C, but `tinc log abc` succeeding-with-level-0 is a footgun.
/// The change is observable but only for invalid input.
///
/// The SIGINT handler is NOT here (see module doc). Ctrl-C kills
/// the process; exit 130. Daemon doesn't care.
///
/// # Errors
/// Daemon down (`connect`), socket I/O, EPIPE (`tinc log | head`).
#[cfg(unix)]
pub fn run_log(paths: &Paths, level: Option<i32>) -> Result<(), CmdError> {
    let mut ctl = CtlSocket::connect(paths).map_err(|e| CmdError::BadInput(e.to_string()))?;

    // `use_ansi_escapes(stdout)` — checked HERE not inside `log_
    // loop` so the test can pass a fixed bool. Production: stdout's
    // tty-ness.
    let use_color = use_ansi_escapes_stdout();

    // `stdout().lock()` for the duration. The loop flushes per-line
    // anyway, but the lock avoids per-write mutex contention with
    // any background thread that might println (there are none, but
    // the lock is free and idiomatic).
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    log_loop(&mut ctl, &mut out, level, use_color).map_err(|e| CmdError::BadInput(e.to_string()))
}

// `tinc pcap [SNAPLEN]` — stream packet capture in libpcap format
//
// `tincctl.c:590-645`. Subscribe with `snaplen`, write the libpcap
// global header, then loop: tinc header, data, libpcap packet
// header + data to stdout.
//
// `snaplen`: max bytes per packet to capture. 0 = full packet.
// Daemon clips (`route.c:1120`: `if(c->outmaclength && c->
// outmaclength < len) len = c->outmaclength`). The repurposed
// `outmaclength` field is a hack — it was the legacy MAC length,
// reused for pcap snaplen because every connection has it and
// pcap subscribers don't use legacy crypto.
//
// Output is the libpcap "savefile" format (the original, not
// pcapng). Magic `0xa1b2c3d4`, version 2.4, link-type 1
// (Ethernet). Wireshark, tcpdump -r, every analyzer reads it.
//
// `tinc pcap | wireshark -k -i -` is the use case. Real-time
// packet view of the VPN traffic. The daemon hands us raw Ethernet
// frames (the same `vpn_packet_t` the routing engine sees,
// `route.c:1125`).

/// Libpcap global header. 24 bytes. `tincctl.c:594-608`.
///
/// Field-by-field `to_ne_bytes()` rather than a `#[repr(C)]`
/// struct + `bytemuck::bytes_of` (or unsafe `std::slice::from_raw_
/// parts`). The C does `fwrite(&struct)` which is native-endian
/// padded layout. Our struct WOULD have the same layout (all-u32 +
/// two u16, no padding holes), but per-field bytes is `forbid(
/// unsafe)`-compliant and the once-per-session 24-byte write
/// isn't perf-critical.
///
/// `snaplen`: from the user. 0 → defaults to PCAP_DATA_MAX (9018).
/// `tincctl.c:606`: `snaplen ? snaplen : sizeof(data)`. The header
/// records what the file PROMISES; the daemon enforces it.
///
/// Returns the 24 header bytes ready to write.
fn pcap_global_header(snaplen: u32) -> [u8; 24] {
    // C's struct, in declaration order:
    //   uint32_t magic       = 0xa1b2c3d4
    //   uint16_t major       = 2
    //   uint16_t minor       = 4
    //   uint32_t tz_offset   = 0 (always; libpcap stores UTC)
    //   uint32_t tz_accuracy = 0 (unused; legacy)
    //   uint32_t snaplen
    //   uint32_t ll_type     = 1 (LINKTYPE_ETHERNET)
    //
    // Layout: 4 + 2 + 2 + 4 + 4 + 4 + 4 = 24 bytes. No padding
    // (the two u16 pack to one u32-aligned slot). `fwrite(&struct,
    // sizeof, 1)` writes exactly this on every C compiler.
    //
    // `0xa1b2c3d4` is the standard magic. Readers detect endianness
    // by whether they see `a1b2c3d4` or `d4c3b2a1`. `to_ne_bytes`
    // writes whatever the host CPU does — same as `fwrite(&u32)`.
    let magic: u32 = 0xa1b2_c3d4;
    let major: u16 = 2;
    let minor: u16 = 4;
    let tz_offset: u32 = 0;
    let tz_accuracy: u32 = 0;
    // `tincctl.c:606`: `snaplen ? snaplen : sizeof(data)`. The C's
    // `snaplen` is from `atoi(argv[1])` so 0 means "user didn't
    // pass one OR passed 0" — both → max. `as u32` is safe:
    // PCAP_DATA_MAX (9018) fits.
    #[allow(clippy::cast_possible_truncation)] // 9018 < u32::MAX, const
    let snaplen = if snaplen == 0 {
        PCAP_DATA_MAX as u32
    } else {
        snaplen
    };
    let ll_type: u32 = 1; // LINKTYPE_ETHERNET. `pcap/dlt.h`.

    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&magic.to_ne_bytes());
    h[4..6].copy_from_slice(&major.to_ne_bytes());
    h[6..8].copy_from_slice(&minor.to_ne_bytes());
    h[8..12].copy_from_slice(&tz_offset.to_ne_bytes());
    h[12..16].copy_from_slice(&tz_accuracy.to_ne_bytes());
    h[16..20].copy_from_slice(&snaplen.to_ne_bytes());
    h[20..24].copy_from_slice(&ll_type.to_ne_bytes());
    h
}

/// Libpcap per-packet record header. 16 bytes. `tincctl.c:610-617`.
///
/// ```text
///   uint32_t tv_sec    — wall-clock seconds (gettimeofday)
///   uint32_t tv_usec   — microseconds part
///   uint32_t len       — captured bytes (after snaplen clip)
///   uint32_t origlen   — original packet length on the wire
/// ```
///
/// `len` and `origlen`: the daemon clips to `snaplen` BEFORE
/// sending (`route.c:1120`), so we receive `len` bytes and don't
/// know the original. `tincctl.c:641-642`: `packet.len = len;
/// packet.origlen = len;`. Both set to what we got. Wireshark shows
/// "X bytes captured" with no truncation marker. Slightly wrong
/// but the C does it; the daemon would have to send origlen too
/// for accuracy.
///
/// `tv_sec` is the LOW 32 bits of `time_t`. `tincctl.c:639`:
/// `packet.tv_sec = tv.tv_sec;`. On 64-bit platforms `tv.tv_sec`
/// is `i64`; the assignment to a `uint32_t` field truncates. After
/// 2038 (well, 2106 — unsigned wraps later) this rolls over.
/// Libpcap's 2038 problem; not ours. There's a microsecond-magic
/// (`0xa1b2_3c4d`) for 64-bit timestamps but the C doesn't use it.
///
/// Why we timestamp HERE (CLI-side) not daemon-side: the daemon's
/// `send_pcap` doesn't include time (`route.c:1124`: `"%d %d %d"`,
/// no timestamp field). The CLI calls `gettimeofday` per-packet
/// (`tincctl.c:628`). The timestamp is "when the CLI received it,"
/// not "when the daemon routed it." Socket latency is ~10µs
/// (localhost), well below the µs resolution. Good enough.
///
/// `clippy::similar_names`: `tv_sec`/`tv_usec` are the C struct
/// field names (`tincctl.c:614-615`). The names ARE the doc;
/// renaming breaks C-side grep. Allow at fn (the `#[allow]` on a
/// `let` doesn't cover the NEXT `let`).
#[allow(clippy::similar_names)]
fn pcap_packet_header(now: SystemTime, len: u32) -> [u8; 16] {
    // `gettimeofday(&tv, NULL)`. `SystemTime::now()` then
    // `duration_since(UNIX_EPOCH)`. Same wall-clock seconds + µs.
    //
    // `unwrap_or_default`: `duration_since` errs if `now < EPOCH`
    // (clock set to 1960). Default Duration is 0s — the timestamp
    // would be wrong but the file is still valid pcap. Better than
    // panicking on a misconfigured clock.
    let dur = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    // `as u32`: truncates. INTENTIONAL — see fn doc on the 2038
    // problem. `tv.tv_sec` is `i64` on linux x86_64; the C's
    // assignment to `uint32_t` is the same truncation.
    //
    // `subsec_micros` returns `u32` already. `tv_usec` in the C
    // is `suseconds_t` (long); the assignment to `uint32_t`
    // truncates THAT too, but `tv_usec ∈ [0, 999999]` always
    // fits. Our `subsec_micros` is the same range.
    #[allow(clippy::cast_possible_truncation)] // documented above
    let tv_sec: u32 = dur.as_secs() as u32;
    let tv_usec: u32 = dur.subsec_micros();

    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&tv_sec.to_ne_bytes());
    h[4..8].copy_from_slice(&tv_usec.to_ne_bytes());
    h[8..12].copy_from_slice(&len.to_ne_bytes());
    h[12..16].copy_from_slice(&len.to_ne_bytes()); // origlen == len
    h
}

/// The main loop. `tincctl.c:590-645`. Same `Write`-generic as
/// `log_loop`.
///
/// `snaplen`: 0 = full packet. Passed to daemon AND embedded in
/// the global header. Daemon enforces; we record.
///
/// `now`: clock function. Production passes `SystemTime::now`;
/// tests pass a fixed time. Per-packet call, not pre-loop —
/// each packet gets its OWN timestamp (`tincctl.c:628`: `gettimeofday`
/// inside the loop).
///
/// Runs forever. Same exit conditions as `log_loop`.
///
/// # Errors
/// Socket I/O, output I/O. Malformed-header is `Ok(())` clean
/// exit (`tincctl.c:631`: `break`).
pub fn pcap_loop<S, W, Clock>(
    ctl: &mut CtlSocket<S>,
    out: &mut W,
    snaplen: u32,
    mut now: Clock,
) -> Result<(), CtlError>
where
    S: Read + Write,
    W: Write,
    Clock: FnMut() -> SystemTime,
{
    // ─── Subscribe
    // `tincctl.c:591`: `sendline(fd, "%d %d %d", CONTROL, REQ_PCAP,
    // snaplen)`. Daemon's `control.c:128`: `sscanf("%*d %*d %d",
    // &c->outmaclength)`. The cast: `snaplen` is `u32`, `send_int`
    // takes `i32`. `snaplen` from user is 0 or a small number
    // (typical: 96, 1500); fits. `as i32` truncates to negative
    // for snaplen >= 2^31 (won't happen; user-supplied small int).
    // The daemon side reads `%d` (signed), so the wire is `i32`-
    // shaped anyway. `as i32` matches the wire.
    #[allow(clippy::cast_possible_wrap)] // snaplen is small; matches %d wire
    ctl.send_int(CtlRequest::Pcap, snaplen as i32)?;

    // ─── Global header
    // `tincctl.c:618-619`: `fwrite(&header, ...); fflush(out);`.
    // ONCE, before the loop. Wireshark reads this to know the
    // link-type and endianness.
    out.write_all(&pcap_global_header(snaplen))
        .map_err(CtlError::Io)?;
    out.flush().map_err(CtlError::Io)?;

    // ─── Receive loop
    // Same buffer-reuse as `log_loop`. Packets are bigger (up to
    // 9018), so the upfront capacity matters more.
    let mut buf: Vec<u8> = Vec::with_capacity(PCAP_DATA_MAX);

    while let Some(line) = ctl.recv_line()? {
        let Some(len) = parse_header(&line, CtlRequest::Pcap, PCAP_DATA_MAX) else {
            break;
        };

        // `tincctl.c:628`: `gettimeofday(&tv, NULL)`. INSIDE the
        // loop, per-packet, BEFORE the data read. The C does it
        // before `if(n != 3)` so even malformed-header packets
        // get a (wasted) gettimeofday. We do it after the `let
        // else` — the malformed case breaks anyway, who cares
        // about the wasted call. (Neither order is observably
        // different; the data hasn't arrived yet either way.)
        let ts = now();

        buf.clear();
        buf.resize(len, 0);
        ctl.recv_data(&mut buf)?;

        // `tincctl.c:639-644`: build packet header, fwrite header,
        // fwrite data, fflush. Per-packet flush so `tinc pcap |
        // wireshark -k -i -` shows packets in real-time (Wireshark
        // reads from a pipe; no flush → it sees nothing until
        // the pipe buffer fills, ~64KiB ≈ dozens of packets).
        //
        // `len as u32`: `len ≤ PCAP_DATA_MAX (9018) ≤ u32::MAX`.
        // Checked by `parse_header`.
        #[allow(clippy::cast_possible_truncation)] // len ≤ 9018 by parse_header
        let len_u32 = len as u32;
        out.write_all(&pcap_packet_header(ts, len_u32))
            .map_err(CtlError::Io)?;
        out.write_all(&buf).map_err(CtlError::Io)?;
        out.flush().map_err(CtlError::Io)?;
    }

    Ok(())
}

/// CLI entry: `tinc pcap [SNAPLEN]`. `tincctl.c:1518-1530`.
///
/// `SNAPLEN`: `atoi`'d in C. We `parse::<u32>()`. Stricter (rejects
/// negative — `atoi("-5")` is `-5` then assigned to a `uint32_t`
/// arg which wraps to a huge number; daemon then never clips).
/// `tinc pcap -5` failing is better.
///
/// # Errors
/// Same as `run_log`.
#[cfg(unix)]
pub fn run_pcap(paths: &Paths, snaplen: u32) -> Result<(), CmdError> {
    let mut ctl = CtlSocket::connect(paths).map_err(|e| CmdError::BadInput(e.to_string()))?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    pcap_loop(&mut ctl, &mut out, snaplen, SystemTime::now)
        .map_err(|e| CmdError::BadInput(e.to_string()))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;
    use std::time::Duration;

    // parse_header

    /// `parse_header` table. C `tincctl.c:629,656,658`. The two
    /// golden rows are wire-format pins; the rest are the C's
    /// `sscanf %d %d %d` failure modes + bounds checks.
    #[test]
    fn parse_header_table() {
        use CtlRequest::{Log, Pcap};
        #[rustfmt::skip]
        let cases: &[(&str, CtlRequest, usize, Option<usize>)] = &[
            //          (input,                req,   max,   expected)
            // ─── GOLDEN: `"18 15 7"` for log. `tincctl.c:656`. ───
            ("18 15 7",                Log,   1024,  Some(7)),
            // ─── GOLDEN: `"18 14 1500"` for pcap. `tincctl.c:629`. ───
            ("18 14 1500",             Pcap,  9018,  Some(1500)),
            // ─── wrong code: `code != CONTROL`. `tincctl.c:658`. ───
            ("17 15 7",                Log,   1024,  None),
            // ─── wrong req: log subscriber gets pcap header (daemon mux bug case) ───
            ("18 14 7",                Log,   1024,  None),
            ("18 15 7",                Pcap,  9018,  None),
            // ─── len boundary: `len > sizeof(data)`. max is OK, max+1 is not. ───
            ("18 15 1024",             Log,   1024,  Some(1024)),
            ("18 15 1025",             Log,   1024,  None),
            ("18 14 9018",             Pcap,  9018,  Some(9018)),
            ("18 14 9019",             Pcap,  9018,  None),
            // ─── negative len: `len < 0`. `parse::<usize>()` rejects. ───
            ("18 15 -1",               Log,   1024,  None),
            // ─── short line: `n != 3` ───
            ("18 15",                  Log,   1024,  None),
            ("18",                     Log,   1024,  None),
            ("",                       Log,   1024,  None),
            // ─── non-numeric len: `sscanf %d` fails ───
            ("18 15 abc",              Log,   1024,  None),
            // ─── trailing garbage: `sscanf("%d %d %d")` stops after 3rd int, ignores ───
            ("18 15 7 extra stuff",    Log,   1024,  Some(7)),
            // ─── len zero: valid! Zero-byte log line. Daemon won't send it
            //     (`logger.c` always has `pretty` non-empty), but wire allows. ───
            ("18 15 0",                Log,   1024,  Some(0)),
        ];
        for &(input, req, max, expected) in cases {
            assert_eq!(parse_header(input, req, max), expected, "input: {input:?}");
        }
    }

    // pcap headers — byte-exact, sed-verifiable

    /// Global header bytes on little-endian (x86_64). `tincctl.c
    /// :596-608`. Field-by-field. The `cfg(target_endian)` is
    /// because `to_ne_bytes()` differs on big-endian — the magic
    /// would be `[a1, b2, c3, d4]` there. We don't have a BE CI;
    /// LE is what every dev machine and prod box runs.
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_global_header_bytes_le() {
        let h = pcap_global_header(96);
        // Magic: 0xa1b2c3d4 LE.
        assert_eq!(&h[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // Major 2, minor 4, both u16 LE.
        assert_eq!(&h[4..6], &[2, 0]);
        assert_eq!(&h[6..8], &[4, 0]);
        // tz_offset = 0, tz_accuracy = 0.
        assert_eq!(&h[8..16], &[0; 8]);
        // Snaplen 96 LE.
        assert_eq!(&h[16..20], &[96, 0, 0, 0]);
        // ll_type = 1 (Ethernet) LE.
        assert_eq!(&h[20..24], &[1, 0, 0, 0]);
    }

    /// Snaplen 0 → defaults to 9018. `tincctl.c:606`: `snaplen ?
    /// snaplen : sizeof(data)`.
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_global_header_snaplen_zero_defaults() {
        let h = pcap_global_header(0);
        // 9018 = 0x233a. LE: 3a 23 00 00.
        assert_eq!(&h[16..20], &[0x3a, 0x23, 0, 0]);
        assert_eq!(u32::from_ne_bytes([h[16], h[17], h[18], h[19]]), 9018);
    }

    /// Packet header bytes. Fixed timestamp for determinism.
    /// `tincctl.c:639-642`.
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_packet_header_bytes_le() {
        // Epoch + 1000s + 500µs. tv_sec=1000, tv_usec=500.
        let ts = SystemTime::UNIX_EPOCH + Duration::new(1000, 500_000);
        let h = pcap_packet_header(ts, 1500);

        // tv_sec = 1000 = 0x3e8. LE.
        assert_eq!(&h[0..4], &[0xe8, 0x03, 0, 0]);
        // tv_usec = 500 = 0x1f4. LE.
        assert_eq!(&h[4..8], &[0xf4, 0x01, 0, 0]);
        // len = origlen = 1500 = 0x5dc. LE. BOTH set to the same
        // value (`tincctl.c:641-642`).
        assert_eq!(&h[8..12], &[0xdc, 0x05, 0, 0]);
        assert_eq!(&h[12..16], &[0xdc, 0x05, 0, 0]);
    }

    /// 2038 truncation: a timestamp past `u32::MAX` seconds gets
    /// the low 32 bits. `tincctl.c:639`: `packet.tv_sec = tv.tv_sec`
    /// is a `i64 → uint32_t` assignment, same truncation.
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_packet_header_y2038_truncates() {
        // `u32::MAX as u64 + 1` seconds. The high bit overflows.
        let big = u64::from(u32::MAX) + 1; // 0x1_0000_0000
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(big);
        let h = pcap_packet_header(ts, 0);
        // Low 32 bits of `0x1_0000_0000` = 0.
        assert_eq!(&h[0..4], &[0, 0, 0, 0]);
    }

    /// Clock-before-epoch (1960): `duration_since` errs, we
    /// `unwrap_or_default` to zero. The timestamp is wrong but
    /// the file is valid pcap.
    #[test]
    fn pcap_packet_header_before_epoch_is_zero() {
        // SystemTime can't actually represent before-epoch on
        // some platforms. The test of the `unwrap_or_default`
        // branch is the API contract: if `duration_since` fails,
        // we don't panic. Construct a SystemTime BEFORE epoch
        // by subtracting from epoch — works on Unix.
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let h = pcap_packet_header(before, 100);
        // tv_sec = 0, tv_usec = 0 (Duration::default()).
        assert_eq!(&h[0..8], &[0; 8]);
        // len fields still correct.
        assert_eq!(u32::from_ne_bytes([h[8], h[9], h[10], h[11]]), 100);
    }

    // log_loop / pcap_loop — fake socket, captured output
    //
    // The CtlSocket constructor needs the Rc<RefCell> dance.
    // Crate-internal: reach into ctl's internals. A test-only
    // constructor `CtlSocket::for_test(S)` would be cleaner but
    // would be `#[cfg(test)] pub fn` in another module — visible
    // to ALL test modules, used by one. Direct construction here
    // is fine; the fields are `pub(crate)` no wait let me check.

    /// Build a CtlSocket reading from `wire`. The `Cursor` is
    /// `Read+Write`; we only ever read (no `send` in these tests
    /// — the `send_int2`/`send_int` is to the SAME cursor, which
    /// would interleave with reads. The tests below DO call send
    /// (the loops do), so the cursor DOES get written to. The
    /// cursor's position advances on write; the reads then
    /// continue from there. WRONG.)
    ///
    /// Fixed: use a duplex pair. `wire_in` for daemon→client
    /// (we read), `wire_out` for client→daemon (we write,
    /// captured for assertions). The Cursor for reading; a Vec
    /// for writing.
    ///
    /// `Duplex` is a tiny adapter: Read from one, Write to other.
    struct Duplex {
        read_side: Cursor<Vec<u8>>,
        write_side: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read_side.read(buf)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_side.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn ctl_from_wire(daemon_sends: Vec<u8>) -> (CtlSocket<Duplex>, Rc<RefCell<Duplex>>) {
        let dup = Duplex {
            read_side: Cursor::new(daemon_sends),
            write_side: Vec::new(),
        };
        let shared = Rc::new(RefCell::new(dup));
        // Reach into `ctl`'s internals. The fields are private to
        // the `ctl` module — but we're in the SAME crate. The
        // path is `crate::ctl::ReadHalf`, but those types ARE
        // module-private (`struct ReadHalf<S>(...)`). So this
        // doesn't compile from here.
        //
        // The fix: a `CtlSocket::wrap` constructor that's `pub`
        // (or `pub(crate)`). The handshake/connect path stays as
        // the production constructor; `wrap` is the test seam.
        let ctl = CtlSocket::wrap(Rc::clone(&shared));
        (ctl, shared)
    }

    /// Full `log_loop`: subscribe, two records, EOF.
    ///
    /// Daemon sends:
    ///   - "18 15 5\n" + "Hello"
    ///   - "18 15 5\n" + "World"
    ///   - EOF (Cursor exhausted)
    ///
    /// Client should send: "18 15 -1 0\n" (subscribe, level=-1,
    /// color=0).
    ///
    /// Output should be: "Hello\nWorld\n" (data + \n per record).
    #[test]
    fn log_loop_two_records() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"18 15 5\nHello");
        wire.extend_from_slice(b"18 15 5\nWorld");
        // No more — EOF.

        let (mut ctl, shared) = ctl_from_wire(wire);
        let mut out = Vec::new();

        log_loop(&mut ctl, &mut out, None, false).unwrap();

        // ─── Subscription wire
        // `tincctl.c:649`. level=DEBUG_UNSET (-1), color=0.
        assert_eq!(shared.borrow().write_side, b"18 15 -1 0\n");

        // ─── Output
        // `tincctl.c:666-668`: data + '\n'. The flushes are
        // invisible in a Vec.
        assert_eq!(out, b"Hello\nWorld\n");
    }

    /// `level` parameter forwards. `tinc log 5` → "18 15 5 0\n".
    #[test]
    fn log_loop_level_forwarded() {
        let (mut ctl, shared) = ctl_from_wire(Vec::new()); // EOF immediately
        let mut out = Vec::new();

        log_loop(&mut ctl, &mut out, Some(5), false).unwrap();

        assert_eq!(shared.borrow().write_side, b"18 15 5 0\n");
        assert_eq!(out, b"");
    }

    /// `use_color=true` → fourth int is 1. `tincctl.c:649`:
    /// `use_color` printed as `%d`.
    #[test]
    fn log_loop_color_forwarded() {
        let (mut ctl, shared) = ctl_from_wire(Vec::new());
        let mut out = Vec::new();

        log_loop(&mut ctl, &mut out, None, true).unwrap();

        assert_eq!(shared.borrow().write_side, b"18 15 -1 1\n");
    }

    /// Malformed header → clean break. `tincctl.c:660`: `break;`.
    /// No error, partial output kept.
    #[test]
    fn log_loop_malformed_breaks_clean() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"18 15 5\nHello");
        // Garbage header. Loop should break HERE.
        wire.extend_from_slice(b"garbage\n");
        // This second record is never read.
        wire.extend_from_slice(b"18 15 5\nWorld");

        let (mut ctl, _) = ctl_from_wire(wire);
        let mut out = Vec::new();

        // `Ok(())` — silent exit, NOT an error.
        log_loop(&mut ctl, &mut out, None, false).unwrap();

        // First record made it. Second didn't.
        assert_eq!(out, b"Hello\n");
    }

    /// Data with embedded newline. Log lines DON'T usually have
    /// these but the format allows it (length-framed, not line-
    /// framed). The data is passed through verbatim. The added
    /// `\n` is OURS (`fputc('\n', out)`).
    #[test]
    fn log_loop_data_with_newline() {
        let mut wire = Vec::new();
        // 11 bytes: "Line1\nLine2". Embedded \n.
        wire.extend_from_slice(b"18 15 11\nLine1\nLine2");

        let (mut ctl, _) = ctl_from_wire(wire);
        let mut out = Vec::new();

        log_loop(&mut ctl, &mut out, None, false).unwrap();

        // Passed through + our trailing \n. Two newlines total:
        // the embedded one (data byte 5) and the appended one.
        assert_eq!(out, b"Line1\nLine2\n");
    }

    /// Full `pcap_loop`: global header + one packet.
    ///
    /// Daemon sends "18 14 4\n" + 4 bytes "ABCD".
    /// Output: 24-byte global header + 16-byte packet header + 4
    /// bytes data = 44 bytes.
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_loop_one_packet() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"18 14 4\nABCD");

        let (mut ctl, shared) = ctl_from_wire(wire);
        let mut out = Vec::new();

        // Fixed clock: epoch + 100s.
        let fixed_time = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        pcap_loop(&mut ctl, &mut out, 96, || fixed_time).unwrap();

        // ─── Subscription wire
        // `tincctl.c:591`: `"%d %d %d"`, snaplen=96.
        assert_eq!(shared.borrow().write_side, b"18 14 96\n");

        // ─── Output
        // 24 + 16 + 4 = 44 bytes.
        assert_eq!(out.len(), 44);

        // Global header: magic at [0..4].
        assert_eq!(&out[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // Snaplen at [16..20]: 96.
        assert_eq!(&out[16..20], &[96, 0, 0, 0]);

        // Packet header: tv_sec at [24..28] = 100.
        assert_eq!(&out[24..28], &[100, 0, 0, 0]);
        // len at [32..36] = 4, origlen at [36..40] = 4.
        assert_eq!(&out[32..36], &[4, 0, 0, 0]);
        assert_eq!(&out[36..40], &[4, 0, 0, 0]);

        // Data at [40..44].
        assert_eq!(&out[40..44], b"ABCD");
    }

    /// `snaplen=0` → subscription says 0, header says 9018.
    /// `tincctl.c:591` (subscribe with raw snaplen) vs `:606`
    /// (header defaults). The daemon sees 0 → no clip (`route.c
    /// :1120`: `if(c->outmaclength && ...)` — 0 is falsy).
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_loop_snaplen_zero() {
        let (mut ctl, shared) = ctl_from_wire(Vec::new());
        let mut out = Vec::new();

        pcap_loop(&mut ctl, &mut out, 0, SystemTime::now).unwrap();

        // Subscribe with 0.
        assert_eq!(shared.borrow().write_side, b"18 14 0\n");
        // Header has 9018.
        assert_eq!(
            u32::from_ne_bytes([out[16], out[17], out[18], out[19]]),
            9018
        );
    }

    /// Per-packet timestamp: clock called once per packet.
    /// Two packets → two `now()` calls → two different
    /// timestamps in the output.
    #[test]
    fn pcap_loop_timestamps_per_packet() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"18 14 1\nA");
        wire.extend_from_slice(b"18 14 1\nB");

        let (mut ctl, _) = ctl_from_wire(wire);
        let mut out = Vec::new();

        // Monotone clock: 100s, 200s.
        let mut t = 0u64;
        let clock = || {
            t += 100;
            SystemTime::UNIX_EPOCH + Duration::from_secs(t)
        };

        pcap_loop(&mut ctl, &mut out, 0, clock).unwrap();

        // Packet 1 header at [24..40], tv_sec at [24..28] = 100.
        assert_eq!(
            u32::from_ne_bytes([out[24], out[25], out[26], out[27]]),
            100
        );
        // Packet 1 data at [40] = 'A'.
        assert_eq!(out[40], b'A');
        // Packet 2 header at [41..57], tv_sec at [41..45] = 200.
        assert_eq!(
            u32::from_ne_bytes([out[41], out[42], out[43], out[44]]),
            200
        );
        // Packet 2 data at [57] = 'B'.
        assert_eq!(out[57], b'B');
    }

    // use_ansi_escapes_stdout — tested by inspection
    //
    // Can't unit-test `is_terminal()` without a PTY (cargo test's
    // stdout is a pipe). The TERM check IS testable but only if
    // we factor it out, and the function is 6 lines. The C
    // (`console.c:5-11`) is correctness-by-inspection; same here.
    // Integration tests (when `tinc log` runs against a real
    // daemon) cover it implicitly: stdout is a pipe → no color
    // → daemon receives `use_color=0` → log lines are unescaped.

    // Consts pinned against C

    /// `tincctl.c:592`: `char data[9018]`. `tincctl.c:651`: `char
    /// data[1024]`. sed-verifiable:
    ///   sed -n '592p;651p' src/tincctl.c
    #[test]
    fn data_max_consts() {
        assert_eq!(PCAP_DATA_MAX, 9018);
        assert_eq!(LOG_DATA_MAX, 1024);
    }

    /// `logger.h:27`: `DEBUG_UNSET = -1`. sed-verifiable:
    ///   sed -n '27p' src/logger.h
    #[test]
    fn debug_unset_is_minus_one() {
        assert_eq!(DEBUG_UNSET, -1);
    }
}
