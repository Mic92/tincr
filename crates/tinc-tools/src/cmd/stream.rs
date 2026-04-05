//! Streaming control commands: `log` and `pcap`.
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
//! sets `c->status.log = true`; every `logger()` call thereafter
//! `send_request`s to subscribers. The CLI loops until daemon EOF
//! or Ctrl-C.
//!
//! ## The wire shape (recvdata vs recvline)
//!
//! Daemon-side, log/pcap each emit a `send_request` (line-framed,
//! printf + `\n`) followed by `send_meta` (raw bytes, NO `\n`).
//! The data IS arbitrary bytes — pcap data is Ethernet frames, log
//! data may have embedded `\n`s. So:
//!
//!   - Parse the header with `recv_line` (line-framed)
//!   - Read the data with `recv_data` (length-framed, raw bytes)
//!
//! `recv_line`'s `recv()` might over-read past the `\n` into the
//! start of the data block; see `ctl.rs`'s `CtlSocket` doc-comment
//! for why `BufReader` is the shared buffer.
//!
//! ## The SIGINT handler — NOT ported
//!
//! Upstream installs a SIGINT handler that `shutdown(fd, SHUT_RDWR)`s
//! so the loop exits cleanly with code 0 instead of 130. NOT ported:
//! the daemon doesn't care (kernel closes the socket either way,
//! connection-reaper handles it), `tinc log` is interactive so
//! nobody checks `$?`, and the static-fd signal-handler dance has
//! hairy failure modes. Exit codes for streaming commands aren't a
//! contract.
//!
//! ## pcap headers: native-endian
//!
//! Upstream writes pcap headers via `fwrite(&struct)` — native-
//! endian. This is by design: libpcap's magic `0xa1b2c3d4` is the
//! endianness marker, readers byte-swap as needed. We use
//! `to_ne_bytes()` per-field to match. The struct is all-u32 (no
//! padding); we write field-by-field so no padding question.

use std::io::{Read, Write};
use std::time::SystemTime;

use crate::ctl::{CtlError, CtlRequest, CtlSocket};
use crate::names::Paths;

use super::CmdError;

// Shared header parse + size limits

/// Max log line. Daemon-side `pretty[1024]` (the format buffer).
/// Log lines that somehow exceed this would be silently truncated
/// by the daemon's `snprintf`; we'd never see len>1024 on the wire.
/// The check is defense against a buggy daemon.
const LOG_DATA_MAX: usize = 1024;

/// Max packet capture. 9000-byte jumbo MTU + Ethernet header (14) +
/// a few for slop. Daemon-side `vpn_packet_t` is `MAXSIZE` (9018).
/// The check is the SAME defense — a daemon bug saying len=2^32
/// would alloc 4GiB without this.
const PCAP_DATA_MAX: usize = 9018;

/// Parse `"18 N len"` header. The shared header shape for both
/// streams.
///
/// Returns `Some(len)` if header is well-formed and the request
/// type matches. `None` for malformed or wrong type — the caller
/// breaks (silent exit).
///
/// `kind`: which stream. The header echoes the subscription type —
/// a `REQ_LOG` subscriber sees `"18 15 N"` headers, a `REQ_PCAP`
/// subscriber sees `"18 14 N"`. Why check it: the daemon's
/// connection mux means a bug COULD cross-send. Unlikely; defense.
///
/// `max`: per-stream size limit. `len > max → None`.
///
/// We parse `len` as `usize` for both streams — `parse::<usize>()`
/// rejects negative AND overflow. The wire is ASCII digits either
/// way.
fn parse_header(line: &str, kind: CtlRequest, max: usize) -> Option<usize> {
    // `"18 15 7"`. Three space-separated ints.
    let mut it = line.split(' ');
    let code = it.next()?;
    let req = it.next()?;
    let len = it.next()?;
    // No `it.next().is_none()` check — sscanf-style ignores trailing.
    // The daemon won't send any, but match the slack.

    if code != "18" {
        return None;
    }
    // Compare as ASCII (the wire is ASCII). `kind as u8 → string`:
    // 15 → "15" or 14 → "14". Per-call alloc is fine; this runs
    // once per log line, the syscall to read the line dominates.
    if req != (kind as u8).to_string() {
        return None;
    }
    let len: usize = len.parse().ok()?;
    if len > max {
        return None;
    }
    Some(len)
}

// `tinc log [LEVEL]` — stream daemon's logger() output
//
// Subscribe with `(level, use_color)`, then loop: header, data,
// write data + `\n` to stdout.
//
// `level` is the FILTER, not the daemon's debug level. The daemon
// CLAMPs it into `c->log_level`, and checks `level > c->log_level
// → continue` per-connection. `-1` (`DEBUG_UNSET`) means "use the
// daemon's own debug level". Higher numbers = more verbose.
//
// `use_color`: pass-through to the daemon's `format_pretty`. Per-
// subscriber: the daemon formats the SAME log line both colored
// and uncolored if it has subscribers of both kinds.

/// `DEBUG_UNSET`. The "use daemon's level" sentinel.
const DEBUG_UNSET: i32 = -1;

/// Three checks: stdout IS a tty, TERM is set, TERM isn't `"dumb"`.
///
/// Hard-coded stdout. The daemon writes log lines to OUR stdout
/// via the socket; if we're piped (`tinc log | less`), color
/// escapes look like garbage in less without `-R`.
/// `isatty(stdout)` is false then → no color.
///
/// Why not check `NO_COLOR` env var (the modern convention):
/// upstream doesn't. `script -c "tinc log"` is the answer (PTY in
/// between). Same as every isatty-gated colorizer.
fn use_ansi_escapes_stdout() -> bool {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return false;
    }
    // Empty string is "set" in the getenv sense (non-NULL for
    // `TERM=`). `env::var` returns `Ok("")` for that, which is
    // `!= "dumb"`, so colors on. Probably wrong (TERM= means "no
    // terminfo"), but upstream-compat.
    match std::env::var("TERM") {
        Ok(term) => term != "dumb",
        Err(_) => false, // unset, or non-UTF-8 (unlikely)
    }
}

/// The main loop. Generic over the output `Write` so the test can
/// pass a `Vec`. Production passes stdout's lock.
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
///   - malformed header: `Ok(())`, clean (silent break)
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
    // The bool prints as 0/1; the daemon reads as int and treats
    // nonzero as true. `i32::from(bool)` is 0/1.
    ctl.send_int2(
        CtlRequest::Log,
        level.unwrap_or(DEBUG_UNSET),
        i32::from(use_color),
    )?;

    // ─── Receive loop
    // Reused buffer; `clear` + `resize` per-iteration. `resize`
    // doesn't shrink capacity, so after the first message we never
    // re-alloc. `with_capacity` for the FIRST message: pre-size to
    // max so even the first iteration doesn't grow.
    let mut buf: Vec<u8> = Vec::with_capacity(LOG_DATA_MAX);

    // `recv_line → None` is EOF (daemon closed) — `Ok(())` clean.
    while let Some(line) = ctl.recv_line()? {
        // Malformed → break (silent).
        let Some(len) = parse_header(&line, CtlRequest::Log, LOG_DATA_MAX) else {
            break;
        };

        // Exactly `len` raw bytes after the header line. `resize`
        // (NOT `reserve`) because `recv_data` writes into `&mut
        // [u8]` — we need initialized length, not just capacity.
        // The zero-fill is wasted work but the syscall dominates
        // by 10000×.
        buf.clear();
        buf.resize(len, 0);
        // Mid-data EOF → bubble (slightly noisier than upstream,
        // but the daemon dying mid-stream is rare and a message
        // helps).
        ctl.recv_data(&mut buf)?;

        // The data is the FORMATTED log line (priority prefix,
        // timestamp, message). It doesn't include a trailing `\n`
        // — we add it. Then flush (line-buffered output for
        // interactive viewing).
        //
        // `write_all` not `write`: partial writes happen (pipe
        // full); `write_all` retries.
        //
        // EPIPE: the binary's `signal(SIGPIPE, SIG_IGN)` means we
        // get the error not the signal. Bubble it; main exits.
        out.write_all(&buf).map_err(CtlError::Io)?;
        out.write_all(b"\n").map_err(CtlError::Io)?;
        out.flush().map_err(CtlError::Io)?;
    }

    Ok(())
}

/// CLI entry: `tinc log [LEVEL]`.
///
/// `LEVEL` is `atoi`'d upstream; `atoi("garbage")` is 0 (silently).
/// We use `parse::<i32>()` which errors. STRICTER, but `tinc log
/// abc` succeeding-with-level-0 is a footgun. The change is
/// observable but only for invalid input.
///
/// The SIGINT handler is NOT here (see module doc). Ctrl-C kills
/// the process; exit 130. Daemon doesn't care.
///
/// # Errors
/// Daemon down (`connect`), socket I/O, EPIPE (`tinc log | head`).
#[cfg(unix)]
pub fn run_log(paths: &Paths, level: Option<i32>) -> Result<(), CmdError> {
    let mut ctl = CtlSocket::connect(paths).map_err(|e| CmdError::BadInput(e.to_string()))?;

    // Checked HERE not inside `log_loop` so the test can pass a
    // fixed bool.
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
// Subscribe with `snaplen`, write the libpcap global header, then
// loop: tinc header, data, libpcap packet header + data to stdout.
//
// `snaplen`: max bytes per packet to capture. 0 = full packet.
// Daemon clips. The repurposed `outmaclength` field is a hack — it
// was the legacy MAC length, reused for pcap snaplen because every
// connection has it and pcap subscribers don't use legacy crypto.
//
// Output is the libpcap "savefile" format (the original, not
// pcapng). Magic `0xa1b2c3d4`, version 2.4, link-type 1
// (Ethernet). Wireshark, tcpdump -r, every analyzer reads it.
//
// `tinc pcap | wireshark -k -i -` is the use case. Real-time
// packet view of the VPN traffic. The daemon hands us raw Ethernet
// frames (the same `vpn_packet_t` the routing engine sees).

/// Libpcap global header. 24 bytes.
///
/// Field-by-field `to_ne_bytes()` rather than a `#[repr(C)]`
/// struct + `bytemuck::bytes_of` (or unsafe `std::slice::from_raw_
/// parts`). Our struct WOULD have the same layout (all-u32 + two
/// u16, no padding holes), but per-field bytes is `forbid(unsafe)`-
/// compliant and the once-per-session 24-byte write isn't perf-
/// critical.
///
/// `snaplen`: from the user. 0 → defaults to `PCAP_DATA_MAX` (9018).
/// The header records what the file PROMISES; the daemon enforces
/// it.
///
/// Returns the 24 header bytes ready to write.
fn pcap_global_header(snaplen: u32) -> [u8; 24] {
    // Layout, in declaration order:
    //   uint32_t magic       = 0xa1b2c3d4
    //   uint16_t major       = 2
    //   uint16_t minor       = 4
    //   uint32_t tz_offset   = 0 (always; libpcap stores UTC)
    //   uint32_t tz_accuracy = 0 (unused; legacy)
    //   uint32_t snaplen
    //   uint32_t ll_type     = 1 (LINKTYPE_ETHERNET)
    //
    // 4 + 2 + 2 + 4 + 4 + 4 + 4 = 24 bytes. No padding (the two
    // u16 pack to one u32-aligned slot).
    //
    // `0xa1b2c3d4` is the standard magic. Readers detect endianness
    // by whether they see `a1b2c3d4` or `d4c3b2a1`. `to_ne_bytes`
    // writes whatever the host CPU does — same as `fwrite(&u32)`.
    let magic: u32 = 0xa1b2_c3d4;
    let major: u16 = 2;
    let minor: u16 = 4;
    let tz_offset: u32 = 0;
    let tz_accuracy: u32 = 0;
    // 0 means "user didn't pass one OR passed 0" — both → max.
    #[allow(clippy::cast_possible_truncation)] // 9018 < u32::MAX, const
    let snaplen = if snaplen == 0 {
        PCAP_DATA_MAX as u32
    } else {
        snaplen
    };
    let ll_type: u32 = 1; // LINKTYPE_ETHERNET

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

/// Libpcap per-packet record header. 16 bytes.
///
/// ```text
///   uint32_t tv_sec    — wall-clock seconds (gettimeofday)
///   uint32_t tv_usec   — microseconds part
///   uint32_t len       — captured bytes (after snaplen clip)
///   uint32_t origlen   — original packet length on the wire
/// ```
///
/// `len` and `origlen`: the daemon clips to `snaplen` BEFORE
/// sending, so we receive `len` bytes and don't know the original.
/// Both set to what we got. Wireshark shows "X bytes captured"
/// with no truncation marker. Slightly wrong but the daemon would
/// have to send origlen too for accuracy.
///
/// `tv_sec` is the LOW 32 bits of `time_t`. After 2106 (unsigned
/// wraps later than 2038) this rolls over. Libpcap's 2038 problem;
/// not ours. There's a microsecond-magic (`0xa1b2_3c4d`) for 64-bit
/// timestamps but we don't use it.
///
/// Why we timestamp HERE (CLI-side) not daemon-side: the daemon's
/// `send_pcap` doesn't include time. The CLI calls `gettimeofday`
/// per-packet. The timestamp is "when the CLI received it," not
/// "when the daemon routed it." Socket latency is ~10µs (localhost),
/// well below the µs resolution. Good enough.
///
/// `clippy::similar_names`: `tv_sec`/`tv_usec` are the libpcap
/// struct field names. The names ARE the doc; renaming breaks
/// libpcap-side grep.
#[allow(clippy::similar_names)]
fn pcap_packet_header(now: SystemTime, len: u32) -> [u8; 16] {
    // `unwrap_or_default`: `duration_since` errs if `now < EPOCH`
    // (clock set to 1960). Default Duration is 0s — the timestamp
    // would be wrong but the file is still valid pcap. Better than
    // panicking on a misconfigured clock.
    let dur = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    // `as u32`: truncates. INTENTIONAL — see fn doc on the 2038
    // problem. `subsec_micros` returns `u32` already (always in
    // [0, 999999]).
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

/// The main loop. Same `Write`-generic as `log_loop`.
///
/// `snaplen`: 0 = full packet. Passed to daemon AND embedded in
/// the global header. Daemon enforces; we record.
///
/// `now`: clock function. Production passes `SystemTime::now`;
/// tests pass a fixed time. Per-packet call, not pre-loop — each
/// packet gets its OWN timestamp.
///
/// Runs forever. Same exit conditions as `log_loop`.
///
/// # Errors
/// Socket I/O, output I/O. Malformed-header is `Ok(())` clean exit.
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
    // The cast: `snaplen` is `u32`, `send_int` takes `i32`.
    // `snaplen` from user is 0 or a small number (typical: 96,
    // 1500); fits. The daemon side reads `%d` (signed), so the
    // wire is `i32`-shaped anyway. `as i32` matches the wire.
    #[allow(clippy::cast_possible_wrap)] // snaplen is small; matches %d wire
    ctl.send_int(CtlRequest::Pcap, snaplen as i32)?;

    // ─── Global header
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

        // INSIDE the loop, per-packet, BEFORE the data read.
        // (Neither order is observably different; the data hasn't
        // arrived yet either way.)
        let ts = now();

        buf.clear();
        buf.resize(len, 0);
        ctl.recv_data(&mut buf)?;

        // Per-packet flush so `tinc pcap | wireshark -k -i -`
        // shows packets in real-time (Wireshark reads from a pipe;
        // no flush → it sees nothing until the pipe buffer fills,
        // ~64KiB ≈ dozens of packets).
        #[allow(clippy::cast_possible_truncation)] // len ≤ 9018 by parse_header
        let len_u32 = len as u32;
        out.write_all(&pcap_packet_header(ts, len_u32))
            .map_err(CtlError::Io)?;
        out.write_all(&buf).map_err(CtlError::Io)?;
        out.flush().map_err(CtlError::Io)?;
    }

    Ok(())
}

/// CLI entry: `tinc pcap [SNAPLEN]`.
///
/// `SNAPLEN`: `atoi`'d upstream. We `parse::<u32>()`. Stricter
/// (rejects negative — `atoi("-5")` is `-5` then assigned to a
/// `uint32_t` arg which wraps to a huge number; daemon then never
/// clips). `tinc pcap -5` failing is better.
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

    /// `parse_header` table. The two golden rows are wire-format
    /// pins; the rest are sscanf-style failure modes + bounds.
    #[test]
    fn parse_header_table() {
        use CtlRequest::{Log, Pcap};
        #[rustfmt::skip]
        let cases: &[(&str, CtlRequest, usize, Option<usize>)] = &[
            //          (input,                req,   max,   expected)
            // GOLDEN: log
            ("18 15 7",                Log,   1024,  Some(7)),
            // GOLDEN: pcap
            ("18 14 1500",             Pcap,  9018,  Some(1500)),
            // wrong code
            ("17 15 7",                Log,   1024,  None),
            // wrong req: log subscriber gets pcap header (daemon mux bug case)
            ("18 14 7",                Log,   1024,  None),
            ("18 15 7",                Pcap,  9018,  None),
            // len boundary: max is OK, max+1 is not
            ("18 15 1024",             Log,   1024,  Some(1024)),
            ("18 15 1025",             Log,   1024,  None),
            ("18 14 9018",             Pcap,  9018,  Some(9018)),
            ("18 14 9019",             Pcap,  9018,  None),
            // negative len: parse::<usize>() rejects
            ("18 15 -1",               Log,   1024,  None),
            // short line
            ("18 15",                  Log,   1024,  None),
            ("18",                     Log,   1024,  None),
            ("",                       Log,   1024,  None),
            // non-numeric len
            ("18 15 abc",              Log,   1024,  None),
            // trailing garbage: sscanf-style stops after 3rd int, ignores
            ("18 15 7 extra stuff",    Log,   1024,  Some(7)),
            // len zero: valid! Zero-byte log line. Daemon won't send it,
            // but wire allows.
            ("18 15 0",                Log,   1024,  Some(0)),
        ];
        for &(input, req, max, expected) in cases {
            assert_eq!(parse_header(input, req, max), expected, "input: {input:?}");
        }
    }

    // pcap headers — byte-exact

    /// Global header bytes on little-endian (`x86_64`). Field-by-
    /// field. The `cfg(target_endian)` is because `to_ne_bytes()`
    /// differs on big-endian — the magic would be `[a1, b2, c3, d4]`
    /// there. We don't have a BE CI; LE is what every dev machine
    /// and prod box runs.
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

    /// Snaplen 0 → defaults to 9018.
    #[test]
    #[cfg(target_endian = "little")]
    fn pcap_global_header_snaplen_zero_defaults() {
        let h = pcap_global_header(0);
        // 9018 = 0x233a. LE: 3a 23 00 00.
        assert_eq!(&h[16..20], &[0x3a, 0x23, 0, 0]);
        assert_eq!(u32::from_ne_bytes([h[16], h[17], h[18], h[19]]), 9018);
    }

    /// Packet header bytes. Fixed timestamp for determinism.
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
        // len = origlen = 1500 = 0x5dc. LE. BOTH set to the same value.
        assert_eq!(&h[8..12], &[0xdc, 0x05, 0, 0]);
        assert_eq!(&h[12..16], &[0xdc, 0x05, 0, 0]);
    }

    /// 2038 truncation: a timestamp past `u32::MAX` seconds gets
    /// the low 32 bits.
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
        // Construct a SystemTime BEFORE epoch by subtracting from
        // epoch — works on Unix.
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let h = pcap_packet_header(before, 100);
        // tv_sec = 0, tv_usec = 0 (Duration::default()).
        assert_eq!(&h[0..8], &[0; 8]);
        // len fields still correct.
        assert_eq!(u32::from_ne_bytes([h[8], h[9], h[10], h[11]]), 100);
    }

    // log_loop / pcap_loop — fake socket, captured output

    /// Read+Write adapter: reads come from `read_side`, writes
    /// land in `write_side`. The loops under test both subscribe
    /// (write) AND consume (read); a single Cursor would interleave
    /// the two. Wrapped via `CtlSocket::wrap` (the test-seam ctor).
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

        // Subscription wire: level=DEBUG_UNSET (-1), color=0.
        assert_eq!(shared.borrow().write_side, b"18 15 -1 0\n");

        // Output: data + '\n'. The flushes are invisible in a Vec.
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

    /// `use_color=true` → fourth int is 1.
    #[test]
    fn log_loop_color_forwarded() {
        let (mut ctl, shared) = ctl_from_wire(Vec::new());
        let mut out = Vec::new();

        log_loop(&mut ctl, &mut out, None, true).unwrap();

        assert_eq!(shared.borrow().write_side, b"18 15 -1 1\n");
    }

    /// Malformed header → clean break. No error, partial output kept.
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
    /// `\n` is OURS.
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

        // Subscription wire: snaplen=96.
        assert_eq!(shared.borrow().write_side, b"18 14 96\n");

        // Output: 24 + 16 + 4 = 44 bytes.
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
    /// The daemon sees 0 → no clip (`if(c->outmaclength && ...)` —
    /// 0 is falsy).
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
    // we factor it out, and the function is 6 lines. Integration
    // tests (when `tinc log` runs against a real daemon) cover it
    // implicitly: stdout is a pipe → no color → daemon receives
    // `use_color=0` → log lines are unescaped.
}
