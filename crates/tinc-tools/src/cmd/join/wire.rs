//! Greeting-phase wire helpers (pre-SPTPS plaintext lines).

use std::io::Read;
use std::net::TcpStream;

use crate::cmd::{CmdError, io_err};
use crate::names::check_id;

/// Wire protocol major version.
pub(super) const PROT_MAJOR: u32 = 17;

/// `ACK = 4` from the protocol enum. The daemon's second greeting
/// line starts with this.
pub(super) const ACK: u32 = 4;

/// Read one line from `sock` into a returned String, using `buf` as
/// the leftover accumulator.
///
/// `buf` carries bytes between calls — `recv()` may deliver multiple
/// lines (or a line plus the start of SPTPS data) in one syscall.
/// Upstream uses static `buffer[4096]`/`blen` for the same reason; we
/// make the state explicit.
///
/// The line is returned WITHOUT the trailing `\n`.
pub(super) fn recv_line(sock: &mut TcpStream, buf: &mut Vec<u8>) -> Result<String, CmdError> {
    loop {
        if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).take(nl).collect();
            return String::from_utf8(line)
                .map_err(|_| CmdError::BadInput("Cannot read greeting from peer".into()));
        }

        // We grow `buf` (no fixed cap; the lines are short, ~60
        // bytes, so this isn't a DoS surface — and we bail at 4096
        // just in case).
        if buf.len() >= 4096 {
            return Err(CmdError::BadInput("Cannot read greeting from peer".into()));
        }

        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).map_err(io_err("recv"))?;
        if n == 0 {
            return Err(CmdError::BadInput("Cannot read greeting from peer".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Validate `"0 NAME 17.x"` greeting. Returns `()` because we only
/// care that it's well-formed; the daemon's *name* and *minor*
/// don't affect anything.
pub(super) fn parse_greeting_line1(line: &str) -> Result<(), CmdError> {
    let bad = || CmdError::BadInput("Cannot read greeting from peer".into());

    let mut tok = line.split_ascii_whitespace();
    // `code` must be 0 (= ID).
    let code: u32 = tok.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if code != 0 {
        return Err(bad());
    }
    // `hisname` must pass check_id.
    let his_name = tok.next().ok_or_else(bad)?;
    if !check_id(his_name) {
        return Err(bad());
    }
    // `hismajor` must equal PROT_MAJOR. Minor is don't-care: the
    // sscanf `%d.%d` on "17\0" stops at the `.` mismatch but still
    // returns 3 (the mismatch is after 3 conversions). So minor is
    // optional. We replicate: parse `MAJOR` or `MAJOR.MINOR`.
    let ver = tok.next().ok_or_else(bad)?;
    let major: u32 = ver
        .split('.')
        .next()
        .unwrap_or(ver)
        .parse()
        .map_err(|_| bad())?;
    if major != PROT_MAJOR {
        return Err(bad());
    }
    Ok(())
}

/// Extract fingerprint from `"4 FINGERPRINT"`.
///
/// Returns the fingerprint as `&str` borrowing from the input — we
/// hash it immediately, no need to own.
pub(super) fn parse_greeting_line2(line: &str) -> Result<&str, CmdError> {
    let bad = || CmdError::BadInput("Cannot read greeting from peer".into());

    // We're stricter than upstream's sscanf: split on first space,
    // check first token is "4". `"4X"` would fail here (no space).
    // The daemon always sends `"4 FINGERPRINT"` (`send_request` adds
    // a space between `%d` and `%s`).
    let (code, rest) = line.split_once(' ').ok_or_else(bad)?;
    let code: u32 = code.parse().map_err(|_| bad())?;
    if code != ACK || rest.is_empty() {
        return Err(bad());
    }
    Ok(rest)
}
