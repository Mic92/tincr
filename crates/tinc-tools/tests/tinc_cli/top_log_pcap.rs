//! The streaming commands. Subscribe lines are asserted exactly (this
//! is what a C tincd parses); pushed records are `18 N LEN\n` followed
//! by LEN raw bytes with no newline.

use super::{Conf, tinc};

#[test]
fn top_too_many_args() {
    tinc(&["top", "extra"]).fails_with("Too many arguments");
}

/// `top` connects before entering raw mode, so on a real terminal a
/// dead daemon is reported rather than a tty error. Under test stdin
/// is a pipe: the greeting happens, then raw mode fails and nothing
/// else (in particular no `18 13` traffic dump) is requested.
#[test]
fn top_connects_then_fails_on_non_tty() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| ctl.expect_eof());
    let stderr = conf.tinc(&["top"]).fails_with("stdin is not a terminal");
    assert!(!stderr.contains("Could not"), "{stderr}");
    daemon.finish();
}

/// Level -1 is `DEBUG_UNSET` (no argument); colour is off because
/// stdout is a pipe. The CLI appends the newline after each record.
/// Header and body in one write also exercises the shared `BufReader`.
#[test]
fn log_prints_pushed_records() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 15 -1 0");
        ctl.send_raw(b"18 15 5\nHello18 15 5\nWorld");
        ctl.close();
        ctl.expect_eof();
    });
    assert_eq!(conf.tinc(&["log"]).succeeds(), "Hello\nWorld\n");
    daemon.finish();
}

#[test]
fn log_level_forwarded() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 15 5 0");
        ctl.close();
    });
    assert_eq!(conf.tinc(&["log", "5"]).succeeds(), "");
    daemon.finish();
}

/// C's atoi would turn this into level 0.
#[test]
fn log_rejects_garbage_level() {
    tinc(&["log", "abc"]).fails_with("Invalid debug level");
}

/// libpcap savefile: 24-byte global header (snaplen 0 → 9018
/// default, linktype 1), 16-byte record header, data verbatim.
#[test]
fn pcap_writes_savefile() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 14 0");
        ctl.send_raw(b"18 14 4\nABCD");
        ctl.close();
    });
    let run = conf.tinc(&["pcap"]);
    daemon.finish();
    assert!(run.success, "{}", run.stderr);
    let out = run.raw_stdout;
    let u32_at = |offset: usize| u32::from_ne_bytes(out[offset..offset + 4].try_into().unwrap());
    assert_eq!(out.len(), 24 + 16 + 4);
    assert_eq!(u32_at(0), 0xa1b2_c3d4, "magic, native endian");
    assert_eq!(u32_at(16), 9018, "snaplen");
    assert_eq!(u32_at(20), 1, "linktype ethernet");
    assert!(u32_at(24) > 1_000_000_000, "tv_sec is wall clock");
    assert_eq!(u32_at(32), 4, "caplen");
    assert_eq!(u32_at(36), 4, "origlen");
    assert_eq!(&out[40..], b"ABCD");
}

/// Either the option parser (`-5` looks like a flag) or pcap may
/// reject it; wrapping to a huge snaplen may not happen.
#[test]
fn pcap_rejects_negative_snaplen() {
    let stderr = tinc(&["pcap", "-5"]).fails();
    assert!(
        stderr.contains("Invalid") || stderr.contains("Unknown"),
        "{stderr}"
    );
}
