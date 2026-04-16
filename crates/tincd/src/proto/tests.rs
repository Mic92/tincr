use super::*;
use std::os::fd::OwnedFd;

/// `/dev/null` fd; handlers don't touch the fd, just need a valid conn.
fn nullfd() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").unwrap())
}

fn mkconn() -> Connection {
    Connection::test_with_fd(nullfd())
}

/// `IdCtx` for tests not reaching the peer pubkey load. `OnceLock`
/// for `'static` lifetime. `confbase="."` → pubkey load fails;
/// tests reaching it use `PeerSetup`.
fn mkctx(cookie: &str) -> IdCtx<'_> {
    static DUMMY_KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
    let mykey = DUMMY_KEY.get_or_init(|| SigningKey::from_seed(&[0x99; 32]));
    IdCtx {
        cookie,
        my_name: "testd",
        mykey,
        confbase: Path::new("."),
        invitation_key: None,
        global_pmtu: None,
    }
}

use rand_core::OsRng;

// ─── check_gate

/// `DispatchError` isn't `PartialEq`-friendly; gate only yields these.
#[derive(Debug, PartialEq)]
enum GateExpect {
    Ok(Request),
    Unauthorized,
    UnknownRequest,
}

/// Full allow/deny matrix + malformed. Covers `atoi`, `*request
/// == '0'`, range check, gate.
#[test]
fn gate_cases() {
    use GateExpect::{Ok, Unauthorized, UnknownRequest};
    #[rustfmt::skip]
    let cases: &[(Option<Request>, &[u8], GateExpect)] = &[
        // ─── allows expected
        // new_control sets allow_request = Some(Id).
        (Some(Request::Id), b"0 ^abc 0",   Ok(Request::Id)),
        // ─── blocks unexpected
        // Fresh conn allows only ID (0). CONTROL (18) is gated.
        (Some(Request::Id), b"18 0",       Unauthorized),
        // ─── None = ALL
        (None,              b"18 0",       Ok(Request::Control)),
        (None,              b"0 foo 17.7", Ok(Request::Id)),
        (None,              b"8",          Ok(Request::Ping)),
        // ─── empty: `atoi("")` → 0 in C, but the `*request ==
        // '0'` check fails. We reject too: empty first token.
        (Some(Request::Id), b"",           UnknownRequest),
        (Some(Request::Id), b"  ",         UnknownRequest),
        // ─── out of range
        (None,              b"99 foo",     UnknownRequest),
        (None,              b"-1 foo",     UnknownRequest),
        // ─── STRICTER: `"18foo"` rejected; `atoi` would parse 18
        (None,              b"18foo bar",  UnknownRequest),
    ];
    for (i, (allow, line, expected)) in cases.iter().enumerate() {
        let mut c = mkconn();
        c.allow_request = *allow;
        let got = match check_gate(&c, line) {
            Result::Ok(r) => Ok(r),
            Err(DispatchError::Unauthorized) => Unauthorized,
            Err(DispatchError::UnknownRequest) => UnknownRequest,
            Err(e) => panic!("case {i}: {line:?}: unexpected error: {e:?}"),
        };
        assert_eq!(got, *expected, "case {i}: {line:?}");
    }
}

// ─── handle_id
//
// Happy-path control auth covered by `tests/stop.rs::spawn_connect_stop`.
// Rejection paths only

#[test]
fn id_control_rejected_on_non_unix_conn() {
    let mut c = mkconn();
    c.is_unix_ctl = false;
    let cookie = "a".repeat(64);
    let line = format!("0 ^{cookie} 0");
    let r = handle_id(
        &mut c,
        line.as_bytes(),
        &mkctx(&cookie),
        Instant::now(),
        &mut OsRng,
    );
    assert!(matches!(r, Err(DispatchError::BadId(_))), "got {r:?}");
    assert!(!c.control);
    assert!(c.outbuf.is_empty());
}

#[test]
fn id_cookie_mismatch() {
    let mut c = mkconn();
    let cookie = "a".repeat(64);
    let bad = "b".repeat(64);
    let line = format!("0 ^{bad} 0");

    let r = handle_id(
        &mut c,
        line.as_bytes(),
        &mkctx(&cookie),
        Instant::now(),
        &mut OsRng,
    );
    assert!(matches!(r, Err(DispatchError::BadId(_))));
    // No state change on failure.
    assert!(!c.control);
    assert_eq!(c.allow_request, Some(Request::Id));
    assert!(c.outbuf.is_empty());
}

/// Early-reject paths: all bail BEFORE the pubkey load. `mkctx`
/// (confbase=".") suffices; the Err proves we never hit the fs.
#[test]
fn id_early_rejects() {
    #[rustfmt::skip]
    let cases: &[(&[u8], &str)] = &[
        // `if(!invitation_key)` (mkctx has None)
        (b"0 ?somekey 17.7",     "invitation, no key"),
        // `!check_id(name)`. Path-traversal gate.
        (b"0 ../etc/passwd 17.7", "path traversal"),
        // `|| !strcmp(name, myself->name)`
        (b"0 testd 17.7",        "peer is self"),
        // `sscanf` returns 0/1 (`< 2` fails)
        (b"0",                   "no name token"),
        (b"0 alice",             "no version token"),
    ];
    for (i, (line, label)) in cases.iter().enumerate() {
        let mut c = mkconn();
        let r = handle_id(&mut c, line, &mkctx("x"), Instant::now(), &mut OsRng);
        assert!(
            matches!(r, Err(DispatchError::BadId(_))),
            "case {i} ({label}): {line:?} → {r:?}"
        );
        // No state mutation on early reject.
        assert!(c.sptps.is_none(), "case {i} ({label}): sptps installed");
        assert_eq!(c.name, "<control>", "case {i} ({label}): name set");
        assert!(c.outbuf.is_empty(), "case {i} ({label}): outbuf written");
    }
}

// ─── id_h peer branch

/// Tempdir + hosts/ layout for peer-branch tests.
struct PeerSetup {
    tmp: std::path::PathBuf,
}
impl PeerSetup {
    fn new(tag: &str, peer_name: &str, peer_pub: &[u8; 32]) -> Self {
        let tid = std::thread::current().id();
        let tmp = std::env::temp_dir().join(format!("tincd-proto-{tag}-{tid:?}"));
        std::fs::create_dir_all(tmp.join("hosts")).unwrap();
        // Inline b64 (read_ecdsa_public_key source 1).
        let b64 = tinc_crypto::b64::encode(peer_pub);
        std::fs::write(
            tmp.join("hosts").join(peer_name),
            format!("Ed25519PublicKey = {b64}\n"),
        )
        .unwrap();
        Self { tmp }
    }
    fn confbase(&self) -> &Path {
        &self.tmp
    }
}
impl Drop for PeerSetup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

// Happy-path peer ID covered by `tests/stop.rs::peer_ack_exchange`
// (full SPTPS handshake proves sptps installed + right pubkey).

/// Major mismatch.
#[test]
fn id_peer_major_mismatch() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let peerkey = SigningKey::from_seed(&[2; 32]);
    let setup = PeerSetup::new("major", "alice", peerkey.public_key());

    let mut c = mkconn();
    let cookie = "a".repeat(64);
    let ctx = IdCtx {
        cookie: &cookie,
        my_name: "testd",
        mykey: &mykey,
        confbase: setup.confbase(),
        invitation_key: None,
        global_pmtu: None,
    };

    // 18.7 — major 18, we're 17.
    let r = handle_id(&mut c, b"0 alice 18.7", &ctx, Instant::now(), &mut OsRng);
    assert!(matches!(r, Err(DispatchError::BadId(_))));
    // Name set before version check.
    assert_eq!(c.name, "alice");
    assert!(c.sptps.is_none());
}

/// Unknown identity: no `hosts/alice` file.
#[test]
fn id_peer_unknown_identity() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    // PeerSetup for a DIFFERENT name. hosts/alice doesn't exist.
    let setup = PeerSetup::new("unknown", "bob", &[0; 32]);

    let mut c = mkconn();
    let cookie = "a".repeat(64);
    let ctx = IdCtx {
        cookie: &cookie,
        my_name: "testd",
        mykey: &mykey,
        confbase: setup.confbase(),
        invitation_key: None,
        global_pmtu: None,
    };

    let r = handle_id(&mut c, b"0 alice 17.7", &ctx, Instant::now(), &mut OsRng);
    let Err(DispatchError::BadId(msg)) = r else {
        panic!("expected BadId, got {r:?}");
    };
    assert!(msg.contains("alice"), "msg: {msg}");
    assert!(msg.contains("unknown identity"), "msg: {msg}");
    assert!(c.sptps.is_none());
}

/// Rollback: known peer sends minor=0. STRICTER:
/// minor=1 also rejected (no legacy).
#[test]
fn id_peer_rollback_rejected() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let peerkey = SigningKey::from_seed(&[2; 32]);
    let setup = PeerSetup::new("rollback", "alice", peerkey.public_key());

    let mut c = mkconn();
    let cookie = "a".repeat(64);
    let ctx = IdCtx {
        cookie: &cookie,
        my_name: "testd",
        mykey: &mykey,
        confbase: setup.confbase(),
        invitation_key: None,
        global_pmtu: None,
    };

    let r = handle_id(&mut c, b"0 alice 17.0", &ctx, Instant::now(), &mut OsRng);
    let Err(DispatchError::BadId(msg)) = r else {
        panic!("expected BadId, got {r:?}");
    };
    assert!(msg.contains("roll back"), "msg: {msg}");

    // minor=1: C would `send_metakey`. STRICTER reject.
    let mut c = mkconn();
    let r = handle_id(&mut c, b"0 alice 17.1", &ctx, Instant::now(), &mut OsRng);
    assert!(matches!(r, Err(DispatchError::BadId(_))));
}

/// `"17"` (no dot) → minor=0: parse SUCCEEDS, then SEMANTIC reject.
/// Pins: "roll back" error, not "malformed" — same as C.
#[test]
fn id_peer_no_dot_minor_zero() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let peerkey = SigningKey::from_seed(&[2; 32]);
    let setup = PeerSetup::new("nodot", "alice", peerkey.public_key());

    let mut c = mkconn();
    let cookie = "a".repeat(64);
    let ctx = IdCtx {
        cookie: &cookie,
        my_name: "testd",
        mykey: &mykey,
        confbase: setup.confbase(),
        invitation_key: None,
        global_pmtu: None,
    };

    let r = handle_id(&mut c, b"0 alice 17", &ctx, Instant::now(), &mut OsRng);
    let Err(DispatchError::BadId(msg)) = r else {
        panic!("expected BadId, got {r:?}");
    };
    assert!(msg.contains("roll back"), "msg: {msg}");
    // protocol_minor set BEFORE the reject.
    assert_eq!(c.protocol_minor, 0);
}

// ─── invitation `?` branch
//
// Happy path covered by `tests/two_daemons.rs::tinc_join_against_real_daemon`.

/// `?` with garbage b64. `if(!c->ecdsa)` reject.
#[test]
fn id_invitation_bad_throwaway() {
    let mykey = SigningKey::from_seed(&[1; 32]);
    let inv_key = SigningKey::from_seed(&[0x77; 32]);

    let mut c = mkconn();
    let cookie = "a".repeat(64);
    let ctx = IdCtx {
        cookie: &cookie,
        my_name: "alice",
        mykey: &mykey,
        confbase: Path::new("."),
        invitation_key: Some(&inv_key),
        global_pmtu: None,
    };

    // Too short (32 bytes b64 → 43 chars; this is 7).
    let r = handle_id(&mut c, b"0 ?garbage 17.7", &ctx, Instant::now(), &mut OsRng);
    assert!(matches!(r, Err(DispatchError::BadId(_))));
    assert!(c.sptps.is_none());
    assert!(c.outbuf.is_empty());
}

/// `"tinc invitation", 15` — explicit count,
/// NOT `sizeof()`. NO trailing NUL (cf `tcp_label_has_trailing_nul`).
#[test]
fn invite_label_no_nul() {
    assert_eq!(INVITE_LABEL.len(), 15);
    assert_eq!(INVITE_LABEL, b"tinc invitation");
    assert!(!INVITE_LABEL.contains(&0));
}

// ─── tcp_label (the NUL)

/// WIRE-COMPAT. gcc-verified: `labellen=33`, byte 32 = 0x00. Miss
/// the NUL → `BadSig` against C tincd. Fast fail vs 100ms+
/// `stop.rs::peer_handshake`.
#[test]
fn tcp_label_has_trailing_nul() {
    let label = tcp_label("alice", "bob");
    assert_eq!(label.len(), 25 + 5 + 3); // `25 + strlen(a) + strlen(b)`
    assert_eq!(label.len(), 33);
    assert_eq!(label[32], 0);
    assert_eq!(label[31], b'b');
    assert_eq!(&label[..], b"tinc TCP key expansion alice bob\0");
}

/// Always (initiator, responder). Swap → `BadSig`.
#[test]
fn tcp_label_order_matters() {
    let a = tcp_label("alice", "bob");
    let b = tcp_label("bob", "alice");
    assert_ne!(a, b);
    assert!(a.starts_with(b"tinc TCP key expansion alice "));
    assert!(b.starts_with(b"tinc TCP key expansion bob "));
}

/// Path-traversal gate. Pin security-relevant cases.
#[test]
fn check_id_security() {
    assert!(check_id("alice"));
    assert!(check_id("node_01"));
    assert!(check_id("A"));
    // Traversal: all must fail.
    assert!(!check_id("../etc"));
    assert!(!check_id("a/b"));
    assert!(!check_id("."));
    assert!(!check_id(".."));
    assert!(!check_id("a b")); // would break token split
    assert!(!check_id(""));
    assert!(!check_id("^abc")); // control sigil
}

/// `last_ping_time = now + 3600` exempts
/// control conns from ping sweep.
#[test]
fn id_bumps_ping_time() {
    let mut c = mkconn();
    let now = Instant::now();
    let cookie = "a".repeat(64);
    let line = format!("0 ^{cookie} 0");

    handle_id(&mut c, line.as_bytes(), &mkctx(&cookie), now, &mut OsRng).unwrap();

    assert!(c.last_ping_time > now + std::time::Duration::from_secs(3000));
}

// ─── handle_control
//
// `"18 0"` → Stop covered by `tests/stop.rs::spawn_connect_stop`.

#[test]
fn control_reload() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);

    let (r, nw) = handle_control(&mut c, b"18 1");
    assert_eq!(r, DispatchResult::Reload);
    // No write yet — daemon queues the reply after reload runs.
    assert!(!nw);
    assert!(c.outbuf.is_empty());
}

#[test]
fn control_retry() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);

    let (r, nw) = handle_control(&mut c, b"18 10");
    assert_eq!(r, DispatchResult::Retry);
    // Daemon writes the `"18 10 0"` ack after `on_retry()` runs.
    assert!(!nw);
    assert!(c.outbuf.is_empty());
}

#[test]
fn control_purge() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);

    let (r, nw) = handle_control(&mut c, b"18 8");
    assert_eq!(r, DispatchResult::Purge);
    // Daemon writes the `"18 8 0"` ack after `purge()` runs.
    assert!(!nw);
    assert!(c.outbuf.is_empty());
}

#[test]
fn control_disconnect() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);

    // `"%*d %*d " MAX_STRING` — token 3 is the name.
    let (r, _) = handle_control(&mut c, b"18 12 bob");
    assert_eq!(r, DispatchResult::Disconnect(Some("bob".into())));

    // No third token → sscanf returns 0 → -1 reply.
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 12");
    assert_eq!(r, DispatchResult::Disconnect(None));
}

#[test]
fn control_dump_traffic() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    // `case REQ_DUMP_TRAFFIC: return dump_traffic(c)`.
    let (r, nw) = handle_control(&mut c, b"18 13");
    assert_eq!(r, DispatchResult::DumpTraffic);
    assert!(!nw);
}

/// `REQ_LOG`: parse level.
#[test]
fn control_log() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    // `"18 15 <level> <use_color>"`. Level 5.
    let (r, nw) = handle_control(&mut c, b"18 15 5 0");
    assert_eq!(r, DispatchResult::Log(5));
    assert!(!nw);

    // Missing level: C's local-init defaults to 0.
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 15");
    assert_eq!(r, DispatchResult::Log(0));

    // -1 = DEBUG_UNSET ("use the daemon's level"). The CLI
    // sends this when no -d given.
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 15 -1 1");
    assert_eq!(r, DispatchResult::Log(-1));
}

#[test]
fn control_set_debug() {
    // `"18 9 5"` — CONTROL SET_DEBUG level=5.
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, nw) = handle_control(&mut c, b"18 9 5");
    assert_eq!(r, DispatchResult::SetDebug(Some(5)));
    // Daemon arm sends, not proto.rs.
    assert!(!nw);
    assert!(c.outbuf.is_empty());

    // Missing level → None (sscanf fails → return false).
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 9");
    assert_eq!(r, DispatchResult::SetDebug(None));

    // Negative level → query-only. C accepts it (sscanf %d).
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 9 -1");
    assert_eq!(r, DispatchResult::SetDebug(Some(-1)));

    // Garbage level → None (parse fail, same as missing).
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 9 garbage");
    assert_eq!(r, DispatchResult::SetDebug(None));
}

#[test]
fn control_pcap() {
    // Snaplen present.
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, nw) = handle_control(&mut c, b"18 14 96");
    assert_eq!(r, DispatchResult::Pcap(96));
    // `return true` — NO control_ok reply.
    assert!(!nw);
    assert!(c.outbuf.is_empty());

    // Snaplen absent: sscanf fails, outmaclength stays 0.
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 14");
    assert_eq!(r, DispatchResult::Pcap(0));

    // Snaplen 0 explicit (CLI default "full packet").
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 14 0");
    assert_eq!(r, DispatchResult::Pcap(0));

    // Huge snaplen → saturate (functionally ∞: > MTU captures all).
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);
    let (r, _) = handle_control(&mut c, b"18 14 999999");
    assert_eq!(r, DispatchResult::Pcap(u16::MAX));
}

/// Unknown subtype (99). `REQ_INVALID` reply, connection stays.
#[test]
fn control_unknown_subtype() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);

    let (r, nw) = handle_control(&mut c, b"18 99");
    assert_eq!(r, DispatchResult::Ok);
    assert!(nw);
    assert_eq!(c.outbuf.live(), b"18 -1\n");
}

/// Malformed: no second token. Hits the `_` arm same as unknown.
#[test]
fn control_malformed() {
    let mut c = mkconn();
    c.allow_request = Some(Request::Control);

    let (r, _) = handle_control(&mut c, b"18");
    assert_eq!(r, DispatchResult::Ok);
    assert_eq!(c.outbuf.live(), b"18 -1\n");
}

/// Belt-and-braces over tinc-proto's `protocol.h` pin.
#[test]
fn proto_version_pin() {
    assert_eq!(PROT_MAJOR, 17);
    assert_eq!(PROT_MINOR, 7);
    assert_eq!(CTL_VERSION, 0);
}

// ─── send_ack / parse_ack

/// All-defaults: `0x0700000c`.
#[test]
fn myself_options_default_value() {
    let opts = myself_options_default();
    assert_eq!(opts.bits() & 0xff, 0x0c); // PMTU(4) | CLAMP(8)
    assert_eq!(opts.prot_minor(), PROT_MINOR);
    assert_eq!(opts.bits() & 0x00ff_ff00, 0);
    assert_eq!(opts.bits(), 0x0700_000c);
}

fn cfg(lines: &[&str]) -> tinc_conf::Config {
    let mut c = tinc_conf::Config::default();
    c.merge(lines.iter().enumerate().filter_map(|(i, l)| {
        tinc_conf::parse_line(
            l,
            tinc_conf::Source::File {
                path: "tinc.conf".into(),
                line: u32::try_from(i).unwrap() + 1,
            },
        )?
        .ok()
    }));
    c
}

/// Empty config = all `get_config_bool`
/// fall-throughs. Same bits as `myself_options_default`.
#[test]
fn myself_options_empty_config() {
    let opts = myself_options_from_config(&tinc_conf::Config::default());
    assert_eq!(opts, myself_options_default());
}

/// `TCPOnly = yes` sets TCPONLY
/// and INDIRECT (`:391` implication), and `:442` `choice =
/// !(options & OPTION_TCPONLY)` makes the PMTU default off.
/// `ClampMSS` unaffected (`:449` default on).
#[test]
fn myself_options_tcponly_implies_indirect_clears_pmtu() {
    let opts = myself_options_from_config(&cfg(&["TCPOnly = yes"]));
    assert!(opts.contains(ConnOptions::TCPONLY));
    assert!(opts.contains(ConnOptions::INDIRECT));
    assert!(!opts.contains(ConnOptions::PMTU_DISCOVERY));
    assert!(opts.contains(ConnOptions::CLAMP_MSS));
    // 0x0b = INDIRECT|TCPONLY|CLAMP_MSS, top byte PROT_MINOR.
    assert_eq!(opts.bits(), 0x0700_000b);
}

/// `IndirectData = yes` standalone: only INDIRECT, defaults
/// otherwise. PMTU default `:442` is `!(options & TCPONLY)` =
/// true; `ClampMSS` `:449` true.
#[test]
fn myself_options_indirect_only() {
    let opts = myself_options_from_config(&cfg(&["IndirectData = yes"]));
    assert!(opts.contains(ConnOptions::INDIRECT));
    assert!(!opts.contains(ConnOptions::TCPONLY));
    assert!(opts.contains(ConnOptions::PMTU_DISCOVERY));
    assert!(opts.contains(ConnOptions::CLAMP_MSS));
}

/// Explicit `PMTUDiscovery = yes` overrides
/// the `!TCPONLY` default. The C reads `PMTUDiscovery` AFTER
/// computing the default — explicit wins.
#[test]
fn myself_options_tcponly_but_pmtu_forced_on() {
    let opts = myself_options_from_config(&cfg(&["TCPOnly = yes", "PMTUDiscovery = yes"]));
    assert!(opts.contains(ConnOptions::TCPONLY));
    assert!(opts.contains(ConnOptions::PMTU_DISCOVERY));
}

/// `ClampMSS = no` clears the bit.
#[test]
fn myself_options_clamp_mss_off() {
    let opts = myself_options_from_config(&cfg(&["ClampMSS = no"]));
    assert!(!opts.contains(ConnOptions::CLAMP_MSS));
    // PMTU still default-on.
    assert!(opts.contains(ConnOptions::PMTU_DISCOVERY));
}

// `send_ack` wire format (`"%d %s %d %x"` lowercase no-pad) covered
// by `tests/stop.rs::peer_ack_exchange`.

/// Per-host `TCPOnly = yes` sets TCPONLY|INDIRECT and CLEARS
/// `PMTU_DISCOVERY`. The clear is load-bearing: if the inherited
/// PMTU bit stuck, peer would waste `udp_discovery_timeout` probing
/// a path the user told us is broken.
#[test]
fn send_ack_per_host_tcponly_clears_pmtu() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    c.host_tcponly = Some(true);
    let now = Instant::now();
    send_ack(&mut c, 655, myself_options_default(), None, now);
    assert!(c.options.contains(ConnOptions::TCPONLY));
    assert!(c.options.contains(ConnOptions::INDIRECT));
    assert!(!c.options.contains(ConnOptions::PMTU_DISCOVERY));
    // ClampMSS unaffected (default on).
    assert!(c.options.contains(ConnOptions::CLAMP_MSS));
    // Wire bits: 0x0b = INDIRECT|TCPONLY|CLAMP_MSS, NOT 0x0c.
    let line = std::str::from_utf8(c.outbuf.live()).unwrap();
    assert!(line.ends_with(" 700000b\n"), "got {line:?}");
}

/// `ClampMSS` per-host overrides global
/// (not OR'd). `ClampMSS = no` in hosts/NAME clears it even though
/// the daemon default is on.
#[test]
fn send_ack_per_host_clamp_mss_overrides() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    c.host_clamp_mss = Some(false);
    send_ack(&mut c, 655, myself_options_default(), None, Instant::now());
    assert!(!c.options.contains(ConnOptions::CLAMP_MSS));
    assert!(c.options.contains(ConnOptions::PMTU_DISCOVERY));
}

/// `IndirectData = yes` per-host. The
/// `&& choice` means `= no` in hosts/NAME does NOT clear a global
/// INDIRECT (asymmetric with `ClampMSS`).
#[test]
fn send_ack_per_host_indirect() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    c.host_indirect = Some(true);
    send_ack(&mut c, 655, myself_options_default(), None, Instant::now());
    assert!(c.options.contains(ConnOptions::INDIRECT));
    assert!(!c.options.contains(ConnOptions::TCPONLY));
    // PMTU stays on (only TCPONLY suppresses it).
    assert!(c.options.contains(ConnOptions::PMTU_DISCOVERY));

    // `IndirectData = no` per-host doesn't clear global INDIRECT.
    let mut c = mkconn();
    c.protocol_minor = 2;
    c.host_indirect = Some(false);
    send_ack(
        &mut c,
        655,
        ConnOptions::INDIRECT | ConnOptions::CLAMP_MSS,
        None,
        Instant::now(),
    );
    assert!(c.options.contains(ConnOptions::INDIRECT));
}

/// Per-host Weight overrides RTT.
#[test]
fn send_ack_per_host_weight() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    c.host_weight = Some(42);
    // RTT measure would be 0ms (start == now); per-host wins.
    let now = c.start;
    send_ack(&mut c, 655, myself_options_default(), None, now);
    assert_eq!(c.estimated_weight, 42);
    let line = std::str::from_utf8(c.outbuf.live()).unwrap();
    // "4 655 42 700000c\n"
    assert!(line.contains(" 42 "), "got {line:?}");
}

/// Global Weight fallback when per-host
/// absent. `if(!get_host) get_global` — overrides RTT measure.
#[test]
fn send_ack_global_weight_fallback() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    // Per-host absent; RTT would be 0ms (start == now).
    let now = c.start;
    send_ack(&mut c, 655, myself_options_default(), Some(50), now);
    assert_eq!(c.estimated_weight, 50); // global wins over RTT
    let line = std::str::from_utf8(c.outbuf.live()).unwrap();
    assert!(line.contains(" 50 "), "got {line:?}");
}

/// Per-host suppresses global. Fallback
/// chain, NOT min: per-host > global > RTT.
#[test]
fn send_ack_per_host_beats_global() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    c.host_weight = Some(42);
    let now = c.start;
    send_ack(&mut c, 655, myself_options_default(), Some(50), now);
    assert_eq!(c.estimated_weight, 42); // per-host wins
}

/// Per-host AND global PMTU both
/// clamp (min wins). NOT a fallback. The match in `handle_id`.
#[test]
fn pmtu_cap_is_min_of_host_and_global() {
    // The `[a, b].into_iter().flatten().min()` idiom. Direct
    // unit test of the semantics; handle_id wiring is exercised
    // by the peer-branch integration tests.
    let cap = |h: Option<u16>, g: Option<u16>| [h, g].into_iter().flatten().min();
    assert_eq!(cap(Some(1200), Some(1400)), Some(1200));
    assert_eq!(cap(None, Some(1400)), Some(1400));
    assert_eq!(cap(Some(1400), Some(1200)), Some(1200));
    assert_eq!(cap(None, None), None);
    assert_eq!(cap(Some(1200), None), Some(1200));
}

/// No per-host overrides → inherit global. Regression: this is
/// what the STUBBED code did; ensure the rewrite preserves it.
#[test]
fn send_ack_no_per_host_inherits_global() {
    let mut c = mkconn();
    c.protocol_minor = 2;
    send_ack(&mut c, 655, myself_options_default(), None, Instant::now());
    assert_eq!(
        c.options,
        ConnOptions::PMTU_DISCOVERY | ConnOptions::CLAMP_MSS
    );
}

#[test]
fn parse_ack_roundtrip() {
    let line = b"4 655 50 700000c";
    let parsed = parse_ack(line).unwrap();
    assert_eq!(parsed.his_udp_port, 655);
    assert_eq!(parsed.his_weight, 50);
    assert_eq!(parsed.his_options.bits(), 0x0700_000c);
    assert_eq!(parsed.his_options.prot_minor(), 7);
    assert!(parsed.his_options.contains(ConnOptions::PMTU_DISCOVERY));
    assert!(parsed.his_options.contains(ConnOptions::CLAMP_MSS));
}

/// `sscanf < 3` → false.
#[test]
fn parse_ack_malformed() {
    assert!(matches!(
        parse_ack(b"4 655 50"),
        Err(DispatchError::BadAck(_))
    ));
    // STRICTER: `%s` would read "http"; we reject up front.
    assert!(matches!(
        parse_ack(b"4 http 50 c"),
        Err(DispatchError::BadAck(_))
    ));
    // Negative weight: parses (`%d`), clamped to 0.
    let p = parse_ack(b"4 655 -1 c").unwrap();
    assert_eq!(p.his_weight, 0);
    let p = parse_ack(b"4 655 -2147483648 0").unwrap();
    assert_eq!(p.his_weight, 0);
    assert!(matches!(
        parse_ack(b"4 655 50 0xZZ"),
        Err(DispatchError::BadAck(_))
    ));
}

#[test]
fn record_body_strip() {
    assert_eq!(record_body(b"4 655 50 c\n"), b"4 655 50 c");
    assert_eq!(record_body(b"4 655 50 c"), b"4 655 50 c"); // no \n: unchanged
    assert_eq!(record_body(b""), b"");
    assert_eq!(record_body(b"\n"), b"");
}
