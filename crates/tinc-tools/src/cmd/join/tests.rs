use super::finalize::split_var;
use super::wire::{parse_greeting_line1, parse_greeting_line2};
use super::*;

use crate::cmd::init;
use crate::cmd::invite;
use crate::keypair;
use crate::names::PathsInput;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use tinc_crypto::invite::{COOKIE_LEN, SLUG_LEN, SLUG_PART_LEN};
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps};

fn paths_at(dir: &Path) -> Paths {
    Paths::for_cli(&PathsInput {
        confbase: Some(dir.to_owned()),
        ..Default::default()
    })
}

// parse_url

/// `parse_url` Ok-path table: `(prefix, expected_host, expected_port)`.
/// The slug is appended; we only test host/port extraction here.
#[test]
fn url_ok() {
    let slug = "a".repeat(SLUG_LEN);
    #[rustfmt::skip]
        let cases: &[(&str, &str, &str)] = &[
            //          (prefix,               host,           port)
            ("host.example:1234/",  "host.example", "1234"),
            // default port
            ("host.example/",       "host.example", "655"),
            // IPv6 with brackets → brackets stripped
            ("[::1]:655/",          "::1",          "655"),
            // IPv6 no port
            ("[fe80::1]/",          "fe80::1",      "655"),
        ];
    for (prefix, host, port) in cases {
        let url = format!("{prefix}{slug}");
        let p = parse_url(&url).unwrap();
        assert_eq!(p.host, *host, "url: {url:?}");
        assert_eq!(p.port, *port, "url: {url:?}");
    }
}

#[test]
fn url_roundtrip_with_invite() {
    // Real URL from invite() — proves the producer/consumer agree.
    let dir = tempfile::tempdir().unwrap();
    let inviter = paths_at(&dir.path().join("inviter"));
    init::run(&inviter, "alice").unwrap();
    let mut h = fs::OpenOptions::new()
        .append(true)
        .open(inviter.host_file("alice"))
        .unwrap();
    writeln!(h, "Address = vpn.example").unwrap();
    drop(h);

    let r = invite::invite(&inviter, None, "bob", SystemTime::now()).unwrap();
    let p = parse_url(&r.url).unwrap();
    assert_eq!(p.host, "vpn.example");
    assert_eq!(p.port, "655");

    // The key_hash from the URL must match the invitation key on
    // disk. (This is the same check `invite_full_flow` does, but
    // through `parse_url` instead of `parse_slug`.)
    let inv_key = keypair::read_private(&inviter.invitation_key()).unwrap();
    assert_eq!(
        p.key_hash,
        tinc_crypto::invite::key_hash(inv_key.public_key())
    );
}

#[test]
fn url_err() {
    let long = "a".repeat(SLUG_LEN + 1);
    let bad_b64 = "!".repeat(SLUG_LEN); // `!` not in either b64 alphabet
    for url in [
        // bad slug length: short
        "host/short".to_owned(),
        // bad slug length: long
        format!("host/{long}"),
        // no slash at all
        "host:655".to_owned(),
        // 48 chars but not valid b64-url
        format!("host/{bad_b64}"),
    ] {
        assert!(parse_url(&url).is_none(), "url: {url:?}");
    }
}

// split_var — the C tokenizer

#[test]
fn split_var_forms() {
    assert_eq!(split_var("Port = 655"), Some(("Port", "655")));
    assert_eq!(split_var("Port=655"), Some(("Port", "655")));
    assert_eq!(split_var("Port\t655"), Some(("Port", "655")));
    assert_eq!(split_var("Port"), Some(("Port", "")));
    assert_eq!(split_var(""), None);
    assert_eq!(split_var(" "), None); // ws-only → empty key
    assert_eq!(split_var("=655"), None); // empty key (= at pos 0)
}

// greeting parsers

#[test]
fn greeting_line1() {
    assert!(parse_greeting_line1("0 alice 17.7").is_ok());
    assert!(parse_greeting_line1("0 alice 17").is_ok()); // no minor
    assert!(parse_greeting_line1("1 alice 17.7").is_err()); // wrong code
    assert!(parse_greeting_line1("0 alice 16.7").is_err()); // wrong major
    assert!(parse_greeting_line1("0 ../etc 17.7").is_err()); // bad name
    assert!(parse_greeting_line1("0 alice").is_err()); // no version
}

#[test]
fn greeting_line2() {
    assert_eq!(parse_greeting_line2("4 SOMEKEY").unwrap(), "SOMEKEY");
    assert!(parse_greeting_line2("3 KEY").is_err()); // wrong code (3=CHAL_REPLY)
    assert!(parse_greeting_line2("4 ").is_err()); // empty fingerprint
    assert!(parse_greeting_line2("4").is_err()); // no space
}

// finalize_join — the testable seam

/// Minimal valid blob: chunk 1 with Name only, no chunk 2.
/// Shouldn't happen in practice (invite always emits chunk 2)
/// but `finalize_join` must handle it — proves the chunk-2 loop
/// is a `while`, not a `do while`.
#[test]
fn finalize_minimal_blob() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let blob = b"Name = bob\n";
    let r = finalize_join(blob, &p, false).unwrap();

    assert_eq!(r.name, "bob");
    assert_eq!(r.pubkey_b64.len(), 43); // 32 bytes → 43 b64
    assert!(r.hosts_written.is_empty());

    // tinc.conf has just Name.
    assert_eq!(fs::read_to_string(p.tinc_conf()).unwrap(), "Name = bob\n");
    // hosts/bob has just the pubkey.
    let host = fs::read_to_string(p.host_file("bob")).unwrap();
    assert_eq!(host, format!("Ed25519PublicKey = {}\n", r.pubkey_b64));
    // Private key written, mode 0600, loadable.
    let mode = fs::metadata(p.ed25519_private())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let sk = keypair::read_private(&p.ed25519_private()).unwrap();
    // Pubkey from disk matches what's going back over SPTPS.
    assert_eq!(b64::encode(sk.public_key()), r.pubkey_b64);
}

/// `VAR_SAFE` filter. `Mode` is SERVER|SAFE → tinc.conf.
/// `Subnet` is HOST|MULTIPLE|SAFE → hosts/bob.
/// `Device` is SERVER but NOT SAFE → dropped (without --force).
#[test]
fn finalize_var_safe_filter() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let blob = b"\
Name = bob
Mode = switch
Subnet = 10.0.0.2/32
Device = /dev/net/tun
ConnectTo = alice
";
    let r = finalize_join(blob, &p, false).unwrap();

    let conf = fs::read_to_string(p.tinc_conf()).unwrap();
    // Mode (SERVER|SAFE) → tinc.conf. ConnectTo too.
    assert!(conf.contains("Mode = switch\n"));
    assert!(conf.contains("ConnectTo = alice\n"));
    // Device NOT in tinc.conf — it's not SAFE, dropped.
    assert!(!conf.contains("Device"));

    let host = fs::read_to_string(p.host_file("bob")).unwrap();
    // Subnet (HOST|SAFE) → hosts/bob.
    assert!(host.contains("Subnet = 10.0.0.2/32\n"));
    // Ed25519PublicKey appended after.
    assert!(host.contains(&format!("Ed25519PublicKey = {}\n", r.pubkey_b64)));
}

/// `--force` accepts unsafe vars (with a warning, which we don't
/// capture here — eprintln in lib code).
#[test]
fn finalize_force_accepts_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    // Device is SERVER but not SAFE.
    let blob = b"Name = bob\nDevice = /dev/evil\n";
    finalize_join(blob, &p, true).unwrap();

    let conf = fs::read_to_string(p.tinc_conf()).unwrap();
    assert!(conf.contains("Device = /dev/evil\n"));
}

/// Unknown vars dropped silently (well, with eprintln, but no error).
#[test]
fn finalize_unknown_var_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let blob = b"Name = bob\nNonexistentVariable = foo\n";
    finalize_join(blob, &p, false).unwrap();

    let conf = fs::read_to_string(p.tinc_conf()).unwrap();
    assert!(!conf.contains("Nonexistent"));
}

/// `Ifconfig`/`Route` are recognized (no "unknown variable" warning),
/// not acted on (stub). The placeholder tinc-up is what gets written.
#[test]
fn finalize_ifconfig_recognized_stubbed() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let blob = b"\
Name = bob
Ifconfig = 10.0.0.2/24
Route = 10.0.0.0/8
";
    finalize_join(blob, &p, false).unwrap();

    // Neither went anywhere — they're not in variables[], they're
    // not config lines. They WOULD have generated shell commands
    // in tinc-up.invitation. We just write the placeholder.
    let conf = fs::read_to_string(p.tinc_conf()).unwrap();
    assert!(!conf.contains("Ifconfig"));
    assert!(!conf.contains("Route"));

    // Placeholder tinc-up written, mode 0755.
    let up = p.tinc_up();
    let mode = fs::metadata(&up).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    let body = fs::read_to_string(up).unwrap();
    assert!(body.starts_with("#!/bin/sh"));
}

/// Chunk 2+: host files written verbatim (no SAFE filter), separator
/// dropped, multiple chunks.
#[test]
fn finalize_secondary_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let sep = invite::SEPARATOR;
    let blob = format!(
        "Name = bob\n\
             ConnectTo = alice\n\
             {sep}\n\
             Name = alice\n\
             Ed25519PublicKey = AAAA\n\
             Address = vpn.example\n\
             {sep}\n\
             Name = carol\n\
             Address = carol.example\n"
    );
    let r = finalize_join(blob.as_bytes(), &p, false).unwrap();

    assert_eq!(r.hosts_written, vec!["alice", "carol"]);

    // alice's host file: verbatim from chunk 2.
    let alice = fs::read_to_string(p.host_file("alice")).unwrap();
    assert_eq!(alice, "Ed25519PublicKey = AAAA\nAddress = vpn.example\n");
    // carol's: verbatim from chunk 3.
    let carol = fs::read_to_string(p.host_file("carol")).unwrap();
    assert_eq!(carol, "Address = carol.example\n");

    // bob's host file (chunk-1 HOST vars + pubkey): NO Address
    // (alice's Address went to alice's file, not bob's).
    let bob_host = fs::read_to_string(p.host_file("bob")).unwrap();
    assert!(!bob_host.contains("vpn.example"));
}

/// Secondary chunk with our own name → bail. Malicious inviter
/// trying to clobber our host file.
///
/// The blob shape matters: `Name = bob\nName = bob\n...` does NOT
/// trigger this — the second `Name = bob` matches `val == name`
/// and is `continue`'d *inside chunk 1*. You can only get to the
/// chunk-2 self-clobber check by first
/// breaking chunk-1 on a *different* name. The attack vector is
/// `chunk 2 = alice` (legit) then `chunk 3 = bob` (clobber).
#[test]
fn finalize_self_clobber_detected() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    // chunk 1: Name=bob. chunk 2: Name=alice (legit). chunk 3:
    // Name=bob — the clobber attempt.
    let blob = b"\
Name = bob
Name = alice
Address = x
Name = bob
Ed25519PublicKey = EVIL
";
    let err = finalize_join(blob, &p, false).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert!(msg.contains("overwrite our own"));
}

/// First line not `Name = X` → bail.
#[test]
fn finalize_no_name() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let err = finalize_join(b"Mode = switch\n", &p, false).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert!(msg.contains("No Name"));
}

/// Invalid name → bail. Same `check_id` as everywhere else.
#[test]
fn finalize_bad_name() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("vpn"));

    let err = finalize_join(b"Name = ../etc\n", &p, false).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert!(msg.contains("Invalid Name"));
}

/// tinc.conf already exists → bail before writing anything.
#[test]
fn finalize_existing_tinc_conf() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let p = paths_at(&confbase);
    fs::create_dir_all(&confbase).unwrap();
    fs::write(p.tinc_conf(), "Name = existing\n").unwrap();

    let err = finalize_join(b"Name = bob\n", &p, false).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert!(msg.contains("already exists"));
    // Nothing else touched.
    assert!(!p.host_file("bob").exists());
}

// server_receive_cookie — the daemon stub

/// Full server-side flow on a real invitation file from `invite()`.
#[test]
fn server_stub_recovers_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("inviter"));
    init::run(&p, "alice").unwrap();
    let mut h = fs::OpenOptions::new()
        .append(true)
        .open(p.host_file("alice"))
        .unwrap();
    writeln!(h, "Address = x").unwrap();
    drop(h);

    let r = invite::invite(&p, None, "bob", SystemTime::now()).unwrap();
    let parsed = parse_url(&r.url).unwrap();
    let inv_key = keypair::read_private(&p.invitation_key()).unwrap();

    let (contents, name, used_path) =
        server_receive_cookie(&p, &inv_key, &parsed.cookie, "alice", SystemTime::now()).unwrap();

    assert_eq!(name, "bob");
    // First line is `Name = bob`.
    let s = std::str::from_utf8(&contents).unwrap();
    assert!(s.starts_with("Name = bob\n"));
    // The .used file exists, original is gone.
    assert!(used_path.exists());
    // `.used` is literal; case-sensitive is the port-faithful
    // comparison.
    #[allow(clippy::case_sensitive_file_extension_comparisons)] // ".used": literal we wrote
    let has_used = used_path.to_str().unwrap().ends_with(".used");
    assert!(has_used);
}

/// Single-use: second call with same cookie → ENOENT → "non-existing".
#[test]
fn server_stub_single_use() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths_at(&dir.path().join("inviter"));
    init::run(&p, "alice").unwrap();
    let mut h = fs::OpenOptions::new()
        .append(true)
        .open(p.host_file("alice"))
        .unwrap();
    writeln!(h, "Address = x").unwrap();
    drop(h);

    let r = invite::invite(&p, None, "bob", SystemTime::now()).unwrap();
    let parsed = parse_url(&r.url).unwrap();
    let inv_key = keypair::read_private(&p.invitation_key()).unwrap();

    // First use: ok.
    server_receive_cookie(&p, &inv_key, &parsed.cookie, "alice", SystemTime::now()).unwrap();
    // Second use: file is gone (renamed to .used).
    let err = server_receive_cookie(&p, &inv_key, &parsed.cookie, "alice", SystemTime::now())
        .unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert!(msg.contains("non-existing"));
}

// The CONTRACT TEST: full invite ↔ join roundtrip, in-process

/// **The contract.** `invite()` writes a file → server stub reads
/// it → SPTPS ping-pong → `finalize_join` writes a confbase →
/// the confbase loads. No subprocess. No real socket. Two
/// `Sptps` structs ping-ponging.
///
/// This is the proof that:
/// 1. The invitation file format `cmd_invite` writes is the
///    format `finalize_join` reads. (`build_invitation_file` ↔
///    `finalize_join`'s parser agree on chunk boundaries,
///    SAFE filter, etc.)
/// 2. The SPTPS record-type protocol (0=data, 1=finalize,
///    2=ack) works end-to-end with our SPTPS state machine.
/// 3. The cookie→filename recovery in `server_receive_cookie`
///    matches `cmd_invite`'s filename derivation. (Already KAT-
///    tested in `tinc-crypto`, but this is the integration.)
/// 4. The pubkey we send back is the one on disk.
///
/// What this DOESN'T test: the meta-greeting exchange, the TCP
/// layer. Those need a real socket. The integration test in
/// `tinc_cli.rs` (when the daemon stub gets a listen socket)
/// will cover those. For now, the SPTPS layer + format layer
/// are the high-value seams.
#[test]
#[allow(
        // The test is long because it transcribes the full SPTPS
        // protocol — 4-phase handshake, cookie, file chunks, pubkey
        // echo, ack — with assertions at each step. Splitting would
        // mean threading 8 pieces of state through helpers; the
        // monolith is the readable form. Same justification as
        // `cmd_join` itself (also one function).
        clippy::too_many_lines,
        // ServerPhase enum defined inside the test body, after the
        // setup vars. Moving it before the `let dir = ...` would
        // separate it from its sole use site by 60 lines.
        clippy::items_after_statements,
    )]
fn invite_join_roundtrip_in_process() {
    let dir = tempfile::tempdir().unwrap();

    // ─── Inviter side: alice invites bob
    let inviter = paths_at(&dir.path().join("inviter"));
    init::run(&inviter, "alice").unwrap();
    {
        let mut h = fs::OpenOptions::new()
            .append(true)
            .open(inviter.host_file("alice"))
            .unwrap();
        writeln!(h, "Address = vpn.example").unwrap();
    }
    // Add a Mode (SERVER|SAFE) so we exercise the chunk-1 filter.
    {
        let mut tc = fs::OpenOptions::new()
            .append(true)
            .open(inviter.tinc_conf())
            .unwrap();
        writeln!(tc, "Mode = switch").unwrap();
    }

    let inv_result = invite::invite(&inviter, Some("acme"), "bob", SystemTime::now()).unwrap();
    let parsed = parse_url(&inv_result.url).unwrap();

    // Load invitation key. Both the server stub and the joiner's
    // SPTPS need it (server uses it as identity; joiner uses
    // its pubkey to verify key_hash and as `hiskey`).
    let inv_key = keypair::read_private(&inviter.invitation_key()).unwrap();
    let inv_pub = *inv_key.public_key();

    // ─── Joiner setup
    let joiner_paths = paths_at(&dir.path().join("joiner"));
    let throwaway = keypair::generate();
    let throwaway_pub = *throwaway.public_key();

    // ─── Start both SPTPS sessions
    // Joiner = initiator. Server = responder. Stream framing.
    // Same label, same as the C wire bytes.
    let (mut joiner, j_init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        throwaway,
        inv_pub,
        INVITE_LABEL,
        0,
        &mut OsRng,
    );
    let (mut server, s_init) = Sptps::start(
        Role::Responder,
        Framing::Stream,
        // The server's full SigningKey is the invitation key.
        // We just loaded it; clone via blob roundtrip (no Clone
        // on SigningKey, by design — keys shouldn't be copied
        // casually).
        SigningKey::from_blob(&inv_key.to_blob()),
        throwaway_pub,
        INVITE_LABEL,
        0,
        &mut OsRng,
    );

    // ─── The pump
    // Two unidirectional byte queues. `Output::Wire` from one
    // side → enqueue → `receive()` on the other. Loop until both
    // queues are empty AND no new wire bytes were produced
    // (steady state).
    //
    // State tracked across the loop, mirroring the C globals:
    //   data: type-0 record accumulator (joiner side)
    //   server_phase: what the server expects next
    //   join_result: filled when type-1 arrives, used after loop
    //   success: type-2 arrived
    let mut to_server: Vec<u8> = Vec::new();
    let mut to_joiner: Vec<u8> = Vec::new();

    let mut data: Vec<u8> = Vec::new();
    let mut join_result: Option<JoinResult> = None;
    let mut success = false;

    // Server protocol state. The C uses `c->status.invitation_used`
    // to gate "have we sent the file yet". We're more explicit.
    #[derive(PartialEq, Debug)]
    enum ServerPhase {
        WaitCookie, // expect type-0 with cookie
        WaitPubkey, // file sent, expect type-1 with joiner's pubkey
        Done,       // type-2 sent
    }
    let mut server_phase = ServerPhase::WaitCookie;
    let mut joiner_pubkey: Option<String> = None;

    // Seed the queues with the initial KEX bytes from start().
    for o in j_init {
        if let Output::Wire { bytes, .. } = o {
            to_server.extend_from_slice(&bytes);
        }
    }
    for o in s_init {
        if let Output::Wire { bytes, .. } = o {
            to_joiner.extend_from_slice(&bytes);
        }
    }

    // Pending sends — records to push AFTER draining a receive's
    // outputs. We can't `send_record` *inside* the drain loop
    // because the drain loop is iterating Outputs from the same
    // Sptps. Same constraint as `pubkey_to_send` in `join()`.
    let mut joiner_pending: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut server_pending: Vec<(u8, Vec<u8>)> = Vec::new();

    // Loop bound. The handshake is 4 round trips, the file is
    // a few records, the pubkey echo is 1. If we loop 100 times
    // something's wedged.
    for _iter in 0..100 {
        if to_server.is_empty()
            && to_joiner.is_empty()
            && joiner_pending.is_empty()
            && server_pending.is_empty()
        {
            break;
        }

        // ─── Server processes its inbox
        if !to_server.is_empty() {
            let inp = std::mem::take(&mut to_server);
            let mut off = 0;
            while off < inp.len() {
                let (n, outs): (usize, Vec<Output>) =
                    server.receive(&inp[off..], &mut OsRng).unwrap();
                if n == 0 {
                    to_server.extend_from_slice(&inp[off..]);
                    break;
                }
                off += n;
                for o in outs {
                    match o {
                        Output::Wire { bytes, .. } => {
                            to_joiner.extend_from_slice(&bytes);
                        }
                        Output::HandshakeDone => {
                            // Server doesn't act on handshake-done;
                            // the joiner sends the cookie unprompted.
                            // The daemon swallows handshake records
                            // (type 128 → return true).
                        }
                        Output::Record {
                            record_type: 0,
                            bytes,
                        } if server_phase == ServerPhase::WaitCookie => {
                            // `type != 0 || len != 18` → fail.
                            assert_eq!(bytes.len(), COOKIE_LEN);
                            let mut cookie = [0u8; COOKIE_LEN];
                            cookie.copy_from_slice(&bytes);

                            // Recover the file. (KAT-tested
                            // composition.)
                            let (contents, name, used) = server_receive_cookie(
                                &inviter,
                                &inv_key,
                                &cookie,
                                "alice",
                                SystemTime::now(),
                            )
                            .unwrap();
                            assert_eq!(name, "bob");

                            // Send file in 1024-byte chunks as
                            // type-0.
                            // We chunk at 512 to exercise the
                            // joiner's accumulator (proves it
                            // handles multi-record data).
                            for chunk in contents.chunks(512) {
                                server_pending.push((0, chunk.to_vec()));
                            }
                            // type-1, zero-len: the "finalize"
                            // trigger.
                            server_pending.push((1, Vec::new()));
                            // `unlink(usedname)`.
                            fs::remove_file(used).unwrap();
                            server_phase = ServerPhase::WaitPubkey;
                        }
                        Output::Record {
                            record_type: 1,
                            bytes,
                        } if server_phase == ServerPhase::WaitPubkey => {
                            // `return finalize_invitation(...)`.
                            // Body: `fprintf(f, "Ed25519PublicKey
                            // = %s\n", data)` then `sptps_send
                            // _record(&c->sptps, 2, data, 0)`.
                            let pk = String::from_utf8(bytes).unwrap();
                            assert_eq!(pk.len(), 43);
                            joiner_pubkey = Some(pk);
                            // type-2, zero-len. The ack.
                            server_pending.push((2, Vec::new()));
                            server_phase = ServerPhase::Done;
                        }
                        Output::Record { record_type, .. } => {
                            panic!(
                                "unexpected server-side record type {record_type} \
                                     in phase {server_phase:?}"
                            );
                        }
                    }
                }
            }
        }

        // Flush server's pending sends.
        for (ty, body) in server_pending.drain(..) {
            for o in server.send_record(ty, &body).unwrap() {
                if let Output::Wire { bytes, .. } = o {
                    to_joiner.extend_from_slice(&bytes);
                }
            }
        }

        // ─── Joiner processes its inbox
        // This is `cmd_join`'s SPTPS loop, transcribed for in-
        // process testing. Same structure: type-0 accumulate,
        // type-1 finalize, type-2 success.
        if !to_joiner.is_empty() {
            let inp = std::mem::take(&mut to_joiner);
            let mut off = 0;
            while off < inp.len() {
                let (n, outs): (usize, Vec<Output>) =
                    joiner.receive(&inp[off..], &mut OsRng).unwrap();
                if n == 0 {
                    to_joiner.extend_from_slice(&inp[off..]);
                    break;
                }
                off += n;
                for o in outs {
                    match o {
                        Output::Wire { bytes, .. } => {
                            to_server.extend_from_slice(&bytes);
                        }
                        Output::HandshakeDone => {
                            // Send cookie.
                            joiner_pending.push((0, parsed.cookie.to_vec()));
                        }
                        Output::Record {
                            record_type: 0,
                            bytes,
                        } => {
                            data.extend_from_slice(&bytes);
                        }
                        Output::Record { record_type: 1, .. } => {
                            // The seam.
                            let r = finalize_join(&data, &joiner_paths, false).unwrap();
                            joiner_pending.push((1, r.pubkey_b64.clone().into_bytes()));
                            join_result = Some(r);
                        }
                        Output::Record { record_type: 2, .. } => {
                            success = true;
                        }
                        Output::Record { record_type, .. } => {
                            panic!("unexpected joiner record type {record_type}");
                        }
                    }
                }
            }
        }

        for (ty, body) in joiner_pending.drain(..) {
            for o in joiner.send_record(ty, &body).unwrap() {
                if let Output::Wire { bytes, .. } = o {
                    to_server.extend_from_slice(&bytes);
                }
            }
        }
    }

    // ─── Asserts
    assert!(success, "type-2 never arrived; pump stalled");
    assert_eq!(server_phase, ServerPhase::Done);
    let r = join_result.unwrap();

    // 1. Joiner's confbase is populated. tinc.conf has Name +
    //    Mode (the SAFE var that threaded through).
    let conf = fs::read_to_string(joiner_paths.tinc_conf()).unwrap();
    assert!(conf.starts_with("Name = bob\n"));
    assert!(conf.contains("Mode = switch\n"));
    assert!(conf.contains("ConnectTo = alice\n"));

    // 2. Joiner's hosts/alice has alice's pubkey (from chunk 2).
    //    This is the "secondary chunk written verbatim" half.
    let alice_host = fs::read_to_string(joiner_paths.host_file("alice")).unwrap();
    assert!(alice_host.contains("Ed25519PublicKey = "));
    assert!(alice_host.contains("Address = vpn.example"));

    // 3. Joiner's private key loads. Same key as the pubkey
    //    that went back over SPTPS.
    let sk = keypair::read_private(&joiner_paths.ed25519_private()).unwrap();
    assert_eq!(b64::encode(sk.public_key()), r.pubkey_b64);
    assert_eq!(joiner_pubkey.unwrap(), r.pubkey_b64);

    // 4. Joiner's hosts/bob has bob's pubkey — the same one.
    let bob_host = fs::read_to_string(joiner_paths.host_file("bob")).unwrap();
    assert!(bob_host.contains(&format!("Ed25519PublicKey = {}\n", r.pubkey_b64)));

    // 5. Inviter's invitation file is GONE (renamed + unlinked).
    //    Single-use enforced.
    let inv_dir = inviter.invitations_dir();
    let leftover: Vec<_> = fs::read_dir(&inv_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.len() == SLUG_PART_LEN)
        .collect();
    assert!(
        leftover.is_empty(),
        "invitation file should be consumed: {leftover:?}"
    );

    // 6. fsck passes on the joiner's confbase. The contract:
    //    join produces a confbase that fsck approves of. If join
    //    ever writes something fsck flags, this fires.
    let report = crate::cmd::fsck::run(&joiner_paths, false).unwrap();
    assert!(
        report.ok,
        "join should produce fsck-clean confbase: {:?}",
        report.findings
    );
}
