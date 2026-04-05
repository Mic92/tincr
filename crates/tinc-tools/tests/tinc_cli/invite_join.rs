use super::{bare_dir, init_dir, tinc, tinc_stdin};
use std::io::Write;

/// Full flow through the binary: init, append Address, invite.
/// URL on stdout, warning on stderr, exit 0.
///
/// This is also the **fsck contract test for invite**: the
/// invitation key must NOT trip fsck. If fsck started warning about
/// `invitations/ed25519_key.priv` (e.g. by being too aggressive
/// about "what's this private key file doing here"), this test
/// would catch it.
#[test]
fn invite_prints_url() {
    let (_dir, confbase, cb) = init_dir("alice");

    // Add Address (init doesn't write it; invite needs it).
    let mut h = std::fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("hosts/alice"))
        .unwrap();
    writeln!(h, "Address = invite-test.example").unwrap();
    drop(h);

    let out = tinc(&["-c", &cb, "invite", "bob"]);
    assert!(out.status.success(), "invite failed: {out:?}");

    // URL on stdout, exactly one line, no other noise.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let url = stdout.trim();
    assert!(!url.is_empty());
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout should be exactly one line: {stdout:?}"
    );
    assert!(
        url.starts_with("invite-test.example:655/"),
        "url was: {url}"
    );
    let slug = url.rsplit('/').next().unwrap();
    assert_eq!(
        slug.len(),
        tinc_crypto::invite::SLUG_LEN,
        "slug should be 48 chars: {slug}"
    );
    // Slug parses (proves it's valid b64-urlsafe, not just 48 chars).
    assert!(tinc_crypto::invite::parse_slug(slug).is_some());

    // Warning on stderr (key was freshly generated, daemon needs
    // restart). The C phrasing.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restart or reload"), "stderr was: {stderr}");

    // ─── fsck contract ───
    // The invitation key + invitation file should NOT trip fsck.
    // fsck only checks the node's OWN key (ed25519_key.priv at
    // confbase root), not invitation keys. If fsck's path glob
    // got too broad, this fires.
    let out = tinc(&["-c", &cb, "fsck"]);
    assert!(
        out.status.success(),
        "fsck should pass after invite: {out:?}"
    );
    assert!(
        out.stderr.is_empty(),
        "fsck should be silent: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// invite without Address → exit 1, clear message, no files left.
#[test]
fn invite_no_address() {
    let (_dir, confbase, cb) = init_dir("alice");
    // Don't add Address.

    let out = tinc(&["-c", &cb, "invite", "bob"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No Address"), "{stderr}");
    assert!(stderr.contains("set Address"), "{stderr}");

    // No invitations/ dir created. Our reorder vs C: we check
    // Address BEFORE makedirs. C checks late and leaves debris.
    assert!(
        !confbase.join("invitations").exists(),
        "no-Address failure should leave no trace"
    );
}

/// `-n NETNAME` reaches the invitation file. The Globals.netname
/// thread-through. Unit test can't see this — it doesn't go through
/// argv.
#[test]
fn invite_netname_threads_through() {
    let dir = tempfile::tempdir().unwrap();
    // -n NETNAME → confbase = CONFDIR/tinc/NETNAME, but we override
    // with -c. The "both given" warning fires; confbase wins for path
    // resolution. The netname global is STILL set even when
    // confbasegiven is true (the invite handler reads it
    // unconditionally), so it threads through to the NetName= line.
    let cb = dir.path().join("vpn");
    let cb_s = cb.to_str().unwrap();

    let out = tinc(&["-c", cb_s, "-n", "mymesh", "init", "alice"]);
    assert!(out.status.success());
    let mut h = std::fs::OpenOptions::new()
        .append(true)
        .open(cb.join("hosts/alice"))
        .unwrap();
    writeln!(h, "Address = x").unwrap();
    drop(h);

    let out = tinc(&["-c", cb_s, "-n", "mymesh", "invite", "bob"]);
    assert!(out.status.success(), "{out:?}");

    // Read the invitation file. Only one 24-char-named file in
    // invitations/ (the key is 16 chars).
    let inv_dir = cb.join("invitations");
    let inv_file = std::fs::read_dir(&inv_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.len() == tinc_crypto::invite::SLUG_PART_LEN)
        })
        .unwrap();
    let body = std::fs::read_to_string(inv_file).unwrap();

    // NetName line is in chunk 1.
    assert!(
        body.contains("NetName = mymesh\n"),
        "NetName should be threaded: {body}"
    );
}

#[test]
fn invite_missing_arg() {
    let (_dir, cb) = bare_dir();
    let out = tinc(&["-c", &cb, "invite"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("node name"));
}

// ────────────────────────────────────────────────────────────────────
// join through the binary
// ────────────────────────────────────────────────────────────────────
//
// What this proves over the unit tests in `cmd/join.rs`: argv
// parsing (`tinc join URL` vs `echo URL | tinc join`), exit-code
// mapping, the preflight checks running BEFORE TCP connect attempts.
//
// What this does NOT prove: the actual TCP+SPTPS path. That needs a
// server. The in-process roundtrip in `cmd/join.rs` covers the SPTPS
// + format layer; a real-socket test waits for either (a) a daemon
// stub that listens, or (b) cross-impl against the C daemon. Both
// are TODO. The pieces below that path — URL parse, preflight,
// `finalize_join`, `server_receive_cookie` — are all unit-covered.

/// Bad URL → exit 1 with the C's exact message, no TCP attempted.
/// The "Invalid invitation URL." message is the C error; matching
/// it means existing docs/forum posts apply.
#[test]
fn join_bad_url() {
    let (_dir, cb) = bare_dir();
    let out = tinc(&["-c", &cb, "join", "not-a-url"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Invalid invitation URL"), "{stderr}");
}

/// tinc.conf already exists → fail BEFORE attempting connect. The
/// preflight check. This is important because the cookie is single-
/// use on the daemon side; failing here means the cookie isn't burned.
///
/// We use `127.0.0.1:1` (port 1 is tcpmux, almost never bound) as
/// the URL host so if the preflight DOESN'T fire we get a fast
/// connection-refused instead of a DNS timeout. The test asserts
/// the *preflight* error, not the connect error.
#[test]
fn join_existing_config_fails_early() {
    let (_dir, _confbase, cb) = init_dir("alice");

    // Valid-shape URL pointing nowhere. 48 'a's decode to valid b64.
    let slug = "a".repeat(tinc_crypto::invite::SLUG_LEN);
    let url = format!("127.0.0.1:1/{slug}");

    let out = tinc(&["-c", &cb, "join", &url]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // "already exists", NOT "connection refused". Preflight fired.
    assert!(
        stderr.contains("already exists"),
        "preflight should fail before connect: {stderr}"
    );
    assert!(
        !stderr.contains("connect"),
        "should not have attempted connect: {stderr}"
    );
}

/// URL via stdin. `echo URL | tinc join`. The handler
/// `fgets(line, ..., stdin)`.
#[test]
fn join_url_from_stdin() {
    let (_dir, cb) = bare_dir();
    // Feed a bad URL via stdin to prove the stdin path is wired.
    // (We can't feed a *good* URL without a server.)
    let out = tinc_stdin(&["-c", &cb, "join"], b"garbage-url\n");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // The URL was parsed (and rejected) — stdin reached parse_url.
    assert!(stderr.contains("Invalid invitation URL"), "{stderr}");
}
