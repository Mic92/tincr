//! Rust↔Rust SPTPS over a real socket. Spawns `sptps_keypair` and
//! `sptps_test` as subprocesses — same shape as
//! `test/integration/sptps_basic.py`, but in `cargo test` so it lives
//! next to the unit tests, runs with the rest of CI, and can use real
//! timeouts instead of `wait $pid` and hoping.
//!
//! ## What this proves
//!
//! `tinc-sptps/tests/vs_c.rs` is the gold standard for *correctness*:
//! same RNG seed both sides, byte-identical wire output, in-process.
//! But "in-process with seeded RNG" misses everything the daemon will
//! actually face:
//!
//!   - **`OsRng`** — first time real entropy flows through the key
//!     derivation. Seeded ChaCha is great for differential testing
//!     and useless for catching "we accidentally hardcoded the seed".
//!   - **PEM key files end-to-end** — generate → write → read → use.
//!     `tinc-conf::pem` round-trips bytes; this round-trips a *key
//!     that signs*.
//!   - **Kernel socket** — TCP can split a `send()` across multiple
//!     `recv()`s, coalesce two `send()`s into one `recv()`, deliver
//!     short reads. The SPTPS stream framing has to survive that. The
//!     in-process test pumps whole records.
//!   - **The poll() loop** — the actual binary entry point, fd
//!     plumbing, EOF detection. No way to unit-test that without
//!     spawning the binary.
//!
//! ## Cross-impl with C
//!
//! Set `TINC_C_SPTPS_TEST` and `TINC_C_SPTPS_KEYPAIR` to enable the
//! `cross_*` tests below. They run a 2×2 matrix — each role (server,
//! client) can be Rust or C, four combinations × two modes. If the env
//! var is unset, those tests skip (return early; libtest has no proper
//! skip status, so they show as "passed" — the test name says `cross_`
//! so you know to set the var if you care).
//!
//! `nix build .#sptps-test-c` builds the C side in nolegacy mode (no
//! openssl). To run locally:
//!
//! ```sh
//! C=$(nix build .#sptps-test-c --no-link --print-out-paths)
//! TINC_C_SPTPS_TEST=$C/bin/sptps_test \
//! TINC_C_SPTPS_KEYPAIR=$C/bin/sptps_keypair \
//!   cargo test -p tinc-tools cross
//! ```
//!
//! Why we couldn't just reuse `test/integration/sptps_basic.py`: it
//! only knows one `SPTPS_TEST_PATH`. Same impl both sides. The whole
//! point of cross-impl is *different* impls per role.
//!
//! ## The UDP-has-no-FIN problem
//!
//! Stream mode: client closes socket, server's `recv()` returns 0,
//! server prints "Connection terminated by peer." and exits cleanly.
//!
//! Datagram mode: client closes socket, server's `recv()`… blocks
//! forever. UDP has no connection teardown. `sptps_basic.py` deals with
//! this by reading the expected number of bytes from the server's
//! stdout and then `server.kill()`. We do the same — kill the server
//! after we've read what we sent. That's not a hack; it's the only
//! correct behavior for a UDP listener with no application-layer
//! goodbye message.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
// Backticking proper nouns reads like a ransom note. Same allow as
// tinc-crypto/tinc-sptps.
#![allow(clippy::doc_markdown)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Find the binary cargo built. `CARGO_BIN_EXE_<name>` is set by cargo
/// for integration tests when the crate has a `[[bin]]` of that name —
/// the documented way to find your own binaries from `tests/`. Falls
/// back to relative-path probing for `cargo build && cargo test` where
/// the env var might not be set (it should be, but belt-and-braces).
fn bin(name: &str) -> PathBuf {
    if let Ok(p) = std::env::var(format!("CARGO_BIN_EXE_{name}")) {
        return PathBuf::from(p);
    }
    // Integration tests run from `target/{profile}/deps/`; the bins
    // are one level up. `current_exe()` → strip `deps/` → append name.
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("parent");
    let profile = deps.parent().expect("profile dir");
    profile.join(name)
}

/// Which binaries to spawn. Everything else in this file works on the
/// CLI surface (argv, stdin/stdout, the `Listening on N...` line), so
/// swapping the binary path is the entire interface for cross-impl.
#[derive(Clone, Copy)]
enum Impl {
    Rust,
    C,
}

impl Impl {
    fn sptps_test(self) -> Option<PathBuf> {
        match self {
            Impl::Rust => Some(bin("sptps_test")),
            // `ok()`: unset env var → None → caller skips. `var_os`
            // not `var` — store paths can have any bytes (they don't
            // in practice, but `var` would panic on non-UTF-8 and
            // that's a needlessly brittle dep).
            Impl::C => std::env::var_os("TINC_C_SPTPS_TEST").map(PathBuf::from),
        }
    }
    fn sptps_keypair(self) -> Option<PathBuf> {
        match self {
            Impl::Rust => Some(bin("sptps_keypair")),
            Impl::C => std::env::var_os("TINC_C_SPTPS_KEYPAIR").map(PathBuf::from),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Impl::Rust => "rust",
            Impl::C => "c",
        }
    }
}

/// Generate a keypair via the `sptps_keypair` binary. Going through the
/// binary (not `keypair::generate()` directly) is the point: it tests
/// the binary's argv handling and the on-disk PEM format.
///
/// `who` picks which impl writes the key. The cross-impl matrix uses
/// this too: a key generated by C `sptps_keypair` should be readable
/// by the Rust `sptps_test`, and vice versa. That's a separate axis
/// from "can they handshake" — it's "do they agree on the PEM format".
fn gen_keys(who: Impl, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let priv_path = dir.join(format!("{name}.priv"));
    let pub_path = dir.join(format!("{name}.pub"));
    let status = Command::new(who.sptps_keypair().unwrap())
        .arg(&priv_path)
        .arg(&pub_path)
        .status()
        .expect("spawn sptps_keypair");
    assert!(status.success(), "sptps_keypair failed");
    (priv_path, pub_path)
}

/// Parse `Listening on N...` from a child's stderr. This is the same
/// regex `sptps_basic.py` uses; the line format is API.
///
/// **Takes `&mut`, not by value.** The caller MUST keep the stderr
/// handle alive for the child's lifetime. If the read end of the pipe
/// drops, the child's next `eprintln!` gets `EPIPE` → `SIGPIPE` →
/// dead server. We learned this the empirical way: `wait_for_port`
/// returned the port, the client connected, the server `accept()`ed,
/// then the server `eprintln!("Connected")` and died. 0.01s test
/// duration was the tell — too fast for any real I/O.
fn wait_for_port(stderr: &mut impl Read) -> u16 {
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read stderr");
        assert!(n != 0, "server stderr closed without Listening line");
        // C: `fprintf(stderr, "Listening on %d...\n", port);`
        if let Some(rest) = line.trim().strip_prefix("Listening on ")
            && let Some(num) = rest.strip_suffix("...")
        {
            return num.parse().expect("port number");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for Listening line"
        );
    }
}

/// Read exactly `n` bytes from a child's stdout, with a deadline.
/// `read_exact` would block past the deadline; we loop on `read` and
/// check the clock. `sptps_basic.py` does the same with its `while
/// len(received) < len(DATA)` loop.
fn read_n(stdout: &mut impl Read, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    while out.len() < n {
        assert!(
            Instant::now() < deadline,
            "timed out: have {} of {n} bytes",
            out.len()
        );
        let want = (n - out.len()).min(buf.len());
        match stdout.read(&mut buf[..want]) {
            Ok(0) => panic!(
                "server stdout closed early: have {} of {n} bytes",
                out.len()
            ),
            Ok(k) => out.extend_from_slice(&buf[..k]),
            // EAGAIN can't happen on a blocking pipe; treat any error
            // as fatal. The deadline above handles hangs.
            Err(e) => panic!("read server stdout: {e}"),
        }
    }
    out
}

/// `try_wait` poll with deadline → `kill`. The graceful path for
/// stream mode. If the child doesn't exit on its own (UDP, or a
/// genuine hang), kill it so the test doesn't leave processes behind.
fn reap(mut child: Child, expect_clean: bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                if expect_clean {
                    assert!(status.success(), "child exited non-zero: {status:?}");
                }
                return;
            }
            None if Instant::now() >= deadline => {
                // UDP: expected. Stream: bug. Either way, kill so the
                // test ends. The `expect_clean` assert above won't fire
                // because `kill` → `wait` returns the SIGKILL status,
                // which we don't check.
                let _ = child.kill();
                let _ = child.wait();
                assert!(
                    !expect_clean,
                    "child didn't exit cleanly within 2s (TCP server hung?)"
                );
                return;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// One round-trip: server listens, client connects + sends, we diff.
/// Returns the bytes the server wrote to stdout.
///
/// `server_impl`/`client_impl` pick which binary plays which role.
/// Everything else — argv, port discovery, the SIGPIPE drain thread —
/// is identical regardless of impl, because both impls speak the same
/// CLI. That symmetry is the test design: if the harness doesn't care
/// which is which, then any failure is a wire-level disagreement, not
/// a harness artifact.
#[allow(clippy::too_many_arguments)] // 8 is fine; a struct here would just move the names
fn roundtrip(
    server_impl: Impl,
    client_impl: Impl,
    server_priv: &Path,
    client_pub: &Path,
    client_priv: &Path,
    server_pub: &Path,
    data: &[u8],
    flags: &[&str],
) -> Vec<u8> {
    // Server: `sptps_test -4 -r [flags] server.priv client.pub 0`
    //   -4: IPv4 (avoids dual-stack flakiness in CI)
    //   -r: readonly — don't poll stdin (we're not feeding it any)
    //   port 0: kernel picks
    let mut server = Command::new(server_impl.sptps_test().unwrap())
        .arg("-4")
        .arg("-r")
        .args(flags)
        .arg(server_priv)
        .arg(client_pub)
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");

    // Hold stderr for the server's lifetime. See `wait_for_port` doc
    // for why dropping it kills the server.
    let mut server_stderr = server.stderr.take().expect("stderr piped");
    let port = wait_for_port(&mut server_stderr);

    // Client: `sptps_test -4 -q [flags] client.priv server.pub localhost PORT`
    //   -q: quit on stdin EOF (after we close the pipe)
    let mut client = Command::new(client_impl.sptps_test().unwrap())
        .arg("-4")
        .arg("-q")
        .args(flags)
        .arg(client_priv)
        .arg(server_pub)
        .arg("localhost")
        .arg(port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    // Push data, close pipe → client sees EOF → exits (-q).
    {
        let mut stdin = client.stdin.take().expect("stdin piped");
        stdin.write_all(data).expect("write client stdin");
        // Drop closes the pipe — that's the EOF.
    }

    // Read exactly len(data) from server stdout. Stream mode: this is
    // one or two SPTPS records' worth depending on TCP coalescing.
    // Datagram: one record per stdin read (≤1460 bytes), so one record
    // for our 256.
    let mut server_stdout = server.stdout.take().expect("stdout piped");
    let received = read_n(&mut server_stdout, data.len());

    // Client should exit cleanly: -q → break on EOF → ExitCode::SUCCESS.
    // If the client hung, that's a real bug — its `-q` path failed.
    let client_status = client.wait().expect("client wait");
    assert!(
        client_status.success(),
        "client exited non-zero: {client_status:?}\nstderr: {}",
        {
            let mut s = String::new();
            client
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut s)
                .unwrap();
            s
        }
    );

    // Server: stream mode exits cleanly when client closes the TCP
    // socket. Datagram mode never exits on its own — kill it.
    let datagram = flags.contains(&"-d");
    // For stream mode the server also `eprintln!("Connection terminated
    // by peer.")` on shutdown — if we drop server_stderr before reap,
    // SIGPIPE again. Spawn a drain thread: it reads to EOF, which only
    // arrives when the server exits (or is killed). Join after reap.
    let drain = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = server_stderr.read_to_end(&mut sink);
        sink // for diagnostics if reap asserts
    });
    reap(server, !datagram);
    let _ = drain.join();

    received
}

// ────────────────────────────────────────────────────────────────────

/// 256 bytes, same as `sptps_basic.py`. The size matters less than
/// "nonzero and not all zeroes" — we want decryption failures to be
/// loud (all-zero plaintext could mask a bad-key-but-same-tag bug,
/// vanishingly unlikely but cheap to avoid).
fn payload() -> Vec<u8> {
    (0..=255).collect()
}

/// Common scenario: gen two keypairs, push `data`, diff against what
/// the server received. The (server_impl, client_impl) pair is the
/// independent variable. Returns true if it ran, false if it skipped
/// (C binary not available).
///
/// **Key generator follows the loader.** Server keypair is generated by
/// `server_impl`, client keypair by `client_impl`. Why: the *private*
/// key is loaded by the same impl that generated it, so PEM-format
/// disagreement on the private side won't break the handshake — only
/// the public key crosses impls (server reads client's public, client
/// reads server's public). That's the relevant cross-impl PEM test.
/// `cross_pem_read` below tests private-key cross-reads explicitly.
fn scenario(server: Impl, client: Impl, data: &[u8], flags: &[&str]) -> bool {
    let (Some(_), Some(_)) = (server.sptps_test(), client.sptps_test()) else {
        eprintln!(
            "SKIP: TINC_C_SPTPS_TEST not set ({} server, {} client)",
            server.label(),
            client.label()
        );
        return false;
    };
    let dir = tempfile::tempdir().unwrap();
    let (s_priv, s_pub) = gen_keys(server, dir.path(), "server");
    let (c_priv, c_pub) = gen_keys(client, dir.path(), "client");

    let received = roundtrip(
        server, client, &s_priv, &c_pub, &c_priv, &s_pub, data, flags,
    );

    assert_eq!(
        received.len(),
        data.len(),
        "length mismatch ({} server, {} client, flags {flags:?})",
        server.label(),
        client.label()
    );
    if let Some(i) = received.iter().zip(data).position(|(a, b)| a != b) {
        panic!(
            "first byte mismatch at {i}: got {:02x}, want {:02x} \
             ({} server, {} client, flags {flags:?})",
            received[i],
            data[i],
            server.label(),
            client.label()
        );
    }
    true
}

// ──── Rust↔Rust ─────────────────────────────────────────────────────
// Always run. The unit-test floor: if these fail, the binary is
// broken regardless of cross-impl.

#[test]
fn stream_mode() {
    assert!(scenario(Impl::Rust, Impl::Rust, &payload(), &[]));
}

#[test]
fn datagram_mode() {
    assert!(scenario(Impl::Rust, Impl::Rust, &payload(), &["-d"]));
}

/// Swap roles: server uses what was the "client" keypair, and vice
/// versa. `sptps_basic.py` does this too. Catches a hypothetical bug
/// where keygen produces a working initiator key but a broken responder
/// key — implausible but the test is free.
#[test]
fn stream_swapped_roles() {
    let dir = tempfile::tempdir().unwrap();
    let (a_priv, a_pub) = gen_keys(Impl::Rust, dir.path(), "a");
    let (b_priv, b_pub) = gen_keys(Impl::Rust, dir.path(), "b");

    let data = payload();
    // First: a serves, b connects.
    let r1 = roundtrip(
        Impl::Rust,
        Impl::Rust,
        &a_priv,
        &b_pub,
        &b_priv,
        &a_pub,
        &data,
        &[],
    );
    assert_eq!(r1, data);
    // Then: b serves, a connects. Same keys, swapped roles.
    let r2 = roundtrip(
        Impl::Rust,
        Impl::Rust,
        &b_priv,
        &a_pub,
        &a_priv,
        &b_pub,
        &data,
        &[],
    );
    assert_eq!(r2, data);
}

/// Stream mode with a payload bigger than one TCP segment. This forces
/// the kernel to split the `send()` across multiple `recv()`s on the
/// server side, exercising the SPTPS stream-framing reassembly. 64KB
/// is well past any MTU and past the typical 16KB socket buffer.
///
/// `sptps_basic.py` only sends 256 bytes — one TCP segment, one
/// `recv()`, one SPTPS record. Doesn't test reassembly. This does.
#[test]
fn stream_large_payload() {
    // 64 KiB — bigger than `sptps_test`'s 65535 read buffer minus one,
    // so even a single stdin `read()` can't hold it all. Guaranteed to
    // exercise the loop. The bytes are a counter so a swapped/dropped
    // chunk shows up as a localized diff, not just "lengths match,
    // contents don't".
    let data: Vec<u8> = (0u32..65536).map(|i| (i % 251) as u8).collect();
    assert!(scenario(Impl::Rust, Impl::Rust, &data, &[]));
}

// ──── Cross-impl: Rust↔C ─────────────────────────────────────────────
// These tests skip (return early) if TINC_C_SPTPS_TEST is unset.
// They aren't #[ignore]'d because:
//   1. `cargo test --include-ignored` would run them and fail noisily
//      when the var isn't set, which is annoying for local dev.
//   2. With the env var set, you want them in the default `cargo test`
//      run — no extra flag, no special invocation.
// The `cross_guard` check below is the CI gate: when CI sets the var,
// a false return is a real failure (env var set but binary missing).
//
// The 2×2 matrix is asymmetric in what each cell tests:
//
//   ┌──────────┬──────────────┬──────────────────────────────────┐
//   │ server   │ client       │ what's actually being tested     │
//   ├──────────┼──────────────┼──────────────────────────────────┤
//   │ Rust     │ Rust         │ (above) — the binary works at all│
//   │ Rust     │ C            │ Rust *responder* SPTPS state mach│
//   │ C        │ Rust         │ Rust *initiator* SPTPS state mach│
//   │ C        │ C            │ the C binary still works (control)│
//   └──────────┴──────────────┴──────────────────────────────────┘
//
// The two off-diagonal cells are the prize. Initiator and responder
// take different code paths in SPTPS (initiator sends KEX first, signs
// first; responder waits, verifies first). `tinc-sptps/tests/vs_c.rs`
// covers both with seeded RNG; this covers both with real entropy and
// real sockets.
//
// The C↔C cell is the control. If it fails, the C binary or the test
// harness is broken — stop and fix that before believing anything else.

fn cross_guard(ran: bool) {
    // CI sets TINC_C_SPTPS_TEST. In that environment, skipping is a
    // bug — the env var is set, the test must run. Locally, the var
    // is unset, `scenario` returns false, and we just don't assert.
    if std::env::var_os("TINC_C_SPTPS_TEST").is_some() {
        assert!(ran, "TINC_C_SPTPS_TEST is set but scenario skipped");
    }
}

#[test]
fn cross_stream_rust_server_c_client() {
    cross_guard(scenario(Impl::Rust, Impl::C, &payload(), &[]));
}

#[test]
fn cross_stream_c_server_rust_client() {
    cross_guard(scenario(Impl::C, Impl::Rust, &payload(), &[]));
}

#[test]
fn cross_stream_c_server_c_client() {
    cross_guard(scenario(Impl::C, Impl::C, &payload(), &[]));
}

#[test]
fn cross_datagram_rust_server_c_client() {
    cross_guard(scenario(Impl::Rust, Impl::C, &payload(), &["-d"]));
}

#[test]
fn cross_datagram_c_server_rust_client() {
    cross_guard(scenario(Impl::C, Impl::Rust, &payload(), &["-d"]));
}

#[test]
fn cross_datagram_c_server_c_client() {
    cross_guard(scenario(Impl::C, Impl::C, &payload(), &["-d"]));
}

/// 64KB through the cross-impl path. The Rust *responder* reassembling
/// records that the *C initiator* fragmented across TCP segments — and
/// the reverse. The C↔C cell is skipped here; it'd just be testing the
/// C binary against itself, which is `sptps_basic.py`'s job.
#[test]
fn cross_stream_large_payload() {
    let data: Vec<u8> = (0u32..65536).map(|i| (i % 251) as u8).collect();
    let r1 = scenario(Impl::Rust, Impl::C, &data, &[]);
    let r2 = scenario(Impl::C, Impl::Rust, &data, &[]);
    cross_guard(r1 && r2);
}

/// PEM cross-read: a key generated by C `sptps_keypair` should load
/// in Rust and vice versa. The `scenario()` cross-impl tests already
/// exercise *public*-key cross-reads (server reads client's public);
/// this exercises *private*-key cross-reads by generating with one
/// impl and using with the other on both ends.
///
/// What this catches that the matrix above doesn't: the 96-byte
/// private-key blob layout (`ecdsa.c`'s struct-overlap trick —
/// `private[64] || public[32]` packed). The public-key file is just 32
/// bytes; harder to get wrong. The private side is where the LSB-first
/// b64 encoding and the exact byte order matter.
#[test]
fn cross_pem_read() {
    let Some(_) = Impl::C.sptps_keypair() else {
        eprintln!("SKIP: TINC_C_SPTPS_KEYPAIR not set");
        cross_guard(false);
        return;
    };
    let dir = tempfile::tempdir().unwrap();

    // C generates, Rust uses (both ends — so private cross-read on
    // both server and client).
    let (s_priv, s_pub) = gen_keys(Impl::C, dir.path(), "c_server");
    let (c_priv, c_pub) = gen_keys(Impl::C, dir.path(), "c_client");
    let data = payload();
    let r = roundtrip(
        Impl::Rust,
        Impl::Rust,
        &s_priv,
        &c_pub,
        &c_priv,
        &s_pub,
        &data,
        &[],
    );
    assert_eq!(r, data, "C-generated keys, Rust-used");

    // Rust generates, C uses.
    let (s_priv, s_pub) = gen_keys(Impl::Rust, dir.path(), "r_server");
    let (c_priv, c_pub) = gen_keys(Impl::Rust, dir.path(), "r_client");
    let r = roundtrip(
        Impl::C,
        Impl::C,
        &s_priv,
        &c_pub,
        &c_priv,
        &s_pub,
        &data,
        &[],
    );
    assert_eq!(r, data, "Rust-generated keys, C-used");
}
