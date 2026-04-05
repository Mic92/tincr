#![cfg(unix)]

use super::tinc;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Run `tinc init`, take the resulting private key, hand it to the C
/// `sptps_test`. If the C binary can complete a handshake with that
/// key, the PEM format and blob layout are correct end-to-end.
///
/// The test setup is the same shape as `self_roundtrip.rs::scenario` —
/// server listens, client connects, push bytes, diff. The difference:
/// the *key files* come from `tinc init`, not `sptps_keypair`.
///
/// Why both ends use init-generated keys: maximizes coverage. C-server
/// loads alice's private key (PEM read), C-client loads alice's
/// *public* key from a synthesized PEM file (we extract it from
/// `hosts/alice` and re-wrap). Both directions of the format.
#[test]
fn cross_init_key_loads_in_c() {
    let Some(c_sptps_test) = std::env::var_os("TINC_C_SPTPS_TEST").map(PathBuf::from) else {
        eprintln!("SKIP: TINC_C_SPTPS_TEST not set");
        return;
    };

    let dir = tempfile::tempdir().unwrap();

    // Two confbases — alice and bob — so we have two distinct keypairs.
    // Real tinc deployment shape.
    let alice_base = dir.path().join("alice");
    let bob_base = dir.path().join("bob");

    let out = tinc(&["-c", alice_base.to_str().unwrap(), "init", "alice"]);
    assert!(out.status.success(), "{out:?}");
    let out = tinc(&["-c", bob_base.to_str().unwrap(), "init", "bob"]);
    assert!(out.status.success(), "{out:?}");

    // The private keys are PEM files — sptps_test reads them directly.
    let alice_priv = alice_base.join("ed25519_key.priv");
    let bob_priv = bob_base.join("ed25519_key.priv");

    // The *public* keys are config lines in hosts/NAME, not PEM files.
    // sptps_test wants PEM. Extract the b64, decode (tinc LSB-first),
    // re-wrap as PEM. This is what a peer would do when reading a
    // host file: `get_config_string("Ed25519PublicKey")` →
    // `ecdsa_set_base64_public_key` → key in memory. We replicate that
    // pipeline, then dump back to PEM for sptps_test.
    let alice_pub = extract_pubkey_to_pem(&alice_base.join("hosts/alice"), dir.path(), "alice");
    let bob_pub = extract_pubkey_to_pem(&bob_base.join("hosts/bob"), dir.path(), "bob");

    // ─── Now the actual SPTPS handshake. C both sides. ─────────────
    // alice serves (responder), bob connects (initiator).
    // This is the `self_roundtrip.rs` choreography, inlined and
    // simplified (we don't need the full Impl matrix here, just C↔C
    // with init-generated keys).

    let mut server = Command::new(&c_sptps_test)
        .arg("-4")
        .arg("-r")
        .arg(&alice_priv)
        .arg(&bob_pub)
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn C server");

    let mut server_stderr = server.stderr.take().unwrap();
    let port = wait_for_port(&mut server_stderr);

    let mut client = Command::new(&c_sptps_test)
        .arg("-4")
        .arg("-q")
        .arg(&bob_priv)
        .arg(&alice_pub)
        .arg("localhost")
        .arg(port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn C client");

    // Push 256 bytes.
    let data: Vec<u8> = (0..=255).collect();
    {
        let mut stdin = client.stdin.take().unwrap();
        stdin.write_all(&data).unwrap();
    }

    // Read it back from the server.
    let mut server_stdout = server.stdout.take().unwrap();
    let mut received = vec![0u8; data.len()];
    let mut got = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while got < data.len() {
        assert!(
            std::time::Instant::now() < deadline,
            "timeout reading server stdout (got {got}/{})",
            data.len()
        );
        let n = server_stdout.read(&mut received[got..]).unwrap();
        assert!(n != 0, "server stdout EOF after {got} bytes");
        got += n;
    }

    // The proof.
    assert_eq!(received, data, "C↔C handshake with tinc-init keys");

    // Cleanup. Stream mode → server exits on TCP FIN.
    let client_status = client.wait().unwrap();
    assert!(client_status.success(), "client: {client_status:?}");

    // Hold stderr open until server exits (SIGPIPE footgun — see
    // self_roundtrip.rs `wait_for_port` doc).
    let drain = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = server_stderr.read_to_end(&mut sink);
    });
    let server_status = server.wait().unwrap();
    let _ = drain.join();
    assert!(server_status.success(), "server: {server_status:?}");
}

/// Read `Ed25519PublicKey = <b64>` from a host file, decode the
/// tinc-b64, re-wrap as PEM. This is the `ecdsa_set_base64_public_key`
/// → `ecdsa_write_pem_public_key` pipeline, manually.
fn extract_pubkey_to_pem(host_file: &Path, out_dir: &Path, name: &str) -> PathBuf {
    let contents = std::fs::read_to_string(host_file).unwrap();
    // Parse: `Ed25519PublicKey = <b64>\n`. We could use tinc-conf's
    // parser here, but the format is simple enough that string ops
    // suffice and don't pull in another dependency for the test.
    let b64 = contents
        .lines()
        .find_map(|l| l.strip_prefix("Ed25519PublicKey = "))
        .expect("host file has Ed25519PublicKey line");

    // tinc LSB-first b64 → 32 bytes.
    let pubkey = tinc_crypto::b64::decode(b64).expect("valid tinc-b64");
    assert_eq!(pubkey.len(), 32);

    // Re-wrap as PEM. `sptps_test` calls `ecdsa_read_pem_public_key`
    // which expects `-----BEGIN ED25519 PUBLIC KEY-----`.
    let out_path = out_dir.join(format!("{name}.pub"));
    let f = std::fs::File::create(&out_path).unwrap();
    let mut w = std::io::BufWriter::new(f);
    tinc_conf::pem::write_pem(&mut w, "ED25519 PUBLIC KEY", &pubkey).unwrap();

    out_path
}

/// Parse `Listening on PORT...` from stderr. Same as `self_roundtrip.rs`.
/// Takes `&mut` so the caller keeps stderr alive (SIGPIPE — see that
/// file's `wait_for_port` doc, hard-won lesson).
fn wait_for_port(stderr: &mut impl Read) -> u16 {
    let mut buf = Vec::new();
    let mut byte = [0u8];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "timeout waiting for 'Listening on'; got: {}",
            String::from_utf8_lossy(&buf)
        );
        let n = stderr.read(&mut byte).unwrap();
        assert!(
            n != 0,
            "stderr EOF before 'Listening on'; got: {}",
            String::from_utf8_lossy(&buf)
        );
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            let line = String::from_utf8_lossy(&buf);
            if let Some(rest) = line.strip_prefix("Listening on ") {
                let port_str = rest.trim_end_matches("...\n");
                return port_str.parse().unwrap();
            }
            buf.clear();
        }
    }
}
