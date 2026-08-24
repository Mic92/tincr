//! `sptps_test`/`sptps_keypair` as subprocesses over a real socket,
//! Rust and (with `TINC_C_SPTPS_TEST`/`TINC_C_SPTPS_KEYPAIR`, set by the
//! devshell) C in every server/client combination. Covers what the
//! in-process `vs_c.rs` cannot: `OsRng`, PEM files, kernel short
//! reads, the binaries' argv/poll/EOF handling.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn cargo_bin(name: &str) -> PathBuf {
    std::env::var_os(format!("CARGO_BIN_EXE_{name}")).map_or_else(
        // target/{profile}/deps/<test> → target/{profile}/<name>
        || {
            let exe = std::env::current_exe().unwrap();
            exe.parent().unwrap().parent().unwrap().join(name)
        },
        PathBuf::from,
    )
}

#[derive(Clone, Copy, Debug)]
enum Impl {
    Rust,
    C,
}

impl Impl {
    fn sptps_test(self) -> Option<PathBuf> {
        match self {
            Self::Rust => Some(cargo_bin("sptps_test")),
            Self::C => std::env::var_os("TINC_C_SPTPS_TEST").map(PathBuf::from),
        }
    }

    fn sptps_keypair(self) -> Option<PathBuf> {
        match self {
            Self::Rust => Some(cargo_bin("sptps_keypair")),
            Self::C => std::env::var_os("TINC_C_SPTPS_KEYPAIR").map(PathBuf::from),
        }
    }

    fn available(self) -> bool {
        self.sptps_test().is_some() && self.sptps_keypair().is_some()
    }
}

fn skip_without_c(test: &str) -> bool {
    if Impl::C.available() {
        return false;
    }
    assert!(
        std::env::var_os("TINC_C_SPTPS_TEST").is_none(),
        "TINC_C_SPTPS_TEST set but TINC_C_SPTPS_KEYPAIR missing"
    );
    eprintln!("SKIP {test}: TINC_C_SPTPS_TEST / TINC_C_SPTPS_KEYPAIR not set");
    true
}

struct KeyPair {
    private: PathBuf,
    public: PathBuf,
}

fn generate_keys(generator: Impl, dir: &Path, name: &str) -> KeyPair {
    let keys = KeyPair {
        private: dir.join(format!("{name}.priv")),
        public: dir.join(format!("{name}.pub")),
    };
    let status = Command::new(generator.sptps_keypair().unwrap())
        .arg(&keys.private)
        .arg(&keys.public)
        .status()
        .expect("spawn sptps_keypair");
    assert!(status.success(), "{generator:?} sptps_keypair failed");
    keys
}

/// The caller must keep stderr open afterwards or the server's next
/// diagnostic is a SIGPIPE.
fn wait_for_port(stderr: &mut impl Read) -> u16 {
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "server stderr closed without a Listening line"
        );
        if let Some(port) = line
            .trim()
            .strip_prefix("Listening on ")
            .and_then(|rest| rest.strip_suffix("..."))
        {
            return port.parse().unwrap();
        }
    }
}

fn read_exactly(stdout: &mut impl Read, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    while out.len() < len {
        assert!(
            Instant::now() < deadline,
            "have {} of {len} bytes",
            out.len()
        );
        let want = (len - out.len()).min(buf.len());
        match stdout.read(&mut buf[..want]) {
            Ok(0) => panic!("server stdout closed at {} of {len} bytes", out.len()),
            Ok(got) => out.extend_from_slice(&buf[..got]),
            Err(e) => panic!("read server stdout: {e}"),
        }
    }
    out
}

/// Datagram servers never see EOF and are killed; stream servers must
/// exit by themselves.
fn reap(mut child: Child, must_exit: bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!must_exit || status.success(), "server exited {status:?}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            assert!(!must_exit, "stream server did not exit on EOF");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Returns what the server printed for `data` sent by the client.
fn roundtrip(
    server: (Impl, &KeyPair),
    client: (Impl, &KeyPair),
    data: &[u8],
    datagram: bool,
) -> Vec<u8> {
    let mode: &[&str] = if datagram { &["-d"] } else { &[] };
    let mut server_child = Command::new(server.0.sptps_test().unwrap())
        .args(["-4", "-r"])
        .args(mode)
        .arg(&server.1.private)
        .arg(&client.1.public)
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");
    let mut server_stderr = server_child.stderr.take().unwrap();
    let port = wait_for_port(&mut server_stderr);

    let mut client_child = Command::new(client.0.sptps_test().unwrap())
        .args(["-4", "-q"])
        .args(mode)
        .arg(&client.1.private)
        .arg(&server.1.public)
        .arg("localhost")
        .arg(port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");
    client_child.stdin.take().unwrap().write_all(data).unwrap();

    let received = read_exactly(&mut server_child.stdout.take().unwrap(), data.len());

    let client_out = client_child.wait_with_output().unwrap();
    assert!(
        client_out.status.success(),
        "client exited {:?}\n{}",
        client_out.status,
        String::from_utf8_lossy(&client_out.stderr)
    );
    let drain = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = server_stderr.read_to_end(&mut sink);
    });
    reap(server_child, !datagram);
    drain.join().unwrap();
    received
}

fn scenario(server: Impl, client: Impl, data: &[u8], datagram: bool) {
    let dir = tempfile::tempdir().unwrap();
    let server_keys = generate_keys(server, dir.path(), "server");
    let client_keys = generate_keys(client, dir.path(), "client");
    let received = roundtrip(
        (server, &server_keys),
        (client, &client_keys),
        data,
        datagram,
    );
    if let Some(offset) = received.iter().zip(data).position(|(a, b)| a != b) {
        panic!("{server:?} server, {client:?} client: first mismatch at byte {offset}");
    }
    assert_eq!(received.len(), data.len());
}

fn payload() -> Vec<u8> {
    (0..=255).collect()
}

/// Forces stream reassembly across several short reads.
fn large_payload() -> Vec<u8> {
    (0u32..65536).map(|i| (i % 251) as u8).collect()
}

#[test]
fn stream() {
    scenario(Impl::Rust, Impl::Rust, &payload(), false);
}

#[test]
fn datagram() {
    scenario(Impl::Rust, Impl::Rust, &payload(), true);
}

#[test]
fn stream_swapped_roles() {
    let dir = tempfile::tempdir().unwrap();
    let a = generate_keys(Impl::Rust, dir.path(), "a");
    let b = generate_keys(Impl::Rust, dir.path(), "b");
    let data = payload();
    assert_eq!(
        roundtrip((Impl::Rust, &a), (Impl::Rust, &b), &data, false),
        data
    );
    assert_eq!(
        roundtrip((Impl::Rust, &b), (Impl::Rust, &a), &data, false),
        data
    );
}

#[test]
fn stream_large_payload() {
    scenario(Impl::Rust, Impl::Rust, &large_payload(), false);
}

#[test]
fn cross_matrix() {
    if skip_without_c("cross_matrix") {
        return;
    }
    for datagram in [false, true] {
        for (server, client) in [
            (Impl::Rust, Impl::C),
            (Impl::C, Impl::Rust),
            (Impl::C, Impl::C),
        ] {
            scenario(server, client, &payload(), datagram);
        }
    }
}

#[test]
fn cross_stream_large_payload() {
    if skip_without_c("cross_stream_large_payload") {
        return;
    }
    scenario(Impl::Rust, Impl::C, &large_payload(), false);
    scenario(Impl::C, Impl::Rust, &large_payload(), false);
}

/// Private key files written by one implementation, read by the other.
#[test]
fn cross_pem_private_keys() {
    if skip_without_c("cross_pem_private_keys") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let data = payload();
    for (generator, user) in [(Impl::C, Impl::Rust), (Impl::Rust, Impl::C)] {
        let server = generate_keys(generator, dir.path(), "server");
        let client = generate_keys(generator, dir.path(), "client");
        assert_eq!(
            roundtrip((user, &server), (user, &client), &data, false),
            data,
            "{generator:?} keys used by {user:?}"
        );
    }
}

/// Keys as `tinc init` writes them (a different PEM writer) load in C.
#[test]
fn init_keys_load_in_c() {
    if skip_without_c("init_keys_load_in_c") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let init = |name: &str| {
        let confbase = dir.path().join(name);
        let status = Command::new(cargo_bin("tinc"))
            .arg("-c")
            .arg(&confbase)
            .args(["init", name])
            .env_remove("NETNAME")
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let host = std::fs::read_to_string(confbase.join("hosts").join(name)).unwrap();
        let b64 = host
            .lines()
            .find_map(|line| line.strip_prefix("Ed25519PublicKey = "))
            .unwrap();
        let public = dir.path().join(format!("{name}.pub"));
        tinc_conf::pem::write_pem(
            &mut std::fs::File::create(&public).unwrap(),
            "ED25519 PUBLIC KEY",
            &tinc_crypto::b64::decode(b64).unwrap(),
        )
        .unwrap();
        KeyPair {
            private: confbase.join("ed25519_key.priv"),
            public,
        }
    };
    let alice = init("alice");
    let bob = init("bob");
    let data = payload();
    assert_eq!(
        roundtrip((Impl::C, &alice), (Impl::C, &bob), &data, false),
        data
    );
}
