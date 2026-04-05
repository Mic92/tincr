#![cfg(unix)]

/// and `config_set_fires_reload`, factored.
///
/// Returns: (tempdir-guard, confbase path string, pidfile path string).
/// Tempdir drop cleans up; the listener thread joins inside the test.
pub(crate) fn fake_daemon_setup() -> (
    tempfile::TempDir,
    String,
    String,
    std::os::unix::net::UnixListener,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().join("vpn");
    let cb_s = cb.to_str().unwrap().to_owned();
    // Minimal confbase — dump doesn't read it, but main() resolves
    // paths relative to it.
    std::fs::create_dir_all(&cb).unwrap();

    let pidfile = dir.path().join("tinc.pid");
    let pidfile_s = pidfile.to_str().unwrap().to_owned();
    let sock = dir.path().join("tinc.socket");

    // Our pid → kill(pid, 0) returns 0.
    let cookie = "abcdef0123456789".repeat(4);
    let our_pid = std::process::id();
    std::fs::write(&pidfile, format!("{our_pid} {cookie} 127.0.0.1 port 655\n")).unwrap();

    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    (dir, cb_s, pidfile_s, listener, cookie)
}

/// Serves the greeting + handshake. Returns (`BufReader`, write-handle).
/// The closure pattern from existing tests, hoisted.
pub(crate) fn serve_greeting<'a>(
    stream: &'a std::os::unix::net::UnixStream,
    cookie: &str,
) -> (
    std::io::BufReader<&'a std::os::unix::net::UnixStream>,
    &'a std::os::unix::net::UnixStream,
) {
    use std::io::{BufRead, BufReader, Write};
    let mut br = BufReader::new(stream);
    let mut line = String::new();
    br.read_line(&mut line).unwrap();
    // Cookie auth.
    assert!(line.contains(&format!("^{cookie}")));
    let mut w = stream;
    writeln!(w, "0 fakedaemon 17.7").unwrap();
    writeln!(w, "4 0 1").unwrap();
    (br, stream)
}
