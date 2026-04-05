use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;

use super::common::*;
use super::write_config;

fn tmp(tag: &str) -> super::common::TmpGuard {
    super::common::TmpGuard::new("stop", tag)
}

/// Missing tinc.conf → setup fails. The error message comes from
/// `tinc-conf::read_server_config`.
#[test]
fn missing_config_fails() {
    let tmp = tmp("noconfig");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // confbase exists but no tinc.conf inside.
    std::fs::create_dir_all(&confbase).unwrap();

    let out = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    // Don't pin the exact message (tinc-conf owns it). Just: it
    // mentions tinc.conf or config.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("tinc.conf") || stderr.to_lowercase().contains("config"),
        "expected config error in stderr; got: {stderr}"
    );

    // No pidfile/socket created on setup failure.
    assert!(!pidfile.exists());
    assert!(!socket.exists());
}

/// `-o KEY=VALUE` overrides tinc.conf. Cmdline `-o` entries get
/// `Source::Cmdline` which sorts BEFORE file entries
/// in the config-compare 4-tuple, so `lookup().next()` returns the
/// cmdline value.
///
/// Proves: tinc.conf says `Name = testnode`, `-o Name=override`
/// wins. The greeting line shows the override.
#[test]
fn dash_o_overrides_config() {
    let tmp = tmp("dash-o");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);
    // write_config wrote hosts/testnode but the daemon will look for
    // hosts/override. It's a soft skip (warn + defaults) so the
    // daemon still starts — see `Daemon::setup` host-file handling.
    // Port falls back to 655 default; we don't connect over TCP here
    // so the bind clash doesn't matter (oh wait, it does — 655 needs
    // root). Write hosts/override with Port=0 too.
    std::fs::write(confbase.join("hosts").join("override"), "Port = 0\n").unwrap();

    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        // The override. tinc.conf has `Name = testnode`; this wins.
        .arg("-o")
        .arg("Name = override")
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket), "tincd didn't bind; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    // Connect, do the greeting. Line 1 shows the daemon's name.
    let cookie = read_cookie(&pidfile);
    let stream = UnixStream::connect(&socket).unwrap();
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    writeln!(writer, "0 ^{cookie} 0").unwrap();

    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    // The override won. Not "testnode".
    assert_eq!(
        line1, "0 override 17.7\n",
        "-o Name should override tinc.conf"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// `-o` with malformed value (no `=`, no value) fails argv parsing.
#[test]
fn dash_o_bad_value_fails() {
    let tmp = tmp("dash-o-bad");
    let out = tincd_cmd()
        .arg("-c")
        .arg(tmp.path())
        .arg("--pidfile")
        .arg(tmp.path().join("p"))
        .arg("--socket")
        .arg(tmp.path().join("s"))
        .arg("-o")
        .arg("KeyWithoutValue")
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // parse_line's error: "expected for variable". Don't pin the exact
    // wording (tinc-conf owns it) but it should mention the key.
    assert!(
        stderr.contains("KeyWithoutValue"),
        "expected -o parse error mentioning the key; got: {stderr}"
    );
}

/// `-n NETNAME` derives confbase = CONFDIR/tinc/NETNAME. We can't
/// write to /etc/tinc in tests, so this proves the DERIVATION by
/// checking the error message: missing tinc.conf at the derived path.
#[test]
fn dash_n_derives_confbase() {
    let tmp = tmp("dash-n");
    let out = tincd_cmd()
        .arg("-n")
        .arg("testnet")
        .arg("--pidfile")
        .arg(tmp.path().join("p"))
        .arg("--socket")
        .arg(tmp.path().join("s"))
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The daemon tried to read CONFDIR/tinc/testnet/tinc.conf.
    // CONFDIR is build-time (default /etc); the netname component
    // is what we're checking for.
    assert!(
        stderr.contains("testnet"),
        "expected derived confbase path with 'testnet'; got: {stderr}"
    );
}

/// `NETNAME` env var as `-n` fallback.
#[test]
fn netname_env_fallback() {
    let tmp = tmp("netname-env");
    let out = tincd_cmd()
        .arg("--pidfile")
        .arg(tmp.path().join("p"))
        .arg("--socket")
        .arg(tmp.path().join("s"))
        .env("NETNAME", "envnet")
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("envnet"),
        "expected confbase derived from NETNAME=envnet; got: {stderr}"
    );
}

/// `-n` with path-traversal characters rejected.
/// `strpbrk(netname, "\\/")`.
#[test]
fn dash_n_rejects_slash() {
    let tmp = tmp("dash-n-slash");
    let out = tincd_cmd()
        .arg("-n")
        .arg("foo/bar")
        .arg("--pidfile")
        .arg(tmp.path().join("p"))
        .arg("--socket")
        .arg(tmp.path().join("s"))
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("netname") || stderr.to_lowercase().contains("invalid"),
        "expected netname validation error; got: {stderr}"
    );
}

/// `Name` missing from config → `setup_myself` fails.
/// `"Name for tinc daemon required!"`.
#[test]
fn missing_name_fails() {
    let tmp = tmp("noname");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    std::fs::create_dir_all(&confbase).unwrap();
    // Config without Name.
    std::fs::write(confbase.join("tinc.conf"), "DeviceType = dummy\n").unwrap();

    let out = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Name") && stderr.contains("required"),
        "expected 'Name required' error; got: {stderr}"
    );
}

/// `hosts/NAME` missing → daemon starts anyway, port defaults to
/// 655. `read_host_config` failure is not checked. We match: warn +
/// continue.
///
/// We can't actually let it bind 655 (might clash with something on
/// the build host, or with another test). So: this test ONLY checks
/// the daemon doesn't crash on missing hosts/NAME by overriding Port
/// in tinc.conf instead. Wait — Port is HOST-tagged. Can it go in
/// tinc.conf?
///
/// Per the C: `lookup_config("Port")` searches the merged tree.
/// `read_server_config` merges tinc.conf; `read_host_config` merges
/// hosts/NAME. If hosts/NAME is missing, the tree only has tinc.conf
/// entries. So putting Port in tinc.conf works — `lookup` doesn't
/// care which file an entry came from. The `vars.rs` HOST
/// tag is for `cmd_config set` (which file to WRITE to), not lookup.
///
/// What this proves: `read_host_config` is genuinely optional. A
/// freshly `tinc init`-ed daemon (which has hosts/NAME) is fine; a
/// hand-crafted minimal config (tinc.conf only) is also fine.
#[test]
fn missing_hosts_file_ok() {
    let tmp = tmp("nohosts");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // tinc.conf + private key, but NO hosts/ dir. Port goes in
    // tinc.conf (HOST-tagged, but lookup doesn't care which file —
    // see doc). The key IS required (chunk 4a); hosts/ is the
    // optional one being tested.
    //
    // Can't use write_config() here — it creates hosts/.
    std::fs::create_dir_all(&confbase).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\nPort = 0\n",
    )
    .unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);
    // Precondition: hosts/ doesn't exist. THIS is what's tested.
    assert!(!confbase.join("hosts").exists());

    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=warn")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Daemon starts (doesn't crash on missing hosts/testnode).
    assert!(
        wait_for_file(&socket),
        "daemon should start without hosts/; stderr: {}",
        {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stderr).into_owned()
        }
    );

    // The pidfile addr is real (port from tinc.conf was respected).
    let addr = read_tcp_addr(&pidfile);
    assert_ne!(addr.port(), 0);

    let _ = child.kill();
    // Stderr should mention the warning. Matching exact text is
    // brittle; matching the substring `hosts/testnode` is enough
    // to prove the warn-path executed (vs silently skipping).
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hosts/testnode"),
        "expected hosts-missing warning; stderr: {stderr}"
    );
}

/// `-D` keeps the daemon foreground. Proves `do_detach=true` default
/// is overridden: the spawned `Child` stays the daemon (PID matches
/// the pidfile), `child.kill()` works.
///
/// This is the inverse of testing detach itself (which would lose
/// the child). Every other test in this file relies on `-D` working;
/// this one makes that reliance explicit.
#[test]
fn dash_d_upper_stays_foreground() {
    let tmp = tmp("dash-D");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    // tincd_cmd() bakes in -D. We're proving that's load-bearing.
    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket), "tincd didn't bind; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    // pidfile's PID == our Child's PID. If detach had run, the
    // pidfile would hold the grandchild's PID and child.id() would
    // be the (already-exited) parent.
    let pid_line = std::fs::read_to_string(&pidfile).unwrap();
    let pid: u32 = pid_line.split_whitespace().next().unwrap().parse().unwrap();
    assert_eq!(pid, child.id(), "-D: daemon PID should be our direct child");

    let _ = child.kill();
    let _ = child.wait();
}

/// `-dN` glued form (`atoi(optarg)`). The level shows up in the
/// "starting" banner.
#[test]
fn dash_d_level_sets_debug() {
    let tmp = tmp("dash-d-level");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    let mut child = tincd_cmd()
        .arg("-d5")
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env_remove("RUST_LOG") // -d5 should win on its own
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The banner: "tincd VERSION starting, debug level 5". Don't pin
    // version; pin the level.
    assert!(
        stderr.contains("debug level 5"),
        "expected -d5 in startup banner; stderr:\n{stderr}"
    );
}

/// `--logfile PATH` redirects log output. The "starting" banner ends
/// up in the file, NOT on stderr.
#[test]
fn logfile_redirects_output() {
    let tmp = tmp("logfile");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    let logfile = tmp.path().join("tinc.log");
    write_config(&confbase);

    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .arg("--logfile")
        .arg(&logfile)
        .env_remove("RUST_LOG")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let logged = std::fs::read_to_string(&logfile).unwrap();

    // Banner went to the file.
    assert!(
        logged.contains("starting"),
        "expected startup banner in logfile; got:\n{logged}"
    );
    // Banner did NOT go to stderr. (stderr might have the env_logger
    // module noise or be empty; either way, no "starting".)
    assert!(
        !stderr.contains("starting"),
        "--logfile should redirect; stderr still had:\n{stderr}"
    );
}

/// `-U baduser` errors loudly. `getpwnam` returns NULL → "unknown
/// user". Runs AFTER setup (sockets bound, tinc-up
/// done) so the socket exists briefly then vanishes on Drop.
///
/// We don't test the success case (actually dropping privs) — that
/// needs root, and the geteuid()==0 gate would skip on dev machines.
/// The error path proves the call site is wired.
#[test]
fn dash_u_bad_user_fails() {
    let tmp = tmp("dash-U-bad");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    let out = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .arg("-U")
        .arg("definitely_not_a_real_user_xyz_9999")
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success(), "-U baduser should exit nonzero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown user") && stderr.contains("definitely_not_a_real_user_xyz_9999"),
        "expected `unknown user` error; got:\n{stderr}"
    );
}

/// `-L` (mlockall) is wired. Whether it SUCCEEDS depends on
/// `RLIMIT_MEMLOCK` / `CAP_IPC_LOCK` — the nix dev shell has 8MB which
/// is enough for the daemon's resident set, CI sandboxes vary, root
/// always succeeds. We can't reliably test the EPERM path.
///
/// What we CAN prove: `-L` parses, the syscall fires, and EITHER
/// the daemon starts (`mlockall` worked) OR it fails fast with
/// "mlockall" in the error. Both are valid; "silently ignore -L"
/// is not.
///
/// Hard-fail on error.
#[test]
fn dash_l_mlock_wired() {
    let tmp = tmp("dash-L");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    let mut child = tincd_cmd()
        .arg("-L")
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Three-second wait: either the socket appears (mlockall ok,
    // setup ran) or the child has exited (mlockall failed, error
    // path). wait_for_file's 3s timeout covers both.
    let started = wait_for_file(&socket);

    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    if started {
        // mlockall succeeded. The daemon ran. Prove `-L` didn't get
        // dropped on the floor: no "unknown argument" complaint.
        // (Weak, but the alternative is reading /proc/PID/status
        // VmLck which is Linux-only AND racy against our kill.)
        assert!(
            !stderr.contains("unknown argument"),
            "-L should be recognized; stderr:\n{stderr}"
        );
    } else {
        // mlockall failed. Daemon should have said so and exited
        // BEFORE setup (no socket). The error mentions "mlockall"
        // by name.
        assert!(
            stderr.contains("mlockall"),
            "-L failure should mention mlockall; stderr:\n{stderr}"
        );
        assert!(!out.status.success());
    }
}

/// `ProcessPriority = bogus` → error logged, daemon CONTINUES.
/// Upstream does `goto end` on bad priority. We diverge: log and
/// continue (`apply_process_priority` is best-effort). Upstream
/// behavior is arguably a bug — refusing to tunnel because someone
/// typo'd "Hihg" is hostile.
#[test]
fn process_priority_bad_value_warns() {
    let tmp = tmp("priority-bad");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .arg("-o")
        .arg("ProcessPriority = bogus")
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Daemon DOES start (best-effort).
    assert!(
        wait_for_file(&socket),
        "tincd should start despite bad priority"
    );

    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Invalid priority") && stderr.contains("bogus"),
        "expected priority error in log; got:\n{stderr}"
    );
}

/// `ProcessPriority = low` → `setpriority(PRIO_PROCESS, 0, 10)`.
/// Unprivileged users CAN lower their own priority (raise nice).
/// Prove the syscall path executes without error.
#[test]
fn process_priority_low_succeeds() {
    let tmp = tmp("priority-low");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .arg("-o")
        .arg("ProcessPriority = low")
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    // Read /proc/PID/stat field 19 (nice). Linux-only; skip elsewhere.
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
        // Field 19, 0-indexed after the `)`-delimited comm field.
        // /proc/stat format: pid (comm) state ppid ... nice ...
        // Safer parse: rsplit on ')' to skip comm (can contain spaces).
        let after_comm = stat.rsplit_once(')').unwrap().1;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // After `)`: state=0, ppid=1, ..., nice=16 (field 19 overall, 16 after comm).
        let nice: i32 = fields[16].parse().unwrap();
        assert_eq!(
            nice, 10,
            "ProcessPriority=low → nice 10; /proc/stat said {nice}"
        );
    }

    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("setpriority") || !stderr.contains("failed"),
        "setpriority should succeed for nice=10 (lowering); stderr:\n{stderr}"
    );
}
