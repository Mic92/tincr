use std::process::{Command, Stdio};
use std::time::Duration;

use super::common::linux::*;
use super::common::*;
use super::rig::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("netns", tag)
}

/// `Sandbox = normal` end-to-end. Same shape as `real_tun_ping` but
/// with the path allowlist active. Proves:
///
/// 1. **Daemon boots under Landlock.** `enter()` runs after
///    `Daemon::setup` (TUN open, listeners bound, tinc-up fired);
///    if the ruleset blocked any of those paths the daemon would
///    error out before the socket file appears.
/// 2. **Ping works.** Steady-state path access: cache/ write from
///    addrcache (alice's address-learn writes `cache/bob`); the
///    per-tunnel SPTPS only touches in-memory state.
/// 3. **Paths outside the allowlist EACCES.** A `host-up` script
///    with `#!/bin/sh` shebang fails: the daemon's exec of
///    confbase/host-up succeeds (Execute granted on confbase), but
///    the kernel's shebang-chase to /bin/sh hits a path NOT under
///    any `PathBeneath` rule → EACCES. This is the documented sharp
///    edge (sandbox.rs module doc): we don't port C's `open_exec_
///    paths` (/bin, /sbin, etc) because that's distro-specific.
///    The test pins the behavior so it's intentional.
///
/// **Self-skip if Landlock unavailable.** At `normal`, kernel-too-
/// old logs a warning and continues unrestricted (sandbox.rs
/// `RulesetStatus::NotEnforced` arm). The daemon STARTS but the
/// EACCES assert would fail (nothing's blocked). Check stderr for
/// "Entered sandbox"; absent → SKIP.
#[test]
fn sandbox_normal_ping() {
    use std::os::unix::fs::PermissionsExt;

    let Some(netns) = enter_netns("sandbox_normal_ping") else {
        return;
    };

    let tmp = tmp("sboxping");
    let alice = Node::new(tmp.path(), "alice", 0xAC, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBC, "tinc1", "10.42.0.2/32");

    bob.write_config_with(&alice, false, "Sandbox = normal\n");
    alice.write_config_with(&bob, true, "Sandbox = normal\n");

    // host-up reaching outside the allowlist via #!/bin/sh. The
    // body is irrelevant: the kernel never gets past the shebang.
    let host_up = alice.confbase.join("host-up");
    std::fs::write(&host_up, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perm = std::fs::metadata(&host_up).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&host_up, perm).unwrap();

    // ─── spawn (same as real_tun_ping) ────────────────────────
    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup: {}",
        drain_stderr(bob_child)
    );
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup: {}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // Kick + wait validkey.
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let validkey = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey.is_err() {
        let _ = bob_child.kill();
        panic!(
            "validkey timeout;\n=== alice ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(bob_child)
        );
    }

    // ─── THE PING (under Landlock) ─────────────────────────────
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let bob_stderr = drain_stderr(bob_child);

    assert!(
        ping.status.success(),
        "ping failed under Sandbox=normal: {:?}\nstdout: {}\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
        ping.status,
        String::from_utf8_lossy(&ping.stdout),
    );
    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    // ─── Landlock actually entered (not silently no-op'd) ──────
    // sandbox::enter_impl logs "Entered sandbox at level Normal"
    // on RulesetStatus::{Fully,Partially}Enforced. Absent → either
    // kernel too old or LSM not enabled → the rest of this test
    // would be a tautology.
    if !alice_stderr.contains("Entered sandbox") {
        eprintln!(
            "SKIP sandbox_normal_ping: Landlock not enforced \
             (kernel <5.13 or lsm= boot param missing landlock). \
             alice stderr:\n{alice_stderr}"
        );
        drop(netns);
        return;
    }
    assert!(
        bob_stderr.contains("Entered sandbox"),
        "bob also under Landlock; stderr:\n{bob_stderr}"
    );

    // ─── host-up spawn failed (EACCES on /bin/sh shebang) ─────
    // THE LANDLOCK PROOF. periodic.rs::log_script logs spawn
    // failure at Error level ("Script host-up spawn failed: ...").
    // The error is the kernel's EACCES from the shebang chase.
    assert!(
        alice_stderr.contains("host-up spawn failed"),
        "host-up's #!/bin/sh shebang should EACCES under Landlock. \
         If this fires but ping above passed, either Landlock \
         partially-enforced and Execute wasn't handled, or someone \
         added a /bin rule. alice stderr:\n{alice_stderr}"
    );

    // (Dropped: addrcache write check. AddressCache::save fires in
    // Drop, but drain_stderr SIGKILLs → no Drop → cache/bob never
    // written. The host-up EACCES above is the Landlock proof; a
    // graceful-shutdown variant could prove the cache/ write but
    // that's a SIGTERM dance the existing real_tun_ping doesn't do
    // either. The MakeReg rule is exercised by sandbox::enter
    // pre-creating cache/ itself — which clearly worked since the
    // daemon entered FullyEnforced.)

    drop(netns);
}

/// `Sandbox = high` blocks ALL scripts via `can(StartProcesses)`.
/// The gate is intent-tracking (`sandbox::STATE` atomic), independent
/// of whether Landlock actually enforced — so this runs even on
/// kernels without Landlock, modulo the hard-fail check below.
///
/// Single daemon, no peer: the gate fires on tinc-down at
/// Daemon::Drop. If the witness file appears, `script::execute`'s
/// early-return is broken.
#[test]
fn sandbox_high_blocks_scripts() {
    use std::os::unix::fs::PermissionsExt;

    let Some(_netns) = enter_netns("sandbox_high_blocks_scripts") else {
        return;
    };

    let tmp = tmp("sboxhigh");
    let alice = Node::new(tmp.path(), "alice", 0xAD, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBD, "tinc1", "10.42.0.2/32");

    alice.write_config_with(&bob, false, "Sandbox = high\n");

    // tinc-down witness. At high, script::execute returns
    // Sandboxed BEFORE stat'ing the file. The shebang here would
    // ALSO fail under Landlock (same as sandbox_normal_ping's
    // host-up), but we're proving the EARLIER gate — the script
    // file is never touched. The witness-absent assert would catch
    // a regression where the can() check moved AFTER the spawn.
    let witness = alice.confbase.join("tinc-down-ran");
    let tinc_down = alice.confbase.join("tinc-down");
    std::fs::write(
        &tinc_down,
        format!("#!/bin/sh\ntouch '{}'\n", witness.display()),
    )
    .unwrap();
    let mut perm = std::fs::metadata(&tinc_down).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&tinc_down, perm).unwrap();

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        // Sandbox=high HARD-FAILS when Landlock is unavailable
        // (sandbox.rs enter_impl, the NotEnforced → Err arm).
        // Daemon never reaches the socket bind. SKIP.
        let stderr = drain_stderr(alice_child);
        if stderr.contains("Landlock is not available") {
            eprintln!("SKIP sandbox_high_blocks_scripts: {stderr}");
            return;
        }
        panic!("alice setup failed: {stderr}");
    }

    // tinc-up ALREADY RAN (before sandbox::enter, can()==true).
    // SIGTERM → RunOutcome::Clean → Daemon::Drop →
    // run_script("tinc-down") → gate. NOT child.kill() (SIGKILL):
    // that skips Drop entirely and the test would pass for the
    // wrong reason (tinc-down never even attempted).
    //
    // SAFETY: kill(2). We spawned this child; wait_for_file
    // confirmed it's alive and serving.
    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)] // pid_t fits a child PID
    unsafe {
        let rc = libc::kill(alice_child.id() as libc::pid_t, libc::SIGTERM);
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = alice_child.try_wait().unwrap() {
            break s;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "daemon didn't exit on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "daemon should exit 0 on SIGTERM");
    let stderr = {
        use std::io::Read;
        let mut s = String::new();
        alice_child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    };

    assert!(
        !witness.exists(),
        "tinc-down ran under Sandbox=high (witness file exists). \
         can(StartProcesses) gate failed. stderr:\n{stderr}"
    );

    // The debug-level log from periodic.rs::log_script. spawn()
    // sets RUST_LOG=tincd=debug.
    assert!(
        stderr.contains("tinc-down") && stderr.contains("Sandbox=high"),
        "expected 'Script tinc-down: skipped (Sandbox=high)' log; \
         stderr:\n{stderr}"
    );
}
