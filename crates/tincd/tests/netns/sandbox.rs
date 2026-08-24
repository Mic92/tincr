use std::os::unix::fs::PermissionsExt;

use super::rig::*;

fn write_script(path: &std::path::Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `Sandbox = normal`: the daemon boots and pings under Landlock,
/// and a `#!/bin/sh` host-up fails because /bin is deliberately not
/// on the allowlist. Self-skips when Landlock is not enforced.
#[test]
fn sandbox_normal_ping() {
    let Some(netns) = enter_netns("sandbox::sandbox_normal_ping") else {
        return;
    };
    let tmp = tmp!("sboxping");
    let mut pair = TunPair::new(netns, &tmp, "Sandbox = normal");
    std::fs::create_dir_all(&pair.alice.confbase).unwrap();
    write_script(&pair.alice.confbase.join("host-up"), "exit 0");
    pair.start_direct();
    pair.wait_validkey();

    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let (alice_log, bob_log) = pair.finish();
    assert!(
        output.status.success(),
        "=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    if !alice_log.contains("Entered sandbox") {
        eprintln!("SKIP sandbox_normal_ping: Landlock not enforced");
        return;
    }
    assert!(bob_log.contains("Entered sandbox"), "{bob_log}");
    assert!(alice_log.contains("host-up spawn failed"), "{alice_log}");
}

/// `Sandbox = high` refuses to run scripts at all, before touching
/// the file. tinc-up already ran before the sandbox was entered, so
/// tinc-down on graceful shutdown is the witness.
#[test]
fn sandbox_high_blocks_scripts() {
    let Some(_netns) = enter_netns("sandbox::sandbox_high_blocks_scripts") else {
        return;
    };
    let tmp = tmp!("sboxhigh");
    let mut alice = tun_node(tmp.path(), "alice", 0xAD, "tinc0")
        .with_conf("Sandbox = high")
        .log_level("tincd=debug");
    alice.write_config_multi(&[], &[]);
    let witness = alice.confbase.join("tinc-down-ran");
    write_script(
        &alice.confbase.join("tinc-down"),
        &format!("touch '{}'", witness.display()),
    );

    // `high` hard-fails without Landlock instead of degrading.
    if let Err(log) = alice.try_start() {
        if log.contains("Landlock is not available") {
            eprintln!("SKIP sandbox_high_blocks_scripts: {log}");
            return;
        }
        panic!("alice did not come up: {log}");
    }

    alice.signal(nix::sys::signal::Signal::SIGTERM);
    assert!(alice.wait_exit().success());
    let log = alice.log();
    assert!(!witness.exists(), "tinc-down ran:\n{log}");
    assert!(
        log.contains("tinc-down") && log.contains("Sandbox=high"),
        "{log}"
    );
}
