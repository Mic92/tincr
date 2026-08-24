//! Regression: a slow `host-up` (waitpid on the event loop) must not
//! stall forwarding on reachability flips.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use super::common::*;
use super::fd_tunnel::*;

/// Scripts get a fixed PATH that lacks coreutils on NixOS.
fn sleep_binary() -> std::path::PathBuf {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(|dir| std::path::Path::new(dir).join("sleep"))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| "/bin/sleep".into())
}

#[test]
fn slow_host_up_does_not_stall_forwarding() {
    let tmp = tmp!("script-latency");
    // With the bug alice's loop is dead for 2s; a short PingTimeout on
    // bob would tear the conn down and hide the latency.
    let pair = FdPair::new(tmp.path(), "PingTimeout = 10\n", "PingTimeout = 10\n");
    let host_up = pair.alice.confbase.join("host-up");
    std::fs::write(
        &host_up,
        format!(
            "#!/bin/sh\nexec {} 2 </dev/null >/dev/null 2>&1\n",
            sleep_binary().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&host_up, std::fs::Permissions::from_mode(0o755)).unwrap();
    // start() polls bob too, who has no scripts and answers at once
    // while alice is busy firing host-up.
    let pair = pair.start();

    // Direct neighbours forward over the meta connection before
    // validkey, so only alice's loop liveness matters here.
    let mut max_latency = Duration::ZERO;
    for probe in 0..10u8 {
        let sent = Instant::now();
        write_fd(
            &pair.alice_dev,
            &mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], &[probe; 8]),
        );
        let received = poll_until(Duration::from_secs(5), || read_fd_nb(&pair.bob_dev));
        assert!(received.ends_with(&[probe; 8]));
        max_latency = max_latency.max(sent.elapsed());
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        max_latency < Duration::from_millis(500),
        "stalled: {max_latency:?}"
    );
}
