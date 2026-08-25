//! Real kernel TUN on both ends: exercises `LinuxTun` (TUNSETIFF,
//! `vnet_hdr`, TSO re-segmentation) and real kernel checksums, which
//! the socketpair-based tests never touch.

use std::process::{Command, Stdio};
use std::time::Duration;

use super::common::KillOnDrop;
use super::rig::{TunPair, enter_netns, ping, tun_node};
use std::path::Path;
use std::thread;

#[test]
fn real_tun_ping() {
    let Some(netns) = enter_netns("ping::real_tun_ping") else {
        return;
    };
    let tmp = tmp!("ping");
    let pair = TunPair::start(netns, &tmp, "");
    pair.wait_validkey();

    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let (_, alice_out) = TunPair::traffic(&pair.alice);
    let (bob_in, _) = TunPair::traffic(&pair.bob);
    let (alice_log, bob_log) = pair.finish();
    assert!(
        output.status.success(),
        "{}\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(alice_out >= 3 && bob_in >= 3, "{alice_out} {bob_in}");
    assert!(alice_log.contains("interface: tinc0"), "{alice_log}");
    assert!(bob_log.contains("interface: tinc1"), "{bob_log}");
    assert!(alice_log.contains("SPTPS key exchange with bob successful"));
}

/// No subnet owns 10.42.0.99: alice synthesizes ICMP net-unknown back
/// into the TUN. The kernel only matches it to ping's socket if
/// checksum and quoted header are right, so ping printing the error
/// proves the packet is well-formed.
#[test]
fn real_tun_unreachable() {
    let Some(netns) = enter_netns("ping::real_tun_unreachable") else {
        return;
    };
    let tmp = tmp!("unreach");
    let mut alice = tun_node(tmp.path(), "alice", 0xA9, "tinc0").log_level("tincd=debug");
    alice.write_config_multi(&[], &[]);
    alice.start();
    netns.place_alice();

    // Two only: a third within the second hits the ICMP rate limit.
    let output = ping(&["-c", "2", "-W", "2"], "10.42.0.99");
    let text = String::from_utf8_lossy(&output.stdout) + String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    // iputils: "Destination Net Unknown"; busybox: "No route to host".
    assert!(
        ["Unreachable", "Unknown", "No route"]
            .iter()
            .any(|needle| text.contains(needle)),
        "{text}"
    );
    assert!(alice.stop().contains("route: sending ICMP UNREACH"));
}

/// 8 MiB TCP stream through the tunnel with TSO on: the kernel hands
/// alice ≤64K super-segments and `tso_split` must re-synthesize
/// seqnos, checksums and flags. Any mistake shows up as a sha256
/// mismatch (wrong bytes) or a hang (dropped segments).
#[test]
fn tso_ingest_stream_integrity() {
    let Some(netns) = enter_netns("ping::tso_ingest_stream_integrity") else {
        return;
    };
    let tmp = tmp!("tso");
    let mut pair = TunPair::new(netns, &tmp, "");
    // "TSO ingest enabled" is logged by tinc_device at info.
    pair.alice = pair.alice.log_level("info");
    pair.bob = pair.bob.log_level("tincd=info");
    pair.start_direct();
    pair.wait_validkey();

    let data_path = tmp.path().join("stream.bin");
    let status = Command::new("dd")
        .args(["if=/dev/urandom", "bs=1M", "count=8"])
        .arg(format!("of={}", data_path.display()))
        .stderr(Stdio::null())
        .status()
        .expect("spawn dd");
    assert!(status.success());
    let sha256 = |path: &Path| {
        let out = Command::new("sha256sum").arg(path).output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    };

    let received_path = tmp.path().join("received.bin");
    let mut receiver = KillOnDrop(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                "bobside",
                "socat",
                "-u",
                "TCP-LISTEN:18099,reuseaddr",
            ])
            .arg(format!("CREATE:{}", received_path.display()))
            .spawn()
            .expect("spawn receiver"),
    );
    thread::sleep(Duration::from_millis(200));
    let sender = Command::new("socat")
        .arg("-u")
        .arg(format!("FILE:{}", data_path.display()))
        .arg("TCP:10.42.0.2:18099,connect-timeout=5")
        .output()
        .expect("spawn sender");
    // The FIN still has to cross the tunnel, so reap before `finish`.
    let receiver_ok = sender.status.success() && receiver.0.wait().unwrap().success();
    let (alice_log, bob_log) = pair.finish();
    assert!(
        receiver_ok,
        "{}\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}",
        String::from_utf8_lossy(&sender.stderr)
    );
    assert!(alice_log.contains("TSO ingest enabled"), "{alice_log}");
    // A warning here means a super-segment was dropped and TCP
    // retransmitted around it.
    assert!(!alice_log.contains("tso_split"), "{alice_log}");
    assert_eq!(
        sha256(&data_path),
        sha256(&received_path),
        "stream corrupted"
    );
}
