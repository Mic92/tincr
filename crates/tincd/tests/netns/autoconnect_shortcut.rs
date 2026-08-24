//! `alice — {mid,mid2,mid3} — bob` with bob's UDP blackholed, so
//! alice's data to bob is relayed over TCP through mid. Three hubs
//! give alice the degree at which the autoconnect shortcut arm runs;
//! only alice has `AutoConnect = yes`.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::common::*;
use super::rig::*;
use super::tcp_fallback::iptables;

struct Mesh {
    pair: TunPair,
    hubs: Vec<Node>,
}

impl Mesh {
    /// Everything up, bob reachable via mid, alice at three meta
    /// connections and none to bob. `None` if iptables is unusable.
    fn start(netns: NetNs, tmp: &TmpGuard) -> Option<Self> {
        let TunPair {
            netns,
            mut alice,
            mut bob,
        } = TunPair::new(netns, tmp, "");
        alice = alice.log_level("tincd=info");
        bob = bob.with_conf("AutoConnect = no").log_level("tincd=info");
        let mut hubs: Vec<Node> = [("mid", 0xFC), ("mid2", 0xFD), ("mid3", 0xFE)]
            .into_iter()
            .map(|(name, seed)| Node::new(tmp.path(), name, seed).with_conf("AutoConnect = no"))
            .collect();
        for index in 0..3 {
            let mut peers: Vec<&Node> = hubs.iter().collect();
            peers.remove(index);
            peers.extend([&alice, &bob]);
            hubs[index].write_config_multi(&peers, &[]);
        }
        for hub in &mut hubs {
            hub.start();
        }
        bob.write_config_multi(&[&hubs[0], &alice], &[&hubs[0]]);
        bob.start();
        if !iptables(&[
            "-I",
            "INPUT",
            "-p",
            "udp",
            "--dport",
            &bob.port.to_string(),
            "-j",
            "DROP",
        ]) {
            return None;
        }
        let hub_refs: Vec<&Node> = hubs.iter().collect();
        let mut peers = hub_refs.clone();
        peers.push(&bob);
        alice.write_config_multi(&peers, &hub_refs);
        // Not a ConnectTo, but the shortcut needs to know where bob is.
        alice.write_host_file(&bob, true);
        alice.start();
        netns.place_devices();

        let mesh = Self {
            pair: TunPair { netns, alice, bob },
            hubs,
        };
        poll_until(Duration::from_secs(10), || {
            let reachable = node_status(&mesh.pair.alice.ctl().dump(3), "bob")? & 0x10 != 0;
            (reachable && mesh.meta_connections() >= 3).then_some(())
        });
        assert!(!mesh.alice_connected_to_bob());
        Some(mesh)
    }

    fn meta_connections(&self) -> usize {
        self.pair
            .alice
            .ctl()
            .dump(6)
            .iter()
            .filter(|row| !row.contains("<control>"))
            .count()
    }

    /// Any meta connection row for bob, in whatever state.
    fn alice_connected_to_bob(&self) -> bool {
        self.pair.alice.ctl().dump(6).iter().any(|row| {
            row.strip_prefix("18 6 ")
                .and_then(|body| body.split_whitespace().next())
                == Some("bob")
        })
    }

    /// ~100 KiB/s alice→bob, above the 32 KiB/s relay threshold.
    fn flood(extra: &[&str]) -> Child {
        Command::new("ping")
            .args(["-i", "0.01", "-s", "1000", "-q"])
            .args(extra)
            .arg("10.42.0.2")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping flood")
    }

    /// Flood until alice dials bob directly (≤ 6 ticks × 5s).
    fn flood_until_shortcut(&self) -> bool {
        let mut flood = Self::flood(&[]);
        let promoted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(Duration::from_secs(30), || {
                self.alice_connected_to_bob().then_some(())
            });
        }))
        .is_ok();
        let _ = flood.kill();
        let _ = flood.wait();
        promoted
    }

    fn finish(mut self) -> String {
        for hub in &mut self.hubs {
            hub.stop();
        }
        self.pair.finish().0
    }
}

/// Relayed load makes alice open a direct connection; once idle (after
/// the 60s minimum hold plus rate decay) she drops it again.
#[test]
fn autoconnect_shortcut_promotes_hot_relay() {
    let Some(netns) = enter_netns("autoconnect_shortcut::autoconnect_shortcut_promotes_hot_relay")
    else {
        return;
    };
    let tmp = tmp!("ac-shortcut");
    let Some(mesh) = Mesh::start(netns, &tmp) else {
        return;
    };
    assert!(
        mesh.flood_until_shortcut(),
        "shortcut not added\n{}",
        mesh.finish()
    );
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(90), || {
            (!mesh.alice_connected_to_bob()).then_some(())
        });
    }));
    let alice_log = mesh.finish();
    assert!(
        dropped.is_ok(),
        "shortcut not dropped after idle\n{alice_log}"
    );
}

/// Regression: a 30s pause in the load (shorter than the minimum
/// hold) must not drop and re-add the shortcut.
#[test]
fn shortcut_survives_traffic_gap() {
    let Some(netns) = enter_netns("autoconnect_shortcut::shortcut_survives_traffic_gap") else {
        return;
    };
    let tmp = tmp!("ac-shortcut-gap");
    let Some(mesh) = Mesh::start(netns, &tmp) else {
        return;
    };
    assert!(
        mesh.flood_until_shortcut(),
        "shortcut not added\n{}",
        mesh.finish()
    );
    let gap_start = Instant::now();
    let mut flapped = false;
    while gap_start.elapsed() < Duration::from_secs(30) && !flapped {
        flapped = !mesh.alice_connected_to_bob();
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = Mesh::flood(&["-w", "10"]).wait();
    let alice_log = mesh.finish();
    let activations = alice_log
        .lines()
        .filter(|line| line.contains("Connection with bob") && line.contains("activated"))
        .count();
    assert!(!flapped, "shortcut dropped during gap\n{alice_log}");
    assert_eq!(activations, 1, "{alice_log}");
}
