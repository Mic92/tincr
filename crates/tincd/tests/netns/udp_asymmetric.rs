//! Regression: alice sits behind an inbound-UDP filter. Her probes
//! reach bob, bob's replies are eaten. bob acks probe sizes over the
//! meta connection, so alice→bob may still go UDP, while bob→alice
//! correctly stays on TCP (`minmtu == 0`).

use std::time::Duration;

use super::common::*;
use super::rig::*;
use super::tcp_fallback::iptables;

#[test]
fn udp_asymmetric_meta_confirm() {
    let Some(netns) = enter_netns("udp_asymmetric::udp_asymmetric_meta_confirm") else {
        return;
    };
    let tmp = tmp!("udpasym");
    // The meta ack is debounced by MTUInfoInterval and driven by the
    // ping tick; defaults would exceed the test budget.
    let mut pair = TunPair::new(netns, &tmp, "MTUInfoInterval = 1\nPingInterval = 1");
    let alice_port = pair.alice.reserve_port();
    if !iptables(&[
        "-I",
        "INPUT",
        "-p",
        "udp",
        "--dport",
        &alice_port.to_string(),
        "-j",
        "DROP",
    ]) {
        return;
    }
    pair.start_direct();
    pair.wait_validkey();

    let confirmed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(15), || {
            ping_once("10.42.0.2");
            let nodes = pair.alice.ctl().dump(3);
            let udp_confirmed = node_status(&nodes, "bob")? & 0x80 != 0;
            let (_, minmtu, _) = node_pmtu(&nodes, "bob")?;
            (udp_confirmed && minmtu >= 1400).then_some(())
        });
    }));
    let bob_nodes = pair.bob.ctl().dump(3);
    let (alice_log, bob_log) = pair.finish();
    assert!(
        confirmed.is_ok(),
        "alice never confirmed bob via meta\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    // bob's 0x80 bit does get set (he received alice's UDP), so
    // minmtu is the invariant that keeps bob→alice on TCP.
    assert_eq!(
        node_pmtu(&bob_nodes, "alice").map(|pmtu| pmtu.1),
        Some(0),
        "{bob_nodes:?}"
    );
    assert!(alice_log.contains("confirmed via meta"), "{alice_log}");
    assert!(bob_log.contains("Got UDP probe request"), "{bob_log}");
}
