//! Rust tincd ↔ C tincd over real TUN/TAP: the end-to-end wire
//! compatibility check (ID, meta-SPTPS, ACK, graph gossip,
//! `REQ_KEY/ANS_KEY`, per-tunnel SPTPS, UDP framing, PACKET 17).
//!
//! Gated on `TINC_C_TINCD` pointing at a C `tincd` (the devshell sets
//! it; otherwise `nix build .#tincd-c`). Unset → SKIP.

use std::path::PathBuf;

use super::common::TmpGuard;
use super::rig::{NetNs, Node, TunPair, enter_bwrap, ping};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

#[derive(Clone, Copy)]
enum Impl {
    Rust,
    C,
}

/// SKIP unless `TINC_C_TINCD` is set, then the usual bwrap re-exec.
fn enter(test_name: &str, tap: bool) -> Option<NetNs> {
    if env::var_os("BWRAP_INNER").is_none() && env::var_os("TINC_C_TINCD").is_none() {
        eprintln!("SKIP {test_name}: TINC_C_TINCD not set (nix develop sets it)");
        return None;
    }
    enter_bwrap(test_name).then(|| NetNs::setup(tap))
}

fn with_impl(node: Node, which: Impl) -> Node {
    match which {
        Impl::Rust => node.log_level("tincd=debug"),
        Impl::C => node.c_tincd(PathBuf::from(env::var_os("TINC_C_TINCD").unwrap())),
    }
}

fn pair(netns: NetNs, tmp: &TmpGuard, alice: Impl, bob: Impl, extra_conf: &str) -> TunPair {
    let mut pair = TunPair::new(netns, tmp, extra_conf);
    pair.alice = with_impl(pair.alice, alice);
    pair.bob = with_impl(pair.bob, bob);
    pair
}

fn assert_ping(pair: TunPair) {
    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let subnets = pair.alice.ctl().dump(5);
    let (alice_log, bob_log) = pair.finish();
    assert!(
        output.status.success(),
        "{}\nalice subnets: {subnets:?}\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Router mode over UDP. Waiting for `udp_confirmed`, not just
/// validkey, keeps the first pings from racing PMTU discovery.
fn router_mode(test_name: &str, alice: Impl, bob: Impl) {
    let Some(netns) = enter(test_name, false) else {
        return;
    };
    let tmp = tmp!("crossimpl");
    let mut pair = pair(netns, &tmp, alice, bob, "");
    pair.start_direct();
    pair.wait_validkey();
    pair.wait_udp_confirmed();
    assert_ping(pair);
}

/// Our initiator side; in particular `ANS_KEY` from C carries `-1 -1 -1`
/// for cipher/digest/maclen, which must parse strtoul-style.
#[test]
fn rust_dials_c() {
    router_mode("crossimpl::rust_dials_c", Impl::Rust, Impl::C);
}

/// Our responder side of the same.
#[test]
fn c_dials_rust() {
    router_mode("crossimpl::c_dials_rust", Impl::C, Impl::Rust);
}

/// Regression: `hosts/bob` with a bare `Address =` and a separate
/// `Port =` line once dialled 655 instead of `Port`.
#[test]
fn rust_dials_c_bare_address_port() {
    let Some(netns) = enter("crossimpl::rust_dials_c_bare_address_port", false) else {
        return;
    };
    let tmp = tmp!("crossimpl");
    let mut pair = pair(netns, &tmp, Impl::Rust, Impl::C, "");
    pair.bob.write_config(&pair.alice, false);
    pair.bob.start();
    pair.alice.write_config(&pair.bob, true);
    fs::write(
        pair.alice.confbase.join("hosts/bob"),
        format!(
            "Ed25519PublicKey = {}\nPort = {}\nAddress = 127.0.0.1\n",
            tinc_crypto::b64::encode(&pair.bob.pubkey()),
            pair.bob.port
        ),
    )
    .unwrap();
    pair.alice.start();
    pair.wait_reachable();
}

/// `TCPOnly = yes` on both: PMTU never runs, so every packet goes as
/// PACKET 17 inside the meta connection (single-encrypted raw frame),
/// never UDP and never per-tunnel SPTPS. Set in `hosts/PEER` too
/// because that is where C reads it from.
fn tcponly(test_name: &str, alice: Impl, bob: Impl) {
    let Some(netns) = enter(test_name, false) else {
        return;
    };
    let tmp = tmp!("crossimpl");
    let mut pair = pair(netns, &tmp, alice, bob, "TCPOnly = yes");
    pair.bob.write_config(&pair.alice, false);
    append(&pair.bob.confbase.join("hosts/alice"), "TCPOnly = yes\n");
    pair.bob.start();
    pair.alice.write_config(&pair.bob, true);
    append(&pair.alice.confbase.join("hosts/bob"), "TCPOnly = yes\n");
    pair.alice.start();
    pair.netns.place_devices();
    pair.wait_reachable();
    assert_ping(pair);
}

fn append(path: &Path, text: &str) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

/// Our PACKET 17 send path.
#[test]
fn rust_dials_c_tcponly() {
    tcponly("crossimpl::rust_dials_c_tcponly", Impl::Rust, Impl::C);
}

/// Our PACKET 17 receive path (regression: once silently dropped).
#[test]
fn c_dials_rust_tcponly() {
    tcponly("crossimpl::c_dials_rust_tcponly", Impl::C, Impl::Rust);
}

/// `Mode = switch` over TAP, no preconfigured subnets: alice's ARP
/// broadcast must be forwarded, both sides must learn and gossip MAC
/// subnets, then unicast routes by MAC. Devices come up only after
/// the meta handshake (see `NetNs::setup`).
fn switch_mode(test_name: &str, alice: Impl, bob: Impl) {
    let Some(netns) = enter(test_name, true) else {
        return;
    };
    let tmp = tmp!("crossimpl");
    let mut pair = pair(netns, &tmp, alice, bob, "Mode = switch");
    for node in [&mut pair.alice, &mut pair.bob] {
        node.subnets.clear();
        node.tap = true;
    }
    pair.bob.write_config(&pair.alice, false);
    pair.bob.start();
    pair.alice.write_config(&pair.bob, true);
    pair.alice.start();
    pair.wait_reachable();
    pair.netns.place_devices();
    pair.wait_validkey();
    pair.wait_udp_confirmed();

    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let subnets = pair.alice.ctl().dump(5);
    let (alice_log, bob_log) = pair.finish();
    assert!(
        output.status.success(),
        "alice subnets: {subnets:?}\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    // MAC subnets have single colons; IPv6 would have `::`.
    assert!(
        subnets
            .iter()
            .any(|row| row.contains(':') && !row.contains("::")),
        "no MAC subnet learned: {subnets:?}"
    );
}

#[test]
fn rust_dials_c_switch() {
    switch_mode("crossimpl::rust_dials_c_switch", Impl::Rust, Impl::C);
}

#[test]
fn c_dials_rust_switch() {
    switch_mode("crossimpl::c_dials_rust_switch", Impl::C, Impl::Rust);
}
