//! `retry()` (SIGALRM / `REQ_RETRY`) cuts an outgoing's backoff short,
//! plus the `REQ_DISCONNECT` reply codes.

use std::path::Path;
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[macro_use]
mod common;
use common::node::Node;
use common::refusing_port;

const BACKOFF_5S: &str = "re-establish outgoing connection in 5 seconds";

/// testnode dialing a dead peer, already in its first 5s backoff. The
/// socket keeps the dead port reserved. Linux refuses the connect at
/// once; macOS drops the SYN, so there each dial takes `PingTimeout`.
fn node_in_backoff(dir: &Path) -> (Node, socket2::Socket) {
    let (dead_socket, dead_port) = refusing_port();
    let mut deadpeer = Node::new(dir, "deadpeer", 0xDE);
    deadpeer.port = dead_port;
    let mut node = Node::new(dir, "testnode", 0x42).with_conf("PingTimeout = 3");
    node.write_config(&deadpeer, true);
    node.start();
    wait_log(&node, Duration::from_secs(5), |log| {
        log.contains(BACKOFF_5S)
    });
    (node, dead_socket)
}

/// Fails with the daemon log.
fn wait_log(node: &Node, timeout: Duration, done: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + timeout;
    while !done(&node.log()) {
        assert!(std::time::Instant::now() < deadline, "{}", node.log());
        thread::sleep(Duration::from_millis(20));
    }
}

/// Without retry the second dial would come after 5s; 2s proves the
/// timer was reset (and its outcome lands within `PingTimeout`). The second backoff being 5s again (not 10s)
/// proves the accumulated backoff was zeroed too.
#[test]
fn sigalrm_retries_now() {
    let tmp = tmp!("sigalrm");
    let (mut node, _dead) = node_in_backoff(tmp.path());
    node.signal(nix::sys::signal::Signal::SIGALRM);
    wait_log(&node, Duration::from_secs(2), |log| {
        log.matches("Trying to connect to deadpeer").count() >= 2
    });
    wait_log(&node, Duration::from_secs(4), |log| {
        log.matches(BACKOFF_5S).count() == 2
    });
    let log = node.stop();
    assert!(log.contains("Got SIGALRM"), "{log}");
    assert!(!log.contains("in 10 seconds"), "backoff not zeroed:\n{log}");
}

#[test]
fn req_retry_retries_now() {
    let tmp = tmp!("req-retry");
    let (node, _dead) = node_in_backoff(tmp.path());
    assert_eq!(node.ctl().retry(), 0);
    wait_log(&node, Duration::from_secs(2), |log| {
        log.matches("Trying to connect to deadpeer").count() >= 2
    });
}

/// Not-found → -2, malformed → -1, and the control connection
/// survives both.
#[test]
fn req_disconnect_replies() {
    let tmp = tmp!("disconnect");
    let mut node = Node::new(tmp.path(), "testnode", 0x42);
    node.write_config_multi(&[], &[]);
    node.start();
    let mut ctl = node.ctl();
    assert_eq!(ctl.request_line("18 12 nobody"), "18 12 -2");
    assert_eq!(ctl.request_line("18 12"), "18 12 -1");
    assert_eq!(ctl.dump(6).len(), 1, "only the control connection");
}
