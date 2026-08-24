//! tinc-up/-down, host-up/-down, hosts/NAME-up/-down and
//! subnet-up/-down fire in the right order with the right env.
//! Scripts run synchronously in the daemon, so the append order of a
//! shared log file is the firing order.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

#[macro_use]
mod common;
use common::node::Node;
use common::poll_until;

const ENV_KEYS: [&str; 7] = [
    "NAME",
    "NODE",
    "SUBNET",
    "WEIGHT",
    "REMOTEADDRESS",
    "REMOTEPORT",
    "INTERFACE",
];

#[derive(Debug)]
struct Event {
    /// Basename: `tinc-up`, `host-up`, `bob-up`, …
    script: String,
    /// Unset variables come through as "".
    env: HashMap<String, String>,
}

struct ScriptLog(std::path::PathBuf);

impl ScriptLog {
    /// Installs every script kind (plus `hosts/{peer}-up/-down`) into
    /// `node`'s confbase, all appending one `script|K=V|…` line here.
    fn install(dir: &Path, node: &Node, peer: Option<&str>) -> Self {
        let log = dir.join(format!("{}-events.log", node.name));
        let mut vars = String::new();
        for key in ENV_KEYS {
            write!(vars, "|{key}=${key}").unwrap();
        }
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"${{0##*/}}{vars}\" >> '{}'\n",
            log.display()
        );
        let mut names: Vec<String> = ["tinc", "host", "subnet"]
            .iter()
            .flat_map(|kind| [format!("{kind}-up"), format!("{kind}-down")])
            .collect();
        if let Some(peer) = peer {
            names.extend([format!("hosts/{peer}-up"), format!("hosts/{peer}-down")]);
        }
        for name in names {
            let path = node.confbase.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self(log)
    }

    fn events(&self) -> Vec<Event> {
        std::fs::read_to_string(&self.0)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let mut parts = line.split('|');
                let script = parts.next().unwrap().to_owned();
                let env = parts
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect();
                Event { script, env }
            })
            .collect()
    }

    fn wait_len(&self, len: usize) -> Vec<Event> {
        poll_until(Duration::from_secs(5), || {
            Some(self.events()).filter(|events| events.len() >= len)
        })
    }

    /// Wait until an event `script` with `NODE == node` shows up.
    fn wait_for(&self, script: &str, node: &str) -> Vec<Event> {
        poll_until(Duration::from_secs(10), || {
            let events = self.events();
            events
                .iter()
                .any(|event| event.script == script && event.env["NODE"] == node)
                .then_some(events)
        })
    }
}

fn position(events: &[Event], script: &str, node: &str) -> usize {
    events
        .iter()
        .position(|event| event.script == script && event.env["NODE"] == node)
        .unwrap_or_else(|| panic!("no {script} for {node:?} in {events:#?}"))
}

/// Scripts fork/exec inside the event loop; under load that can eat
/// the default 1s `PingTimeout` mid-handshake.
fn node(dir: &Path, name: &str, seed: u8) -> Node {
    Node::new(dir, name, seed).with_conf("PingTimeout = 3")
}

#[test]
fn tinc_up_then_own_subnet_up() {
    let tmp = tmp!("startup");
    let mut alice = node(tmp.path(), "alice", 0xA1)
        .subnet("10.0.1.0/24#5")
        .subnet("fec0::/64");
    alice.write_config_multi(&[], &[]);
    let log = ScriptLog::install(tmp.path(), &alice, None);
    alice.start();

    let events = log.wait_len(3);
    assert_eq!(events.len(), 3, "{events:#?}");
    assert_eq!(events[0].script, "tinc-up");
    assert_eq!(events[0].env["NAME"], "alice");
    assert_eq!(events[0].env["INTERFACE"], "dummy");
    assert_eq!(events[0].env["NODE"], "");
    assert_eq!(events[0].env["SUBNET"], "");
    let mut weights = HashMap::new();
    for event in &events[1..] {
        assert_eq!(event.script, "subnet-up");
        assert_eq!(event.env["NODE"], "alice");
        assert_eq!(event.env["REMOTEADDRESS"], "");
        weights.insert(event.env["SUBNET"].as_str(), event.env["WEIGHT"].as_str());
    }
    assert_eq!(
        weights,
        HashMap::from([("10.0.1.0/24", "5"), ("fec0::/64", "10")])
    );
}

#[test]
fn host_up_order_on_connect() {
    let tmp = tmp!("connect");
    let mut alice = node(tmp.path(), "alice", 0xA2).subnet("10.0.1.0/24");
    let mut bob = node(tmp.path(), "bob", 0xB2).subnet("10.0.2.0/24");
    bob.write_config(&alice, false);
    bob.start();
    alice.write_config(&bob, true);
    let log = ScriptLog::install(tmp.path(), &alice, Some("bob"));
    alice.start();

    let events = log.wait_for("subnet-up", "bob");
    let host_up = position(&events, "host-up", "bob");
    let bob_up = position(&events, "bob-up", "bob");
    let subnet_up = position(&events, "subnet-up", "bob");
    assert!(host_up < bob_up && bob_up < subnet_up, "{events:#?}");

    for index in [host_up, bob_up, subnet_up] {
        let env = &events[index].env;
        assert_eq!(env["NAME"], "alice");
        assert_eq!(env["INTERFACE"], "dummy");
        assert_eq!(env["REMOTEADDRESS"], "127.0.0.1");
        assert_eq!(env["REMOTEPORT"], bob.port.to_string());
    }
    assert_eq!(events[subnet_up].env["SUBNET"], "10.0.2.0/24");
    assert_eq!(events[subnet_up].env["WEIGHT"], "10");
}

#[test]
fn host_down_order_on_disconnect() {
    let tmp = tmp!("disconnect");
    let mut alice = node(tmp.path(), "alice", 0xA3).subnet("10.0.1.0/24");
    let mut bob = node(tmp.path(), "bob", 0xB3).subnet("10.0.2.0/24");
    bob.write_config(&alice, false);
    bob.start();
    alice.write_config(&bob, true);
    let log = ScriptLog::install(tmp.path(), &alice, Some("bob"));
    alice.start();
    let connected = log.wait_for("subnet-up", "bob").len();

    bob.stop();
    let events = log.wait_for("subnet-down", "bob");
    let events = &events[connected..];
    let host_down = position(events, "host-down", "bob");
    let bob_down = position(events, "bob-down", "bob");
    let subnet_down = position(events, "subnet-down", "bob");
    assert!(
        host_down < bob_down && bob_down < subnet_down,
        "{events:#?}"
    );
    // The address is read before the node is reset, so it is still set.
    assert_eq!(events[host_down].env["REMOTEADDRESS"], "127.0.0.1");
    assert_eq!(events[subnet_down].env["SUBNET"], "10.0.2.0/24");
}

#[test]
fn own_subnet_down_then_tinc_down_on_shutdown() {
    let tmp = tmp!("shutdown");
    let mut alice = node(tmp.path(), "alice", 0xA4).subnet("10.0.1.0/24");
    alice.write_config_multi(&[], &[]);
    let log = ScriptLog::install(tmp.path(), &alice, None);
    alice.start();
    let started = log.wait_len(2).len();

    // SIGKILL would skip the shutdown scripts.
    alice.signal(nix::sys::signal::Signal::SIGTERM);
    assert!(alice.wait_exit().success());
    let events = log.events();
    let events = &events[started..];
    let subnet_down = position(events, "subnet-down", "alice");
    let tinc_down = position(events, "tinc-down", "");
    assert!(subnet_down < tinc_down, "{events:#?}");
    assert_eq!(events[subnet_down].env["SUBNET"], "10.0.1.0/24");
    assert_eq!(events[subnet_down].env["REMOTEADDRESS"], "");
    assert_eq!(events[tinc_down].env["NAME"], "alice");
    assert_eq!(events[tinc_down].env["INTERFACE"], "dummy");
}
