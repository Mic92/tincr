//! `tinc info`: three sequential dumps for a node (each request
//! carrying the name as a dead third argument, as C sends it), one for
//! an address.

use super::{Conf, tinc_with};

/// bob is second of three nodes (skip one, match, drain one), has two
/// of four edges and one subnet. status 0x52 = validkey | reachable |
/// sptps; options 0x07000004 = `PMTU_DISCOVERY` | protocol minor 7;
/// 1700000000 is 2023-11-14 22:13:20 UTC, hence `TZ=UTC`.
#[test]
fn info_node() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3 bob");
        ctl.send("18 3 alice 0 1.1.1.1 port 655 0 0 0 0 0 12 - alice 1 0 0 0 0 -1 0 0 0 0");
        ctl.send(
            "18 3 bob 0a1b2c3d4e5f 10.0.0.2 port 655 0 0 0 0 7000004 52 alice bob 1 \
             1518 1400 1518 1700000000 1500 100 50000 200 100000",
        );
        ctl.send("18 3 carol 0 unknown port unknown 0 0 0 0 0 0 - - 99 0 0 0 0 -1 0 0 0 0");
        ctl.send("18 3");
        ctl.expect("18 4 bob");
        ctl.send("18 4 alice bob 1.1.1.2 port 655 unspec port unspec 0 100");
        ctl.send("18 4 bob alice 1.1.1.1 port 655 unspec port unspec 0 100");
        ctl.send("18 4 bob carol 1.1.1.3 port 655 unspec port unspec 0 200");
        ctl.send("18 4 carol bob 1.1.1.2 port 655 unspec port unspec 0 200");
        ctl.send("18 4");
        ctl.expect("18 5 bob");
        ctl.send("18 5 10.0.0.0/24 alice");
        ctl.send("18 5 10.0.1.0/24 bob");
        ctl.send("18 5 ff:ff:ff:ff:ff:ff (broadcast)");
        ctl.send("18 5");
    });
    let base = conf.arg();
    let pidfile = conf.pidfile();
    let stdout = tinc_with(
        &[
            "-c",
            &base,
            "--pidfile",
            pidfile.to_str().unwrap(),
            "info",
            "bob",
        ],
        b"",
        |cmd| {
            cmd.env("TZ", "UTC");
        },
    )
    .ok();
    daemon.finish();
    assert_eq!(
        stdout,
        "\
Node:         bob
Node ID:      0a1b2c3d4e5f
Address:      10.0.0.2 port 655
Online since: 2023-11-14 22:13:20
Status:       validkey reachable sptps
Options:      pmtu_discovery
Protocol:     17.7
Reachability: directly with UDP
PMTU:         1518
RTT:          1.500
RX:           100 packets  50000 bytes
TX:           200 packets  100000 bytes
Edges:        alice carol
Subnets:      10.0.1.0/24
"
    );
}

/// No match in the nodes dump: error out without requesting edges.
#[test]
fn info_unknown_node_stops_after_nodes() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3 dave");
        ctl.send("18 3 alice 0 1.1.1.1 port 655 0 0 0 0 0 12 - alice 1 0 0 0 0 -1 0 0 0 0");
        ctl.send("18 3");
        ctl.expect_eof();
    });
    conf.tinc(&["info", "dave"])
        .fails_with("Unknown node dave.");
    daemon.finish();
}

/// Every containing subnet is printed (longest-prefix selection is
/// the daemon's job at packet time); MAC subnets never match an
/// address.
#[test]
fn info_address() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 5 10.0.0.5");
        ctl.send("18 5 10.0.0.0/24 alice");
        ctl.send("18 5 10.0.0.0/16 bob");
        ctl.send("18 5 192.168.0.0/24 carol");
        ctl.send("18 5 ff:ff:ff:ff:ff:ff (broadcast)");
        ctl.send("18 5");
    });
    let stdout = conf.tinc(&["info", "10.0.0.5"]).ok();
    daemon.finish();
    assert_eq!(
        stdout,
        "Subnet: 10.0.0.0/24\nOwner:  alice\nSubnet: 10.0.0.0/16\nOwner:  bob\n"
    );
}

#[test]
fn info_unknown_address() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 5 99.99.99.99");
        ctl.send("18 5 10.0.0.0/24 alice");
        ctl.send("18 5");
    });
    conf.tinc(&["info", "99.99.99.99"])
        .fails_with("Unknown address 99.99.99.99.");
    daemon.finish();
}

/// Rejected before connecting.
#[test]
fn info_invalid_argument() {
    Conf::bare()
        .tinc(&["info", "not/valid"])
        .fails_with("Argument is not a node name, subnet or address.");
}
