//! `tinc dump`: the daemon's dump rows in, C `tinc`'s output format
//! out. Rows are what tincd's `dump_*` printf: note that a hostname
//! field is one `%s` printing `"HOST port PORT"`, three tokens.

use super::Conf;

const ALICE_ROW: &str = "18 3 alice 0a1b2c3d4e5f 10.0.0.1 port 655 \
     0 0 0 0 1000000c 12 bob alice 1 1518 1400 1518 1700000000 1500 100 50000 200 100000";
/// Unreachable, NULL hostname, no RTT.
const CAROL_ROW: &str =
    "18 3 carol 000000000000 unknown port unknown 0 0 0 0 0 0 - - 99 0 0 0 0 -1 0 0 0 0";

#[test]
fn dump_nodes_formats_like_c() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3");
        ctl.send(ALICE_ROW);
        ctl.send(CAROL_ROW);
        ctl.send("18 3");
    });
    let stdout = conf.tinc(&["dump", "nodes"]).succeeds();
    daemon.finish();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "alice id 0a1b2c3d4e5f at 10.0.0.1 port 655 cipher 0 digest 0 \
             maclength 0 compression 0 options 1000000c status 0012 \
             nexthop bob via alice distance 1 pmtu 1518 (min 1400 max 1518) \
             rx 100 50000 tx 200 100000 rtt 1.500",
            "carol id 000000000000 at unknown port unknown cipher 0 digest 0 \
             maclength 0 compression 0 options 0 status 0000 \
             nexthop - via - distance 99 pmtu 0 (min 0 max 0) rx 0 0 tx 0 0",
        ]
    );
}

/// Status bit 4 is "reachable"; carol has it clear.
#[test]
fn dump_reachable_nodes_filters() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3");
        ctl.send(ALICE_ROW);
        ctl.send(CAROL_ROW);
        ctl.send("18 3");
    });
    let stdout = conf.tinc(&["dump", "reachable", "nodes"]).succeeds();
    daemon.finish();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.starts_with("alice "));
}

/// `list` is an alias; same request on the wire.
#[test]
fn list_nodes_alias() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3");
        ctl.send(CAROL_ROW);
        ctl.send("18 3");
    });
    let stdout = conf.tinc(&["list", "nodes"]).succeeds();
    daemon.finish();
    assert!(stdout.starts_with("carol id "));
}

/// The default weight `#10` is stripped (tincd already does, an older
/// one might not); other weights stay.
#[test]
fn dump_subnets() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 5");
        ctl.send("18 5 10.0.0.0/24 alice");
        ctl.send("18 5 192.168.0.0/16#5 bob");
        ctl.send("18 5 ff:ff:ff:ff:ff:ff (broadcast)");
        ctl.send("18 5 172.16.0.0/12#10 carol");
        ctl.send("18 5");
    });
    let stdout = conf.tinc(&["dump", "subnets"]).succeeds();
    daemon.finish();
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            "10.0.0.0/24 owner alice",
            "192.168.0.0/16#5 owner bob",
            "ff:ff:ff:ff:ff:ff owner (broadcast)",
            "172.16.0.0/12 owner carol",
        ]
    );
}

/// Nodes and edges are requested back to back and answered in turn;
/// the first terminator must not end the read loop. MYSELF is drawn
/// filled, a node with working UDP (validkey, minmtu > 0) green, and
/// edge weight becomes `1 + 65536/weight` as C's float prints it.
#[test]
fn dump_digraph() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3");
        ctl.expect("18 4");
        ctl.send("18 3 alice 0 MYSELF port 655 0 0 0 0 0 1f - alice 0 1500 1500 1500 0 -1 0 0 0 0");
        ctl.send(
            "18 3 bob 0 1.1.1.2 port 655 0 0 0 0 0 12 alice bob 1 1500 1400 1500 0 -1 0 0 0 0",
        );
        ctl.send("18 3");
        ctl.send("18 4 alice bob 1.1.1.2 port 655 unspec port unspec 0 100");
        ctl.send("18 4 bob alice 1.1.1.1 port 655 unspec port unspec 0 100");
        ctl.send("18 4");
    });
    let stdout = conf.tinc(&["dump", "digraph"]).succeeds();
    daemon.finish();
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            "digraph {",
            " \"alice\" [label = \"alice\", color = \"green\", style = \"filled\"];",
            " \"bob\" [label = \"bob\", color = \"green\"];",
            " \"alice\" -> \"bob\" [w = 656.359985, weight = 656.359985];",
            " \"bob\" -> \"alice\" [w = 656.359985, weight = 656.359985];",
            "}",
        ]
    );
}

/// Undirected: only the `from < to` edge of each pair is printed.
#[test]
fn dump_graph_dedups_edges() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 3");
        ctl.expect("18 4");
        ctl.send("18 3 a 0 MYSELF port 1 0 0 0 0 0 1f - a 0 0 0 0 0 -1 0 0 0 0");
        ctl.send("18 3");
        ctl.send("18 4 a b 1.1.1.1 port 1 unspec port unspec 0 100");
        ctl.send("18 4 b a 1.1.1.1 port 1 unspec port unspec 0 100");
        ctl.send("18 4");
    });
    let stdout = conf.tinc(&["dump", "graph"]).succeeds();
    daemon.finish();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 4, "{stdout}");
    assert_eq!(lines[0], "graph {");
    assert!(lines[2].contains("\"a\" -- \"b\""), "{stdout}");
    assert!(!stdout.contains("\"b\" -"), "{stdout}");
}

/// Reads the invitations directory; never talks to the daemon.
#[test]
fn dump_invitations_without_daemon() {
    let conf = Conf::init("alice");
    assert_eq!(
        conf.tinc(&["dump", "invitations"]).succeeds(),
        "",
        "none outstanding: message goes to stderr"
    );

    let host = conf.read("hosts/alice");
    conf.write("hosts/alice", &format!("Address = 192.0.2.1\n{host}"));
    conf.tinc(&["invite", "bob"]).succeeds();
    let run = conf.tinc(&["dump", "invitations"]);
    assert!(!run.stderr.contains("pid file"), "{}", run.stderr);
    let stdout = run.succeeds();
    let [hash, invitee] = stdout.trim_end().split(' ').collect::<Vec<_>>()[..] else {
        panic!("{stdout:?}");
    };
    assert_eq!(hash.len(), 24, "b64 cookie hash");
    assert_eq!(invitee, "bob");
}

#[test]
fn dump_unknown_type() {
    Conf::bare()
        .tinc(&["dump", "lasers"])
        .fails_with("Unknown dump type 'lasers'.");
}
