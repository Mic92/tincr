//! `alice$ tinc export | ssh bob tinc import`

use super::Conf;

#[test]
fn export_needs_tinc_conf() {
    Conf::bare().tinc(&["export"]).fails_with("tinc.conf");
}

/// C import matches `sscanf("Name = %s")`, so the first line's exact
/// spelling is part of the format.
#[test]
fn export_then_import() {
    let alice = Conf::init("alice");
    let bob = Conf::init("bob");
    let host = alice.read("hosts/alice") + "Address = 192.0.2.1\nSubnet = 10.0.1.0/24\n";
    alice.write("hosts/alice", &host);

    let exported = alice.tinc(&["export"]).ok();
    assert_eq!(exported.lines().next(), Some("Name = alice"));
    bob.tinc_stdin(&["import"], exported.as_bytes()).ok();
    assert_eq!(bob.read("hosts/alice"), host);
}

#[test]
fn export_all_then_import() {
    let alice = Conf::init("alice");
    let charlie = Conf::init("charlie");
    alice.write("hosts/bob", "Subnet = 10.0.2.0/24\nAddress = 192.0.2.2\n");

    let exported = alice.tinc(&["export-all"]).ok();
    assert!(exported.contains("Name = alice") && exported.contains("Name = bob"));
    let run = charlie.tinc_stdin(&["import"], exported.as_bytes());
    assert!(run.stderr.contains("Imported 2"), "{}", run.stderr);
    run.ok();
    assert_eq!(
        charlie.read("hosts/bob"),
        "Subnet = 10.0.2.0/24\nAddress = 192.0.2.2\n"
    );
    assert!(
        !charlie.read("hosts/alice").contains("#-"),
        "separator leaked"
    );
}

/// Existing host files are only replaced with `--force`; importing
/// nothing is exit 1.
#[test]
fn import_existing_needs_force() {
    let conf = Conf::init("alice");
    let blob = b"Name = alice\nOVERWRITTEN\n";
    let stderr = conf
        .tinc_stdin(&["import"], blob)
        .fails_with("already exists");
    assert!(
        stderr.contains("No host configuration files imported"),
        "{stderr}"
    );
    assert!(conf.read("hosts/alice").contains("Ed25519PublicKey"));

    conf.tinc_stdin(&["--force", "import"], blob).ok();
    assert_eq!(conf.read("hosts/alice"), "OVERWRITTEN\n");
}
