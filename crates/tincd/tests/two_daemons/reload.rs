use std::time::Duration;

use nix::sys::signal::Signal;

use super::common::node::has_subnet;
use super::common::{
    Ctl, Node, poll_until, pubkey_from_seed, wait_for_file, write_ed25519_privkey,
};

/// Rewrite `hosts/SELF` with `subnets` and SIGHUP. The sleep is for
/// the reload's `mtime > last_check` comparison at second granularity.
fn reload_with_subnets(node: &Node, subnets: &[&str]) {
    std::thread::sleep(Duration::from_millis(1100));
    let mut host = format!("Port = {}\n", node.port);
    for subnet in subnets {
        use std::fmt::Write;
        writeln!(host, "Subnet = {subnet}").unwrap();
    }
    std::fs::write(node.confbase.join("hosts").join(&node.name), host).unwrap();
    node.signal(Signal::SIGHUP);
}

fn wait_for_subnets(ctl: &mut Ctl, owner: &str, present: &[&str], absent: &[&str]) {
    poll_until(Duration::from_secs(10), || {
        let subnets = ctl.dump(5);
        (present.iter().all(|s| has_subnet(&subnets, s, owner))
            && absent.iter().all(|s| !has_subnet(&subnets, s, owner)))
        .then_some(())
    });
}

/// SIGHUP → re-read own subnets → diff → `ADD_SUBNET`/`DEL_SUBNET` to the peer.
/// The DEL half also guards the `on_del_subnet` lookup-before-owner
/// reorder from security fix 2f72c2ba.
#[test]
fn sighup_subnet_changes_reach_peer() {
    let tmp = tmp!("reload");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA).subnet("10.0.0.0/24");
    let mut bob = Node::new(tmp.path(), "bob", 0xBB);
    bob.start_dialing(&mut alice);
    let mut bob_ctl = bob.ctl();
    wait_for_subnets(&mut bob_ctl, "alice", &["10.0.0.0/24"], &["10.1.0.0/24"]);

    reload_with_subnets(&alice, &["10.0.0.0/24", "10.1.0.0/24"]);
    wait_for_subnets(&mut bob_ctl, "alice", &["10.0.0.0/24", "10.1.0.0/24"], &[]);
    assert!(has_subnet(&alice.ctl().dump(5), "10.1.0.0/24", "alice"));

    reload_with_subnets(&alice, &["10.0.0.0/24"]);
    wait_for_subnets(&mut bob_ctl, "alice", &["10.0.0.0/24"], &["10.1.0.0/24"]);
}

/// Real `tinc join` (in-process tinc-tools) against a real daemon:
/// invitation handshake, file transfer, key exchange, and single use.
#[test]
fn tinc_join_consumes_invitation() {
    use tinc_crypto::invite::{build_slug, cookie_filename};
    use tinc_crypto::sign::SigningKey;

    let tmp = tmp!("join");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA);
    alice.write_config_multi(&[], &[]);
    alice.start();

    let invitations = alice.confbase.join("invitations");
    std::fs::create_dir_all(&invitations).unwrap();
    let invitation_key = SigningKey::from_seed(&[0x11; 32]);
    write_ed25519_privkey(&invitations, &[0x11; 32]);
    let cookie: [u8; 18] = *b"test-cookie-18bxxx";
    let invitation_file = invitations.join(cookie_filename(&cookie, invitation_key.public_key()));
    std::fs::write(
        &invitation_file,
        format!(
            "Name = bob\nConnectTo = alice\n\
             #---------------------------------------------------------------#\n\
             Name = alice\nEd25519PublicKey = {}\nAddress = 127.0.0.1 {}\n",
            tinc_crypto::b64::encode(&alice.pubkey()),
            alice.port
        ),
    )
    .unwrap();
    // The daemon loads the invitation key at startup/reload only.
    assert_eq!(alice.ctl().reload(), 0);

    let url = format!(
        "127.0.0.1:{}/{}",
        alice.port,
        build_slug(invitation_key.public_key(), &cookie)
    );
    let paths_for = |dir: &str| {
        tinc_tools::names::Paths::for_cli(&tinc_tools::names::PathsInput {
            confbase: Some(tmp.path().join(dir)),
            ..Default::default()
        })
    };

    if let Err(err) = tinc_tools::cmd::join::join(&url, &paths_for("bob"), false) {
        panic!("join: {err:?}\nalice:\n{}", alice.stop());
    }
    let bob_confbase = tmp.path().join("bob");
    let bob_conf = std::fs::read_to_string(bob_confbase.join("tinc.conf")).unwrap();
    assert!(
        bob_conf.contains("Name = bob") && bob_conf.contains("ConnectTo = alice"),
        "{bob_conf}"
    );
    assert!(
        std::fs::read_to_string(bob_confbase.join("hosts/alice"))
            .unwrap()
            .contains("Ed25519PublicKey")
    );
    assert!(bob_confbase.join("ed25519_key.priv").exists());

    let alice_hosts_bob = alice.confbase.join("hosts/bob");
    assert!(wait_for_file(&alice_hosts_bob));
    assert!(
        std::fs::read_to_string(&alice_hosts_bob)
            .unwrap()
            .starts_with("Ed25519PublicKey = ")
    );
    assert!(!invitation_file.exists());
    assert!(!invitation_file.with_extension("used").exists());

    assert!(
        tinc_tools::cmd::join::join(&url, &paths_for("bob2"), false).is_err(),
        "invitation reused"
    );
}

/// Android bundle update: rename-swap `hosts/` and reload over the
/// control socket. A peer whose key changed must be dropped and must
/// not get back in with the old key.
#[test]
fn control_reload_after_hosts_swap_drops_rekeyed_peer() {
    let tmp = tmp!("hswap");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA);
    let mut bob = Node::new(tmp.path(), "bob", 0xBB);
    bob.start_dialing(&mut alice);

    std::thread::sleep(Duration::from_millis(1100));
    let hosts = bob.confbase.join("hosts");
    let new_hosts = bob.confbase.join("hosts.new");
    std::fs::create_dir(&new_hosts).unwrap();
    std::fs::copy(hosts.join("bob"), new_hosts.join("bob")).unwrap();
    std::fs::write(
        new_hosts.join("alice"),
        format!(
            "Ed25519PublicKey = {}\nAddress = 127.0.0.1 {}\n",
            tinc_crypto::b64::encode(&pubkey_from_seed(&[0xEE; 32])),
            alice.port
        ),
    )
    .unwrap();
    std::fs::rename(&hosts, bob.confbase.join("hosts.old")).unwrap();
    std::fs::rename(&new_hosts, &hosts).unwrap();

    let mut bob_ctl = bob.ctl();
    assert_eq!(bob_ctl.reload(), 0);
    bob.wait_for_peer("alice", false, Duration::from_secs(10));
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        !bob.has_active_peer("alice"),
        "re-authenticated with stale key"
    );
}
