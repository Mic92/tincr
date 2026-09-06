use nix::sys::signal::Signal;
use std::time::{Duration, Instant, SystemTime};

use super::common::node::has_subnet;
use super::common::{
    Ctl, Node, poll_until, pubkey_from_seed, wait_for_file, write_ed25519_privkey,
};
use std::fmt::Write;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use tinc_crypto::invite::{build_slug, cookie_filename};
use tinc_crypto::sign::SigningKey;
use tinc_tools::cmd::join::Mode;
use tinc_tools::names::{Paths, PathsInput};

/// Rewrite `hosts/SELF` with `subnets` and SIGHUP. The sleep is for
/// the reload's `mtime > last_check` comparison at second granularity.
fn reload_with_subnets(node: &Node, subnets: &[&str]) {
    thread::sleep(Duration::from_millis(1100));
    let mut host = format!("Port = {}\n", node.port);
    for subnet in subnets {
        writeln!(host, "Subnet = {subnet}").unwrap();
    }
    fs::write(node.confbase.join("hosts").join(&node.name), host).unwrap();
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

/// Plant an invitation for bob on a running `alice` and return
/// `(url, invitation_file)`.
fn invite_bob(alice: &Node) -> (String, PathBuf) {
    let invitations = alice.confbase.join("invitations");
    fs::create_dir_all(&invitations).unwrap();
    let invitation_key = SigningKey::from_seed(&[0x11; 32]);
    write_ed25519_privkey(&invitations, &[0x11; 32]);
    let cookie: [u8; 18] = *b"test-cookie-18bxxx";
    let invitation_file = invitations.join(cookie_filename(&cookie, invitation_key.public_key()));
    fs::write(
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
    (url, invitation_file)
}

fn full(paths: &Paths) -> Mode<'_> {
    Mode::Full {
        paths,
        force: false,
    }
}

fn cli_paths(confbase: PathBuf) -> Paths {
    Paths::for_cli(&PathsInput {
        confbase: Some(confbase),
        ..Default::default()
    })
}

/// Real `tinc join` (in-process tinc-tools) against a real daemon. Covers
/// the invitation handshake, file transfer, key exchange and single use.
#[test]
fn tinc_join_consumes_invitation() {
    let tmp = tmp!("join");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA);
    alice.write_config_multi(&[], &[]);
    alice.start();
    let (url, invitation_file) = invite_bob(&alice);
    let paths_for = |dir: &str| cli_paths(tmp.path().join(dir));

    if let Err(err) = tinc_tools::cmd::join::join(&url, &full(&paths_for("bob"))) {
        panic!("join: {err:?}\nalice:\n{}", alice.stop());
    }
    let bob_confbase = tmp.path().join("bob");
    let bob_conf = fs::read_to_string(bob_confbase.join("tinc.conf")).unwrap();
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
        tinc_tools::cmd::join::join(&url, &full(&paths_for("bob2"))).is_err(),
        "invitation reused"
    );
}

/// With `HostsOverlayDirectory` set, the invited node's key is written to
/// the overlay rather than the deploy-managed `hosts/`, and the daemon
/// then authenticates bob from there.
#[test]
fn join_with_overlay_writes_there_and_peer_connects() {
    let tmp = tmp!("joinov");
    let mut alice =
        Node::new(tmp.path(), "alice", 0xAA).with_conf("HostsOverlayDirectory = hosts.local\n");
    alice.write_config_multi(&[], &[]);
    // The hook must learn where the file went. It cannot assume hosts/$NODE.
    let hook = alice.confbase.join("invitation-accepted");
    let hook_out = alice.confbase.join("hook.out");
    fs::write(
        &hook,
        format!(
            // A slow hook must not delay the joiner's ACK.
            "#!/bin/sh\nsleep 3\necho \"$NODE $HOST_FILE\" > '{}'\n",
            hook_out.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    alice.start();
    let (url, _) = invite_bob(&alice);

    let bob_confbase = tmp.path().join("bob");
    let t0 = Instant::now();
    if let Err(err) = tinc_tools::cmd::join::join(&url, &full(&cli_paths(bob_confbase.clone()))) {
        panic!("join: {err:?}\nalice:\n{}", alice.stop());
    }
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    let overlay_bob = alice.confbase.join("hosts.local/bob");
    assert!(wait_for_file(&overlay_bob));
    assert!(!alice.confbase.join("hosts/bob").exists());
    assert!(wait_for_file(&hook_out));
    assert_eq!(
        fs::read_to_string(&hook_out).unwrap().trim(),
        format!("bob {}", overlay_bob.display())
    );

    // bob dials alice with the joined config. His key exists only in
    // alice's overlay.
    let append = |p: &str, s: &str| {
        let p = bob_confbase.join(p);
        fs::write(&p, fs::read_to_string(&p).unwrap() + s).unwrap();
    };
    append(
        "tinc.conf",
        "DeviceType = dummy\nAddressFamily = ipv4\nPingTimeout = 1\n",
    );
    append("hosts/bob", "Port = 0\n");
    let mut bob = Node::new(tmp.path(), "bob", 0xBB);
    bob.start();
    alice.wait_for_peer("bob", true, Duration::from_secs(10));
}

/// `--identity-only`: bob's config is deployed out of band (here: written
/// by the test), the join only registers a key with alice and hands bob
/// the private half via `Ed25519PrivateKeyFile`.
#[test]
fn identity_only_join_registers_key_and_peer_connects() {
    let tmp = tmp!("joinid");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA);
    alice.write_config_multi(&[], &[]);
    alice.start();
    let (url, _) = invite_bob(&alice);

    let key = tmp.path().join("vault/bob.priv");
    fs::create_dir_all(key.parent().unwrap()).unwrap();
    if let Err(err) = tinc_tools::cmd::join::join(&url, &Mode::IdentityOnly(Some(key.clone()))) {
        panic!("join: {err:?}\nalice:\n{}", alice.stop());
    }
    assert!(key.exists());
    assert!(
        !tmp.path().join("bob").exists(),
        "identity-only wrote a confbase"
    );
    let alice_hosts_bob = alice.confbase.join("hosts/bob");
    assert!(wait_for_file(&alice_hosts_bob));

    // The "deploy": bob's confbase from the registry, key from the vault.
    let mut bob = Node::new(tmp.path(), "bob", 0xBB)
        .with_conf(&format!("Ed25519PrivateKeyFile = {}\n", key.display()));
    bob.write_config_multi(&[&alice], &[&alice]);
    // Not the harness key: the one the join generated.
    fs::remove_file(bob.confbase.join("ed25519_key.priv")).unwrap();
    bob.start();
    alice.wait_for_peer("bob", true, Duration::from_secs(10));
}

/// `tinc invite --replace bob` on alice while the old bob is connected.
/// A new device joins under bob's name. Alice keeps bob's Subnet and
/// swaps the key in the overlay, leaving `hosts/` untouched. The old bob
/// is kicked and stays out, the new key gets in.
#[test]
fn replace_invite_rekeys_node_and_drops_old_device() {
    let tmp = tmp!("replace");
    let mut alice =
        Node::new(tmp.path(), "alice", 0xAA).with_conf("HostsOverlayDirectory = hosts.local\n");
    let mut bob = Node::new(tmp.path(), "bob", 0xBB);
    bob.start_dialing(&mut alice);
    let hosts_bob = alice.confbase.join("hosts/bob");
    fs::write(
        &hosts_bob,
        fs::read_to_string(&hosts_bob).unwrap() + "Subnet = 10.0.0.7/32\n",
    )
    .unwrap();
    let hook = alice.confbase.join("invitation-accepted");
    let hook_out = alice.confbase.join("hook.out");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\necho \"$REPLACE $KARTEI_NS\" > '{}'\n",
            hook_out.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();

    // Real `tinc invite --replace`, which needs alice's Address for the URL.
    let hosts_alice = alice.confbase.join("hosts/alice");
    fs::write(
        &hosts_alice,
        fs::read_to_string(&hosts_alice).unwrap()
            + &format!("Address = 127.0.0.1 {}\n", alice.port),
    )
    .unwrap();
    let alice_paths = cli_paths(alice.confbase.clone());
    let now = SystemTime::now();
    let err =
        tinc_tools::cmd::invite::invite(&alice_paths, None, "bob", false, &[], now).unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    let env = [("KARTEI_NS".to_owned(), "mic92".to_owned())];
    let url = tinc_tools::cmd::invite::invite(&alice_paths, None, "bob", true, &env, now)
        .unwrap()
        .url;
    assert_eq!(alice.ctl().reload(), 0);

    let key = tmp.path().join("newbob.priv");
    if let Err(err) = tinc_tools::cmd::join::join(&url, &Mode::IdentityOnly(Some(key.clone()))) {
        panic!("join: {err:?}\nalice:\n{}", alice.stop());
    }

    let old_b64 = tinc_crypto::b64::encode(&bob.pubkey());
    let overlay_bob = alice.confbase.join("hosts.local/bob");
    assert!(wait_for_file(&overlay_bob));
    let new_host = fs::read_to_string(&overlay_bob).unwrap();
    assert!(
        new_host.starts_with("Subnet = 10.0.0.7/32\nEd25519PublicKey = "),
        "{new_host}"
    );
    assert!(!new_host.contains(&old_b64));
    assert!(fs::read_to_string(&hosts_bob).unwrap().contains(&old_b64));
    assert!(wait_for_file(&hook_out));
    assert_eq!(
        fs::read_to_string(&hook_out).unwrap().trim(),
        format!("{old_b64} mic92")
    );

    // Old bob was kicked and stays out when it retries with the old key.
    alice.wait_for_peer("bob", false, Duration::from_secs(10));
    thread::sleep(Duration::from_millis(1500));
    assert!(!alice.has_active_peer("bob"), "old key got back in");
    bob.stop();

    // New device with the joined key connects as bob.
    let mut newbob = Node::new(tmp.path(), "bob", 0xBB)
        .with_conf(&format!("Ed25519PrivateKeyFile = {}\n", key.display()));
    newbob.write_config_multi(&[&alice], &[&alice]);
    fs::remove_file(newbob.confbase.join("ed25519_key.priv")).unwrap();
    newbob.start();
    alice.wait_for_peer("bob", true, Duration::from_secs(10));
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

    thread::sleep(Duration::from_millis(1100));
    let hosts = bob.confbase.join("hosts");
    let new_hosts = bob.confbase.join("hosts.new");
    fs::create_dir(&new_hosts).unwrap();
    fs::copy(hosts.join("bob"), new_hosts.join("bob")).unwrap();
    fs::write(
        new_hosts.join("alice"),
        format!(
            "Ed25519PublicKey = {}\nAddress = 127.0.0.1 {}\n",
            tinc_crypto::b64::encode(&pubkey_from_seed(&[0xEE; 32])),
            alice.port
        ),
    )
    .unwrap();
    fs::rename(&hosts, bob.confbase.join("hosts.old")).unwrap();
    fs::rename(&new_hosts, &hosts).unwrap();

    let mut bob_ctl = bob.ctl();
    assert_eq!(bob_ctl.reload(), 0);
    bob.wait_for_peer("alice", false, Duration::from_secs(10));
    thread::sleep(Duration::from_millis(1500));
    assert!(
        !bob.has_active_peer("alice"),
        "re-authenticated with stale key"
    );
}
