use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use super::common::*;
use super::node::*;

/// SIGHUP reload: alice changes her own Subnets, sends SIGHUP, bob
/// sees the diff via `ADD_SUBNET` / `DEL_SUBNET`.
///
/// ## What's proven (per step)
///
/// 1. **Reload reads config**: alice's `read_server_config` re-runs
///    on SIGHUP. The diff sees `10.1.0.0/24` as new.
/// 2. **`diff_subnets` + broadcast**: alice's `reload_configuration`
///    sends `ADD_SUBNET` for the new subnet. Bob's `on_add_subnet`
///    fires; `dump subnets` shows it.
/// 3. **DEL half**: removing the subnet + SIGHUP → bob sees it gone.
///
/// This is the strongest reload test — it exercises the full chain:
/// signal → self-pipe wake → `reload_configuration` → diff → broadcast
/// → peer's `on_add_subnet` → `SubnetTree`.
#[test]
fn sighup_reload_subnets() {
    let tmp = tmp!("reload");
    let alice = Node::new(tmp.path(), "alice", 0xAA);
    let bob = Node::new(tmp.path(), "bob", 0xBB);

    // alice has ONE subnet initially.
    let alice = alice.subnet("10.0.0.0/24");
    alice.write_config(&bob, false);
    bob.write_config(&alice, true);

    let mut alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed: {}",
        drain_stderr(alice_child)
    );
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = alice_child.kill();
        panic!("bob setup failed: {}", drain_stderr(bob_child));
    }

    // Wait for the connection.
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        if has_active_peer(&bob_ctl.dump(6), "alice") {
            Some(())
        } else {
            None
        }
    });

    // ─── baseline: bob sees alice's 10.0.0.0/24 ──────────────
    poll_until(Duration::from_secs(5), || {
        if has_subnet(&bob_ctl.dump(5), "10.0.0.0/24", "alice") {
            Some(())
        } else {
            None
        }
    });
    let baseline = bob_ctl.dump(5);
    assert!(
        !has_subnet(&baseline, "10.1.0.0/24", "alice"),
        "baseline should NOT have 10.1.0.0/24 yet: {baseline:?}"
    );

    // ─── step 1: ADD a subnet ───────────────────────────────
    // Rewrite alice's hosts/alice with BOTH subnets. Port stays.
    // Sleep 1.1s before write: `conns_to_terminate` uses
    // `mtime > last_config_check` (strict, second-granularity);
    // a write in the same wall-clock second as boot would have
    // `mtime == last_config_check` and not trigger. Our test
    // doesn't WANT it to trigger (we're rewriting alice's OWN
    // hosts file, not a peer's), but the safety margin avoids
    // flakiness if mtime semantics differ across filesystems.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!(
            "Port = {}\nSubnet = 10.0.0.0/24\nSubnet = 10.1.0.0/24\n",
            alice.port
        ),
    )
    .unwrap();

    // SIGHUP alice. Read pid from pidfile (first token).
    let alice_pid: i32 = std::fs::read_to_string(&alice.pidfile)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    kill(Pid::from_raw(alice_pid), Signal::SIGHUP).expect("kill SIGHUP");

    // Poll bob until 10.1.0.0/24 appears. This proves: alice
    // re-read config, diff_subnets found the new one, sent
    // ADD_SUBNET, bob received and added.
    poll_until(Duration::from_secs(10), || {
        let s = bob_ctl.dump(5);
        if has_subnet(&s, "10.1.0.0/24", "alice") && has_subnet(&s, "10.0.0.0/24", "alice") {
            Some(())
        } else {
            None
        }
    });

    // alice's own dump: also shows both (proves SubnetTree.add).
    let a_subnets = alice_ctl.dump(5);
    assert!(
        has_subnet(&a_subnets, "10.1.0.0/24", "alice"),
        "alice should have new subnet locally: {a_subnets:?}"
    );

    // ─── step 2: REMOVE a subnet ────────────────────────────
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!("Port = {}\nSubnet = 10.0.0.0/24\n", alice.port),
    )
    .unwrap();
    kill(Pid::from_raw(alice_pid), Signal::SIGHUP).expect("kill SIGHUP");

    // Poll until 10.1.0.0/24 is GONE. Proves DEL_SUBNET path.
    poll_until(Duration::from_secs(10), || {
        let s = bob_ctl.dump(5);
        if !has_subnet(&s, "10.1.0.0/24", "alice") && has_subnet(&s, "10.0.0.0/24", "alice") {
            Some(())
        } else {
            None
        }
    });

    // ─── cleanup ───────────────────────────────────────────────
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let _ = drain_stderr(bob_child);
    // alice should have logged the reload.
    assert!(
        alice_stderr.contains("SIGHUP") || alice_stderr.contains("reload"),
        "alice should log reload; stderr:\n{alice_stderr}"
    );
}

/// `tinc join` against a real daemon. The strongest invitation test:
/// real TCP, real epoll, real `tinc-tools::cmd::join::join()`.
///
/// ## Setup chain
///
/// 1. Alice's confbase: tinc.conf + hosts/alice + `ed25519_key.priv`
///    + `invitations/ed25519_key.priv` (the per-mesh invitation key).
/// 2. The invitation FILE: `invitations/<cookie_filename>` with
///    `Name = bob\n#-----#\n<alice's host file>\n`.
/// 3. The URL: `127.0.0.1:<alice-port>/<slug>` where slug =
///    `b64(key_hash(inv_pubkey)) || b64(cookie)`.
///
/// ## What's proven (full chain)
///
/// - daemon's `id_h` `?` branch: throwaway-key parse, `invitation_key`
///   present, plaintext greeting (line1+line2), SPTPS start with
///   the 15-byte no-NUL label.
/// - SPTPS handshake: joiner Initiator, daemon Responder. Label
///   match (both sides use 15 bytes).
/// - `dispatch_invitation_outputs`: cookie record → `serve_cookie` →
///   `chunk_file` → type-0 records + type-1 marker.
/// - join's finalize: receives file, writes bob's tinc.conf +
///   hosts/alice, generates bob's identity key, sends it as type-1.
/// - daemon's finalize: writes hosts/bob, sends type-2.
/// - Single-use: second join with same cookie fails (the rename to
///   .used + unlink left no file behind).
#[test]
#[expect(clippy::similar_names)] // bob_* vs bob2_*: two distinct nodes, names track
fn tinc_join_against_real_daemon() {
    use tinc_crypto::invite::{build_slug, cookie_filename};
    use tinc_crypto::sign::SigningKey;

    let tmp = tmp!("join");
    let alice = Node::new(tmp.path(), "alice", 0xAA);

    // ─── alice's basic config (no peer; she just listens) ──────
    {
        std::fs::create_dir_all(alice.confbase.join("hosts")).unwrap();
        std::fs::write(
            alice.confbase.join("tinc.conf"),
            format!(
                "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\nPingTimeout = 1\n",
                alice.name
            ),
        )
        .unwrap();
        // hosts/alice: Port + Address (the invitation file copies
        // this section so bob knows where to connect).
        std::fs::write(
            alice.confbase.join("hosts").join("alice"),
            format!(
                "Port = {}\nAddress = 127.0.0.1 {}\n",
                alice.port, alice.port
            ),
        )
        .unwrap();
        // alice's identity key.
        write_ed25519_privkey(&alice.confbase, &alice.seed);
    }

    // ─── invitation key + invitation file ───────────────────────
    let inv_dir = alice.confbase.join("invitations");
    std::fs::create_dir_all(&inv_dir).unwrap();
    let inv_key = SigningKey::from_seed(&[0x11; 32]);
    write_ed25519_privkey(&inv_dir, &[0x11; 32]);

    // Cookie: deterministic for the test.
    let cookie: [u8; 18] = *b"test-cookie-18bxxx";
    let inv_filename = cookie_filename(&cookie, inv_key.public_key());

    // Invitation file body. Format:
    //   Name = <invited>\n
    //   <some-config>\n
    //   #---#\n
    //   <copy of inviter's hosts/NAME>\n
    // The joiner's `finalize_join` parses this; the `#---#` line
    // separates joiner-config from inviter-host-file.
    let alice_pub_b64 = tinc_crypto::b64::encode(&alice.pubkey());
    let inv_body = format!(
        "Name = bob\n\
         ConnectTo = alice\n\
         #---------------------------------------------------------------#\n\
         Name = alice\n\
         Ed25519PublicKey = {alice_pub_b64}\n\
         Address = 127.0.0.1 {}\n",
        alice.port
    );
    std::fs::write(inv_dir.join(&inv_filename), &inv_body).unwrap();

    // ─── spawn alice ────────────────────────────────────────────
    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed: {}",
        drain_stderr(alice_child)
    );

    // ─── build URL + run join ──────────────────────────────────
    // URL = `host:port/slug`. slug = b64(key_hash) || b64(cookie).
    let slug = build_slug(inv_key.public_key(), &cookie);
    let url = format!("127.0.0.1:{}/{slug}", alice.port);

    // bob's confbase (where join() writes). `for_cli` with explicit
    // confbase: confdir stays None (we passed --config explicitly).
    let bob_confbase = tmp.path().join("bob");
    let bob_paths = tinc_tools::names::Paths::for_cli(&tinc_tools::names::PathsInput {
        confbase: Some(bob_confbase.clone()),
        ..Default::default()
    });

    // The actual join. In-process — the test IS the joiner client.
    let result = tinc_tools::cmd::join::join(&url, &bob_paths, false);
    if let Err(e) = &result {
        let stderr = drain_stderr(alice_child);
        panic!("join failed: {e:?}\nalice stderr:\n{stderr}");
    }

    // ─── verify join() wrote bob's config ──────────────────────
    let bob_tinc_conf = std::fs::read_to_string(bob_confbase.join("tinc.conf"))
        .expect("join should write bob/tinc.conf");
    assert!(
        bob_tinc_conf.contains("Name = bob"),
        "bob/tinc.conf should have Name = bob: {bob_tinc_conf}"
    );
    assert!(
        bob_tinc_conf.contains("ConnectTo = alice"),
        "bob/tinc.conf should have ConnectTo = alice: {bob_tinc_conf}"
    );

    // bob/hosts/alice from the invitation file's second section.
    let bob_hosts_alice = std::fs::read_to_string(bob_confbase.join("hosts").join("alice"))
        .expect("join should write bob/hosts/alice");
    assert!(
        bob_hosts_alice.contains("Ed25519PublicKey"),
        "bob/hosts/alice should have alice's pubkey: {bob_hosts_alice}"
    );

    // bob's own identity key was generated.
    assert!(
        bob_confbase.join("ed25519_key.priv").exists(),
        "join should generate bob's identity key"
    );

    // ─── verify daemon wrote alice/hosts/bob ───────────────────
    // The type-1 record carried bob's pubkey; finalize() wrote it.
    // Poll: the daemon's epoll loop processes records on the next
    // turn; might lag by a few ms after join() returns.
    let alice_hosts_bob = alice.confbase.join("hosts").join("bob");
    poll_until(Duration::from_secs(5), || {
        if alice_hosts_bob.exists() {
            Some(())
        } else {
            None
        }
    });
    let hosts_bob_content = std::fs::read_to_string(&alice_hosts_bob).unwrap();
    assert!(
        hosts_bob_content.starts_with("Ed25519PublicKey = "),
        "alice/hosts/bob: {hosts_bob_content}"
    );

    // ─── verify .used file was unlinked ────────────────────────
    // The original invitation file was renamed to .used by
    // serve_cookie, then unlinked by dispatch_invitation_outputs
    // after the file chunks were sent. Neither should exist.
    assert!(
        !inv_dir.join(&inv_filename).exists(),
        "original invitation file should be gone (renamed)"
    );
    assert!(
        !inv_dir.join(format!("{inv_filename}.used")).exists(),
        ".used file should be unlinked after serving"
    );

    // ─── single-use: second join fails ─────────────────────────
    // Same cookie, fresh confbase. serve_cookie's rename hits
    // ENOENT → NonExisting → daemon terminates the conn → join
    // gets EOF mid-handshake.
    let bob2_confbase = tmp.path().join("bob2");
    let bob2_paths = tinc_tools::names::Paths::for_cli(&tinc_tools::names::PathsInput {
        confbase: Some(bob2_confbase),
        ..Default::default()
    });
    let result2 = tinc_tools::cmd::join::join(&url, &bob2_paths, false);
    assert!(
        result2.is_err(),
        "second join with same cookie should fail (single-use); got: {result2:?}"
    );

    // ─── cleanup ───────────────────────────────────────────────
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        alice_stderr.contains("Invitation") || alice_stderr.contains("invitation"),
        "alice should log invitation activity; stderr:\n{alice_stderr}"
    );
}

/// Security audit `2f72c2ba` regression: `on_del_subnet` must NOT
/// retaliate `ADD_SUBNET` for a subnet we never claimed.
///
/// alice connects to bob. alice owns `10.0.0.1/32`. bob (acting
/// malicious) hand-crafts a `DEL_SUBNET alice 99.99.99.99/32` over
/// the meta-conn. `lookup_subnet` fails, warn, return true. Before
/// fix: alice's `owner == myself`
/// fired BEFORE lookup, retaliated `ADD_SUBNET alice 99.99.99.99/32`
/// — lying about a subnet she never claimed.
///
/// We can't easily inject raw meta-conn lines into bob's daemon. So
/// instead: a stripped-down test where bob is replaced with a raw TCP
/// + SPTPS client driven by the test would be needed. That's heavy.
///
/// **Simpler proof**: assert via `dump subnets` that alice's subnet
/// table never contains `99.99.99.99/32` after a normal handshake.
/// The retaliate path doesn't ADD to the local table (it only sends
/// the wire message), so this is INSUFFICIENT as a direct regression.
///
/// **What we do**: assert the warning log line. Before fix, alice
/// logs "Got `DEL_SUBNET` from bob for ourself (99.99.99.99/32)" and
/// queues the retaliate. After fix, alice logs "...does not appear
/// in our subnet tree" and queues nothing. We trigger the DEL via
/// a SIGHUP-based config swap on bob's side that ADDs 99.99.99.99/32
/// to alice's hosts/ file (so bob gossips ADD), then DELs it — but
/// that doesn't trigger the `owner == myself` branch on alice (the
/// owner is bob, not alice).
///
/// **Actual approach**: this needs a raw-SPTPS injector. Deferred to
/// a future cross-impl test rig. For NOW: a unit-level test in
/// `gossip.rs` would be ideal, but `on_del_subnet` needs full daemon
/// state. Covered indirectly: `three_daemon_strictsubnets` exercises
/// `DEL_SUBNET` dispatch end-to-end (proves the handler still works);
/// the fix is a one-liner gate (`subnets.contains()` check). The
/// `udp_relay_gate` test above is the security-critical regression
/// of this batch.
///
/// Same applies to fix #5 (subnet-down for unknown subnets): the
/// del-first reorder is structurally identical; `scripts.rs::host_
/// down_then_subnet_down` exercises the legitimate path.
///
/// This stub asserts the legitimate DEL still works (mutation gate).
#[test]
fn del_subnet_legitimate_still_works() {
    // Reuse the SIGHUP-reload mechanism: alice adds, then removes
    // a subnet; bob sees both via gossip. Proves `on_del_subnet`'s
    // happy path survived the lookup-gate reorder.
    let tmp = tmp!("del-subnet-gate");
    let alice = Node::new(tmp.path(), "alice", 0xA6);
    let bob = Node::new(tmp.path(), "bob", 0xB6);

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // alice's hosts/alice with TWO subnets initially.
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!(
            "Port = {}\nSubnet = 10.0.0.1/32\nSubnet = 10.0.0.2/32\n",
            alice.port
        ),
    )
    .unwrap();

    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    let mut bob_ctl = bob.ctl();

    // Wait for bob to learn both subnets via ADD_SUBNET gossip.
    // Subnet Display omits `/32` (default v4 prefix).
    poll_until(Duration::from_secs(10), || {
        let s = bob_ctl.dump(5);
        (has_subnet(&s, "10.0.0.1", "alice") && has_subnet(&s, "10.0.0.2", "alice")).then_some(())
    });

    // Remove 10.0.0.2/32 from alice's hosts file, SIGHUP. Sleep
    // 1.1s first: `last_config_check` mtime gate is second-
    // granularity strict (`mtime > last`); a same-second write
    // wouldn't trigger reload.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!("Port = {}\nSubnet = 10.0.0.1/32\n", alice.port),
    )
    .unwrap();
    // SIGHUP alice. `reload_configuration` diffs and sends DEL_SUBNET.
    let alice_pid: i32 = std::fs::read_to_string(&alice.pidfile)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    kill(Pid::from_raw(alice_pid), Signal::SIGHUP).expect("kill SIGHUP");

    // bob should DEL it. Proves `on_del_subnet`'s `subnets.del()` runs
    // (lookup-gate didn't break the legitimate path).
    poll_until(Duration::from_secs(10), || {
        let s = bob_ctl.dump(5);
        (!has_subnet(&s, "10.0.0.2", "alice")).then_some(())
    });
    // 10.0.0.1/32 should still be there.
    let final_subnets = bob_ctl.dump(5);
    assert!(
        has_subnet(&final_subnets, "10.0.0.1", "alice"),
        "surviving subnet gone; subnets: {final_subnets:#?}"
    );

    drop(bob_ctl);
    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
}
