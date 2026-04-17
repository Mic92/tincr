//! UPnP-IGD / NAT-PMP port mapping against a real `miniupnpd`.
//!
//! Topology (all inside the bwrap re-exec; three child netns + the
//! outer bwrap netns acting as "internet"):
//!
//! ```text
//!   alice-ns 192.168.77.2/24 ─veth-lan─┐
//!                                      gw-ns: ip_forward=1, MASQUERADE -o veth-wan
//!                                             miniupnpd: ext_ifname=veth-wan
//!                                                        listening_ip=veth-lan
//!   outer-ns 10.77.0.1/24    ─veth-wan─┘     enable_upnp=yes enable_natpmp=yes
//! ```
//!
//! The daemon in alice-ns sets `UPnP=yes`. The portmapper thread
//! tries NAT-PMP first (one round-trip to the default-gw), falls
//! back to SSDP→IGD on failure. miniupnpd answers both. We assert:
//!
//!   (a) tincd logs `Portmapped TCP 655 → 10.77.0.2:NNNN`
//!   (b) `iptables -t nat -L` in gw-ns shows the DNAT rule miniupnpd
//!       installed (a real kernel rule, not just a SOAP 200)
//!   (c) outer-ns can `nc -zv 10.77.0.2 NNNN` and reach alice's :6550
//!       — the mapping actually delivers
//!
//! Runs unprivileged via the **nftables** backend: nfnetlink works in
//! a userns (the kernel namespaces nft tables per-netns), whereas the
//! legacy libiptc backend doesn't. The devshell ships the
//! `miniupnpd-nftables` build + `nft`; the test SKIPs cleanly if
//! either is missing or if `nft` can't open netlink in this kernel.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::common::linux::{ChildWithLog, run_ip};
use super::common::{TmpGuard, tincd_bin, wait_for_file_with, write_ed25519_privkey};
use super::rig::{enter_bwrap, make_child_netns, veth_pair};

/// Run a command inside `ip netns exec NS`. Panic on nonzero.
fn nsexec(ns: &str, argv: &[&str]) -> String {
    let out = Command::new("ip")
        .args(["netns", "exec", ns])
        .args(argv)
        .output()
        .expect("spawn ip netns exec");
    assert!(
        out.status.success(),
        "ip netns exec {ns} {argv:?}: {}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// miniupnpd (nftables backend) in gw-ns, foreground (`-d`), config
/// in a tmpfile. We pre-create the `inet filter` table with the
/// chains it expects and hook prerouting so the DNAT it installs is
/// actually consulted. The shipped `nft_init.sh` does the same but
/// also installs a `forward { policy drop }` chain — we want a
/// permissive forward, so do the minimum by hand.
struct Miniupnpd(ChildWithLog);

impl Miniupnpd {
    fn spawn(tmp: &std::path::Path, bin: &str) -> Option<Self> {
        let ruleset = tmp.join("nft.rules");
        std::fs::write(
            &ruleset,
            // MASQUERADE here too (replaces the iptables -A above);
            // miniupnpd default chain names: miniupnpd /
            // prerouting_miniupnpd / postrouting_miniupnpd, default
            // table name `filter` for both filter and nat.
            "table inet filter {\n\
               chain miniupnpd { }\n\
               chain prerouting_miniupnpd { }\n\
               chain postrouting_miniupnpd { }\n\
               chain prerouting {\n\
                 type nat hook prerouting priority -100; policy accept;\n\
                 jump prerouting_miniupnpd\n\
               }\n\
               chain postrouting {\n\
                 type nat hook postrouting priority 100; policy accept;\n\
                 oifname \"veth-wan\" masquerade\n\
               }\n\
             }\n",
        )
        .unwrap();
        // This is the userns capability probe: nft talking nfnetlink.
        // Any failure here ⇒ SKIP (kernel without USERNS nft, or
        // CONFIG_NF_TABLES off).
        let out = Command::new("ip")
            .args(["netns", "exec", "gw", "nft", "-f"])
            .arg(&ruleset)
            .output()
            .expect("spawn nft");
        if !out.status.success() {
            eprintln!(
                "SKIP upnp_miniupnpd_gateway: nft -f failed in userns: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }

        // `secure_mode=no`: alice asks to map to her own LAN IP
        // anyway, but igd-next/natpmp don't always pass the right
        // internal-client field on every router; secure_mode=no
        // sidesteps a class of test-only failures.
        // `ext_allow_private_ipv4=yes`: 10.77.0.2 IS rfc1918; by
        // default miniupnpd refuses port-forwarding when the WAN
        // address is private (it assumes double-NAT).
        let conf = tmp.join("miniupnpd.conf");
        std::fs::write(
            &conf,
            "ext_ifname=veth-wan\n\
             listening_ip=veth-lan\n\
             enable_upnp=yes\n\
             enable_natpmp=yes\n\
             secure_mode=no\n\
             ext_allow_private_ipv4=yes\n\
             uuid=00000000-0000-0000-0000-000000000000\n\
             allow 0-65535 192.168.77.0/24 0-65535\n\
             deny 0-65535 0.0.0.0/0 0-65535\n",
        )
        .unwrap();

        let pid = tmp.join("miniupnpd.pid");
        let child = Command::new("ip")
            .args(["netns", "exec", "gw"])
            .arg(bin)
            .arg("-d") // foreground + debug to stderr
            .arg("-f")
            .arg(&conf)
            .arg("-P")
            .arg(&pid)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn miniupnpd");
        // ChildWithLog drains stderr on a thread — `-d` is chatty
        // and the 64KiB pipe filling would wedge the daemon
        // mid-SOAP-response.
        Some(Self(ChildWithLog::spawn(child)))
    }
}

/// Write a minimal one-node config: `DeviceType=dummy`, fixed
/// `Port=655`, `UPnP=yes`. We don't need a peer — only the listener
/// + portmapper thread.
fn write_alice_config(confbase: &std::path::Path, refresh: u32) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alice\n\
             DeviceType = dummy\n\
             AddressFamily = ipv4\n\
             AutoConnect = no\n\
             UPnP = yes\n\
             UPnPRefreshPeriod = {refresh}\n"
        ),
    )
    .unwrap();
    // 6550, not 655: bwrap's userns doesn't grant
    // CAP_NET_BIND_SERVICE; the daemon's bind(655) gets EACCES.
    // The mapping logic doesn't care which port it forwards.
    std::fs::write(confbase.join("hosts").join("alice"), "Port = 6550\n").unwrap();
    write_ed25519_privkey(confbase, &[0xA1; 32]);
}

#[test]
fn upnp_miniupnpd_gateway() {
    // ─── feature-detect BEFORE bwrap ─────────────────────────────
    if std::env::var_os("BWRAP_INNER").is_none() {
        let Ok(bin) = which("miniupnpd") else {
            eprintln!("SKIP upnp_miniupnpd_gateway: miniupnpd not on PATH");
            return;
        };
        if which("nft").is_err() {
            eprintln!("SKIP upnp_miniupnpd_gateway: nft not on PATH");
            return;
        }
        // SAFETY: nextest = process-per-test.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("MINIUPNPD_BIN", bin);
        }
    }
    if !enter_bwrap("portmap::upnp_miniupnpd_gateway") {
        return;
    }
    let miniupnpd_bin =
        std::env::var("MINIUPNPD_BIN").expect("outer pass sets MINIUPNPD_BIN; bwrap inherits env");

    let tmp = TmpGuard::new("netns", "portmap");

    // ─── topology ────────────────────────────────────────────────
    let mut sleepers = [make_child_netns("alice"), make_child_netns("gw")];
    // ifnames must be unique in the outer ns at create time (both
    // ends exist there until the per-end `netns` move).
    veth_pair(
        ("alice", "veth-a", "192.168.77.2/24"),
        ("gw", "veth-lan", "192.168.77.1/24"),
    );
    // Outer bwrap netns is "internet". `ip link set ... netns 1`
    // won't work (PID 1 inside bwrap is bwrap itself, not us);
    // instead create the veth in the outer ns and only move ONE
    // end into gw.
    run_ip(&[
        "link", "add", "veth-out", "type", "veth", "peer", "name", "veth-wan",
    ]);
    run_ip(&["link", "set", "veth-wan", "netns", "gw"]);
    run_ip(&["addr", "add", "10.77.0.1/24", "dev", "veth-out"]);
    run_ip(&["link", "set", "veth-out", "up"]);
    nsexec(
        "gw",
        &["ip", "addr", "add", "10.77.0.2/24", "dev", "veth-wan"],
    );
    nsexec("gw", &["ip", "link", "set", "veth-wan", "up"]);

    // alice's default route → gw (so NAT-PMP's get_default_gateway()
    // and the SSDP multicast both go out veth-lan).
    nsexec(
        "alice",
        &["ip", "route", "add", "default", "via", "192.168.77.1"],
    );

    // gw: forward on. MASQUERADE installed by the nft ruleset below.
    nsexec("gw", &["sysctl", "-w", "net.ipv4.ip_forward=1"]);

    // ─── miniupnpd (nft chains + spawn) ──────────────────────────
    let Some(mut upnpd) = Miniupnpd::spawn(tmp.path(), &miniupnpd_bin) else {
        for s in &mut sleepers {
            let _ = s.kill();
        }
        return;
    };
    // Wait for it to bind 5351 (NAT-PMP) — proves init succeeded.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let ss = nsexec("gw", &["ss", "-uln"]);
        if ss.contains(":5351") {
            break;
        }
        if let Ok(Some(st)) = upnpd.0.child.try_wait() {
            panic!(
                "miniupnpd exited early ({st:?}):\n{}",
                upnpd.0.kill_and_log()
            );
        }
        assert!(Instant::now() < deadline, "miniupnpd didn't bind 5351");
        std::thread::sleep(Duration::from_millis(100));
    }

    // ─── alice tincd ─────────────────────────────────────────────
    let confbase = tmp.path().join("alice");
    let pidfile = tmp.path().join("alice.pid");
    let socket = tmp.path().join("alice.socket");
    write_alice_config(&confbase, 5);
    let alice = ChildWithLog::spawn(
        Command::new("ip")
            .args(["netns", "exec", "alice"])
            .arg(tincd_bin())
            .arg("-D")
            .arg("-c")
            .arg(&confbase)
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--socket")
            .arg(&socket)
            .env("RUST_LOG", "tincd=debug,tincd::portmap=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd in netns"),
    );
    assert!(
        wait_for_file_with(&socket, Duration::from_secs(5)),
        "alice setup failed:\n{}",
        alice.kill_and_log()
    );

    // ─── (a) journal: Portmapped TCP 655 → 10.77.0.2:NNNN ────────
    // 20 s budget: NAT-PMP is sub-second; if that path fails for
    // any reason the IGD fallback's SSDP discover wait is ~5 s.
    let deadline = Instant::now() + Duration::from_secs(20);
    let ext_port: u16 = loop {
        let log = alice.log_snapshot();
        if let Some(port) = log
            .lines()
            .find(|l| l.contains("Portmapped Tcp 6550"))
            .and_then(|l| l.rsplit_once("10.77.0.2:"))
            .and_then(|(_, rest)| {
                rest.split(|c: char| !c.is_ascii_digit())
                    .next()?
                    .parse()
                    .ok()
            })
        {
            break port;
        }
        assert!(
            Instant::now() < deadline,
            "no `Portmapped TCP` line within 20s; alice stderr:\n{}",
            alice.kill_and_log()
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    eprintln!("portmapped: 10.77.0.2:{ext_port} → 192.168.77.2:6550");

    // ─── (b) gw-ns nft shows the dnat rule ───────────────────────
    let nat = nsexec(
        "gw",
        &[
            "nft",
            "list",
            "chain",
            "inet",
            "filter",
            "prerouting_miniupnpd",
        ],
    );
    assert!(
        nat.contains("dnat") && nat.contains("192.168.77.2") && nat.contains("6550"),
        "dnat rule for alice:6550 not found in prerouting_miniupnpd:\n{nat}"
    );

    // ─── (c) outer-ns can reach the mapped port ──────────────────
    // Don't depend on `nc`: a bare `TcpStream::connect` from the
    // outer bwrap netns is the same probe and saves a devshell dep.
    let probe = std::net::TcpStream::connect_timeout(
        &format!("10.77.0.2:{ext_port}").parse().unwrap(),
        Duration::from_secs(3),
    );
    assert!(
        probe.is_ok(),
        "connect 10.77.0.2:{ext_port} from outer-ns failed: {probe:?}\n\
         nat table:\n{nat}\nalice stderr:\n{}",
        alice.kill_and_log()
    );
    // The 3-way handshake completing is proof: gw-ns has nothing
    // listening on 6550, so the SYN-ACK can only have come from
    // alice's listener via the DNAT rule. (tincd accept-side waits
    // for the initiator's ID line; nothing to read.)
    drop(probe);

    eprint!("{}", alice.kill_and_log());
    let _ = upnpd.0.kill_and_log();
    for s in &mut sleepers {
        let _ = s.kill();
    }
}

/// Roaming: after the first mapping succeeds, swap alice's LAN IP
/// (`.2` → `.3`) underneath the running daemon. The portmap worker
/// re-derives the LAN IP each refresh round (see `portmap.rs`
/// worker loop), so the next round must (a) log the route-change
/// notice, (b) re-emit `Portmapped Tcp` (even though the external
/// addr is unchanged — `last[]` is force-cleared on LAN-IP change),
/// and (c) install a fresh DNAT rule pointing at `.3`.
#[test]
fn upnp_gateway_ip_change() {
    if std::env::var_os("BWRAP_INNER").is_none() {
        let Ok(bin) = which("miniupnpd") else {
            eprintln!("SKIP upnp_gateway_ip_change: miniupnpd not on PATH");
            return;
        };
        if which("nft").is_err() {
            eprintln!("SKIP upnp_gateway_ip_change: nft not on PATH");
            return;
        }
        // SAFETY: nextest = process-per-test.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("MINIUPNPD_BIN", bin);
        }
    }
    if !enter_bwrap("portmap::upnp_gateway_ip_change") {
        return;
    }
    let miniupnpd_bin =
        std::env::var("MINIUPNPD_BIN").expect("outer pass sets MINIUPNPD_BIN; bwrap inherits env");

    let tmp = TmpGuard::new("netns", "portmap-roam");

    let mut sleepers = [make_child_netns("alice"), make_child_netns("gw")];
    veth_pair(
        ("alice", "veth-a", "192.168.77.2/24"),
        ("gw", "veth-lan", "192.168.77.1/24"),
    );
    run_ip(&[
        "link", "add", "veth-out", "type", "veth", "peer", "name", "veth-wan",
    ]);
    run_ip(&["link", "set", "veth-wan", "netns", "gw"]);
    run_ip(&["addr", "add", "10.77.0.1/24", "dev", "veth-out"]);
    run_ip(&["link", "set", "veth-out", "up"]);
    nsexec(
        "gw",
        &["ip", "addr", "add", "10.77.0.2/24", "dev", "veth-wan"],
    );
    nsexec("gw", &["ip", "link", "set", "veth-wan", "up"]);
    nsexec(
        "alice",
        &["ip", "route", "add", "default", "via", "192.168.77.1"],
    );
    nsexec("gw", &["sysctl", "-w", "net.ipv4.ip_forward=1"]);

    let Some(mut upnpd) = Miniupnpd::spawn(tmp.path(), &miniupnpd_bin) else {
        for s in &mut sleepers {
            let _ = s.kill();
        }
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if nsexec("gw", &["ss", "-uln"]).contains(":5351") {
            break;
        }
        if let Ok(Some(st)) = upnpd.0.child.try_wait() {
            panic!(
                "miniupnpd exited early ({st:?}):\n{}",
                upnpd.0.kill_and_log()
            );
        }
        assert!(Instant::now() < deadline, "miniupnpd didn't bind 5351");
        std::thread::sleep(Duration::from_millis(100));
    }

    let confbase = tmp.path().join("alice");
    let pidfile = tmp.path().join("alice.pid");
    let socket = tmp.path().join("alice.socket");
    // Refresh every 2 s so the post-swap round lands well inside the
    // test budget.
    write_alice_config(&confbase, 2);
    let alice = ChildWithLog::spawn(
        Command::new("ip")
            .args(["netns", "exec", "alice"])
            .arg(tincd_bin())
            .arg("-D")
            .arg("-c")
            .arg(&confbase)
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--socket")
            .arg(&socket)
            .env("RUST_LOG", "tincd=debug,tincd::portmap=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd in netns"),
    );
    assert!(
        wait_for_file_with(&socket, Duration::from_secs(5)),
        "alice setup failed:\n{}",
        alice.kill_and_log()
    );

    // ─── first Portmapped (LAN .2) ────────────────────────────────
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if alice.log_snapshot().contains("Portmapped Tcp 6550") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no first `Portmapped Tcp` within 20s:\n{}",
            alice.kill_and_log()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // ─── swap alice's LAN IP .2 → .3 ─────────────────────────────
    // Deleting the only on-link addr also drops the default route
    // (no more nexthop source); re-add both. The daemon's listener
    // is bound to 0.0.0.0 so it survives the renumber.
    nsexec(
        "alice",
        &["ip", "addr", "del", "192.168.77.2/24", "dev", "veth-a"],
    );
    nsexec(
        "alice",
        &["ip", "addr", "add", "192.168.77.3/24", "dev", "veth-a"],
    );
    nsexec(
        "alice",
        &["ip", "route", "add", "default", "via", "192.168.77.1"],
    );

    // ─── (a) route-change INFO + (b) second Portmapped ──────────
    // periodic tick is 5 s and the worker refresh is 2 s, so the
    // re-emitted event surfaces within one tick after the next
    // refresh round — budget 20 s for slop.
    let deadline = Instant::now() + Duration::from_secs(20);
    let log = loop {
        let log = alice.log_snapshot();
        let mapped = log.matches("Portmapped Tcp 6550").count();
        if log.contains("default route changed") && mapped >= 2 {
            break log;
        }
        assert!(
            Instant::now() < deadline,
            "no route-change notice / re-map within 20s:\n{}",
            alice.kill_and_log()
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        log.contains("192.168.77.2 \u{2192} 192.168.77.3"),
        "route-change line missing old→new IPs:\n{log}"
    );

    // ─── (c) miniupnpd's DNAT now targets .3 ─────────────────────
    let nat = nsexec(
        "gw",
        &[
            "nft",
            "list",
            "chain",
            "inet",
            "filter",
            "prerouting_miniupnpd",
        ],
    );
    assert!(
        nat.contains("192.168.77.3"),
        "dnat rule for .3 not found in prerouting_miniupnpd:\n{nat}\n\
         alice stderr:\n{}",
        alice.kill_and_log()
    );

    eprint!("{}", alice.kill_and_log());
    let _ = upnpd.0.kill_and_log();
    for s in &mut sleepers {
        let _ = s.kill();
    }
}

fn which(bin: &str) -> Result<String, ()> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or(())
}
