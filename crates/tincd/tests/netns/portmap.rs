//! `UPnP = yes` against a real `miniupnpd` (nftables backend, which
//! works unprivileged in a userns) and against a hostile hand-rolled
//! gateway.
//!
//! ```text
//!   alice-ns 192.168.77.2/24 ─veth-lan─┐
//!                                      gw-ns: forwarding, masquerade, miniupnpd
//!   outer-ns 10.77.0.1/24    ─veth-wan─┘      ("internet" = the bwrap netns)
//! ```

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::common::ChildWithLog;
use super::common::linux::run_ip;
use super::common::{tincd_bin, wait_for_file_with, write_ed25519_privkey};
use super::rig::{ChildNetNs, enter_bwrap, veth_pair};
use std::env;
use std::fs;
use std::net::Shutdown;
use std::path::Path;
use std::thread;
use std::thread::JoinHandle;

/// The daemon's own port. Not 655: no `CAP_NET_BIND_SERVICE` in the
/// userns.
const ALICE_PORT: u16 = 6550;

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

/// `nft -f` in `ns`; `false` (logged as SKIP) when nfnetlink is not
/// usable from this userns.
fn load_nft(ns: &str, test_name: &str, path: &Path, rules: &str) -> bool {
    fs::write(path, rules).unwrap();
    let out = Command::new("ip")
        .args(["netns", "exec", ns, "nft", "-f"])
        .arg(path)
        .output()
        .expect("spawn nft");
    if !out.status.success() {
        eprintln!(
            "SKIP {test_name}: nft -f in {ns}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    out.status.success()
}

fn which(bin: &str) -> Option<String> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(bin))
        .find(|path| path.is_file())
        .map(|path| path.to_string_lossy().into_owned())
}

/// Feature-detect before the bwrap re-exec (PATH lookups are cheaper
/// to report out here), then enter it. Returns the miniupnpd path.
fn enter_bwrap_with_miniupnpd(test_name: &str) -> Option<String> {
    if env::var_os("BWRAP_INNER").is_none() {
        let Some(bin) = which("miniupnpd") else {
            eprintln!("SKIP {test_name}: miniupnpd not on PATH");
            return None;
        };
        if which("nft").is_none() {
            eprintln!("SKIP {test_name}: nft not on PATH");
            return None;
        }
        // SAFETY: nextest runs one test per process.
        #[expect(unsafe_code)]
        unsafe {
            env::set_var("MINIUPNPD_BIN", bin);
        }
    }
    enter_bwrap(test_name).then(|| env::var("MINIUPNPD_BIN").unwrap())
}

/// alice-ns and gw-ns wired as in the module doc, alice with a
/// stateful drop-by-default input firewall, and miniupnpd running in
/// gw-ns.
struct Gateway {
    upnpd: ChildWithLog,
    _netns: [ChildNetNs; 2],
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.upnpd.child.kill();
    }
}

impl Gateway {
    fn start(test_name: &str, tmp: &Path, miniupnpd_bin: &str, natpmp: bool) -> Option<Self> {
        let netns = [ChildNetNs::new("alice"), ChildNetNs::new("gw")];
        veth_pair(
            ("alice", "veth-a", "192.168.77.2/24"),
            ("gw", "veth-lan", "192.168.77.1/24"),
        );
        // PID 1 in here is bwrap, so `netns 1` can't name the outer
        // ns: create the pair out here and move one end.
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
        // The chains miniupnpd expects (its nft_init.sh would also add
        // a drop-policy forward chain), plus masquerade. Doubles as the
        // probe for nft working in this userns at all.
        let gw_rules = "table inet filter {\n\
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
             }\n";
        // NixOS-firewall shape on alice. Regression: the multicast
        // SSDP query and the gateway's unicast reply are different
        // conntrack tuples, so the reply is only let in because the
        // IGD client first sends a unicast M-SEARCH from the same
        // socket.
        let alice_rules = format!(
            "table inet fw {{\n\
               chain input {{\n\
                 type filter hook input priority 0; policy drop;\n\
                 ct state established,related accept\n\
                 iif lo accept\n\
                 tcp dport {ALICE_PORT} accept\n\
               }}\n\
             }}\n"
        );
        if !load_nft("gw", test_name, &tmp.join("gw.nft"), gw_rules)
            || !load_nft("alice", test_name, &tmp.join("alice.nft"), &alice_rules)
        {
            return None;
        }

        // 10.77.0.2 is RFC 1918, which miniupnpd treats as double NAT:
        // refuses mappings unless allowed, and reports an empty
        // external address unless `ext_ip` pins it.
        let conf = tmp.join("miniupnpd.conf");
        fs::write(
            &conf,
            format!(
                "ext_ifname=veth-wan\n\
                 listening_ip=veth-lan\n\
                 enable_upnp=yes\n\
                 enable_natpmp={}\n\
                 secure_mode=no\n\
                 ext_allow_private_ipv4=yes\n\
                 ext_ip=10.77.0.2\n\
                 uuid=00000000-0000-0000-0000-000000000000\n\
                 allow 0-65535 192.168.77.0/24 0-65535\n\
                 deny 0-65535 0.0.0.0/0 0-65535\n",
                if natpmp { "yes" } else { "no" }
            ),
        )
        .unwrap();
        // `-d` is foreground and chatty; ChildWithLog keeps the pipe
        // drained so it doesn't block mid-response.
        let mut upnpd = ChildWithLog::spawn(
            Command::new("ip")
                .args(["netns", "exec", "gw", miniupnpd_bin, "-d", "-f"])
                .arg(&conf)
                .arg("-P")
                .arg(tmp.join("miniupnpd.pid"))
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn miniupnpd"),
        );
        let ready_port = if natpmp { ":5351" } else { ":1900" };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !nsexec("gw", &["ss", "-uln"]).contains(ready_port) {
            if let Ok(Some(status)) = upnpd.child.try_wait() {
                panic!(
                    "miniupnpd exited early ({status:?}):\n{}",
                    upnpd.kill_and_log()
                );
            }
            assert!(
                Instant::now() < deadline,
                "miniupnpd didn't bind {ready_port}"
            );
            thread::sleep(Duration::from_millis(100));
        }
        Some(Self {
            upnpd,
            _netns: netns,
        })
    }

    fn dnat_rules() -> String {
        nsexec(
            "gw",
            &[
                "nft",
                "list",
                "chain",
                "inet",
                "filter",
                "prerouting_miniupnpd",
            ],
        )
    }
}

/// Peerless dummy-device daemon in alice-ns with `UPnP = yes`.
fn start_alice(tmp: &Path, refresh_period: u32) -> ChildWithLog {
    let confbase = tmp.join("alice");
    fs::create_dir_all(confbase.join("hosts")).unwrap();
    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alice\nDeviceType = dummy\nAddressFamily = ipv4\n\
             AutoConnect = no\nUPnP = yes\nUPnPRefreshPeriod = {refresh_period}\n"
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alice"),
        format!("Port = {ALICE_PORT}\n"),
    )
    .unwrap();
    write_ed25519_privkey(&confbase, &[0xA1; 32]);
    let socket = tmp.join("alice.socket");
    let alice = ChildWithLog::spawn(
        Command::new("ip")
            .args(["netns", "exec", "alice"])
            .arg(tincd_bin())
            .arg("-D")
            .arg("-c")
            .arg(&confbase)
            .arg("--pidfile")
            .arg(tmp.join("alice.pid"))
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
    alice
}

/// Poll alice's log until `done(log)`; panics with the log after
/// `timeout` or as soon as `must_not` appears.
fn wait_log(
    alice: &ChildWithLog,
    timeout: Duration,
    must_not: Option<&str>,
    done: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let log = alice.log_snapshot();
        if done(&log) {
            return log;
        }
        if let Some(needle) = must_not {
            assert!(!log.contains(needle), "`{needle}` in:\n{log}");
        }
        assert!(Instant::now() < deadline, "timed out; alice:\n{log}");
        thread::sleep(Duration::from_millis(200));
    }
}

const MAPPED: &str = "Portmapped Tcp 6550";

/// A mapping is logged via `expect_via`, miniupnpd installed a real
/// DNAT rule for it, and a connect from the "internet" side reaches
/// alice's listener through it.
fn mapping_works(test_name: &str, natpmp: bool, expect_via: &str) {
    let Some(miniupnpd_bin) = enter_bwrap_with_miniupnpd(test_name) else {
        return;
    };
    let tmp = tmp!("portmap");
    let Some(_gateway) = Gateway::start(test_name, tmp.path(), &miniupnpd_bin, natpmp) else {
        return;
    };
    let alice = start_alice(tmp.path(), 5);

    // NAT-PMP is sub-second; the IGD fallback waits ~5s on SSDP.
    let log = wait_log(&alice, Duration::from_secs(20), None, |log| {
        log.contains(MAPPED)
    });
    let line = log.lines().find(|line| line.contains(MAPPED)).unwrap();
    assert!(line.contains(expect_via), "{line}");
    let ext_port: u16 = line
        .rsplit_once("10.77.0.2:")
        .and_then(|(_, rest)| {
            rest.split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no ext port in: {line}"));

    let dnat = Gateway::dnat_rules();
    assert!(
        dnat.contains("dnat") && dnat.contains("192.168.77.2") && dnat.contains("6550"),
        "{dnat}"
    );
    // Nothing listens on gw itself, so a completed handshake can only
    // be alice via the DNAT rule.
    let probe = TcpStream::connect_timeout(
        &SocketAddr::from(([10, 77, 0, 2], ext_port)),
        Duration::from_secs(3),
    );
    let alice_log = alice.kill_and_log();
    assert!(probe.is_ok(), "{probe:?}\n{dnat}\n{alice_log}");
}

#[test]
fn upnp_miniupnpd_gateway() {
    mapping_works("portmap::upnp_miniupnpd_gateway", true, "PCP");
}

/// NAT-PMP off on the gateway forces the hand-rolled SSDP→SOAP client.
#[test]
fn upnp_miniupnpd_gateway_igd_only() {
    mapping_works(
        "portmap::upnp_miniupnpd_gateway_igd_only",
        false,
        "UPnP-IGD",
    );
}

/// Renumbering alice's LAN address under the running daemon: the next
/// refresh round must notice, log a new mapping (forced even though
/// the external side is unchanged) and have miniupnpd DNAT to the new
/// address.
#[test]
fn upnp_gateway_ip_change() {
    let test_name = "portmap::upnp_gateway_ip_change";
    let Some(miniupnpd_bin) = enter_bwrap_with_miniupnpd(test_name) else {
        return;
    };
    let tmp = tmp!("portmap-roam");
    let Some(_gateway) = Gateway::start(test_name, tmp.path(), &miniupnpd_bin, true) else {
        return;
    };
    let alice = start_alice(tmp.path(), 2);
    wait_log(&alice, Duration::from_secs(20), None, |log| {
        log.contains(MAPPED)
    });

    // Removing the only address drops the default route with it.
    for args in [
        ["ip", "addr", "del", "192.168.77.2/24", "dev", "veth-a"],
        ["ip", "addr", "add", "192.168.77.3/24", "dev", "veth-a"],
        ["ip", "route", "add", "default", "via", "192.168.77.1"],
    ] {
        nsexec("alice", &args);
    }
    let log = wait_log(&alice, Duration::from_secs(20), None, |log| {
        log.contains("default route changed") && log.matches(MAPPED).count() >= 2
    });
    assert!(
        log.contains("192.168.77.2") && log.contains("192.168.77.3"),
        "{log}"
    );
    let dnat = Gateway::dnat_rules();
    let alice_log = alice.kill_and_log();
    assert!(dnat.contains("192.168.77.3"), "{dnat}\n{alice_log}");
}

/// A UDP responder on the gateway address until the returned sender
/// is dropped.
fn serve_udp(
    port: u16,
    reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> (mpsc::Sender<()>, JoinHandle<()>) {
    let socket = UdpSocket::bind(("192.168.77.1", port)).expect("bind udp");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let thread = thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while stop_rx.try_recv() != Err(mpsc::TryRecvError::Disconnected) {
            if let Ok((len, src)) = socket.recv_from(&mut buf) {
                for packet in reply(&buf[..len]) {
                    let _ = socket.send_to(&packet, src);
                }
            }
        }
    });
    (stop_tx, thread)
}

/// This process plays gateway: PCP answers with external address
/// `::ffff:127.0.0.1`, SSDP first points LOCATION off-gateway
/// (127.0.0.1, an SSRF attempt) then at our HTTP server, whose SOAP
/// reports external address 127.0.0.1. None of that may be dialled
/// or published.
#[test]
fn upnp_rogue_gateway_ext_addr_rejected() {
    if !enter_bwrap("portmap::upnp_rogue_gateway_ext_addr_rejected") {
        return;
    }
    let tmp = tmp!("portmap-rogue");
    let _alice_netns = ChildNetNs::new("alice");
    run_ip(&[
        "link", "add", "veth-gw", "type", "veth", "peer", "name", "veth-a",
    ]);
    run_ip(&["link", "set", "veth-a", "netns", "alice"]);
    run_ip(&["addr", "add", "192.168.77.1/24", "dev", "veth-gw"]);
    run_ip(&["link", "set", "veth-gw", "up"]);
    for args in [
        ["ip", "addr", "add", "192.168.77.2/24", "dev", "veth-a"].as_slice(),
        &["ip", "link", "set", "veth-a", "up"],
        &["ip", "route", "add", "default", "via", "192.168.77.1"],
    ] {
        nsexec("alice", args);
    }

    let http = TcpListener::bind(("192.168.77.1", 0)).unwrap();
    let http_port = http.local_addr().unwrap().port();

    let (pcp_stop, pcp_thread) = serve_udp(5351, |request| {
        if request.len() < 60 {
            return vec![];
        }
        let mut response = vec![0u8; 60];
        response[0] = 2; // version
        response[1] = 0x81; // response | MAP
        response[24..36].copy_from_slice(&request[24..36]); // nonce
        response[36] = request[36]; // protocol
        response[40..42].copy_from_slice(&request[40..42]); // internal port
        // external port 0, external address ::ffff:127.0.0.1
        response[44..60].copy_from_slice(&Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
        vec![response]
    });
    let ssdp_reply = |location: String| {
        format!(
            "HTTP/1.1 200 OK\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
             LOCATION: {location}\r\n\r\n"
        )
        .into_bytes()
    };
    let ssrf = ssdp_reply("http://127.0.0.1:9/pwn".into());
    let real = ssdp_reply(format!("http://192.168.77.1:{http_port}/rootDesc.xml"));
    let (ssdp_stop, ssdp_thread) = serve_udp(1900, move |_| vec![ssrf.clone(), real.clone()]);

    let http_thread = thread::spawn(move || {
        let soap = |body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/xml\r\n\r\n\
                 <s:Envelope><s:Body>{body}</s:Body></s:Envelope>"
            )
        };
        for stream in http.incoming() {
            let Ok(mut stream) = stream else { return };
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(len @ 1..) = stream.read(&mut chunk) {
                raw.extend_from_slice(&chunk[..len]);
            }
            let request = String::from_utf8_lossy(&raw);
            let response = if request.starts_with("GET /rootDesc.xml") {
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n\
                 <?xml version=\"1.0\"?><root><device><serviceList><service>\
                 <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                 <controlURL>/ctl</controlURL></service></serviceList></device></root>"
                    .to_owned()
            } else if request.contains("GetExternalIPAddress") {
                soap(
                    "<u:GetExternalIPAddressResponse>\
                     <NewExternalIPAddress>127.0.0.1</NewExternalIPAddress>\
                     </u:GetExternalIPAddressResponse>",
                )
            } else if request.contains("AddPortMapping") {
                soap("<u:AddPortMappingResponse/>")
            } else {
                "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_owned()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    let alice = start_alice(tmp.path(), 5);
    let log = wait_log(&alice, Duration::from_secs(25), Some(MAPPED), |log| {
        log.contains("rejected ext addr 127.0.0.1:0 from PCP")
            && log.contains("rejected ext addr 127.0.0.1:6550 from UPnP-IGD (loopback)")
    });
    assert!(
        log.contains("ignored SSDP LOCATION host 127.0.0.1"),
        "off-gateway LOCATION not dropped:\n{log}"
    );
    drop(alice);

    drop(pcp_stop);
    drop(ssdp_stop);
    pcp_thread.join().unwrap();
    ssdp_thread.join().unwrap();
    // Unblock `incoming()`; the thread then exits on its own.
    let _ = TcpStream::connect(SocketAddr::from(([192, 168, 77, 1], http_port)));
    drop(http_thread);
}
