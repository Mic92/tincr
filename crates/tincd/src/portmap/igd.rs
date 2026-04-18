//! Minimal UPnP-IGD client: SSDP M-SEARCH + two SOAP POSTs.
//!
//! This replaces `igd-next` (53 transitive deps via attohttpc →
//! url → idna → ICU) with ~200 lines of `std::net` + string
//! formatting. The protocol is trivial: one UDP multicast to find
//! the gateway, one HTTP GET for the device-desc XML, then a SOAP
//! POST per action. miniupnpc — what C tinc links — does the same
//! substring-scan parsing (`minixml.c`); a real XML parser is
//! overkill for three fixed-shape responses from a LAN gateway.
//!
//! Surface matches the three calls `try_igd` made on `igd-next`:
//! `discover` (was `search_gateway`), `Gateway::add_port`,
//! `Gateway::external_ip`.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::Proto;

/// SSDP search request. `MX:2` = routers may delay reply ≤2s.
const M_SEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
    HOST: 239.255.255.250:1900\r\n\
    ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
    MAN: \"ssdp:discover\"\r\n\
    MX: 2\r\n\r\n";

/// Service types whose `controlURL` accepts `AddPortMapping` /
/// `GetExternalIPAddress`. Tried in order; first one present in the
/// device-desc XML wins. Fritzbox is `WANIPConnection:1`.
const WAN_SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
/// Hard wall-clock cap for one `http_roundtrip` (connect + write +
/// read). `HTTP_TIMEOUT` above is a per-`read(2)` `SO_RCVTIMEO`; a
/// rogue responder that trickles 1 B/s keeps every individual read
/// under that and would otherwise wedge the worker (and
/// `Portmapper::Drop`'s blocking `join()`) indefinitely.
const HTTP_DEADLINE: Duration = Duration::from_secs(5);
/// Cap on the response body. Real IGD `rootDesc.xml` / SOAP
/// envelopes are <8 KiB; 64 KiB is generous and stops a hostile
/// gateway from driving an unbounded `Vec` allocation.
const HTTP_MAX_RESPONSE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Gateway {
    addr: SocketAddrV4,
    control_url: String,
    /// The matched WAN service URN — echoed in `SOAPACTION` and the
    /// envelope's `xmlns:u`. Some routers 500 on a mismatch.
    service_type: String,
}

/// SSDP multicast → parse first IGD reply → fetch root desc →
/// substring-scan for a WAN service's `controlURL`.
///
/// `gw_v4`: the v4 default gateway, if known. When set, the same
/// M-SEARCH bytes are sent *unicast* to `gw_v4:1900` first, on the
/// same socket, before the standard multicast. Rationale (Tailscale
/// `net/portmapper`, tailscale#3197): the SSDP multicast goes to
/// `239.255.255.250:1900` but the IGD answers *unicast* from
/// `gw:1900` — a stateful host firewall (nixos-fw, ufw) sees the
/// reply 5-tuple as NEW (request dst was the multicast group, not
/// `gw`) and drops it. The unicast send creates the conntrack entry
/// `{us:eph ↔ gw:1900}` so the reply matches ESTABLISHED. Most
/// routers also *answer* the unicast M-SEARCH directly (miniupnpd
/// binds `INADDR_ANY:1900`, `minissdp.c:205`); for the few that
/// only reply to multicast, the unicast send still serves as the
/// firewall punch.
pub fn discover(timeout: Duration, gw_v4: Option<Ipv4Addr>) -> Result<Gateway, String> {
    let sock =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| format!("bind 0.0.0.0:0: {e}"))?;
    // TTL 2: cross one router hop (the gateway), no further.
    let _ = sock.set_multicast_ttl_v4(2);
    // Unicast pre-punch (see doc comment). Best-effort: gateway may
    // be unreachable / ICMP-reject; multicast below is the real
    // query.
    if let Some(gw) = gw_v4 {
        let _ = sock.send_to(M_SEARCH, (gw, 1900));
    }
    sock.send_to(M_SEARCH, (Ipv4Addr::new(239, 255, 255, 250), 1900))
        .map_err(|e| format!("send M-SEARCH: {e}"))?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let remain = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "SSDP discover: no IGD reply within timeout".to_string())?;
        sock.set_read_timeout(Some(remain.max(Duration::from_millis(1))))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                use std::io::ErrorKind::{TimedOut, WouldBlock};
                if matches!(e.kind(), WouldBlock | TimedOut) {
                    return Err("SSDP discover: no IGD reply within timeout".into());
                }
                return Err(format!("recv: {e}"));
            }
        };
        // SSDP is link-local multicast — *any* host on the
        // broadcast domain can answer and point `LOCATION` at an
        // arbitrary address (loopback, cloud metadata, …). Only the
        // route-table default gateway is a legitimate IGD; ignore
        // everyone else. This also closes the SSRF: the only host
        // we ever HTTP to is `gw_v4`.
        if let Some(gw) = gw_v4
            && src.ip() != IpAddr::V4(gw)
        {
            log::debug!(target: "tincd::portmap",
                        "ignored SSDP reply from {src} (not gateway {gw})");
            continue;
        }
        let reply = String::from_utf8_lossy(&buf[..n]);
        let Some((addr, root_path)) = parse_ssdp_location(&reply).and_then(split_http_url) else {
            continue;
        };
        if let Some(gw) = gw_v4
            && *addr.ip() != gw
        {
            log::debug!(target: "tincd::portmap",
                        "ignored SSDP LOCATION host {addr} (not gateway {gw})");
            continue;
        }
        // If this responder's desc has no WAN service (or the GET
        // fails), keep listening — another may follow.
        match fetch_control_url(addr, &root_path) {
            Ok((control_url, service_type)) => {
                return Ok(Gateway {
                    addr,
                    control_url,
                    service_type,
                });
            }
            Err(e) => log::debug!(target: "tincd::portmap",
                                  "IGD desc {addr}{root_path}: {e}"),
        }
    }
}

impl Gateway {
    pub fn addr(&self) -> IpAddr {
        IpAddr::V4(*self.addr.ip())
    }

    /// SOAP `GetExternalIPAddress`.
    pub fn external_ip(&self) -> Result<IpAddr, String> {
        let body = format!(
            "<u:GetExternalIPAddress xmlns:u=\"{}\"></u:GetExternalIPAddress>",
            self.service_type
        );
        let resp = self.soap("GetExternalIPAddress", &body)?;
        let ip = extract_tag(&resp, "NewExternalIPAddress")
            .ok_or("no <NewExternalIPAddress> in response")?;
        ip.parse()
            .map_err(|e| format!("bad external IP {ip:?}: {e}"))
    }

    /// SOAP `AddPortMapping`.
    pub fn add_port(
        &self,
        proto: Proto,
        ext_port: u16,
        internal: SocketAddrV4,
        lease: u32,
        desc: &str,
    ) -> Result<(), String> {
        let proto = match proto {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        };
        // Argument order matters for some IGDs (miniupnpd is lax,
        // but Broadcom/Realtek stacks index positionally). This is
        // the spec order, same as miniupnpc's `upnpcommands.c`.
        let body = format!(
            "<u:AddPortMapping xmlns:u=\"{st}\">\
               <NewRemoteHost></NewRemoteHost>\
               <NewExternalPort>{ext_port}</NewExternalPort>\
               <NewProtocol>{proto}</NewProtocol>\
               <NewInternalPort>{iport}</NewInternalPort>\
               <NewInternalClient>{iaddr}</NewInternalClient>\
               <NewEnabled>1</NewEnabled>\
               <NewPortMappingDescription>{desc}</NewPortMappingDescription>\
               <NewLeaseDuration>{lease}</NewLeaseDuration>\
             </u:AddPortMapping>",
            st = self.service_type,
            iport = internal.port(),
            iaddr = internal.ip(),
        );
        self.soap("AddPortMapping", &body).map(drop)
    }

    /// POST one SOAP envelope, return the response body on 2xx.
    fn soap(&self, action: &str, inner: &str) -> Result<String, String> {
        let body = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
                 s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
               <s:Body>{inner}</s:Body>\
             </s:Envelope>"
        );
        // HTTP/1.1 + Connection: close ⇒ read-to-EOF yields the
        // whole body, no Content-Length / chunked parsing needed.
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: {len}\r\n\
             Content-Type: text/xml; charset=\"utf-8\"\r\n\
             SOAPAction: \"{st}#{action}\"\r\n\
             Connection: close\r\n\r\n{body}",
            path = self.control_url,
            host = self.addr,
            len = body.len(),
            st = self.service_type,
        );
        let resp = http_roundtrip(self.addr, &req)?;
        let (status, body) = split_http_response(&resp)?;
        if !(200..300).contains(&status) {
            // SOAP faults carry a UPnP error code in the body —
            // surface it for the caller's `format!("…: {e}")`.
            let detail = extract_tag(body, "errorDescription")
                .or_else(|| extract_tag(body, "errorCode"))
                .unwrap_or(body.trim());
            return Err(format!("HTTP {status}: {detail}"));
        }
        Ok(body.to_owned())
    }
}

// ──── HTTP / parsing helpers ────────────────────────────────────

fn fetch_control_url(addr: SocketAddrV4, root_path: &str) -> Result<(String, String), String> {
    let req = format!(
        "GET {root_path} HTTP/1.1\r\nHost: {addr}\r\n\
         Accept: text/xml\r\nConnection: close\r\n\r\n"
    );
    let resp = http_roundtrip(addr, &req)?;
    let (status, body) = split_http_response(&resp)?;
    if status != 200 {
        return Err(format!("GET rootdesc: HTTP {status}"));
    }
    parse_control_url(body)
        .ok_or_else(|| "no WAN{IP,PPP}Connection service in device description".into())
}

fn http_roundtrip(addr: SocketAddrV4, req: &str) -> Result<String, String> {
    let deadline = Instant::now() + HTTP_DEADLINE;
    let mut s = TcpStream::connect_timeout(&SocketAddr::V4(addr), HTTP_TIMEOUT)
        .map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_write_timeout(Some(HTTP_TIMEOUT)).ok();
    s.write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    // Manual read loop instead of `read_to_end`: enforce both a
    // wall-clock deadline (so a 1 B/s trickle can't wedge us past
    // `HTTP_DEADLINE`) and a size cap (so a fast writer can't OOM).
    let mut out = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let remain = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| format!("read: exceeded {HTTP_DEADLINE:?} wall-clock deadline"))?;
        s.set_read_timeout(Some(remain.max(Duration::from_millis(1))))
            .ok();
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                // Cap, don't error: the part we need (status line +
                // the handful of XML tags) is at the front; a
                // miniupnpd that pads with whitespace shouldn't fail.
                let take = n.min(HTTP_MAX_RESPONSE - out.len());
                out.extend_from_slice(&chunk[..take]);
                if out.len() >= HTTP_MAX_RESPONSE {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(format!(
                    "read: exceeded {HTTP_DEADLINE:?} wall-clock deadline"
                ));
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn split_http_response(resp: &str) -> Result<(u16, &str), String> {
    let status: u16 = resp
        .strip_prefix("HTTP/1.")
        .and_then(|r| r.get(2..5))
        .and_then(|s| s.parse().ok())
        .ok_or("malformed HTTP status line")?;
    let body = resp
        .split_once("\r\n\r\n")
        .or_else(|| resp.split_once("\n\n"))
        .map_or("", |(_, b)| b);
    Ok((status, body))
}

/// Case-insensitive scan for the `LOCATION:` header in an SSDP
/// reply. Returns the trimmed URL.
fn parse_ssdp_location(reply: &str) -> Option<&str> {
    for line in reply.split("\r\n") {
        let mut it = line.splitn(2, ':');
        if it.next()?.eq_ignore_ascii_case("location") {
            return Some(it.next()?.trim());
        }
    }
    None
}

/// `http://192.168.1.1:49000/igddesc.xml` → `(addr, "/igddesc.xml")`.
/// No `url` crate: IGD `LOCATION` is always this exact shape.
fn split_http_url(url: &str) -> Option<(SocketAddrV4, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let addr: SocketAddrV4 = authority.parse().ok()?;
    Some((addr, format!("/{path}")))
}

/// Find the first WAN service's `controlURL` in a device-desc XML.
/// Walks each `<service>…</service>` block; for the first whose
/// `<serviceType>` matches `WAN_SERVICES`, return its
/// `<controlURL>`. Substring scan, no XML parser — miniupnpc does
/// the same (`minixml.c`).
fn parse_control_url(xml: &str) -> Option<(String, String)> {
    // Preference order: try each service type across the whole doc
    // before falling back to the next. A Fritzbox exposes both
    // WANIPConn:1 and WANPPPConn:1; the IP one is the right one.
    for want in WAN_SERVICES {
        let mut rest = xml;
        while let Some(start) = rest.find("<service>") {
            rest = &rest[start + "<service>".len()..];
            // Malformed (no close tag) → give up on this `want`
            // but still try the next preference.
            let Some(end) = rest.find("</service>") else {
                break;
            };
            let block = &rest[..end];
            rest = &rest[end..];
            if extract_tag(block, "serviceType") == Some(want) {
                let mut url = extract_tag(block, "controlURL")?.to_owned();
                // Some stacks emit a relative URL without leading
                // slash; the GET/POST path needs one.
                if !url.starts_with('/') {
                    url.insert(0, '/');
                }
                return Some((url, want.to_owned()));
            }
        }
    }
    None
}

/// Text between `<tag>` and `</tag>`. No attribute/namespace
/// handling — the IGD tags we read never carry either.
fn extract_tag<'a>(hay: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = hay.find(&open)? + open.len();
    let e = s + hay[s..].find(&close)?;
    Some(hay[s..e].trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_reply_to_addr_and_path() {
        // Mixed-case header, value contains ':' (port) — splitn(2).
        let reply = "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=120\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
             Location: http://192.168.77.1:5000/rootDesc.xml\r\n\
             SERVER: miniupnpd/2.3\r\n\r\n";
        assert_eq!(
            parse_ssdp_location(reply).and_then(split_http_url),
            Some(("192.168.77.1:5000".parse().unwrap(), "/rootDesc.xml".into()))
        );
    }

    /// Trimmed miniupnpd `rootDesc.xml`: nested device tree, an
    /// uninteresting service before the WAN one. Covers the
    /// per-`<service>`-block scoping of `controlURL`.
    #[test]
    fn control_url_from_miniupnpd_rootdesc() {
        let xml = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
 <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
 <deviceList><device>
  <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
  <serviceList>
   <service>
    <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
    <controlURL>/ctl/CmnIfCfg</controlURL>
   </service>
   <service>
    <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
    <controlURL>/ctl/IPConn</controlURL>
    <SCPDURL>/WANIPCn.xml</SCPDURL>
   </service>
  </serviceList>
 </device></deviceList>
</device></root>"#;
        let (url, st) = parse_control_url(xml).unwrap();
        assert_eq!(url, "/ctl/IPConn");
        assert_eq!(st, "urn:schemas-upnp-org:service:WANIPConnection:1");
    }

    /// Fritzbox lists `WANPPPConnection` before `WANIPConnection`;
    /// the IP service is the one that actually maps ports.
    #[test]
    fn control_url_prefers_ip_over_ppp() {
        let xml = "<service>\
             <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
             <controlURL>/upnp/control/WANPPPConn1</controlURL></service>\
             <service>\
             <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
             <controlURL>/upnp/control/WANIPConn1</controlURL></service>";
        let (url, _) = parse_control_url(xml).unwrap();
        assert_eq!(url, "/upnp/control/WANIPConn1");
    }

    /// A rogue HTTP endpoint that (a) sends an oversize body and
    /// (b) trickles bytes slowly must neither blow past
    /// `HTTP_MAX_RESPONSE` nor block past `HTTP_DEADLINE`.
    #[test]
    fn http_roundtrip_bounded() {
        use std::net::TcpListener;
        use std::thread;

        // (a) size cap: 128 KiB body, sent fast.
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = match l.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => unreachable!(),
        };
        let srv = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut sink = [0u8; 4096];
            let _ = s.read(&mut sink);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            let _ = s.write_all(&vec![b'A'; 128 * 1024]);
        });
        let resp = http_roundtrip(addr, "GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(resp.len() <= HTTP_MAX_RESPONSE, "len={}", resp.len());
        srv.join().unwrap();

        // (b) wall-clock cap: trickle 1 B/200 ms forever; must give
        // up by HTTP_DEADLINE (assert <6 s for slop).
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = match l.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => unreachable!(),
        };
        let srv = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut sink = [0u8; 4096];
            let _ = s.read(&mut sink);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            while s.write_all(b"A").is_ok() {
                thread::sleep(Duration::from_millis(200));
            }
        });
        let t0 = Instant::now();
        let r = http_roundtrip(addr, "GET / HTTP/1.1\r\n\r\n");
        let elapsed = t0.elapsed();
        assert!(r.is_err(), "trickle should hit deadline, got {r:?}");
        assert!(elapsed < Duration::from_secs(6), "took {elapsed:?}");
        // Unblock the server thread (write_all will fail on RST).
        drop(r);
        srv.join().unwrap();
    }
}
