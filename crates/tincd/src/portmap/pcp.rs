//! Port Control Protocol (RFC 6887) — MAP opcode only.
//!
//! PCP is the IETF successor to NAT-PMP (which it formally
//! supersedes; RFC 6886 abstract, and IANA reassigned port 5351 to
//! PCP). One UDP request to the default gateway, one response.
//! Packet format is fixed-layout binary (no XML/HTTP), so we
//! hand-roll it: ~100 lines, zero deps, vs `natpmp`'s
//! `async-trait`/`netdev` baggage or n0 `portmapper`'s +190 crates.
//!
//! ## Why PCP and not NAT-PMP
//!
//! Probed in the field (AVM Fritzbox 7583, FRITZ!OS 8.x): answers
//! PCP on `:5351` (v4 *and* v6), does **not** answer NAT-PMP. Every
//! miniupnpd-based router (`OpenWRT`, pfSense, Asus/Ubiquiti stock)
//! dispatches both off the same socket by version byte, so PCP ⊇
//! NAT-PMP in practice. RFC 6887 Appendix A also says clients
//! supporting both "SHOULD send using the PCP packet format".
//! NAT-PMP-only servers (≈ pre-2013 Apple `AirPort`, EOL 2018) would
//! reply `UNSUPP_VERSION` ver=0 and we'd fall through to IGD —
//! acceptable.
//!
//! ## v6
//!
//! Unlike NAT-PMP, PCP carries 128-bit addresses and works over a
//! v6 transport. On v6 there's no NAT: a MAP request asks the
//! router's *firewall* to accept inbound to `our_gua:port` (the
//! response's "assigned external addr" is just our own GUA echoed
//! back). The transport is the v6 default router's link-local
//! address — we must bind the socket to our GUA first, or the
//! kernel sources from our link-local and the server's
//! `ADDRESS_MISMATCH` check rejects it (and even if it didn't, a
//! pinhole to a link-local addr is useless).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::Duration;

use super::Proto;

const PCP_PORT: u16 = 5351;
const VERSION: u8 = 2;
const OP_MAP: u8 = 1;
/// Common header (24) + MAP payload (36). Same for request and
/// response (RFC 6887 §11.1: "similar packet layout for both").
const MAP_LEN: usize = 60;

/// IANA proto numbers — what the MAP `Protocol` field carries.
const fn ip_proto(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 6,
        Proto::Udp => 17,
    }
}

/// `::ffff:a.b.c.d` — RFC 6887 mandates v4-mapped form for every
/// IPv4 address that appears in a PCP message (§5).
fn v4_mapped(v4: Ipv4Addr) -> [u8; 16] {
    v4.to_ipv6_mapped().octets()
}

/// RFC 6887 §7.4 result codes (for log readability).
fn result_str(code: u8) -> &'static str {
    match code {
        0 => "SUCCESS",
        1 => "UNSUPP_VERSION",
        2 => "NOT_AUTHORIZED",
        3 => "MALFORMED_REQUEST",
        4 => "UNSUPP_OPCODE",
        5 => "UNSUPP_OPTION",
        6 => "MALFORMED_OPTION",
        7 => "NETWORK_FAILURE",
        8 => "NO_RESOURCES",
        9 => "UNSUPP_PROTOCOL",
        10 => "USER_EX_QUOTA",
        11 => "CANNOT_PROVIDE_EXTERNAL",
        12 => "ADDRESS_MISMATCH",
        13 => "EXCESSIVE_REMOTE_PEERS",
        _ => "(unknown)",
    }
}

/// Build a v2 MAP request.
///
/// `client`: the PCP-client-IP field (our source address as the
/// server will see it). `suggest_ext`: suggested external address —
/// `::ffff:0.0.0.0` for v4 ("any"), our own GUA for v6 (so the
/// server treats it as a firewall pinhole, not a NAT mapping;
/// miniupnpd's `is_fw` keys off `IN6_IS_ADDR_V4MAPPED` here).
fn build_map_request(
    nonce: &[u8; 12],
    lifetime: u32,
    client: [u8; 16],
    proto: Proto,
    int_port: u16,
    suggest_ext_port: u16,
    suggest_ext: [u8; 16],
) -> [u8; MAP_LEN] {
    let mut b = [0u8; MAP_LEN];
    // ── common request header (§7.1) ─────────────────────────────
    b[0] = VERSION;
    b[1] = OP_MAP; // R=0 (request)
    // b[2..4] reserved = 0
    b[4..8].copy_from_slice(&lifetime.to_be_bytes());
    b[8..24].copy_from_slice(&client);
    // ── MAP opcode payload (§11.1, Figure 9) ─────────────────────
    b[24..36].copy_from_slice(nonce);
    b[36] = ip_proto(proto);
    // b[37..40] reserved = 0
    b[40..42].copy_from_slice(&int_port.to_be_bytes());
    b[42..44].copy_from_slice(&suggest_ext_port.to_be_bytes());
    b[44..60].copy_from_slice(&suggest_ext);
    b
}

/// Parse a MAP response. Returns `(ext_addr, ext_port)` on
/// `SUCCESS`, error string otherwise. Validates version, R-bit,
/// opcode, nonce echo.
fn parse_map_response(buf: &[u8], nonce: &[u8; 12]) -> Result<(IpAddr, u16), String> {
    if buf.len() < MAP_LEN {
        return Err(format!("short response ({}B)", buf.len()));
    }
    if buf[1] != (OP_MAP | 0x80) {
        return Err(format!("unexpected opcode 0x{:02x}", buf[1]));
    }
    let result = buf[3];
    if buf[0] != VERSION {
        // §9: server replied with the highest version it speaks. A
        // pure-NAT-PMP server (Apple AirPort) sends ver=0 here per
        // RFC 6886 — we don't downgrade, just report and let the
        // IGD fallback handle it.
        return Err(format!(
            "server speaks version {} (result {} {})",
            buf[0],
            result,
            result_str(result)
        ));
    }
    if result != 0 {
        return Err(format!("result {} {}", result, result_str(result)));
    }
    // Constant-time compare. The reply is unauthenticated UDP from
    // the gateway anyway, so timing leakage isn't a practical
    // oracle here, but `subtle` is already in-tree via dalek and
    // it's the right primitive for a nonce check.
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&buf[24..36], &nonce[..])) {
        return Err("nonce mismatch (stale/forged response)".into());
    }
    let ext_port = u16::from_be_bytes([buf[42], buf[43]]);
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&buf[44..60]);
    let v6 = Ipv6Addr::from(raw);
    // Unwrap ::ffff:a.b.c.d → a.b.c.d so the rest of the daemon
    // (and the published `tcp=`) sees a plain v4 SocketAddr.
    let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
    Ok((ip, ext_port))
}

/// One MAP round-trip on an already-connected UDP socket. Retries
/// once on silence (RFC schedule is 8 retries over ~128 s; on a LAN
/// to the default gateway, 2 s of nothing means "doesn't speak
/// PCP" — fall through to IGD instead of stalling Drop's join).
fn roundtrip(
    sock: &UdpSocket,
    req: &[u8; MAP_LEN],
    nonce: &[u8; 12],
) -> Result<(IpAddr, u16), String> {
    sock.set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let mut buf = [0u8; 1100]; // §7: max PCP message size
    for _ in 0..2 {
        sock.send(req).map_err(|e| format!("send: {e}"))?;
        match sock.recv(&mut buf) {
            Ok(n) => return parse_map_response(&buf[..n], nonce),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
    Err("no reply within 2s".into())
}

/// v4 MAP: ask the v4 default gateway to DNAT `ext:?` → `us:port`.
/// Returns the assigned `(ext_ip, ext_port)`.
pub(super) fn map_v4(
    gw: Ipv4Addr,
    proto: Proto,
    port: u16,
    lease: u32,
    nonce: &[u8; 12],
) -> Result<SocketAddr, String> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| format!("bind: {e}"))?;
    sock.connect((gw, PCP_PORT))
        .map_err(|e| format!("connect {gw}: {e}"))?;
    // §8.1: client IP MUST equal the packet's source addr (server
    // checks, returns ADDRESS_MISMATCH otherwise). connect() made
    // the kernel pick it.
    let client = match sock.local_addr().map(|a| a.ip()) {
        Ok(IpAddr::V4(v4)) if !v4.is_unspecified() => v4,
        _ => return Err("no v4 source addr towards gateway".into()),
    };
    let req = build_map_request(
        nonce,
        lease,
        v4_mapped(client),
        proto,
        port,
        port, // suggest ext=int; server may override
        v4_mapped(Ipv4Addr::UNSPECIFIED),
    );
    let (ip, ext_port) = roundtrip(&sock, &req, nonce)?;
    Ok(SocketAddr::new(ip, ext_port))
}

/// v6 MAP: ask the v6 default router (link-local) to open a
/// firewall pinhole to `gua:port`. We bind to `gua` so the packet
/// is sourced from it (kernel would otherwise pick our link-local
/// for a link-local dst, and the server's `ADDRESS_MISMATCH` check —
/// `sender_ip == client_ip` — fails). `scope` is the ifindex for
/// the link-local gateway.
pub(super) fn map_v6(
    gw: Ipv6Addr,
    scope: u32,
    gua: Ipv6Addr,
    proto: Proto,
    port: u16,
    lease: u32,
    nonce: &[u8; 12],
) -> Result<SocketAddr, String> {
    let sock = UdpSocket::bind((gua, 0)).map_err(|e| format!("bind [{gua}]: {e}"))?;
    // scope_id only meaningful for link-local (RA-learnt router,
    // the common case); zero it for a global gateway addr.
    let scope = if gw.is_unicast_link_local() { scope } else { 0 };
    let dst = SocketAddrV6::new(gw, PCP_PORT, 0, scope);
    sock.connect(dst)
        .map_err(|e| format!("connect {dst}: {e}"))?;
    let req = build_map_request(
        nonce,
        lease,
        gua.octets(),
        proto,
        port,
        port,
        // Suggest our own GUA: signals "firewall pinhole, not NAT"
        // to the server (miniupnpd keys `is_fw` off whether this
        // field is v4-mapped). RFC says all-zeros is also legal but
        // then a v4-only server might try to NAT it.
        gua.octets(),
    );
    let (ip, ext_port) = roundtrip(&sock, &req, nonce)?;
    Ok(SocketAddr::new(ip, ext_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden against RFC 6887 §7.1 + §11.1 layouts. Values chosen
    /// so each field is visually distinct in hex.
    #[test]
    fn build_map_request_layout() {
        let nonce = *b"NONCEnonce12";
        let req = build_map_request(
            &nonce,
            0x0001_2345,
            v4_mapped(Ipv4Addr::new(192, 168, 1, 7)),
            Proto::Tcp,
            655,
            655,
            v4_mapped(Ipv4Addr::UNSPECIFIED),
        );
        assert_eq!(req[0], 2, "version");
        assert_eq!(req[1], 1, "R=0|opcode=MAP");
        assert_eq!(&req[2..4], &[0, 0], "reserved");
        assert_eq!(&req[4..8], &[0x00, 0x01, 0x23, 0x45], "lifetime BE");
        assert_eq!(
            &req[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 7],
            "client ip ::ffff:v4"
        );
        assert_eq!(&req[24..36], b"NONCEnonce12", "nonce");
        assert_eq!(req[36], 6, "proto=TCP");
        assert_eq!(&req[37..40], &[0, 0, 0], "reserved");
        assert_eq!(&req[40..42], &655u16.to_be_bytes(), "int port");
        assert_eq!(&req[42..44], &655u16.to_be_bytes(), "suggest ext port");
        assert_eq!(
            &req[44..60],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
            "suggest ext ip ::ffff:0.0.0.0"
        );
        assert_eq!(req.len(), 60);
    }

    /// Parse a synthetic SUCCESS MAP response and confirm v4-mapped
    /// unwrapping. Also exercises the error branches the worker
    /// relies on (result≠0, version mismatch, bad nonce).
    #[test]
    fn parse_map_response_paths() {
        let nonce = [7u8; 12];
        // hand-build: ver=2, R|MAP, res=0, lifetime, epoch,
        // 12B reserved, then MAP body (nonce, proto, res, ports,
        // ext addr).
        let mut r = [0u8; 60];
        r[0] = 2;
        r[1] = 0x81;
        r[3] = 0; // SUCCESS
        r[24..36].copy_from_slice(&nonce);
        r[36] = 17; // UDP
        r[40..42].copy_from_slice(&655u16.to_be_bytes());
        r[42..44].copy_from_slice(&40655u16.to_be_bytes());
        r[44..60].copy_from_slice(&v4_mapped(Ipv4Addr::new(203, 0, 113, 9)));
        assert_eq!(
            parse_map_response(&r, &nonce).unwrap(),
            (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 40655)
        );

        // v6 ext addr stays v6.
        let gua: Ipv6Addr = "2001:db8::42".parse().unwrap();
        r[44..60].copy_from_slice(&gua.octets());
        assert_eq!(
            parse_map_response(&r, &nonce).unwrap(),
            (IpAddr::V6(gua), 40655)
        );

        // result ≠ 0 surfaces the symbolic name.
        r[3] = 2;
        let e = parse_map_response(&r, &nonce).unwrap_err();
        assert!(e.contains("NOT_AUTHORIZED"), "{e}");

        // version mismatch (NAT-PMP-only server replying ver=0).
        r[0] = 0;
        r[3] = 1;
        let e = parse_map_response(&r, &nonce).unwrap_err();
        assert!(e.contains("version 0"), "{e}");

        // nonce mismatch.
        r[0] = 2;
        r[3] = 0;
        let e = parse_map_response(&r, &[9u8; 12]).unwrap_err();
        assert!(e.contains("nonce"), "{e}");

        // short.
        assert!(parse_map_response(&r[..40], &nonce).is_err());
    }
}
