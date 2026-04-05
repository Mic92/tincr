//! SOCKS4/SOCKS5 byte format. `proxy.c` (285 LOC).
//!
//! SOCKS4 (<https://www.openssh.com/txt/socks4.protocol>): IPv4 only.
//! Req `[04][01][port:2be][ip:4][userid\0]`; resp 8B, status `0x5A`.
//!
//! SOCKS5 (RFC 1928): three round-trips sent as one blob (`:175-237`).
//! Greet+auth+connect; resp is choice+auth_status+conn_resp concat.
//!
//! NOT here: SOCKS4A (`:80` "not implemented"), HTTP CONNECT
//! (daemon's send_proxyrequest), PROXY_EXEC (I/O).

#![forbid(unsafe_code)]

use std::net::SocketAddr;

// ── SOCKS4 wire constants ──────────────────────────────────────────
const SOCKS4_VERSION: u8 = 4;
const SOCKS4_CMD_CONN: u8 = 1;
const SOCKS4_REPLY_VERSION: u8 = 0;
const SOCKS4_STATUS_OK: u8 = 0x5A;
/// `sizeof(socks4_response_t)` (`proxy.h:18-23`): ver+status+port+ip.
const SOCKS4_RESPONSE_LEN: usize = 8;

// ── SOCKS5 wire constants ──────────────────────────────────────────
const SOCKS5_VERSION: u8 = 5;
const SOCKS5_AUTH_METHOD_NONE: u8 = 0;
const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 2;
/// Server chose nothing we offered (RFC 1928 §3).
const SOCKS5_AUTH_FAILED: u8 = 0xFF;
const SOCKS5_AUTH_VERSION: u8 = 1;
const SOCKS5_AUTH_OK: u8 = 0;
const SOCKS5_COMMAND_CONN: u8 = 1;
const SOCKS5_STATUS_OK: u8 = 0;
const SOCKS5_ATYP_IPV4: u8 = 1;
const SOCKS5_ATYP_IPV6: u8 = 4;

// `proxy.h` struct sizes. We use byte offsets, not #[repr(C)].
const SOCKS5_SERVER_CHOICE_LEN: usize = 2; // socks5_server_choice_t
const SOCKS5_AUTH_STATUS_LEN: usize = 2; // socks5_auth_status_t
const SOCKS5_CONN_RESP_LEN: usize = 4; // socks5_conn_resp_t (header only)
const SOCKS5_IPV4_LEN: usize = 6; // socks5_ipv4_t (4 + 2)
const SOCKS5_IPV6_LEN: usize = 18; // socks5_ipv6_t (16 + 2)

/// Proxy type. `net.h:171-178`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProxyType {
    /// `PROXY_SOCKS4` — IPv4 only.
    Socks4,
    /// `PROXY_SOCKS5` — IPv4 + IPv6.
    Socks5,
}

/// `proxyuser`/`proxypass`. SOCKS4: user only. SOCKS5: both for
/// password auth; `pass=None` → anonymous.
#[derive(Debug, Clone)]
pub struct Creds {
    pub user: String,
    /// SOCKS5 only. `None` → anonymous auth.
    pub pass: Option<String>,
}

/// `create_socks_req`. Returns `(request_bytes, expected_response_len)`.
///
/// # Errors
/// - `Socks4Ipv6`: SOCKS4 has no v6 addressing.
/// - `CredTooLong`: STRICTER than upstream, which truncates `size_t`
///   userlen to u8; a 256B username would send `[00]` and the proxy
///   would read 0 bytes. RFC 1929 says 1..255.
pub fn build_request(
    proxy: ProxyType,
    target: SocketAddr,
    creds: Option<&Creds>,
) -> Result<(Vec<u8>, usize), BuildError> {
    match proxy {
        ProxyType::Socks4 => build_socks4(target, creds),
        ProxyType::Socks5 => build_socks5(target, creds),
    }
}

fn build_socks4(target: SocketAddr, creds: Option<&Creds>) -> Result<(Vec<u8>, usize), BuildError> {
    let SocketAddr::V4(v4) = target else {
        return Err(BuildError::Socks4Ipv6);
    };

    let user = creds.map_or("", |c| c.user.as_str());
    let mut buf = Vec::with_capacity(8 + user.len() + 1);

    buf.push(SOCKS4_VERSION);
    buf.push(SOCKS4_CMD_CONN);
    // :163. sin_port is net-order; SocketAddr::port() is host-order.
    buf.extend_from_slice(&v4.port().to_be_bytes());
    buf.extend_from_slice(&v4.ip().octets()); // :164
    // :167-170 NUL-terminated
    buf.extend_from_slice(user.as_bytes());
    buf.push(0);

    Ok((buf, SOCKS4_RESPONSE_LEN)) // :172
}

fn build_socks5(target: SocketAddr, creds: Option<&Creds>) -> Result<(Vec<u8>, usize), BuildError> {
    // password auth needs BOTH user AND pass
    let password_auth = creds.and_then(|c| c.pass.as_ref().map(|p| (c.user.as_str(), p.as_str())));

    // STRICTER: upstream narrows size_t→u8; we check (RFC 1929).
    if let Some((user, pass)) = password_auth
        && (user.len() > 255 || pass.len() > 255)
    {
        return Err(BuildError::CredTooLong);
    }

    let mut buf = Vec::new();
    let mut resplen = SOCKS5_SERVER_CHOICE_LEN; // :188

    // ── Greet. :183: nmethods=1 — server's choice is predictable
    // (our method or 0xFF). "Offered password, server chose anon"
    // doesn't arise for tinc's shape.
    buf.push(SOCKS5_VERSION);
    buf.push(1); // nmethods
    buf.push(if password_auth.is_some() {
        SOCKS5_AUTH_METHOD_PASSWORD
    } else {
        SOCKS5_AUTH_METHOD_NONE
    });

    // ── Auth (RFC 1929, :192-213): [01][userlen][user][passlen][pass]
    if let Some((user, pass)) = password_auth {
        buf.push(SOCKS5_AUTH_VERSION);
        #[allow(clippy::cast_possible_truncation)] // checked ≤255 above
        {
            buf.push(user.len() as u8);
            buf.extend_from_slice(user.as_bytes());
            buf.push(pass.len() as u8);
            buf.extend_from_slice(pass.as_bytes());
        }
        resplen += SOCKS5_AUTH_STATUS_LEN; // :213
    }

    // ── Connect (:217-220)
    buf.push(SOCKS5_VERSION);
    buf.push(SOCKS5_COMMAND_CONN);
    buf.push(0); // reserved
    resplen += SOCKS5_CONN_RESP_LEN; // :222

    match target {
        SocketAddr::V4(v4) => {
            buf.push(SOCKS5_ATYP_IPV4); // :225-228
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
            resplen += SOCKS5_IPV4_LEN;
        }
        SocketAddr::V6(v6) => {
            buf.push(SOCKS5_ATYP_IPV6); // :230-233
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
            resplen += SOCKS5_IPV6_LEN;
        }
    }

    Ok((buf, resplen))
}

/// Response from a SOCKS proxy.
#[derive(Debug, PartialEq, Eq)]
pub enum SocksResponse {
    /// `0x5A` (SOCKS4) or `0x00` (SOCKS5). Tunnel open.
    Granted,
    /// Rejected. Codes not decoded (C doesn't either).
    Rejected,
    /// Wrong version byte / auth-version / etc.
    Malformed(&'static str),
}

/// Slice is exactly `expected_response_len`. `creds` unused:
/// dispatches on server's choice byte (predictable since nmethods=1).
#[must_use]
pub fn check_response(proxy: ProxyType, _creds: Option<&Creds>, buf: &[u8]) -> SocksResponse {
    match proxy {
        ProxyType::Socks4 => check_socks4(buf),
        ProxyType::Socks5 => check_socks5(buf),
    }
}

fn check_socks4(buf: &[u8]) -> SocksResponse {
    if buf.len() < SOCKS4_RESPONSE_LEN {
        return SocksResponse::Malformed("Received short response from proxy");
    }
    if buf[0] != SOCKS4_REPLY_VERSION {
        return SocksResponse::Malformed("Bad response from SOCKS4 proxy");
    }
    // :56-58. Port/ip in buf[2..8] ignored.
    if buf[1] == SOCKS4_STATUS_OK {
        SocksResponse::Granted
    } else {
        SocksResponse::Rejected
    }
}

/// Layout depends on server's auth choice (anon: no auth_status block).
fn check_socks5(buf: &[u8]) -> SocksResponse {
    if buf.len() < SOCKS5_SERVER_CHOICE_LEN {
        return SocksResponse::Malformed("Received short response from proxy");
    }
    let rest = &buf[SOCKS5_SERVER_CHOICE_LEN..];

    // :100-103
    if buf[0] != SOCKS5_VERSION {
        return SocksResponse::Malformed("Invalid response from proxy server");
    }

    // :105-144 dispatch on server's pick (with nmethods=1: ours or 0xFF)
    match buf[1] {
        SOCKS5_AUTH_METHOD_NONE => {
            // :106-112
            if rest.len() < SOCKS5_CONN_RESP_LEN {
                return SocksResponse::Malformed("Received short response from proxy");
            }
            check_socks5_conn(rest)
        }
        SOCKS5_AUTH_METHOD_PASSWORD => {
            // :114-132
            let header_len = SOCKS5_AUTH_STATUS_LEN + SOCKS5_CONN_RESP_LEN;
            if rest.len() < header_len {
                return SocksResponse::Malformed("Received short response from proxy");
            }
            // :122-125
            if rest[0] != SOCKS5_AUTH_VERSION {
                return SocksResponse::Malformed("Invalid proxy authentication protocol version");
            }
            // :127-130. Auth fail is VALID → Rejected, not Malformed.
            if rest[1] != SOCKS5_AUTH_OK {
                return SocksResponse::Rejected;
            }
            check_socks5_conn(&rest[SOCKS5_AUTH_STATUS_LEN..])
        }
        // :135-137. C log says "rejected".
        SOCKS5_AUTH_FAILED => SocksResponse::Rejected,
        // :139-141
        _ => SocksResponse::Malformed("Unsupported authentication method"),
    }
}

/// Addr/port not validated (addr_type is just for length check).
fn check_socks5_conn(buf: &[u8]) -> SocksResponse {
    // Caller checked len >= SOCKS5_CONN_RESP_LEN.
    let addr_type = buf[3];
    let addrlen = match addr_type {
        SOCKS5_ATYP_IPV4 => SOCKS5_IPV4_LEN,
        SOCKS5_ATYP_IPV6 => SOCKS5_IPV6_LEN,
        // :73-75. Includes atyp=3 (domain) — tinc never asks for it.
        _ => {
            return SocksResponse::Malformed("Unsupported address type from proxy server");
        }
    };

    // :77-80
    if buf.len() < SOCKS5_CONN_RESP_LEN + addrlen {
        return SocksResponse::Malformed("Received short address from proxy server");
    }

    // :82-85
    if buf[0] != SOCKS5_VERSION {
        return SocksResponse::Malformed("Invalid response from proxy server");
    }

    // :87-89
    if buf[1] == SOCKS5_STATUS_OK {
        SocksResponse::Granted
    } else {
        SocksResponse::Rejected
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    /// SOCKS4 + IPv6.
    Socks4Ipv6,
    /// Credential string > 255 bytes. STRICTER than upstream.
    CredTooLong,
}

// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    // ── SOCKS4 build ───────────────────────────────────────────────

    #[test]
    fn socks4_v4_anonymous() {
        let (req, resplen) = build_request(ProxyType::Socks4, v4(127, 0, 0, 1, 655), None).unwrap();
        // [04][01][02 8f][7f 00 00 01][00]. 02 8f = 655 BE.
        assert_eq!(
            req,
            vec![0x04, 0x01, 0x02, 0x8f, 0x7f, 0x00, 0x00, 0x01, 0x00]
        );
        assert_eq!(resplen, 8);
    }

    #[test]
    fn socks4_v4_with_user() {
        let creds = Creds {
            user: "alice".into(),
            pass: None,
        };
        let (req, resplen) =
            build_request(ProxyType::Socks4, v4(127, 0, 0, 1, 655), Some(&creds)).unwrap();
        assert_eq!(
            req,
            vec![
                0x04, 0x01, 0x02, 0x8f, 0x7f, 0x00, 0x00, 0x01, b'a', b'l', b'i', b'c', b'e', 0x00
            ]
        );
        assert_eq!(resplen, 8);
    }

    #[test]
    fn socks4_v6_rejected() {
        let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 655, 0, 0));
        let err = build_request(ProxyType::Socks4, target, None).unwrap_err();
        assert_eq!(err, BuildError::Socks4Ipv6);
    }

    // ── SOCKS5 build ───────────────────────────────────────────────

    #[test]
    fn socks5_v4_anonymous() {
        let (req, resplen) =
            build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), None).unwrap();
        assert_eq!(
            req,
            vec![
                0x05, 0x01, 0x00, // greet: ver, nmethods=1, anon
                0x05, 0x01, 0x00, 0x01, // conn hdr: ver, conn, rsvd, ipv4
                0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
                0x1f, 0x90, // 8080 BE
            ]
        );
        assert_eq!(req.len(), 13);
        assert_eq!(resplen, 12); // choice(2) + conn_resp(4) + ipv4(6)
    }

    #[test]
    fn socks5_v4_password() {
        let creds = Creds {
            user: "bob".into(),
            pass: Some("hunter2".into()),
        };
        let (req, resplen) =
            build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), Some(&creds)).unwrap();
        let expect: Vec<u8> = vec![
            0x05, 0x01, 0x02, // greet: password method
            0x01, // auth version
            3, b'b', b'o', b'b', // userlen + user
            7, b'h', b'u', b'n', b't', b'e', b'r', b'2', // passlen + pass
            0x05, 0x01, 0x00, 0x01, // conn hdr
            0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
            0x1f, 0x90, // 8080
        ];
        assert_eq!(req, expect);
        assert_eq!(resplen, 14); // choice(2) + auth_status(2) + conn_resp(4) + ipv4(6)
    }

    #[test]
    fn socks5_user_without_pass_is_anonymous() {
        // both must be set.
        let creds = Creds {
            user: "bob".into(),
            pass: None,
        };
        let (req, resplen) =
            build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), Some(&creds)).unwrap();
        assert_eq!(req[2], 0x00); // anon method, no auth block
        assert_eq!(req.len(), 13); // same as anonymous
        assert_eq!(resplen, 12);
    }

    #[test]
    fn socks5_v6() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let target = SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 0));
        let (req, resplen) = build_request(ProxyType::Socks5, target, None).unwrap();

        let mut expect = vec![
            0x05, 0x01, 0x00, // greet
            0x05, 0x01, 0x00, 0x04, // conn hdr: atyp=ipv6
        ];
        expect.extend_from_slice(&ip.octets());
        expect.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(req, expect);
        assert_eq!(resplen, 24); // choice(2) + conn_resp(4) + ipv6(18)
    }

    #[test]
    fn socks5_cred_too_long() {
        let creds = Creds {
            user: "x".repeat(256),
            pass: Some("y".into()),
        };
        let err = build_request(ProxyType::Socks5, v4(1, 1, 1, 1, 1), Some(&creds)).unwrap_err();
        assert_eq!(err, BuildError::CredTooLong);

        // 255 is fine.
        let creds = Creds {
            user: "x".repeat(255),
            pass: Some("y".into()),
        };
        assert!(build_request(ProxyType::Socks5, v4(1, 1, 1, 1, 1), Some(&creds)).is_ok());

        let creds = Creds {
            user: "x".into(),
            pass: Some("y".repeat(256)),
        };
        let err = build_request(ProxyType::Socks5, v4(1, 1, 1, 1, 1), Some(&creds)).unwrap_err();
        assert_eq!(err, BuildError::CredTooLong);
    }

    // ── SOCKS4 check ───────────────────────────────────────────────

    #[test]
    fn check_socks4_table() {
        use SocksResponse::*;
        #[rustfmt::skip]
        let cases: &[(&str, &[u8], SocksResponse)] = &[
            ("granted",       &[0x00, 0x5a, 0, 0, 0, 0, 0, 0], Granted),
            ("rejected",      &[0x00, 0x5b, 0, 0, 0, 0, 0, 0], Rejected),
            ("wrong version", &[0x01, 0x5a, 0, 0, 0, 0, 0, 0], Malformed("Bad response from SOCKS4 proxy")),
            ("short",         &[0x00, 0x5a, 0, 0],             Malformed("Received short response from proxy")),
        ];
        for (label, buf, want) in cases {
            assert_eq!(
                check_response(ProxyType::Socks4, None, buf),
                *want,
                "{label}"
            );
        }
    }

    // ── SOCKS5 check ───────────────────────────────────────────────
    // `_creds` param unused (dispatch on server's choice byte), so all
    // rows pass `None`. The v6 row's 24B layout is asserted inline.

    #[test]
    fn check_socks5_table() {
        use SocksResponse::*;
        #[rustfmt::skip]
        let v6_granted: &[u8] = &[
            0x05, 0x00, 0x05, 0x00, 0x00, 0x04, // choice + conn ok, atyp=ipv6
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // ipv6 addr+port (ignored)
        ];
        assert_eq!(v6_granted.len(), 24, "v6 resp layout");

        #[rustfmt::skip]
        let cases: &[(&str, &[u8], SocksResponse)] = &[
            ("anon granted",         &[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0],             Granted),
            ("password granted",     &[0x05, 0x02, 0x01, 0x00, 0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0], Granted),
            ("v6 addr in response",  v6_granted,                                                     Granted),
            // Auth fail is VALID → Rejected, not Malformed.
            ("auth rejected",        &[0x05, 0x02, 0x01, 0x01, 0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0], Rejected),
            ("auth method 0xff",     &[0x05, 0xff, 0,0,0,0,0,0,0,0,0,0],                             Rejected),
            ("conn rejected",        &[0x05, 0x00, 0x05, 0x01, 0x00, 0x01, 0,0,0,0,0,0],             Rejected),
            ("wrong choice version", &[0x04, 0x00, 0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0],             Malformed("Invalid response from proxy server")),
            ("wrong auth version",   &[0x05, 0x02, 0x02, 0x00, 0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0], Malformed("Invalid proxy authentication protocol version")),
            // atyp=3 (domain) — tinc never asks for it.
            ("unsupported addr type",&[0x05, 0x00, 0x05, 0x00, 0x00, 0x03, 0,0,0,0,0,0],             Malformed("Unsupported address type from proxy server")),
            ("unknown auth method",  &[0x05, 0x03, 0,0,0,0,0,0,0,0,0,0],                             Malformed("Unsupported authentication method")),
        ];
        for (label, buf, want) in cases {
            assert_eq!(
                check_response(ProxyType::Socks5, None, buf),
                *want,
                "{label}"
            );
        }
    }

    // ── Roundtrip: prove the resplen math ──────────────────────────

    #[test]
    fn roundtrip_socks5_v4_anon() {
        let (_req, resplen) = build_request(ProxyType::Socks5, v4(10, 0, 0, 1, 80), None).unwrap();
        let resp = vec![
            0x05, 0x00, // choice: anon
            0x05, 0x00, 0x00, 0x01, // conn ok, ipv4
            10, 0, 0, 1, 0, 80, // bound addr (proxy can put anything)
        ];
        assert_eq!(resp.len(), resplen);
        assert_eq!(
            check_response(ProxyType::Socks5, None, &resp),
            SocksResponse::Granted
        );
    }

    #[test]
    fn roundtrip_socks5_v4_password() {
        let creds = Creds {
            user: "u".into(),
            pass: Some("p".into()),
        };
        let (_req, resplen) =
            build_request(ProxyType::Socks5, v4(10, 0, 0, 1, 80), Some(&creds)).unwrap();
        let resp = vec![
            0x05, 0x02, // choice: password
            0x01, 0x00, // auth ok
            0x05, 0x00, 0x00, 0x01, // conn ok
            0, 0, 0, 0, 0, 0, // addr
        ];
        assert_eq!(resp.len(), resplen);
        assert_eq!(
            check_response(ProxyType::Socks5, Some(&creds), &resp),
            SocksResponse::Granted
        );
    }

    #[test]
    fn roundtrip_socks5_v6_anon() {
        let target = SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 443, 0, 0));
        let (_req, resplen) = build_request(ProxyType::Socks5, target, None).unwrap();
        let mut resp = vec![0x05, 0x00, 0x05, 0x00, 0x00, 0x04];
        resp.extend_from_slice(&[0u8; 18]);
        assert_eq!(resp.len(), resplen);
        assert_eq!(
            check_response(ProxyType::Socks5, None, &resp),
            SocksResponse::Granted
        );
    }

    #[test]
    fn roundtrip_socks4() {
        let (_req, resplen) = build_request(ProxyType::Socks4, v4(1, 2, 3, 4, 22), None).unwrap();
        let resp = [0x00, 0x5a, 0, 0, 0, 0, 0, 0];
        assert_eq!(resp.len(), resplen);
        assert_eq!(
            check_response(ProxyType::Socks4, None, &resp),
            SocksResponse::Granted
        );
    }
}
