//! SOCKS4/SOCKS5 byte format. `proxy.c` (285 LOC).
//!
//! SOCKS4 (<https://www.openssh.com/txt/socks4.protocol>): IPv4 only.
//! Req `[04][01][port:2be][ip:4][userid\0]`; resp 8B, status `0x5A`.
//!
//! SOCKS5 (RFC 1928): three round-trips sent as one blob.
//! Greet+auth+connect; resp is `choice+auth_status+conn_resp` concat.
//!
//! not here: SOCKS4A (not implemented), HTTP CONNECT
//! (daemon's `send_proxyrequest`), `PROXY_EXEC` (I/O).

#![forbid(unsafe_code)]

use std::net::SocketAddr;

// SOCKS4 wire constants.
const SOCKS4_VERSION: u8 = 4;
const SOCKS4_CMD_CONN: u8 = 1;
const SOCKS4_REPLY_VERSION: u8 = 0;
const SOCKS4_STATUS_OK: u8 = 0x5A;
/// SOCKS4 response: ver+status+port+ip.
const SOCKS4_RESPONSE_LEN: usize = 8;

// SOCKS5 wire constants.
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
const SOCKS5_ATYP_DOMAIN: u8 = 3;
const SOCKS5_ATYP_IPV6: u8 = 4;

// `proxy.h` struct sizes. We use byte offsets, not #[repr(C)].
const SOCKS5_SERVER_CHOICE_LEN: usize = 2; // socks5_server_choice_t
const SOCKS5_AUTH_STATUS_LEN: usize = 2; // socks5_auth_status_t
const SOCKS5_CONN_RESP_LEN: usize = 4; // socks5_conn_resp_t (header only)
const SOCKS5_IPV4_LEN: usize = 6; // socks5_ipv4_t (4 + 2)
const SOCKS5_IPV6_LEN: usize = 18; // socks5_ipv6_t (16 + 2)

/// Proxy type.
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

/// `create_socks_req`.
///
/// # Errors
/// - `Socks4Ipv6`: SOCKS4 has no v6 addressing.
/// - `CredTooLong`: STRICTER than upstream, which truncates `size_t`
///   userlen to u8; a 256B username would send `[00]` and the proxy
///   would read 0 bytes. RFC 1929 says 1..255.
pub(crate) fn build_request(
    proxy: ProxyType,
    target: SocketAddr,
    creds: Option<&Creds>,
) -> Result<Vec<u8>, BuildError> {
    match proxy {
        ProxyType::Socks4 => build_socks4(target, creds),
        ProxyType::Socks5 => build_socks5(target, creds),
    }
}

fn build_socks4(target: SocketAddr, creds: Option<&Creds>) -> Result<Vec<u8>, BuildError> {
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

    Ok(buf)
}

fn build_socks5(target: SocketAddr, creds: Option<&Creds>) -> Result<Vec<u8>, BuildError> {
    // password auth needs both user and pass
    let password_auth = creds.and_then(|c| c.pass.as_ref().map(|p| (c.user.as_str(), p.as_str())));

    // STRICTER: upstream narrows size_t→u8; we check (RFC 1929).
    let password_auth = match password_auth {
        Some((user, pass)) => match (u8::try_from(user.len()), u8::try_from(pass.len())) {
            (Ok(ulen), Ok(plen)) => Some((user, ulen, pass, plen)),
            _ => return Err(BuildError::CredTooLong),
        },
        None => None,
    };

    let mut buf = Vec::new();

    // Greet. :183: nmethods=1 — server's choice is predictable.
    // (our method or 0xFF). "Offered password, server chose anon"
    // doesn't arise for tinc's shape.
    buf.push(SOCKS5_VERSION);
    buf.push(1); // nmethods
    buf.push(if password_auth.is_some() {
        SOCKS5_AUTH_METHOD_PASSWORD
    } else {
        SOCKS5_AUTH_METHOD_NONE
    });

    // Auth (RFC 1929, :192-213): [01][userlen][user][passlen][pass].
    if let Some((user, ulen, pass, plen)) = password_auth {
        buf.push(SOCKS5_AUTH_VERSION);
        buf.push(ulen);
        buf.extend_from_slice(user.as_bytes());
        buf.push(plen);
        buf.extend_from_slice(pass.as_bytes());
    }

    // Connect.
    buf.push(SOCKS5_VERSION);
    buf.push(SOCKS5_COMMAND_CONN);
    buf.push(0); // reserved

    match target {
        SocketAddr::V4(v4) => {
            buf.push(SOCKS5_ATYP_IPV4); // :225-228
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(SOCKS5_ATYP_IPV6); // :230-233
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    Ok(buf)
}

/// Which proxy reply precedes the peer's ID line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyWait {
    Socks(ProxyType),
    Http,
}

/// Proxy reply parse result over the bytes received so far.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Incomplete,
    /// Tunnel open. The reply was this many bytes, the rest is the peer's.
    Granted(usize),
    Rejected(String),
    Malformed(&'static str),
}

/// The proxy's reply to our request. Sized by what the reply says, not
/// by what we asked for: a SOCKS5 proxy picks its own `BND.ADDR` type.
#[must_use]
pub(crate) fn parse_reply(wait: ProxyWait, buf: &[u8]) -> Reply {
    match wait {
        ProxyWait::Socks(ProxyType::Socks4) => parse_socks4(buf),
        ProxyWait::Socks(ProxyType::Socks5) => parse_socks5(buf),
        ProxyWait::Http => parse_http(buf),
    }
}

fn parse_socks4(buf: &[u8]) -> Reply {
    let Some(&[ver, status, _, _, _, _, _, _]) = buf.get(..SOCKS4_RESPONSE_LEN) else {
        return Reply::Incomplete;
    };
    if ver != SOCKS4_REPLY_VERSION {
        return Reply::Malformed("Bad response from SOCKS4 proxy");
    }
    if status == SOCKS4_STATUS_OK {
        Reply::Granted(SOCKS4_RESPONSE_LEN)
    } else {
        Reply::Rejected(format!("status {status:#x}"))
    }
}

fn parse_socks5(buf: &[u8]) -> Reply {
    let Some(&[ver, method]) = buf.get(..SOCKS5_SERVER_CHOICE_LEN) else {
        return Reply::Incomplete;
    };
    if ver != SOCKS5_VERSION {
        return Reply::Malformed("Invalid response from proxy server");
    }
    let conn_at = match method {
        SOCKS5_AUTH_METHOD_NONE => SOCKS5_SERVER_CHOICE_LEN,
        SOCKS5_AUTH_METHOD_PASSWORD => {
            let end = SOCKS5_SERVER_CHOICE_LEN + SOCKS5_AUTH_STATUS_LEN;
            let Some(&[auth_ver, status]) = buf.get(SOCKS5_SERVER_CHOICE_LEN..end) else {
                return Reply::Incomplete;
            };
            if auth_ver != SOCKS5_AUTH_VERSION {
                return Reply::Malformed("Invalid proxy authentication protocol version");
            }
            if status != SOCKS5_AUTH_OK {
                return Reply::Rejected("authentication failed".into());
            }
            end
        }
        SOCKS5_AUTH_FAILED => return Reply::Rejected("no acceptable auth method".into()),
        _ => return Reply::Malformed("Unsupported authentication method"),
    };
    let Some(&[ver, status, _, atyp]) = buf.get(conn_at..conn_at + SOCKS5_CONN_RESP_LEN) else {
        return Reply::Incomplete;
    };
    if ver != SOCKS5_VERSION {
        return Reply::Malformed("Invalid response from proxy server");
    }
    let addr_at = conn_at + SOCKS5_CONN_RESP_LEN;
    let addrlen = match atyp {
        SOCKS5_ATYP_IPV4 => SOCKS5_IPV4_LEN,
        SOCKS5_ATYP_IPV6 => SOCKS5_IPV6_LEN,
        SOCKS5_ATYP_DOMAIN => match buf.get(addr_at) {
            Some(&n) => 1 + usize::from(n) + 2,
            None => return Reply::Incomplete,
        },
        _ => return Reply::Malformed("Unsupported address type from proxy server"),
    };
    let end = addr_at + addrlen;
    if buf.len() < end {
        Reply::Incomplete
    } else if status == SOCKS5_STATUS_OK {
        Reply::Granted(end)
    } else {
        Reply::Rejected(format!("status {status:#x}"))
    }
}

/// `HTTP/1.x 2xx`, then headers up to the blank line.
fn parse_http(buf: &[u8]) -> Reply {
    let mut lines = buf.split_inclusive(|&b| b == b'\n');
    let Some(status) = lines.next().filter(|l| l.ends_with(b"\n")) else {
        return Reply::Incomplete;
    };
    let code = status
        .strip_prefix(b"HTTP/1.")
        .and_then(|r| r.get(1..))
        .and_then(|r| r.strip_prefix(b" "))
        .and_then(|r| r.get(..3));
    let Some(code) = code else {
        return Reply::Malformed("Bad response from HTTP proxy");
    };
    if !code.starts_with(b"2") {
        let line = String::from_utf8_lossy(status);
        return Reply::Rejected(line.trim_end().to_owned());
    }
    let mut end = status.len();
    for line in lines {
        if !line.ends_with(b"\n") {
            break;
        }
        end += line.len();
        if line == b"\n" || line == b"\r\n" {
            return Reply::Granted(end);
        }
    }
    Reply::Incomplete
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// SOCKS4 + IPv6.
    Socks4Ipv6,
    /// Credential string > 255 bytes. STRICTER than upstream.
    CredTooLong,
}

#[cfg(test)]
mod tests {
    use super::Reply::{Granted, Incomplete, Malformed};
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    // SOCKS4 build.

    #[test]
    fn socks4_v4_anonymous() {
        let req = build_request(ProxyType::Socks4, v4(127, 0, 0, 1, 655), None).unwrap();
        // [04][01][02 8f][7f 00 00 01][00]. 02 8f = 655 BE.
        assert_eq!(
            req,
            vec![0x04, 0x01, 0x02, 0x8f, 0x7f, 0x00, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn socks4_v4_with_user() {
        let creds = Creds {
            user: "alice".into(),
            pass: None,
        };
        let req = build_request(ProxyType::Socks4, v4(127, 0, 0, 1, 655), Some(&creds)).unwrap();
        assert_eq!(
            req,
            vec![
                0x04, 0x01, 0x02, 0x8f, 0x7f, 0x00, 0x00, 0x01, b'a', b'l', b'i', b'c', b'e', 0x00
            ]
        );
    }

    #[test]
    fn socks4_v6_rejected() {
        let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 655, 0, 0));
        let err = build_request(ProxyType::Socks4, target, None).unwrap_err();
        assert_eq!(err, BuildError::Socks4Ipv6);
    }

    // SOCKS5 build.

    #[test]
    fn socks5_v4_anonymous() {
        let req = build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), None).unwrap();
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
    }

    #[test]
    fn socks5_v4_password() {
        let creds = Creds {
            user: "bob".into(),
            pass: Some("hunter2".into()),
        };
        let req = build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), Some(&creds)).unwrap();
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
    }

    #[test]
    fn socks5_user_without_pass_is_anonymous() {
        // both must be set.
        let creds = Creds {
            user: "bob".into(),
            pass: None,
        };
        let req = build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), Some(&creds)).unwrap();
        assert_eq!(req[2], 0x00); // anon method, no auth block
        assert_eq!(req.len(), 13); // same as anonymous
    }

    #[test]
    fn socks5_v6() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let target = SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 0));
        let req = build_request(ProxyType::Socks5, target, None).unwrap();

        let mut expect = vec![
            0x05, 0x01, 0x00, // greet
            0x05, 0x01, 0x00, 0x04, // conn hdr: atyp=ipv6
        ];
        expect.extend_from_slice(&ip.octets());
        expect.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(req, expect);
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

    fn rejected(s: &str) -> Reply {
        Reply::Rejected(s.into())
    }

    #[test]
    fn parse_reply_table() {
        let s4 = ProxyWait::Socks(ProxyType::Socks4);
        let s5 = ProxyWait::Socks(ProxyType::Socks5);
        let http = ProxyWait::Http;
        let mut v6 = vec![0x05, 0x00, 0x05, 0x00, 0x00, 0x04];
        v6.extend_from_slice(&[0; 18]);
        #[rustfmt::skip]
        let cases: Vec<(&str, ProxyWait, &[u8], Reply)> = vec![
            ("s4 granted",        s4, &[0x00, 0x5a, 0, 0, 0, 0, 0, 0, b'0'], Granted(8)),
            ("s4 rejected",       s4, &[0x00, 0x5b, 0, 0, 0, 0, 0, 0], rejected("status 0x5b")),
            ("s4 wrong version",  s4, &[0x01, 0x5a, 0, 0, 0, 0, 0, 0], Malformed("Bad response from SOCKS4 proxy")),
            ("s4 short",          s4, &[0x00, 0x5a, 0, 0], Incomplete),
            ("s5 anon v4",        s5, &[5, 0, 5, 0, 0, 1, 0,0,0,0,0,0, b'0'], Granted(12)),
            ("s5 password",       s5, &[5, 2, 1, 0, 5, 0, 0, 1, 0,0,0,0,0,0], Granted(14)),
            ("s5 v6 bound addr",  s5, &v6, Granted(24)),
            ("s5 domain bound",   s5, &[5, 0, 5, 0, 0, 3, 2, b'a', b'b', 0, 0], Granted(11)),
            ("s5 v4 partial",     s5, &[5, 0, 5, 0, 0, 1, 0, 0], Incomplete),
            ("s5 auth rejected",  s5, &[5, 2, 1, 1], rejected("authentication failed")),
            ("s5 method 0xff",    s5, &[5, 0xff], rejected("no acceptable auth method")),
            ("s5 conn rejected",  s5, &[5, 0, 5, 1, 0, 1, 0,0,0,0,0,0], rejected("status 0x1")),
            ("s5 wrong version",  s5, &[4, 0], Malformed("Invalid response from proxy server")),
            ("s5 auth version",   s5, &[5, 2, 2, 0], Malformed("Invalid proxy authentication protocol version")),
            ("s5 bad atyp",       s5, &[5, 0, 5, 0, 0, 9], Malformed("Unsupported address type from proxy server")),
            ("s5 unknown method", s5, &[5, 3], Malformed("Unsupported authentication method")),
            ("http 1.1",          http, b"HTTP/1.1 200 OK\r\n\r\n0 bob", Granted(19)),
            ("http 1.0 headers",  http, b"HTTP/1.0 200 OK\r\nProxy-agent: x\r\n\r\n", Granted(35)),
            ("http partial",      http, b"HTTP/1.1 200 OK\r\nVia: x\r\n", Incomplete),
            ("http rejected",     http, b"HTTP/1.1 403 Forbidden\r\n", rejected("HTTP/1.1 403 Forbidden")),
            ("http garbage",      http, b"0 bob 17.7\n", Malformed("Bad response from HTTP proxy")),
        ];
        for (label, wait, buf, want) in cases {
            assert_eq!(parse_reply(wait, buf), want, "{label}");
        }
    }
}
