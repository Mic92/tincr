//! SOCKS4/SOCKS5 proxy request building and response parsing.
//!
//! `proxy.c` (285 LOC). Pure byte format — `SocketAddr` in,
//! `Vec<u8>` out. The daemon (`outgoing.rs`, `meta.c:283`) is the I/O
//! shell.
//!
//! ## SOCKS4 (no RFC; <https://www.openssh.com/txt/socks4.protocol>)
//!
//! Request:  `[04][01][port:2be][ip:4][userid:\0]`
//! Response: `[00][status][port:2][ip:4]` (8 bytes, `status==0x5A` is granted)
//!
//! IPv4 only. IPv6 → error (`proxy.c:157-160`).
//!
//! ## SOCKS5 (RFC 1928)
//!
//! Three round-trips collapsed into one request blob (`proxy.c:175-237`).
//! The proxy server reads them sequentially, but we send them all at once
//! because TCP is a stream and the proxy will buffer:
//!
//! 1. Greet:   `[05][01][method]`  (method = 00 anon, 02 password)
//! 2. Auth (if password): `[01][userlen][user][passlen][pass]`
//! 3. Connect: `[05][01][00][atyp][addr][port:2be]`
//!    (atyp = 01 ipv4, 04 ipv6)
//!
//! Response is also a concat:
//!   `[05][method]` (server choice, 2 bytes)
//!   + `[01][00]` (auth status, 2 bytes, only if password)
//!   + `[05][status][00][atyp][addr][port]` (4 + 6 or 4 + 18 bytes)
//!
//! `status==0x00` is granted.
//!
//! ## NOT here
//!
//! - SOCKS4A (`PROXY_SOCKS4A`): `proxy.c:80` — "Proxy type not
//!   implemented yet". Faithfully unimplemented.
//! - HTTP CONNECT (`PROXY_HTTP`): one `format!()` line, lives in
//!   the daemon's `send_proxyrequest` arm. `protocol_auth.c:60-68`.
//! - `PROXY_EXEC`: socketpair+fork. I/O, not byte format.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

// ── SOCKS4 wire constants (proxy.c:13-16) ──────────────────────────
const SOCKS4_VERSION: u8 = 4;
const SOCKS4_CMD_CONN: u8 = 1;
const SOCKS4_REPLY_VERSION: u8 = 0;
const SOCKS4_STATUS_OK: u8 = 0x5A;
/// `sizeof(socks4_response_t)` (`proxy.h:18-23`): ver+status+port+ip.
const SOCKS4_RESPONSE_LEN: usize = 8;

// ── SOCKS5 wire constants (proxy.c:18-30) ──────────────────────────
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

// `proxy.h` struct sizes — we use byte offsets, not `#[repr(C)]`,
// because we don't have a `sockaddr_t` to memcpy into; we have
// `std::net::SocketAddr`. The wire is just bytes.
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

/// Proxy credentials. `proxyuser`/`proxypass` globals in C.
/// SOCKS4 uses only `user` (as the userid string).
/// SOCKS5 uses both for `AUTH_PASSWORD`; if `pass` is `None`,
/// anonymous auth is used (matches `proxy.c:192`: `proxyuser && proxypass`).
#[derive(Debug, Clone)]
pub struct Creds {
    pub user: String,
    /// SOCKS5 only. `None` → anonymous auth.
    pub pass: Option<String>,
}

/// `create_socks_req` (`proxy.c:278-285`). Returns
/// `(request_bytes, expected_response_len)`.
///
/// The C returns `expected_response_len` as the function return value
/// AND writes request to a caller-allocated buffer (via `socks_req_len`
/// for sizing). We return both. The daemon will queue `request_bytes`
/// and read `expected_response_len` before calling [`check_response`].
///
/// # Errors
/// - [`BuildError::Socks4Ipv6`]: `Socks4` + IPv6 addr (`proxy.c:157`).
/// - [`BuildError::CredTooLong`]: SOCKS5 user/pass > 255 bytes
///   (RFC 1929 single-byte length). The C doesn't check this —
///   `*auth++ = userlen` truncates the `size_t` to `u8` implicitly.
///   **C-is-WRONG #9**: a 256-byte username sends `[00][...]` and the
///   proxy reads 0 bytes of username. We error instead. STRICTER.
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

/// `create_socks4_req` (`proxy.c:156-172`).
///
/// Wire: `[04][01][port:2be][ip:4][userid][00]`.
fn build_socks4(target: SocketAddr, creds: Option<&Creds>) -> Result<(Vec<u8>, usize), BuildError> {
    // proxy.c:157-160: SOCKS4 is IPv4-only.
    let SocketAddr::V4(v4) = target else {
        return Err(BuildError::Socks4Ipv6);
    };

    let user = creds.map_or("", |c| c.user.as_str());
    let mut buf = Vec::with_capacity(8 + user.len() + 1);

    buf.push(SOCKS4_VERSION);
    buf.push(SOCKS4_CMD_CONN);
    // proxy.c:163: req->dstport = sa->in.sin_port. sin_port is ALREADY
    // network order; SocketAddr::port() is HOST order. We convert.
    // Same wire bytes.
    buf.extend_from_slice(&v4.port().to_be_bytes());
    // proxy.c:164: req->dstip = sa->in.sin_addr. .octets() is in-order
    // (192.168.1.1 → [192,168,1,1]), same as in_addr's wire layout.
    buf.extend_from_slice(&v4.ip().octets());
    // proxy.c:167-170: strcpy(req->id, proxyuser) or id[0]='\0'.
    // Either way: NUL-terminated.
    buf.extend_from_slice(user.as_bytes());
    buf.push(0);

    // proxy.c:172: return sizeof(socks4_response_t).
    Ok((buf, SOCKS4_RESPONSE_LEN))
}

/// `create_socks5_req` (`proxy.c:175-237`).
///
/// Builds greet + (optional auth) + connect as one blob. Tracks
/// `resplen` exactly as the C does, accumulating struct sizes.
fn build_socks5(target: SocketAddr, creds: Option<&Creds>) -> Result<(Vec<u8>, usize), BuildError> {
    // proxy.c:192: only do password auth if BOTH user and pass are set.
    // Otherwise anonymous. (creds with user but no pass → anonymous.)
    let password_auth = creds.and_then(|c| c.pass.as_ref().map(|p| (c.user.as_str(), p.as_str())));

    // C-is-WRONG #9: proxy.c:201,206 do `*auth++ = userlen` where
    // userlen is size_t. Implicit narrowing to u8. A 256-byte username
    // becomes a length byte of 0x00 and the proxy reads 0 bytes —
    // garbage follows. RFC 1929 says 1..255. We check.
    if let Some((user, pass)) = password_auth
        && (user.len() > 255 || pass.len() > 255)
    {
        return Err(BuildError::CredTooLong);
    }

    let mut buf = Vec::new();
    // proxy.c:188: resplen = sizeof(socks5_server_choice_t).
    let mut resplen = SOCKS5_SERVER_CHOICE_LEN;

    // ── Greet (socks5_greet_t, 3 bytes) ────────────────────────────
    // proxy.c:183: req->nmethods = 1. We always offer EXACTLY ONE
    // method. So the server's choice is predictable from
    // `password_auth.is_some()`: it's our method or 0xFF, never the
    // other one. check_response() still parses the choice byte (the C
    // does), but the "offered password, server chose anon" case
    // doesn't arise for tinc's request shape.
    buf.push(SOCKS5_VERSION);
    buf.push(1); // nmethods
    buf.push(if password_auth.is_some() {
        SOCKS5_AUTH_METHOD_PASSWORD
    } else {
        SOCKS5_AUTH_METHOD_NONE
    });

    // ── Auth (RFC 1929, only if password) ──────────────────────────
    // proxy.c:192-213.
    // Wire: [01][userlen][user][passlen][pass]
    if let Some((user, pass)) = password_auth {
        buf.push(SOCKS5_AUTH_VERSION);
        // Checked ≤255 above.
        #[allow(clippy::cast_possible_truncation)]
        {
            buf.push(user.len() as u8);
            buf.extend_from_slice(user.as_bytes());
            buf.push(pass.len() as u8);
            buf.extend_from_slice(pass.as_bytes());
        }
        // proxy.c:213: resplen += sizeof(socks5_auth_status_t).
        resplen += SOCKS5_AUTH_STATUS_LEN;
    }

    // ── Connect (socks5_conn_hdr_t + addr) ─────────────────────────
    // proxy.c:217-220.
    buf.push(SOCKS5_VERSION);
    buf.push(SOCKS5_COMMAND_CONN);
    buf.push(0); // reserved
    // proxy.c:222: resplen += sizeof(socks5_conn_resp_t).
    resplen += SOCKS5_CONN_RESP_LEN;

    match target {
        SocketAddr::V4(v4) => {
            // proxy.c:225-228.
            buf.push(SOCKS5_ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
            resplen += SOCKS5_IPV4_LEN;
        }
        SocketAddr::V6(v6) => {
            // proxy.c:230-233.
            buf.push(SOCKS5_ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
            resplen += SOCKS5_IPV6_LEN;
        }
    }

    Ok((buf, resplen))
}

/// Response from a SOCKS proxy. `check_socks_resp` (`proxy.c:145-152`).
#[derive(Debug, PartialEq, Eq)]
pub enum SocksResponse {
    /// `0x5A` (SOCKS4) or `0x00` (SOCKS5). Tunnel open.
    Granted,
    /// Rejected. Codes are protocol-specific; we don't decode them
    /// (the C doesn't either — `log_proxy_grant(false)`).
    Rejected,
    /// Wrong version byte / wrong auth-version / etc. The proxy is
    /// speaking a different protocol or is misconfigured.
    Malformed(&'static str),
}

/// `check_socks_resp` (`proxy.c:145-152`). The slice length is exactly
/// `expected_response_len` from [`build_request`] — daemon reads that
/// many bytes before calling here.
///
/// `creds` is taken for API symmetry with `build_request` but is NOT
/// consulted: `check_socks5_resp` (`proxy.c:92-144`) dispatches on the
/// SERVER'S CHOICE BYTE, not on what we sent. Since we always offer
/// exactly one method, the server's choice tells us the response shape.
#[must_use]
pub fn check_response(proxy: ProxyType, _creds: Option<&Creds>, buf: &[u8]) -> SocksResponse {
    match proxy {
        ProxyType::Socks4 => check_socks4(buf),
        ProxyType::Socks5 => check_socks5(buf),
    }
}

/// `check_socks4_resp` (`proxy.c:45-58`).
///
/// Wire: `[ver][status][port:2][ip:4]` = 8 bytes.
fn check_socks4(buf: &[u8]) -> SocksResponse {
    // proxy.c:46-49.
    if buf.len() < SOCKS4_RESPONSE_LEN {
        return SocksResponse::Malformed("Received short response from proxy");
    }
    // proxy.c:51-54.
    if buf[0] != SOCKS4_REPLY_VERSION {
        return SocksResponse::Malformed("Bad response from SOCKS4 proxy");
    }
    // proxy.c:56-58. Port/ip in buf[2..8] are ignored — proxy can put
    // whatever there; we don't care, the tunnel is open.
    if buf[1] == SOCKS4_STATUS_OK {
        SocksResponse::Granted
    } else {
        SocksResponse::Rejected
    }
}

/// `check_socks5_resp` (`proxy.c:92-144`).
///
/// Wire layout depends on server's auth choice:
/// - anon:     `[choice:2][conn_resp:4][addr:6|18]`
/// - password: `[choice:2][auth_status:2][conn_resp:4][addr:6|18]`
fn check_socks5(buf: &[u8]) -> SocksResponse {
    // proxy.c:93-96.
    if buf.len() < SOCKS5_SERVER_CHOICE_LEN {
        return SocksResponse::Malformed("Received short response from proxy");
    }
    let rest = &buf[SOCKS5_SERVER_CHOICE_LEN..];

    // proxy.c:100-103: choice.socks_version.
    if buf[0] != SOCKS5_VERSION {
        return SocksResponse::Malformed("Invalid response from proxy server");
    }

    // proxy.c:105-144: dispatch on choice.auth_method (server's pick,
    // NOT what we offered — though with nmethods=1 they coincide or
    // it's 0xFF).
    match buf[1] {
        SOCKS5_AUTH_METHOD_NONE => {
            // proxy.c:106-112: anonymous, no auth-status block.
            if rest.len() < SOCKS5_CONN_RESP_LEN {
                return SocksResponse::Malformed("Received short response from proxy");
            }
            check_socks5_conn(rest)
        }
        SOCKS5_AUTH_METHOD_PASSWORD => {
            // proxy.c:114-132: auth_status_t + conn_resp_t header.
            let header_len = SOCKS5_AUTH_STATUS_LEN + SOCKS5_CONN_RESP_LEN;
            if rest.len() < header_len {
                return SocksResponse::Malformed("Received short response from proxy");
            }
            // proxy.c:122-125: status.auth_version.
            if rest[0] != SOCKS5_AUTH_VERSION {
                return SocksResponse::Malformed("Invalid proxy authentication protocol version");
            }
            // proxy.c:127-130: status.auth_status. Auth fail is a
            // VALID response — Rejected, not Malformed.
            if rest[1] != SOCKS5_AUTH_OK {
                return SocksResponse::Rejected;
            }
            check_socks5_conn(&rest[SOCKS5_AUTH_STATUS_LEN..])
        }
        SOCKS5_AUTH_FAILED => {
            // proxy.c:135-137: server liked none of our methods.
            // The C log says "rejected", so this is Rejected.
            SocksResponse::Rejected
        }
        _ => {
            // proxy.c:139-141.
            SocksResponse::Malformed("Unsupported authentication method")
        }
    }
}

/// `socks5_check_result` (`proxy.c:60-90`). Parses the connect
/// response header. Input slice starts at the `socks5_conn_resp_t`.
///
/// Wire: `[ver][status][rsvd][atyp][addr:4|16][port:2]`.
///
/// We DON'T validate the addr/port values (`proxy.c` doesn't either —
/// `addr_type` is read only to know how many bytes to skip for the
/// length check). The proxy can put whatever there.
fn check_socks5_conn(buf: &[u8]) -> SocksResponse {
    // Caller checked len >= SOCKS5_CONN_RESP_LEN.
    // buf[0..4] = [socks_version, conn_status, reserved, addr_type].
    let addr_type = buf[3];
    let addrlen = match addr_type {
        SOCKS5_ATYP_IPV4 => SOCKS5_IPV4_LEN,
        SOCKS5_ATYP_IPV6 => SOCKS5_IPV6_LEN,
        // proxy.c:73-75. Includes domain (atyp=3) — tinc never asks
        // for domain, so getting one back is bizarre.
        _ => {
            return SocksResponse::Malformed("Unsupported address type from proxy server");
        }
    };

    // proxy.c:77-80: len passed to socks5_check_result is what's
    // LEFT AFTER the conn_resp header.
    if buf.len() < SOCKS5_CONN_RESP_LEN + addrlen {
        return SocksResponse::Malformed("Received short address from proxy server");
    }

    // proxy.c:82-85.
    if buf[0] != SOCKS5_VERSION {
        return SocksResponse::Malformed("Invalid response from proxy server");
    }

    // proxy.c:87-89.
    if buf[1] == SOCKS5_STATUS_OK {
        SocksResponse::Granted
    } else {
        SocksResponse::Rejected
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    /// `proxy.c:157`: SOCKS4 + IPv6.
    Socks4Ipv6,
    /// Credential string > 255 bytes. STRICTER than C.
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
        // [04][01][02 8f][7f 00 00 01][00]
        // 02 8f = 655 BE; 7f 00 00 01 = 127.0.0.1; 00 = empty id NUL.
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
        // Same header; userid = "alice" + NUL.
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
        // greet[05 01 00] + connect[05 01 00 01 c0 a8 01 01 1f 90]
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
        // choice(2) + conn_resp(4) + ipv4(6) = 12.
        assert_eq!(resplen, 12);
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
        // choice(2) + auth_status(2) + conn_resp(4) + ipv4(6) = 14.
        assert_eq!(resplen, 14);
    }

    #[test]
    fn socks5_user_without_pass_is_anonymous() {
        // proxy.c:192: `proxyuser && proxypass` — both must be set.
        // user-only → anonymous.
        let creds = Creds {
            user: "bob".into(),
            pass: None,
        };
        let (req, resplen) =
            build_request(ProxyType::Socks5, v4(192, 168, 1, 1, 8080), Some(&creds)).unwrap();
        // Method byte is 0x00 (anon), no auth block.
        assert_eq!(req[2], 0x00);
        assert_eq!(req.len(), 13); // same as anonymous
        assert_eq!(resplen, 12);
    }

    #[test]
    fn socks5_v6() {
        // 2001:db8::1
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
        // choice(2) + conn_resp(4) + ipv6(18) = 24.
        assert_eq!(resplen, 24);
    }

    #[test]
    fn socks5_cred_too_long() {
        let creds = Creds {
            user: "x".repeat(256),
            pass: Some("y".into()),
        };
        let err = build_request(ProxyType::Socks5, v4(1, 1, 1, 1, 1), Some(&creds)).unwrap_err();
        assert_eq!(err, BuildError::CredTooLong);

        // 255 is fine (RFC 1929 max).
        let creds = Creds {
            user: "x".repeat(255),
            pass: Some("y".into()),
        };
        assert!(build_request(ProxyType::Socks5, v4(1, 1, 1, 1, 1), Some(&creds)).is_ok());

        // Password too.
        let creds = Creds {
            user: "x".into(),
            pass: Some("y".repeat(256)),
        };
        let err = build_request(ProxyType::Socks5, v4(1, 1, 1, 1, 1), Some(&creds)).unwrap_err();
        assert_eq!(err, BuildError::CredTooLong);
    }

    // ── SOCKS4 check ───────────────────────────────────────────────

    #[test]
    fn check_socks4_granted() {
        let buf = [0x00, 0x5a, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks4, None, &buf),
            SocksResponse::Granted
        );
    }

    #[test]
    fn check_socks4_rejected() {
        let buf = [0x00, 0x5b, 0, 0, 0, 0, 0, 0]; // 0x5b = rejected/failed
        assert_eq!(
            check_response(ProxyType::Socks4, None, &buf),
            SocksResponse::Rejected
        );
    }

    #[test]
    fn check_socks4_wrong_version() {
        let buf = [0x01, 0x5a, 0, 0, 0, 0, 0, 0]; // ver != 0
        assert_eq!(
            check_response(ProxyType::Socks4, None, &buf),
            SocksResponse::Malformed("Bad response from SOCKS4 proxy")
        );
    }

    #[test]
    fn check_socks4_short() {
        let buf = [0x00, 0x5a, 0, 0]; // 4 bytes, need 8
        assert_eq!(
            check_response(ProxyType::Socks4, None, &buf),
            SocksResponse::Malformed("Received short response from proxy")
        );
    }

    // ── SOCKS5 check ───────────────────────────────────────────────

    #[test]
    fn check_socks5_anon_granted() {
        // [05 00] choice + [05 00 00 01] conn ok ipv4 + [0;6] addr/port
        let buf = [0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Granted
        );
    }

    #[test]
    fn check_socks5_password_granted() {
        let creds = Creds {
            user: "x".into(),
            pass: Some("y".into()),
        };
        // [05 02] + [01 00] auth ok + [05 00 00 01] + [0;6]
        let buf = [
            0x05, 0x02, 0x01, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            check_response(ProxyType::Socks5, Some(&creds), &buf),
            SocksResponse::Granted
        );
    }

    #[test]
    fn check_socks5_auth_rejected() {
        // [05 02] server chose password; [01 01] auth FAIL.
        // Auth fail is a VALID response → Rejected, not Malformed.
        let buf = [
            0x05, 0x02, 0x01, 0x01, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Rejected
        );
    }

    #[test]
    fn check_socks5_auth_method_ff() {
        // Server rejects all our methods. Just 2 bytes of choice; the
        // daemon would have read more (resplen) but we stop at choice.
        let buf = [0x05, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Rejected
        );
    }

    #[test]
    fn check_socks5_conn_rejected() {
        // [05 00] anon + [05 01 ...] conn_status=1 (general failure).
        let buf = [0x05, 0x00, 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Rejected
        );
    }

    #[test]
    fn check_socks5_wrong_choice_version() {
        let buf = [0x04, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Malformed("Invalid response from proxy server")
        );
    }

    #[test]
    fn check_socks5_wrong_auth_version() {
        // [05 02] + [02 00] auth_version=2 (wrong) + ...
        let buf = [
            0x05, 0x02, 0x02, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Malformed("Invalid proxy authentication protocol version")
        );
    }

    #[test]
    fn check_socks5_unsupported_addr_type() {
        // [05 00] + [05 00 00 03] atyp=3 (domain) — tinc never asks
        // for domain; getting one back is bizarre.
        let buf = [0x05, 0x00, 0x05, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Malformed("Unsupported address type from proxy server")
        );
    }

    #[test]
    fn check_socks5_unknown_auth_method() {
        // [05 03] — GSSAPI or something we never offered.
        let buf = [0x05, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Malformed("Unsupported authentication method")
        );
    }

    #[test]
    fn check_socks5_v6_addr_in_response() {
        // Anon + ipv6 response addr. resplen would be 24.
        let mut buf = vec![0x05, 0x00, 0x05, 0x00, 0x00, 0x04];
        buf.extend_from_slice(&[0u8; 18]); // ipv6 addr+port (ignored)
        assert_eq!(buf.len(), 24);
        assert_eq!(
            check_response(ProxyType::Socks5, None, &buf),
            SocksResponse::Granted
        );
    }

    // ── Roundtrip: prove the resplen math ──────────────────────────

    #[test]
    fn roundtrip_socks5_v4_anon() {
        let (_req, resplen) = build_request(ProxyType::Socks5, v4(10, 0, 0, 1, 80), None).unwrap();
        // Hand-construct a granted response of EXACTLY resplen bytes.
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
