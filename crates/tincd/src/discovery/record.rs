//! Sealed-record envelope (`seal_record`/`open_record`), the BEP 44
//! signable encoding, and the inner-plaintext parser. Crypto + string
//! parsing only — no `mainline::Dht` in here.

use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand_core::{OsRng, RngCore};

use super::blind::Derived;

/// `v` envelope: 6-byte magic ‖ 24-byte `XChaCha` nonce ‖ ciphertext ‖ 16-byte
/// Poly1305 tag. Magic lets `open_record` reject garbage / future versions
/// before spending an AEAD-open.
const MAGIC: &[u8; 6] = b"tincE1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Bytes added on top of the inner `"tinc1 …"` plaintext.
pub const AEAD_OVERHEAD: usize = MAGIC.len() + NONCE_LEN + TAG_LEN;

/// Seal the inner `"tinc1 …"` plaintext for publish. Random 192-bit
/// nonce per put (`XChaCha` → birthday bound is irrelevant at one put per
/// 5 min). `aad = seq_be8`: the storer can't splice an old ciphertext
/// under a newer seq without the AEAD-open failing.
#[expect(clippy::missing_panics_doc)] // encrypt() only errs on >4GiB input
#[must_use]
pub fn seal_record(d: &Derived, seq: i64, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&d.aead_key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &seq.to_be_bytes(),
            },
        )
        .expect("XChaCha20-Poly1305 encrypt is infallible for <4GiB inputs");
    let mut out = Vec::with_capacity(AEAD_OVERHEAD + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Reverse of [`seal_record`]. `None` on wrong magic, short input, or
/// AEAD failure (wrong key / wrong seq / tampered). Caller treats all
/// three as "miss".
#[must_use]
pub fn open_record(d: &Derived, seq: i64, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < AEAD_OVERHEAD || &sealed[..MAGIC.len()] != MAGIC {
        return None;
    }
    let nonce = &sealed[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ct = &sealed[MAGIC.len() + NONCE_LEN..];
    XChaCha20Poly1305::new((&d.aead_key).into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ct,
                aad: &seq.to_be_bytes(),
            },
        )
        .ok()
}

/// BEP 44 signable encoding. Vendored — mainline's `encode_signable` is
/// `pub fn` in a non-`pub mod`. NOT a full bencode dict (no `d`/`e`
/// wrapping); just the sorted fragment DHT nodes verify against.
pub(super) fn encode_bep44_signable(seq: i64, value: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    let mut signable = Vec::new();
    if let Some(salt) = salt {
        signable.extend(format!("4:salt{}:", salt.len()).into_bytes());
        signable.extend(salt);
    }
    signable.extend(format!("3:seqi{seq}e1:v{}:", value.len()).into_bytes());
    signable.extend(value);
    signable
}

/// Parse a record value. Tolerant: unknown keys + malformed addrs
/// skipped. v6 sorted before v4 in trial order (no NAT, more likely
/// to just work).
#[must_use]
pub fn parse_record(value: &str) -> ParsedRecord {
    let mut out = ParsedRecord::default();
    let mut iter = value.split_ascii_whitespace();

    if iter.next() != Some("tinc1") {
        return out;
    }

    for field in iter {
        let Some((k, v)) = field.split_once('=') else {
            continue;
        };
        // Address-class gate: the record is peer-authored (and, on
        // the unauthenticated DHT path, attacker-authored). Never let
        // loopback / unspecified / multicast / link-local reach the
        // dial queue. RFC1918/ULA pass — see `addr` module docs.
        match k {
            "v4" => {
                if let Ok(sa) = v.parse::<SocketAddr>()
                    && !crate::addr::is_unwanted_dial_addr(&sa)
                {
                    out.direct.push(sa);
                }
            }
            "v6" => {
                // `[addr]:port` — std parser handles the brackets.
                if let Ok(sa) = v.parse::<SocketAddrV6>()
                    && !crate::addr::is_unwanted_dial_target(IpAddr::V6(*sa.ip()))
                {
                    // Prepend: v6 first in trial order.
                    out.direct.insert(0, SocketAddr::V6(sa));
                }
            }
            "tcp" | "tcp6" => {
                if let Ok(sa) = v.parse::<SocketAddr>()
                    && !crate::addr::is_unwanted_dial_addr(&sa)
                {
                    // Either AF is a router-installed accept rule ⇒
                    // best direct-dial candidate. `.tcp` keeps only
                    // the first seen (publish order is tcp, tcp6).
                    if out.tcp.is_none() {
                        out.tcp = Some(sa);
                    }
                    // Also a direct-dial candidate: outgoing meta-
                    // conns are TCP, and a portmapped address is the
                    // *most* likely to accept (no punch needed).
                    // Prepend so it's tried first.
                    out.direct.insert(0, sa);
                }
            }
            _ => {} // unknown key — skip, forward-compat
        }
    }
    out
}

/// Addresses extracted from a peer's published record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    /// Direct-dial candidates (tcp/v6 first, then v4). Feed to
    /// `addr_cache.known` alongside `ADD_EDGE`'s.
    pub direct: Vec<SocketAddr>,
    /// Router-installed TCP DNAT (UPnP/NAT-PMP). Subset of `direct`
    /// surfaced separately so callers that distinguish "dialable
    /// without punch" from "punch hint" can.
    pub tcp: Option<SocketAddr>,
}

#[cfg(test)]
mod tests {
    use super::super::blind::derive;
    use super::*;
    use tinc_crypto::sign::SigningKey;

    /// D2 regression: peer-authored record must not smuggle
    /// loopback/unspecified/link-local into the dial queue, but
    /// RFC1918 stays (flat-LAN meshes are a supported topology).
    #[test]
    fn parse_record_filters_unwanted_addr_classes() {
        let rec = parse_record(
            "tinc1 tcp=127.0.0.1:22 v4=10.0.0.1:445 v4=0.0.0.0:1 \
             v6=[::1]:80 v6=[fe80::1]:655 v6=[fd00::1]:655",
        );
        let direct: Vec<String> = rec.direct.iter().map(ToString::to_string).collect();
        // Dropped:
        for bad in ["127.0.0.1:22", "0.0.0.0:1", "[::1]:80", "[fe80::1]:655"] {
            assert!(
                !direct.iter().any(|s| s == bad),
                "{bad} leaked into .direct"
            );
        }
        assert!(rec.tcp.is_none(), "loopback tcp= must not populate .tcp");
        // Kept:
        assert!(direct.iter().any(|s| s == "10.0.0.1:445"));
        assert!(direct.iter().any(|s| s == "[fd00::1]:655"));
    }

    /// `seal_record`/`open_record` envelope properties. No DHT.
    #[test]
    fn seal_open_roundtrip() {
        let pk = *SigningKey::from_seed(&[3u8; 32]).public_key();
        let d = derive(&pk, Some(&[0x11; 32]), 5000);
        let plain = b"tinc1 v4=203.0.113.7:44132";
        let sealed = seal_record(&d, 42, plain);

        assert!(sealed.starts_with(MAGIC), "magic prefix");
        assert_eq!(
            sealed.len(),
            AEAD_OVERHEAD + plain.len(),
            "overhead is exactly 46B"
        );
        assert_eq!(open_record(&d, 42, &sealed).as_deref(), Some(&plain[..]));

        // aad=seq binds: storer can't replay old ct under bumped seq.
        assert!(open_record(&d, 43, &sealed).is_none(), "seq+1 → fail");

        // Wrong AEAD key → fail. Covers both "wrong DhtSecret" and
        // "hostile node self-signed forgery" (different pk_A): both
        // reduce to a different `derive()` output, and `open_record`
        // doesn't distinguish.
        let d_wrong = derive(&pk, Some(&[0x22; 32]), 5000);
        assert!(open_record(&d_wrong, 42, &sealed).is_none());

        // Garbage / truncated.
        assert!(open_record(&d, 42, b"tinc1 v4=1.2.3.4:5").is_none());
        assert!(open_record(&d, 42, &sealed[..AEAD_OVERHEAD - 1]).is_none());
    }

    #[test]
    fn bep44_signable_matches_mainline() {
        // Spec example from bep_0044.rst.
        let got = encode_bep44_signable(1, b"Hello World!", Some(b"foobar"));
        assert_eq!(got, b"4:salt6:foobar3:seqi1e1:v12:Hello World!");

        // No salt: just seq+v.
        let got = encode_bep44_signable(42, b"x", None);
        assert_eq!(got, b"3:seqi42e1:v1:x");
    }

    #[test]
    fn record_parse() {
        // v6 sorted before v4 (load-bearing: connect.rs trial order).
        let p = parse_record("tinc1 v4=203.0.113.7:44132 v6=[2001:db8::1]:655");
        assert_eq!(
            p.direct,
            vec![
                "[2001:db8::1]:655".parse().unwrap(),
                "203.0.113.7:44132".parse().unwrap(),
            ]
        );
        assert_eq!(p.tcp, None);
        // tcp= present: surfaces in .tcp AND first in .direct,
        // regardless of field order in the record.
        let p = parse_record("tinc1 v4=203.0.113.7:44132 tcp=203.0.113.7:655");
        assert_eq!(p.tcp, Some("203.0.113.7:655".parse().unwrap()));
        assert_eq!(
            p.direct,
            vec![
                "203.0.113.7:655".parse().unwrap(),
                "203.0.113.7:44132".parse().unwrap(),
            ]
        );
        // tcp= first, v6 second: both prepend; trial order is
        // last-prepend-wins. Just checks both land in .direct.
        let p = parse_record("tinc1 tcp=192.0.2.1:655 v6=[2001:db8::1]:655");
        assert_eq!(p.tcp, Some("192.0.2.1:655".parse().unwrap()));
        assert_eq!(p.direct.len(), 2);
        // v6 portmapped (PCP on v6 CPE): brackets parse.
        let p = parse_record("tinc1 tcp=[2001:db8::7]:655");
        assert_eq!(p.tcp, Some("[2001:db8::7]:655".parse().unwrap()));
        // tcp + tcp6 both present: both land in .direct; .tcp keeps
        // the v4 (publish order). tcp6 prepended after ⇒ first.
        let p = parse_record("tinc1 tcp=192.0.2.1:655 tcp6=[2001:db8::7]:655");
        assert_eq!(p.tcp, Some("192.0.2.1:655".parse().unwrap()));
        assert_eq!(
            p.direct,
            vec![
                "[2001:db8::7]:655".parse().unwrap(),
                "192.0.2.1:655".parse().unwrap(),
            ]
        );
        // Unknown keys + malformed values: skip, don't fail.
        let p = parse_record("tinc1 v4=garbage tcp=nope future=thing v6=[fd00::1]:655 ext=x:1");
        assert_eq!(p.direct, vec!["[fd00::1]:655".parse().unwrap()]);
        assert_eq!(p.tcp, None);
        // Wrong version.
        assert_eq!(parse_record("tinc2 v4=1.2.3.4:5"), ParsedRecord::default());
        assert_eq!(parse_record(""), ParsedRecord::default());
    }
}
