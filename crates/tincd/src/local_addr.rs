//! `choose_local_address` + `adapt_socket`: LAN-direct UDP address
//! selection.
//!
//! `ADD_EDGE` carries two addresses: the WAN-visible one (`e->address`, what
//! the peer's `accept()` saw) and the local one (`e->local_address`,
//! what `getsockname()` on the connecting end returned — see
//! `daemon/connect.rs:192-210`). For two nodes behind the same
//! NAT, WAN round-trips the gateway; LAN goes direct.
//!
//! `try_udp` sets `n->status.send_locally`, sends a probe via
//! `choose_local_address`, then clears the flag. If the probe ACKs, the
//! recorded UDP address is the LAN one. Next packets go direct.
//!
//! ## What's here
//!
//! Three pure pieces. The daemon supplies the candidate list (it knows which
//! `EdgeId`s have `from == target`; we don't take `&Graph`).
//!
//! - [`adapt_socket`]: family-match scan over listeners
//! - [`choose_local`]: random pick from candidates
//! - [`parse_addr_port`] / [`format_addr_port`]: the `protocol_key.c`
//!   reflexive-address wire shape
//!
//! ## What's not here
//!
//! `n->status.send_locally` flag — daemon's `TunnelState`. The `try_udp` probe
//! loop — `daemon/tx_control.rs`. Reflexive `ANS_KEY` append/consume —
//! `daemon/gossip.rs` `on_ans_key`.
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

use crate::listen;
use rand_core::Rng;

/// If `listener_addrs[current]` already matches `target`'s family return
/// `current`; else the first matching index; else `current` unchanged (the
/// later `sendto` fails EAFNOSUPPORT and is logged). Takes `&[SocketAddr]`
/// since only the family matters; the daemon maps its ≤8 listeners per call.
#[must_use]
pub(crate) fn adapt_socket(target: &SocketAddr, current: u8, listener_addrs: &[SocketAddr]) -> u8 {
    // `is_ipv4()` is the family check; SocketAddr has no direct family().
    let want_v4 = target.is_ipv4();

    // Early-exit if current already matches. Guard against an
    // out-of-range index (shouldn't happen; we return unchanged and
    // let sendto fail).
    if listener_addrs
        .get(current as usize)
        .is_some_and(|a| a.is_ipv4() == want_v4)
    {
        return current;
    }

    // Linear scan, first match wins. ≤8 listeners (MAXSOCKETS=8) so
    // u8 always fits.
    listener_addrs
        .iter()
        .position(|a| a.is_ipv4() == want_v4)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(current) // no match: leave as-is
}

/// Pick a random `local_address` among `candidates` (the daemon pre-filters
/// edges with `from == n` and parses their local addr/port), then adjust the
/// socket index by family via `listener_addrs`. Returns `(addr, sock_index)`,
/// `None` if there are no candidates. `next_u32() % len` has the same modulo
/// bias as C's `prng()`; tests pass a seeded RNG.
#[must_use]
pub(crate) fn choose_local<R: Rng>(
    candidates: &[SocketAddr],
    rng: &mut R,
    listener_addrs: &[SocketAddr],
) -> Option<(SocketAddr, u8)> {
    // The family check is folded into the daemon's
    // `filter_map(parse_addr_port)` above (UNSPEC → None), so empty
    // slice covers both "no edges" and "no
    // edge has a local address".
    if candidates.is_empty() {
        return None;
    }

    let j = (rng.next_u32() as usize) % candidates.len();
    let sa = candidates[j];

    // Random initial sock. Guard div-by-zero; a daemon with no
    // listeners has bigger problems but adapt_socket handles it
    // gracefully (returns 0 unchanged).
    let n_listen = u32::try_from(listener_addrs.len()).unwrap_or(u32::MAX);
    let sock = if n_listen == 0 {
        0
    } else {
        // ≤8 listeners (`net.h` MAXSOCKETS=8); fits u8.
        u8::try_from(rng.next_u32() % n_listen).unwrap_or(0)
    };

    Some((sa, adapt_socket(&sa, sock, listener_addrs)))
}

/// Parse the reflexive-address fields: `unspec` or anything unparseable →
/// `None` (C would build `AF_UNKNOWN` and never connect). Brackets around v6
/// are stripped defensively though `sockaddr2str` never emits them.
#[must_use]
pub(crate) fn parse_addr_port(addr: &str, port: &str) -> Option<SocketAddr> {
    if addr == tinc_proto::AddrStr::UNSPEC {
        return None;
    }
    // Strip optional `[...]` bracketing for v6.
    let addr = addr
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(addr);
    let port: u16 = port.parse().ok()?;
    let ip: IpAddr = addr.parse().ok()?;
    // Unmap ::ffff:a.b.c.d → v4 so adapt_socket picks the v4 listener (v6 is V6ONLY).
    Some(listen::unmap(SocketAddr::new(ip, port)))
}

/// `sockaddr2str` shape for the `ANS_KEY` append. Dotted-quad / RFC-5952 v6.
/// `IpAddr::Display` matches.
#[must_use]
pub(crate) fn format_addr_port(sa: &SocketAddr) -> (String, String) {
    (sa.ip().to_string(), sa.port().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use tinc_proto::msg::AnsKey;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // --- adapt_socket --------------------------------------------------

    #[test]
    fn adapt_same_family_noop() {
        let listeners = [v4("0.0.0.0:655"), v6("[::]:655")];
        assert_eq!(adapt_socket(&v4("192.168.1.5:655"), 0, &listeners), 0);
    }

    #[test]
    fn adapt_finds_match() {
        let listeners = [v4("0.0.0.0:655"), v6("[::]:655")];
        // current=0 is v4, target is v6 → scan finds index 1.
        assert_eq!(adapt_socket(&v6("[fe80::1]:655"), 0, &listeners), 1);
    }

    #[test]
    fn adapt_no_match_returns_current() {
        let listeners = [v4("0.0.0.0:655"), v4("10.0.0.1:656")];
        // v6 target, all-v4 listeners → C falls out of loop, *sock untouched.
        assert_eq!(adapt_socket(&v6("[::1]:655"), 1, &listeners), 1);
    }

    // --- choose_local --------------------------------------------------

    #[test]
    fn choose_empty_returns_none() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert_eq!(choose_local(&[], &mut rng, &[v4("0.0.0.0:655")]), None);
    }

    #[test]
    fn choose_single_returns_it() {
        let cand = v4("192.168.1.42:655");
        let listeners = [v4("0.0.0.0:655")];
        // Any seed: only one candidate.
        for seed in 0..16 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let (got, sock) = choose_local(&[cand], &mut rng, &listeners).unwrap();
            assert_eq!(got, cand);
            assert_eq!(sock, 0);
        }
    }

    #[test]
    fn choose_distribution() {
        let cands = [
            v4("10.0.0.1:655"),
            v4("10.0.0.2:655"),
            v4("10.0.0.3:655"),
            v4("10.0.0.4:655"),
        ];
        let listeners = [v4("0.0.0.0:655")];
        let mut rng = ChaCha8Rng::seed_from_u64(0x00C0_FFEE);
        let mut counts = [0usize; 4];
        for _ in 0..4000 {
            let (got, _) = choose_local(&cands, &mut rng, &listeners).unwrap();
            let idx = cands.iter().position(|c| *c == got).unwrap();
            counts[idx] += 1;
        }
        // ~1000 each; loose bound (this is gen_range, not crypto).
        for c in counts {
            assert!((800..=1200).contains(&c), "skewed: {counts:?}");
        }
    }

    /// Candidate is v6, listeners are `[v4, v6]`. Force the initial sock
    /// pick to land on the v4 listener; `adapt_socket` should bump it to 1.
    #[test]
    fn choose_adapts_socket() {
        // ZeroRng: always returns 0 → picks candidates[0], picks sock=0.
        struct ZeroRng;
        impl rand_core::TryRng for ZeroRng {
            type Error = rand_core::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                dest.fill(0);
                Ok(())
            }
        }

        let cands = [v6("[fe80::1]:655")];
        let listeners = [v4("0.0.0.0:655"), v6("[::]:655")];
        let (got, sock) = choose_local(&cands, &mut ZeroRng, &listeners).unwrap();
        assert_eq!(got, cands[0]);
        // Initial pick was 0 (v4); adapted to 1 (v6).
        assert_eq!(sock, 1);
    }

    // --- parse / format ------------------------------------------------

    #[test]
    fn parse_roundtrip_v4() {
        let sa = v4("127.0.0.1:655");
        let (a, p) = format_addr_port(&sa);
        assert_eq!(a, "127.0.0.1");
        assert_eq!(p, "655");
        assert_eq!(parse_addr_port(&a, &p), Some(sa));
    }

    #[test]
    fn parse_roundtrip_v6() {
        let sa = v6("[::1]:655");
        let (a, p) = format_addr_port(&sa);
        // format gives "::1" not "[::1]" — sockaddr2str doesn't bracket.
        assert_eq!(a, "::1");
        assert_eq!(p, "655");
        assert_eq!(parse_addr_port(&a, &p), Some(sa));
        // parse handles brackets defensively too.
        assert_eq!(parse_addr_port("[::1]", "655"), Some(sa));
    }

    #[test]
    fn parse_v4_mapped_unmaps_to_native_v4() {
        let got = parse_addr_port("::ffff:10.0.0.5", "655").unwrap();
        assert_eq!(got, v4("10.0.0.5:655"));
        assert!(got.is_ipv4());
        let got = parse_addr_port("[::ffff:10.0.0.5]", "655").unwrap();
        assert_eq!(got, v4("10.0.0.5:655"));
    }

    #[test]
    fn parse_unspec_is_none() {
        assert_eq!(parse_addr_port("unspec", "655"), None);
        assert_eq!(parse_addr_port(tinc_proto::AddrStr::UNSPEC, "0"), None);
    }

    #[test]
    fn parse_garbage_is_none() {
        assert_eq!(parse_addr_port("not-an-ip", "655"), None);
        assert_eq!(parse_addr_port("127.0.0.1", "not-a-port"), None);
    }

    /// The reflexive append/consume roundtrip THROUGH the `AnsKey`
    /// wire format. Relay does `format_addr_port` → `"%s %s %s"`
    /// concat (`gossip.rs` `on_ans_key`); destination does
    /// `AnsKey::parse` → `parse_addr_port`. Proves the wire shape
    /// is right for both v4 and v6.
    #[test]
    fn ans_key_reflexive_roundtrip() {
        // Base ANS_KEY (7-field, no addr).
        let base = "16 alice bob aGVsbG8 0 0 0 0";
        for sa in [v4("192.168.1.42:655"), v6("[fe80::1]:12345")] {
            // Relay-side: format + raw concat (`"%s %s %s"`).
            let (a, p) = format_addr_port(&sa);
            let appended = format!("{base} {a} {p}");
            // Destination-side: parse + extract.
            let msg = AnsKey::parse(&appended).expect("parse appended");
            let (a_s, p_s) = msg.udp_addr.as_ref().expect("udp_addr present");
            let got = parse_addr_port(a_s.as_str(), p_s.as_str());
            assert_eq!(got, Some(sa), "roundtrip for {sa}");
            // And re-format is byte-exact (idempotent relay).
            assert_eq!(msg.format(), appended);
        }
    }
}
