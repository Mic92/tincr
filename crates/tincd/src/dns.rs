//! DNS stub resolver: `<node>.<suffix>` → `Subnet=` IPs.
//!
//! ## Architecture: TUN intercept, not socket bind
//!
//! Tailscale's MagicDNS never binds `100.100.100.100:53`. Their
//! userspace netstack inspects every TUN-ingress packet and matches
//! `dst == serviceIP && dport == 53` (`wgengine/netstack/netstack.go:
//! 847-858`); the DNS query bytes are handed to an in-process
//! resolver, the reply is injected straight back into the TUN.
//!
//! tincd already inspects every TUN packet's dst IP for routing
//! (`route.rs` → `subnet_tree.rs`). Adding the intercept is one
//! branch in code that's already hot. No port-53 conflict with
//! systemd-resolved's `127.0.0.53`, no socket fd to babysit through
//! `drop_privs` (`main.rs:1139`) or `sandbox::enter` (`main.rs:1174`),
//! no `CAP_NET_BIND_SERVICE`.
//!
//! ## What we answer
//!
//! - **A / AAAA** for `<node>.<suffix>`: every `/32` (v4) or `/128`
//!   (v6) the node advertises. A `Subnet = 10.0.0.0/24` is a *route*,
//!   not an *identity* — the node doesn't "have" address `10.0.0.0`.
//!   Nebula picks the first address (`dns_server.go:84-100`); we
//!   return ALL host-prefix subnets (multi-homed nodes are normal in
//!   tinc, and DNS clients have handled multiple A records since
//!   1987).
//! - **PTR** for `*.in-addr.arpa` / `*.ip6.arpa`: reverse-lookup the
//!   exact IP in the subnet tree, return the owner. Makes `who`,
//!   `last`, `journalctl` show node names instead of `10.0.0.5`.
//!   Tailscale does this (`tsdns.go:524,1005,1164`); Nebula doesn't.
//! - **NXDOMAIN for everything else.** No upstream forwarding.
//!   Tailscale's `forwarder.go` is 1375 LOC and only needed when you
//!   take over `/etc/resolv.conf` entirely. We don't — split-DNS via
//!   systemd-resolved (`SetLinkDomains` with `~tinc.internal`) means
//!   the OS only sends `*.tinc.internal` queries here. Everything
//!   else goes to the real resolver without us touching it.
//!
//! ## OS integration: not our problem
//!
//! `tinc-up` does it. Two lines:
//!
//! ```sh
//! resolvectl dns "$INTERFACE" "$DNS_ADDR"
//! resolvectl domain "$INTERFACE" "~$DNS_SUFFIX" "$DNS_SUFFIX"
//! ```
//!
//! The `~` prefix is "routing-only domain" (resolved sends ONLY
//! matching queries here); the bare suffix is also a *search* domain
//! so `ssh alice` works without `.tinc.internal` (hyprspace's
//! `RoutingDomain: false` trick — `resolved_linux.go:43`).
//!
//! Tailscale spends 1888 LOC on Linux integration alone (`manager_
//! linux.go` 398 + `resolved.go` 401 + `nm.go` 436 + `direct.go` 653)
//! with NetworkManager-version-specific workarounds. That's a
//! maintenance treadmill. The `resolvectl` CLI is stable.
//!
//! ## Wire format
//!
//! Hand-rolled. RFC 1035 §4. A/AAAA/PTR is ~12 fixed fields; the
//! `domain` crate pulls a proc-macro, `hickory-proto` pulls 14 deps
//! including `idna` and `url`. Nebula's whole DNS server is 210 LOC
//! *with* `miekg/dns` doing the parsing; we're at ~250 without.
//!
//! No DNS message compression (RFC 1035 §4.1.4 pointers). Legal —
//! "a server MAY use compression"; it's an optimization. Our answers
//! are tiny (one or two RRs); the bytes saved aren't worth the
//! state machine.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use zerocopy::IntoBytes;

use crate::packet::{Ipv4Hdr, Ipv4Pseudo, Ipv6Hdr, Ipv6Pseudo, inet_checksum};
use crate::subnet_tree::SubnetTree;
use tinc_proto::Subnet;

// ── Config ──────────────────────────────────────────────────────────

/// DNS stub config. `None` (the daemon-side `Option<DnsConfig>`)
/// disables the whole feature; the TUN-intercept branch never fires.
///
/// Why no default `dns_addr`: it has to be (a) routed to the TUN so
/// the kernel sends packets there, (b) not a real node's `/32`. We
/// can't pick that — the operator's address plan is opaque to us.
/// Tailscale gets away with `100.100.100.100` because they control
/// the CGNAT allocation.
#[derive(Debug, Clone)]
pub(crate) struct DnsConfig {
    /// The magic IP. Must be added to the TUN in `tinc-up` (`ip
    /// addr add ... dev $INTERFACE`).
    pub dns_addr4: Option<Ipv4Addr>,
    /// IPv6 equivalent. Either or both can be set.
    pub dns_addr6: Option<Ipv6Addr>,
    /// Suffix WITHOUT leading/trailing dot. `tinc.internal` →
    /// answers `alice.tinc.internal.`. ICANN reserved `.internal`
    /// for private use July 2024 — it will NEVER be delegated.
    /// `.tinc` alone could theoretically be sold as a gTLD.
    pub suffix: String,
}

// ── Wire constants (RFC 1035) ───────────────────────────────────────

const DNS_HDR_LEN: usize = 12;
/// Response, Authoritative Answer. RD echoed from query.
const FLAG_QR_AA: u16 = 0x8400;
/// RFC 1035 §4.1.1: rcode 3, "Name Error". Authoritative: "the
/// domain name referenced in the query does not exist."
const RCODE_NXDOMAIN: u16 = 0x0003;
/// rcode 1, "Format Error".
const RCODE_FORMERR: u16 = 0x0001;
/// rcode 4, "Not Implemented" — for non-QUERY opcodes.
const RCODE_NOTIMP: u16 = 0x0004;

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// 30s. Low so a node disappearing surfaces quickly. Tailscale uses
/// much higher (their node→IP binding is stable); ours can churn
/// (a node re-advertises a different `/32` after a config change).
const TTL: u32 = 30;

// ── Packet intercept ────────────────────────────────────────────────
//
// Reuses `packet.rs` constants. The actual offsets are written out
// here because they're load-bearing for the ETH+IP+UDP slicing and
// the doc-comment for each is the layer split.

const ETHER_SIZE: usize = 14;
const IP4_SIZE: usize = 20;
const IP6_SIZE: usize = 40;
const UDP_SIZE: usize = 8;
const IPPROTO_UDP: u8 = 17;
/// 0x86DD. `route.rs` has a private copy; we don't want to thread
/// it through `packet.rs` (which is missing it, see `:322` comment).
const ETH_P_IPV6: u16 = 0x86DD;

/// Is this an IPv4 UDP packet to `dns_addr:53`? Full-frame match
/// from the eth header down. `None` for "not for us"; `Some((src_ip,
/// src_port, dns_payload))` for the intercept. Packets with IP
/// options (`ihl != 5`) are rejected — keeps the offset math fixed,
/// and the kernel's resolver doesn't set them.
#[must_use]
pub(crate) fn match_v4(data: &[u8], dns_addr: Ipv4Addr) -> Option<(Ipv4Addr, u16, &[u8])> {
    // eth + ip + udp + DNS header (12 bytes) is the floor.
    // Shorter → not a DNS query, fall through to route().
    let off = ETHER_SIZE;
    if data.len() < off + IP4_SIZE + UDP_SIZE + DNS_HDR_LEN {
        return None;
    }
    // ihl=5 only — no IP options. The kernel resolver doesn't set
    // them; supporting them would mean variable UDP offset.
    if data[off] != 0x45 {
        return None;
    }
    if data[off + 9] != IPPROTO_UDP {
        return None;
    }
    let dst = Ipv4Addr::new(
        data[off + 16],
        data[off + 17],
        data[off + 18],
        data[off + 19],
    );
    if dst != dns_addr {
        return None;
    }
    // UDP dport at [eth+ip+2..+4]
    let udp_off = off + IP4_SIZE;
    let dport = u16::from_be_bytes([data[udp_off + 2], data[udp_off + 3]]);
    if dport != 53 {
        return None;
    }
    let src = Ipv4Addr::new(
        data[off + 12],
        data[off + 13],
        data[off + 14],
        data[off + 15],
    );
    let sport = u16::from_be_bytes([data[udp_off], data[udp_off + 1]]);
    // UDP length includes the 8-byte header; trust the IP totlen
    // less (the device drain may pad). Either is fine for a stub.
    Some((src, sport, &data[udp_off + UDP_SIZE..]))
}

/// IPv6 equivalent of [`match_v4`]. Only matches with no extension
/// headers (`nxt == UDP` directly). Extension-header chains between
/// IPv6 and UDP are legal but the kernel's resolver doesn't emit
/// them, and chasing the chain is a parser. Same call as the
/// `ihl == 5` gate above.
#[must_use]
pub(crate) fn match_v6<'a>(
    data: &'a [u8],
    dns_addr: &Ipv6Addr,
) -> Option<(Ipv6Addr, u16, &'a [u8])> {
    let off = ETHER_SIZE;
    if data.len() < off + IP6_SIZE + UDP_SIZE + DNS_HDR_LEN {
        return None;
    }
    // nxt at +6. No extension-header chain walk — see above.
    if data[off + 6] != IPPROTO_UDP {
        return None;
    }
    let dst_bytes: [u8; 16] = data[off + 24..off + 40].try_into().ok()?;
    let dst = Ipv6Addr::from(dst_bytes);
    if &dst != dns_addr {
        return None;
    }
    let udp_off = off + IP6_SIZE;
    let dport = u16::from_be_bytes([data[udp_off + 2], data[udp_off + 3]]);
    if dport != 53 {
        return None;
    }
    let src_bytes: [u8; 16] = data[off + 8..off + 24].try_into().ok()?;
    let src = Ipv6Addr::from(src_bytes);
    let sport = u16::from_be_bytes([data[udp_off], data[udp_off + 1]]);
    Some((src, sport, &data[udp_off + UDP_SIZE..]))
}

// ── DNS query parse ─────────────────────────────────────────────────

/// What we pulled out of the question section. Everything we need to
/// build a response. The raw `qname` bytes (still in wire format —
/// length-prefixed labels) are kept so we can echo them back in the
/// question section + answer NAME field without re-encoding.
#[cfg_attr(test, derive(Debug))]
struct ParsedQuery<'a> {
    id: u16,
    /// Echoed back in response (RFC 1035 §4.1.1: "Recursion Desired
    /// — this bit may be set in a query and is copied into the
    /// response").
    rd: bool,
    qtype: u16,
    /// Wire-format QNAME (length-prefixed labels, terminated by
    /// zero-length label). Slice into the input.
    qname_wire: &'a [u8],
    /// QNAME decoded to dotted lowercase. NO trailing dot.
    qname: String,
}

/// Parse the DNS header + first question. RFC 1035 §4.1.1-2.
/// Returns `None` for anything we won't even FORMERR (truncated
/// header — can't reply without the ID).
///
/// Errors that ARE reportable (`FORMERR`, `NOTIMP`) are returned as
/// `Err((id, rd, rcode))` so the caller can synthesize a header-only
/// error response.
fn parse_query(dns: &[u8]) -> Option<Result<ParsedQuery<'_>, (u16, bool, u16)>> {
    if dns.len() < DNS_HDR_LEN {
        return None; // can't even read ID — drop silently
    }
    let id = u16::from_be_bytes([dns[0], dns[1]]);
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    let rd = flags & 0x0100 != 0;
    // QR bit (0x8000): 1 = this is a response, not a query. Drop
    // silently — replying to a response is a reflection-loop hazard.
    if flags & 0x8000 != 0 {
        return None;
    }
    // Opcode (bits 11-14): 0 = standard QUERY. Everything else
    // (IQUERY, STATUS, NOTIFY, UPDATE) → NOTIMP.
    if (flags >> 11) & 0x0F != 0 {
        return Some(Err((id, rd, RCODE_NOTIMP)));
    }
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    // RFC 1035 says QDCOUNT can be >1 but in practice every resolver
    // sends exactly 1. BIND, unbound, systemd-resolved all do. The
    // only thing that sends 0 is a malformed packet.
    if qdcount != 1 {
        return Some(Err((id, rd, RCODE_FORMERR)));
    }

    // ─── QNAME: walk length-prefixed labels.
    // RFC 1035 §4.1.2: "a domain name represented as a sequence of
    // labels, where each label consists of a length octet followed
    // by that number of octets. The domain name terminates with the
    // zero length octet."
    //
    // Compression pointers (top two bits of length = 11) shouldn't
    // appear in a QUESTION qname (there's nothing earlier to point
    // to). If we see one, FORMERR.
    let mut pos = DNS_HDR_LEN;
    let mut labels: Vec<&[u8]> = Vec::with_capacity(4);
    let qname_start = pos;
    loop {
        let len = *dns.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // Top two bits set = compression pointer. Reject.
        // §4.1.4: pointer is "a two octet sequence: 11 + 14-bit
        // offset". len & 0xC0 catches both 11xxxxxx and 10/01
        // (latter are reserved → also FORMERR).
        if len & 0xC0 != 0 {
            return Some(Err((id, rd, RCODE_FORMERR)));
        }
        if pos + len > dns.len() {
            return Some(Err((id, rd, RCODE_FORMERR)));
        }
        labels.push(&dns[pos..pos + len]);
        pos += len;
    }
    let qname_wire = &dns[qname_start..pos];

    // QTYPE + QCLASS (2 bytes each)
    if pos + 4 > dns.len() {
        return Some(Err((id, rd, RCODE_FORMERR)));
    }
    let qtype = u16::from_be_bytes([dns[pos], dns[pos + 1]]);
    let qclass = u16::from_be_bytes([dns[pos + 2], dns[pos + 3]]);
    // CLASS_IN only. CHAOS (`dig @x version.bind ch txt`) etc → NX.
    // Not strictly correct (NOTIMP would be more honest) but the
    // distinction doesn't matter for a private stub.
    if qclass != CLASS_IN {
        return Some(Err((id, rd, RCODE_NXDOMAIN)));
    }

    // Join labels with `.`, lowercase. RFC 1035 §2.3.3: "When data
    // enters the domain system, its original case should be
    // preserved" but "comparisons [...] are done in a
    // case-insensitive manner". We lowercase eagerly; tinc node
    // names are case-sensitive (`check_id`) but the OPERATOR can't
    // have `Alice` and `alice` both in `hosts/` on a
    // case-insensitive filesystem anyway.
    let mut qname = String::with_capacity(pos - qname_start);
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            qname.push('.');
        }
        for &b in *label {
            qname.push(b.to_ascii_lowercase() as char);
        }
    }

    Some(Ok(ParsedQuery {
        id,
        rd,
        qtype,
        qname_wire,
        qname,
    }))
}

// ── PTR helpers ─────────────────────────────────────────────────────

/// `5.0.0.10.in-addr.arpa` → `10.0.0.5`. RFC 1035 §3.5. Octets
/// reversed; each is a separate label.
fn parse_ptr_v4(qname: &str) -> Option<Ipv4Addr> {
    let stem = qname.strip_suffix(".in-addr.arpa")?;
    let mut parts = stem.split('.');
    // The arpa zone is reversed; the IP is least-significant-first.
    let d: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let a: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None; // extra labels → not a /32 PTR
    }
    Some(Ipv4Addr::new(a, b, c, d))
}

/// `1.0.0.0.[...].8.b.d.0.1.0.0.2.ip6.arpa` → `2001:db8:...::1`.
/// RFC 3596 §2.5. 32 hex nibbles, least-significant first.
fn parse_ptr_v6(qname: &str) -> Option<Ipv6Addr> {
    let stem = qname.strip_suffix(".ip6.arpa")?;
    let mut bytes = [0u8; 16];
    let mut parts = stem.split('.');
    // 32 nibbles, reversed: nibble[0] is the LOW nibble of byte 15.
    for byte_idx in (0..16).rev() {
        let lo = u8::from_str_radix(parts.next()?, 16).ok()?;
        let hi = u8::from_str_radix(parts.next()?, 16).ok()?;
        if lo > 0xF || hi > 0xF {
            return None;
        }
        bytes[byte_idx] = (hi << 4) | lo;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv6Addr::from(bytes))
}

/// Encode a dotted name to wire format. Used for PTR RDATA only
/// (the question QNAME is echoed verbatim from the query).
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        // RFC 1035 §2.3.4: labels are 63 octets max. tinc node
        // names are well under that (`check_id` rejects long ones);
        // the suffix is operator-provided. Clamp rather than error.
        #[allow(clippy::cast_possible_truncation)] // .min(63) clamps to u8 range
        let len = label.len().min(63) as u8;
        out.push(len);
        out.extend_from_slice(&label.as_bytes()[..len as usize]);
    }
    out.push(0);
    out
}

// ── Answer builder ──────────────────────────────────────────────────

/// Build the DNS response payload (header + question + answers).
/// Separate from the IP/UDP wrapping so unit tests can poke it
/// without crafting full ethernet frames.
///
/// `subnets` is read-only; the daemon's `subnet_tree` is the live
/// table (DNS sees the same view as `route()`). No staleness — every
/// query is a fresh walk.
///
/// `myname` is OUR node name. We answer for ourselves too: `dig
/// alice.tinc.internal` from alice resolves to alice's own /32. The
/// alternative (filter myself out) breaks `ssh $(hostname)` and is
/// surprising.
#[must_use]
pub(crate) fn answer(
    dns: &[u8],
    cfg: &DnsConfig,
    subnets: &SubnetTree,
    myname: &str,
) -> Option<Vec<u8>> {
    let parsed = parse_query(dns)?;

    let q = match parsed {
        Ok(q) => q,
        Err((id, rd, rcode)) => {
            // Header-only error response. Echo ID + RD; QDCOUNT=0.
            // RFC 2308 §2.1 says we SHOULD include the question
            // section, but for FORMERR we may not have parsed it.
            return Some(build_error(id, rd, rcode, &[], 0));
        }
    };

    // ─── A / AAAA: <node>.<suffix> → host-prefix Subnets
    if q.qtype == TYPE_A || q.qtype == TYPE_AAAA {
        // Suffix match. Lowercase already (parse_query did it).
        // Match against `cfg.suffix` lowered too — config is
        // case-preserved but DNS isn't.
        let suffix_lc = cfg.suffix.to_ascii_lowercase();
        let Some(node) = q
            .qname
            .strip_suffix(&suffix_lc)
            .and_then(|s| s.strip_suffix('.'))
        else {
            return Some(build_error(
                q.id,
                q.rd,
                RCODE_NXDOMAIN,
                q.qname_wire,
                q.qtype,
            ));
        };
        // No further dots — `<service>.<node>.suffix` isn't a thing
        // (yet — see hyprspace's two-level names if we ever want it).
        if node.contains('.') {
            return Some(build_error(
                q.id,
                q.rd,
                RCODE_NXDOMAIN,
                q.qname_wire,
                q.qtype,
            ));
        }
        // Walk the subnet tree, collect host-prefix subnets owned by
        // `node`. Case-insensitive owner compare: tinc names are
        // case-preserved on disk but `check_id` allows both, and the
        // lowercased qname won't match `Alice` otherwise.
        let mut answers: Vec<Vec<u8>> = Vec::new();
        for (subnet, owner) in subnets.iter() {
            if !owner.eq_ignore_ascii_case(node) {
                continue;
            }
            match (q.qtype, subnet) {
                (
                    TYPE_A,
                    Subnet::V4 {
                        addr, prefix: 32, ..
                    },
                ) => {
                    answers.push(build_rr(q.qname_wire, TYPE_A, &addr.octets()));
                }
                (
                    TYPE_AAAA,
                    Subnet::V6 {
                        addr, prefix: 128, ..
                    },
                ) => {
                    answers.push(build_rr(q.qname_wire, TYPE_AAAA, &addr.octets()));
                }
                _ => {}
            }
        }
        // Found the name but no records of the requested type:
        // that's NOERROR with ANCOUNT=0 (RFC 2308 "NODATA"), NOT
        // NXDOMAIN. NXDOMAIN means "the name doesn't exist". A node
        // with only a v4 /32 queried for AAAA is "name exists, no
        // AAAA" — different cache behavior in resolved.
        //
        // BUT: we don't track "does this node exist" separately from
        // "does it have subnets" (a node with zero subnets is
        // unreachable anyway). Approximate: NXDOMAIN when the node
        // doesn't appear in `subnets` at all (including under the
        // wrong qtype); NODATA otherwise. Close enough.
        if answers.is_empty() {
            // Second walk to distinguish NX from NODATA: did we see
            // the node at ALL (any subnet, any family)? Compare
            // against `myname` too — we have no subnets of our own
            // until tinc-up runs and a peer ADD_SUBNETs us, but `dig
            // <myname>` should still NODATA not NX.
            let exists = node.eq_ignore_ascii_case(myname)
                || subnets
                    .iter()
                    .any(|(_, owner)| owner.eq_ignore_ascii_case(node));
            let rcode = if exists { 0 } else { RCODE_NXDOMAIN };
            return Some(build_response(
                q.id,
                q.rd,
                rcode,
                q.qname_wire,
                q.qtype,
                &[],
            ));
        }
        return Some(build_response(
            q.id,
            q.rd,
            0,
            q.qname_wire,
            q.qtype,
            &answers,
        ));
    }

    // ─── PTR: arpa → owner name
    if q.qtype == TYPE_PTR {
        return Some(answer_ptr(&q, cfg, subnets));
    }

    // Everything else: NXDOMAIN. We don't NOTIMP per-type (the
    // distinction between "no such name" and "I don't speak SRV"
    // doesn't matter for a private stub, and NXDOMAIN gets cached
    // properly).
    Some(build_error(
        q.id,
        q.rd,
        RCODE_NXDOMAIN,
        q.qname_wire,
        q.qtype,
    ))
}

/// PTR: arpa qname → owner of the exact /32 or /128. Unlike the A/AAAA
/// path, no `cfg.suffix` strip — the arpa namespace is its own thing.
fn answer_ptr(q: &ParsedQuery<'_>, cfg: &DnsConfig, subnets: &SubnetTree) -> Vec<u8> {
    let owner = if let Some(ip) = parse_ptr_v4(&q.qname) {
        // Reverse: lookup the EXACT /32 in the tree. `lookup_
        // ipv4` does longest-prefix-match, which would let a /24
        // answer for any host in it — wrong for PTR. Filter the
        // hit to prefix==32. The reachability gate is `|_| true`
        // because PTR is "who owns this", not "are they up"
        // (matches the ARP handler's gate at `daemon/net.rs:2492`).
        subnets.lookup_ipv4(ip, |_| true).and_then(|(s, o)| {
            if let Subnet::V4 { prefix: 32, .. } = s {
                o
            } else {
                None
            }
        })
    } else if let Some(ip) = parse_ptr_v6(&q.qname) {
        subnets.lookup_ipv6(&ip, |_| true).and_then(|(s, o)| {
            if let Subnet::V6 { prefix: 128, .. } = s {
                o
            } else {
                None
            }
        })
    } else {
        None
    };
    let Some(owner) = owner else {
        return build_error(q.id, q.rd, RCODE_NXDOMAIN, q.qname_wire, q.qtype);
    };
    // RDATA is the wire-encoded `<owner>.<suffix>.`
    let target = format!("{}.{}", owner.to_ascii_lowercase(), cfg.suffix);
    let rdata = encode_name(&target);
    let rr = build_rr(q.qname_wire, TYPE_PTR, &rdata);
    build_response(q.id, q.rd, 0, q.qname_wire, TYPE_PTR, &[rr])
}

/// One Resource Record. NAME echoed verbatim (wire format) — no
/// compression pointer back to the question section; `dig` doesn't
/// care, the bytes saved are ~10.
fn build_rr(name_wire: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut rr = Vec::with_capacity(name_wire.len() + 10 + rdata.len());
    rr.extend_from_slice(name_wire);
    rr.extend_from_slice(&rtype.to_be_bytes());
    rr.extend_from_slice(&CLASS_IN.to_be_bytes());
    rr.extend_from_slice(&TTL.to_be_bytes());
    // RDLENGTH: 16 bits. /32 → 4, /128 → 16, PTR name is bounded
    // by max DNS name (255). Never overflows.
    #[allow(clippy::cast_possible_truncation)] // rdata is ≤4/16/255 bytes (see above)
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(rdata);
    rr
}

/// Header-only or header+question error response.
///
/// The echoed question section MUST include the original QTYPE —
/// dig 9.20 validates `QNAME/QTYPE/QCLASS` of the echoed question
/// against what it sent and rejects on mismatch ("Question section
/// mismatch: got x/TYPE0/IN"). Older resolvers tolerated qtype=0.
/// Caught by the NixOS test (real dig); the bwrap'd netns test was
/// silently `SKIP`ping (`--tmpfs /run` wiped /run/current-system/sw,
/// where dig lives on NixOS).
fn build_error(id: u16, rd: bool, rcode: u16, qname_wire: &[u8], qtype: u16) -> Vec<u8> {
    // Reuse the full builder with zero answers — same wire shape.
    // qname_wire empty → QDCOUNT=0 (the FORMERR case where we
    // couldn't parse the question; qtype is ignored then).
    build_response(id, rd, rcode, qname_wire, qtype, &[])
}

/// Full response: header + (echoed) question + answers.
fn build_response(
    id: u16,
    rd: bool,
    rcode: u16,
    qname_wire: &[u8],
    qtype: u16,
    answers: &[Vec<u8>],
) -> Vec<u8> {
    let qd = u16::from(!qname_wire.is_empty());
    let mut flags = FLAG_QR_AA | rcode;
    if rd {
        flags |= 0x0100;
    }

    let mut out = Vec::with_capacity(DNS_HDR_LEN + qname_wire.len() + 4 + answers.len() * 16);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes()); // QDCOUNT
    #[allow(clippy::cast_possible_truncation)] // ≤ subnets.len(), which is small
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    if qd == 1 {
        out.extend_from_slice(qname_wire);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
    }
    for a in answers {
        out.extend_from_slice(a);
    }
    out
}

// ── IP/UDP wrap ─────────────────────────────────────────────────────
//
// Builds the full eth+IP+UDP+DNS reply frame for `device.write()`.
// Same shape as `icmp.rs::build_v4_unreachable` — fresh `Vec`, not
// in-place mutation. DNS fires once per `getaddrinfo()`, not per
// data packet; alloc doesn't matter.

/// Push a 14-byte ethernet header onto `out` with src/dst MACs
/// swapped from `original` (or zeroed when `original` is too short).
/// Shared by `wrap_v4`/`wrap_v6`; the eth header is throwaway in TUN
/// mode but `device.write` expects the full frame.
fn write_eth_swap(out: &mut Vec<u8>, original: &[u8], ethertype: u16) {
    if original.len() >= ETHER_SIZE {
        out.extend_from_slice(&original[6..12]); // dst ← orig src
        out.extend_from_slice(&original[0..6]); // src ← orig dst
    } else {
        out.extend_from_slice(&[0u8; 12]);
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
}

/// Build the 8-byte UDP header for `dns_reply` with the checksum
/// folded over `pseudo_ck` (the partial sum of the v4/v6
/// pseudo-header). RFC 768/8200: a computed checksum of 0 is
/// transmitted as 0xFFFF.
fn build_udp(dns_reply: &[u8], dst_port: u16, pseudo_ck: u16) -> [u8; UDP_SIZE] {
    #[allow(clippy::cast_possible_truncation)] // bounded by DNS reply size (~512)
    let udp_len = (UDP_SIZE + dns_reply.len()) as u16;
    let mut udp = [0u8; UDP_SIZE];
    udp[0..2].copy_from_slice(&53u16.to_be_bytes()); // src = 53
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // csum at [6..8] starts zero; fold header + payload onto the
    // caller-provided pseudo-header sum.
    let mut ck = inet_checksum(&udp, pseudo_ck);
    ck = inet_checksum(dns_reply, ck);
    let ck = if ck == 0 { 0xFFFF } else { ck };
    udp[6..8].copy_from_slice(&ck.to_ne_bytes());
    udp
}

/// Wrap a DNS response in eth+IPv4+UDP. The eth header is throwaway
/// (TUN mode strips it), but `device.write` expects the full frame
/// (`route()`'s framing). MACs swapped from `original` per the
/// `icmp.rs` convention.
///
/// UDP checksum: optional in IPv4 (RFC 768: "if the computed
/// checksum is zero, it is transmitted as all ones [...] An all
/// zero transmitted checksum value means that the transmitter
/// generated no checksum"). The Linux kernel accepts zero on RX. We
/// compute it anyway — three more `inet_checksum` calls is cheap and
/// it's mandatory in IPv6, so the code is shared.
#[must_use]
pub(crate) fn wrap_v4(
    original: &[u8],
    dns_reply: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Vec<u8> {
    let total = ETHER_SIZE + IP4_SIZE + UDP_SIZE + dns_reply.len();
    let mut out = Vec::with_capacity(total);

    write_eth_swap(&mut out, original, crate::packet::ETH_P_IP);

    // ─── IPv4. Same builder pattern as `icmp.rs:123-137`.
    let mut ip = Ipv4Hdr::default();
    ip.set_vhl(4, 5);
    // truncation: DNS responses are bounded (~512 in practice with
    // our few RRs); + 28 for IP+UDP. Never near u16.
    #[allow(clippy::cast_possible_truncation)] // bounded by DNS reply size (~512)
    ip.set_total_len((IP4_SIZE + UDP_SIZE + dns_reply.len()) as u16);
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_UDP;
    ip.ip_src = src_ip.octets();
    ip.ip_dst = dst_ip.octets();
    ip.ip_sum = inet_checksum(ip.as_bytes(), 0xFFFF);
    out.extend_from_slice(ip.as_bytes());

    // ─── UDP. RFC 768 + RFC 1071: pseudo-header → UDP header → payload.
    #[allow(clippy::cast_possible_truncation)] // bounded by DNS reply size (~512)
    let udp_len = (UDP_SIZE + dns_reply.len()) as u16;
    let mut pseudo = Ipv4Pseudo::default();
    pseudo.ip_src = src_ip.octets();
    pseudo.ip_dst = dst_ip.octets();
    pseudo.proto = IPPROTO_UDP;
    pseudo.set_length(udp_len);
    let pseudo_ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);

    out.extend_from_slice(&build_udp(dns_reply, dst_port, pseudo_ck));
    out.extend_from_slice(dns_reply);
    out
}

/// IPv6 wrap. UDP checksum is **mandatory** (RFC 8200 §8.1: "Unlike
/// IPv4, the default behavior when UDP packets are originated by an
/// IPv6 node is that the UDP checksum is NOT optional").
#[must_use]
pub(crate) fn wrap_v6(
    original: &[u8],
    dns_reply: &[u8],
    src_ip: &Ipv6Addr,
    dst_ip: &Ipv6Addr,
    dst_port: u16,
) -> Vec<u8> {
    let total = ETHER_SIZE + IP6_SIZE + UDP_SIZE + dns_reply.len();
    let mut out = Vec::with_capacity(total);

    write_eth_swap(&mut out, original, ETH_P_IPV6);

    // ─── IPv6. No IP-level checksum (it's the UDP layer's job).
    let mut ip6 = Ipv6Hdr::default();
    ip6.set_flow(0x6000_0000);
    #[allow(clippy::cast_possible_truncation)] // bounded by DNS reply size (~512)
    ip6.set_plen((UDP_SIZE + dns_reply.len()) as u16);
    ip6.ip6_nxt = IPPROTO_UDP;
    ip6.ip6_hlim = 64;
    ip6.ip6_src = src_ip.octets();
    ip6.ip6_dst = dst_ip.octets();
    out.extend_from_slice(ip6.as_bytes());

    // ─── UDP. Pseudo-header → UDP header → payload. RFC 2460 §8.1 (now 8200).
    #[allow(clippy::cast_possible_truncation)] // bounded by DNS reply size (~512)
    let udp_len = (UDP_SIZE + dns_reply.len()) as u16;
    let mut pseudo = Ipv6Pseudo::default();
    pseudo.ip6_src = src_ip.octets();
    pseudo.ip6_dst = dst_ip.octets();
    pseudo.set_length(u32::from(udp_len));
    pseudo.set_next(u32::from(IPPROTO_UDP));
    let pseudo_ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);

    out.extend_from_slice(&build_udp(dns_reply, dst_port, pseudo_ck));
    out.extend_from_slice(dns_reply);
    out
}

// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DnsConfig {
        DnsConfig {
            dns_addr4: Some(Ipv4Addr::new(10, 255, 255, 53)),
            dns_addr6: None,
            suffix: "tinc.internal".into(),
        }
    }

    fn sn(s: &str) -> Subnet {
        s.parse().unwrap()
    }

    /// Hand-craft a DNS query packet. `dig` would emit roughly this
    /// for `dig @10.255.255.53 alice.tinc.internal`.
    fn mk_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&[0u8; 6]); // AN/NS/AR all 0
        q.extend_from_slice(&encode_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    // ─── parse_query

    #[test]
    fn parse_query_basic() {
        let q = mk_query("alice.tinc.internal", TYPE_A);
        let p = parse_query(&q).unwrap().unwrap();
        assert_eq!(p.id, 0x1234);
        assert!(p.rd);
        assert_eq!(p.qtype, TYPE_A);
        assert_eq!(p.qname, "alice.tinc.internal");
        // qname_wire is the encoded form including the terminal zero
        assert_eq!(
            p.qname_wire,
            &[
                5, b'a', b'l', b'i', b'c', b'e', 4, b't', b'i', b'n', b'c', 8, b'i', b'n', b't',
                b'e', b'r', b'n', b'a', b'l', 0
            ]
        );
    }

    #[test]
    fn parse_query_lowercases() {
        let q = mk_query("Alice.TINC.Internal", TYPE_A);
        let p = parse_query(&q).unwrap().unwrap();
        assert_eq!(p.qname, "alice.tinc.internal");
    }

    /// QR=1 (this is a response, not a query) → drop silently.
    /// Replying to responses is a reflection-loop hazard.
    #[test]
    fn parse_query_response_bit_drops() {
        let mut q = mk_query("x.tinc.internal", TYPE_A);
        q[2] |= 0x80; // set QR
        assert!(parse_query(&q).is_none());
    }

    #[test]
    fn parse_query_non_standard_opcode() {
        let mut q = mk_query("x.tinc.internal", TYPE_A);
        q[2] |= 0x08; // opcode=1 (IQUERY, obsolete)
        let r = parse_query(&q).unwrap();
        assert_eq!(r.unwrap_err().2, RCODE_NOTIMP);
    }

    #[test]
    fn parse_query_truncated_header() {
        assert!(parse_query(&[0u8; 5]).is_none());
    }

    /// Compression pointer in the question section: shouldn't happen
    /// (nothing earlier to point to). Reject as FORMERR.
    #[test]
    fn parse_query_compression_pointer_rejected() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.push(0xC0); // pointer marker
        q.push(0x0C);
        q.extend_from_slice(&TYPE_A.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        let r = parse_query(&q).unwrap();
        assert_eq!(r.unwrap_err().2, RCODE_FORMERR);
    }

    // ─── PTR parsing

    #[test]
    fn ptr_v4_roundtrip() {
        assert_eq!(
            parse_ptr_v4("5.0.0.10.in-addr.arpa"),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
        // wrong number of labels
        assert_eq!(parse_ptr_v4("0.0.10.in-addr.arpa"), None);
        // not numeric
        assert_eq!(parse_ptr_v4("x.0.0.10.in-addr.arpa"), None);
        // wrong suffix
        assert_eq!(parse_ptr_v4("5.0.0.10.ip6.arpa"), None);
    }

    #[test]
    fn ptr_v6_roundtrip() {
        // 2001:db8::1 → 32 nibbles, reversed
        let arpa = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        assert_eq!(parse_ptr_v6(arpa), Some("2001:db8::1".parse().unwrap()));
        // 31 nibbles → reject
        let short = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.ip6.arpa";
        assert_eq!(parse_ptr_v6(short), None);
    }

    // ─── answer()

    #[test]
    fn answer_a_single() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.5"), "alice".into());

        let q = mk_query("alice.tinc.internal", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();

        // Header: ID echoed, QR+AA+RD set, NOERROR, 1Q 1A
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0x8500); // QR|AA|RD
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT
        // The A rdata is at the very end (4 bytes)
        assert_eq!(&resp[resp.len() - 4..], &[10, 0, 0, 5]);
    }

    #[test]
    fn answer_a_multi() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.5"), "alice".into());
        t.add(sn("10.0.0.6"), "alice".into());
        t.add(sn("192.168.1.1"), "alice".into());

        let q = mk_query("alice.tinc.internal", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 3); // ANCOUNT
    }

    /// /24 is a route, not an identity: NO A record. This is the
    /// load-bearing decision (see module doc).
    #[test]
    fn answer_a_ignores_ranges() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());

        let q = mk_query("alice.tinc.internal", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        // Node exists (it has SOME subnet) but no /32 → NODATA
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x0F, 0); // NOERROR
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT
    }

    #[test]
    fn answer_a_unknown_node_nxdomain() {
        let t = SubnetTree::new();
        let q = mk_query("nobody.tinc.internal", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(
            u16::from_be_bytes([resp[2], resp[3]]) & 0x0F,
            RCODE_NXDOMAIN
        );
    }

    /// REGRESSION: NXDOMAIN must echo the question section with the
    /// ORIGINAL qtype, not 0. dig 9.20 validates qname/qtype/qclass
    /// of the echoed question against what it sent ("Question section
    /// mismatch: got x/TYPE0/IN") and discards the whole response.
    /// First caught by `nix/nixos-test.nix`; the bwrap'd netns test
    /// was silently `SKIP`ping (no dig in `--tmpfs /run`).
    #[test]
    fn nxdomain_echoes_qtype() {
        let t = SubnetTree::new();
        let q = mk_query("google.com", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();

        assert_eq!(
            u16::from_be_bytes([resp[2], resp[3]]) & 0x0F,
            RCODE_NXDOMAIN
        );
        // QDCOUNT=1 → question section follows the 12-byte header.
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        // QNAME wire = encode_name("google.com") = 12 bytes.
        // QTYPE is at [12 + qname_len .. +2].
        let qname_len = encode_name("google.com").len();
        let qtype_off = DNS_HDR_LEN + qname_len;
        assert_eq!(
            u16::from_be_bytes([resp[qtype_off], resp[qtype_off + 1]]),
            TYPE_A,
            "echoed qtype must match query (was 0 — dig 9.20 rejects)"
        );
        assert_eq!(
            u16::from_be_bytes([resp[qtype_off + 2], resp[qtype_off + 3]]),
            CLASS_IN
        );
    }

    /// `dig myself.tinc.internal` should NODATA (not NX) even before
    /// we have subnets — the name exists, it's us.
    #[test]
    fn answer_a_myself_nodata() {
        let t = SubnetTree::new();
        let q = mk_query("myself.tinc.internal", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x0F, 0); // NOERROR
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT
    }

    #[test]
    fn answer_aaaa() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::1"), "alice".into());
        t.add(sn("10.0.0.5"), "alice".into()); // not in AAAA answer

        let q = mk_query("alice.tinc.internal", TYPE_AAAA);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        let want: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(&resp[resp.len() - 16..], &want.octets());
    }

    #[test]
    fn answer_wrong_suffix_nx() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.5"), "alice".into());

        let q = mk_query("alice.example.com", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(
            u16::from_be_bytes([resp[2], resp[3]]) & 0x0F,
            RCODE_NXDOMAIN
        );
    }

    #[test]
    fn answer_case_insensitive_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.5"), "Alice".into()); // mixed case

        let q = mk_query("alice.tinc.internal", TYPE_A);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    #[test]
    fn answer_ptr_v4() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.5"), "alice".into());

        let q = mk_query("5.0.0.10.in-addr.arpa", TYPE_PTR);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // RDATA tail is wire-encoded "alice.tinc.internal."
        let want = encode_name("alice.tinc.internal");
        assert_eq!(&resp[resp.len() - want.len()..], &want[..]);
    }

    /// PTR for an IP covered only by a /24, not a /32: NXDOMAIN.
    /// `lookup_ipv4` would find the /24 (longest-prefix-match) but
    /// PTR semantics want exact-host. The prefix==32 filter catches
    /// this.
    #[test]
    fn answer_ptr_v4_only_range_nx() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());

        let q = mk_query("5.0.0.10.in-addr.arpa", TYPE_PTR);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(
            u16::from_be_bytes([resp[2], resp[3]]) & 0x0F,
            RCODE_NXDOMAIN
        );
    }

    #[test]
    fn answer_ptr_v6() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::1"), "alice".into());

        let arpa = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        let q = mk_query(arpa, TYPE_PTR);
        let resp = answer(&q, &cfg(), &t, "myself").unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    // ─── match_v4 / match_v6

    fn mk_udp4(dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP4_SIZE + UDP_SIZE];
        p[12..14].copy_from_slice(&crate::packet::ETH_P_IP.to_be_bytes());
        p[ETHER_SIZE] = 0x45;
        p[ETHER_SIZE + 9] = IPPROTO_UDP;
        // src
        p[ETHER_SIZE + 12..ETHER_SIZE + 16].copy_from_slice(&[10, 0, 0, 1]);
        // dst
        p[ETHER_SIZE + 16..ETHER_SIZE + 20].copy_from_slice(&dst.octets());
        let udp = ETHER_SIZE + IP4_SIZE;
        p[udp..udp + 2].copy_from_slice(&54321u16.to_be_bytes());
        p[udp + 2..udp + 4].copy_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn match_v4_hit() {
        let dns_ip = Ipv4Addr::new(10, 255, 255, 53);
        let payload = mk_query("x.tinc.internal", TYPE_A);
        let pkt = mk_udp4(dns_ip, 53, &payload);
        let (src, sport, dns) = match_v4(&pkt, dns_ip).unwrap();
        assert_eq!(src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(sport, 54321);
        assert_eq!(dns, &payload[..]);
    }

    #[test]
    fn match_v4_wrong_dst() {
        let dns_ip = Ipv4Addr::new(10, 255, 255, 53);
        let pkt = mk_udp4(Ipv4Addr::new(10, 0, 0, 99), 53, &mk_query("x", TYPE_A));
        assert!(match_v4(&pkt, dns_ip).is_none());
    }

    #[test]
    fn match_v4_wrong_port() {
        let dns_ip = Ipv4Addr::new(10, 255, 255, 53);
        let pkt = mk_udp4(dns_ip, 80, &mk_query("x", TYPE_A));
        assert!(match_v4(&pkt, dns_ip).is_none());
    }

    /// IP options (`ihl > 5`): rejected. Keeps offset math fixed;
    /// the kernel resolver doesn't set them.
    #[test]
    fn match_v4_ip_options_rejected() {
        let dns_ip = Ipv4Addr::new(10, 255, 255, 53);
        let mut pkt = mk_udp4(dns_ip, 53, &mk_query("x.tinc.internal", TYPE_A));
        pkt[ETHER_SIZE] = 0x46; // ihl=6
        assert!(match_v4(&pkt, dns_ip).is_none());
    }

    fn mk_udp6(dst: Ipv6Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE + UDP_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        // version=6 in high nibble of byte 0
        p[ETHER_SIZE] = 0x60;
        p[ETHER_SIZE + 6] = IPPROTO_UDP; // nxt
        // src = fd00::1
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        p[ETHER_SIZE + 8..ETHER_SIZE + 24].copy_from_slice(&src.octets());
        p[ETHER_SIZE + 24..ETHER_SIZE + 40].copy_from_slice(&dst.octets());
        let udp = ETHER_SIZE + IP6_SIZE;
        p[udp..udp + 2].copy_from_slice(&54321u16.to_be_bytes());
        p[udp + 2..udp + 4].copy_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn match_v6_hit() {
        let dns_ip: Ipv6Addr = "fd00::53".parse().unwrap();
        let payload = mk_query("x.tinc.internal", TYPE_A);
        let pkt = mk_udp6(dns_ip, 53, &payload);
        let (src, sport, dns) = match_v6(&pkt, &dns_ip).unwrap();
        assert_eq!(src, "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(sport, 54321);
        assert_eq!(dns, &payload[..]);
    }

    // ─── wrap_v4 / wrap_v6: kernel-verifiable checksums

    /// Pin the IPv4 wrapping. Kernel verifies the IP checksum on RX
    /// (drops silently if wrong); the netns integration test catches
    /// that, but a unit-level pin is cheaper to debug.
    #[test]
    fn wrap_v4_shape() {
        let dns_reply = b"\x12\x34\x85\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let frame = wrap_v4(
            &[0u8; 14],
            dns_reply,
            Ipv4Addr::new(10, 255, 255, 53),
            Ipv4Addr::new(10, 0, 0, 1),
            54321,
        );
        assert_eq!(frame.len(), 14 + 20 + 8 + 12);
        assert_eq!(frame[12..14], crate::packet::ETH_P_IP.to_be_bytes());
        // IP version+ihl
        assert_eq!(frame[14], 0x45);
        // proto = UDP
        assert_eq!(frame[14 + 9], 17);
        // IP checksum: re-verify by recomputing over the header with
        // the sum field included — RFC 1071 says it should sum to 0.
        let ip_hdr = &frame[14..14 + 20];
        assert_eq!(inet_checksum(ip_hdr, 0xFFFF), 0);
        // UDP src port = 53, dst = 54321
        assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), 53);
        assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 54321);
        // payload echoed
        assert_eq!(&frame[14 + 20 + 8..], dns_reply);
    }

    /// IPv6 UDP checksum: mandatory (RFC 8200 §8.1). The kernel
    /// REJECTS zero checksum on v6. Re-verify the pseudo-header sum.
    #[test]
    fn wrap_v6_checksum_verifies() {
        let dns_reply = b"\x12\x34\x85\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let src: Ipv6Addr = "fd00::53".parse().unwrap();
        let dst: Ipv6Addr = "fd00::1".parse().unwrap();
        let frame = wrap_v6(&[0u8; 14], dns_reply, &src, &dst, 54321);

        assert_eq!(frame.len(), 14 + 40 + 8 + 12);
        let ip6 = &frame[14..14 + 40];
        let udp = &frame[14 + 40..14 + 40 + 8];
        let payload = &frame[14 + 40 + 8..];

        // Rebuild pseudo, fold everything in: should sum to 0.
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src.copy_from_slice(&ip6[8..24]);
        pseudo.ip6_dst.copy_from_slice(&ip6[24..40]);
        pseudo.set_length(u32::from(u16::from_be_bytes([udp[4], udp[5]])));
        pseudo.set_next(u32::from(IPPROTO_UDP));

        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(udp, ck);
        ck = inet_checksum(payload, ck);
        // Non-zero on the wire (RFC 8200), and round-trips to 0.
        assert_ne!(u16::from_ne_bytes([udp[6], udp[7]]), 0);
        assert_eq!(ck, 0);
    }
}
