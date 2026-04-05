#![allow(clippy::cast_possible_truncation)]
use super::*;

/// Decode the wg-go test vectors' header shapes. wg-go
/// `offload_linux_test.go:179` "tcp4" case: `csum_start=20`
/// (IPv4 hdr), `csum_offset=16` (TCP `th_sum`), `gso_size=100`.
#[test]
fn vnet_hdr_decode() {
    // flags=NEEDS_CSUM(1), gso=TCPV4(1), hdr_len=40, gso_size=100,
    // csum_start=20, csum_offset=16. All u16 LE.
    let raw = [1u8, 1, 40, 0, 100, 0, 20, 0, 16, 0];
    let h = VirtioNetHdr::decode(&raw).unwrap();
    assert_eq!(h.flags, 1);
    assert_eq!(h.gso_type, 1);
    assert_eq!(h.hdr_len, 40);
    assert_eq!(h.gso_size, 100);
    assert_eq!(h.csum_start, 20);
    assert_eq!(h.csum_offset, 16);
    assert_eq!(h.gso(), Some(GsoType::TcpV4));
    assert!(h.needs_csum());

    // Short → None.
    assert!(VirtioNetHdr::decode(&[0; 9]).is_none());

    // Roundtrip: encode → decode is identity. Covers the LE
    // boundary in both directions; a `to_be_bytes` typo in
    // encode would scramble fields here.
    let mut roundtrip = [0u8; VNET_HDR_LEN];
    h.encode(&mut roundtrip);
    assert_eq!(roundtrip, raw);
}

/// RFC 1071 reference vector. From the RFC's example: sum over
/// `00 01 f2 03 f4 f5 f6 f7` = `0xddf2`, complement = `0x220d`.
#[test]
fn checksum_rfc1071_reference() {
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    // RFC: sum = 0001 + f203 + f4f5 + f6f7 = 2ddf0, fold = ddf2.
    assert_eq!(checksum(&data, 0), 0x220d);
}

/// Odd-length tail. RFC 1071 §4.1: pad with zero in the LOW byte
/// (= high byte of the BE-interpreted word).
#[test]
fn checksum_odd_tail() {
    // `00 01 f2` → 0001 + f200 = f201, ~f201 = 0dfe.
    assert_eq!(checksum(&[0x00, 0x01, 0xf2], 0), 0x0dfe);
}

/// Chaining: `checksum(A‖B, 0)` = fold(nofold(A) + nofold(B)).
/// This is what makes pseudo-header chaining work.
#[test]
fn checksum_chains() {
    let a = [0x12, 0x34, 0x56, 0x78];
    let b = [0xab, 0xcd];
    let mut ab = a.to_vec();
    ab.extend_from_slice(&b);
    let direct = checksum(&ab, 0);
    let chained = checksum(&b, checksum_nofold(&a, 0));
    assert_eq!(direct, chained);
}

// ─── packet builders for tso_split tests ───────────────────

/// IPv4 + TCP + `payload_len` bytes of `0xAA`. Minimal headers
/// (20 + 20). seq=1000, ACK+PSH set. Checksums valid.
fn build_v4_tcp(payload_len: usize) -> Vec<u8> {
    let total = 20 + 20 + payload_len;
    let mut p = vec![0u8; total];
    // IPv4 header: ver=4, ihl=5, tos=0, totlen, id=0x1234, off=DF,
    // ttl=64, proto=TCP, csum=0, src=10.0.0.1, dst=10.0.0.2.
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    p[8] = 64;
    p[9] = IPPROTO_TCP;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let csum = checksum(&p[..20], 0);
    p[10..12].copy_from_slice(&csum.to_be_bytes());
    // TCP: sport=1000, dport=2000, seq=1000, ack=0, doff=5<<4,
    // flags=ACK|PSH, win=65535, csum=0, urp=0.
    p[20..22].copy_from_slice(&1000u16.to_be_bytes());
    p[22..24].copy_from_slice(&2000u16.to_be_bytes());
    p[24..28].copy_from_slice(&1000u32.to_be_bytes());
    p[32] = 5 << 4;
    p[33] = 0x10 | TCP_FLAG_PSH; // ACK | PSH
    p[34..36].copy_from_slice(&65535u16.to_be_bytes());
    // Payload.
    for b in &mut p[40..] {
        *b = 0xAA;
    }
    // TCP csum: pseudo + tcp.
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &p[12..20], (20 + payload_len) as u16);
    let csum = checksum(&p[20..], pseudo);
    p[36..38].copy_from_slice(&csum.to_be_bytes());
    p
}

/// IPv6 + TCP. Same as v4 but 40-byte IP header.
fn build_v6_tcp(payload_len: usize) -> Vec<u8> {
    let total = 40 + 20 + payload_len;
    let mut p = vec![0u8; total];
    // IPv6: ver=6/tc=0/flow=0, plen=20+payload, nh=TCP, hlim=64,
    // src=fe80::1, dst=fe80::2.
    p[0] = 0x60;
    p[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
    p[6] = IPPROTO_TCP;
    p[7] = 64;
    p[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    p[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // TCP at 40..60, same as v4.
    p[40..42].copy_from_slice(&1000u16.to_be_bytes());
    p[42..44].copy_from_slice(&2000u16.to_be_bytes());
    p[44..48].copy_from_slice(&1000u32.to_be_bytes());
    p[52] = 5 << 4;
    p[53] = 0x10 | TCP_FLAG_PSH;
    p[54..56].copy_from_slice(&65535u16.to_be_bytes());
    for b in &mut p[60..] {
        *b = 0xBB;
    }
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &p[8..40], (20 + payload_len) as u16);
    let csum = checksum(&p[40..], pseudo);
    p[56..58].copy_from_slice(&csum.to_be_bytes());
    p
}

fn hdr_v4(gso_size: u16) -> VirtioNetHdr {
    VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
        hdr_len: 40,
        gso_size,
        csum_start: 20,
        csum_offset: TCP_CSUM_OFF as u16,
    }
}

fn hdr_v6(gso_size: u16) -> VirtioNetHdr {
    VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
        hdr_len: 60,
        gso_size,
        csum_start: 40,
        csum_offset: TCP_CSUM_OFF as u16,
    }
}

/// Verify a v4 TCP segment: IP csum valid, TCP csum valid,
/// totlen matches frame, ID = expected, seq = expected.
fn verify_v4_seg(frame: &[u8], expect_id: u16, expect_seq: u32, expect_payload_len: usize) {
    // eth header
    assert_eq!(&frame[12..14], &ETH_P_IP.to_be_bytes());
    let ip = &frame[ETH_HLEN..];
    // IP version + IHL
    assert_eq!(ip[0], 0x45);
    // total len = frame len - eth
    let totlen = u16::from_be_bytes([ip[2], ip[3]]);
    assert_eq!(usize::from(totlen), ip.len());
    assert_eq!(usize::from(totlen), 20 + 20 + expect_payload_len);
    // ID
    assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), expect_id);
    // IP csum: re-verify by re-summing (must be 0 over a valid header).
    // RFC 1071: checksum of a valid header (csum field included) is 0.
    let mut hdr = ip[..20].to_vec();
    let stored = [hdr[10], hdr[11]];
    hdr[10] = 0;
    hdr[11] = 0;
    let recomputed = checksum(&hdr, 0);
    assert_eq!(recomputed.to_be_bytes(), stored, "IPv4 hdr csum");
    // seq
    let seq = u32::from_be_bytes([ip[24], ip[25], ip[26], ip[27]]);
    assert_eq!(seq, expect_seq);
    // TCP csum: pseudo + zero-csum-field-then-sum.
    let mut tcp = ip[20..].to_vec();
    let stored = [tcp[16], tcp[17]];
    tcp[16] = 0;
    tcp[17] = 0;
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &ip[12..20], tcp.len() as u16);
    let recomputed = checksum(&tcp, pseudo);
    assert_eq!(recomputed.to_be_bytes(), stored, "TCP csum");
}

// ─── tso_split: the main cases ─────────────────────────────

/// IPv4, 200 bytes payload, `gso_size=100` → 2 segments of 100.
/// wg-go `offload_linux_test.go:179` "tcp4" case shape.
#[test]
fn split_v4_even() {
    let pkt = build_v4_tcp(200);
    let hdr = hdr_v4(100);
    let mut out = vec![0u8; 4 * 1600];
    let mut lens = [0usize; 4];

    let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
    assert_eq!(n, 2);
    assert_eq!(lens[0], ETH_HLEN + 40 + 100);
    assert_eq!(lens[1], ETH_HLEN + 40 + 100);

    // Seg 0: ID=0x1234, seq=1000, 100 bytes, PSH cleared (not last).
    verify_v4_seg(&out[..lens[0]], 0x1234, 1000, 100);
    assert_eq!(out[ETH_HLEN + 33] & TCP_FLAG_PSH, 0, "PSH cleared seg0");
    assert_eq!(out[ETH_HLEN + 33] & 0x10, 0x10, "ACK kept seg0");

    // Seg 1: ID=0x1235, seq=1100, 100 bytes, PSH KEPT (last).
    verify_v4_seg(&out[1600..1600 + lens[1]], 0x1235, 1100, 100);
    assert_eq!(
        out[1600 + ETH_HLEN + 33] & TCP_FLAG_PSH,
        TCP_FLAG_PSH,
        "PSH kept seg1"
    );

    // Payload bytes intact.
    assert_eq!(out[ETH_HLEN + 40], 0xAA);
    assert_eq!(out[1600 + ETH_HLEN + 40], 0xAA);
}

/// IPv4, 250 bytes, `gso_size=100` → 3 segments: 100, 100, 50.
/// Last segment shorter — the iperf3 trailing-ACK case.
#[test]
fn split_v4_short_tail() {
    let pkt = build_v4_tcp(250);
    let hdr = hdr_v4(100);
    let mut out = vec![0u8; 4 * 1600];
    let mut lens = [0usize; 4];

    let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
    assert_eq!(n, 3);
    assert_eq!(lens[0], ETH_HLEN + 40 + 100);
    assert_eq!(lens[1], ETH_HLEN + 40 + 100);
    assert_eq!(lens[2], ETH_HLEN + 40 + 50);

    verify_v4_seg(&out[..lens[0]], 0x1234, 1000, 100);
    verify_v4_seg(&out[1600..1600 + lens[1]], 0x1235, 1100, 100);
    verify_v4_seg(&out[3200..3200 + lens[2]], 0x1236, 1200, 50);

    // PSH only on last.
    assert_eq!(out[ETH_HLEN + 33] & TCP_FLAG_PSH, 0);
    assert_eq!(out[1600 + ETH_HLEN + 33] & TCP_FLAG_PSH, 0);
    assert_eq!(out[3200 + ETH_HLEN + 33] & TCP_FLAG_PSH, TCP_FLAG_PSH);
}

/// Single chunk: payload ≤ `gso_size` → 1 segment, identical to
/// input (modulo eth header). The "kernel handed us a small
/// packet anyway" case.
#[test]
fn split_v4_single_chunk() {
    let pkt = build_v4_tcp(50);
    let hdr = hdr_v4(100);
    let mut out = vec![0u8; 1600];
    let mut lens = [0usize; 1];

    let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
    assert_eq!(n, 1);
    assert_eq!(lens[0], ETH_HLEN + 40 + 50);
    verify_v4_seg(&out[..lens[0]], 0x1234, 1000, 50);
    // PSH kept (only/last segment).
    assert_eq!(out[ETH_HLEN + 33] & TCP_FLAG_PSH, TCP_FLAG_PSH);
}

/// IPv6: no IP csum, no ID, `payload_len` field instead of totlen.
#[test]
fn split_v6_even() {
    let pkt = build_v6_tcp(200);
    let hdr = hdr_v6(100);
    let mut out = vec![0u8; 4 * 1600];
    let mut lens = [0usize; 4];

    let n = tso_split(&pkt, &hdr, GsoType::TcpV6, &mut out, 1600, &mut lens).unwrap();
    assert_eq!(n, 2);
    assert_eq!(lens[0], ETH_HLEN + 60 + 100);

    // Ethertype = IPv6.
    assert_eq!(&out[12..14], &ETH_P_IPV6.to_be_bytes());
    let ip = &out[ETH_HLEN..ETH_HLEN + 60 + 100];
    // ver=6.
    assert_eq!(ip[0] >> 4, 6);
    // plen = TCP hdr + payload chunk = 20 + 100.
    assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 120);
    // seq = 1000.
    assert_eq!(u32::from_be_bytes([ip[44], ip[45], ip[46], ip[47]]), 1000);
    // TCP csum: verify against pseudo-header.
    let mut tcp = ip[40..].to_vec();
    let stored = [tcp[16], tcp[17]];
    tcp[16] = 0;
    tcp[17] = 0;
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &ip[8..40], 120);
    assert_eq!(checksum(&tcp, pseudo).to_be_bytes(), stored);

    // Seg 1: seq = 1100, plen = 120.
    let ip1 = &out[1600 + ETH_HLEN..1600 + ETH_HLEN + 60 + 100];
    assert_eq!(u16::from_be_bytes([ip1[4], ip1[5]]), 120);
    assert_eq!(
        u32::from_be_bytes([ip1[44], ip1[45], ip1[46], ip1[47]]),
        1100
    );
}

/// Seqno wrap. RFC 793: seqno is mod 2^32. A long-lived flow
/// near the wrap point must not break.
#[test]
fn split_seq_wraps() {
    let mut pkt = build_v4_tcp(200);
    // Set seq to 0xFFFF_FF80 (128 below wrap).
    pkt[24..28].copy_from_slice(&0xFFFF_FF80u32.to_be_bytes());
    let hdr = hdr_v4(100);
    let mut out = vec![0u8; 4 * 1600];
    let mut lens = [0usize; 4];

    let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
    assert_eq!(n, 2);
    // Seg 0: 0xFFFF_FF80.
    let s0 = u32::from_be_bytes([
        out[ETH_HLEN + 24],
        out[ETH_HLEN + 25],
        out[ETH_HLEN + 26],
        out[ETH_HLEN + 27],
    ]);
    assert_eq!(s0, 0xFFFF_FF80);
    // Seg 1: 0xFFFF_FF80 + 100 = 0xFFFF_FFE4.
    let s1 = u32::from_be_bytes([
        out[1600 + ETH_HLEN + 24],
        out[1600 + ETH_HLEN + 25],
        out[1600 + ETH_HLEN + 26],
        out[1600 + ETH_HLEN + 27],
    ]);
    assert_eq!(s1, 0xFFFF_FFE4);
}

// ─── tso_split: error paths ────────────────────────────────

#[test]
fn split_err_too_short() {
    let hdr = hdr_v4(100);
    let mut out = [0u8; 1600];
    let mut lens = [0usize; 1];
    // Can't even read TCP data offset.
    assert_eq!(
        tso_split(&[0x45; 30], &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens),
        Err(TsoError::TooShort)
    );
}

#[test]
fn split_err_bad_tcp_hlen() {
    let mut pkt = build_v4_tcp(100);
    pkt[32] = 3 << 4; // doff=3 → 12 bytes, < 20.
    let hdr = hdr_v4(100);
    let mut out = [0u8; 1600];
    let mut lens = [0usize; 1];
    assert_eq!(
        tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens),
        Err(TsoError::BadTcpHlen)
    );
}

#[test]
fn split_err_ip_mismatch() {
    let pkt = build_v4_tcp(100);
    let hdr = hdr_v6(100); // says v6, packet is v4.
    let mut out = [0u8; 1600];
    let mut lens = [0usize; 1];
    assert_eq!(
        tso_split(&pkt, &hdr, GsoType::TcpV6, &mut out, 1600, &mut lens),
        Err(TsoError::IpVersionMismatch)
    );
}

#[test]
fn split_err_too_many_segments() {
    // 1000 bytes / 100 gso = 10 segments, but only 2 slots.
    let pkt = build_v4_tcp(1000);
    let hdr = hdr_v4(100);
    let mut out = vec![0u8; 2 * 1600];
    let mut lens = [0usize; 2];
    assert_eq!(
        tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens),
        Err(TsoError::TooManySegments)
    );
}

/// `gso_none_checksum`: the partial-csum completion. Build a
/// packet with the pseudo-header sum stuffed into the csum field
/// (what the kernel does), call `gso_none_checksum`, verify the
/// resulting csum is valid.
#[test]
fn gso_none_completes_partial_csum() {
    let mut pkt = build_v4_tcp(100);
    // Replace the valid TCP csum with the pseudo-header sum
    // (what the kernel writes for CHECKSUM_PARTIAL).
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &pkt[12..20], 120);
    // Fold pseudo to 16 bits, NO complement (the kernel writes
    // the un-complemented partial — RFC 1071 chaining).
    let mut p = pseudo;
    p = (p >> 16) + (p & 0xffff);
    p = (p >> 16) + (p & 0xffff);
    pkt[36..38].copy_from_slice(&(p as u16).to_be_bytes());

    gso_none_checksum(&mut pkt, 20, 16);

    // Now the TCP csum should be valid: re-verify.
    let mut tcp = pkt[20..].to_vec();
    let stored = [tcp[16], tcp[17]];
    tcp[16] = 0;
    tcp[17] = 0;
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &pkt[12..20], 120);
    assert_eq!(checksum(&tcp, pseudo).to_be_bytes(), stored);
}

// ─── GRO bucket ─────────────────────────────────────────────────

/// Build N adjacent v4 TCP segments à la what a peer's `tso_split`
/// would emit. seq starts at 1000, each segment carries
/// `seg_len` bytes of `0xAA`, ACK only (no PSH except last).
fn build_v4_segs(n: usize, seg_len: usize, psh_on_last: bool) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let total = 20 + 20 + seg_len;
            let mut p = vec![0u8; total];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[4..6].copy_from_slice(&(0x1234u16.wrapping_add(i as u16)).to_be_bytes());
            p[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            p[8] = 64;
            p[9] = IPPROTO_TCP;
            p[12..16].copy_from_slice(&[10, 0, 0, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
            let csum = checksum(&p[..20], 0);
            p[10..12].copy_from_slice(&csum.to_be_bytes());
            p[20..22].copy_from_slice(&1000u16.to_be_bytes());
            p[22..24].copy_from_slice(&2000u16.to_be_bytes());
            let seq = 1000u32 + (seg_len * i) as u32;
            p[24..28].copy_from_slice(&seq.to_be_bytes());
            p[28..32].copy_from_slice(&42u32.to_be_bytes()); // ack constant
            p[32] = 5 << 4;
            p[33] = TCP_FLAG_ACK
                | if psh_on_last && i == n - 1 {
                    TCP_FLAG_PSH
                } else {
                    0
                };
            p[34..36].copy_from_slice(&65535u16.to_be_bytes());
            for b in &mut p[40..] {
                *b = 0xAA;
            }
            let pseudo =
                pseudo_header_checksum_nofold(IPPROTO_TCP, &p[12..20], (20 + seg_len) as u16);
            let csum = checksum(&p[20..], pseudo);
            p[36..38].copy_from_slice(&csum.to_be_bytes());
            p
        })
        .collect()
}

/// 3 in-order segments → 1 flush. The `vnet_hdr` describes a TSO
/// super; IP totlen/csum updated; payload concatenated.
#[test]
fn gro_coalesce_three_v4() {
    let segs = build_v4_segs(3, 100, false);
    let mut b = GroBucket::new();
    for s in &segs {
        assert_eq!(b.offer(s), GroVerdict::Coalesced);
    }
    let out = b.flush().expect("flush returns the super");

    // vnet_hdr: NEEDS_CSUM, TCPV4, gso_size=100, csum_start=20.
    let hdr = VirtioNetHdr::decode(&out[..VNET_HDR_LEN]).unwrap();
    assert!(hdr.needs_csum());
    assert_eq!(hdr.gso(), Some(GsoType::TcpV4));
    assert_eq!(hdr.gso_size, 100);
    assert_eq!(hdr.csum_start, 20);
    assert_eq!(hdr.csum_offset, 16);

    // IP totlen = 20 + 20 + 300, csum re-verifies.
    let ip = &out[VNET_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([ip[2], ip[3]]), 340);
    let mut h = ip[..20].to_vec();
    let stored = [h[10], h[11]];
    h[10] = 0;
    h[11] = 0;
    assert_eq!(checksum(&h, 0).to_be_bytes(), stored);

    // Payload: 300 bytes of 0xAA.
    assert_eq!(ip.len(), 340);
    assert!(ip[40..].iter().all(|&b| b == 0xAA));

    // TCP csum field is the partial pseudo: completing it
    // (gso_none_checksum semantics) yields a valid full csum.
    // This is what the kernel does on `NEEDS_CSUM` skb intake.
    let mut ip_mut = ip.to_vec();
    gso_none_checksum(&mut ip_mut, 20, 16);
    let mut tcp = ip_mut[20..].to_vec();
    let stored = [tcp[16], tcp[17]];
    tcp[16] = 0;
    tcp[17] = 0;
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &ip_mut[12..20], 320);
    assert_eq!(checksum(&tcp, pseudo).to_be_bytes(), stored);

    assert!(b.is_empty());
}

/// THE roundtrip: `tso_split`'s output, fed to GRO, reassembles
/// the original payload. This is what alice→bob exercises:
/// alice's `tso_split` emits, bob's GRO coalesces, bob's kernel
/// re-splits. If THIS works, the sha256 stream test works.
#[test]
fn gro_reassembles_tso_split_output() {
    // 1400-byte segments, 5 of them. Real iperf3 shape.
    let pkt = build_v4_tcp(5 * 1400);
    let hdr = hdr_v4(1400);
    let mut split_out = vec![0u8; 8 * 1600];
    let mut split_lens = [0usize; 8];
    let n = tso_split(
        &pkt,
        &hdr,
        GsoType::TcpV4,
        &mut split_out,
        1600,
        &mut split_lens,
    )
    .unwrap();
    assert_eq!(n, 5);

    // tso_split puts PSH on the last segment (it was on the
    // input). PSH terminates a GRO run — nothing after it. So
    // 5 segments → still 1 super: the PSH segment is LAST and
    // appends fine; only a SUBSEQUENT offer would FlushFirst.
    let mut b = GroBucket::new();
    for i in 0..n {
        // Strip the synthetic eth header tso_split prepended.
        let frame = &split_out[i * 1600..i * 1600 + split_lens[i]];
        let ip = &frame[ETH_HLEN..];
        assert_eq!(b.offer(ip), GroVerdict::Coalesced, "seg {i}");
    }
    let out = b.flush().unwrap();
    let ip = &out[VNET_HDR_LEN..];
    // Same payload bytes, same length, seq starts at 1000.
    assert_eq!(ip.len(), pkt.len());
    assert_eq!(&ip[40..], &pkt[40..]);
    assert_eq!(u32::from_be_bytes([ip[24], ip[25], ip[26], ip[27]]), 1000);
    // PSH propagated to the super's flags.
    assert_eq!(ip[33] & TCP_FLAG_PSH, TCP_FLAG_PSH);
}

/// Single packet → zero `vnet_hdr`. The miss case (only one
/// packet in the recvmmsg batch matched the flow). The IP
/// packet is passed through verbatim — csum still valid.
#[test]
fn gro_single_packet_zero_vnet_hdr() {
    let segs = build_v4_segs(1, 100, false);
    let mut b = GroBucket::new();
    assert_eq!(b.offer(&segs[0]), GroVerdict::Coalesced);
    let out = b.flush().unwrap();
    assert_eq!(&out[..VNET_HDR_LEN], &[0u8; VNET_HDR_LEN]);
    assert_eq!(&out[VNET_HDR_LEN..], &segs[0][..]);
}

/// Reject criteria. Each is a wg-go check; each is a
/// kernel-contract requirement (`gro.c` selftests).
#[test]
fn gro_rejects() {
    let mut b = GroBucket::new();

    // Non-TCP (proto=UDP).
    let mut p = build_v4_segs(1, 100, false).pop().unwrap();
    p[9] = 17;
    assert_eq!(b.offer(&p), GroVerdict::NotCandidate);

    // FIN set — not a candidate (only ACK or ACK|PSH).
    let mut p = build_v4_segs(1, 100, false).pop().unwrap();
    p[33] |= TCP_FLAG_FIN;
    assert_eq!(b.offer(&p), GroVerdict::NotCandidate);

    // Zero payload (pure ACK).
    let p = build_v4_segs(1, 0, false).pop().unwrap();
    assert_eq!(b.offer(&p), GroVerdict::NotCandidate);

    // Fragmented (MF set).
    let mut p = build_v4_segs(1, 100, false).pop().unwrap();
    p[6] |= 0x20;
    assert_eq!(b.offer(&p), GroVerdict::NotCandidate);

    // IP options (IHL=6).
    let mut p = build_v4_segs(1, 100, false).pop().unwrap();
    p[0] = 0x46;
    assert_eq!(b.offer(&p), GroVerdict::NotCandidate);

    assert!(b.is_empty());
}

/// `FlushFirst` on flow mismatch. Seed with one flow, offer a
/// different ack value (the iperf3-reverse-direction case:
/// data interleaved with the rare ack-carrying-data packet).
#[test]
fn gro_flush_on_mismatch() {
    let segs = build_v4_segs(2, 100, false);
    let mut b = GroBucket::new();
    assert_eq!(b.offer(&segs[0]), GroVerdict::Coalesced);

    // Same everything but ack=43 (was 42). wg-go: separate
    // flow key.
    let mut other = segs[1].clone();
    other[28..32].copy_from_slice(&43u32.to_be_bytes());
    assert_eq!(b.offer(&other), GroVerdict::FlushFirst);

    // After flush, the mismatched packet seeds a new run.
    let _ = b.flush();
    assert_eq!(b.offer(&other), GroVerdict::Coalesced);

    // Seq gap also flushes. Reset, seed seq=1000, offer
    // seq=1200 (skipped 100).
    let _ = b.flush();
    assert_eq!(b.offer(&segs[0]), GroVerdict::Coalesced);
    let mut gap = segs[1].clone();
    gap[24..28].copy_from_slice(&1200u32.to_be_bytes());
    assert_eq!(b.offer(&gap), GroVerdict::FlushFirst);
}

/// PSH terminates the run: nothing appends after.
#[test]
fn gro_psh_terminates() {
    let segs = build_v4_segs(3, 100, false);
    let mut b = GroBucket::new();
    assert_eq!(b.offer(&segs[0]), GroVerdict::Coalesced);
    // PSH on the second.
    let mut psh = segs[1].clone();
    psh[33] |= TCP_FLAG_PSH;
    assert_eq!(b.offer(&psh), GroVerdict::Coalesced);
    // Third can't append (psh_set).
    assert_eq!(b.offer(&segs[2]), GroVerdict::FlushFirst);
}

/// Short tail terminates: 100, 100, 50 → ok; then 100 → flush.
/// GSO is `gso_size`-stride + one short trailer; nothing after.
#[test]
fn gro_short_tail_terminates() {
    let mut b = GroBucket::new();
    let segs100 = build_v4_segs(2, 100, false);
    // Seg at seq=1200, 50 bytes.
    let mut seg50 = build_v4_segs(1, 50, false).pop().unwrap();
    seg50[24..28].copy_from_slice(&1200u32.to_be_bytes());
    // Recompute csums (totlen changed when build used 50,
    // but seq edit invalidated TCP csum).
    let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &seg50[12..20], 70);
    seg50[36] = 0;
    seg50[37] = 0;
    let csum = checksum(&seg50[20..], pseudo);
    seg50[36..38].copy_from_slice(&csum.to_be_bytes());

    assert_eq!(b.offer(&segs100[0]), GroVerdict::Coalesced);
    assert_eq!(b.offer(&segs100[1]), GroVerdict::Coalesced);
    assert_eq!(b.offer(&seg50), GroVerdict::Coalesced);
    // Next 100-byte seg at seq=1250 → short_tail blocks it.
    let mut seg_after = build_v4_segs(1, 100, false).pop().unwrap();
    seg_after[24..28].copy_from_slice(&1250u32.to_be_bytes());
    assert_eq!(b.offer(&seg_after), GroVerdict::FlushFirst);
}

/// 65535 cap → `FlushFirst` when the next append would overflow.
#[test]
fn gro_hits_64k_cap() {
    let mut b = GroBucket::new();
    // 46 × 1400 = 64400 payload + 40 header = 64440 ≤ 65535.
    // 47th × 1400 → 65800 > 65535.
    for i in 0..46 {
        let mut p = build_v4_segs(1, 1400, false).pop().unwrap();
        let seq = 1000u32 + 1400 * i;
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        assert_eq!(b.offer(&p), GroVerdict::Coalesced, "seg {i}");
    }
    let mut p = build_v4_segs(1, 1400, false).pop().unwrap();
    p[24..28].copy_from_slice(&(1000u32 + 1400 * 46).to_be_bytes());
    assert_eq!(b.offer(&p), GroVerdict::FlushFirst);
}
