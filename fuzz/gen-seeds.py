#!/usr/bin/env python3
"""Regenerate fuzz/seeds/<target>/*.bin: minimal well-formed inputs that
get each target past its length and ethertype checks.

The seeds are committed; rerun this only when a harness input format
changes.
"""

import struct
from pathlib import Path

ALICE6 = b"\xfd" + b"\0" * 14 + b"\x01"
BOB6 = b"\xfd" + b"\0" * 14 + b"\x02"
MSS_OPT = b"\x02\x04\x05\xb4\x01\x01\x04\x02"


def csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ip4(proto: int, payload: bytes) -> bytes:
    h = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0x4000,
        64,
        proto,
        0,
        bytes([10, 0, 0, 1]),
        bytes([10, 1, 2, 3]),
    )
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload


def ip6(
    nh: int, payload: bytes, hlim: int = 64, src: bytes = BOB6, dst: bytes = ALICE6
) -> bytes:
    return struct.pack("!IHBB", 6 << 28, len(payload), nh, hlim) + src + dst + payload


def tcp(
    flags: int = 0x02, opts: bytes = b"", payload: bytes = b"", seq: int = 1000
) -> bytes:
    off = (20 + len(opts)) // 4
    return (
        struct.pack("!HHIIBBHHH", 1234, 80, seq, 0, off << 4, flags, 65535, 0, 0)
        + opts
        + payload
    )


def udp(payload: bytes) -> bytes:
    return struct.pack("!HHHH", 5353, 53, 8 + len(payload), 0) + payload


def eth(ethertype: int, dst: bytes = b"\x02\0\0\0\0\x01") -> bytes:
    return dst + b"\x02\0\0\0\0\x02" + struct.pack("!H", ethertype)


def vnet(gso_type: int, hdr_len: int, gso_size: int, csum_start: int) -> bytes:
    return struct.pack("<BBHHHH", 1, gso_type, hdr_len, gso_size, csum_start, 16)


def stream(*packets: bytes) -> bytes:
    return b"".join(struct.pack("<H", len(p)) + p for p in packets)


def u16(v: int) -> bytes:
    return struct.pack("<H", v)


def main() -> None:
    syn4 = eth(0x800) + ip4(6, tcp(opts=MSS_OPT))
    syn6 = eth(0x86DD) + ip6(6, tcp(opts=MSS_OPT))
    vlan = eth(0x8100) + b"\x00\x05\x08\x00" + ip4(6, tcp(opts=MSS_OPT))
    ipip = eth(0x800) + ip4(4, ip4(6, tcp(opts=MSS_OPT)))
    arp = (
        eth(0x806, dst=b"\xff" * 6)
        + struct.pack("!HHBBH", 1, 0x800, 6, 4, 1)
        + b"\x02\0\0\0\0\x02"
        + bytes([10, 0, 0, 1])
        + b"\0" * 6
        + bytes([10, 1, 2, 3])
    )
    solicit = struct.pack("!BBHI", 135, 0, 0, 0) + ALICE6 + b"\x01\x01\x02\0\0\0\0\x02"
    snm = b"\xff\x02" + b"\0" * 9 + b"\x01\xff\0\0\x01"
    ndp = eth(0x86DD) + ip6(58, solicit, hlim=255, dst=snm)

    seg = tcp(flags=0x18, payload=b"y" * 3000)
    a4 = ip4(6, tcp(flags=0x10, payload=b"z" * 1000, seq=1))
    b4 = ip4(6, tcp(flags=0x18, payload=b"z" * 1000, seq=1001))
    a6 = ip6(6, tcp(flags=0x10, payload=b"z" * 1000, seq=1))
    b6 = ip6(6, tcp(flags=0x10, payload=b"z" * 500, seq=1001))

    mtu = u16(1400)
    seeds = {
        "mss_clamp": {
            "syn4": mtu + syn4,
            "syn6": mtu + syn6,
            "vlan": mtu + vlan,
            "ipip": mtu + ipip,
        },
        "route_frame": {
            "syn4": mtu + syn4,
            "syn6": mtu + syn6,
            "udp4": mtu + eth(0x800) + ip4(17, udp(b"abcd")),
            "udp6": mtu + eth(0x86DD) + ip6(17, udp(b"abcd")),
            "arp": mtu + arp,
            "ndp": mtu + ndp,
            "big4": u16(576) + eth(0x800) + ip4(17, udp(b"x" * 1400)),
            "vlan": mtu + vlan,
        },
        "socks_reply": {
            "socks4": bytes([0, 0x5A, 0, 0, 0, 0, 0, 0]),
            "socks5_v4": bytes([5, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 80]),
            "socks5_v6": bytes([5, 0, 5, 0, 0, 4]) + b"\0" * 16 + b"\0\x50",
            "socks5_dom": bytes([5, 0, 5, 0, 0, 3, 3]) + b"abc\0\x50",
        },
        "tso": {
            "v4": vnet(1, 40, 1400, 20) + ip4(6, seg),
            "v6": vnet(4, 60, 1400, 40) + ip6(6, seg),
        },
        "gro": {
            "v4": stream(a4, b4),
            "v6": stream(a6, b6),
            "mixed": stream(a4, a6, b4, b6),
        },
    }
    root = Path(__file__).parent / "seeds"
    for target, files in seeds.items():
        (root / target).mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (root / target / f"{name}.bin").write_bytes(data)


if __name__ == "__main__":
    main()
