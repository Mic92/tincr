//! `SO_ATTACH_REUSEPORT_CBPF`: UDP ingress steering. Unprivileged.
//!
//! ────────────────── Why cBPF, not eBPF `SK_REUSEPORT` ─────────────
//!
//! The plan's `bpf_sk_select_reuseport` + `BPF_MAP_TYPE_SOCKMAP`
//! picks a socket by **explicit fd** stored in a map — bulletproof
//! against reuseport group reordering. But:
//!
//! 1. cBPF return-value-is-index works just as well IF bind order
//!    is deterministic. We open shards in order; `reuse->socks[k]`
//!    IS shard k. Validated 100/100 in shard-proto.
//!
//! 2. cBPF needs **no `bpf()` syscall**, no `CAP_BPF`. The whole
//!    test suite exercises this path, not just the with-root NixOS
//!    VM tests. CI coverage is the deciding factor.
//!
//! 3. The eBPF version's only extra capability is `peer_to_shard`
//!    map updates at runtime (NAT rebind → restee). But the prog
//!    below parses `src_id6` from the SPTPS prefix — that's stable
//!    (`SHA512(name)[:6]`, never changes). NAT rebind doesn't
//!    change which SHARD a peer goes to; only the daemon's
//!    `udp_addr` cache, which is shard-local anyway.
//!
//! So: cBPF, `src_id6` hash, modulo N. Stateless, unprivileged,
//! steers correctly on the first packet.
//!
//! ────────────────── What the prog sees ────────────────────────────
//!
//! `sock_reuseport.c:512` (`run_bpf_filter`): `pskb_pull(skb,
//! hdr_len)` where `hdr_len = sizeof(udphdr) = 8` for UDP
//! (`net/ipv4/udp.c:495`). So `BPF_LD|BPF_ABS` offset 0 is the
//! **first byte of UDP payload**. For tincd: that's `dst_id6[0]`.
//! `src_id6` starts at offset 6.
//!
//! ────────────────── Hash choice ───────────────────────────────────
//!
//! 6 bytes of `src_id6` → shard index. cBPF has 32-bit accumulator,
//! no multiply. Options:
//!
//! - **XOR-fold**: `A = b[6] ^ b[7] ^ b[8] ^ b[9] ^ b[10] ^ b[11]`.
//!   8-bit output, 256 buckets. With N≤8 shards: `% N` distributes
//!   uniformly IF the input is uniform. `src_id6` IS uniform (it's
//!   SHA-512 prefix). 6 instructions.
//!
//! - **Load 4 bytes**: `BPF_LD|BPF_W|BPF_ABS` at offset 6 gives
//!   `src_id6[0..4]` as a big-endian u32 in one insn. Then `% N`.
//!   2 instructions. The high 2 bytes of `src_id6` are unused, but
//!   4 bytes of SHA-512 prefix is still 32 bits of uniform entropy
//!   — way more than enough for `% N` with N≤256.
//!
//! Second option. Two insns: load word, modulo, return. Dead simple.
//!
//! ────────────────── Null `src_id6` (relay path) ───────────────────
//!
//! `NodeId6::NULL` (six zero bytes) marks the relay forwarding path:
//! the relay node forwards without setting `src_id6`. Word at offset 6
//! is `0x00000000` → `0 % N = 0` → shard 0. Shard 0 then does
//! `try_mac` (trial decrypt against every node) — the slow path the
//! id6 prefix exists to avoid. Correct: relay traffic is rare, and
//! shard 0 already handles "unknown stuff" (queue 0 catchall on the
//! TUN side too).
//!
//! ────────────────── Handshake/KEX records ─────────────────────────
//!
//! The first SPTPS handshake datagram doesn't have the 12-byte
//! prefix — it's `[seq:4][type:1][data...]` raw. Word at offset 6
//! reads into the handshake payload, returns garbage % N. **Doesn't
//! matter**: the receiving shard finds no `tunnel.sptps` for that
//! seq, falls back to the daemon's id6-absent path, which DOES work
//! (trial-mac). One garbage steer per handshake; fine.
//!
//! Actually wait — handshake goes over TCP (the meta-conn), not UDP.
//! The first UDP packet is post-KEX, with the 12-byte prefix. Never
//! mind.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use socket2::{Domain, Protocol, Socket, Type};

/// `SO_ATTACH_REUSEPORT_CBPF` — `asm-generic/socket.h:85`. Not in
/// libc 0.2.184.
const SO_ATTACH_REUSEPORT_CBPF: libc::c_int = 51;

// cBPF opcodes — `linux/bpf_common.h`.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00; // 32-bit (note: "W" is 0x00, not 0x18)
const BPF_ABS: u16 = 0x20;
const BPF_ALU: u16 = 0x04;
const BPF_MOD: u16 = 0x90;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_A: u16 = 0x10;

/// Offset in UDP payload where `src_id6` starts. tincd wire format:
/// `[dst_id6:6][src_id6:6][sptps...]` (`net.h:92` `SRCID` macro).
/// The reuseport prog sees post-UDP-header bytes.
const SRC_ID6_OFFSET: u32 = 6;

/// Build and attach the cBPF prog. The `n_shards` divisor is baked
/// into the prog's `MOD` instruction — re-attach on shard count change
/// (which only happens at daemon startup; `TINCD_SHARDS` is read once).
///
/// Attaches to the FIRST socket in the group. The reuseport group
/// shares one prog (`reuseport_attach_prog` stores it on the
/// `sock_reuseport` struct, not per-socket). Socket 0 must already
/// be bound (the group exists at first bind).
///
/// # Errors
///
/// - `EINVAL`: socket not in a reuseport group (forgot `SO_REUSEPORT`
///   before bind).
/// - `ENOMEM`: prog copy alloc failed (3 insns × 8 bytes; won't happen).
///
/// Never `EPERM`: cBPF attach goes through `sk_attach_filter`, the
/// same path as `SO_ATTACH_FILTER` (libpcap, tcpdump). Unprivileged
/// since forever.
#[allow(unsafe_code)]
pub fn attach_reuseport_id6(sock0_fd: BorrowedFd<'_>, n_shards: u32) -> io::Result<()> {
    debug_assert!(n_shards > 0 && n_shards <= 256, "shard count out of range");

    // Three instructions. The kernel's `pskb_pull` already moved
    // past UDP header (sock_reuseport.c:512); offset 6 is src_id6[0].
    //
    // BPF_LD|BPF_W|BPF_ABS: A = ntohl(*(u32*)(pkt + k)). Yes, ntohl —
    // BPF_ABS for word/halfword does network-to-host conversion
    // (`net/core/filter.c:bpf_convert_filter`, the BPF_LD|BPF_W case
    // emits `bswap` on little-endian). For our purpose (modulo) the
    // byte order doesn't matter — `(x % n) == (bswap(x) % n)` is
    // FALSE in general, but the DISTRIBUTION is identical because
    // both `x` and `bswap(x)` are uniform when the input is. We
    // don't care which shard a particular peer lands on, only that
    // it's deterministic and uniform.
    let mut filter = [
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SRC_ID6_OFFSET, // load 4 bytes of src_id6
        },
        libc::sock_filter {
            code: BPF_ALU | BPF_MOD | BPF_K,
            jt: 0,
            jf: 0,
            k: n_shards,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_A,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    // Clippy: `filter.len()` is 3, fits in u16.
    #[allow(clippy::cast_possible_truncation)]
    let fprog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };

    // SAFETY: SO_ATTACH_REUSEPORT_CBPF takes `struct sock_fprog *`.
    // The kernel `copy_bpf_fprog_from_user` reads `sizeof(sock_fprog)`
    // bytes (16: u16 len + pad + ptr), then dereferences `.filter` to
    // read `len * sizeof(sock_filter)` = 24 bytes of instructions.
    // Both `fprog` and `filter` live on our stack and outlive this
    // call. Kernel makes its own copy (`bpf_prog_create_from_user`).
    let ret = unsafe {
        libc::setsockopt(
            sock0_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_ATTACH_REUSEPORT_CBPF,
            (&raw const fprog).cast::<libc::c_void>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t
            },
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// N reuseport sockets, all bound to `addr`, prog attached to socket 0.
/// Socket k receives packets where `src_id6[0..4] % N == k`.
///
/// Consumes `addr` as `(ip, port)` instead of `SocketAddr` to keep
/// `std::net` out of the type signature — `tincd`'s listener setup
/// already has the parts.
///
/// # Errors
///
/// `EADDRINUSE` if `port` is taken by a non-reuseport socket.
/// Propagated from `attach_reuseport_id6` if socket 0's bind didn't
/// create a group (shouldn't happen — we set `SO_REUSEPORT` first).
pub fn open_reuseport_group(ip: std::net::IpAddr, port: u16, n: u32) -> io::Result<ReuseportGroup> {
    debug_assert!(n > 0 && n <= 256);

    let addr = SocketAddr::new(ip, port);
    let mut socks = Vec::with_capacity(n as usize);

    for i in 0..n {
        // Nonblock so the shard's epoll loop doesn't wedge; cloexec so
        // tinc-up scripts don't inherit. Same flags as
        // `tincd::listen::open_udp_listener`. socket2 sets CLOEXEC on
        // Linux by default.
        let sock = Socket::new(
            Domain::for_address(addr),
            Type::DGRAM.nonblocking(),
            Some(Protocol::UDP),
        )?;

        // SO_REUSEPORT before bind. Without it, the second bind fails
        // EADDRINUSE — the option opts the socket into the group at
        // bind time (`reuseport_alloc`, `net/core/sock_reuseport.c`).
        sock.set_reuse_port(true)?;
        sock.bind(&addr.into())?;

        // Attach AFTER socket 0 is bound: the reuseport group doesn't
        // exist until first bind. `reuseport_attach_prog` checks
        // `rcu_dereference(sk->sk_reuseport_cb)` which is set at
        // `reuseport_alloc` (bind time). Attach-before-bind: ENOENT.
        if i == 0 {
            attach_reuseport_id6(sock.as_fd(), n)?;
        }

        socks.push(OwnedFd::from(sock));
    }

    Ok(ReuseportGroup { socks })
}

/// N bound sockets, one per shard. Socket k → shard k. Dropping this
/// closes all sockets (the reuseport group dissolves at last close).
#[derive(Debug)]
pub struct ReuseportGroup {
    /// Index k = shard k. The cBPF prog returns `src_id6[0..4] % N`;
    /// `reuse->socks[that]` is `socks[that]` (bind order).
    pub socks: Vec<std::os::fd::OwnedFd>,
}
