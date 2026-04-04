# 10G architecture — reaching 10 Gbps single-flow

**Target**: 10 Gbps single-flow over loopback netns. Phase 0+1 LANDED:
**1391 Mbps** (HEAD `26f9c5ac`, n=4 median, profiling profile, AVX2).
**7.2× to go.**

**Budget**: 10 Gbps ÷ 8 ÷ 1453 B/pkt = 860,000 pkt/s = **1.16 µs/pkt**.
Measured: **8.36 µs/pkt** = 4.66 crypto + 2.76 kernel + 0.94 other.

**TL;DR (recalibrated)**: GSO/TSO + par-enc(8) + ZC ≈ **7.6 Gbps**
(8 cores) / **~9.1 Gbps** (16 cores). The original 12.4G@8c was 1.6×
optimistic — the model **zeroed out the RX path** (TUN write for inner-
TCP ACKs is 1.12 µs/pkt, 41% of remaining kernel time). 10G@8c needs
the ACK-side TUN write batched (GRO coalesce, wg-go `handleGRO`); add
that to Phase 2's scope. 10G@16c is reachable as planned. See
[Model accuracy](#model-accuracy-phase-01-postmortem) below.

---

## The math

| Stack (single-flow, sender side) | µs/pkt pred | µs/pkt **meas** | Mbps pred | Mbps **meas/recalib** | Cores | 10G |
|---|---|---|---|---|---|---|
| Baseline (`28dad75f`) | 9.07 | 9.07 | 1282 | 1282 | 1 | — |
| **Phase 0+1: UDP_SEGMENT (`26f9c5ac`)** | ~7.2 | **8.36** | ~1600 | **1391** | 1 | ❌ |
| Phase 2a: + TSO ingest (orig scope) | 4.86 | — | 2391 | ~1680 | 1 | ❌ |
| Phase 2b: + GRO TUN write (NEW) | — | — | — | ~1970 | 1 | ❌ |
| Phase 3a: + par-enc(4) | 1.79 | — | 6495 | ~4190 | 4 | ❌ |
| Phase 3b: + par-enc(8) + par-dec(4) | 1.25 | — | 9321 | ~6190 | 8 | ❌ |
| Phase 3c: + par-enc(16) | 0.98 | — | 11912 | ~5830 | 16 | ❌ |
| **Phase 4: + MSG_ZEROCOPY (8-core)** | 0.93 | — | **12448** | **~7600** | 8 | ❌ |
| Phase 4: + MSG_ZEROCOPY (16-core) | 0.66 | — | 17544 | **~9100** | 16 | ~ |

**Predictions recomputed from measured Phase-1 baseline.** Original
right-column overshot ~1.6×: the napkin treated alice (sender) as
TX-only, but iperf3 sender also receives ~0.5 ACK/data-pkt and writes
each to the TUN. That's **1.12 µs/pkt of RX kernel** the model put at
zero. Phase 2 needs to batch this side too — see Phase 2b below.

**ZC's leverage shrank.** sendmsg is already amortized to 0.43µs/pkt
(GSO did its job). ZC removes the `copy_from_iter` slice of *that*,
worth ~0.2µs. Still positive ROI but no longer the 1.46× kingmaker;
at the recalibrated Phase-3 endpoint the dominant residuals are
crypto-tail (0.58µs @8c) and `other` (route_packet, hash, the dense-
pack staging memmove).

---

## Phases

### Phase 1: UDP_SEGMENT (cmsg, TX) — ~120 LOC

**Kernel mechanism**: `udp.c:1139-1168` `udp_send_skb`, gso branch.
`cmsg UDP_SEGMENT` per-send (`udp.c:1233-1244`, `__udp_cmsg_send`) —
not setsockopt; tincd talks to many peers on one socket, each with
own PMTU. `UDP_MAX_SEGMENTS = 128` (`include/linux/udp.h:124`).

**SPTPS framing fits**: `seal_data_into` (`state.rs:488`) → on-wire
= `body.len() + 33` (12 ids + 4 seqno + 1 type + 16 tag). Fixed
overhead, no padding. Same-MSS TCP segments → identical encrypted
sizes. Contiguous layout, set `gso_size = body+33`, one `sendmsg`.

**Why first**: testable with existing `on_device_read` 64-read
batch. Feature-detect with `getsockopt(IPPROTO_UDP, UDP_SEGMENT)`.
Kernel ≥4.18 (2018). Fall back to `sendmmsg` if `ENOPROTOOPT`.
Receiver sees identical datagrams either way.

**LANDED (`37bbf165`/`44cb5580`). Measured: 1391 Mbps (+18% over
Phase-0 worktree run, vs +12% predicted).** Findings the model
didn't have:

- **Dense-pack TxBatch, NOT arena slots.** `DeviceArena::STRIDE` is
  1600 (cacheline-round) but the encrypted frame is body+33 ≈ 1519.
  UDP_SEGMENT splits at `gso_size`; an 81-byte gap between fixed
  arena slots would land in the previous datagram's tail. **The
  buffer IS the wire layout.** TxBatch stages at `[count*stride ..
  count*stride+len]` in its own dense Vec. The arena stays
  plaintext-ingest-side (Phase 2 fills it).

- **65535-byte cap, ~43 frames max.** `udp_sendmsg` (`udp.c:1292`)
  rejects `len > 0xFFFF` with `EMSGSIZE` *before* parsing the cmsg —
  the kernel never learns this was a GSO send. Daemon's `EMSGSIZE`
  handler then misinterprets it as path-MTU failure → TCP fallback
  death spiral (gate caught it at 17 Mbps). At MTU+33=1519 the cap
  is ~43 frames. **Observed effective batch: 30:1** (read/sendmsg
  trace ratio) — inner-TCP bursts don't always fill 43.

- **`udp_addr_cached` was never repopulating** (latent ~2% bug). The
  cache write was gated on `udp_addr != Some(peer_addr)`; when gossip
  set `udp_addr = Some(edge_addr)` and the peer then sent from that
  same addr (the common case), the gate was false forever. Every send
  fell to `choose_udp_address` (the 2.18% Vec-alloc cold path). Fix
  bundled in Phase 1. ~5-6pp of the +18% is this, not GSO.

- **Raw libc sendmsg, not nix.** `nix::sendmsg` does `vec![0u8; cap]`
  per call. The cmsg here is a fixed 24-byte `{SOL_UDP, UDP_SEGMENT,
  u16}` — pre-built once, 2-byte gso_size patched per send.

**Errors**: `EMSGSIZE` (`udp.c:1145`) = gso_size > PMTU → retry at
peer's `minmtu`. `EINVAL` (`:1149`) = >128 segs → cap batch.
`EMSGSIZE` from `udp.c:1292` (>65535 total) → cap `BATCH_MAX_BYTES`.

**Ref**: `tailscale:net/batching/conn_linux.go:122` `coalesceMessages`;
Willem's `bec1f6f69736` (876→2139 MB/s, 17× call reduction).

### Phase 2: IFF_VNET_HDR + TUNSETOFFLOAD — ~250 LOC

**Kernel mechanism**: `tun.c:1731,2045` vnet_hdr paths. `set_offload`
(`tun.c:2842`) with `TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6` sets
`NETIF_F_TSO` on the netdev → kernel TCP stops segmenting → one
64KB skb to `tun_put_user`.

**The hard part — userspace TSO-split**: read returns
`[virtio_net_hdr(10B)] ‖ [≤65535B]`. If `gso_type==GSO_TCPV4/6`:
split at `gso_size` boundaries, re-synthesize TCP headers per chunk
(seqno arithmetic, len/csum recompute, IPv4 ID increment, IPv6 ext
hdr preservation). ~200 of the 250 LOC. **wireguard-go `tun_linux.go:
448 gsoSplit` is the reference. Port it carefully.**

**Risk**: MED. Get TCP seqno wrong → silent stream corruption.
Mitigate: feature-gate (`-o ExperimentalGSO=on`), default off until
`tests/netns.rs` runs iperf3 + sha256-of-stream end-to-end.

**Win beyond syscalls**: `route_packet` runs **once** per super-
packet (one IP dst, one trie lookup) instead of ~30×. The 0.94µs
"other" → ~0.56µs (route_packet is ~40% of it; the rest is per-
packet dispatch, hash_one, the dense-pack staging memmove that
doesn't amortize).

**Phase 2b (NEW, scope expansion): GRO TUN write.** Phase-1 profiling
found TUN *write* is 41% of remaining kernel time — alice writes ~0.5
ACKs per data packet to the TUN (delayed-ACK ratio). At 1391 Mbps
that's 168k write()/5s = 1.12µs/data-pkt. Unbatched. wireguard-go
`handleGRO` (`receive.go`) coalesces same-flow inbound packets into
a vnet_hdr super-segment before TUN write — same `virtio_net_hdr`
shape as the ingest side, just outbound. ACKs are 52B same-flow; ~15
coalesce per recvmmsg batch → 1 TUN write. **+50 LOC on top of
`tso_split`, ~1.0 µs/pkt saved.** Without this, Phase 3+4 cap at
~7G @ 8c.

### Phase 3: par-encrypt — ~150 LOC

**The crypto-audit's finding**: `ChaPoly::seal_into` is *already*
`&self` (`chapoly.rs:153`). The `&mut Sptps` is one `outseqno++`.
Split:

```rust
// Serial, ~2 cycles/packet:
let base = tunnel.sptps.outseqno;
tunnel.sptps.outseqno = base.wrapping_add(n_chunks);
let cipher: &ChaPoly = &tunnel.sptps.outcipher;
let stride = body_len + 33;  // dense, NOT DeviceArena::STRIDE

// rayon::scope, embarrassingly parallel:
chunks.par_iter().enumerate().for_each(|(i, body)| {
    let seqno = base.wrapping_add(i as u32);
    cipher.seal_with_seqno(seqno, body, &mut tx_batch[i * stride..]);
});
```

**Phase-1 reality check: workers write into the dense `TxBatch`, NOT
arena slots.** TxBatch stride is `body+33` (variable, computed per
batch from `gso_size`); arena STRIDE is 1600 (fixed). This is HARDER
than the original sketch: workers can't blindly index `[i*1600..]`.
Either (a) precompute the offset slice and `split_at_mut` it N ways
before the rayon scope, or (b) workers compute `i*stride` themselves
(stride is uniform within a batch, so this is fine — the trap is
mixed-MSS batches, which TSO doesn't produce). Option (b) is simpler;
the `&mut tx_batch[..]` aliasing across workers needs `split_at_mut`
regardless.

**API surgery**: `tinc-sptps`: add `Sptps::alloc_seqnos(n) -> u32`
(returns base, bumps internal) + `seal_with_seqno(&self, seqno, ...)`
that doesn't touch outseqno. ~40 LOC, no semantic change. The
`#![forbid(unsafe_code)]` stays.

**par-decrypt mirror** (RX side, bob): same shape. `open_into` is
`&self`; only `replay.check` is `&mut`. Phase-split: parallel
decrypt → serial replay-commit (~10ns × 43). The napkin found this
near-useless at 1.3G ("alice's RX crypto is 4.7%"); **at 10G it's
mandatory** — bob decrypts 10G too.

**Tail latency cost**: frame 0 waits for super-packet read +
TSO-split before encrypt fires. ~50µs added p99. Ping shows it;
TCP doesn't (windowed). Acceptable for a 10G data path.

### Phase 4: MSG_ZEROCOPY — ~150 LOC

**Mechanism**: `setsockopt(SO_ZEROCOPY, 1)` once; `sendmsg(...,
MSG_ZEROCOPY)` per-send. Kernel pins user pages, no `copy_from_iter`.
Completion via `MSG_ERRQUEUE` poll: `sock_extended_err` with
`ee_origin == SO_EE_ORIGIN_ZEROCOPY`, `ee_data` = highest completed
ID, `ee_info` = lowest. Buffer reusable when ID is ack'd.

**Break-even**: kernel `Documentation/networking/msg_zerocopy.rst`
puts it at ~10KB/send. With UDP_SEGMENT we're at ~63KB/send. **6×
over break-even.**

**Buffer lifecycle**: the Phase-1 **dense TxBatch** becomes a *ring*
of 4-8 dense buffers. Buffer N in-flight until errqueue acks ID N.
Par-enc workers write directly into the buffer they're handed at
computed `i*stride` offsets; no post-encrypt memcpy. **Buffer must
stay alive until kernel says so** — bugs here are silent corruption
(kernel reads freed memory). The DeviceArena (ingest side) is
separate and doesn't need ZC plumbing — TUN read isn't ZC-able.

**Errqueue plumbing**: new fd in epoll set, `EPOLLIN` on errqueue.
`recvmsg(MSG_ERRQUEUE)` per fire. ~50 LOC of the 150.

**vs io_uring `IORING_OP_SENDMSG_ZC`**: same ZC math, but
"the CQE is the completion" — no separate errqueue fd, no
`sock_extended_err` parsing. Cleaner. But replaces epoll wholesale
(~800 LOC). **Decision deferred to Phase 4 implementation time**:
if errqueue plumbing turns out clean, ship it. If it's ugly,
io_uring's already-integrated completion is the answer.

---

## What we are NOT building

**Full ctrl/data split (the shared-state audit's straw-man).** ArcSwap
snapshot, DashMap tunnels, MPSC for TCP-fallback, ~2000 LOC. The napkin
showed it's a **0.99× regression on single-flow** — SO_REUSEPORT 4-tuple
hash sends one flow to one socket, you pay sync overhead for nothing.
Guus's 2011 `1.1-threads` branch hit this in 2 days.

The split DOES win at multi-flow (4 data threads × par-enc(4) =
~23 Gbps aggregate, derated). But that's *aggregate*, not the
single-flow target. Revisit when "many slow peers" overtakes "one
fast peer" as the deployment shape — that's a separate gate
(`iperf3 -P 8`).

**SO_BUSY_POLL.** 350µs inter-batch vs <50µs benefit window. Wrong
timescale. Even at 10G with super-packets, ~100µs apart.

**TUN_F_USO4/6.** Only inner-UDP (QUIC). The gate is iperf3-TCP.
TSO4/6 first; USO when someone runs QUIC over the tunnel.

---

## Per-phase validation

| Phase | Success metric | Hardware needed |
|---|---|---|
| 1 ✓ | `TINCD_TRACE=1` sendmsg/read ratio ~30:1 | none (sw GSO works without NIC USO, kernel `10154dbded6d`) |
| 2a | `read()` count drops ~30×; iperf3 + sha256-of-stream end-to-end clean | none |
| 2b | `write()` count drops ~15× (ACK coalesce) | none |
| 3 | `perf` shows chacha across N cores; gate >5 Gbps @ n=4 | 8+ cores |
| 4 | `perf` shows `copy_from_iter` <1%; gate >7 Gbps @ 8c | 8+ cores |

---

## Risk register

| Phase | Risk | Mitigation |
|---|---|---|
| 1 | gso_size ≠ peer PMTU → `EMSGSIZE` | Per-peer cmsg gso_size = `tunnel.minmtu - 33`. Retry-once on EMSGSIZE. |
| 2 | TSO-split header bugs → silent TCP corruption | Feature-gate. wg-go `gsoSplit` as reference. Netns test with sha256(stream). |
| 2 | Mixed-dst super-packets (rare) | TSO produces single-flow only. Non-TSO frames pass through unchanged (`gso_type==NONE`). |
| 3 | rayon dispatch overhead at small N | Threshold: skip rayon below 8 chunks. The overhead is ~5µs; 8 chunks of crypto is ~35µs. |
| 4 | Buffer lifetime bug → kernel reads freed mem | Ring with explicit slot states. ASAN run in CI. Ack-before-reuse invariant. |
| 4 | Errqueue under-polled → ring fills | Poll on every epoll wake. Fallback to non-ZC sendmsg when ring full (graceful degradation). |
| All | Model error in the µs/pkt decomposition | **Profile after every phase.** Phase-1 already found a 1.12µs term the model zeroed. |

---

## Summary

| Phase | LOC | Pred Mbps | **Recalib Mbps** | Σ cores | Risk | Key artifact |
|---|---|---|---|---|---|---|
| 0 seams (drain, UdpEgress) | ~280 | — | LANDED (~1240) | 1 | LOW | DeviceArena (ingest-side) |
| 1 UDP_SEGMENT | ~120 | ~1600 | **LANDED 1391** | 1 | LOW | Dense TxBatch (egress-side) |
| 2a TSO ingest | ~250 | ~2400 | ~1680 | 1 | MED | `gsoSplit` port |
| 2b GRO TUN write (NEW) | ~50 | — | ~1970 | 1 | LOW | `handleGRO` port |
| 3 par-enc + par-dec | ~200 | ~6500 | ~6190 | 8 | LOW | `seal_with_seqno(&self)` |
| 4 MSG_ZEROCOPY | ~150 | ~12400 | **~7600** | 8 | MED | errqueue OR io_uring |
| 4 MSG_ZEROCOPY | | ~17500 | **~9100** | 16 | | |
| **Total** | **~770** | | **~9–10G** | **16** | | |

**The spine is two buffers, not one.** Phase 1 found that
UDP_SEGMENT can't use arena slots (gso_size IS the wire layout;
fixed-STRIDE gaps would corrupt). The `DeviceArena` stays as the
**plaintext ingest side** (drain fills it; Phase 2 TSO super-packets
land in slot 0; Phase 4 ZC pins it for the device-read direction).
The **dense `TxBatch`** is the egress side (Phase-1 GSO writes wire
bytes into it; Phase-3 par-enc workers seal directly into computed
offsets; Phase-4 ZC pins it for the sendmsg direction). Two
allocations, two uses each. The page-alignment requirement holds for
both.

References: full kernel-side analysis at
`/home/joerg/.claude/outputs/mt-kernel-findings.md`; threading
math at `/home/joerg/.claude/outputs/mt-napkin-results.md`;
shared-state inventory at
`/home/joerg/.claude/outputs/mt-shared-findings.md`.

---

## Model accuracy (Phase 0+1 postmortem)

Measured at HEAD `26f9c5ac`, n=4, `--cargo-profile profiling`:

| | n=4 | vs model |
|---|---|---|
| Rust↔Rust | 1391 Mbps (σ=56, median) | model said 1600, **−13%** |
| Rust/C ratio | 138.7% | napkin baseline 119.1% → **+20pp** ✓ |
| crypto% | 55.8% (4.66µs) | model 47.9% (4.34µs) — fraction up because kernel shrank ✓ |
| kernel% | 33.0% (2.76µs) | model 41.4% (3.75µs), **−0.99µs GSO win** ✓ |
| GSO batch ratio | 30.4:1 (trace read/sendmsg) | model assumed 43:1 |
| sendmsg µs/pkt | 0.43 | — |
| TUN read µs/pkt | 1.11 | — |
| **TUN write µs/pkt** | **1.12** | **model: 0. UNMODELED.** |

**Where the model was right.** Kernel shrank ~1µs as predicted (GSO
amortized the sendto entry/skb/stack cost). Crypto absolute cost
stayed flat (~4.5µs) and fraction grew — textbook Amdahl. The +20pp
ratio gain decomposes cleanly: ~7pp Phase-0 drain-loop, ~6pp the
`udp_addr_cached` fix bundled in Phase 1, ~7pp GSO proper.

**Where it was wrong.**

1. **RX path was zeroed out.** The napkin profiled alice as TX-only,
   but the iperf3 sender receives an ACK every ~2 data packets and
   writes each one to the TUN. trace shows 168k `write()` against
   330k `read()` — 0.51 ACK/data-pkt at 4.7µs/call (trace-loaded;
   ~2.6µs clean). That's **1.12 µs/data-pkt** the model put at zero.
   At 10G that's 96% of the 1.16µs budget. **This is why the
   original Phase-4 endpoint overshot 1.6×.** Fix: Phase 2b batches
   the write side too (GRO coalesce → vnet_hdr super-segment → one
   TUN write per ACK burst).

2. **Effective batch is 30:1, not 43:1.** The 65535-byte cap allows
   43 frames at MTU+33, but inner-TCP bursts arrive in clumps that
   don't always fill 43. trace: 330k reads / 10.9k sendmsg = 30.4.
   Amortization math used 43; reality is 30. Minor (≈0.05µs).

3. **`other` doesn't fully amortize.** Model said 0.97→01.0µs→0.02µs
   after Phase 2 (route_packet once per batch). But `other` includes
   hash_one (0.58%), send_sptps_data_relay framing (1.83%), the
   dense-pack staging memmove (1.65%) — those are per-packet.
   Recalibrated: 0.94µs → ~0.56µs. **0.5µs of irreducible userspace
   per packet** is the new floor term.

4. **ZC's payoff shrank.** Original: ZC removes `copy_from_iter` =
   31.5% of wall @ 10G. But that was computed against the *pre-GSO*
   model where sendmsg copy was a big slice. Measured post-GSO:
   sendmsg total is 0.43µs/pkt; copy is ~60% of that ≈ 0.26µs. ZC
   trades it for ~0.05µs page-pin. Net **≈0.2µs saved**, not 0.32µs.
   Still positive; not the 1.46× kingmaker.

**Calibration discipline.** Re-profile after Phase 2 lands. The
recalibrated Phase 3+4 numbers above assume the Phase-2 kernel split
behaves as modeled (TUN read → 1/30, TUN write → 1/15). If GRO
coalescing is worse than 15:1 (ACKs are tiny and may not always be
adjacent in the recvmmsg batch), Phase 3's ceiling drops further.

# OS portability

**Policy**: Linux gets the full GSO/TSO/ZC stack unconditionally.
Non-Linux gets the portable byte-loop. No runtime feature probing,
no Linux-kernel-version fallback ladder.

**Kernel floor**: ≥4.18 (UDP_SEGMENT, MSG_ZEROCOPY — both 2018).
TUN_F_TSO is 2.6.27. TUN_F_USO is 6.2 — only matters for inner-UDP
(QUIC); skip the flag if you want a 4.18 floor.

A 4.14 box that hits `setsockopt(SO_ZEROCOPY)` → `ENOPROTOOPT`
should fail loudly at startup, not silently degrade. That's a
deployment problem ("upgrade your kernel"), not a code path.

```rust
// daemon.rs::setup() — the entire OS dispatch
#[cfg(target_os = "linux")]
let (device, egress) = {
    let dev = tinc_device::linux::TunGso::open(&cfg)?;  // IFF_VNET_HDR + TUNSETOFFLOAD
    let egr = egress::linux::Fast::new(sock)?;          // SO_ZEROCOPY + cmsg UDP_SEGMENT
    (Box::new(dev) as Box<dyn Device>, Box::new(egr) as Box<dyn UdpEgress>)
};
#[cfg(not(target_os = "linux"))]
let (device, egress) = {
    let dev = tinc_device::open(&cfg)?;                 // utun / bsd tun
    let egr = egress::Portable::new(sock);              // sendto loop
    (Box::new(dev) as Box<dyn Device>, Box::new(egr) as Box<dyn UdpEgress>)
};
```

Four lines per OS. No `match caps`.

---

## The two seams (unchanged shape, half the impls)

### `Device::drain` — frames or a super-packet

```rust
// tinc-device/src/lib.rs
pub enum DrainResult<'a> {
    /// N independent frames in arena slots. Everything non-Linux.
    Frames { lens: &'a [usize] },
    /// One TSO super-segment. Linux IFF_VNET_HDR only.
    /// vnet_hdr stripped; gso_size extracted. Caller does
    /// the TCP/IP header-fixup split (portable arithmetic).
    Super { len: usize, gso_size: u16, gso_type: GsoType },
    Empty,
}

pub trait Device: Send {
    fn drain(&mut self, arena: &mut [u8], cap: usize)
        -> io::Result<DrainResult<'_>>;
    // existing fd/iface/mode/mac stay
}
```

| Impl | Compiled on | Returns | LOC |
|---|---|---|---|
| `linux::TunGso` | Linux | `Super` if `gso_type != NONE`, else `Frames` | ~80 |
| **default impl** | everywhere | loop `read()` into arena → `Frames` | ~20 |

The default is the trait's `fn drain() { ... }` body. macOS utun,
FreeBSD tun, mock device all inherit it for free. The byte-pipe
`read()` they already have is the building block.

### `UdpEgress::send_batch` — ship N same-size frames

```rust
// crates/tincd/src/egress.rs
pub struct EgressBatch<'a> {
    pub dst: SocketAddr,
    pub frames: &'a [u8],   // contiguous, count chunks at stride
    pub stride: u16,
    pub count: u16,
    pub last_len: u16,      // ≤ stride (kernel allows shorter trailing seg)
}

pub trait UdpEgress: Send {
    fn send_batch(&mut self, b: &EgressBatch) -> io::Result<()>;
    /// ZC completion poll. Default no-op (Portable doesn't ZC).
    fn poll_completions(&mut self) -> io::Result<usize> { Ok(0) }
}
```

| Impl | Compiled on | `send_batch` | LOC |
|---|---|---|---|
| `linux::Fast` | Linux | `sendmsg(MSG_ZEROCOPY)` + cmsg `UDP_SEGMENT=stride` | ~100 |
| `Portable` | everywhere | `count` × `sendto` | ~15 |

Two impls. The trait exists for the cfg seam, not for runtime
polymorphism. The `Box<dyn>` is one vtable indirect per BATCH
(~20k/s at 10G × 2ns = 0.004% cycles).

---

## What stays portable (the middle, ~450 LOC)

```
DrainResult::Super{buf, gso_size}
  → tso_split(buf, gso_size) -> &mut [&mut [u8]]
       TCP seqno+=gso_size, IPv4 ID++, csum recompute. RFC
       arithmetic — no syscalls, no OS APIs. ~150 LOC.
       wireguard-go gsoSplit is the reference.
  → route_packet(chunks[0]) ONCE  (one IP dst, one trie lookup)
  → tunnel.sptps.alloc_seqnos(n)  (outseqno += n; 5 LOC)
  → rayon: workers seal_with_seqno into arena[i*stride..]
  → egress.send_batch(...)

DrainResult::Frames{lens}
  → today's per-frame loop, sendto replaced by send_batch(count=1)
       (or group same-dst-same-stride runs if you want sendmmsg-
        equivalent on Portable; not free, ~+20 LOC, low value)
```

`tso_split`, the arena, par-enc, the routing — all run on macOS
unchanged. They just never see a `Super` because utun never yields
one. The match arm is dead code on non-Linux; LLVM strips it.

---

## Per-OS ceiling

**Audited** — see "Non-Linux ceilings" below; the initial 1.8 Gbps
guess was wrong. With per-OS batch APIs:

| OS | Device | Egress | Ceiling (8 cores) | Mode |
|---|---|---|---|---|
| **Linux ≥4.18** | `TunGso` | `linux::Fast` (GSO+ZC) | **~12.4 Gbps** | any |
| Windows 10 2004+ | WinTun ring | WSASendMsg+USO | ~6.3 Gbps | any |
| macOS | vmnet@200 | sendmsg_x@256 | ~5.1 Gbps | **switch only** |
| macOS | utun | sendmsg_x | ~3.1 Gbps | router |
| FreeBSD | TAPSVNETHDR | `Portable` | ~3.1 Gbps | **switch only** |
| FreeBSD | if_tun | `Portable` | ~2.2 Gbps | router |

The shared wall: no OS except Linux has userspace zero-copy UDP.
Linux MSG_ZEROCOPY's 1.46× at 10G is unique.

---

## Code layout (revised, smaller)

```
crates/
  tinc-device/
    src/
      lib.rs           # Device trait + DrainResult + default drain()
      linux.rs         # cfg(linux): TunGso (IFF_VNET_HDR, TUNSETOFFLOAD)
      bsd.rs           # cfg(bsd): existing utun, inherits default drain()
      mock.rs          # tests, inherits default drain()
  tincd/
    src/
      egress.rs        # UdpEgress trait + EgressBatch + Portable impl
      egress/
        linux.rs       # cfg(linux): Fast (UDP_SEGMENT + MSG_ZEROCOPY)
      daemon/
        net.rs         # tso_split() — portable, lives next to route_packet
        txpath.rs      # par-enc rayon scope — portable
```

Five files touched, two new. ~550 LOC total (was ~720 with the
fallback ladder). Of that, ~100 is Linux-only.

---

## What this avoids vs the previous draft

The runtime-probing version had four egress impls, a `EgressCaps`
bitflags, `probe_udp_caps()`, and a `match` ladder in setup. ~165
LOC of "what if the kernel is old" handling.

That code defends against a deployment scenario ("modern Linux
binary, ancient kernel") that you'd rather catch at startup with a
clear error than support silently. `setsockopt(SO_ZEROCOPY)` →
`ENOPROTOOPT` → `bail!("kernel ≥4.18 required (UDP_SEGMENT,
MSG_ZEROCOPY); got {}", uname.release)`. One error message, zero
fallback paths.

The C tinc carries fallbacks for kernels back to 2.6; that's why
its `net_packet.c` has `#ifdef HAVE_RECVMMSG` ladders. We're
choosing not to inherit that.

---

# Non-Linux ceilings (audited)

The "1.8 Gbps" portable estimate above was lowballed — nobody
checked. Full audits at `/home/joerg/.claude/outputs/{bsd,win}-perf-
findings.md`. Ceilings recomputed with 8-core par-enc(8), crypto =
0.54 µs:

| OS | Best stack | Gbps | %Linux | LOC | Hard wall |
|---|---|---|---|---|---|
| **Linux** ≥4.18 | GSO+TSO+ZC | **12.4** | 100% | ~550 | (the reference) |
| **Windows** 10 2004+ | WinTun + WSASendMsg+USO | **6.3** | 51% | ~900 | no ZC equivalent |
| **macOS** (switch mode) | vmnet@200 + sendmsg_x@256 | **5.1** | 41% | ~450 | no ZC; switch-mode only |
| **macOS** (router mode) | utun + sendmsg_x | **3.1** | 25% | ~200 | utun has no batch read |
| **FreeBSD** (switch mode) | TAPSVNETHDR + par-enc | **3.1** | 25% | ~300 | no real sendmmsg, no ZC |
| **FreeBSD** (router mode) | par-enc only | **2.2** | 18% | 0 | if_tun has nothing |

**The shared wall**: none of macOS, FreeBSD, or Windows has a
userspace-reachable zero-copy UDP send. Linux MSG_ZEROCOPY's 1.46×
at high throughput is unique. 50-60% of Linux is the realistic
non-Linux ceiling without going kernel-driver (WireGuard-NT, ovpn(4))
or kernel-bypass (netmap, Windows XDP).

## Per-platform notes

### Windows: WinTun is *better* than Linux TUN

WinTun (`api/session.c`) is an mmap'd ring shared with the driver.
`WintunReceivePacket`/`WintunSendPacket` are pure userspace ring ops
— `ReadULongAcquire` on head/tail, no syscall. Under load the
`SetEvent` wakeup never fires (both sides spin). **Zero syscalls on
the TUN side.** Linux `/dev/net/tun` still needs read()/write()
even with vnet_hdr.

The catch: ring slots are `{ULONG size; UCHAR data[]}` interleaved,
ULONG-aligned, must release in order. Can't `RIORegisterBuffer` it
directly. **One memcpy ring→arena is mandatory.** Same copy count
as Linux readv-into-arena, so no penalty — just no bonus.

`UDP_SEND_MSG_SIZE` (Win10 2004+) is the exact `UDP_SEGMENT`
equivalent: `WSASendMsg` cmsg, kernel splits. quinn-udp (`windows.rs`,
~500 LOC) is the clean Rust reference; lift it.

C tinc's `src/windows/device.c` uses TAP-Windows + overlapped
ReadFile (1 syscall + 1 NDIS dispatch per packet) and **drops
packets** when the prior write hasn't completed (single-buffered
OVERLAPPED). The driver WireGuard built WinTun to escape.

**Don't port the C path. Greenfield WinTun + USO.** ~900 LOC,
~6.3 Gbps, separate datapath thread (mio handles meta-TCP only;
WinTun ring + USO are not file descriptors mio understands).

### macOS: vmnet IS batch — C tinc throws it away

`vmnet_read(iface, struct vmpktdesc *packets, int *pktcnt)` —
inout count, batch by design. **C tinc passes `pkt_count=1`**
(`src/bsd/darwin/vmnet.c:80`), then trampolines through a
`socketpair` adding *another* syscall per packet. Worst possible
use of a batch API.

QEMU does it right: `VMNET_PACKETS_LIMIT = 200`. The framework's
hard cap is `VMNET_TOO_MANY_PACKETS = 1008`.

**Gating**: vmnet is L2 (Ethernet bridge). **Switch mode only.**
Router-mode utun has no batch read at all.

`sendmsg_x`/`recvmsg_x` (XNU syscalls 480/481, since 10.10): real
sendmmsg-shaped batch, **but only on connected sockets** —
`uipc_syscalls.c:1895` gates the `sosend_list` fast path on
`SS_ISCONNECTED`. Unconnected = libc loop. tincd's single-socket
model needs per-peer connected sockets.

One red flag: Bun analytics says "macOS 13 hangs with sendmsg_x".
Runtime probe + `dlsym` fallback required.

**wireguard-go on macOS**: `BatchSize() int { return 1 }`. They
never tried. Tailscale's "10 Gbps" is Linux-only.

### FreeBSD: TAPSVNETHDR is the same virtio_net_hdr — SHARE the code

`if_tuntap.c:168`: `TAP_VNET_HDR_CAPS` includes `IFCAP_TSO|IFCAP_LRO`.
The read path prepends `struct virtio_net_hdr` with `gso_type`/
`gso_size` — **identical wire format to Linux IFF_VNET_HDR**. The
Linux `tso_split()` (Phase 2, ~150 LOC) works on FreeBSD unchanged.

**Gating**: `if (l2tun)` — TAP only (`if_tuntap.c:1608`). L3 if_tun
returns ENOTTY. Same as macOS: **switch mode only**.

FreeBSD's `sendmmsg` exists in libc but **is a loop** — no syscall
in `syscalls.master`. Zero amortization. The UDP-side wall stays.

netmap (in-tree since 10.0, mmap'd rings, zero per-packet syscalls)
is the only path past ~3 Gbps on FreeBSD. Separate event model;
~2000 LOC; FreeBSD-only mode. Not now.

OpenVPN's `ovpn(4)` (FreeBSD 14, kernel module) is the white flag:
they couldn't make userspace UDP fast enough, moved encrypt
in-kernel.

## Design implication: `tso_split` is more shared than expected

The Linux Phase-2 `tso_split()` (TCP seqno arithmetic, csum
recompute, IPv4 ID++) takes a `virtio_net_hdr` + super-segment.
**Same input on FreeBSD TAPSVNETHDR.** Same input on Windows if you
do USO ingest (NDIS LSO uses the same offload model). One ~150 LOC
function, three platforms.

The portability seams from above hold:
- **`DrainResult::Super`**: Linux TUN, FreeBSD TAP, (Windows WinTun
  could synthesize it from a ring drain). macOS vmnet is `Frames`
  (batch but not super-packet).
- **`UdpEgress::send_batch`**: Linux UDP_SEGMENT, Windows USO cmsg,
  macOS sendmsg_x (connected), FreeBSD/OpenBSD plain sendto loop.

The trait is now justified by 4 impls, not 2.

## Non-goals (audited and rejected)

| | Why not |
|---|---|
| macOS Skywalk channel | `PRIV_SKYWALK_REGISTER_KERNEL_PIPE` needs Apple-signed entitlement. Bare daemon = `EPERM`. NetworkExtension wrapper is a different product. |
| Windows RIO+USO combo | `RIOSendEx` has a `controlContext` param that *could* carry the USO cmsg. **Zero examples in the wild.** msquic chose WSASendMsg+USO over RIO. Unverified. |
| FreeBSD netmap | Only path past 3G but ~2000 LOC, separate event model. Same shape as Linux AF_XDP, which we also skipped. |
| NetBSD sendmmsg | Real syscall (since 7.0), but NetBSD-at-5-Gbps market rounds to zero. |
