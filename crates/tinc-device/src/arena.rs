//! `DeviceArena` — fixed-stride slot arena for the 10G datapath.
//!
//! The spine of the GSO/TSO datapath (`RUST_REWRITE_10G.md`):
//!
//! - `Device::drain` reads frames into slots.
//! - The TSO ingest path puts a 64KB super-segment in slot 0
//!   (spilling into 1..N); `tso_split` reads from there.
//! - Fixed stride means slots are independently addressable for
//!   future parallel encrypt (no inter-worker offset coordination).
//! - Page-aligned for `MSG_ZEROCOPY` page-pin should that land —
//!   costs nothing today, avoids rebuilding the arena (and
//!   re-auditing slot lifetimes) later.
//!
//! One allocation, multiple uses. The layout is the design.
//!
//! ## Page alignment
//!
//! `Box<[u8]>` from `vec![].into_boxed_slice()` is malloc-aligned
//! (16B on glibc). `MSG_ZEROCOPY` pins user pages
//! (`Documentation/networking/msg_zerocopy.rst`); a buffer straddling
//! a page boundary works but pins one extra page per straddle, and
//! the page-pin cost is the whole break-even calculation. Aligning
//! the arena to a page boundary makes slot 0 start on a page, which
//! makes the math clean and the perf-analysis tractable.
//!
//! Three options for page-aligned heap:
//!   (a) `std::alloc::alloc(Layout::from_size_align(_, 4096))` — raw
//!       alloc, manual `dealloc` in Drop, `unsafe`.
//!   (b) Over-allocate by `PAGE-1`, find the aligned offset, slice.
//!       No unsafe, but the `Box` owns the unaligned block while we
//!       hand out slices into the middle — Drop is fine, the
//!       arithmetic isn't pretty.
//!   (c) `nix::sys::mman::mmap` anonymous — what malloc does under
//!       the hood for large allocations anyway. Also `unsafe`.
//!
//! We pick **(a)**. It's the smallest unsafe surface (one `alloc`,
//! one matching `dealloc`, both with the same `Layout`), and it's
//! exactly what `Box` does internally — we're just specifying the
//! alignment instead of taking malloc's default. The `unsafe` is
//! scoped to the constructor and Drop; the slot accessors are safe.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;

/// One drain pass result. The daemon dispatches per-RESULT, not
/// per-device — `Linux+vnet_hdr` can yield EITHER on consecutive
/// reads (one TSO super-segment, then a `gso_type==NONE` ARP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    /// `count` independent L3/L2 frames in arena slots `0..count`.
    /// Everything non-TSO. `arena.slot(i)` is the frame; its length
    /// is `arena.lens()[i]`.
    Frames { count: usize },

    /// One TCP super-segment from a TSO-advertising device. The
    /// `virtio_net_hdr` prefix is stripped by the device impl;
    /// `gso_size`/`gso_type` extracted from it. The payload sits in
    /// slot 0 as one IP packet with `total_len > MTU` (up to 65535).
    /// Caller does the userspace TSO-split (portable header
    /// arithmetic — see `tso.rs`).
    ///
    /// Producers: Linux `IFF_VNET_HDR` + `TUNSETOFFLOAD`. FreeBSD
    /// `TAPSVNETHDR` (same `virtio_net_hdr` wire format).
    /// Windows could synthesize from a `WinTun`
    /// ring drain but doesn't today. macOS vmnet is `Frames` (batch,
    /// not super-packet — see `bsd-perf-findings.md`).
    Super {
        /// Length of the IP packet in `as_contiguous()[..len]`. The
        /// `vnet_hdr` prefix is already stripped by the device impl.
        len: usize,
        /// MSS — payload bytes per output segment after `tso_split`.
        gso_size: u16,
        gso_type: GsoType,
        /// `virtio_net_hdr.csum_start`: the L4 header offset (= IP
        /// header length, since TUN has no L2). `tso_split` reads
        /// the TCP header at `pkt[csum_start..]`.
        csum_start: u16,
        /// `virtio_net_hdr.csum_offset`: where the L4 checksum field
        /// sits within the L4 header. 16 for TCP.
        csum_offset: u16,
    },

    /// EAGAIN on the first read. Re-arm the fd and yield.
    Empty,
}

/// `virtio_net_hdr.gso_type` (`include/uapi/linux/virtio_net.h:158`).
/// Only the values we act on. `UdpL4` (`VIRTIO_NET_HDR_GSO_UDP_L4`,
/// kernel 6.2+ `TUN_F_USO`) deferred — only matters for inner-UDP
/// (QUIC), and the gate is iperf3-TCP. Add when someone runs QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsoType {
    /// `VIRTIO_NET_HDR_GSO_NONE`. Pass through; not actually a
    /// super-segment, the device just always prepends the header.
    None,
    /// `VIRTIO_NET_HDR_GSO_TCPV4`.
    TcpV4,
    /// `VIRTIO_NET_HDR_GSO_TCPV6`.
    TcpV6,
}

/// Fixed-stride slot arena. See module doc for the design.
///
/// `STRIDE` = the largest frame the device hands us at MTU 1518.
/// Rounded to 64 (cacheline) so consecutive slots don't false-share
/// if adjacent slots are ever written concurrently.
///
/// Slot 0 doubles as the super-packet buffer for `DrainResult::Super`:
/// a 64KB TSO segment fits because `cap × STRIDE ≥ 65535` for any
/// reasonable `cap` (64 × 1536 = 96KB). The `slot_mut(0)` accessor
/// returns the full STRIDE; the device impl that returns `Super`
/// writes past STRIDE into what would be slots 1..N. That's fine —
/// `Super` and `Frames` are exclusive per drain call.
pub struct DeviceArena {
    /// Page-aligned, `cap * STRIDE` bytes, zero-initialized.
    /// `NonNull` not `*mut` so the struct is `Send` without an
    /// `unsafe impl` (raw pointers are `!Send`; `NonNull` is).
    buf: NonNull<u8>,
    /// `Layout` we passed to `alloc`. Kept for `dealloc` (must
    /// match exactly — alignment included).
    layout: Layout,
    /// Valid bytes in slot `i`. Set by the device on read; read by
    /// the daemon when it walks slots. `Box<[usize]>` not `Vec` —
    /// fixed-size, never grows.
    lens: Box<[usize]>,
    /// Slot count. `lens.len()` would work but having it explicit
    /// makes `super_slot_mut`'s bounds check (`cap * STRIDE`) read
    /// cleanly.
    cap: usize,
}

// SAFETY: `buf` is a heap pointer we exclusively own (no aliasing,
// `&mut self` on every mutator). Same Send-safety argument as
// `Box<[u8]>` — the only difference is we picked the alignment.
#[allow(unsafe_code)]
unsafe impl Send for DeviceArena {}

/// Conventional 4K page. ZC's page-pin granularity. We could
/// `sysconf(_SC_PAGESIZE)` but every Linux/BSD/macOS we care about
/// is 4K (Apple Silicon is 16K — over-aligning to 4K still works,
/// the kernel rounds up; under-aligning would not). Keep it const
/// so `Layout::from_size_align` is infallible at compile-ish time.
const PAGE: usize = 4096;

impl DeviceArena {
    /// Slot stride: `MTU` rounded up to a cacheline. `MTU=1518`
    /// → 1536. The 18 bytes of slack are the SPTPS overhead margin
    /// for in-place encrypt (body+33 fits because body ≤ MTU−14 and
    /// 1518−14+33 = 1537 — one byte over. We round UP to cacheline,
    /// so 1536 < 1537 by one. Bump to 1600 for headroom; still
    /// cacheline-aligned).
    ///
    /// (The "+33" is `mt-kernel-findings.md`'s on-wire overhead:
    /// 12 ids + 4 seqno + 1 type + 16 tag. The encrypt path
    /// currently goes through `tx_scratch`, not the arena — but
    /// rebuilding the arena to change STRIDE means re-auditing
    /// every slot accessor, so the headroom is reserved now.)
    pub const STRIDE: usize = {
        let need = super::MTU + 33; // 1518 + 33 = 1551
        // Round up to cacheline (64). 1551 → 1600.
        (need + 63) & !63
    };

    /// Allocate `cap` slots, page-aligned, zeroed.
    ///
    /// # Panics
    /// On allocation failure (OOM) — same as `Box::new`. Also if
    /// `cap == 0` (can't form a non-empty `Layout`; and a zero-slot
    /// arena is a daemon-setup bug, not a runtime condition).
    #[must_use]
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "DeviceArena: cap must be > 0");
        let size = cap
            .checked_mul(Self::STRIDE)
            .expect("DeviceArena: cap * STRIDE overflows");
        // Round size up to a page so the LAST slot doesn't share a
        // page with whatever malloc puts after us. Matters for
        // `MSG_ZEROCOPY` (kernel pins whole pages; sharing means
        // pinning unrelated allocations).
        let size = (size + PAGE - 1) & !(PAGE - 1);
        let layout = Layout::from_size_align(size, PAGE)
            .expect("DeviceArena: layout invariant (PAGE is power of 2)");
        // SAFETY: `layout.size() > 0` (cap > 0, STRIDE > 0, rounded
        // up). `alloc_zeroed` is the same call `vec![0u8; n]` makes
        // under the hood; we're just picking the alignment.
        #[allow(unsafe_code)]
        let buf = unsafe { alloc_zeroed(layout) };
        let buf = NonNull::new(buf).unwrap_or_else(|| {
            // Match `Box`'s OOM behavior: abort via the std handler.
            std::alloc::handle_alloc_error(layout)
        });
        Self {
            buf,
            layout,
            lens: vec![0usize; cap].into_boxed_slice(),
            cap,
        }
    }

    /// Slot `i`, trimmed to its valid length. `&buf[i*STRIDE ..
    /// i*STRIDE + lens[i]]`. The daemon reads frames from here
    /// after `drain` fills them.
    ///
    /// # Panics
    /// If `i >= cap`.
    #[must_use]
    pub fn slot(&self, i: usize) -> &[u8] {
        let len = self.lens[i]; // bounds check: i < cap
        // SAFETY: `i < cap` (checked above via lens[i]). `len ≤
        // STRIDE` (set_len asserts it). The slice is within the
        // allocation (i*STRIDE + STRIDE ≤ cap*STRIDE ≤ layout.size).
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts(self.buf.as_ptr().add(i * Self::STRIDE), len)
        }
    }

    /// Slot `i`, full STRIDE, for writing. Device `read()` writes
    /// here; `set_len` records the valid prefix.
    ///
    /// # Panics
    /// If `i >= cap`.
    #[must_use]
    pub fn slot_mut(&mut self, i: usize) -> &mut [u8] {
        assert!(
            i < self.cap,
            "DeviceArena::slot_mut: {i} >= cap {}",
            self.cap
        );
        // SAFETY: bounds checked above. `&mut self` excludes aliases.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts_mut(self.buf.as_ptr().add(i * Self::STRIDE), Self::STRIDE)
        }
    }

    /// The whole arena as one slice — for `DrainResult::Super`
    /// (the device writes past slot boundaries) and for TSO ingest
    /// (`tso_split` reads the super-segment from here).
    #[must_use]
    pub const fn as_contiguous(&self) -> &[u8] {
        // SAFETY: the full allocation. `layout.size()` is what we
        // alloc'd; ≥ cap*STRIDE.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts(self.buf.as_ptr(), self.cap * Self::STRIDE)
        }
    }

    /// Mutable whole-arena slice. The `vnet_hdr` device writes a
    /// 64KB super-segment into slot 0's region, spilling
    /// into slots 1..N. `Frames` and `Super` are exclusive per
    /// drain call so there's no overlap with `slot_mut`.
    #[must_use]
    pub const fn as_contiguous_mut(&mut self) -> &mut [u8] {
        // SAFETY: same as `as_contiguous`; `&mut self` excludes.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts_mut(self.buf.as_ptr(), self.cap * Self::STRIDE)
        }
    }

    /// Per-slot valid lengths. The daemon walks `0..count` after
    /// `DrainResult::Frames{count}`.
    #[must_use]
    pub fn lens(&self) -> &[usize] {
        &self.lens
    }

    /// Record the valid length of slot `i`. Called by `drain` after
    /// each `read()` lands.
    ///
    /// # Panics
    /// If `i >= cap` or `len > STRIDE`.
    pub fn set_len(&mut self, i: usize, len: usize) {
        assert!(
            len <= Self::STRIDE,
            "DeviceArena::set_len: {len} > STRIDE {}",
            Self::STRIDE
        );
        self.lens[i] = len;
    }

    /// Slot count.
    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }
}

impl Drop for DeviceArena {
    fn drop(&mut self) {
        // SAFETY: `buf` came from `alloc_zeroed(self.layout)` and
        // we're the sole owner (no clones, no leaks of the pointer).
        // Layout matches exactly — that's why we stored it.
        #[allow(unsafe_code)]
        unsafe {
            dealloc(self.buf.as_ptr(), self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STRIDE arithmetic. `MTU + 33` (SPTPS on-wire overhead from
    /// `mt-kernel-findings.md`) rounded to cacheline. Pin it: if
    /// MTU bumps for jumbo, this fails and points at the layout.
    #[test]
    fn stride_is_mtu_plus_overhead_cacheline_rounded() {
        assert_eq!(DeviceArena::STRIDE, 1600);
        assert_eq!(DeviceArena::STRIDE % 64, 0);
        const { assert!(DeviceArena::STRIDE >= super::super::MTU + 33) };
    }

    /// Page alignment is the whole point of the custom alloc. If
    /// this fails, the `MSG_ZEROCOPY` page-pin math is wrong.
    #[test]
    fn arena_is_page_aligned() {
        let a = DeviceArena::new(64);
        let p = a.as_contiguous().as_ptr() as usize;
        assert_eq!(p % PAGE, 0, "arena base {p:#x} not page-aligned");
    }

    /// Slot accessors: `slot_mut` is full STRIDE, `slot` is trimmed
    /// to `set_len`. The device writes to the former, the daemon
    /// reads the latter.
    #[test]
    fn slot_accessors() {
        let mut a = DeviceArena::new(4);
        assert_eq!(a.cap(), 4);
        // slot_mut returns full stride
        assert_eq!(a.slot_mut(0).len(), DeviceArena::STRIDE);
        assert_eq!(a.slot_mut(3).len(), DeviceArena::STRIDE);
        // write a known pattern, set_len, read back trimmed
        a.slot_mut(1)[..5].copy_from_slice(b"hello");
        a.set_len(1, 5);
        assert_eq!(a.slot(1), b"hello");
        assert_eq!(a.lens()[1], 5);
        // unset slots are len 0
        assert_eq!(a.slot(0), b"");
        assert_eq!(a.slot(2), b"");
    }

    /// Consecutive slots don't overlap. If adjacent slots are ever
    /// written concurrently and they alias, that's UB.
    #[test]
    fn slots_are_disjoint() {
        let a = DeviceArena::new(4);
        let base = a.as_contiguous().as_ptr() as usize;
        for i in 0..4 {
            // Can't call slot_mut here (takes &mut, conflicts with
            // base borrow). Compute offsets directly.
            let slot_start = base + i * DeviceArena::STRIDE;
            let slot_end = slot_start + DeviceArena::STRIDE;
            assert_eq!(slot_start - base, i * DeviceArena::STRIDE);
            // Slot i ends exactly where i+1 starts.
            if i < 3 {
                assert_eq!(slot_end, base + (i + 1) * DeviceArena::STRIDE);
            }
        }
    }

    /// Slot ranges all live inside `as_contiguous`. Callers slice
    /// the contiguous region at slot boundaries; this is the
    /// invariant that makes that valid.
    #[test]
    fn slots_within_contiguous() {
        let mut a = DeviceArena::new(8);
        let whole = a.as_contiguous().as_ptr_range();
        for i in 0..8 {
            let s = a.slot_mut(i).as_ptr_range();
            assert!(whole.start <= s.start);
            assert!(s.end <= whole.end);
        }
    }

    /// `set_len` rejects overflow. A device that returns more than
    /// STRIDE bytes from `read()` (it shouldn't — STRIDE > MTU)
    /// would corrupt the next slot; better to panic at the seam.
    #[test]
    #[should_panic(expected = "STRIDE")]
    fn set_len_rejects_overflow() {
        let mut a = DeviceArena::new(2);
        a.set_len(0, DeviceArena::STRIDE + 1);
    }

    /// Out-of-bounds slot index panics. Same argument as `set_len`:
    /// the daemon iterates `0..count` where `count ≤ cap`; if it
    /// doesn't, that's a bug we want to catch loudly, not a silent
    /// out-of-bounds read.
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn slot_oob_panics() {
        let a = DeviceArena::new(2);
        let _ = a.slot(2);
    }

    /// Drop runs. (Miri catches the leak/double-free if dealloc is
    /// wrong; this test is here so `cargo nextest` exercises the
    /// alloc/dealloc pair under normal builds too.)
    #[test]
    fn drop_runs() {
        for cap in [1, 8, 64, 128] {
            let _ = DeviceArena::new(cap);
        }
    }
}
