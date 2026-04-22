//! Darwin `recvmsg_x`/`sendmsg_x` batch I/O on the utun kctl socket.
//!
//! XNU facts (xnu-12377, source-verified):
//!
//! - utun is `PF_SYSTEM`/`SOCK_DGRAM`/`PR_ATOMIC`/`SS_ISCONNECTED`.
//! - `UTUN_OPT_MAX_PENDING_PACKETS` (level `SYSPROTO_CONTROL`, opt 16)
//!   defaults to **1**: until raised, the kctl rcvbuf holds a single
//!   packet and `recvmsg_x` can never return more than one. We raise
//!   it in [`super::utun`] right after `connect()`.
//! - `recvmsg_x` on a kctl socket goes through `soreceive_m_list` and
//!   returns up to `min(cnt, kern.ipc.somaxrecvmsgx=256)` packets per
//!   call. `msg_namelen` comes back 0 (kctl has no `PR_ADDR`); the
//!   per-packet length is in the extra `msg_datalen` field. Only
//!   `MSG_DONTWAIT|MSG_NBIO` flags are accepted.
//! - `sendmsg_x` on a connected socket takes the `sendit_x` mbuf-list
//!   fast path: one syscall injects N packets. `msg_name` must be
//!   null/zero.
//! - `readv`/`writev` on utun are single-packet (one mbuf per call);
//!   useless for batching.
//!
//! The struct/FFI here mirrors `tincd::egress::macos`; duplicated
//! rather than shared because `tinc-device` sits below `tincd` in the
//! dep graph and the type is 8 fields of libc primitives.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use super::AF_PREFIX_LEN;
use crate::arena::DeviceArena;
use crate::ether::{ETH_HLEN, from_ip_nibble, set_etherheader};

/// utun read offset: kernel writes `[AF prefix][IP]`; we leave room
/// for the synthetic ether header in front.
const READ_OFFSET: usize = ETH_HLEN - AF_PREFIX_LEN; // = 10

/// `struct msghdr_x` (xnu `bsd/sys/socket_private.h`). LP64 layout
/// matches the kernel user-ABI exactly. Field names verbatim from C
/// for greppability.
#[repr(C)]
#[allow(clippy::struct_field_names)] // verbatim from C for greppability
struct MsghdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    /// `recvmsg_x`: bytes received in this slot. `sendmsg_x`: must be
    /// zero on input.
    msg_datalen: libc::size_t,
}

// SAFETY: declarations match `bsd/sys/socket_private.h` exactly. Both
// symbols are exported unconditionally from libSystem since macOS
// 10.10 (verified via `libSystem.B.tbd`); no `dlsym` needed.
unsafe extern "C" {
    fn recvmsg_x(
        s: libc::c_int,
        msgp: *mut MsghdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const MsghdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;
}

/// Batch stride: how many `msghdr_x` slots to preallocate. Matches
/// `daemon::net::DEVICE_DRAIN_CAP` so one drain call empties one
/// kqueue wake's worth without re-entering the syscall.
const STRIDE: usize = 64;

/// Per-slot write buffer: AF prefix + max IP frame. Rounded to a
/// cacheline so adjacent slots don't false-share.
const WRITE_SLOT: usize = (AF_PREFIX_LEN + crate::MTU + 63) & !63; // 1536

/// Persistent scratch for utun batch I/O. Heap-once, reused warm.
pub(super) struct UtunBatch {
    /// Latched after the first `ENOSYS` so we stop retrying. Never
    /// observed on 10.10+ but the header says "subject to change".
    disabled: bool,
    /// `recvmsg_x`/`sendmsg_x` header array. Reused for both
    /// directions; fully overwritten before every call.
    hdrs: Box<[MsghdrX]>,
    /// One iovec per header.
    iovs: Box<[libc::iovec]>,
    /// Staged outbound frames: `STRIDE × WRITE_SLOT` bytes,
    /// `[AF prefix][IP]` per slot. Heap-once.
    wbuf: Box<[u8]>,
    /// Valid bytes in `wbuf` slot `i`. `wcount` = staged frames.
    wlens: [u16; STRIDE],
    wcount: usize,
}

// SAFETY: raw pointers in `hdrs`/`iovs` are scratch slots fully
// overwritten before every syscall and never read by Rust code; they
// alias only `wbuf`/the caller's arena, both exclusively borrowed at
// call time. `Device: Send` is the bound; the daemon is
// single-threaded so this is belt-only.
unsafe impl Send for UtunBatch {}

impl UtunBatch {
    pub(super) fn new() -> Self {
        // SAFETY: zeroed `msghdr_x`/`iovec` are valid (null pointers,
        // zero lengths) and are fully overwritten before each syscall.
        let hdrs = (0..STRIDE).map(|_| unsafe { std::mem::zeroed() }).collect();
        let iovs = (0..STRIDE).map(|_| unsafe { std::mem::zeroed() }).collect();
        Self {
            disabled: false,
            hdrs,
            iovs,
            wbuf: vec![0u8; STRIDE * WRITE_SLOT].into_boxed_slice(),
            wlens: [0; STRIDE],
            wcount: 0,
        }
    }

    /// `recvmsg_x` drain into `arena`. Mirrors [`crate::drain_via_read`]
    /// but with one syscall for up to `cap` packets.
    ///
    /// Returns `None` to signal "fall back to per-packet `read()`"
    /// (variant != utun, or `ENOSYS` latched). The caller then
    /// delegates to [`crate::drain_via_read`] so behaviour is
    /// byte-identical to the trait default.
    pub(super) fn drain(
        &mut self,
        fd: BorrowedFd<'_>,
        arena: &mut DeviceArena,
        cap: usize,
    ) -> Option<io::Result<crate::DrainResult>> {
        if self.disabled {
            return None;
        }
        let cap = cap.min(arena.cap()).min(STRIDE);

        // One iovec per slot, pointing `READ_OFFSET` bytes into the
        // arena slot so the kernel's `[AF prefix][IP]` lands where
        // `BsdTun::read` would have put it. Raw offsets because
        // borrowing `slot_mut(i)` N times at once would overlap.
        let base = arena.as_contiguous_mut().as_mut_ptr();
        for i in 0..cap {
            // SAFETY: `i < cap ≤ arena.cap()` so
            // `i*STRIDE + READ_OFFSET .. i*STRIDE + STRIDE` is within
            // the arena allocation; `base` is the live `&mut` we just
            // took, exclusively borrowed for the duration of this call.
            self.iovs[i] = libc::iovec {
                iov_base: unsafe { base.add(i * DeviceArena::STRIDE + READ_OFFSET) }.cast(),
                iov_len: DeviceArena::STRIDE - READ_OFFSET,
            };
            self.hdrs[i] = MsghdrX {
                // kctl has no PR_ADDR; kernel writes `msg_namelen=0`
                // back regardless. Passing null avoids the macOS
                // 10.15 `msg_controllen` quirk entirely (we request
                // no cmsgs).
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &raw mut self.iovs[i],
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
        }

        // cap ≤ STRIDE = 64.
        #[allow(clippy::cast_possible_truncation)]
        let cnt = cap as libc::c_uint;
        // SAFETY: `hdrs[..cap]` fully initialised above; each iovec
        // points into the exclusively-borrowed arena. `MSG_DONTWAIT`
        // is one of the two flags `recvmsg_x` accepts.
        let ret = unsafe {
            recvmsg_x(
                fd.as_raw_fd(),
                self.hdrs.as_mut_ptr(),
                cnt,
                libc::MSG_DONTWAIT,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EAGAIN) => Some(Ok(crate::DrainResult::Empty)),
                Some(libc::ENOSYS) => {
                    self.disabled = true;
                    None
                }
                _ => Some(Err(err)),
            };
        }
        // `ret` ≤ cap ≤ STRIDE ≤ usize::MAX. Non-negative checked above.
        #[allow(clippy::cast_sign_loss)]
        let n = ret as usize;
        if n == 0 {
            return Some(Ok(crate::DrainResult::Empty));
        }

        // Post-process exactly as `BsdTun::read` would: synthesize
        // the ether header from the IP version nibble at byte 14
        // (the AF prefix at [10..14] is overwritten by it). Doing it
        // here keeps the daemon's `Frames` arm byte-identical to the
        // per-packet path.
        for i in 0..n {
            // Clamp: xnu sets `msg_datalen` to bytes copied, but be
            // defensive so a future kernel reporting the untruncated
            // length can't trip `set_len`'s `len ≤ STRIDE` assertion.
            let dlen = self.hdrs[i]
                .msg_datalen
                .min(DeviceArena::STRIDE - READ_OFFSET);
            // Runt or non-v4/v6 nibble: zero-length slot. The
            // per-packet path would surface an error here; in a
            // batch we skip so one bad frame doesn't drop the rest.
            if dlen <= AF_PREFIX_LEN {
                arena.set_len(i, 0);
                continue;
            }
            let slot = arena.slot_mut(i);
            let Some(ethertype) = from_ip_nibble(slot[ETH_HLEN]) else {
                log::debug!(target: "tinc::device",
                            "utun recvmsg_x: bad IP nibble {:#x}", slot[ETH_HLEN] >> 4);
                arena.set_len(i, 0);
                continue;
            };
            set_etherheader(slot, ethertype);
            arena.set_len(i, dlen + READ_OFFSET);
        }
        Some(Ok(crate::DrainResult::Frames { count: n }))
    }

    /// Stage one frame for `sendmsg_x`. `buf` is `[eth(14)][IP]` as
    /// produced by the routing layer; we strip to `[AF prefix][IP]`
    /// like [`super::BsdTun::write`] would. Returns `true` if staged,
    /// `false` if the caller should fall back to immediate `write()`
    /// (batching disabled, buffer full, or unmappable ethertype —
    /// the last case lets the per-packet path surface the error).
    pub(super) fn stage(&mut self, buf: &[u8]) -> bool {
        if self.disabled || self.wcount >= STRIDE || buf.len() < ETH_HLEN {
            return false;
        }
        let ip = &buf[ETH_HLEN..];
        if ip.len() > WRITE_SLOT - AF_PREFIX_LEN {
            return false;
        }
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        let Some(prefix) = super::to_af_prefix(ethertype) else {
            return false;
        };
        let len = AF_PREFIX_LEN + ip.len();
        let slot = &mut self.wbuf[self.wcount * WRITE_SLOT..][..len];
        slot[..AF_PREFIX_LEN].copy_from_slice(&prefix);
        slot[AF_PREFIX_LEN..].copy_from_slice(ip);
        // len ≤ WRITE_SLOT = 1536.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.wlens[self.wcount] = len as u16;
        }
        self.wcount += 1;
        true
    }

    /// Ship all staged frames via one `sendmsg_x`. No-op when empty.
    /// On `ENOSYS` latches `disabled` and replays via per-frame
    /// `write(2)` so nothing is lost; on `ENOBUFS`/partial send the
    /// unsent tail is dropped (utun inject is best-effort — same
    /// semantics as a full TUN txq under the per-packet path).
    pub(super) fn flush(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let n = std::mem::take(&mut self.wcount);
        if n == 0 {
            return Ok(());
        }
        let base = self.wbuf.as_ptr();
        for i in 0..n {
            // SAFETY: `i < n ≤ STRIDE` and `wlens[i] ≤ WRITE_SLOT`, so
            // the iovec is within `wbuf`. The kernel only reads
            // through it; const→mut cast is sound.
            self.iovs[i] = libc::iovec {
                iov_base: unsafe { base.add(i * WRITE_SLOT) } as *mut libc::c_void,
                iov_len: usize::from(self.wlens[i]),
            };
            self.hdrs[i] = MsghdrX {
                // Connected kctl: `sendit_x` fast path requires null.
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &raw mut self.iovs[i],
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
        }
        // n ≤ STRIDE = 64.
        #[allow(clippy::cast_possible_truncation)]
        let cnt = n as libc::c_uint;
        // SAFETY: `hdrs[..n]` fully initialised above; each iovec is
        // within `self.wbuf` which we exclusively own. fd is the utun
        // socket borrowed from the owning `BsdTun`.
        let ret = unsafe { sendmsg_x(fd.as_raw_fd(), self.hdrs.as_ptr(), cnt, libc::MSG_DONTWAIT) };
        if ret >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) => {
                self.disabled = true;
                // Replay so this batch isn't lost; subsequent calls
                // go straight to per-packet `write()`.
                for i in 0..n {
                    let off = i * WRITE_SLOT;
                    let len = usize::from(self.wlens[i]);
                    let _ = nix::unistd::write(fd, &self.wbuf[off..off + len]);
                }
                Ok(())
            }
            // sndbuf full: same as per-packet `ENOBUFS` — drop, the
            // inner transport retransmits.
            Some(libc::ENOBUFS | libc::EAGAIN) => Ok(()),
            _ => Err(err),
        }
    }
}
