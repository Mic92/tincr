//! Packet compression.
//!
//! Per-packet, hot path. Upstream uses static workspace buffers
//! (`lzo_wrkmem`, `lz4_stream`, `z_stream`); we put them in a struct
//! the daemon owns. Compression level is per-REMOTE-peer (their
//! `Compression = N` config, sent in `ADD_EDGE`), so the struct must
//! handle any level on any call — one workspace per backend.
//!
//! | Level | Backend | C call | Rust |
//! |-------|---------|--------|------|
//! | 0 | none | `memcpy` | `Vec::from` |
//! | 1–9 | zlib | `compress2(..., level)` | `flate2::Compress` (miniz) |
//! | 10 | LZO low | `lzo1x_1_compress` | vendored `minilzo.c` (FFI) |
//! | 11 | LZO hi | `lzo1x_999_compress` | compress stubbed (minilzo lacks `_999`); decompress works |
//! | 12 | LZ4 | `LZ4_compress_fast_extState` | `lz4_flex::block` |
//!
//! Wire-level int is the `compression_level_t` enum verbatim.
//!
//! **zlib one-shot vs streaming**: the C reuses a static `z_stream`
//! with `inflateReset` to skip `inflateInit` per packet. We start with
//! the simple one-shot API. PERF(chunk-10): if iperf3 says zlib alloc
//! shows up, switch to a persistent `flate2::Decompress` here.
//!
//! **LZ4 wire compat**: `LZ4_compress_fast_extState` produces RAW LZ4
//! block format — no frame header, no length prefix. `lz4_flex::
//! block::compress` matches. Do NOT use `compress_prepend_size`; that
//! prepends a u32 the C side won't expect.
//!
//! **LZO via vendored minilzo**: not pure Rust. We compile
//! `minilzo/minilzo.c` (`build.rs` + `cc` crate) and call it through
//! FFI. The pure-Rust LZO ports are of unknown provenance and LZO is
//! the tinc 1.0 DEFAULT — wire-compat is non-negotiable, so we link
//! the exact same C the C tinc links. minilzo only ships
//! `lzo1x_1_compress` (level 10), not `lzo1x_999_compress` (level
//! 11); the latter stays stubbed. Decompress uses the shared
//! `lzo1x_decompress_safe` for both — same wire format — so we can
//! RECEIVE level-11 packets, just not SEND them. Asymmetric is fine:
//! we advertise our compression in `ANS_KEY`; if we want `LzoLo`, peer
//! sends `LzoLo`.

// Not `forbid`: the lzo module needs `unsafe` for FFI to vendored C.
// All other code in this file remains safe; the unsafe is scoped to
// the `extern "C"` calls inside `mod lzo`, behind safe wrappers that
// maintain the invariants (non-null pointers, valid lengths,
// init-once).
#![deny(unsafe_code)]

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

/// `compression_level_t` (`compression.h`). Wire-level int.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Level {
    None = 0,
    Zlib1 = 1,
    Zlib2 = 2,
    Zlib3 = 3,
    Zlib4 = 4,
    Zlib5 = 5,
    Zlib6 = 6,
    Zlib7 = 7,
    Zlib8 = 8,
    Zlib9 = 9,
    LzoLo = 10,
    LzoHi = 11,
    Lz4 = 12,
}

impl Level {
    /// Parse the wire-level int. >12 → `None` (unknown level silently
    /// degrades to no-op — same as C: the dispatch switch's `default:
    /// return 0` makes the caller log "compression failed" and fall
    /// back to raw, but we map unknown to `None` so it doesn't even
    /// hit the failure path on inbound).
    #[must_use]
    pub const fn from_wire(n: u8) -> Self {
        match n {
            1 => Self::Zlib1,
            2 => Self::Zlib2,
            3 => Self::Zlib3,
            4 => Self::Zlib4,
            5 => Self::Zlib5,
            6 => Self::Zlib6,
            7 => Self::Zlib7,
            8 => Self::Zlib8,
            9 => Self::Zlib9,
            10 => Self::LzoLo,
            11 => Self::LzoHi,
            12 => Self::Lz4,
            _ => Self::None,
        }
    }

    /// zlib compression level (1–9) if this is a zlib variant.
    const fn zlib_level(self) -> Option<u32> {
        match self {
            Self::Zlib1 => Some(1),
            Self::Zlib2 => Some(2),
            Self::Zlib3 => Some(3),
            Self::Zlib4 => Some(4),
            Self::Zlib5 => Some(5),
            Self::Zlib6 => Some(6),
            Self::Zlib7 => Some(7),
            Self::Zlib8 => Some(8),
            Self::Zlib9 => Some(9),
            _ => None,
        }
    }
}

/// Per-daemon compression workspace.
///
/// `lz4_flex::block` is stateless, `flate2` is one-shot per call. LZO
/// needs `LZO1X_1_MEM_COMPRESS` bytes of scratch (~128KB on 64-bit);
/// we lazy-allocate on first LZO compress so daemons that never
/// negotiate LZO pay nothing. The C's static `z_stream` reuse is a
/// micro-opt we defer.
#[derive(Debug, Default)]
pub struct Compressor {
    /// `lzo_wrkmem` (`tincd.c`: static `lzo_align_t lzo_wrkmem[...]`).
    /// Lazy: `None` until first `LzoLo` compress. Boxed because 128KB
    /// on the stack is too much. `lzo_align_t` is a max-align union
    /// in C; Vec's heap allocation is sufficiently aligned (the
    /// global allocator returns at least `align_of::<usize>()`, and
    /// minilzo only stores pointer-sized dict entries).
    lzo_wrkmem: Option<Vec<u8>>,
}

impl Compressor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compress a packet. Returns `None` on backend failure (lib error, or backend
    /// stubbed). C returns 0; the caller compares `complen <
    /// origlen` and falls back to uncompressed when compression
    /// didn't help. We don't compare here — that's the caller's job —
    /// so this CAN return `Some(v)` with `v.len() > src.len()` for
    /// incompressible input.
    #[must_use]
    pub fn compress(&mut self, src: &[u8], level: Level) -> Option<Vec<u8>> {
        match level {
            Level::None => Some(src.to_vec()),

            Level::Lz4 => {
                // lz4_flex::block::compress is infallible: worst case
                // it emits literals + overhead. Matches C's
                // LZ4_compress_fast_extState which only returns 0 if
                // dest is too small — we size dest to the bound.
                Some(lz4_flex::block::compress(src))
            }

            Level::LzoLo => {
                lzo::ensure_init();
                let wrkmem = self
                    .lzo_wrkmem
                    .get_or_insert_with(|| vec![0u8; lzo::LZO1X_1_MEM_COMPRESS]);
                lzo::compress_1(src, wrkmem)
            }

            Level::LzoHi => {
                // NOT-PORTING(lzo-999): minilzo doesn't include
                // lzo1x_999_compress. The full lzo2 library has it;
                // nobody cares. Decompress works
                // (same _safe fn, same wire format) so we can receive
                // level-11 from a C peer; we just can't send it.
                // Returning None mirrors C built without HAVE_LZO:
                // caller logs "compression failed" and sends raw.
                None
            }

            _ => {
                let zlevel = level.zlib_level()?;
                compress_zlib(src, zlevel)
            }
        }
    }

    /// Decompress a packet. `level` is the SENDER's level (we know it from their
    /// `ADD_EDGE`). `max_len` is the dest buffer cap — for LZ4 it's
    /// the only sizing hint (C's `LZ4_decompress_safe(src, dest,
    /// srclen, destlen)` has no length prefix); for zlib it's the
    /// inflate bound.
    ///
    /// Returns `None` on corrupt input or backend stubbed. Never
    /// panics on garbage.
    #[must_use]
    #[allow(clippy::unused_self)] // becomes &mut when state lands
    pub fn decompress(&mut self, src: &[u8], level: Level, max_len: usize) -> Option<Vec<u8>> {
        match level {
            Level::None => {
                if src.len() <= max_len {
                    Some(src.to_vec())
                } else {
                    None
                }
            }

            Level::Lz4 => {
                // Raw block decode, no length prefix. Matches
                // LZ4_decompress_safe wire format. Err on corrupt
                // input or output > max_len.
                lz4_flex::block::decompress(src, max_len).ok()
            }

            Level::LzoLo | Level::LzoHi => {
                // Same _safe decompressor for both: lzo1x_1 and
                // lzo1x_999 share a wire format.
                lzo::ensure_init();
                lzo::decompress_safe(src, max_len)
            }

            _ => {
                // All zlib levels decompress identically — level only
                // affects the encoder.
                decompress_zlib(src, max_len)
            }
        }
    }
}

/// `compress2(dest, &len, src, srclen, level)` — one-shot zlib
/// (deflate + zlib wrapper). `flate2::Compress` with `zlib_header =
/// true` matches the wire format. miniz output bytes differ from real
/// zlib but cross-decompress (both implement RFC 1950).
fn compress_zlib(src: &[u8], level: u32) -> Option<Vec<u8>> {
    let mut c = Compress::new(Compression::new(level), true);
    // compressBound: srclen + srclen/1000 + 12 (zlib manual). flate2
    // has no bound fn; this matches the C's bound + slack.
    let bound = src.len() + src.len() / 1000 + 64;
    let mut out = Vec::with_capacity(bound);
    match c.compress_vec(src, &mut out, FlushCompress::Finish) {
        Ok(Status::StreamEnd) => Some(out),
        _ => None,
    }
}

/// `inflate(..., Z_FINISH)` one-shot. The C uses a static `z_stream`
/// with `inflateReset`; we re-init per call. PERF(chunk-10).
fn decompress_zlib(src: &[u8], max_len: usize) -> Option<Vec<u8>> {
    let mut d = Decompress::new(true);
    let mut out = Vec::with_capacity(max_len);
    // decompress_vec grows up to capacity. One Finish call: the
    // packet is complete or corrupt.
    match d.decompress_vec(src, &mut out, FlushDecompress::Finish) {
        Ok(Status::StreamEnd) => Some(out),
        // BufError / Ok mean "need more output space" or "need more
        // input" — for a one-shot complete packet that's corruption
        // or oversize. C's `inflate(..., Z_FINISH) == Z_STREAM_END`
        // is the same gate.
        _ => None,
    }
}

/// FFI to vendored `minilzo/minilzo.c` (built via `build.rs`).
///
/// `lzo_uint` is defined in `lzoconf.h` to match `size_t` on every
/// supported platform (LLP64 → u64, LP64 → unsigned long → u64,
/// ILP32 → unsigned long → u32). Rust `usize` is exactly that.
/// `__lzo_init_v2` runtime-checks these sizeof assumptions and
/// returns non-zero on mismatch; `ensure_init` asserts on it.
#[allow(unsafe_code)]
mod lzo {
    use std::ffi::{c_int, c_long, c_short, c_uint};
    use std::mem::size_of;
    use std::sync::Once;

    /// `minilzo.h:76`: `16384L * lzo_sizeof_dict_t` where
    /// `lzo_sizeof_dict_t = sizeof(lzo_bytep) = sizeof(char*)`.
    pub const LZO1X_1_MEM_COMPRESS: usize = 16384 * size_of::<*const u8>();

    const LZO_E_OK: c_int = 0;
    /// `lzoconf.h:32`: 2.10.
    const LZO_VERSION: c_uint = 0x20a0;

    unsafe extern "C" {
        fn lzo1x_1_compress(
            src: *const u8,
            src_len: usize,
            dst: *mut u8,
            dst_len: *mut usize,
            wrkmem: *mut u8,
        ) -> c_int;

        fn lzo1x_decompress_safe(
            src: *const u8,
            src_len: usize,
            dst: *mut u8,
            dst_len: *mut usize,
            wrkmem: *mut u8, // unused, may be null
        ) -> c_int;

        /// `lzo_init()` is a macro wrapping this. First arg is
        /// `LZO_VERSION` (unsigned), the rest are `(int)sizeof(...)`
        /// for short, int, long, `lzo_uint32_t`, `lzo_uint`, `dict_t`,
        /// char*, void*, `lzo_callback_t` — runtime ABI check.
        fn __lzo_init_v2(
            v: c_uint,
            s_short: c_int,
            s_int: c_int,
            s_long: c_int,
            s_u32: c_int,
            s_lzo_uint: c_int,
            s_dict: c_int,
            s_charp: c_int,
            s_voidp: c_int,
            s_callback: c_int,
        ) -> c_int;
    }

    /// `lzoconf.h:284`: `struct lzo_callback_t` is 3 function
    /// pointers + 1 `lzo_voidp` + 2 `lzo_xint` (= `lzo_uint` since
    /// `LZO_SIZEOF_LZO_INT >= 4` on every platform we target). All
    /// six fields are pointer-sized. We never construct one — only
    /// `sizeof` matters for the init check.
    #[repr(C)]
    struct LzoCallback {
        nalloc: *const u8,
        nfree: *const u8,
        nprogress: *const u8,
        user1: *const u8,
        user2: usize,
        user3: usize,
    }

    static INIT: Once = Once::new();

    /// `lzo_init()` macro (`lzoconf.h:336-339`) expanded. Must be
    /// called once before any other LZO function. Panics on ABI
    /// mismatch — that's a build/porting bug, not a runtime
    /// condition.
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)] // size_of: all <16; LZO ABI wants c_int
    pub fn ensure_init() {
        INIT.call_once(|| {
            // SAFETY: pure function, no preconditions. The whole
            // point is to verify the sizeof constants we pass match
            // what minilzo.c was compiled with.
            let r = unsafe {
                __lzo_init_v2(
                    LZO_VERSION,
                    size_of::<c_short>() as c_int,
                    size_of::<c_int>() as c_int,
                    size_of::<c_long>() as c_int,
                    size_of::<u32>() as c_int,       // lzo_uint32_t
                    size_of::<usize>() as c_int,     // lzo_uint == size_t
                    size_of::<*const u8>() as c_int, // lzo_sizeof_dict_t
                    size_of::<*const u8>() as c_int, // char *
                    size_of::<*const ()>() as c_int, // lzo_voidp
                    size_of::<LzoCallback>() as c_int,
                )
            };
            assert_eq!(r, LZO_E_OK, "lzo_init failed (ABI mismatch): {r}");
        });
    }

    /// `lzo1x_1_compress`. Worst-case output is
    /// `src_len + src_len/16 + 64 + 3` (LZO docs). Never fails when
    /// the dest buffer is sized to that bound — but we still gate on
    /// `LZO_E_OK` for paranoia.
    pub fn compress_1(src: &[u8], wrkmem: &mut [u8]) -> Option<Vec<u8>> {
        debug_assert!(wrkmem.len() >= LZO1X_1_MEM_COMPRESS);
        let bound = src.len() + src.len() / 16 + 64 + 3;
        let mut out = vec![0u8; bound];
        let mut out_len: usize = bound;
        // SAFETY: src/out/wrkmem are valid for their stated lengths
        // (slice → ptr+len). out_len is initialized to the dest
        // capacity. wrkmem is at least LZO1X_1_MEM_COMPRESS bytes.
        // ensure_init() has been called by the caller.
        let r = unsafe {
            lzo1x_1_compress(
                src.as_ptr(),
                src.len(),
                out.as_mut_ptr(),
                &raw mut out_len,
                wrkmem.as_mut_ptr(),
            )
        };
        if r == LZO_E_OK && out_len <= bound {
            out.truncate(out_len);
            Some(out)
        } else {
            None
        }
    }

    /// `lzo1x_decompress_safe`. The `_safe` variant bounds-checks; the non-safe one trusts input lengths.
    /// Ours come from the wire — MUST use `_safe`.
    pub fn decompress_safe(src: &[u8], max_len: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; max_len];
        let mut out_len: usize = max_len;
        // SAFETY: src/out are valid for their stated lengths.
        // out_len is the dest capacity on entry, written length on
        // exit. wrkmem is documented "NOT USED" — null is fine.
        // ensure_init() has been called by the caller.
        let r = unsafe {
            lzo1x_decompress_safe(
                src.as_ptr(),
                src.len(),
                out.as_mut_ptr(),
                &raw mut out_len,
                std::ptr::null_mut(),
            )
        };
        if r == LZO_E_OK && out_len <= max_len {
            out.truncate(out_len);
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `02ab` → `[0x02, 0xab]`. KAT helper.
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Cheap deterministic "random" — xorshift32. Avoids a dev-dep.
    fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                (s & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn none_is_memcpy() {
        let mut c = Compressor::new();
        let src = b"hello world";
        assert_eq!(c.compress(src, Level::None).unwrap(), src);
        assert_eq!(c.decompress(src, Level::None, 100).unwrap(), src);
    }

    #[test]
    fn none_decompress_respects_max_len() {
        let mut c = Compressor::new();
        let src = b"hello world";
        assert!(c.decompress(src, Level::None, 5).is_none());
        assert_eq!(c.decompress(src, Level::None, 11).unwrap(), src);
    }

    #[test]
    fn zlib_roundtrip_level_6() {
        let mut c = Compressor::new();
        let src = pseudo_random(1024, 0xdead_beef);
        let comp = c.compress(&src, Level::Zlib6).unwrap();
        let dec = c.decompress(&comp, Level::Zlib6, 2048).unwrap();
        assert_eq!(dec, src);
    }

    #[test]
    fn zlib_all_levels() {
        let mut c = Compressor::new();
        // Compressible input: repeated pattern. Higher levels should
        // produce ≤ lower-level output (or equal — small inputs may
        // hit the same encoding).
        let src: Vec<u8> = b"the quick brown fox "
            .iter()
            .copied()
            .cycle()
            .take(1024)
            .collect();
        let mut prev_len = usize::MAX;
        for n in 1u8..=9 {
            let level = Level::from_wire(n);
            let comp = c.compress(&src, level).unwrap();
            assert!(
                comp.len() <= prev_len,
                "level {n} produced {} bytes, prev was {prev_len}",
                comp.len()
            );
            prev_len = comp.len();
            let dec = c.decompress(&comp, level, 2048).unwrap();
            assert_eq!(dec, src, "level {n} round-trip mismatch");
        }
        // Level 9 on 1KB of 20-byte repeats should compress hard.
        assert!(prev_len < 100, "level 9 only got down to {prev_len}");
    }

    #[test]
    fn lz4_roundtrip() {
        let mut c = Compressor::new();
        let src = pseudo_random(1024, 0xcafe_babe);
        let comp = c.compress(&src, Level::Lz4).unwrap();
        let dec = c.decompress(&comp, Level::Lz4, 2048).unwrap();
        assert_eq!(dec, src);
    }

    #[test]
    fn lzo_lo_compresses() {
        // Repeating pattern: must shrink. lzo1x is fast but not
        // dense; a 20-byte pattern repeated 50× should still
        // compress to a fraction.
        let mut c = Compressor::new();
        let src: Vec<u8> = b"the quick brown fox "
            .iter()
            .copied()
            .cycle()
            .take(1024)
            .collect();
        let comp = c.compress(&src, Level::LzoLo).unwrap();
        assert!(
            comp.len() < src.len(),
            "LZO didn't compress 1KB of repeats: {} bytes",
            comp.len()
        );
        let dec = c.decompress(&comp, Level::LzoLo, 2048).unwrap();
        assert_eq!(dec, src);
    }

    #[test]
    fn lzo_lo_random_roundtrip() {
        // Incompressible input: output may grow (lzo1x adds a few
        // bytes of overhead for literals) but MUST roundtrip.
        let mut c = Compressor::new();
        let src = pseudo_random(1024, 0xfee1_dead);
        let comp = c.compress(&src, Level::LzoLo).unwrap();
        let dec = c.decompress(&comp, Level::LzoLo, 2048).unwrap();
        assert_eq!(dec, src);
    }

    #[test]
    fn lzo_hi_compress_stub_decompress_works() {
        // Asymmetric: minilzo lacks lzo1x_999_compress so LzoHi
        // compress is stubbed (None), but decompress uses the SAME
        // lzo1x_decompress_safe as LzoLo (shared wire format). We
        // can RECEIVE level-11 from a C peer; we just can't SEND it.
        // This is fine — compression level is per-direction: we
        // advertise OUR level in ANS_KEY, peer compresses outbound
        // to us with whatever THEY choose. We must decompress
        // anything; we may compress with anything we have.
        let mut c = Compressor::new();
        let src = b"Hello, world! Hello, world! Hello, world!";
        assert!(c.compress(src, Level::LzoHi).is_none());
        // lzo1x_1 output is valid lzo1x — decompresses under either
        // level label.
        let comp = c.compress(src, Level::LzoLo).unwrap();
        let dec = c.decompress(&comp, Level::LzoHi, 100).unwrap();
        assert_eq!(dec, src);
    }

    #[test]
    fn lzo_decompress_garbage_is_none() {
        // _safe variant must reject corrupt input, not crash.
        let mut c = Compressor::new();
        let garbage = [0xffu8; 100];
        assert!(c.decompress(&garbage, Level::LzoLo, 1000).is_none());
        assert!(c.decompress(&[], Level::LzoLo, 1000).is_none());
    }

    #[test]
    fn lzo_compress_empty() {
        // Edge: zero-length input. lzo1x_1 produces a tiny
        // end-of-stream marker.
        let mut c = Compressor::new();
        let comp = c.compress(&[], Level::LzoLo).unwrap();
        let dec = c.decompress(&comp, Level::LzoLo, 10).unwrap();
        assert_eq!(dec, Vec::<u8>::new());
    }

    #[test]
    fn unknown_level_is_none() {
        assert_eq!(Level::from_wire(99), Level::None);
        assert_eq!(Level::from_wire(13), Level::None);
        assert_eq!(Level::from_wire(255), Level::None);
    }

    #[test]
    fn from_wire_all_known() {
        // Round-trip the enum → u8 → enum for every defined value.
        for n in 0u8..=12 {
            let level = Level::from_wire(n);
            assert_eq!(level as u8, n);
        }
    }

    #[test]
    fn decompress_garbage_is_none() {
        // Corrupt input must return None, not panic. Untrusted data
        // from the network hits this path.
        let mut c = Compressor::new();
        let garbage = [0xffu8; 100];
        assert!(c.decompress(&garbage, Level::Zlib6, 1000).is_none());
        assert!(c.decompress(&garbage, Level::Lz4, 1000).is_none());
        // Empty input too.
        assert!(c.decompress(&[], Level::Zlib6, 1000).is_none());
        assert!(c.decompress(&[], Level::Lz4, 1000).is_none());
    }

    #[test]
    fn compress_incompressible() {
        // Random bytes don't compress. Output may be LARGER than
        // input (deflate/LZ4 add overhead). The C returns the larger
        // size; the CALLER compares `complen < origlen` before using
        // it. We must not return None just because it grew.
        let mut c = Compressor::new();
        let src = pseudo_random(256, 0x1234_5678);
        let z = c.compress(&src, Level::Zlib6).unwrap();
        let l = c.compress(&src, Level::Lz4).unwrap();
        // Don't assert they grew (might get lucky), just that they
        // succeeded and round-trip.
        assert_eq!(c.decompress(&z, Level::Zlib6, 512).unwrap(), src);
        assert_eq!(c.decompress(&l, Level::Lz4, 512).unwrap(), src);
    }

    /// Cross-impl KAT: real zlib's `compress2(..., 6)` output, fed to
    /// our miniz-backed decompressor. Proves wire compat with C tinc
    /// peers. Generated by `/tmp/compress-kat.c` (see task spec).
    ///
    /// miniz and zlib produce DIFFERENT compressed bytes for the same
    /// input (different match-finders), but both decode each other —
    /// deflate is a spec.
    #[test]
    fn zlib_kat_cross_decompress() {
        let mut c = Compressor::new();
        // zlib compress2 level 6 of "the quick brown fox jumps over the lazy dog"
        let kat = unhex(
            "789c2bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a70300613c0ffa",
        );
        let dec = c.decompress(&kat, Level::Zlib6, 100).unwrap();
        assert_eq!(dec, b"the quick brown fox jumps over the lazy dog");
    }

    /// Cross-impl KAT: liblz4's `LZ4_compress_default` output (raw
    /// block, no frame, no prefix — same as `LZ4_compress_fast_
    /// extState` at accel=0). Proves `lz4_flex::block` wire compat.
    #[test]
    fn lz4_kat_cross_decompress() {
        let mut c = Compressor::new();
        // LZ4_compress_default of "the quick brown fox jumps over the lazy dog"
        let kat = unhex(
            "f01074686520717569636b2062726f776e20666f78206a756d7073206f766572201f00806c617a7920646f67",
        );
        let dec = c.decompress(&kat, Level::Lz4, 100).unwrap();
        assert_eq!(dec, b"the quick brown fox jumps over the lazy dog");
    }

    /// And the other direction: OUR LZ4 output must decode with the
    /// reference. We can't run liblz4 here, but `lz4_flex`'s own
    /// decompress IS the reference algorithm — block format has no
    /// encoder freedom for short literals. Spot-check that our output
    /// for a tiny input matches the C KAT byte-for-byte (LZ4 block
    /// format is deterministic for inputs this short — no match
    /// choices to make).
    #[test]
    fn lz4_kat_compress_matches() {
        let mut c = Compressor::new();
        let src = b"the quick brown fox jumps over the lazy dog";
        let ours = c.compress(src, Level::Lz4).unwrap();
        let kat = unhex(
            "f01074686520717569636b2062726f776e20666f78206a756d7073206f766572201f00806c617a7920646f67",
        );
        assert_eq!(ours, kat);
    }

    #[test]
    fn compress_empty() {
        // Edge: zero-length packet. C's memcpy(dest, src, 0) is fine;
        // compress2 of 0 bytes produces a valid empty zlib stream.
        let mut c = Compressor::new();
        assert_eq!(c.compress(&[], Level::None).unwrap(), Vec::<u8>::new());
        let z = c.compress(&[], Level::Zlib6).unwrap();
        assert_eq!(
            c.decompress(&z, Level::Zlib6, 10).unwrap(),
            Vec::<u8>::new()
        );
        let l = c.compress(&[], Level::Lz4).unwrap();
        assert_eq!(c.decompress(&l, Level::Lz4, 10).unwrap(), Vec::<u8>::new());
    }
}
