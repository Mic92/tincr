//! Safe wrapper around tinc's C SPTPS implementation, for differential testing.
//!
//! ## What this is
//!
//! `sptps.c` compiled fresh from `src/` and wrapped in just enough Rust to
//! drive it from a test. The C side runs the real handshake — same code that
//! ships in `tincd` — so when Phase 2's pure-Rust `tinc-sptps` lands, this
//! crate is the byte-for-byte oracle: feed both the same keys + RNG seed,
//! diff the wire output.
//!
//! ## What this is not
//!
//! Production code. The `unsafe` here is contained but not zero-cost: every
//! call mallocs a 64K event sink, the deterministic RNG is a process-global,
//! and there's no panic-unwinding-across-FFI guard because none of the
//! callbacks call back into Rust. Phase 2 throws this crate away.
//!
//! ## Determinism contract
//!
//! `sptps_start` calls `randomize()` (twice: nonce, ECDH seed). The shim
//! routes that through a ChaCha20 keystream seeded by [`seed_rng`]. **The
//! seed is process-global**, not per-session — you must call `seed_rng`
//! before each `CSptps::start` and not run sessions concurrently. This is
//! a deliberate trade-off: per-session RNG would require threading a context
//! pointer through `ecdh.c`'s `ecdh_generate_public`, which means patching
//! upstream. Serial tests don't care.

#![warn(missing_docs)]

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard};

/// Serialization lock for the process-global RNG.
///
/// `randomize()` in the shim is a single ChaCha20 stream — see crate docs
/// for why per-session RNG would mean patching `ecdh.c`. Tests must hold
/// this lock across `seed_rng` + `start` to keep the determinism contract.
///
/// We hand this out via [`serial_guard`] rather than baking it into
/// `start()`: a test that runs *two* `start`s with different seeds (the
/// normal case — alice and bob need distinct ephemerals) needs to hold
/// the lock across both. `start()` can't know that.
static RNG_LOCK: Mutex<()> = Mutex::new(());

/// Take the serialization lock. Hold it for the duration of any test that
/// calls [`seed_rng`].
///
/// Poisoning is recovered from: a panicking test mid-handshake leaves the
/// C side in some half-state, but since each test allocates fresh
/// `harness_t`s and re-seeds, the only shared state is the RNG context,
/// which the next `seed_rng` overwrites unconditionally.
pub fn serial_guard() -> MutexGuard<'static, ()> {
    RNG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ────────────────────────────────────────────────────────────────────
// Raw FFI surface. Hand-declared — see build.rs for why no bindgen.

#[link(name = "tinc_sptps_ffi", kind = "static")]
unsafe extern "C" {
    fn ffi_seed_rng(key32: *const u8);

    fn ffi_ecdsa_from_blob(blob: *const u8) -> *mut c_void;
    fn ffi_ecdsa_free(e: *mut c_void);

    fn ffi_harness_new() -> *mut c_void;
    fn ffi_harness_free(h: *mut c_void);

    fn ffi_start(
        h: *mut c_void,
        initiator: bool,
        datagram: bool,
        mykey: *mut c_void,
        hiskey: *mut c_void,
        label: *const u8,
        labellen: usize,
    ) -> bool;
    fn ffi_receive(h: *mut c_void, data: *const u8, len: usize) -> usize;
    fn ffi_send_record(h: *mut c_void, ty: u8, data: *const u8, len: u16) -> bool;
    fn ffi_force_kex(h: *mut c_void) -> bool;

    fn ffi_drain(h: *mut c_void, out_buf: *mut *const u8, out_overflow: *mut bool) -> usize;

    // Differential-fuzz entry points (csrc/replay_shim.c). These bypass
    // the harness and poke a single static function with hand-crafted
    // state. Used by `fuzz/` targets, not by the handshake tests above.
    fn ffi_check_seqno(st: *mut FfiReplayState, seqno: u32, update: bool) -> bool;
    fn ffi_subnet_compare_ipv4(a: *const FfiIpv4Subnet, b: *const FfiIpv4Subnet) -> i32;
}

/// Layout-match for `csrc/replay_shim.c`'s `ffi_replay_state_t`.
///
/// Public because the fuzz crate constructs these directly. The `late`
/// pointer is a non-owning borrow of a Rust slice for the duration of
/// one [`c_check_seqno`] call — the C indexes into it, never frees.
#[repr(C)]
pub struct FfiReplayState {
    /// Expected next seqno.
    pub inseqno: u32,
    /// Far-future drop counter.
    pub farfuture: u32,
    /// Window width in BYTES. The bitmap is `replaywin * 8` slots.
    pub replaywin: u32,
    /// Circular bitmap, `replaywin` bytes. **Caller owns; C borrows.**
    pub late: *mut u8,
}

/// Layout-match for `csrc/replay_shim.c`'s `ffi_ipv4_subnet_t`.
///
/// Owner is omitted: the C comparator short-circuits at the owner tier
/// when either is NULL, and we always pass NULL. The owner compare is
/// a `strcmp` — not where transcription bugs hide.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiIpv4Subnet {
    /// Network-order octets. Same as `Ipv4Addr::octets()`.
    pub addr: [u8; 4],
    /// 0..=32 in well-formed subnets, but the C type is bare `int` and
    /// the fuzzer will feed garbage. That's the point.
    pub prefixlength: i32,
    /// `%d`-parsed off the wire — negative is silly but legal.
    pub weight: i32,
}

/// Run `sptps_check_seqno` on a hand-built state.
///
/// `late` must be exactly `replaywin` bytes. The C indexes
/// `late[(seqno/8) % replaywin]`; a short buffer is an OOB write.
///
/// # Safety
/// `late.len()` must equal `replaywin`. Asserted in debug; in release
/// (where the fuzzer runs) the caller is on the hook — the fuzz harness
/// derives both from the same input byte so they can't disagree.
pub fn c_check_seqno(
    inseqno: u32,
    farfuture: u32,
    late: &mut [u8],
    seqno: u32,
    update: bool,
) -> (bool, u32, u32) {
    debug_assert!(
        !late.is_empty(),
        "replaywin=0 makes the C skip the bitmap entirely; not interesting"
    );
    let mut st = FfiReplayState {
        inseqno,
        farfuture,
        // replay window is u8 in tinc.conf (max 255); test harness caps at 32
        #[allow(clippy::cast_possible_truncation)]
        replaywin: late.len() as u32,
        late: late.as_mut_ptr(),
    };
    let ok = unsafe { ffi_check_seqno(&raw mut st, seqno, update) };
    (ok, st.inseqno, st.farfuture)
}

/// Run the C IPv4 subnet comparator on two hand-built subnets.
///
/// Returns the raw signed difference (not normalized to {-1,0,1}).
/// Compare against Rust's `Ordering` via `.signum()`.
#[must_use]
pub fn c_subnet_compare_ipv4(a: &FfiIpv4Subnet, b: &FfiIpv4Subnet) -> i32 {
    unsafe { ffi_subnet_compare_ipv4(a, b) }
}

// ────────────────────────────────────────────────────────────────────
// Public types

/// One side's role in the handshake.
///
/// Initiator vs responder differ in two places: the byte 0 of the SIG
/// transcript (`fill_msg`), and which half of the PRF output keys send
/// vs receive (`receive_ack` / `receive_sig`). Both peers compute
/// identical 128-byte key material; the role just picks the slice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// We sent KEX first. Signs with byte-0 = 1, encrypts with key1.
    Initiator,
    /// We waited for their KEX. Signs with byte-0 = 0, encrypts with key0.
    Responder,
}

/// Stream vs datagram framing.
///
/// Stream mode prefixes each record with a 2-byte big-endian length and
/// expects the receiver to reassemble across short reads (`sptps_receive_data`
/// is a state machine for that). Datagram mode prefixes with a 4-byte
/// big-endian seqno and assumes one record per call (UDP).
///
/// SPTPS over the meta-protocol uses stream; SPTPS over the data channel
/// uses datagram. Both must round-trip for Phase 2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Framing {
    /// 2-byte length prefix, reassembly buffer.
    Stream,
    /// 4-byte seqno prefix, replay window.
    Datagram,
}

/// What `sptps.c` produced during a `start`/`receive`/`send_record` call.
///
/// `sptps.c`'s callbacks fire re-entrantly *inside* the entry points: a
/// single `sptps_receive_data` of buffered handshake bytes can fire
/// `send_data` (the SIG goes out), then `receive_record` (handshake done),
/// then `send_data` again (the ACK). Hence `Vec<Event>`, not `Option`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// Bytes the C side wants put on the wire. The `record_type` is what
    /// `send_data` was told it's sending — useful for asserting "this is a
    /// HANDSHAKE record" without parsing the framing, but **not part of the
    /// wire format**. The bytes themselves are the entire framed record
    /// (length/seqno header + body + tag if encrypted).
    Wire {
        /// The `type` argument `send_data` was called with. Advisory only.
        record_type: u8,
        /// Fully framed wire bytes (header + body + tag if encrypted).
        bytes: Vec<u8>,
    },
    /// A decrypted application record was delivered up the stack.
    /// `record_type < 128` always (sptps.c routes ≥128 to handshake).
    Record {
        /// Application-defined record type, < 128.
        record_type: u8,
        /// Decrypted body (header and tag stripped).
        bytes: Vec<u8>,
    },
    /// `receive_record(SPTPS_HANDSHAKE, NULL, 0)` — the in-band signal
    /// that the handshake completed. After this, `send_record` will work.
    HandshakeDone,
}

/// A 96-byte tinc Ed25519 key (private or public-only) loaded into the C side.
///
/// Same layout as the on-disk `ed25519_key.priv` blob: 64 bytes of
/// SHA512-expanded private key, 32 bytes public. For a verify-only key
/// (the peer's), the private 64 bytes are unused — `ecdsa_verify` only
/// reads `.public` — so just zero them.
///
/// **`sptps_start` borrows the key pointers, it doesn't copy.** The
/// `ecdsa_t*` is dereferenced on every SIG send/verify. So `CKey` must
/// outlive the `CSptps` it's passed to. Rust enforces that via lifetimes.
pub struct CKey {
    ptr: NonNull<c_void>,
}

impl CKey {
    /// Load a 96-byte private key blob (`SHA512(seed)[64] ‖ pubkey[32]`).
    ///
    /// Matches `tinc_crypto::sign::SigningKey::from_blob` — same input
    /// produces the same signing behaviour, modulo whatever bugs exist
    /// on either side. That's the whole point.
    ///
    /// # Panics
    /// If C-side `xzalloc` returns NULL (i.e. OOM on a test box — won't happen).
    #[must_use]
    pub fn from_private_blob(blob: &[u8; 96]) -> Self {
        let ptr = unsafe { ffi_ecdsa_from_blob(blob.as_ptr()) };
        Self {
            ptr: NonNull::new(ptr).expect("xzalloc never returns NULL on test boxes"),
        }
    }

    /// Load a 32-byte public key. Private bytes are zeroed.
    ///
    /// Don't try to sign with this — `ecdsa_sign` would happily produce
    /// a signature with a zero scalar. The C code doesn't check.
    #[must_use]
    pub fn from_public(pubkey: &[u8; 32]) -> Self {
        let mut blob = [0u8; 96];
        blob[64..].copy_from_slice(pubkey);
        Self::from_private_blob(&blob)
    }
}

impl Drop for CKey {
    fn drop(&mut self) {
        unsafe { ffi_ecdsa_free(self.ptr.as_ptr()) }
    }
}

// CKey is Send (it's a malloc'd block, no thread-locals) but the harness
// itself isn't, so don't bother marking it.

/// One end of a C SPTPS session.
///
/// Create with [`CSptps::start`], pump bytes with [`receive`](Self::receive),
/// send app data with [`send_record`](Self::send_record). Every call drains
/// the event sink and returns whatever the C callbacks emitted.
///
/// The lifetime `'k` ties the session to the keys: `sptps_t` keeps raw
/// `ecdsa_t*` pointers and dereferences them lazily (on SIG records).
/// Drop the session before the keys, or the borrow checker yells.
pub struct CSptps<'k> {
    h: NonNull<c_void>,
    /// `sptps.c`'s `mykey`/`hiskey` are non-owning. Tie our lifetime
    /// to the keys so they can't be freed out from under it.
    _keys: std::marker::PhantomData<&'k CKey>,
}

impl<'k> CSptps<'k> {
    /// Start a session and run the initial KEX send.
    ///
    /// **Precondition:** [`seed_rng`] called since the last `start`. The RNG
    /// state is process-global; concurrent `start`s race on it. This is a
    /// test harness — write serial tests.
    ///
    /// `label` is the binding context (`"sptps_test"` in the upstream test
    /// binary, the connection identifier in `tincd`). Both sides must agree
    /// on it or the SIG transcript hash diverges and the handshake fails.
    ///
    /// The returned events include the first wire bytes — `sptps_start`
    /// calls `send_kex` before returning.
    ///
    /// # Panics
    /// If C-side `calloc` for the harness arena returns NULL.
    #[must_use]
    pub fn start(
        role: Role,
        framing: Framing,
        mykey: &'k CKey,
        hiskey: &'k CKey,
        label: &[u8],
    ) -> (Self, Vec<Event>) {
        let h = unsafe { ffi_harness_new() };
        let h = NonNull::new(h).expect("calloc");
        let ok = unsafe {
            ffi_start(
                h.as_ptr(),
                matches!(role, Role::Initiator),
                matches!(framing, Framing::Datagram),
                mykey.ptr.as_ptr(),
                hiskey.ptr.as_ptr(),
                label.as_ptr(),
                label.len(),
            )
        };
        assert!(
            ok,
            "sptps_start failed (ecdh_generate_public returned NULL?)"
        );
        let s = Self {
            h,
            _keys: std::marker::PhantomData,
        };
        let evs = s.drain();
        (s, evs)
    }

    /// Feed wire bytes. Stream mode reassembles partial records; datagram
    /// mode expects one whole record per call.
    ///
    /// Returns `(consumed, events)`. In stream mode `consumed < data.len()`
    /// is impossible-per-spec (the reassembly loop eats everything, the
    /// only early return is `false`-on-error which becomes `consumed == 0`).
    /// We return it anyway because the C signature does, and "this is what
    /// C said" is the oracle contract.
    pub fn receive(&mut self, data: &[u8]) -> (usize, Vec<Event>) {
        let n = unsafe { ffi_receive(self.h.as_ptr(), data.as_ptr(), data.len()) };
        (n, self.drain())
    }

    /// Send an application record. Only valid after [`Event::HandshakeDone`].
    ///
    /// `record_type` must be < 128. The C side asserts that.
    ///
    /// # Panics
    /// If `data.len() > u16::MAX` (SPTPS framing caps records at 64K),
    /// or `sptps_send_record` returns false (state machine misuse).
    pub fn send_record(&mut self, record_type: u8, data: &[u8]) -> Vec<Event> {
        let len: u16 = data.len().try_into().expect("SPTPS records cap at 64K");
        let ok = unsafe { ffi_send_record(self.h.as_ptr(), record_type, data.as_ptr(), len) };
        assert!(ok, "sptps_send_record returned false");
        self.drain()
    }

    /// Trigger a rekey. Only valid in `SECONDARY_KEX` state (i.e. after
    /// the first handshake completed). Exposed so Phase 2 tests can verify
    /// the Rust state machine handles re-KEX, which has different
    /// transitions than the initial handshake (`SPTPS_ACK` only happens
    /// on rekey — see `receive_handshake`'s switch).
    ///
    /// # Panics
    /// If `sptps_force_kex` returns false (not in `SECONDARY_KEX` state).
    pub fn force_kex(&mut self) -> Vec<Event> {
        let ok = unsafe { ffi_force_kex(self.h.as_ptr()) };
        assert!(ok, "sptps_force_kex returned false (not in SECONDARY_KEX?)");
        self.drain()
    }

    /// Slice the flat event arena into typed events.
    ///
    /// Format per shim.c: `[kind:u8][type:u8][len:u32 host-endian][payload]`
    /// repeated. Host endian is fine — we're in the same process.
    fn drain(&self) -> Vec<Event> {
        let mut buf_ptr: *const u8 = std::ptr::null();
        let mut overflow = false;
        let len = unsafe { ffi_drain(self.h.as_ptr(), &raw mut buf_ptr, &raw mut overflow) };

        assert!(
            !overflow,
            "event sink overflow: >64K of callback output from one FFI call. \
             This is almost certainly a test bug (pumping too much data), \
             not an sptps.c bug."
        );

        let raw = unsafe { std::slice::from_raw_parts(buf_ptr, len) };
        let mut out = Vec::new();
        let mut p = 0;
        while p < raw.len() {
            let kind = raw[p];
            let ty = raw[p + 1];
            let elen = u32::from_ne_bytes(raw[p + 2..p + 6].try_into().unwrap()) as usize;
            let payload = raw[p + 6..p + 6 + elen].to_vec();
            p += 6 + elen;
            out.push(match kind {
                1 => Event::Wire {
                    record_type: ty,
                    bytes: payload,
                },
                2 => Event::Record {
                    record_type: ty,
                    bytes: payload,
                },
                3 => Event::HandshakeDone,
                k => panic!("unknown event kind {k} from shim — shim.c and lib.rs out of sync"),
            });
        }
        out
    }
}

impl Drop for CSptps<'_> {
    fn drop(&mut self) {
        unsafe { ffi_harness_free(self.h.as_ptr()) }
    }
}

// ────────────────────────────────────────────────────────────────────

/// Seed the C-side `randomize()` keystream.
///
/// Call before every [`CSptps::start`]. **Process-global** — see crate-level
/// docs for the trade-off.
///
/// The shim aborts the process if `randomize()` is called unseeded; that's
/// the right severity for a determinism violation in a test oracle.
pub fn seed_rng(key: &[u8; 32]) {
    unsafe { ffi_seed_rng(key.as_ptr()) }
}
