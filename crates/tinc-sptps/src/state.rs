//! The state machine. Ported function-by-function from `sptps.c`.
//!
//! Reading guide: every `fn` here corresponds to a `static bool` in the C.
//! Where the C calls `error(s, errno, "...")` and returns `false`, we
//! return `Err(SptpsError::...)`. Where the C calls `s->send_data(...)` we
//! push to `out: &mut Vec<Output>`. Otherwise the logic is line-for-line.
//!
//! The two places where ordering matters more than it looks:
//!
//! - **`receive_sig` sets the new `outcipher` *after* `send_sig` and
//!   `send_ack`.** During rekey, both go out under the old key. See the
//!   doc comment on `receive_sig` — the `tinc-ffi` harness test pinned this.
//!
//! - **`receive_handshake`'s switch falls through `SECONDARY_KEX → KEX`.**
//!   When the responder gets an unsolicited rekey, it sends its own KEX
//!   *and then* processes the incoming one in the same call. C does this
//!   with a literal `// Fall through` and no `break`. Rust does it by
//!   matching `SecondaryKex | Kex` and gating the send on the variant.

use rand_core::RngCore;
use tinc_crypto::chapoly::{ChaPoly, KEY_LEN as CIPHER_KEY_LEN, TAG_LEN};
use tinc_crypto::ecdh::{EcdhPrivate, PUBLIC_LEN as ECDH_PUBLIC_LEN, SHARED_LEN};
use tinc_crypto::prf::prf;
use tinc_crypto::sign::{self, PUBLIC_LEN as SIGN_PUBLIC_LEN, SIG_LEN, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{KEX_LEN, NONCE_LEN, REC_HANDSHAKE, VERSION};

// ────────────────────────────────────────────────────────────────────
// Public types

/// Why the state machine refused to make progress.
///
/// Every variant maps to a specific `error(s, ...)` call site in `sptps.c`.
/// The C version stuffs an `errno` into a logger callback; we keep the
/// distinctions in the type instead. None of these carry data — the C
/// doesn't expose any either, and the differential tests assert "fails at
/// the same point", not "fails with the same message".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SptpsError {
    /// `receive_kex`: KEX body length wasn't 65, or version byte wasn't 0,
    /// or a second KEX arrived before the first was processed.
    BadKex,
    /// `receive_sig`: SIG body wasn't 64 bytes, or `ecdsa_verify` failed.
    BadSig,
    /// `receive_ack`: ACK body wasn't empty.
    BadAck,
    /// `receive_handshake`: handshake record arrived in a state that
    /// doesn't expect one (e.g. SIG before KEX).
    UnexpectedHandshake,
    /// Stream/datagram receive: app record arrived before `instate` set,
    /// or record type ≥ 129 (only 128 is HANDSHAKE).
    BadRecord,
    /// Stream/datagram receive: ChaPoly decrypt failed (tag mismatch).
    DecryptFailed,
    /// Datagram receive: short packet, or `inseqno` mismatch during the
    /// plaintext-handshake phase. Replay window rejections also surface
    /// here once the channel is encrypted.
    BadSeqno,
    /// `send_record`: called before handshake done, or record type ≥ 128.
    /// `force_kex`: called outside `SecondaryKex` state.
    InvalidState,
}

impl std::fmt::Display for SptpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Terse on purpose: the daemon will log surrounding context.
        // Not security-sensitive — no key bytes leak through Debug.
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for SptpsError {}

/// One side of the handshake.
///
/// Decides byte 0 of the SIG transcript and which half of the PRF output
/// keys send vs. receive. The two roles compute the *same* shared secret
/// and the *same* 128-byte key blob; role just picks `key0` vs `key1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sent KEX first. SIG transcript byte 0 = 1. Encrypts with `key1`,
    /// decrypts with `key0`.
    Initiator,
    /// Sent KEX second. SIG transcript byte 0 = 0. Encrypts with `key0`,
    /// decrypts with `key1`. Also: doesn't sign until it receives a SIG
    /// (initiator signs immediately on getting peer's KEX).
    Responder,
}

impl Role {
    const fn is_initiator(self) -> bool {
        matches!(self, Role::Initiator)
    }
}

/// Wire framing.
///
/// Stream is for the meta-protocol (TCP-like, reassembly buffer). Datagram
/// is for the data channel (UDP-like, replay window). The handshake state
/// machine is identical; only `send_record_priv` and the receive entry
/// point differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `len:u16be ‖ type:u8 ‖ body[len] (‖ tag[16] if encrypted)`.
    /// `receive` reassembles across short reads.
    Stream,
    /// `seqno:u32be ‖ type:u8 ‖ body (‖ tag[16] if encrypted)`.
    /// `receive` expects whole records.
    Datagram,
}

/// What the state machine produced. Analogous to `tinc-ffi`'s `Event` —
/// same shape on purpose so the differential test can compare directly.
///
/// `sptps.c` doesn't have this type; it fires callbacks instead. The set
/// of variants is exactly the set of callback signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Bytes to put on the wire. Fully framed: header + encrypted body +
    /// tag. The `record_type` is *advisory* — it's what `send_data` was
    /// told it's sending, useful for asserts, but not transmitted
    /// separately (it's already inside the framed bytes).
    Wire {
        /// Record type. `REC_HANDSHAKE` during handshake, app type after.
        record_type: u8,
        /// Framed wire bytes.
        bytes: Vec<u8>,
    },
    /// A decrypted application record. `record_type < 128` always.
    Record {
        /// App-defined type, 0..=127.
        record_type: u8,
        /// Body, decrypted and stripped of framing.
        bytes: Vec<u8>,
    },
    /// Handshake completed. C signals this with `receive_record(128, NULL, 0)`.
    /// We give it a name because every consumer special-cases it anyway.
    HandshakeDone,
}

// ────────────────────────────────────────────────────────────────────
// Internal state

/// `sptps_state_t` in C. The four reachable states of `receive_handshake`'s
/// switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Sent KEX, waiting for peer's KEX. Set by `start` and `force_kex`.
    Kex,
    /// Handshake done; ready for an unsolicited rekey from the peer.
    /// "Secondary" because the *first* KEX was during `start`.
    SecondaryKex,
    /// Got peer's KEX, waiting for their SIG. (Initiator already sent
    /// own SIG by now; responder hasn't.)
    Sig,
    /// Rekey only: sent SIG + ACK under old key, waiting for peer's ACK
    /// before switching `incipher` to new key.
    Ack,
}

/// Replay window for datagram mode. `sptps_check_seqno` in C.
///
/// A sliding bitmap: bit N of `late[]` is 1 iff sequence number
/// `(inseqno - replaywin*8 + N) mod replaywin*8` has *not* been seen yet.
/// (Yes, the polarity is "1 = not seen". The C calls them "late" packets:
/// the bit is set when we skip past it, cleared when it arrives.)
///
/// `farfuture` is a heuristic for "peer rebooted and seqnos reset": if we
/// see too many packets way ahead, give up and resync. The threshold is
/// `replaywin >> 2`, hardcoded in C.
/// Exposed under `cfg(fuzzing)` so the differential-fuzz harness can
/// build identical Rust and C state from the same input bytes. The
/// fields are otherwise private; the daemon never touches them.
#[cfg_attr(not(fuzzing), allow(unreachable_pub))]
pub struct ReplayWindow {
    /// Expected next seqno.
    pub(crate) inseqno: u32,
    /// Circular bitmap. Length = `replaywin` bytes = `replaywin * 8` slots.
    /// Default 16 bytes (128 packets) per `sptps_replaywin` in C.
    pub(crate) late: Vec<u8>,
    /// Far-future drop counter.
    pub(crate) farfuture: u32,
}

impl ReplayWindow {
    /// Fuzz-only constructor: build a window in an arbitrary mid-stream
    /// state, as if `n` packets had already been processed. The harness
    /// derives `inseqno`/`late`/`farfuture` from the fuzz input and
    /// builds the same state on the C side via `ffi_replay_state_t`.
    #[cfg(fuzzing)]
    pub fn from_raw(inseqno: u32, late: Vec<u8>, farfuture: u32) -> Self {
        Self {
            inseqno,
            late,
            farfuture,
        }
    }

    /// Fuzz-only state inspector. The harness compares post-state
    /// byte-for-byte against the C — same `inseqno`, same `late[]`
    /// bitmap, same `farfuture`. A divergence here that doesn't show
    /// up in the return value is the *interesting* kind: both impls
    /// accepted the packet but disagree on what comes next.
    #[cfg(fuzzing)]
    pub fn raw(&self) -> (u32, &[u8], u32) {
        (self.inseqno, &self.late, self.farfuture)
    }

    /// Fuzz-only public wrapper around [`Self::check`]. The real method
    /// stays private — the daemon goes through `Sptps::receive`.
    ///
    /// # Errors
    /// `BadSeqno` on replay/out-of-window. Same as [`Self::check`].
    #[cfg(fuzzing)]
    pub fn check_fuzz(&mut self, seqno: u32, update: bool) -> Result<(), SptpsError> {
        self.check(seqno, update)
    }

    fn new(win: usize) -> Self {
        Self {
            inseqno: 0,
            late: vec![0; win],
            farfuture: 0,
        }
    }

    /// `sptps_check_seqno`. The `update` flag is `update_state` in C:
    /// `verify_datagram` calls with `false` to peek without committing.
    ///
    /// Returns `Ok(())` if the packet is acceptable, `Err` for
    /// replay/out-of-window. Doesn't distinguish the cases — C doesn't
    /// either (both go to `error(EIO, ...)`).
    ///
    /// The arithmetic is reproduced verbatim from C, integer types and all.
    /// The replay window is one of the places where being clever in
    /// translation creates a subtle interop bug: a peer that accepts
    /// packets the C rejects (or vice versa) is a connection that flaps
    /// under packet loss. Match the C bit-for-bit.
    #[allow(clippy::cast_possible_truncation)] // late.len() is replay-window bytes (≪ u32::MAX); seqno arith is mod 2^32
    fn check(&mut self, seqno: u32, update: bool) -> Result<(), SptpsError> {
        let win = self.late.len() as u32;
        if win > 0 {
            if seqno != self.inseqno {
                if seqno >= self.inseqno.wrapping_add(win * 8) {
                    // Packet is so far ahead it'd blow away the whole window.
                    // The first `win/4` such packets are dropped (could be
                    // forged, could be a single burst); after that, assume
                    // the peer reset and we're behind, mark everything in
                    // between as lost.
                    //
                    // Yes, this is wrap-unsafe in C too. seqno is u32 and
                    // wraps at ~4 billion records; tincd reconnects long
                    // before that. We use wrapping_add to silence the lint
                    // but the semantics are "C does what C does".
                    let early = self.farfuture < (win >> 2);
                    if update {
                        self.farfuture += 1;
                    }
                    if early {
                        return Err(SptpsError::BadSeqno);
                    }
                    if update {
                        // Resync: everything between old and new is gone.
                        self.late.fill(0xFF);
                    }
                } else if seqno < self.inseqno {
                    // Packet from the past. Either too far past (out of
                    // window) or already seen (bit cleared). Both reject.
                    let too_old = self.inseqno >= win * 8 && seqno < self.inseqno - win * 8;
                    let already = self.late[(seqno / 8 % win) as usize] & (1 << (seqno % 8)) == 0;
                    if too_old || already {
                        return Err(SptpsError::BadSeqno);
                    }
                } else if update {
                    // Packet from the near future. Mark the gap as late.
                    for i in self.inseqno..seqno {
                        self.late[(i / 8 % win) as usize] |= 1 << (i % 8);
                    }
                }
            }
            if update {
                // Clear the "this packet is late" bit — it arrived.
                self.late[(seqno / 8 % win) as usize] &= !(1 << (seqno % 8));
                self.farfuture = 0;
            }
        }
        if update && seqno >= self.inseqno {
            // `seqno + 1` must wrap silently at u32::MAX (protocol
            // requirement). Debug-mode `+` panics; `wrapping_add`
            // matches in both profiles. Lean proof `p5_wrap_receive_max` confirms the
            // intended semantics: after seqno=MAX, inseqno wraps to 0.
            self.inseqno = seqno.wrapping_add(1);
        }
        // C also tracks `received` (total packet count, resets on inseqno
        // wrap). It's read by net_packet.c for stats but never by sptps.c
        // itself. Omitted here; the daemon counts packets at its own layer.
        Ok(())
    }
}

/// Stream-mode reassembly buffer. The bottom half of `sptps_receive_data`.
///
/// State machine within a state machine: first read 2 bytes (length), then
/// read `len + (encrypted? 17 : 1)` more bytes (type + body + maybe tag).
/// `buf.len()` tracks where we are; `reclen` is parsed once we hit 2.
#[derive(Default)]
struct StreamBuf {
    buf: Vec<u8>,
    /// Body length, parsed from the first 2 bytes. Valid iff `buf.len() >= 2`.
    reclen: u16,
}

// ────────────────────────────────────────────────────────────────────
// The struct

/// One end of an SPTPS session.
///
/// Create with [`Sptps::start`], pump bytes with [`receive`](Self::receive),
/// send app data with [`send_record`](Self::send_record). Every call returns
/// a `Vec<Output>` because the C callbacks fire re-entrantly: a single
/// `receive` of buffered handshake bytes can yield SIG-out, then
/// `HandshakeDone`, then ACK-out — three events, one call.
///
/// **Stream mode processes one record per `receive` call.** This is
/// *deliberate fidelity to a C oddity*: `sptps_receive_data` has no outer
/// loop, it returns `total_read < len` and `protocol.c` calls it again with
/// the tail. Mimicking that lets the differential test be strict about how
/// many bytes each call reports consumed.
///
/// Not `Send`/`Sync` — `SigningKey` zeroizes on drop and we don't want
/// surprises. The daemon runs one SPTPS per connection, on one thread.
pub struct Sptps {
    role: Role,
    framing: Framing,
    state: State,

    // ─── Reassembly / replay ───
    stream: StreamBuf, // unused in datagram mode (zero-sized buf)
    replay: ReplayWindow,

    // ─── Crypto state ───
    // `instate`/`outstate` in C are bools that gate encryption. Rust models
    // that with Option: `None` = plaintext, `Some(cipher)` = encrypted.
    // The seqnos live alongside even when None because they tick during
    // the plaintext handshake too (`outseqno++` happens unconditionally
    // in send_record_priv).
    incipher: Option<ChaPoly>,
    inseqno: u32, // stream mode only; datagram uses ReplayWindow.inseqno
    outcipher: Option<ChaPoly>,
    outseqno: u32,

    // ─── Handshake-transient state ───
    // mykex/hiskex/ecdh/key are all heap-allocated in C, freed at specific
    // points in the handshake. Same lifecycle here as Options.
    //
    // `mykex`/`hiskex` are 65-byte KEX bodies. They live from KEX-send to
    // SIG-receive: the SIG transcript needs both. C frees them in
    // `receive_sig` after the verify.
    mykex: Option<Zeroizing<[u8; KEX_LEN]>>,
    hiskex: Option<Zeroizing<[u8; KEX_LEN]>>,
    /// ECDH ephemeral. Lives from `send_kex` (where it generates the
    /// pubkey that goes in `mykex`) to `receive_sig` (where it computes
    /// the shared secret and is consumed). `EcdhPrivate::compute_shared`
    /// takes `self` by value, so the Option dance is natural.
    ecdh: Option<EcdhPrivate>,
    /// 128 bytes of PRF output: `key0[64] ‖ key1[64]`. Lives from
    /// `generate_key_material` to `receive_ack` (the `incipher` half is
    /// only consumed when we know the peer is ready). Freed there.
    key: Option<Zeroizing<[u8; 2 * CIPHER_KEY_LEN]>>,

    // ─── Static config ───
    mykey: SigningKey,
    hiskey: [u8; SIGN_PUBLIC_LEN],
    label: Vec<u8>,
}

impl Sptps {
    /// Start a session. Runs the initial KEX immediately — the returned
    /// `Vec<Output>` contains the first wire bytes.
    ///
    /// `rng` is consumed for 64 bytes (32 nonce, 32 ECDH seed). Pass
    /// `OsRng` in production. The differential tests pass a seeded
    /// `ChaCha20Rng` so the bytes match the C harness's seeded
    /// `randomize()`.
    ///
    /// `replaywin` is the datagram replay window in *bytes* (default 16
    /// = 128 packets per `sptps_replaywin` in C). Ignored in stream mode
    /// — pass 0 if you like, but matching the C default is harmless.
    #[allow(clippy::missing_panics_doc)] // unreachable: send_kex on a fresh struct can't fail
    pub fn start(
        role: Role,
        framing: Framing,
        mykey: SigningKey,
        hiskey: [u8; SIGN_PUBLIC_LEN],
        label: impl Into<Vec<u8>>,
        replaywin: usize,
        rng: &mut impl RngCore,
    ) -> (Self, Vec<Output>) {
        let mut s = Self {
            role,
            framing,
            state: State::Kex,
            stream: StreamBuf::default(),
            replay: ReplayWindow::new(replaywin),
            incipher: None,
            inseqno: 0,
            outcipher: None,
            outseqno: 0,
            mykex: None,
            hiskex: None,
            ecdh: None,
            key: None,
            mykey,
            hiskey,
            label: label.into(),
        };
        let mut out = Vec::new();
        // send_kex can only fail if mykex is already set. We just zeroed it.
        s.send_kex(rng, &mut out).expect("first send_kex");
        (s, out)
    }

    // ────────────────────────────────────────────────────────────────
    // Send path

    /// `send_record_priv` + `send_record_priv_datagram`.
    ///
    /// One function does both framings; the C splits them for `alloca`
    /// hygiene. The `outseqno++` happens here unconditionally — yes, even
    /// during plaintext handshake records. That's load-bearing for the
    /// differential test: C ticks the seqno on every send, encrypted or not.
    /// The first encrypted record's seqno is therefore 2 (after KEX=0 and
    /// SIG=1), not 0.
    ///
    /// Hot-path note: this is the ONE per-packet allocation on the SPTPS
    /// send side. One right-sized `Vec`, one `extend_from_slice(body)`
    /// inside `seal_into`, encrypt-in-place.
    fn send_record_priv(&mut self, ty: u8, body: &[u8], out: &mut Vec<Output>) {
        let seqno = self.outseqno;
        self.outseqno = self.outseqno.wrapping_add(1);

        // Compute final length so the ONE alloc is right-sized.
        // Stream:   2 (len)   + 1 (type) + body + [16 (tag) if encrypted]
        // Datagram: 4 (seqno) + 1 (type) + body + [16 (tag) if encrypted]
        let header_len = match self.framing {
            Framing::Stream => 2,
            Framing::Datagram => 4,
        };
        let tag_len = if self.outcipher.is_some() { TAG_LEN } else { 0 };
        let mut wire = Vec::with_capacity(header_len + 1 + body.len() + tag_len);

        // Plaintext header. The type byte lives INSIDE the AEAD span; the
        // len/seqno header is the only thing that survives encryption.
        match self.framing {
            Framing::Stream => {
                let len: u16 = body.len().try_into().expect("body fits in u16");
                wire.extend_from_slice(&len.to_be_bytes());
            }
            Framing::Datagram => {
                wire.extend_from_slice(&seqno.to_be_bytes());
            }
        }

        // type+body, encrypted in-place if cipher is up. Same span the C
        // hands to `chacha_poly1305_encrypt`: `buffer + header_len` for
        // `1 + body.len()` bytes.
        if let Some(cipher) = &self.outcipher {
            cipher.seal_into(u64::from(seqno), ty, body, &mut wire, header_len);
        } else {
            wire.push(ty);
            wire.extend_from_slice(body);
        }

        out.push(Output::Wire {
            record_type: ty,
            bytes: wire,
        });
    }

    /// Public app-record send. `sptps_send_record` in C.
    ///
    /// # Errors
    ///
    /// `InvalidState` if called before [`Output::HandshakeDone`], if
    /// `record_type >= 128` (those are reserved for handshake records),
    /// or if `body.len() > 65535` in stream mode (the wire framing has
    /// a `u16` length header — the C silently truncates with a
    /// `uint16_t` cast and the receiver desyncs; we'd rather refuse).
    pub fn send_record(&mut self, record_type: u8, body: &[u8]) -> Result<Vec<Output>, SptpsError> {
        if self.outcipher.is_none() || record_type >= REC_HANDSHAKE {
            return Err(SptpsError::InvalidState);
        }
        // Stream framing's `len:u16be` header can't carry more than this.
        // Gated here, not in `send_record_priv`: handshake records
        // (KEX=65, SIG=64, ACK=0) are fixed-size, so the `expect` in
        // priv stays a true invariant for those callers.
        if self.framing == Framing::Stream && body.len() > usize::from(u16::MAX) {
            return Err(SptpsError::InvalidState);
        }
        let mut out = Vec::new();
        self.send_record_priv(record_type, body, &mut out);
        Ok(out)
    }

    /// Hot-path datagram send. Writes one encrypted SPTPS datagram directly
    /// into `out`, leaving `headroom` zero bytes at the front for the caller
    /// to fill afterwards.
    ///
    /// On return, `out` is `[0u8; headroom] ‖ seqno:4 ‖ enc(type ‖ body) ‖
    /// tag:16`. Caller overwrites `out[..headroom]` with whatever wraps the
    /// SPTPS frame on the wire (the daemon writes `[dst_id6 ‖ src_id6]`
    /// there, 12 bytes, then `sendto` the whole buffer).
    ///
    /// `out` is **cleared** first: pass a daemon-owned `Vec` and reuse it
    /// across packets. After the first call it has grown to `headroom +
    /// body.len() + 21`; subsequent same-size calls do zero heap ops.
    ///
    /// This pre-padding optimization was a long-standing upstream TODO.
    /// It never landed there because `alloca` made the prepend-memcpy
    /// cheap enough; our heap-Vec equivalent showed up at 1.6% alloc + 1.5%
    /// memmove in the profile.
    ///
    /// vs [`send_record`]: bypasses the `Vec<Output>` push/match (one alloc,
    /// one move), the wire `Vec` alloc (one alloc), and the daemon-side
    /// `Vec::with_capacity(12 + ct.len())` + `extend` (one alloc, one body
    /// copy). Three allocs + one ~1500-byte memmove per packet → zero.
    ///
    /// # Errors
    ///
    /// `InvalidState` if not [`Framing::Datagram`], if called before
    /// [`Output::HandshakeDone`], or if `record_type >= 128`. Same gate as
    /// [`send_record`] plus a datagram-only check (Stream framing has the
    /// 2-byte length prefix; that path stays on the alloc-y `send_record`
    /// since it's the cold meta-conn TCP fallback, not the UDP data path).
    pub fn seal_data_into(
        &mut self,
        record_type: u8,
        body: &[u8],
        out: &mut Vec<u8>,
        headroom: usize,
    ) -> Result<(), SptpsError> {
        // Same gate as send_record. Datagram-only: Stream is the cold
        // meta-conn path (PACKET 17 fallback), not worth a fast-path.
        if self.framing != Framing::Datagram || record_type >= REC_HANDSHAKE {
            return Err(SptpsError::InvalidState);
        }
        let Some(cipher) = self.outcipher.as_ref() else {
            return Err(SptpsError::InvalidState);
        };

        let seqno = self.outseqno;
        self.outseqno = self.outseqno.wrapping_add(1);

        // Clear, don't dealloc. Reused Vec keeps its capacity; after
        // the first packet this resize is a no-op (len already 0 from
        // the previous clear, capacity already sufficient).
        out.clear();
        out.resize(headroom, 0);
        out.extend_from_slice(&seqno.to_be_bytes());

        // type+body, encrypted in-place, tag appended. Same span the
        // Encrypt `[type | body]` past the 4-byte plaintext seqno header.
        cipher.seal_into(u64::from(seqno), record_type, body, out, headroom + 4);
        Ok(())
    }

    /// Hot-path datagram receive. Mirror of [`seal_data_into`]. Decrypts
    /// one SPTPS data record directly into `out`, leaving `headroom` zero
    /// bytes at the front for the caller to fill afterwards.
    ///
    /// On `Ok` return: `out` is `[0u8; headroom] ‖ body`, return value is
    /// the `record_type` byte. Caller (daemon) overwrites the headroom
    /// with whatever wraps the body before delivery (the daemon writes a
    /// synthetic 14-byte ethernet header at `out[..14]` before
    /// `route_packet(&mut out)`).
    ///
    /// `out` is **cleared** first: pass a daemon-owned `Vec` and reuse it
    /// across packets. After the first call it has grown to `headroom +
    /// body.len()`; subsequent same-size calls do zero heap ops.
    ///
    /// vs [`receive`]: bypasses `cipher.open()`'s `ct.to_vec()` (alloc +
    /// body copy), `Output::Record { bytes: body.to_vec() }` (alloc + body
    /// copy), and the `Vec<Output>` push (alloc). Three allocs and two
    /// ~1500-byte memcpys per packet → one body memcpy (the ct extend in
    /// `open_into`; unavoidable, can't XOR an immutable slice).
    ///
    /// # Errors
    ///
    /// - `InvalidState`: not [`Framing::Datagram`], or no `incipher` yet
    ///   (handshake not complete). Caller falls back to [`receive`].
    /// - `BadSeqno`: packet shorter than `4+1+TAG_LEN` (21 bytes minimum
    ///   encrypted datagram), or replayed/out-of-window.
    /// - `DecryptFailed`: tag mismatch.
    /// - `BadRecord`: decrypted `record_type >= REC_HANDSHAKE`. The fast
    ///   path is data-records-only. The replay window is **not** advanced
    ///   in this case, so caller can fall back to [`receive`] which sees
    ///   the same seqno fresh and handles the handshake/KEX-renegotiate
    ///   properly. Slightly wasteful (decrypt twice) but handshake records
    ///   are once-per-connection.
    pub fn open_data_into(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
        headroom: usize,
    ) -> Result<u8, SptpsError> {
        if self.framing != Framing::Datagram {
            return Err(SptpsError::InvalidState);
        }
        let Some(cipher) = self.incipher.as_ref() else {
            return Err(SptpsError::InvalidState);
        };
        // 4 (seqno) + 1 (type) + 16 (tag) = 21 minimum encrypted datagram.
        if data.len() < 21 {
            return Err(SptpsError::BadSeqno);
        }
        let seqno = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Clear, don't dealloc. Reused Vec keeps its capacity.
        out.clear();
        out.resize(headroom, 0);

        // Decrypt-then-replay-check, same order as receive_datagram: a
        // packet that fails decrypt shouldn't advance the window. The
        // type byte lands at out[headroom], body at out[headroom+1..].
        cipher
            .open_into(u64::from(seqno), &data[4..], out, headroom)
            .map_err(|_| SptpsError::DecryptFailed)?;

        let ty = out[headroom];
        if ty >= REC_HANDSHAKE {
            // Don't advance replay. Caller falls back to receive() which
            // re-decrypts and handles the handshake. Restore out to its
            // pre-call shape so the next packet's clear/resize is cheap.
            out.truncate(headroom);
            return Err(SptpsError::BadRecord);
        }

        // Check replay BEFORE leaving plaintext in `out`. On reject,
        // truncate — same Err contract as the BadRecord arm above:
        // `out == [0u8; headroom]` on every Err return. Decrypt first
        // is still required (forged seqnos must not advance the
        // window) but check-before-shift means the memmove below only
        // runs on the Ok path.
        if let Err(e) = self.replay.check(seqno, true) {
            out.truncate(headroom);
            return Err(e);
        }

        // Strip the type byte: shift body left by one. Small memmove.
        out.copy_within(headroom + 1.., headroom);
        out.truncate(out.len() - 1);
        Ok(ty)
    }

    /// `send_kex`: emit `version[1] ‖ nonce[32] ‖ ecdh_pubkey[32]`.
    ///
    /// Consumes 64 bytes from `rng` (nonce, then seed). The C calls
    /// `randomize` for the nonce then `ecdh_generate_public` (which calls
    /// `randomize` internally for the seed); same order here so the
    /// differential test sees the same byte stream.
    fn send_kex(
        &mut self,
        rng: &mut impl RngCore,
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        // Re-KEX before the previous one finished. State machine bug,
        // not a wire error.
        if self.mykex.is_some() {
            return Err(SptpsError::InvalidState);
        }

        let mut kex = Zeroizing::new([0u8; KEX_LEN]);
        kex[0] = VERSION;

        // RNG order matters: nonce first, ECDH seed second. C's
        // `randomize(s->mykex->nonce)` then `ecdh_generate_public()`.
        rng.fill_bytes(&mut kex[1..=NONCE_LEN]);

        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        let (ecdh, pubkey) = EcdhPrivate::from_seed(&seed);
        kex[1 + NONCE_LEN..].copy_from_slice(&pubkey);

        // Wire it before stashing — C does `s->mykex = ...; send_record(mykex)`
        // but the order doesn't observably matter, both touch only mykex.
        self.send_record_priv(REC_HANDSHAKE, &*kex, out);
        self.mykex = Some(kex);
        self.ecdh = Some(ecdh);
        Ok(())
    }

    /// `fill_msg` + `send_sig`: build the SIG transcript and sign it.
    ///
    /// Transcript: `[initiator: u8][mykex: 65][hiskex: 65][label]`.
    /// Note `mykex` first, `hiskex` second — but on the *verify* side
    /// it's `hiskex` first, `mykex` second (with `initiator` flipped).
    /// Both sides agree on what's signed because their roles swap.
    fn send_sig(&mut self, out: &mut Vec<Output>) {
        let mykex = self.mykex.as_ref().expect("send_sig with no mykex");
        let hiskex = self.hiskex.as_ref().expect("send_sig with no hiskex");

        let mut msg = Zeroizing::new(Vec::with_capacity(1 + 2 * KEX_LEN + self.label.len()));
        msg.push(u8::from(self.role.is_initiator()));
        msg.extend_from_slice(&**mykex);
        msg.extend_from_slice(&**hiskex);
        msg.extend_from_slice(&self.label);

        let sig = self.mykey.sign(&msg);
        self.send_record_priv(REC_HANDSHAKE, &sig, out);
    }

    /// `send_ack`: empty handshake record. Only used during rekey
    /// (`receive_sig` with `outstate` already true).
    fn send_ack(&mut self, out: &mut Vec<Output>) {
        self.send_record_priv(REC_HANDSHAKE, &[], out);
    }

    /// `sptps_force_kex`: trigger a rekey.
    ///
    /// # Errors
    ///
    /// `InvalidState` unless we're in `SecondaryKex` (handshake done,
    /// no rekey already in flight). C: `if(!outstate || state != SECONDARY_KEX)`.
    pub fn force_kex(&mut self, rng: &mut impl RngCore) -> Result<Vec<Output>, SptpsError> {
        if self.outcipher.is_none() || self.state != State::SecondaryKex {
            return Err(SptpsError::InvalidState);
        }
        self.state = State::Kex;
        let mut out = Vec::new();
        self.send_kex(rng, &mut out)?;
        Ok(out)
    }

    // ────────────────────────────────────────────────────────────────
    // Receive path: handshake records

    /// `receive_kex`: stash peer's KEX, sign-if-initiator.
    fn receive_kex(&mut self, body: &[u8], out: &mut Vec<Output>) -> Result<(), SptpsError> {
        if body.len() != KEX_LEN || body[0] != VERSION || self.hiskex.is_some() {
            return Err(SptpsError::BadKex);
        }
        let mut kex = Zeroizing::new([0u8; KEX_LEN]);
        kex.copy_from_slice(body);
        self.hiskex = Some(kex);

        if self.role.is_initiator() {
            self.send_sig(out);
        }
        Ok(())
    }

    /// `generate_key_material`: ECDH shared secret → PRF → 128 bytes.
    ///
    /// PRF seed: `"key expansion" ‖ initiator_nonce ‖ responder_nonce ‖ label`.
    /// Note the nonce order: *initiator's nonce first*, regardless of which
    /// side we are. Both sides must compute the same key, so the seed must
    /// be role-symmetric. C: `(initiator ? mykex : hiskex)->nonce` first.
    fn generate_key_material(&mut self, shared: &[u8; SHARED_LEN]) {
        // No NUL: C does `sizeof("key expansion") - 1`.
        const PREFIX: &[u8] = b"key expansion";

        let (init_kex, resp_kex) = if self.role.is_initiator() {
            (self.mykex.as_ref(), self.hiskex.as_ref())
        } else {
            (self.hiskex.as_ref(), self.mykex.as_ref())
        };
        let init_nonce = &init_kex.expect("kex present")[1..=NONCE_LEN];
        let resp_nonce = &resp_kex.expect("kex present")[1..=NONCE_LEN];

        let mut seed = Zeroizing::new(Vec::with_capacity(
            PREFIX.len() + 2 * NONCE_LEN + self.label.len(),
        ));
        seed.extend_from_slice(PREFIX);
        seed.extend_from_slice(init_nonce);
        seed.extend_from_slice(resp_nonce);
        seed.extend_from_slice(&self.label);

        let mut key = Zeroizing::new([0u8; 2 * CIPHER_KEY_LEN]);
        prf(shared, &seed, &mut *key);
        self.key = Some(key);
    }

    /// `receive_ack`: switch `incipher` to the new key, drop the key blob.
    ///
    /// Called either with real wire data (during rekey, in the `Ack` state)
    /// or synthetically with `&[]` (during initial handshake — the
    /// "synthetic ACK" in `receive_handshake`'s `Sig → !was_rekey` path).
    fn receive_ack(&mut self, body: &[u8]) -> Result<(), SptpsError> {
        if !body.is_empty() {
            return Err(SptpsError::BadAck);
        }
        let key = self.key.take().expect("receive_ack with no key material");
        // Initiator decrypts with key0, responder with key1.
        // (Mirror of the outcipher assignment in receive_sig.)
        let half: &[u8; CIPHER_KEY_LEN] = if self.role.is_initiator() {
            (&key[..CIPHER_KEY_LEN]).try_into().unwrap()
        } else {
            (&key[CIPHER_KEY_LEN..]).try_into().unwrap()
        };
        self.incipher = Some(ChaPoly::new(half));
        // `key` Zeroizes on drop here.
        Ok(())
    }

    /// `receive_sig`: verify, ECDH, derive keys, maybe send-SIG, maybe send-ACK.
    ///
    /// Returns `was_rekey` — whether `outcipher` was already set on entry.
    /// `receive_handshake` needs this to pick between the synthetic-ACK
    /// path (initial handshake) and the wait-for-real-ACK path (rekey).
    ///
    /// ## Why a return value, not `self.outcipher.is_some()` after the call?
    ///
    /// The C struct keeps `outstate: bool` and `outcipher: ctx*` separately.
    /// `receive_sig` sets the new `outcipher` but doesn't touch `outstate`;
    /// `receive_handshake` then checks `if(s->outstate)` — which is the *old*
    /// value, because `outstate = true` only happens on line 423, after the
    /// check. Collapsing those into one `Option<ChaPoly>` loses that bit of
    /// state. Threading it through as a return value keeps the C semantics
    /// without inventing a second field that exists only to mirror C's
    /// historical accident of having two.
    ///
    /// ## The ordering, and why it's that way
    ///
    /// During rekey (`outcipher` already `Some`):
    ///
    /// 1. Verify the peer's SIG.
    /// 2. ECDH → PRF → `self.key = Some(...)`.
    /// 3. If responder: `send_sig` — encrypted with **OLD** outcipher.
    /// 4. Drop `mykex`/`hiskex`.
    /// 5. If was_rekey: `send_ack` — encrypted with **OLD** outcipher.
    /// 6. **Now** switch `outcipher` to the new key.
    ///
    /// A natural Rust structure would set the key first then send. That'd
    /// produce different wire bytes (the SIG and ACK would encrypt under
    /// the new key) and the differential test would fail. The C ordering is
    /// correct *for the protocol* too — the peer hasn't switched its
    /// `incipher` yet (that happens on `receive_ack`), so sending under the
    /// new key would be undecryptable on their end.
    fn receive_sig(&mut self, body: &[u8], out: &mut Vec<Output>) -> Result<bool, SptpsError> {
        if body.len() != SIG_LEN {
            return Err(SptpsError::BadSig);
        }
        let sig: &[u8; SIG_LEN] = body.try_into().unwrap();

        // Verify transcript: `[!initiator][hiskex][mykex][label]`.
        // Swapped vs. send_sig: their initiator-bit is our !initiator-bit,
        // their mykex is our hiskex.
        let mykex = self.mykex.as_ref().expect("receive_sig with no mykex");
        let hiskex = self.hiskex.as_ref().expect("receive_sig with no hiskex");
        {
            let mut msg = Zeroizing::new(Vec::with_capacity(1 + 2 * KEX_LEN + self.label.len()));
            msg.push(u8::from(!self.role.is_initiator()));
            msg.extend_from_slice(&**hiskex);
            msg.extend_from_slice(&**mykex);
            msg.extend_from_slice(&self.label);
            sign::verify(&self.hiskey, &msg, sig).map_err(|_| SptpsError::BadSig)?;
        }

        // ECDH. `compute_shared` consumes the private key (zeroizes inside).
        // The peer's pubkey is bytes 33..65 of their KEX.
        let peer_pub: [u8; ECDH_PUBLIC_LEN] = hiskex[1 + NONCE_LEN..].try_into().unwrap();
        let ecdh = self.ecdh.take().expect("receive_sig with no ecdh");
        let shared = Zeroizing::new(ecdh.compute_shared(&peer_pub));

        self.generate_key_material(&shared);

        // ─── ORDER-SENSITIVE FROM HERE ───────────────────────────────
        // C lines 357..375. Don't reorder without re-reading the doc
        // comment above and `rust_vs_c_rekey` in tests/vs_c.rs.

        // The discriminant for "was this a rekey?". Captured before any
        // sends — send_sig/send_ack don't touch outcipher, but reading it
        // up here makes the data flow obvious.
        let was_rekey = self.outcipher.is_some();

        // C line 357: `if(!s->initiator && !send_sig(s)) return false;`
        // OLD outcipher (or None, during initial handshake — same thing).
        if !self.role.is_initiator() {
            self.send_sig(out);
        }

        // C lines 360-363: free mykex/hiskex. Zeroize-on-drop here.
        self.mykex = None;
        self.hiskex = None;

        // C line 366: `if(s->outstate && !send_ack(s)) return false;`
        // STILL the old outcipher.
        if was_rekey {
            self.send_ack(out);
        }

        // C lines 370-374: NOW set the new outcipher.
        // Initiator encrypts with key1, responder with key0.
        let key = self.key.as_ref().expect("just set");
        let half: &[u8; CIPHER_KEY_LEN] = if self.role.is_initiator() {
            (&key[CIPHER_KEY_LEN..]).try_into().unwrap()
        } else {
            (&key[..CIPHER_KEY_LEN]).try_into().unwrap()
        };
        self.outcipher = Some(ChaPoly::new(half)); // NOW the new key

        Ok(was_rekey)
    }

    /// `receive_handshake`: the state-machine switch.
    ///
    /// `rng` is needed because the `SecondaryKex` case sends a fresh KEX
    /// (responding to an unsolicited rekey from the peer).
    fn receive_handshake(
        &mut self,
        body: &[u8],
        rng: &mut impl RngCore,
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        match self.state {
            State::SecondaryKex | State::Kex => {
                // C uses fall-through: SECONDARY_KEX sends KEX then falls
                // into the KEX case. We replicate by checking the state
                // *before* doing anything, then converging.
                if self.state == State::SecondaryKex {
                    self.send_kex(rng, out)?;
                }
                self.receive_kex(body, out)?;
                self.state = State::Sig;
                Ok(())
            }
            State::Sig => {
                let was_rekey = self.receive_sig(body, out)?;
                if was_rekey {
                    // C line 420. outcipher is already the new key (set in
                    // receive_sig); but incipher is still the OLD key.
                    // We sit in Ack until the peer's ACK arrives and tells
                    // us they've switched their outcipher — then we can
                    // safely switch our incipher.
                    self.state = State::Ack;
                } else {
                    // C lines 422-428. Initial handshake: no ACK on the
                    // wire, just a synthetic one. The order here matters
                    // for the event sequence even though there's no wire
                    // output between the steps — the C fires
                    // `receive_record(HANDSHAKE, NULL, 0)` *after*
                    // receive_ack runs, so HandshakeDone comes after the
                    // incipher switch.
                    self.receive_ack(&[]).expect("synthetic ack body is empty");
                    out.push(Output::HandshakeDone);
                    self.state = State::SecondaryKex;
                }
                Ok(())
            }
            State::Ack => {
                self.receive_ack(body)?;
                out.push(Output::HandshakeDone);
                self.state = State::SecondaryKex;
                Ok(())
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Receive path: framing

    /// `sptps_receive_data`. Stream mode reassembles; datagram expects
    /// whole records.
    ///
    /// Returns `(consumed, outputs)`. **Stream mode processes at most one
    /// record per call** — `consumed < data.len()` is normal when the
    /// buffer holds more than one record. Loop until `consumed == 0` or
    /// the buffer's drained. (Datagram mode always consumes all-or-nothing.)
    ///
    /// `rng` is needed for the rekey-response case in `receive_handshake`.
    /// If you know you're not mid-rekey, you can pass a panicking RNG;
    /// it won't be touched.
    ///
    /// # Errors
    ///
    /// All variants are reachable. **`Err` is terminal in stream mode**:
    /// `inseqno` ticks before decrypt, so a decrypt failure poisons
    /// every later record. The daemon closes the
    /// connection on stream `Err`; don't retry. Datagram `Err` is
    /// per-packet and safe to ignore (next packet may succeed).
    pub fn receive(
        &mut self,
        data: &[u8],
        rng: &mut impl RngCore,
    ) -> Result<(usize, Vec<Output>), SptpsError> {
        let mut out = Vec::new();
        let consumed = match self.framing {
            Framing::Datagram => {
                self.receive_datagram(data, rng, &mut out)?;
                data.len()
            }
            Framing::Stream => self.receive_stream(data, rng, &mut out)?,
        };
        Ok((consumed, out))
    }

    /// `sptps_receive_data_datagram`. One whole record per call.
    fn receive_datagram(
        &mut self,
        data: &[u8],
        rng: &mut impl RngCore,
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        let min = if self.incipher.is_some() { 21 } else { 5 };
        if data.len() < min {
            return Err(SptpsError::BadSeqno); // "short packet" in C
        }
        let seqno = u32::from_be_bytes(data[..4].try_into().unwrap());
        let payload = &data[4..];

        if self.incipher.is_none() {
            // Plaintext handshake phase. Seqno must be exactly inseqno —
            // no replay window yet, just a strict counter.
            if seqno != self.replay.inseqno {
                return Err(SptpsError::BadSeqno);
            }
            // Same wrap-at-MAX as ReplayWindow::check above. Handshake
            // phase hitting this is implausible (3-packet handshake) but
            // costs nothing to be consistent.
            self.replay.inseqno = seqno.wrapping_add(1);
            let ty = payload[0];
            if ty != REC_HANDSHAKE {
                return Err(SptpsError::BadRecord);
            }
            return self.receive_handshake(&payload[1..], rng, out);
        }

        // Encrypted phase. Decrypt first, *then* check seqno — that order
        // matters for the replay window's update semantics: a packet that
        // fails decrypt shouldn't advance the window. C does it this way.
        let cipher = self.incipher.as_ref().unwrap();
        let pt = cipher
            .open(u64::from(seqno), payload)
            .map_err(|_| SptpsError::DecryptFailed)?;
        self.replay.check(seqno, true)?;

        let ty = pt[0];
        let body = &pt[1..];
        match ty {
            t if t < REC_HANDSHAKE => {
                out.push(Output::Record {
                    record_type: t,
                    bytes: body.to_vec(),
                });
                Ok(())
            }
            REC_HANDSHAKE => self.receive_handshake(body, rng, out),
            _ => Err(SptpsError::BadRecord), // 129/130: ALERT/CLOSE, unimplemented in C too
        }
    }

    /// Stream-mode reassembly. The bottom half of `sptps_receive_data`.
    ///
    /// The C does this in one flat function with `s->buflen` tracking
    /// progress. We do the same, just with `self.stream.buf.len()` as the
    /// progress counter instead of a separate field.
    fn receive_stream(
        &mut self,
        data: &[u8],
        rng: &mut impl RngCore,
        out: &mut Vec<Output>,
    ) -> Result<usize, SptpsError> {
        let mut consumed = 0;

        // Phase 1: read the 2 length bytes.
        if self.stream.buf.len() < 2 {
            let want = 2 - self.stream.buf.len();
            let take = want.min(data.len());
            self.stream.buf.extend_from_slice(&data[..take]);
            consumed += take;
            if self.stream.buf.len() < 2 {
                return Ok(consumed);
            }
            // Parse the length. Don't pre-allocate — `reclen` is
            // attacker-controlled, capping at u16 = 64K which is fine but
            // doing it lazily means a flood of length-only packets doesn't
            // pre-reserve 64K each.
            self.stream.reclen = u16::from_be_bytes(self.stream.buf[..2].try_into().unwrap());
            if take == data.len() {
                return Ok(consumed); // C early-returns here too
            }
        }

        // Phase 2: read the rest. Body + type + maybe tag.
        // `instate` in C; `incipher.is_some()` here.
        let extra = if self.incipher.is_some() {
            usize::from(self.stream.reclen) + 1 + TAG_LEN
        } else {
            usize::from(self.stream.reclen) + 1
        };
        let total = 2 + extra;
        let want = total - self.stream.buf.len();
        let take = want.min(data.len() - consumed);
        self.stream
            .buf
            .extend_from_slice(&data[consumed..consumed + take]);
        consumed += take;
        if self.stream.buf.len() < total {
            return Ok(consumed);
        }

        // Phase 3: have a whole record. Process it.
        // Unconditional tick, even on plaintext records. Same
        // significance as outseqno:
        // the first encrypted record's seqno is 2, not 0.
        let seqno = self.inseqno;
        self.inseqno = self.inseqno.wrapping_add(1);

        // Pull the framed bytes out and reset the buffer immediately.
        // The C does `buflen = 0` at the *end*, after processing — but if
        // processing errors and the caller calls receive again, the C
        // re-processes the same buffer. That's a latent C bug (replay on
        // error). We clear first; the differential test doesn't probe
        // post-error behaviour anyway.
        let mut framed = std::mem::take(&mut self.stream.buf);
        self.stream.reclen = 0;

        let (ty, body) = if let Some(cipher) = &self.incipher {
            let pt = cipher
                .open(u64::from(seqno), &framed[2..])
                .map_err(|_| SptpsError::DecryptFailed)?;
            framed.zeroize();
            // pt is `type[1] ‖ body[reclen]`. Own the body, don't reslice.
            let ty = pt[0];
            (ty, pt[1..].to_vec())
        } else {
            let ty = framed[2];
            (ty, framed[3..].to_vec())
        };

        match ty {
            t if t < REC_HANDSHAKE => {
                if self.incipher.is_none() {
                    return Err(SptpsError::BadRecord);
                }
                out.push(Output::Record {
                    record_type: t,
                    bytes: body,
                });
            }
            REC_HANDSHAKE => self.receive_handshake(&body, rng, out)?,
            _ => return Err(SptpsError::BadRecord),
        }

        Ok(consumed)
    }
}
