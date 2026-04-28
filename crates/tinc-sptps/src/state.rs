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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rand_core::{CryptoRng, RngCore};
use tinc_crypto::aead::{SptpsAead, SptpsCipher};
use tinc_crypto::chapoly::{KEY_LEN as CIPHER_KEY_LEN, TAG_LEN};
use tinc_crypto::ecdh::{EcdhPrivate, PUBLIC_LEN as ECDH_PUBLIC_LEN, SHARED_LEN};
use tinc_crypto::hybrid::{
    self, CT_LEN as MLKEM_CT_LEN, EK_LEN as MLKEM_EK_LEN, HYBRID_SHARED_LEN, MlKemPrivate,
    SS_LEN as MLKEM_SS_LEN, SptpsKex, kem_transcript_hash,
};
use tinc_crypto::prf::prf;
use tinc_crypto::sign::{self, PUBLIC_LEN as SIGN_PUBLIC_LEN, SIG_LEN, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{KEX_LEN, NONCE_LEN, REC_HANDSHAKE, VERSION};

/// The session label and AEAD selector, bundled because both feed the
/// SIG transcript and PRF seed and must agree on both ends.
///
/// `From<impl Into<Vec<u8>>>` gives the C-tinc-compatible default
/// (`SptpsAead::ChaCha20Poly1305`, empty label suffix), so every
/// caller that doesn't care about the AEAD — tests, the C-interop
/// harness, invitations — keeps passing a bare `Vec<u8>`/`&[u8]` to
/// [`Sptps::start`]. Only the daemon's per-edge tunnel start uses
/// [`with_aead`](Self::with_aead).
pub struct SptpsLabel {
    bytes: Vec<u8>,
    aead: SptpsAead,
}

impl SptpsLabel {
    /// Explicit AEAD. The label suffix is appended inside
    /// [`Sptps::start`], not here, so `bytes` stays exactly what the
    /// caller built (e.g. `make_udp_label`'s NUL-terminated string).
    #[must_use]
    pub fn with_aead(label: impl Into<Vec<u8>>, aead: SptpsAead) -> Self {
        Self {
            bytes: label.into(),
            aead,
        }
    }
}

impl<T: Into<Vec<u8>>> From<T> for SptpsLabel {
    fn from(label: T) -> Self {
        Self {
            bytes: label.into(),
            aead: SptpsAead::default(),
        }
    }
}

/// SIG transcript `[role-bit][kex_a][kex_b][label]`. send_sig and
/// receive_sig pass swapped (bit, kex order); one builder so they
/// can't drift apart.
fn sig_transcript(bit: bool, kex_a: &[u8], kex_b: &[u8], label: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut msg = Zeroizing::new(Vec::with_capacity(
        1 + kex_a.len() + kex_b.len() + label.len(),
    ));
    msg.push(u8::from(bit));
    msg.extend_from_slice(kex_a);
    msg.extend_from_slice(kex_b);
    msg.extend_from_slice(label);
    msg
}

/// Second half of the PRF output iff `initiator == outbound` — the
/// in/out symmetry as one predicate instead of two mirrored if/else.
fn key_half(key: &[u8], initiator: bool, outbound: bool) -> &[u8; CIPHER_KEY_LEN] {
    let half = if initiator == outbound {
        &key[CIPHER_KEY_LEN..]
    } else {
        &key[..CIPHER_KEY_LEN]
    };
    half.try_into().unwrap()
}

/// Max records sealed per `outcipher` before seqno allocation refuses.
/// Wire nonce is `outseqno as u32`; 2^32 = nonce reuse (Forbidden
/// Attack under AES-GCM, plaintext-XOR + forgery under ChaPoly). The
/// 2^16 margin absorbs concurrent shard `fetch_add` slop.
pub const SEAL_KEY_LIMIT: u64 = (1u64 << 32) - (1u64 << 16);

/// Soft threshold at which the daemon should proactively start a fresh
/// handshake. Half of [`SEAL_KEY_LIMIT`] so the hard limit stays the
/// safety net. See [`Sptps::rekey_due`].
pub const SEAL_REKEY_THRESHOLD: u64 = SEAL_KEY_LIMIT / 2;

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
    /// Stream receive: pre-auth `reclen` > [`MAX_PREAUTH_RECLEN`].
    RecordTooLong,
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
        matches!(self, Self::Initiator)
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
#[derive(Clone, PartialEq, Eq)]
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

// Manual Debug: `bytes` is decrypted payload / KEX material; print len
// only so `{:?}` in logs or assert_eq! failures doesn't leak it.
impl core::fmt::Debug for Output {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire { record_type, bytes } => f
                .debug_struct("Wire")
                .field("record_type", record_type)
                .field("len", &bytes.len())
                .finish(),
            Self::Record { record_type, bytes } => f
                .debug_struct("Record")
                .field("record_type", record_type)
                .field("len", &bytes.len())
                .finish(),
            Self::HandshakeDone => f.write_str("HandshakeDone"),
        }
    }
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
    /// Hybrid initial handshake only: both ciphers installed, encrypted
    /// empty ACK sent, waiting for the peer's as explicit key
    /// confirmation. `HandshakeDone` fires on receipt. Classical never
    /// reaches here (C-tinc wire compat).
    Confirm,
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
/// Fields are private; the daemon never touches them directly.
#[derive(Default)]
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
    fn new(win: usize) -> Self {
        Self {
            inseqno: 0,
            late: vec![0; win],
            farfuture: 0,
        }
    }

    /// Shard-side replay commit. Public wrapper around the
    /// daemon-private `check(seqno, true)` so a shard holding
    /// `Arc<Mutex<ReplayWindow>>` (from [`Sptps::replay_handle`]) can
    /// commit without going through `&mut Sptps`. Same body as
    /// [`Sptps::replay_check`]; the wrapper exists because that one
    /// borrows `self.replay` through `Sptps`, and the shard has the
    /// lock guard directly.
    ///
    /// Call AFTER decrypt succeeds. The window is order-sensitive
    /// (`farfuture` heuristic); a forged seqno that fails the tag
    /// must not advance it. Same gate as [`Sptps::open_data_into`].
    ///
    /// # Errors
    /// `BadSeqno` on replay/out-of-window.
    pub fn check_public(&mut self, seqno: u32) -> Result<(), SptpsError> {
        self.check(seqno, true)
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
    #[expect(clippy::cast_possible_truncation)] // late.len() is replay-window bytes (≪ u32::MAX); seqno arith is mod 2^32
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
    // `Arc<Mutex<_>>`: shard hand-off. The daemon's single-thread path
    // never contends (one writer); `lock()` on an uncontended `Mutex`
    // is a CAS + fence, ~50ns vs the ~4µs ChaCha decrypt it follows.
    // The `Arc` lets [`replay_handle`] hand a clone to a shard so it
    // can `lock()` from a non-epoll thread. `into_inner` on poison: a
    // panicking shard left the bitmap mid-write; the worst case is one
    // false positive/negative on the replay check, and the daemon is
    // about to tear the session down anyway (the shard is dead).
    replay: Arc<Mutex<ReplayWindow>>,

    // ─── Crypto state ───
    // `instate`/`outstate` in C are bools that gate encryption. Rust models
    // that with Option: `None` = plaintext, `Some(cipher)` = encrypted.
    // The seqnos live alongside even when None because they tick during
    // the plaintext handshake too (`outseqno++` happens unconditionally
    // in send_record_priv).
    incipher: Option<SptpsCipher>,
    inseqno: u32, // stream mode only; datagram uses ReplayWindow.inseqno
    outcipher: Option<SptpsCipher>,
    // `Arc<AtomicU64>`: shard hand-off. `fetch_add(n, Relaxed)` from
    // any thread allocates a contiguous run; the truncation to u32 at
    // use is the same wrap C's unsigned overflow gives. Wider counter
    // doesn't change wire semantics: `(prev + n) as u32 ==
    // (prev as u32).wrapping_add(n)` for all values. The `Arc` lets
    // [`outseqno_handle`] hand a clone to a shard. `Relaxed` is
    // correct: the seqno is just a nonce, the per-shard SHIP order may
    // differ from the cross-shard ALLOC order, and the receiver's
    // 128-slot replay window absorbs the interleave.
    outseqno: Arc<AtomicU64>,
    /// `outseqno` at the moment `outcipher` was installed; see
    /// [`SEAL_KEY_LIMIT`].
    out_key_base: u64,

    // ─── Handshake-transient state ───
    // mykex/hiskex/ecdh/key are all heap-allocated in C, freed at specific
    // points in the handshake. Same lifecycle here as Options.
    //
    // `mykex`/`hiskex` are 65-byte KEX bodies. They live from KEX-send to
    // SIG-receive: the SIG transcript needs both. C frees them in
    // `receive_sig` after the verify.
    // `Vec`, not `[u8; KEX_LEN]`: hybrid mode's KEX body is 1249 bytes
    // (classical 65 + ML-KEM ek 1184). The body length is fully
    // determined by `self.kex`, checked in `kex_body_ok`.
    mykex: Option<Zeroizing<Vec<u8>>>,
    hiskex: Option<Zeroizing<Vec<u8>>>,
    /// ECDH ephemeral. Lives from `send_kex` (where it generates the
    /// pubkey that goes in `mykex`) to `receive_sig` (where it computes
    /// the shared secret and is consumed). `EcdhPrivate::compute_shared`
    /// takes `self` by value, so the Option dance is natural.
    ecdh: Option<EcdhPrivate>,
    /// ML-KEM-768 decapsulation key. Same lifecycle as `ecdh`: born
    /// in `send_kex`, consumed in `receive_sig`. `None` in classical
    /// mode. Boxed inside `MlKemPrivate` (2400 B), so the `Option`
    /// here is pointer-sized.
    mlkem: Option<MlKemPrivate>,
    /// Our ML-KEM ciphertext + the shared secret it encapsulates,
    /// produced in `receive_kex` (against the peer's `ek`) and
    /// consumed in `send_sig` / `receive_sig` respectively. Paired so
    /// one `Option` covers both — they're born and die together.
    #[expect(clippy::type_complexity)]
    mlkem_encap: Option<(Zeroizing<[u8; MLKEM_CT_LEN]>, Zeroizing<[u8; MLKEM_SS_LEN]>)>,
    /// 128 bytes of PRF output: `key0[64] ‖ key1[64]`. Lives from
    /// `generate_key_material` to `receive_ack` (the `incipher` half is
    /// only consumed when we know the peer is ready). Freed there.
    key: Option<Zeroizing<[u8; 2 * CIPHER_KEY_LEN]>>,

    // ─── Static config ───
    mykey: SigningKey,
    hiskey: [u8; SIGN_PUBLIC_LEN],
    label: Vec<u8>,
    /// Static, per-session. Selects the record AEAD and contributes
    /// the cipher discriminator byte to `label` (so a peer configured
    /// for a different AEAD fails SIG verify, not record decrypt).
    aead: SptpsAead,
    kex: SptpsKex,
}

/// Expected KEX body length for `kex`. Hybrid appends the ML-KEM
/// encapsulation key after the classical `[ver|nonce|ecdh_pk]`.
const fn kex_len(kex: SptpsKex) -> usize {
    match kex {
        SptpsKex::X25519 => KEX_LEN,
        SptpsKex::X25519MlKem768 => KEX_LEN + MLKEM_EK_LEN,
    }
}

/// Expected SIG body length. Hybrid appends our ML-KEM ciphertext
/// after the Ed25519 signature — the SPTPS flow sends both KEX
/// records blind (each side calls `send_kex` from `start`), so the
/// earliest point either side can encapsulate is on receipt of the
/// peer's KEX, and the earliest record that can carry the resulting
/// `ct` is SIG.
const fn sig_len(kex: SptpsKex) -> usize {
    match kex {
        SptpsKex::X25519 => SIG_LEN,
        SptpsKex::X25519MlKem768 => SIG_LEN + MLKEM_CT_LEN,
    }
}

/// Largest legitimate handshake record body (hybrid KEX = 1249, SIG = 1152)
/// plus slack. Pre-auth `reclen` is attacker-chosen plaintext; clamping it
/// here bounds the reassembly buffer an unauthenticated peer can force.
pub const MAX_PREAUTH_RECLEN: usize = {
    let kex = kex_len(SptpsKex::X25519MlKem768);
    let sig = sig_len(SptpsKex::X25519MlKem768);
    (if kex > sig { kex } else { sig }) + 16
};

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
    pub fn start(
        role: Role,
        framing: Framing,
        mykey: SigningKey,
        hiskey: [u8; SIGN_PUBLIC_LEN],
        label: impl Into<SptpsLabel>,
        replaywin: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, Vec<Output>) {
        Self::start_with(
            role,
            framing,
            SptpsKex::X25519,
            mykey,
            hiskey,
            label,
            replaywin,
            rng,
        )
    }

    /// [`start`](Self::start) with an explicit key-exchange mode.
    ///
    /// When either `kex` or the label's `aead` is non-default,
    /// `[kex.discriminator(), aead.discriminator()]` is appended to
    /// `label`. Both the SIG transcript and the PRF seed include the
    /// label, so a static-config mismatch (in either dimension)
    /// surfaces as `BadSig` during the handshake — clean failure, no
    /// chance of deriving keys one side can't open. With both at
    /// default the suffix is empty: byte-identical to C tinc, pinned
    /// by `tests/vs_c.rs`. See `docs/PROTOCOL.md`.
    #[expect(clippy::missing_panics_doc, clippy::too_many_arguments)]
    pub fn start_with(
        role: Role,
        framing: Framing,
        kex: SptpsKex,
        mykey: SigningKey,
        hiskey: [u8; SIGN_PUBLIC_LEN],
        label: impl Into<SptpsLabel>,
        replaywin: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, Vec<Output>) {
        let SptpsLabel {
            bytes: mut label,
            aead,
        } = label.into();
        let kd = kex.discriminator();
        let cd = aead.discriminator();
        if kd != 0 || cd != 0 {
            // Suffix, not prefix: the C label format is
            // `"tinc TCP key expansion <a> <b>\0"`; appending after
            // the NUL keeps the human-readable prefix intact in
            // packet captures while still perturbing every byte of
            // PRF output.
            label.push(kd);
            label.push(cd);
        }
        let mut s = Self {
            role,
            framing,
            state: State::Kex,
            stream: StreamBuf::default(),
            replay: Arc::new(Mutex::new(ReplayWindow::new(replaywin))),
            incipher: None,
            inseqno: 0,
            outcipher: None,
            outseqno: Arc::new(AtomicU64::new(0)),
            out_key_base: 0,
            mykex: None,
            hiskex: None,
            ecdh: None,
            mlkem: None,
            mlkem_encap: None,
            key: None,
            mykey,
            hiskey,
            label,
            aead,
            kex,
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
        // u64 -> u32 truncate: same wrap as C's `s->outseqno++`
        // unsigned overflow. fetch_add returns the *previous* value.
        #[expect(clippy::cast_possible_truncation)]
        // wire seqno IS 4 bytes; mod-2^32 is the protocol
        let seqno = self.outseqno.fetch_add(1, Ordering::Relaxed) as u32;

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
        if !self.app_send_ready() || record_type >= REC_HANDSHAKE || self.needs_rekey() {
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
        if !self.app_send_ready() {
            return Err(SptpsError::InvalidState);
        }
        let seqno = self.alloc_seqnos(1).ok_or(SptpsError::InvalidState)?;
        // Infallible: outcipher checked above, framing/record_type
        // checked at the top of this fn.
        self.seal_with_seqno(seqno, record_type, body, out, headroom)
    }

    /// Reserve a contiguous run of `n` outgoing sequence numbers.
    /// Returns the base; caller assigns `base.wrapping_add(i)` to
    /// chunk `i`. The wrap is correct: seqno is u32 on the wire,
    /// wraps at ~4G records per session, and the C wraps too
    /// (`s->outseqno++` is unsigned overflow there).
    ///
    /// Par-encrypt's serial preamble: one thread bumps `outseqno`;
    /// N workers then call [`seal_with_seqno`] (`&self`) with
    /// disjoint seqnos. The seqno space stays exactly what `n` calls
    /// to [`seal_data_into`] would have produced.
    ///
    /// Caller MUST emit all `n` reserved seqnos. Gaps are harmless on
    /// the wire (replay window tolerates skips) but waste seqno space.
    ///
    /// `None` once [`SEAL_KEY_LIMIT`] records have been sealed under
    /// the current key — the hard nonce-reuse gate. Caller drops the
    /// packet; [`SEAL_REKEY_THRESHOLD`] should have rekeyed long before.
    #[must_use]
    pub fn alloc_seqnos(&self, n: u32) -> Option<u32> {
        // u64 fetch_add, truncate at read. `(prev + n) as u32 ==
        // (prev as u32).wrapping_add(n)`: the high bits the wider
        // counter carries are invisible on the wire. `Relaxed`: the
        // seqno is a nonce, not a happens-before edge; uniqueness is
        // what matters and fetch_add gives it monotonically.
        let prev = self.outseqno.fetch_add(u64::from(n), Ordering::Relaxed);
        // Gate on `prev`: SEAL_KEY_LIMIT's 2^16 margin absorbs the one
        // batch that can race past. Burned seqnos on `None` are a gap.
        if prev.wrapping_sub(self.out_key_base) >= SEAL_KEY_LIMIT {
            return None;
        }
        #[expect(clippy::cast_possible_truncation)]
        // wire seqno IS 4 bytes; mod-2^32 is the protocol
        let base = prev as u32;
        Some(base)
    }

    /// Which AEAD this session seals records with. The shard fast
    /// path needs it alongside [`outcipher_key`]/[`incipher_key`] to
    /// rebuild a matching [`SptpsCipher`] without holding `&Sptps`.
    #[must_use]
    pub const fn aead(&self) -> SptpsAead {
        self.aead
    }

    /// Which side of the handshake this instance is. Used by the
    /// daemon's crossed-`REQ_KEY` tie-break (`gossip::on_req_key`).
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Records sealed under the current `outcipher` so far.
    #[must_use]
    pub fn sealed_count(&self) -> u64 {
        self.outseqno
            .load(Ordering::Relaxed)
            .wrapping_sub(self.out_key_base)
    }

    /// `outseqno` at which the current `outcipher` was installed.
    /// Paired with [`outseqno_handle`](Self::outseqno_handle) for the
    /// shard-side [`SEAL_KEY_LIMIT`] gate.
    #[must_use]
    pub fn out_key_base(&self) -> u64 {
        self.out_key_base
    }

    /// True once [`SEAL_REKEY_THRESHOLD`] records have been sealed
    /// under the current key. Daemon's periodic sweep polls this.
    #[must_use]
    pub fn rekey_due(&self) -> bool {
        self.sealed_count() >= SEAL_REKEY_THRESHOLD
    }

    /// Hard limit reached; app-data sends return `InvalidState`.
    fn needs_rekey(&self) -> bool {
        self.sealed_count() >= SEAL_KEY_LIMIT
    }

    /// App-data send permitted. `Confirm` has ciphers but no
    /// `HandshakeDone` yet; sealing there would bypass key-confirm.
    /// Classical never enters `Confirm` (C-tinc unchanged).
    fn app_send_ready(&self) -> bool {
        self.outcipher.is_some() && self.state != State::Confirm
    }

    /// Clone the outgoing seqno counter for shard hand-off. The shard
    /// `fetch_add(1, Relaxed)`s from its own thread and pairs the
    /// result with [`seal_with_seqno`] (or its own `ChaPoly` built
    /// from [`outcipher_key`]). Multiple shards sharing one counter is
    /// the point: automq hashes per-FLOW, so two flows to the same
    /// peer can land on different shards — both seal, both need fresh
    /// nonces from the same space.
    ///
    /// The wire still wraps at 2^32 (`seqno.to_be_bytes()` is 4 bytes
    /// in [`seal_with_seqno`]). The u64 counter just means the wrap
    /// happens via truncation instead of `wrapping_add`; same bits.
    #[must_use]
    pub fn outseqno_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.outseqno)
    }

    /// Clone the replay window for shard hand-off. Shard locks for
    /// ~50ns AFTER decrypt (which is ~4µs/pkt at MTU); contention only
    /// when two shards hit the same peer in the same instant. The
    /// far-future heuristic inside is order-sensitive across shards,
    /// but two shards' arrivals are *already* ordered by the kernel's
    /// `SO_REUSEPORT` hash — each peer's packets land on one socket.
    /// The cross-shard case is roam (PMTU re-probe from a new addr,
    /// hashed to a different shard), rare.
    #[must_use]
    pub fn replay_handle(&self) -> Arc<Mutex<ReplayWindow>> {
        Arc::clone(&self.replay)
    }

    /// Lock the replay window, recovering from poison: the window holds
    /// no invariants a panicking writer could leave half-broken.
    fn replay_mut(&self) -> MutexGuard<'_, ReplayWindow> {
        self.replay.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Copy the outbound cipher key. Shard hand-off: workers get a
    /// 64-byte copy per session so they never hold `&Sptps` across a
    /// re-KEX. Re-KEX swaps `outcipher`; an in-flight seal with the
    /// old key produces a packet the peer rejects (tag mismatch under
    /// the new key) — one drop, peer's TCP retransmits. Cheaper than
    /// `Arc<ChaPoly>` at ~800k seals/s: no refcount inc/dec on a
    /// contended cacheline.
    ///
    /// `None` until [`Output::HandshakeDone`].
    ///
    /// Pair with seqnos from [`outseqno_handle`] and
    /// `tinc_crypto::chapoly::ChaPoly::new(&key).seal_into(...)`.
    /// Produces wire bytes identical to [`seal_with_seqno`] — the
    /// `seal_into` API is what [`seal_with_seqno`] calls internally;
    /// same body span, same headroom math.
    #[must_use]
    pub fn outcipher_key(&self) -> Option<Zeroizing<[u8; CIPHER_KEY_LEN]>> {
        self.outcipher
            .as_ref()
            .filter(|_| self.state != State::Confirm)
            .map(|c| Zeroizing::new(*c.key_bytes()))
    }

    /// Copy the inbound cipher key. Mirror of [`outcipher_key`] for
    /// par-decrypt. Pair with [`replay_handle`].
    ///
    /// `None` until [`Output::HandshakeDone`].
    #[must_use]
    pub fn incipher_key(&self) -> Option<Zeroizing<[u8; CIPHER_KEY_LEN]>> {
        self.incipher
            .as_ref()
            .filter(|_| self.state != State::Confirm)
            .map(|c| Zeroizing::new(*c.key_bytes()))
    }

    /// Seal one datagram with a caller-supplied seqno. `&self`: no
    /// state mutation. Body of [`seal_data_into`] minus the
    /// `outseqno++`.
    ///
    /// Precondition: `seqno` came from [`alloc_seqnos`] and is not
    /// reused. Reuse is a nonce reuse, which leaks the XOR of two
    /// plaintexts under ChaCha20 — catastrophic. The type system
    /// can't enforce this; the par-encrypt loop's `base + i` indexing
    /// does.
    ///
    /// On return, `out` is `[0u8; headroom] ‖ seqno:4 ‖ enc(type ‖
    /// body) ‖ tag:16` — byte-identical to [`seal_data_into`] called
    /// when `outseqno == seqno`. `out` is **cleared** first.
    ///
    /// # Errors
    ///
    /// `InvalidState` if not [`Framing::Datagram`], if `outcipher`
    /// is `None` (handshake not complete), or if `record_type >= 128`.
    /// Same gate as [`seal_data_into`].
    pub fn seal_with_seqno(
        &self,
        seqno: u32,
        record_type: u8,
        body: &[u8],
        out: &mut Vec<u8>,
        headroom: usize,
    ) -> Result<(), SptpsError> {
        if self.framing != Framing::Datagram
            || record_type >= REC_HANDSHAKE
            || self.state == State::Confirm
        {
            return Err(SptpsError::InvalidState);
        }
        let Some(cipher) = self.outcipher.as_ref() else {
            return Err(SptpsError::InvalidState);
        };

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
    /// `forward_packet(&mut out)`).
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
        // Decrypt-then-replay-check (see open_with_seqno doc): a
        // packet that fails decrypt shouldn't advance the window.
        let (seqno, ty) = self.open_with_seqno(data, out, headroom)?;

        // Check replay BEFORE leaving plaintext in `out`. On reject,
        // truncate — same Err contract as open_with_seqno's BadRecord
        // arm: `out == [0u8; headroom]` on every Err return. Decrypt
        // first is still required (forged seqnos must not advance the
        // window) but check-before-shift means the memmove below only
        // runs on the Ok path.
        if let Err(e) = self.replay_mut().check(seqno, true) {
            out.truncate(headroom);
            return Err(e);
        }

        // Strip the type byte: shift body left by one. Small memmove.
        out.copy_within(headroom + 1.., headroom);
        out.truncate(out.len() - 1);
        Ok(ty)
    }

    /// Decrypt one datagram WITHOUT touching the replay window.
    /// `&self`: no state mutation. Body of [`open_data_into`] minus
    /// `replay.check()` and minus the type-byte strip.
    ///
    /// Par-decrypt: N workers call this concurrently (the cipher
    /// borrow is `&self`); the serial epilogue then calls
    /// [`replay_check`] in arrival order. Decrypt is ~4µs/pkt at
    /// MTU; replay check is ~10ns. Amdahl says parallelize the 4µs.
    ///
    /// On `Ok((seqno, ty))`: `out` is `[0u8; headroom] ‖ type:1 ‖
    /// body`. The type byte is NOT stripped (vs [`open_data_into`])
    /// — caller does that after replay-check passes, so a replayed
    /// packet doesn't pay the memmove. `out` is **cleared** first.
    ///
    /// On every `Err`: `out == [0u8; headroom]` (same contract as
    /// [`open_data_into`]).
    ///
    /// # Errors
    ///
    /// - `InvalidState`: not [`Framing::Datagram`], or no `incipher`.
    /// - `BadSeqno`: packet shorter than 21 bytes.
    /// - `DecryptFailed`: tag mismatch. `out` is unchanged (the
    ///   `open_into` extend happens after the tag check).
    /// - `BadRecord`: decrypted `record_type >= REC_HANDSHAKE`. `out`
    ///   is truncated back to `headroom`.
    pub fn open_with_seqno(
        &self,
        data: &[u8],
        out: &mut Vec<u8>,
        headroom: usize,
    ) -> Result<(u32, u8), SptpsError> {
        if self.framing != Framing::Datagram || self.state == State::Confirm {
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

        // The type byte lands at out[headroom], body at out[headroom+1..].
        cipher
            .open_into(u64::from(seqno), &data[4..], out, headroom)
            .map_err(|_| SptpsError::DecryptFailed)?;

        let ty = out[headroom];
        if ty >= REC_HANDSHAKE {
            // Restore out to its pre-call shape.
            out.truncate(headroom);
            return Err(SptpsError::BadRecord);
        }
        Ok((seqno, ty))
    }

    /// Commit `seqno` to the replay window. Serial epilogue for
    /// par-decrypt: after [`open_with_seqno`] authenticates the
    /// packet, this records it as seen. `&mut self` because the
    /// window's bitmap mutates.
    ///
    /// Separate from [`open_with_seqno`] so the order is preserved:
    /// decrypt is parallel and arbitrary-order; replay-commit is
    /// serial in arrival order. The window's far-future heuristic
    /// (the farfuture counter) is order-sensitive.
    ///
    /// # Errors
    ///
    /// `BadSeqno` if `seqno` is replayed or out-of-window. Caller
    /// drops the (already-decrypted) plaintext.
    pub fn replay_check(&mut self, seqno: u32) -> Result<(), SptpsError> {
        self.replay_mut().check(seqno, true)
    }

    /// `send_kex`: emit `version[1] ‖ nonce[32] ‖ ecdh_pubkey[32]`.
    ///
    /// Consumes 64 bytes from `rng` (nonce, then seed). The C calls
    /// `randomize` for the nonce then `ecdh_generate_public` (which calls
    /// `randomize` internally for the seed); same order here so the
    /// differential test sees the same byte stream.
    fn send_kex(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        // Re-KEX before the previous one finished. State machine bug,
        // not a wire error.
        if self.mykex.is_some() {
            return Err(SptpsError::InvalidState);
        }

        let mut kex = Zeroizing::new(vec![0u8; kex_len(self.kex)]);
        kex[0] = VERSION;

        // RNG order matters: nonce first, ECDH seed second. C's
        // `randomize(s->mykex->nonce)` then `ecdh_generate_public()`.
        // ML-KEM keygen draws *after* both, so the first 64 RNG bytes
        // are identical to classical mode — the `vs_c` harness relies
        // on that ordering and never runs hybrid.
        rng.fill_bytes(&mut kex[1..=NONCE_LEN]);

        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        let (ecdh, pubkey) = EcdhPrivate::from_seed(&seed);
        kex[1 + NONCE_LEN..KEX_LEN].copy_from_slice(&pubkey);

        if self.kex == SptpsKex::X25519MlKem768 {
            let (dk, ek) = MlKemPrivate::generate(rng);
            kex[KEX_LEN..].copy_from_slice(&ek);
            self.mlkem = Some(dk);
        }

        // Wire it before stashing — C does `s->mykex = ...; send_record(mykex)`
        // but the order doesn't observably matter, both touch only mykex.
        self.send_record_priv(REC_HANDSHAKE, &kex, out);
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
        let (mykex, hiskex) = self.kex_pair();
        let msg = sig_transcript(self.role.is_initiator(), mykex, hiskex, &self.label);
        let sig = self.mykey.sign(&msg);
        match self.kex {
            SptpsKex::X25519 => self.send_record_priv(REC_HANDSHAKE, &sig, out),
            SptpsKex::X25519MlKem768 => {
                // `[sig(64) ‖ mlkem_ct(1088)]`. `send_sig` is only
                // reached after `hiskex` is stashed, so `receive_kex`
                // has already encapsulated.
                let (ct, _ss) = self.mlkem_encap.as_ref().expect("encap set in receive_kex");
                let mut body = Zeroizing::new(Vec::with_capacity(sig_len(self.kex)));
                body.extend_from_slice(&sig);
                body.extend_from_slice(&**ct);
                self.send_record_priv(REC_HANDSHAKE, &body, out);
            }
        }
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
    pub fn force_kex(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<Output>, SptpsError> {
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

    /// Both KEX blobs, asserted present. The state machine only reaches
    /// SIG/key-derivation after stashing both, so absence is a bug.
    fn kex_pair(&self) -> (&[u8], &[u8]) {
        (
            self.mykex.as_deref().expect("mykex present"),
            self.hiskex.as_deref().expect("hiskex present"),
        )
    }

    /// `receive_kex` precondition. Factored so `SecondaryKex` can run
    /// it BEFORE `send_kex` (a bad unsolicited rekey mustn't burn `mykex`).
    fn kex_body_ok(&self, body: &[u8]) -> bool {
        body.len() == kex_len(self.kex) && body[0] == VERSION && self.hiskex.is_none()
    }

    /// `receive_kex`: stash peer's KEX, sign-if-initiator.
    fn receive_kex(
        &mut self,
        body: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        if !self.kex_body_ok(body) {
            return Err(SptpsError::BadKex);
        }
        self.hiskex = Some(Zeroizing::new(body.to_vec()));

        if self.kex == SptpsKex::X25519MlKem768 {
            // Encapsulate now: both roles have the peer's ek at this
            // point, and both will need `my_ct` before their next
            // send (`send_sig`). Doing it here keeps `send_sig` a
            // pure formatter with no RNG dependency.
            let peer_ek: &[u8; MLKEM_EK_LEN] =
                body[KEX_LEN..].try_into().expect("kex_body_ok checked len");
            // `ss` pre-`Zeroizing`; `ct` wrapped for pair-shape symmetry.
            let (ct, ss) = hybrid::encapsulate(peer_ek, rng);
            self.mlkem_encap = Some((Zeroizing::new(ct), ss));
        }

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
    ///
    /// `kem_hash` is appended after `label`: empty in classical mode
    /// (seed byte-identical to C tinc), `kem_transcript_hash` in hybrid.
    fn generate_key_material(&mut self, shared: &[u8], kem_hash: &[u8]) {
        // No NUL: C does `sizeof("key expansion") - 1`.
        const PREFIX: &[u8] = b"key expansion";

        let (mykex, hiskex) = self.kex_pair();
        let (init_kex, resp_kex) = if self.role.is_initiator() {
            (mykex, hiskex)
        } else {
            (hiskex, mykex)
        };
        let init_nonce = &init_kex[1..=NONCE_LEN];
        let resp_nonce = &resp_kex[1..=NONCE_LEN];

        let mut seed = Zeroizing::new(Vec::with_capacity(
            PREFIX.len() + 2 * NONCE_LEN + self.label.len() + kem_hash.len(),
        ));
        seed.extend_from_slice(PREFIX);
        seed.extend_from_slice(init_nonce);
        seed.extend_from_slice(resp_nonce);
        seed.extend_from_slice(&self.label);
        seed.extend_from_slice(kem_hash);

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
        self.incipher = Some(SptpsCipher::new(
            self.aead,
            key_half(&*key, self.role.is_initiator(), false),
        ));
        // Replay window kept across rekey: C seqno is session-monotone.
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
        if body.len() != sig_len(self.kex) {
            return Err(SptpsError::BadSig);
        }
        let sig: &[u8; SIG_LEN] = body[..SIG_LEN].try_into().unwrap();

        // Verify transcript: `[!initiator][hiskex][mykex][label]`.
        // Swapped vs. send_sig: their initiator-bit is our !initiator-bit,
        // their mykex is our hiskex.
        // Direct fields, not `kex_pair()`: borrowck must see them as
        // disjoint from the `ecdh`/`mlkem` `.take()`s below.
        let mykex = self.mykex.as_deref().expect("mykex present");
        let hiskex = self.hiskex.as_deref().expect("hiskex present");
        {
            let msg = sig_transcript(!self.role.is_initiator(), hiskex, mykex, &self.label);
            sign::verify(&self.hiskey, &msg, sig).map_err(|_| SptpsError::BadSig)?;
        }

        // ECDH. `compute_shared` consumes the private key (zeroizes inside).
        // The peer's pubkey is bytes 33..65 of their KEX.
        let peer_pub: [u8; ECDH_PUBLIC_LEN] = hiskex[1 + NONCE_LEN..KEX_LEN].try_into().unwrap();
        // Datagram mode lets a peer replay SIG: if a prior SIG took
        // `ecdh` and bailed on a fallible op below (e.g. small-order
        // `compute_shared`), the next must error, not panic.
        let ecdh = self.ecdh.take().ok_or(SptpsError::InvalidState)?;
        let x25519 = Zeroizing::new(ecdh.compute_shared(&peer_pub).ok_or(SptpsError::BadKex)?);

        match self.kex {
            SptpsKex::X25519 => self.generate_key_material(&*x25519, &[]),
            SptpsKex::X25519MlKem768 => {
                // Decapsulate the peer's ct (carried after their sig).
                let peer_ct: &[u8; MLKEM_CT_LEN] = body[SIG_LEN..].try_into().unwrap();
                // Same replayed-SIG reason as the `ecdh` take above.
                let dk = self.mlkem.take().ok_or(SptpsError::InvalidState)?;
                let ss_decap = dk.decapsulate(peer_ct);
                // `mlkem_encap` stays put: responder's `send_sig` below
                // still needs `my_ct`. Dropped with `mykex`/`hiskex`.
                let (my_ct, ss_encap) = self.mlkem_encap.as_ref().expect("set in receive_kex");

                // Role-symmetric ordering, same trick as the PRF nonce
                // order: `ss_i2r` is "initiator encapsulated, responder
                // decapsulated". Initiator's encap == responder's decap.
                let init = self.role.is_initiator();
                let (ss_i2r, ss_r2i): (&[u8; MLKEM_SS_LEN], &[u8; MLKEM_SS_LEN]) = if init {
                    (ss_encap, &ss_decap)
                } else {
                    (&ss_decap, ss_encap)
                };
                let mut shared = Zeroizing::new([0u8; HYBRID_SHARED_LEN]);
                shared[..SHARED_LEN].copy_from_slice(&*x25519);
                shared[SHARED_LEN..SHARED_LEN + MLKEM_SS_LEN].copy_from_slice(ss_i2r);
                shared[SHARED_LEN + MLKEM_SS_LEN..].copy_from_slice(ss_r2i);

                // Bind both `ek`s + both `ct`s (role-ordered) into the
                // PRF seed; see `docs/PROTOCOL.md` for the rationale.
                let (init_ek, resp_ek) = if init {
                    (&mykex[KEX_LEN..], &hiskex[KEX_LEN..])
                } else {
                    (&hiskex[KEX_LEN..], &mykex[KEX_LEN..])
                };
                let (ct_i2r, ct_r2i): (&[u8], &[u8]) = if init {
                    (&**my_ct, peer_ct)
                } else {
                    (peer_ct, &**my_ct)
                };
                let kem_hash = kem_transcript_hash(init_ek, resp_ek, ct_i2r, ct_r2i);

                self.generate_key_material(&*shared, &kem_hash);
            }
        }

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
        // Hybrid transients: dk already `take`n above; the (ct, ss)
        // pair is done now that the responder's `send_sig` has run.
        self.mlkem_encap = None;

        // C line 366: `if(s->outstate && !send_ack(s)) return false;`
        // STILL the old outcipher.
        if was_rekey {
            self.send_ack(out);
        }

        // C lines 370-374: NOW set the new outcipher.
        // Initiator encrypts with key1, responder with key0.
        let key = self.key.as_ref().expect("just set");
        self.outcipher = Some(SptpsCipher::new(
            self.aead,
            key_half(&**key, self.role.is_initiator(), true),
        ));
        // Wire seqno stays session-monotone (C-tinc parity); rebase
        // the per-key seal limit. `alloc_seqnos`'s `< SEAL_KEY_LIMIT
        // < 2^32` gate keeps every nonce in one epoch distinct mod 2^32.
        self.out_key_base = self.outseqno.load(Ordering::Relaxed);

        Ok(was_rekey)
    }

    /// Shared dispatch tail of `receive_datagram`/`receive_stream`.
    /// `encrypted=false` rejects app records (stream's plaintext phase
    /// only carries handshake records).
    fn dispatch_record(
        &mut self,
        ty: u8,
        body: &[u8],
        encrypted: bool,
        rng: &mut (impl RngCore + CryptoRng),
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        match ty {
            t if t < REC_HANDSHAKE => {
                // `Confirm`: drop app data reordered ahead of the
                // peer's ACK; no `Record` before `HandshakeDone`.
                if !encrypted || self.state == State::Confirm {
                    return Err(SptpsError::BadRecord);
                }
                out.push(Output::Record {
                    record_type: t,
                    bytes: body.to_vec(),
                });
                Ok(())
            }
            REC_HANDSHAKE => self.receive_handshake(body, rng, out),
            _ => Err(SptpsError::BadRecord),
        }
    }

    /// `receive_handshake`: the state-machine switch.
    ///
    /// `rng` is needed because the `SecondaryKex` case sends a fresh KEX
    /// (responding to an unsolicited rekey from the peer).
    fn receive_handshake(
        &mut self,
        body: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
        out: &mut Vec<Output>,
    ) -> Result<(), SptpsError> {
        match self.state {
            State::SecondaryKex | State::Kex => {
                // C fall-through: SECONDARY_KEX does send_kex then the
                // KEX case. Validate `body` first so a malformed peer
                // KEX doesn't leave `mykex` set (which would make every
                // later `send_kex` return `InvalidState`). Can't just
                // call `receive_kex` first: its initiator branch calls
                // `send_sig`, which needs `mykex`.
                if self.state == State::SecondaryKex {
                    if !self.kex_body_ok(body) {
                        return Err(SptpsError::BadKex);
                    }
                    self.send_kex(rng, out)?;
                }
                self.receive_kex(body, rng, out)?;
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
                    match self.kex {
                        SptpsKex::X25519 => {
                            out.push(Output::HandshakeDone);
                            self.state = State::SecondaryKex;
                        }
                        SptpsKex::X25519MlKem768 => {
                            // Key confirmation: first record under the
                            // new `outcipher`. `HandshakeDone` withheld
                            // until the peer's ACK verifies, so a
                            // tampered `ct` never yields `validkey`.
                            self.send_ack(out);
                            self.state = State::Confirm;
                        }
                    }
                }
                Ok(())
            }
            State::Ack => {
                self.receive_ack(body)?;
                out.push(Output::HandshakeDone);
                self.state = State::SecondaryKex;
                Ok(())
            }
            State::Confirm => {
                // Already AEAD-verified; reaching here is the proof.
                if !body.is_empty() {
                    return Err(SptpsError::BadAck);
                }
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
        rng: &mut (impl RngCore + CryptoRng),
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
        rng: &mut (impl RngCore + CryptoRng),
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
            // Handshake-phase only: 3 packets, never hot. Hold the
            // lock across the read+write so a (hypothetical) concurrent
            // datagram receive sees a consistent counter.
            let mut win = self.replay_mut();
            if seqno != win.inseqno {
                return Err(SptpsError::BadSeqno);
            }
            // Same wrap-at-MAX as ReplayWindow::check above. Handshake
            // phase hitting this is implausible (3-packet handshake) but
            // costs nothing to be consistent.
            win.inseqno = seqno.wrapping_add(1);
            drop(win);
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
        self.replay_mut().check(seqno, true)?;

        self.dispatch_record(pt[0], &pt[1..], true, rng, out)
    }

    /// Stream-mode reassembly. The bottom half of `sptps_receive_data`.
    ///
    /// The C does this in one flat function with `s->buflen` tracking
    /// progress. We do the same, just with `self.stream.buf.len()` as the
    /// progress counter instead of a separate field.
    fn receive_stream(
        &mut self,
        data: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
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
            // Pre-auth: `reclen` is attacker plaintext; clamp so an
            // unauthenticated peer can't make us buffer 64 KiB.
            if self.incipher.is_none() && usize::from(self.stream.reclen) > MAX_PREAUTH_RECLEN {
                self.stream.buf.clear();
                self.stream.reclen = 0;
                return Err(SptpsError::RecordTooLong);
            }
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

        self.dispatch_record(ty, &body, self.incipher.is_some(), rng, out)?;

        Ok(consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::Output;

    #[test]
    fn output_debug_redacts_payload_bytes() {
        let r = Output::Record {
            record_type: 0,
            bytes: vec![1, 2, 3],
        };
        let s = format!("{r:?}");
        assert!(!s.contains("1, 2, 3"), "Debug leaked payload: {s}");
        assert!(s.contains("len"), "Debug should show length: {s}");

        let w = Output::Wire {
            record_type: 128,
            bytes: vec![0xde, 0xad],
        };
        let s = format!("{w:?}");
        assert!(!s.contains("222") && !s.contains("173"));
    }
}
