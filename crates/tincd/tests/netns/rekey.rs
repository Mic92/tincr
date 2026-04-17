//! Reproducer for the `seqno != 0` / `BadSeqno` burst on per-tunnel
//! SPTPS session restart under load.
//!
//! ## Symptom (production retiolum, both ends Rust)
//!
//! ```text
//! Invalid packet seqno: 4316 != 0 from ian (...)
//! Invalid packet seqno: 4321 != 0 from ian (...)
//! ... ~10 per burst, every few minutes, multiple peers
//! ```
//!
//! `!= 0` ⇒ receiver's SPTPS is in the **plaintext-handshake phase**
//! (`incipher = None`, strict `seqno == inseqno` counter, see
//! `tinc-sptps/src/state.rs::receive_datagram`). The sender is still
//! emitting datagrams sealed with the *previous* session's key and
//! seqno space. In current HEAD the same condition surfaces as
//! `Failed to decode UDP packet from {peer}: BadSeqno`
//! (`crates/tincd/src/daemon/net/rx.rs:520` / `:548`).
//!
//! ## Mechanism encoded here
//!
//! 1. A↔B established, A streaming UDP data to B (ping flood),
//!    `udp_confirmed` on both, seqno in the hundreds.
//! 2. Inject one forged datagram (alice's `src_id6`, garbage body)
//!    into B's UDP socket. B's slow path: `open_data_into` →
//!    `DecryptFailed` → `rx.rs:522-528` `gate_ok` (last_req_key was
//!    >10 s ago) → `send_req_key(alice)`.
//! 3. `send_req_key` (`gossip.rs:88-95`) replaces `tunnel.sptps` with
//!    a fresh initiator (`incipher = None`, `replay.inseqno = 0`) and
//!    clears `validkey` — but does **not** clear `tunnel_handles` /
//!    `tx_snap.tunnels`, and does **not** keep the old `incipher`
//!    alive. Same in `on_req_key` (`gossip.rs:426-434`).
//! 4. With ~30 ms artificial RTT (`netem delay`), ~15 of A's
//!    old-session datagrams are still in flight. They now reach B's
//!    fresh `Sptps`: fast-path `rx_open` still has the *old*
//!    `TunnelHandles.inkey` (handles only swap on `HandshakeDone`,
//!    `net/sptps.rs:159-176`) and silently keeps delivering — but
//!    anything that misses the fast path (probe replies, the next
//!    batch's first packet after `tx_snap` is taken, or once the new
//!    handshake completes and the handles flip) lands on the slow
//!    path where `tunnel.sptps` is the **new** session. There the
//!    plaintext-phase strict counter / wrong-key tag check rejects
//!    every one of them: `BadSeqno` / `DecryptFailed`.
//! 5. The reject path itself is gated 10 s so it doesn't storm
//!    `REQ_KEY`, but every dropped packet is a real loss and the log
//!    burst is operator noise.
//!
//! ## C-parity note
//!
//! `tinc-c/src/protocol_key.c::req_key_ext_h` `case REQ_KEY` does the
//! same `sptps_stop(&from->sptps)` before `sptps_start`, so C tinc
//! has the identical window — `sptps.c:549` is the `!= 0` log. The
//! difference: C has no fast-path `TunnelHandles` mirror that keeps
//! the old `inkey` half-alive, and C's `send_req_key` is *only*
//! reached from the `last_req_key < now-10` gate or `try_tx`'s
//! `!validkey` arm — never from a single tag-fail on a still-valid
//! tunnel. Our `rx.rs` decode-error gate (`:522-528`) means one
//! corrupt/forged datagram tears down a perfectly good session. The
//! assertion below therefore demands **zero** decode failures across
//! the rekey, not "≤ RTT × rate" — the bound we actually want to
//! converge on once the fix lands.
//!
//! FIXME(rekey-seqno-race): the fix lives in
//!   - `crates/tincd/src/daemon/net/sptps.rs::dispatch_tunnel_outputs`
//!     `HandshakeDone` arm (handles swap timing), and
//!   - `crates/tincd/src/daemon/gossip.rs::{send_req_key,on_req_key}`
//!     (don't drop a working `incipher` on the floor; either keep the
//!     old session decrypting until the new one's first authenticated
//!     packet, or stop tearing the session down on a single
//!     `DecryptFailed` in `rx.rs`).

use std::io::Write as _;
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::chaos::{ChaosRig, Netem};
use super::common::TmpGuard;
use super::rig::enter_netns;

/// See module doc. `#[ignore]` until the rekey race is fixed; run
/// explicitly with
/// `cargo test -p tincd --test netns rekey -- --ignored --nocapture`.
#[test]
#[ignore = "FIXME(rekey-seqno-race): SPTPS restart under load drops in-flight datagrams; see module doc"]
fn sptps_restart_under_load_no_seqno_burst() {
    let Some(netns) = enter_netns("rekey::sptps_restart_under_load_no_seqno_burst") else {
        return;
    };
    let tmp = TmpGuard::new("netns", "rekey-seqno");
    // Rig brings both daemons up through validkey + udp_confirmed.
    // No `PriorityInheritance` / pcap games: we want the production
    // fast-path/slow-path mix, not a synthetic all-slow-path config.
    let rig = ChaosRig::setup_with(netns, &tmp, "");

    // ─── open the in-flight window ──────────────────────────────
    // 30 ms one-way on `lo` (egress qdisc, applies to BOTH daemons'
    // UDP and the meta-TCP). At 2 ms ping interval that's ~15
    // datagrams in flight per direction — comparable to a real WAN
    // link, and enough that "drop everything in flight on rekey" is
    // observable as a ping seq gap.
    let _delay = Netem::apply("lo", "delay 30ms");

    // ─── arm the rx.rs decode-error gate ────────────────────────
    // `last_req_key` was stamped during the initial handshake
    // (`gossip.rs:95` / `:434`); the `gate_ok` in `rx.rs:522-528`
    // needs ≥10 s since then before a decode failure re-fires
    // `send_req_key`. Same gate as C (`net_packet.c:444`).
    eprintln!("waiting 11 s for the rx-error → send_req_key gate to open");
    std::thread::sleep(Duration::from_secs(11));

    // ─── start the flood ────────────────────────────────────────
    // 500 × 2 ms = ~1 s of traffic plus 30 ms RTT slop. Spawned in
    // the outer netns (alice's TUN). The flood runs across the
    // forged-packet inject + the whole REQ_KEY/ANS_KEY round-trip.
    let flood = Command::new("ping")
        .args(["-c", "500", "-i", "0.002", "-W", "2", "10.42.0.2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping flood");

    // Let seqno climb past the replay window so a fresh `inseqno=0`
    // is unambiguously distinguishable from "first few packets".
    std::thread::sleep(Duration::from_millis(300));

    // ─── the trigger: one forged datagram to bob ────────────────
    // Wire layout `[dst_id6=NULL][src_id6=sha512("alice")[:6]]
    // [garbage ≥21]`. `rx_probe` finds alice's handles, `rx_open`
    // tag-fails, slow path `open_data_into` → `DecryptFailed`,
    // `gate_ok` (>10 s) → `send_req_key(alice)` → bob's
    // `tunnel.sptps` is replaced mid-flood. The 30 ms of alice's
    // datagrams already on the wire now race the new handshake.
    let alice_id6 = tincd::node_id::NodeId6::from_name("alice");
    let mut forged = [0u8; 12 + 64];
    // dst = NULL (direct-to-bob); src = alice.
    forged[6..12].copy_from_slice(alice_id6.as_bytes());
    // Garbage ct: non-zero seqno + junk so it can't accidentally be
    // a valid plaintext-handshake record either.
    forged[12..16].copy_from_slice(&1234u32.to_be_bytes());
    forged[16..].fill(0x5A);
    let inj = UdpSocket::bind("127.0.0.1:0").expect("bind injector");
    inj.send_to(&forged, ("127.0.0.1", rig.bob.port))
        .expect("inject forged datagram");
    eprintln!(
        "injected forged datagram (src_id6={alice_id6}) → bob:{}",
        rig.bob.port
    );

    // ─── let the rekey + flood play out ─────────────────────────
    let flood_out = flood.wait_with_output().expect("ping flood wait");
    let flood_stdout = String::from_utf8_lossy(&flood_out.stdout);
    eprintln!(
        "{}",
        flood_stdout
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    );
    let received: u32 = flood_stdout
        .lines()
        .find(|l| l.contains("received"))
        .and_then(|l| {
            l.split(',')
                .find(|f| f.contains("received"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("ping summary line");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ────────────────────────────────────────────────
    // 1. The trigger actually fired. `send_req_key` clears
    //    `validkey` (`gossip.rs:92`); the very next echo-reply bob
    //    tries to send hits `send_sptps_packet`'s `!validkey` guard
    //    and logs `"No valid key known yet for alice"` at
    //    `tincd::net` debug — which IS in the rig's log filter.
    //    (The `tincd::proto` "Got REQ_KEY ... already started" line
    //    on alice's side is debug-level under a target the rig
    //    doesn't enable, so we can't gate on it.)
    assert!(
        bob_stderr.contains("No valid key known yet for alice"),
        "trigger did not fire: bob's send_req_key never cleared \
         validkey. Either the 10 s gate (rx.rs:522) didn't open or \
         the forged packet was dropped before reaching the slow \
         path.\n=== bob ===\n{bob_stderr}\n=== alice ===\n{alice_stderr}"
    );

    // 2. THE BUG: decode-failure burst on bob.
    //
    // Count every `Failed to decode UDP packet from alice` line
    // *except* the one we deliberately injected (that one is
    // `DecryptFailed` on the forged garbage and is the only
    // legitimate hit). Anything beyond that is an in-flight
    // datagram from the *real* alice being rejected by bob's
    // freshly-reset session — `BadSeqno` while `incipher=None`
    // (the `!= 0` case from production), or `DecryptFailed` once
    // the new key is installed but old-key stragglers are still
    // arriving.
    //
    // C tinc has the same `sptps_stop`-then-`sptps_start` window
    // (`protocol_key.c:259-264`) so strict zero is *not* C-parity.
    // We assert zero anyway: the point of this reproducer is to
    // pin the behaviour we want after the fix (keep old `incipher`
    // alive until first authenticated new-key packet, à la
    // `force_kex`'s `State::Ack`), not to bless the C race.
    let decode_fails = bob_stderr
        .lines()
        .filter(|l| l.contains("Failed to decode UDP packet from alice"))
        .count();
    let bad_seqno = bob_stderr.matches("BadSeqno").count();
    let decrypt_failed = bob_stderr.matches("DecryptFailed").count();
    eprintln!(
        "bob decode failures: {decode_fails} total \
         (BadSeqno={bad_seqno} DecryptFailed={decrypt_failed}); \
         1 is the injected trigger"
    );
    assert!(
        decode_fails <= 1,
        "SPTPS restart dropped {} of alice's in-flight datagrams \
         (BadSeqno={bad_seqno} DecryptFailed={decrypt_failed}). \
         These were all valid traffic sealed under the previous \
         session key; bob threw the old incipher away in \
         send_req_key (gossip.rs:91) before the new handshake \
         completed.\n\
         FIXME(rekey-seqno-race): see module doc.\n\
         === bob ===\n{bob_stderr}",
        decode_fails - 1,
    );

    // 3. End-to-end loss bound. Even if the log burst were
    //    cosmetic, the packets are genuinely dropped: alice's
    //    `validkey` is cleared by `on_req_key` so the slow path
    //    refuses to send, and bob rejects whatever was already on
    //    the wire. With 30 ms one-way delay and a 2-RTT handshake
    //    over meta-TCP that's ≳120 ms ≈ 60 pings of blackhole. We
    //    allow a small fixed budget for the *handshake* gap but not
    //    for the in-flight rejects.
    //
    //    `replaywin >> 2` (`state.rs:247` farfuture) = 32>>2 = 8 is
    //    the C-side bound on how many far-future packets are
    //    silently eaten before resync; use that as the parity
    //    budget on top of the unavoidable `validkey=false` send
    //    gap.
    #[allow(clippy::items_after_statements)]
    const REPLAYWIN_FARFUTURE: u32 = 8; // settings.rs:316 replaywin=32 → 32>>2
    let max_loss = 60 /* ~2×RTT validkey gap @ 2 ms interval */ + REPLAYWIN_FARFUTURE;
    assert!(
        received + max_loss >= 500,
        "ping flood lost {} of 500 across one SPTPS restart \
         (received {received}); budget was {max_loss} \
         (= 2×RTT send gap + replaywin>>2 farfuture). \
         Sustained loss means the session never recovered.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
        500 - received,
    );

    // Dump on success too: this test is `#[ignore]`d and run by
    // hand; the operator wants to see the burst shape.
    eprintln!("=== bob stderr ===\n{bob_stderr}");
    let _ = std::io::stderr().flush();
}
