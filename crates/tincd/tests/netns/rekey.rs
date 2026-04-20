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
//! tunnel. Our pre-fix `rx.rs` decode-error path went straight to
//! `send_req_key`, so one corrupt/forged datagram tore down a
//! perfectly good session.
//!
//! ## Fix encoded here
//!
//! - `Daemon::maybe_restart_stuck_tunnel`: gate the decode-error →
//!   `send_req_key` escalation on `!validkey` (DoS hardening; a
//!   spoofed UDP datagram can no longer reset a healthy session
//!   every 10 s).
//! - `TunnelState::prev_sptps`: when a restart *does* happen,
//!   `send_req_key`/`on_req_key` salvage the old session for RX so
//!   in-flight datagrams under the old key still decrypt. RX-only,
//!   reaped by `on_ping_tick` after `2×PingInterval` once the new
//!   key is valid (forward-secrecy bound).

use std::io::Write as _;
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::chaos::{ChaosRig, Netem};
use super::common::TmpGuard;
use super::rig::enter_netns;

/// See module doc.
#[test]
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
    // `last_req_key` was stamped during the initial handshake; the
    // C-parity `last_req_key+10` half of `maybe_restart_stuck_tunnel`
    // needs >=10 s since then. Post-fix the `!validkey` half keeps
    // the gate shut anyway, but the test must prove the time gate
    // alone is not what saved us.
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
    // 1. The trigger reached bob's slow path. The forged datagram is
    //    real garbage → `DecryptFailed` against the current session.
    //    After the fix that one log line is the *only* decode failure
    //    we expect; before the fix it kicked `send_req_key` and was
    //    followed by ~RTT×rate of `BadSeqno` from alice's real
    //    traffic hitting bob's freshly reset session.
    assert!(
        bob_stderr.contains("Failed to decode UDP packet from alice: DecryptFailed"),
        "forged datagram never reached bob's slow path — either it \
         was dropped before the AEAD check or the rig's log filter \
         changed.\n=== bob ===\n{bob_stderr}\n=== alice ===\n{alice_stderr}"
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
    // We assert zero anyway: the point of this test is to pin the
    // behaviour we want (a single bad datagram on a healthy session
    // is dropped, not escalated into a session reset), not to bless
    // the C race.
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
        "single bad datagram escalated into a session reset and \
         dropped {} of alice's in-flight datagrams \
         (BadSeqno={bad_seqno} DecryptFailed={decrypt_failed}). \
         maybe_restart_stuck_tunnel must gate on !validkey.\n\
         === bob ===\n{bob_stderr}",
        decode_fails - 1,
    );
    // And neither side ever lost its key.
    assert!(
        !bob_stderr.contains("No valid key known yet for alice")
            && !alice_stderr.contains("No valid key known yet for bob"),
        "a forged datagram cleared validkey on a healthy session.\n\
         === bob ===\n{bob_stderr}\n=== alice ===\n{alice_stderr}"
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
    //    Post-fix the session was never torn down, so the only
    //    legitimate loss is netem scheduling jitter on `lo`. Allow a
    //    small fixed budget; before the fix this was 470/500 lost.
    let max_loss = 5u32;
    assert!(
        received + max_loss >= 500,
        "ping flood lost {} of 500 across one forged datagram \
         (received {received}); budget was {max_loss}. The session \
         was either reset or never recovered.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
        500 - received,
    );
    let _ = std::io::stderr().flush();
}

/// `KeyExpire`-driven in-band rekey under load. Exercises the
/// `force_kex` → `State::Ack` path through the slow RX path while a
/// flood is in flight: both sides keep the OLD `incipher` until the
/// peer's ACK arrives (`tinc-sptps/src/state.rs::receive_ack`), so
/// loss across a proper rekey must be zero — unlike a
/// `send_req_key`-style hard restart. Also proves that the
/// `dispatch_tunnel_outputs` `HandshakeDone` arm rebuilding
/// `tunnel_handles` mid-flood doesn't race the RX fast path into
/// `BadSeqno`.
#[test]
fn keyexpire_rekey_under_load_is_lossless() {
    let Some(netns) = enter_netns("rekey::keyexpire_rekey_under_load_is_lossless") else {
        return;
    };
    let tmp = TmpGuard::new("netns", "rekey-kex");
    // `KeyExpire = 1` arms `on_keyexpire` once per second on BOTH
    // sides while the flood is running.
    let rig = ChaosRig::setup_with(netns, &tmp, "KeyExpire = 1\n");

    let _delay = Netem::apply("lo", "delay 30ms");

    // 3 s of flood → ≥2 rekeys per side mid-stream.
    let flood = Command::new("ping")
        .args(["-c", "1000", "-i", "0.003", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping flood");
    let flood_stdout = String::from_utf8_lossy(&flood.stdout);
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

    let rekeys = alice_stderr.matches("Expiring symmetric keys").count()
        + bob_stderr.matches("Expiring symmetric keys").count();
    assert!(
        rekeys >= 2,
        "KeyExpire timer never fired during the flood; nothing tested.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    // `force_kex` is almost lossless, not strictly: REC_HANDSHAKE
    // (KEX/SIG/ACK) rides meta-TCP, data rides UDP. `receive_sig`
    // swaps `outcipher` right after *queueing* ACK to the TCP
    // outbuf, so the next UDP datagram (NEW key) can overtake the
    // ACK → one `DecryptFailed` per direction per rekey. C-parity.
    // We guard against *unbounded* loss (regressed HandshakeDone /
    // hard reset = RTT×rate rejected): BadSeqno must be 0 (only a
    // reset produces it), DecryptFailed bounded by 2×rekeys.
    let bad_seqno = bob_stderr
        .lines()
        .chain(alice_stderr.lines())
        .filter(|l| l.contains("Failed to decode UDP packet") && l.contains("BadSeqno"))
        .count();
    let decode_fails = bob_stderr
        .lines()
        .chain(alice_stderr.lines())
        .filter(|l| l.contains("Failed to decode UDP packet"))
        .count();
    eprintln!("rekeys={rekeys} decode_fails={decode_fails} (BadSeqno={bad_seqno})");
    assert_eq!(
        bad_seqno, 0,
        "in-band force_kex rekey produced {bad_seqno} BadSeqno — the \
         session was hard-reset (incipher=None). force_kex must keep \
         the old incipher live through `State::Ack`.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
    let fail_budget = 2 * rekeys;
    assert!(
        decode_fails <= fail_budget,
        "in-band force_kex rekey produced {decode_fails} decode \
         failures across {rekeys} rekeys (budget {fail_budget}). \
         Either the fast-path handles swap (HandshakeDone arm) or \
         the `State::Ack` old-incipher window regressed.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    // Every loss accounted for by a logged decode fail or netem
    // jitter; unaccounted loss = a key window leaked silently.
    #[allow(clippy::cast_possible_truncation)] // ≤ 2×rekeys, tiny
    let max_loss = decode_fails as u32 + 5;
    assert!(
        received + max_loss >= 1000,
        "in-band rekey under load lost {} of 1000 (received {received}, \
         {decode_fails} of those logged as decode failures); budget \
         {max_loss}. Unaccounted loss means a key window leaked.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
        1000 - received,
    );
    let _ = std::io::stderr().flush();
}
