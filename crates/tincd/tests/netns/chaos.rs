use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::common::linux::*;
use super::common::*;
use super::rig::*;

/// Parse `(mtu, minmtu, maxmtu)` from a `dump nodes` row. Body
/// tokens 14/15/16 (hostname is always 3 tokens: `HOST port PORT`).
pub(crate) fn node_pmtu(rows: &[String], name: &str) -> Option<(u16, u16, u16)> {
    rows.iter().find_map(|r| {
        let body = r.strip_prefix("18 3 ")?;
        let toks: Vec<&str> = body.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        Some((
            toks.get(14)?.parse().ok()?,
            toks.get(15)?.parse().ok()?,
            toks.get(16)?.parse().ok()?,
        ))
    })
}

/// `tc qdisc add dev DEV root netem SPEC...`. Drop guard `del`s it.
///
/// netem is egress-only (it's a qdisc). On `lo` that means EACH
/// direction takes a hit independently: alice→bob UDP egresses lo
/// once, bob→alice egresses lo once. So `loss 5%` ≈ 5% per direction,
/// not 10% round-trip on a single ICMP exchange (echo and reply are
/// independent draws).
///
/// `spec` is split on whitespace and passed verbatim. No shell.
pub(crate) struct Netem {
    dev: String,
}

impl Netem {
    pub(crate) fn apply(dev: &str, spec: &str) -> Self {
        let mut args = vec!["qdisc", "add", "dev", dev, "root", "netem"];
        args.extend(spec.split_whitespace());
        let out = Command::new("tc").args(&args).output().expect("spawn tc");
        assert!(
            out.status.success(),
            "tc {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Echo what got installed — netem normalizes args (adds
        // `seed`, `limit 1000`); useful in --nocapture failure logs.
        let show = Command::new("tc")
            .args(["qdisc", "show", "dev", dev])
            .output()
            .expect("tc qdisc show");
        eprintln!("netem: {}", String::from_utf8_lossy(&show.stdout).trim());
        Self { dev: dev.into() }
    }
}

impl Drop for Netem {
    fn drop(&mut self) {
        // Best-effort; the netns vanishes with the bwrap process
        // anyway. Explicit `del` is for tests that want to assert
        // post-chaos convergence (clear chaos, THEN poll).
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", &self.dev, "root"])
            .status();
    }
}

/// Bring up the two-daemon harness through validkey. Same dance as
/// `real_tun_ping` minus the actual ping. Factored because every
/// chaos test needs the same ~50 lines of setup before applying
/// netem; copy-paste of that block four times would obscure the
/// per-test variation (which is the whole signal).
///
/// Returns the daemon children so the test owns them — panic-path
/// stderr drainage stays at the call site (where the failing assert
/// knows what context to print).
pub(crate) struct ChaosRig {
    pub(crate) netns: NetNs,
    pub(crate) alice: Node,
    pub(crate) bob: Node,
    pub(crate) alice_child: Child,
    pub(crate) bob_child: Child,
    pub(crate) alice_ctl: Ctl,
    pub(crate) bob_ctl: Ctl,
}

impl ChaosRig {
    fn setup(netns: NetNs, tmp: &TmpGuard) -> Self {
        Self::setup_with(netns, tmp, "")
    }

    /// `extra` appended verbatim to BOTH daemons' tinc.conf. Used by
    /// stress tests that need `PingInterval = 1` / `MaxTimeout = 2`.
    pub(crate) fn setup_with(netns: NetNs, tmp: &TmpGuard, extra: &str) -> Self {
        let alice = Node::new(tmp.path(), "alice", 0xCA, "tinc0", "10.42.0.1/32");
        let bob = Node::new(tmp.path(), "bob", 0xCB, "tinc1", "10.42.0.2/32");

        bob.write_config_with(&alice, false, extra);
        alice.write_config_with(&bob, true, extra);

        // `info` not `debug`: ~100-ping bursts at debug log a line
        // per packet per side. Not a pipe-fill risk at this volume
        // (~20 KiB), but `info` keeps the failure stderr readable.
        // The one debug line we DO want is `tincd::net`'s "Failed
        // to decode UDP packet ... BadSeqno" — that's the replay-
        // reject signal. Target-filter it through.
        let log = "tincd=info,tincd::net=debug";
        let mut bob_child = bob.spawn_with_log(log);
        assert!(
            wait_for_file(&bob.socket),
            "bob setup failed; stderr:\n{}",
            drain_stderr(bob_child)
        );
        let alice_child = alice.spawn_with_log(log);
        if !wait_for_file(&alice.socket) {
            let _ = bob_child.kill();
            panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
        }

        assert!(
            wait_for_carrier("tinc0", Duration::from_secs(2)),
            "alice TUNSETIFF; stderr:\n{}",
            drain_stderr(alice_child)
        );
        assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
        netns.place_devices();

        let mut alice_ctl = alice.ctl();
        let mut bob_ctl = bob.ctl();
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });

        // Kick + wait validkey. Same as real_tun_ping.
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.42.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });

        // ─── wait for udp_confirmed (status bit 7) ────────────
        // CRITICAL for the chaos tests. validkey alone means data
        // CAN go via UDP, but until PMTU probes confirm the path
        // (`txpath.rs:115`, `tunnel.rs:197`), `try_tx` falls back
        // to TCP-tunneling over the meta-conn. Kernel TCP dedups
        // and reorders silently — netem on `lo` would do nothing
        // visible to the SPTPS layer.
        //
        // Found the hard way: `chaos_replay_under_duplicate` saw
        // ZERO `BadSeqno` at 30% dup. Stderr had no "UDP address
        // confirmed" line. Data was riding TCP the whole time.
        //
        // Kick PMTU with traffic (probes are demand-driven via
        // `try_tx`, `txpath.rs:323`). A few pings get the probe/
        // reply round-trip done; udp_confirmed flips on the first
        // probe-reply (`txpath.rs:113-116`).
        poll_until(Duration::from_secs(5), || {
            let _ = Command::new("ping")
                .args(["-c", "1", "-W", "1", "10.42.0.2"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x80 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x80 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });

        Self {
            netns,
            alice,
            bob,
            alice_child,
            bob_child,
            alice_ctl,
            bob_ctl,
        }
    }

    /// PID of alice's daemon (first pidfile token). For
    /// `/proc/<pid>/fd` leak checks.
    pub(crate) fn alice_pid(&self) -> u32 {
        std::fs::read_to_string(&self.alice.pidfile)
            .expect("read pidfile")
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("pidfile pid")
    }

    /// `dump nodes` row → (`in_packets`, `out_packets`) for `name`.
    /// Tail-4, tail-2 of the row (`gossip.rs:947-950`).
    fn traffic(ctl: &mut Ctl, name: &str) -> (u64, u64) {
        ctl.dump(3)
            .iter()
            .find_map(|r| {
                let body = r.strip_prefix("18 3 ")?;
                let toks: Vec<&str> = body.split_whitespace().collect();
                if toks.first() != Some(&name) {
                    return None;
                }
                let n = toks.len();
                Some((toks[n - 4].parse().ok()?, toks[n - 2].parse().ok()?))
            })
            .expect("node row")
    }

    /// Kill bob, return his captured stderr. Leaves alice running
    /// (and the rig consumable for the rest). Used by the reconnect-
    /// storm test which churns bob while observing alice.
    pub(crate) fn kill_bob(&mut self) -> String {
        // Drop bob's ctl FIRST: it holds an AF_UNIX conn into the
        // daemon; killing the daemon makes the next `dump()` on
        // that ctl panic on a broken pipe.
        let _ = self.bob_child.kill();
        let mut dead = std::mem::replace(
            &mut self.bob_child,
            // Placeholder; immediately overwritten by respawn_bob().
            Command::new("true").spawn().expect("spawn placeholder"),
        );
        let _ = dead.wait();
        let mut s = String::new();
        if let Some(mut e) = dead.stderr.take() {
            use std::io::Read;
            let _ = e.read_to_string(&mut s);
        }
        s
    }

    /// Respawn bob (same config). Reconnects `bob_ctl`. Caller
    /// must wait for alice to re-see bob as reachable.
    pub(crate) fn respawn_bob(&mut self) {
        std::fs::remove_file(&self.bob.socket).ok();
        let log = "tincd=info,tincd::net=debug";
        self.bob_child = self.bob.spawn_with_log(log);
        assert!(
            wait_for_file(&self.bob.socket),
            "bob respawn failed; stderr:\n{}",
            drain_stderr(std::mem::replace(
                &mut self.bob_child,
                Command::new("true").spawn().unwrap()
            ))
        );
        self.bob_ctl = self.bob.ctl();
    }

    /// Kill both, return (`alice_stderr`, `bob_stderr`). Consumes self
    /// so the test can't accidentally poll a dead daemon.
    pub(crate) fn finish(mut self) -> (String, String) {
        drop(self.alice_ctl);
        drop(self.bob_ctl);
        let _ = self.bob_child.kill();
        let bob = drain_stderr(self.bob_child);
        let alice = drain_stderr(self.alice_child);
        drop(self.netns);
        (alice, bob)
    }
}

/// **Gate test.** 5% UDP loss on the daemon↔daemon transport. Ping
/// is ICMP-over-SPTPS-over-UDP: no daemon-layer retransmit (the
/// daemon just routes; ICMP is best-effort). So we EXPECT some
/// pings to drop. The signals:
///
/// - **Hang**: nextest timeout fires. The trace is the bug —
///   probably the `Failed to decode` → `send_req_key` arm in
///   `net.rs:495` triggering on something it shouldn't (loss isn't
///   a decode failure; the packet just never arrives).
/// - **Crash**: obvious.
/// - **Zero received**: 5% loss shouldn't zero a 30-ping burst.
///   ~85% should get through (loss applies independently to echo
///   AND reply: `0.95 * 0.95 ≈ 0.90`). Floor at 5/30 to allow for
///   netem RNG variance + the validkey-kick packet skew.
/// - **`BadSeqno` in stderr**: THE FINDING. Loss creates seqno
///   gaps but `ReplayWindow::check` (`state.rs:237-241`) handles
///   gaps fine: future packet arrives, gap marked `late[]`, no
///   reject. Dup/reorder reject; loss doesn't. If `BadSeqno`
///   appears under loss-only, the gap-marking arithmetic is wrong
///   (likely the `for i in self.inseqno..seqno` loop's modular
///   indexing).
#[test]
fn chaos_ping_under_loss() {
    let Some(netns) = enter_netns("chaos::chaos_ping_under_loss") else {
        return;
    };
    let tmp = tmp!("chaos-loss");
    let mut rig = ChaosRig::setup(netns, &tmp);

    // ─── baseline counters BEFORE chaos ──────────────────────────
    // The validkey-kick + flush pings already bumped these.
    let (b_in_pre, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_pre) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");

    let _chaos = Netem::apply("lo", "loss 5%");

    // ─── the burst ───────────────────────────────────────────────
    // `-i 0.05`: 50ms gap. Slow enough that loss is the only
    // perturbation (no queue buildup → no incidental reorder).
    // `-W 1`: don't wait long for replies that won't come.
    let ping = Command::new("ping")
        .args(["-c", "30", "-i", "0.05", "-W", "1", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&ping.stdout);
    eprintln!("{stdout}");

    // Parse "X received" from the summary line.
    let received: u32 = stdout
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

    // ─── post-chaos counters ─────────────────────────────────────
    let (b_in_post, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_post) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");
    let alice_sent = a_out_post - a_out_pre;
    let bob_got = b_in_post - b_in_pre;
    eprintln!("alice sent {alice_sent} packets, bob accepted {bob_got}");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ─────────────────────────────────────────────────
    // Floor: 5/30. Expected ~27 (0.95² × 30), variance is wide at
    // N=30. Below 5 means something other than loss is dropping.
    assert!(
        received >= 5,
        "ping under 5% loss got {received}/30 — too low. \
         Either netem is dropping more than configured (check the \
         `netem:` line above), or the daemon's loss handling is \
         broken (req_key storm? check stderr below).\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    // THE check: zero replay rejects under loss-only. `BadSeqno`
    // is the `{e:?}` in `net.rs:488`'s debug log. Loss creates
    // gaps; gaps are NOT rejects (`state.rs:237-241` marks them
    // late). If this fires, the gap-marking is wrong.
    let bad_seqno_count = bob_stderr.matches("BadSeqno").count();
    assert_eq!(
        bad_seqno_count, 0,
        "loss-only chaos produced {bad_seqno_count} BadSeqno rejects. \
         Loss creates seqno GAPS, not dups/reorder. ReplayWindow::\
         check should mark the gap late and accept the future packet. \
         If this fires, suspect the `for i in inseqno..seqno` loop's \
         modular index (state.rs:239).\n\
         === bob stderr ===\n{bob_stderr}"
    );

    // Sanity: bob's accepted-count never exceeds what alice sent.
    // (Would mean a dup got past the replay check AND was
    // double-counted — but loss-only doesn't dup, so this firing
    // means netem is misconfigured or the counter is wrong.)
    assert!(
        bob_got <= alice_sent,
        "bob accepted {bob_got} but alice only sent {alice_sent}"
    );
}

/// `delay 5ms reorder 25% 50%`. netem holds packets in a delay
/// queue; 25% are sent immediately (out of order). Only works when
/// the queue is non-empty → needs a burst (`-i 0.01`, faster than
/// the 5ms delay).
///
/// **What's tested**: `ReplayWindow`'s `late[]` bitmap under
/// realistic out-of-order. The proptests in `state.rs` use random
/// seqnos; THIS uses kernel-generated near-monotonic-with-swaps,
/// which is what the bitmap was DESIGNED for.
///
/// `state.rs:228-245`: when seqno > inseqno (future), the gap
/// `[inseqno..seqno)` is marked `late[] |= bit`. When the late
/// packet later arrives (seqno < inseqno), `already = bit == 0`
/// is false (bit IS set) → accepted, bit cleared. So:
///
///   **Expected: zero `BadSeqno` under reorder-only.**
///
/// 256-packet window (replaywin=32 bytes); 5ms delay at 10ms
/// intervals means ≤1 packet skew, well inside. If `BadSeqno`
/// appears, the bitmap polarity is wrong ("1 = not seen" is
/// counterintuitive; easy to flip in a refactor).
#[test]
fn chaos_replay_under_reorder() {
    let Some(netns) = enter_netns("chaos::chaos_replay_under_reorder") else {
        return;
    };
    let tmp = tmp!("chaos-reorder");
    let mut rig = ChaosRig::setup(netns, &tmp);

    let (b_in_pre, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");

    let _chaos = Netem::apply("lo", "delay 5ms reorder 25% 50%");

    // Burst: 100 pings at 10ms. The 5ms netem delay means ~every
    // packet sees the previous still queued; reorder probability
    // applies per-dequeue. Expect ~25 swapped pairs.
    let ping = Command::new("ping")
        .args(["-c", "100", "-i", "0.01", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&ping.stdout);
    eprintln!(
        "{}",
        stdout.lines().rev().take(3).collect::<Vec<_>>().join("\n")
    );

    let (b_in_post, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let bob_got = b_in_post - b_in_pre;
    eprintln!("bob accepted {bob_got} packets under reorder");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ─────────────────────────────────────────────────
    // Reorder-only: no loss, no dup. ALL pings should reply.
    // (netem reorder doesn't drop — it just shuffles dequeue
    // order.) Allow 2-packet slack for ping's own `-W` race.
    let received: u32 = stdout
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
    assert!(
        received >= 98,
        "reorder-only should not lose packets; got {received}/100. \
         The replay window is REJECTING reordered-but-valid packets \
         — the late[] bitmap accept path is broken.\n\
         === bob stderr ===\n{bob_stderr}"
    );

    // THE check.
    let bad_seqno_count =
        bob_stderr.matches("BadSeqno").count() + alice_stderr.matches("BadSeqno").count();
    assert_eq!(
        bad_seqno_count, 0,
        "reorder produced {bad_seqno_count} BadSeqno rejects. \
         The late[] bitmap (state.rs:228-245) should accept late-\
         but-in-window packets. Polarity bug? The C comment says \
         `1 = not seen` (state.rs:166); a refactor that flipped \
         that would reject every late arrival.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
}

/// `duplicate 30%`. netem clones egress packets. Dups carry the
/// same wire bytes → same SPTPS seqno → `ReplayWindow::check`
/// sees the bit already cleared (`state.rs:232`: `already = bit
/// == 0`) → `BadSeqno`. THIS IS CORRECT BEHAVIOR.
///
/// 30% not 10%: at 10% × 50 packets the binomial tail is wide
/// enough that a netem RNG seed plausibly gives zero dups; we
/// don't want a flaky positive control. 30% on 50 packets ≈ 15
/// expected; P(zero) is vanishing.
///
/// **What's tested**:
/// 1. Dups ARE rejected (the daemon doesn't double-deliver to the
///    TUN). The brief asks "Is the reject silent or does it log/
///    count?" — answer pinned here: logs at `debug` (`net.rs:488`),
///    no separate counter. `in_packets` is NOT bumped (the bump is
///    post-replay-check, `net.rs:2111`).
/// 2. The reject doesn't cascade. `net.rs:495` fires `send_req_key`
///    on decode failure, gated to once per 10s. A dup-reject is NOT
///    a decode failure semantically, but the code path is the same.
///    If `req_key` fires on every dup, that's a meta-conn storm under
///    realistic 1% network dup. The 10s gate should prevent it; the
///    burst here is ~2s, so we expect ≤1 `req_key` per side.
/// 3. Ping still works. The original (non-dup) packet got through;
///    only the clone is rejected.
#[test]
fn chaos_replay_under_duplicate() {
    let Some(netns) = enter_netns("chaos::chaos_replay_under_duplicate") else {
        return;
    };
    let tmp = tmp!("chaos-dup");
    let mut rig = ChaosRig::setup(netns, &tmp);

    let (b_in_pre, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_pre) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");

    let _chaos = Netem::apply("lo", "duplicate 30%");

    // 50 pings at 20ms = 1s burst. 30% dup ≈ 15 dups expected.
    let ping = Command::new("ping")
        .args(["-c", "50", "-i", "0.02", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    eprintln!(
        "{}",
        String::from_utf8_lossy(&ping.stdout)
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    );

    let (b_in_post, _) = ChaosRig::traffic(&mut rig.bob_ctl, "alice");
    let (_, a_out_post) = ChaosRig::traffic(&mut rig.alice_ctl, "bob");
    let alice_sent = a_out_post - a_out_pre;
    let bob_got = b_in_post - b_in_pre;
    eprintln!("alice sent {alice_sent}, bob accepted {bob_got}");

    let (alice_stderr, bob_stderr) = rig.finish();

    // ─── ASSERTS ─────────────────────────────────────────────────
    // Ping must succeed (originals get through). dup-only doesn't
    // lose packets.
    assert!(
        ping.status.success(),
        "ping under dup-only failed. Originals should pass; only \
         clones reject. Exit: {:?}\n=== bob ===\n{bob_stderr}",
        ping.status
    );

    // Dups MUST be rejected (positive control: this test is
    // useless if netem didn't actually dup). 30% on 50 echoes +
    // 50 replies = ~30 expected dups across both directions.
    // Floor at 3: vanishing P(≤2) at this rate.
    //
    // The reject path: dup ciphertext → `open_data_into` decrypts
    // SUCCESSFULLY (same key, same nonce, same bytes) → `replay.
    // check` sees bit cleared → `BadSeqno` → `net.rs:488` log.
    // NOT DecryptFailed: AEAD doesn't reject re-decryption of
    // valid ciphertext.
    let bad_seqno =
        bob_stderr.matches("BadSeqno").count() + alice_stderr.matches("BadSeqno").count();
    assert!(
        bad_seqno >= 3,
        "expected ≥3 BadSeqno under 30% dup. Got {bad_seqno}. \
         Either netem didn't dup (check `netem:` line) or the \
         replay check is ACCEPTING dups — meaning double-delivery \
         to the TUN. Check `state.rs:232` `already` polarity.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
    eprintln!("BadSeqno rejects: {bad_seqno}");

    // in_packets must NOT count rejects. alice_sent is the upper
    // bound (out_packets counts at send time, pre-chaos; dups are
    // injected by netem AFTER the daemon's sendto). If bob_got >
    // alice_sent, a dup got past the replay check and was counted.
    assert!(
        bob_got <= alice_sent,
        "bob accepted {bob_got} > alice sent {alice_sent}. A dup \
         got past the replay window (state.rs:232 `already` check \
         is wrong, or the bit-clear at :245 races something)."
    );

    // ─── req_key cascade check (indirect) ────────────────────────────────────────
    // `net.rs:483` lumps `BadSeqno` with `DecryptFailed`: both
    // hit `send_req_key`. That's semantically wrong — a dup
    // doesn't mean keys are stale — but the 10s gate
    // (`net.rs:490-493`) saves it: `last_req_key` was set ~1s
    // ago by ChaosRig's validkey-kick, so the gate is CLOSED for
    // this entire burst. If it weren't, `send_req_key` would
    // RESET the tunnel (`gossip.rs:73-77`: `sptps = new`,
    // `validkey = false`) and the rest of the burst would
    // `DecryptFailed` against the new cipher.
    //
    // We can't grep for a "sending REQ_KEY" log (there isn't one;
    // `send_req_key` doesn't log). Instead: assert NO
    // `DecryptFailed` mid-burst. That's the smoking gun of a
    // tunnel-reset-under-dup.
    let decrypt_fail =
        bob_stderr.matches("DecryptFailed").count() + alice_stderr.matches("DecryptFailed").count();
    assert_eq!(
        decrypt_fail, 0,
        "DecryptFailed under dup-only → a BadSeqno-triggered \
         req_key reset the tunnel mid-burst. The 10s gate \
         (net.rs:490) should have held (last_req_key < 10s old). \
         Either the gate is comparing wrong, or something cleared \
         last_req_key.\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
}
