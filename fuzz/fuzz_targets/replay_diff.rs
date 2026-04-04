//! Differential fuzz: `ReplayWindow::check` vs `sptps_check_seqno`.
//!
//! ## What this catches that Lean didn't
//!
//! The Lean proofs (`replay-lean-findings.md`) verified the *algorithm*
//! against its abstract spec — 24 theorems, all green. They can't see:
//!
//! - A `wrapping_add` that should be `wrapping_sub` (transcription typo)
//! - `>=` vs `>` (off-by-one that the spec-level theorems happen to miss)
//! - A `u32` cast that silently truncates a `usize` on 64-bit
//!
//! Those are bugs where Rust does what the *comment* says, not what the
//! C *does*. This harness pits the two implementations against each other
//! byte-for-byte: same input, both must produce same output AND same
//! post-state. libFuzzer's coverage feedback drives toward branch edges
//! (window boundaries, wrap points, the `farfuture` threshold) faster
//! than uniform random would.
//!
//! ## Input encoding
//!
//! Unstructured bytes interpreted as a *trace*: build an initial state,
//! then replay a sequence of `(seqno, update)` pairs. Both impls start
//! from `inseqno=0, late=zeros, farfuture=0` (the `calloc` state in
//! `sptps_start`) and process the same trace. After every step, compare:
//!
//! - return value (accept/reject)
//! - `inseqno`
//! - `farfuture`
//! - `late[]` bitmap, every byte
//!
//! A trace that builds state then probes is strictly more powerful than
//! a single-shot `(state, seqno) → bool`: the fuzzer can discover
//! sequences where step N's divergence only manifests at step N+5.
//!
//! ## Why not `#[derive(Arbitrary)]`?
//!
//! `ReplayWindow`'s state has invariants: `late.len()` must match what
//! the trace would have produced, the `farfuture` counter is bounded by
//! how many far-future packets arrived. An `Arbitrary` impl that
//! generates `inseqno=5, late=[0xFF; 16]` is asking "what if the C and
//! Rust agree on *unreachable* states" — interesting, but secondary.
//! Trace replay generates only reachable states by construction.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tinc_ffi::c_check_seqno;
use tinc_sptps::ReplayWindow;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Byte 0: window width in bytes, clamped to [1, 64].
    //
    // `replaywin = 0` makes both impls skip the bitmap entirely (the
    // outer `if win > 0` / `if(s->replaywin)` guard) — degenerate.
    // Upper bound 64 keeps the C-side stack copy (`sptps_t` zeroed
    // every call in the shim) cheap. Default tinc value is 16; 64
    // covers `ReplayWindow = 512` from `tinc-conf` which is the
    // largest anyone sets in practice.
    let win = (data[0] % 64).max(1) as usize;

    // Byte 1: trace length cap. Unbounded traces let libFuzzer waste
    // cycles on 10K-step sequences when a 3-step sequence would have
    // found the same bug. 64 steps is enough to fill a 512-slot window
    // once over and hit every reachable bitmap configuration.
    let max_steps = (data[1] % 64) as usize + 1;

    // Twin states. C side gets a fresh `late` Vec it owns for the
    // whole trace — `c_check_seqno` borrows it per call, mutates in
    // place. Same lifetime as the Rust window's internal Vec.
    let mut rust = ReplayWindow::from_raw(0, vec![0u8; win], 0);
    let mut c_late = vec![0u8; win];
    let mut c_inseqno = 0u32;
    let mut c_farfuture = 0u32;

    // Trace: 5 bytes per step = `[seqno: u32 LE][update: bool]`.
    // Truncated final step is dropped — partial seqno is meaningless.
    let trace = &data[2..];
    for (step, chunk) in trace.chunks_exact(5).take(max_steps).enumerate() {
        let seqno = u32::from_le_bytes(chunk[..4].try_into().unwrap());
        let update = chunk[4] & 1 != 0;

        let rust_ok = rust.check_fuzz(seqno, update).is_ok();
        let (c_ok, c_in_new, c_ff_new) =
            c_check_seqno(c_inseqno, c_farfuture, &mut c_late, seqno, update);
        c_inseqno = c_in_new;
        c_farfuture = c_ff_new;

        // Verdict divergence is the headline finding.
        assert_eq!(
            rust_ok,
            c_ok,
            "VERDICT diverged at step {step}: seqno={seqno:#010x} update={update} \
             win={win} | rust_inseqno={:#010x} c_inseqno={c_inseqno:#010x}",
            rust.raw().0,
        );

        // State divergence with same verdict is the *subtle* finding:
        // both accepted but disagree on what the window looks like
        // afterward. The next packet will diverge in a way that's hard
        // to trace back without this check.
        let (r_in, r_late, r_ff) = rust.raw();
        assert_eq!(
            r_in, c_inseqno,
            "INSEQNO diverged at step {step}: seqno={seqno:#010x} update={update}"
        );
        assert_eq!(
            r_ff, c_farfuture,
            "FARFUTURE diverged at step {step}: seqno={seqno:#010x} update={update}"
        );
        assert_eq!(
            r_late,
            &c_late[..],
            "LATE[] diverged at step {step}: seqno={seqno:#010x} update={update} \
             rust={r_late:02x?} c={c_late:02x?}"
        );
    }
});
