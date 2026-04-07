/*
 * Differential-fuzz shim for sptps_check_seqno.
 *
 * The function is `static` in sptps.c — invisible to the linker. We
 * #include the .c file directly (unity-build style) so the static is
 * in scope here, then export a thin wrapper.
 *
 * This TU is compiled INSTEAD of sptps.c, not alongside it: the
 * #include brings every non-static symbol from sptps.c into this TU,
 * so compiling both would duplicate-define sptps_start et al.
 *
 * Why a fresh sptps_t per call instead of one persistent harness:
 * the fuzzer interprets each input as an entire trace (initial state +
 * a sequence of seqnos). Building both sides from scratch on every
 * input means a divergence is fully reproducible from the input bytes
 * alone — no hidden state carried across iterations. libFuzzer's
 * persistent mode reuses the process; we don't want it reusing state.
 */

/* shim.h is force-included; sptps.h is unsuppressed. The .c file
   itself includes sptps.h, so the struct body and the SPTPS_* constants
   come through normally. */
#include "../../../tinc-c/src/sptps.c"

/*
 * Mirror of the bits of sptps_t the replay window touches. Rust packs
 * a ReplayWindow into this, we copy into a real sptps_t, run the C,
 * copy back. The double-copy is the price of not exposing struct
 * offsets to Rust (which would break on the OpenSSL build).
 *
 * `late` is a pointer to a Rust-owned buffer. sptps_check_seqno
 * indexes it with `[(seqno/8) % replaywin]` — at most `replaywin`
 * bytes. The Rust caller guarantees that length.
 */
typedef struct {
	uint32_t inseqno;
	uint32_t farfuture;
	uint32_t replaywin;
	uint8_t  *late;
} ffi_replay_state_t;

/* sptps_log defaults to sptps_log_stderr (sptps.c:56). The harness's
   ffi_start() sets it to quiet, but ffi_check_seqno doesn't go through
   that. Set once on first call — the global is process-wide and the
   fuzz target never runs handshakes so nobody else cares. */
static void ensure_quiet(void) {
	static bool done = false;
	if (!done) { sptps_log = sptps_log_quiet; done = true; }
}

bool ffi_check_seqno(ffi_replay_state_t *st, uint32_t seqno, bool update) {
	ensure_quiet();
	/* sptps_check_seqno reads: replaywin, inseqno, farfuture, late.
	   It writes: inseqno, farfuture, late, received. Nothing else.
	   A zeroed sptps_t with those four populated is sufficient — the
	   error() macro inside reads s->state for the log message but
	   sptps_log is set to quiet so that's a no-op. */
	sptps_t s;
	memset(&s, 0, sizeof s);
	s.replaywin = st->replaywin;
	s.inseqno   = st->inseqno;
	s.farfuture = st->farfuture;
	s.late      = st->late;

	bool ok = sptps_check_seqno(&s, seqno, update);

	st->inseqno   = s.inseqno;
	st->farfuture = s.farfuture;
	/* late was mutated in place via the pointer. */
	return ok;
}

