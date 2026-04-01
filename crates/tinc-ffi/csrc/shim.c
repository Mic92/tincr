/*
 * Glue between sptps.c and the Rust harness.
 *
 * Three jobs:
 *   1. Own the awkward C types (sptps_t, ecdsa_t) so Rust can treat them
 *      as opaque pointers.
 *   2. Route the C callbacks into a heap-allocated event sink that Rust
 *      can drain after each FFI call.
 *   3. Hijack randomize() for determinism — without this the harness is
 *      worthless as a Phase-2 differential oracle.
 *
 * No headers from src/ are included here: every type whose layout we
 * actually depend on is open-coded below, every type we don't is opaque.
 * That's deliberate. The header chain in tinc is a meson-generated tangle,
 * and the moment we #include "sptps.h" properly we're back to figuring
 * out have.h, config.h, the works. The handful of struct mirrors below
 * are guarded by static asserts so they break loudly if upstream changes
 * a layout.
 */

/* sptps.h declarations. The type chain is satisfied by shim.h (force-
   included): ecdsa_t is forward-declared there. We re-declare just the
   five entry points with void* for the key params — they're
   never-dereferenced cookies on this side, and void* keeps us honest
   about that. The linker doesn't care about parameter types. */
typedef struct sptps sptps_t;
typedef bool (*send_data_t)(void *handle, uint8_t type, const void *data, size_t len);
typedef bool (*receive_record_t)(void *handle, uint8_t type, const void *data, uint16_t len);

extern bool   sptps_start(sptps_t *s, void *handle, bool initiator, bool datagram,
                          void *mykey, void *hiskey, const void *label, size_t labellen,
                          send_data_t send_data, receive_record_t receive_record);
extern bool   sptps_stop(sptps_t *s);
extern bool   sptps_send_record(sptps_t *s, uint8_t type, const void *data, uint16_t len);
extern size_t sptps_receive_data(sptps_t *s, const void *data, size_t len);
extern bool   sptps_force_kex(sptps_t *s);

/* Silence the C log callback — Rust drives, Rust decides what to print. */
extern void sptps_log_quiet(sptps_t *s, int s_errno, const char *format, va_list ap);
extern void (*sptps_log)(sptps_t *s, int s_errno, const char *format, va_list ap);


/* ──────────────────────────────────────────────────────────────────── */
/* xalloc.h / utils.h shims                                            */

void *xzalloc(size_t n) { return calloc(1, n); }

void xzfree(void *p, size_t n) {
	if (p) {
		/* Real xalloc.h's memzero uses explicit_bzero where available
		   to defeat the optimizer. We don't care here — this is a
		   test harness, not a key handler — but a volatile fn ptr
		   is cheap insurance against the compiler proving the memset
		   dead because free() follows. */
		memzero(p, n);
		free(p);
	}
}

void memzero(void *buf, size_t buflen) {
	static void *(*volatile memset_fn)(void *, int, size_t) = memset;
	memset_fn(buf, 0, buflen);
}

bool mem_eq(const void *a, const void *b, size_t n) {
	/* Upstream's mem_eq is constant-time. Our Phase 0a Rust chapoly does
	   its own ct compare via subtle, so this only ever runs inside the
	   C-side decrypt path. Match the semantics anyway — a timing-variant
	   shim that *happens* to be exercised by a future test is the kind
	   of footgun that bites two phases later. */
	const volatile uint8_t *pa = a, *pb = b;
	uint8_t diff = 0;
	for (size_t i = 0; i < n; i++) diff |= pa[i] ^ pb[i];
	return diff == 0;
}


/* ──────────────────────────────────────────────────────────────────── */
/* Deterministic randomize()                                           */
/*                                                                     */
/* sptps_start → send_kex calls randomize() twice: once for the 32-byte */
/* nonce, once (via ecdh_generate_public) for the 32-byte ECDH seed.    */
/* Both are 32 bytes — handy. We ChaCha20 a fixed key+nonce stream so   */
/* the bytes are reproducible *and* indistinguishable from random:      */
/* future fuzzing of the Rust SPTPS state machine will use this same    */
/* stream as its oracle baseline, and a counter-based RNG would mask    */
/* bugs that only trip on high-entropy input (e.g. Ed25519 point        */
/* decompression edge cases).                                           */
/*                                                                     */
/* The seed is per-harness: Rust sets it via ffi_seed_rng() before      */
/* each session so two concurrent C↔C peers get distinct keys.          */

extern void chacha_keysetup(void *ctx, const uint8_t *k, uint32_t kbits);
extern void chacha_ivsetup(void *ctx, const uint8_t *iv, const uint8_t *counter);
extern void chacha_encrypt_bytes(void *ctx, const uint8_t *m, uint8_t *c, uint32_t bytes);

/* chacha_ctx in chacha.h is `u_int input[16]`. We don't want to include
   the header (it has its own dance), so allocate generously and let the
   keysetup routine treat it as bytes. 16*4 + slop. */
static uint8_t rng_ctx[128];
static bool    rng_seeded;

void ffi_seed_rng(const uint8_t key32[32]) {
	static const uint8_t iv_zero[8] = {0};
	chacha_keysetup(rng_ctx, key32, 256);
	chacha_ivsetup(rng_ctx, iv_zero, NULL);
	rng_seeded = true;
}

void randomize(void *vout, size_t outlen) {
	/* Hard fail on misuse. A handshake under random=zeros is a perfectly
	   valid handshake — and a test that "passes" against the wrong
	   determinism is worse than no test. */
	if (!rng_seeded) {
		fprintf(stderr, "tinc-ffi: randomize() before ffi_seed_rng()\n");
		abort();
	}
	/* chacha_encrypt_bytes XORs against the input buffer; for a keystream
	   we want zeros in. The C source uses uint32_t internally so it's
	   safe to feed it the same buffer for in & out. */
	memset(vout, 0, outlen);
	chacha_encrypt_bytes(rng_ctx, vout, vout, (uint32_t)outlen);
}


/* ──────────────────────────────────────────────────────────────────── */
/* ecdsa_t: thin wrapper over the raw 96-byte key blob.                */
/*                                                                     */
/* sptps.c only calls ecdsa_sign / ecdsa_verify / ecdsa_size. The real */
/* ecdsa.c also has read_pem, base64, logger calls — none of which we   */
/* want. So: ship our own ecdsa_t. The layout MUST match what           */
/* tinc-crypto::sign::SigningKey::from_blob expects, since the Phase 2  */
/* test will feed identical 96-byte blobs to both sides.                */

/* shim.h forward-declared `struct ecdsa`; here's the body. Tagged so the
   types unify — an anonymous struct typedef would be a distinct type and
   the `ecdsa_t*` from sptps.c wouldn't convert. */
struct ecdsa {
	uint8_t private[64];
	uint8_t public[32];
};
STATIC_ASSERT(sizeof(ecdsa_t) == 96, "ecdsa_t blob layout drifted");

/* Direct calls into the vendored ed25519. Re-declared because we
   suppressed the header. */
extern void ed25519_sign(uint8_t *sig, const uint8_t *msg, size_t len,
                         const uint8_t *pub, const uint8_t *priv);
extern int  ed25519_verify(const uint8_t *sig, const uint8_t *msg, size_t len,
                           const uint8_t *pub);

size_t ecdsa_size(ecdsa_t *e) { (void)e; return 64; }

bool ecdsa_sign(ecdsa_t *e, const void *in, size_t len, void *sig) {
	ed25519_sign(sig, in, len, e->public, e->private);
	return true;
}

bool ecdsa_verify(ecdsa_t *e, const void *in, size_t len, const void *sig) {
	return ed25519_verify(sig, in, len, e->public) != 0;
}

void *ffi_ecdsa_from_blob(const uint8_t blob[96]) {
	ecdsa_t *e = xzalloc(sizeof *e);
	memcpy(e, blob, sizeof *e);
	return e;
}

void ffi_ecdsa_free(void *e) {
	xzfree(e, sizeof(ecdsa_t));
}


/* ──────────────────────────────────────────────────────────────────── */
/* Event sink: where the C callbacks dump bytes.                       */
/*                                                                     */
/* sptps_start fires send_data *during* the call (it sends KEX before   */
/* returning). sptps_receive_data may fire send_data, receive_record,   */
/* or both, multiple times, in one call (a single buffer can hold       */
/* several records). So the safe Rust wrapper can't be `fn() -> Event`; */
/* it has to be `fn() -> Vec<Event>` with the Vec filled in here.       */
/*                                                                     */
/* We use a flat byte arena rather than per-event mallocs: each event   */
/* is [kind:u8][type:u8][len:u32][payload:len]. Rust slices it apart.   */
/* This sidesteps the question of who frees which pointer when the      */
/* event count is variable — there's exactly one buffer to hand back.   */

#define SINK_CAP (64 * 1024)

enum { EV_WIRE = 1, EV_RECORD = 2, EV_HANDSHAKE_DONE = 3 };

typedef struct {
	uint8_t buf[SINK_CAP];
	size_t  len;
	bool    overflow;
} sink_t;

static void sink_push(sink_t *s, uint8_t kind, uint8_t type,
                      const void *data, size_t len) {
	if (s->len + 6 + len > SINK_CAP) {
		/* 64K is enough for any sane handshake (KEX=65, SIG=64,
		   plus framing). If a test pumps more than that through a
		   single receive call, that's a test bug — flag it rather
		   than silently dropping events. */
		s->overflow = true;
		return;
	}
	uint8_t *p = s->buf + s->len;
	p[0] = kind;
	p[1] = type;
	uint32_t l32 = (uint32_t)len;
	memcpy(p + 2, &l32, 4);   /* host endian; same process reads it back */
	if (len) memcpy(p + 6, data, len);
	s->len += 6 + len;
}

static bool cb_send_data(void *handle, uint8_t type, const void *data, size_t len) {
	sink_push(handle, EV_WIRE, type, data, len);
	return true;
}

static bool cb_receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	if (type == 128 /* SPTPS_HANDSHAKE */ && len == 0) {
		/* sptps.c signals "handshake complete" by calling
		   receive_record(SPTPS_HANDSHAKE, NULL, 0). It's how
		   sptps_test.c learns when to start sending app data.
		   Surface it as a distinct event kind so Rust doesn't
		   have to re-derive that. */
		sink_push(handle, EV_HANDSHAKE_DONE, 0, NULL, 0);
	} else {
		sink_push(handle, EV_RECORD, type, data, len);
	}
	return true;
}


/* ──────────────────────────────────────────────────────────────────── */
/* The harness handle. One per SPTPS session.                          */
/*                                                                     */
/* sptps_t is variable-size depending on the build (ecdsa_t* vs the     */
/* OpenSSL-backed one, etc) and we deliberately didn't include the      */
/* header that defines it. So: ask the compiler at link time. We add    */
/* a tiny TU compiled *with* the real header just to export sizeof.     */
/* That's csrc/sizeof.c. Here we just consume the answer.               */

extern const size_t SPTPS_T_SIZE;

typedef struct {
	sink_t  sink;
	uint8_t sptps[];   /* SPTPS_T_SIZE bytes, opaque */
} harness_t;

void *ffi_harness_new(void) {
	harness_t *h = calloc(1, sizeof(harness_t) + SPTPS_T_SIZE);
	return h;
}

void ffi_harness_free(void *vh) {
	harness_t *h = vh;
	if (h) {
		sptps_stop((sptps_t *)h->sptps);
		free(h);
	}
}

/* Drain returns the sink length and zeros the cursor. Rust reads
   sink.buf directly via a pointer accessor — no copy. */
size_t ffi_drain(void *vh, const uint8_t **out_buf, bool *out_overflow) {
	harness_t *h = vh;
	*out_buf = h->sink.buf;
	*out_overflow = h->sink.overflow;
	size_t n = h->sink.len;
	h->sink.len = 0;
	h->sink.overflow = false;
	return n;
}

bool ffi_start(void *vh, bool initiator, bool datagram,
               void *mykey, void *hiskey,
               const uint8_t *label, size_t labellen) {
	harness_t *h = vh;
	sptps_log = sptps_log_quiet;
	return sptps_start((sptps_t *)h->sptps, &h->sink,
	                   initiator, datagram, mykey, hiskey,
	                   label, labellen, cb_send_data, cb_receive_record);
}

size_t ffi_receive(void *vh, const uint8_t *data, size_t len) {
	harness_t *h = vh;
	return sptps_receive_data((sptps_t *)h->sptps, data, len);
}

bool ffi_send_record(void *vh, uint8_t type, const uint8_t *data, uint16_t len) {
	harness_t *h = vh;
	return sptps_send_record((sptps_t *)h->sptps, type, data, len);
}

bool ffi_force_kex(void *vh) {
	harness_t *h = vh;
	return sptps_force_kex((sptps_t *)h->sptps);
}
