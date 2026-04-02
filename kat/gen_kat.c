/*
 * KAT (Known Answer Test) vector generator for tinc's bespoke crypto.
 *
 * Why this exists: tinc's wire crypto is NOT off-the-shelf. Every primitive
 * deviates from the RFC/crate you'd reach for first. This program links the
 * actual C implementations and dumps deterministic test vectors so the Rust
 * port can be verified byte-for-byte before any network packet is sent.
 *
 * Output: JSON to stdout. No external deps; we hand-roll the JSON to keep
 * this buildable with nothing but a C compiler and the tinc source tree.
 *
 * Build (from repo root):
 *   cc -O0 -g -Ikat -o kat/gen_kat \
 *      kat/gen_kat.c \
 *      src/chacha-poly1305/chacha.c \
 *      src/chacha-poly1305/chacha-poly1305.c \
 *      src/chacha-poly1305/poly1305.c \
 *      src/ed25519/fe.c src/ed25519/ge.c src/ed25519/sc.c \
 *      src/ed25519/sha512.c src/ed25519/keypair.c \
 *      src/ed25519/key_exchange.c src/ed25519/sign.c src/ed25519/verify.c \
 *      src/nolegacy/prf.c
 *
 * The trick: we provide kat/system.h which shadows ../system.h via -Ikat,
 * so the vendored crypto sources compile without dragging in have.h /
 * meson-generated config / xalloc / logger.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* --- prototypes from the C crypto we link against ------------------------- */

/* chacha-poly1305: opaque ctx, but we know its size from the header */
typedef struct chacha_poly1305_ctx chacha_poly1305_ctx_t;
chacha_poly1305_ctx_t *chacha_poly1305_init(void);
void chacha_poly1305_exit(chacha_poly1305_ctx_t *);
bool chacha_poly1305_set_key(chacha_poly1305_ctx_t *, const uint8_t *key);
bool chacha_poly1305_encrypt(chacha_poly1305_ctx_t *, uint64_t seqnr,
                             const void *in, size_t inlen, void *out, size_t *outlen);
bool chacha_poly1305_decrypt(chacha_poly1305_ctx_t *, uint64_t seqnr,
                             const void *in, size_t inlen, void *out, size_t *outlen);

/* ed25519 family */
void ed25519_create_keypair(unsigned char *pub, unsigned char *priv, const unsigned char *seed);
void ed25519_key_exchange(unsigned char *shared, const unsigned char *pub, const unsigned char *priv);
void ed25519_sign(unsigned char *sig, const unsigned char *msg, size_t msglen,
                  const unsigned char *pub, const unsigned char *priv);
int  ed25519_verify(const unsigned char *sig, const unsigned char *msg, size_t msglen,
                    const unsigned char *pub);

/* TLS-1.0-style PRF over HMAC-SHA512 with A(0)=zeros quirk */
bool prf(const uint8_t *secret, size_t secretlen,
         uint8_t *seed, size_t seedlen,
         uint8_t *out, size_t outlen);

/* base64 — see kat_b64.c, copied verbatim from src/utils.c */
size_t b64encode_tinc(const void *src, char *dst, size_t length);
size_t b64encode_tinc_urlsafe(const void *src, char *dst, size_t length);
size_t b64decode_tinc(const char *src, void *dst, size_t length);

/* sha512 — already linked for ed25519. LibTomCrypt's, but it's
   bog-standard FIPS 180-2 SHA-512; the sha2 crate matches. We need
   it directly for the invitation fingerprint, which hashes a b64
   string (not the raw pubkey). */
int sha512(const void *message, size_t message_len, void *out);

/* --- stubs the linked sources expect ------------------------------------- */

/* chacha-poly1305.c uses xzalloc/xzfree/mem_eq via ../xalloc.h ../utils.h.
   Our shim system.h forward-declares them; provide trivial bodies here. */
void *xzalloc(size_t n) {
	void *p = calloc(1, n);
	if(!p) abort();
	return p;
}
void xzfree(void *p, size_t n) {
	if(p) { memset(p, 0, n); free(p); }
}
/* Constant-time compare. Real tinc has this in utils.c; we only need it
   for chacha_poly1305_decrypt's tag check, and KAT generation never calls
   decrypt on a bad tag, so a plain memcmp is fine here. */
bool mem_eq(const void *a, const void *b, size_t n) {
	return memcmp(a, b, n) == 0;
}

/* --- deterministic byte filler ------------------------------------------- */

/* xorshift64 — NOT cryptographic. We just need reproducible "random-looking"
   inputs so the KATs aren't all-zeros (which would mask carry/endian bugs). */
static uint64_t kat_rng_state;
static void kat_seed(uint64_t s) { kat_rng_state = s ? s : 0xdeadbeefULL; }
static uint8_t kat_byte(void) {
	uint64_t x = kat_rng_state;
	x ^= x << 13; x ^= x >> 7; x ^= x << 17;
	kat_rng_state = x;
	return (uint8_t)(x >> 24);
}
static void kat_fill(uint8_t *p, size_t n) {
	for(size_t i = 0; i < n; i++) p[i] = kat_byte();
}

/* --- minimal JSON emitters ------------------------------------------------ */

static void jhex(const char *name, const uint8_t *p, size_t n) {
	printf("\"%s\":\"", name);
	for(size_t i = 0; i < n; i++) printf("%02x", p[i]);
	printf("\"");
}
static void jstr(const char *name, const char *s) {
	/* No escaping needed: our strings are base64, no quotes/backslashes. */
	printf("\"%s\":\"%s\"", name, s);
}
static void ju64(const char *name, uint64_t v) {
	/* JSON numbers can't reliably represent all u64 values, so emit as
	   decimal string. The Rust side parses with u64::from_str. */
	printf("\"%s\":\"%llu\"", name, (unsigned long long)v);
}

/* --- KAT generators ------------------------------------------------------- */

static void gen_chapoly(void) {
	/* Cases chosen to hit the interesting edges:
	   - seqno = 0, 1, large, near 2^32 (SPTPS uses uint32_t seqno on wire),
	     and a value with high byte set (catches BE/LE nonce confusion)
	   - plaintext lengths 0, 1, 63, 64, 65 (ChaCha block boundary), 1500
	   - all-zero key vs filled key (zero key catches "forgot to set key")
	*/
	struct { uint64_t seq; size_t plen; uint64_t fill_seed; int zero_key; } cases[] = {
		{ 0,           0,    0x1111, 1 },
		{ 0,           1,    0x2222, 0 },
		{ 1,          16,    0x3333, 0 },
		{ 0x100,      63,    0x4444, 0 },  /* high byte in seqno */
		{ 0xdeadbeef, 64,    0x5555, 0 },  /* exactly one block */
		{ 0xffffffff, 65,    0x6666, 0 },  /* one block + 1 */
		{ 7,         100,    0x7777, 0 },
		{ 42,       1500,    0x8888, 0 },  /* MTU-ish */
		{ 0x0102030405060708ULL, 32, 0x9999, 0 }, /* every nonce byte distinct */
		{ 0,          32,    0xaaaa, 1 },  /* zero key, non-empty plaintext */
	};
	int n = sizeof(cases)/sizeof(cases[0]);

	printf("\"chapoly\":[\n");
	for(int i = 0; i < n; i++) {
		uint8_t key[64], pt[2048], ct[2048+16];
		size_t plen = cases[i].plen, olen = 0;

		if(cases[i].zero_key) {
			memset(key, 0, sizeof key);
		} else {
			kat_seed(cases[i].fill_seed ^ 0xcafe);
			kat_fill(key, sizeof key);
		}
		kat_seed(cases[i].fill_seed);
		kat_fill(pt, plen);

		chacha_poly1305_ctx_t *ctx = chacha_poly1305_init();
		chacha_poly1305_set_key(ctx, key);
		chacha_poly1305_encrypt(ctx, cases[i].seq, pt, plen, ct, &olen);
		chacha_poly1305_exit(ctx);

		printf("  {");
		jhex("key", key, 64); printf(",");
		ju64("seqno", cases[i].seq); printf(",");
		jhex("plaintext", pt, plen); printf(",");
		jhex("ciphertext", ct, olen);  /* includes 16-byte tag */
		printf("}%s\n", i+1<n ? "," : "");
	}
	printf("]");
}

static void gen_ecdh(void) {
	/* Generate two keypairs from fixed seeds, compute shared secret both
	   directions. The C code frees the private after use, so we re-derive.
	   Also dump the *expanded* private (SHA512(seed) clamped) — that's
	   what the Rust side needs to feed curve25519-dalek's mul_clamped. */
	uint64_t seed_seeds[][2] = {
		{ 0x1111, 0x2222 },
		{ 0xabcd, 0xef01 },
		{ 0x0001, 0x0002 },
		{ 0xffff, 0xeeee },
		{ 0xdead, 0xbeef },
	};
	int n = sizeof(seed_seeds)/sizeof(seed_seeds[0]);

	printf("\"ecdh\":[\n");
	for(int i = 0; i < n; i++) {
		uint8_t seed_a[32], seed_b[32];
		uint8_t priv_a[64], priv_b[64];
		uint8_t pub_a[32], pub_b[32];
		uint8_t shared_ab[32], shared_ba[32];

		kat_seed(seed_seeds[i][0]); kat_fill(seed_a, 32);
		kat_seed(seed_seeds[i][1]); kat_fill(seed_b, 32);

		ed25519_create_keypair(pub_a, priv_a, seed_a);
		ed25519_create_keypair(pub_b, priv_b, seed_b);

		/* Note: key_exchange.c only reads priv[0..32] and re-clamps. */
		ed25519_key_exchange(shared_ab, pub_b, priv_a);
		ed25519_key_exchange(shared_ba, pub_a, priv_b);

		/* Sanity: ECDH must commute. If this fails the C build is broken. */
		if(memcmp(shared_ab, shared_ba, 32) != 0) {
			fprintf(stderr, "FATAL: ECDH does not commute, case %d\n", i);
			exit(1);
		}

		printf("  {");
		jhex("seed_a", seed_a, 32); printf(",");
		jhex("priv_a", priv_a, 64); printf(",");  /* SHA512(seed), clamped */
		jhex("pub_a", pub_a, 32); printf(",");    /* Ed25519 point, NOT Montgomery */
		jhex("seed_b", seed_b, 32); printf(",");
		jhex("priv_b", priv_b, 64); printf(",");
		jhex("pub_b", pub_b, 32); printf(",");
		jhex("shared", shared_ab, 32);
		printf("}%s\n", i+1<n ? "," : "");
	}
	printf("]");
}

static void gen_prf(void) {
	/* outlen = 128 is the exact size SPTPS asks for (sizeof(sptps_key_t)).
	   Also test partial-block (100 < 128) and multi-block (200 > 128). */
	struct { size_t slen, seedlen, outlen; uint64_t fill; } cases[] = {
		{ 32,  16, 128, 0x1111 },  /* SPTPS-typical: 32B ECDH shared secret */
		{ 32,  64, 128, 0x2222 },
		{ 64, 100, 128, 0x3333 },
		{ 16,   8,  64, 0x4444 },  /* exactly one SHA512 block of output */
		{ 16,   8, 100, 0x5555 },  /* partial final block */
		{ 16,   8, 200, 0x6666 },  /* >2 blocks */
		{  1,   1,  32, 0x7777 },  /* tiny */
		{129,  16, 128, 0x8888 },  /* secret > HMAC block size (128), forces hash-the-key path */
		{  0,   8,  64, 0x9999 },  /* empty secret */
	};
	int n = sizeof(cases)/sizeof(cases[0]);

	printf("\"prf\":[\n");
	for(int i = 0; i < n; i++) {
		uint8_t secret[256], seed[256], out[256];
		kat_seed(cases[i].fill);
		kat_fill(secret, cases[i].slen);
		kat_fill(seed,   cases[i].seedlen);

		prf(secret, cases[i].slen, seed, cases[i].seedlen, out, cases[i].outlen);

		printf("  {");
		jhex("secret", secret, cases[i].slen); printf(",");
		jhex("seed",   seed,   cases[i].seedlen); printf(",");
		jhex("out",    out,    cases[i].outlen);
		printf("}%s\n", i+1<n ? "," : "");
	}
	printf("]");
}

static void gen_sign(void) {
	/* The on-disk private key is the 64-byte EXPANDED form (SHA512(seed)
	   with low half clamped). ed25519-dalek normally wants the 32-byte
	   seed; the Rust side will need hazmat::ExpandedSecretKey. We dump
	   both seed and expanded so the test can verify the expansion too. */
	struct { uint64_t key_seed; size_t msglen; uint64_t msg_seed; } cases[] = {
		{ 0x1001,   0, 0 },
		{ 0x1002,   1, 0x2002 },
		{ 0x1003,  32, 0x2003 },
		{ 0x1004, 100, 0x2004 },
		{ 0x1005, 1000, 0x2005 },
	};
	int n = sizeof(cases)/sizeof(cases[0]);

	printf("\"sign\":[\n");
	for(int i = 0; i < n; i++) {
		uint8_t seed[32], priv[64], pub[32], sig[64], msg[1024];

		kat_seed(cases[i].key_seed); kat_fill(seed, 32);
		ed25519_create_keypair(pub, priv, seed);

		kat_seed(cases[i].msg_seed); kat_fill(msg, cases[i].msglen);
		ed25519_sign(sig, msg, cases[i].msglen, pub, priv);

		if(!ed25519_verify(sig, msg, cases[i].msglen, pub)) {
			fprintf(stderr, "FATAL: sign/verify roundtrip failed, case %d\n", i);
			exit(1);
		}

		printf("  {");
		jhex("seed", seed, 32); printf(",");
		jhex("expanded_private", priv, 64); printf(",");
		jhex("public", pub, 32); printf(",");
		jhex("message", msg, cases[i].msglen); printf(",");
		jhex("signature", sig, 64);
		printf("}%s\n", i+1<n ? "," : "");
	}
	printf("]");
}

static void gen_b64(void) {
	/* tinc's base64 is NOT RFC 4648. Two deviations:
	   1. Decoder accepts BOTH '+/' AND '-_' (and even mixed in one string).
	   2. Bit packing is LSB-first: triplet = b[0] | b[1]<<8 | b[2]<<16,
	      first output char is (triplet & 63). RFC 4648 is MSB-first.
	   So even ignoring alphabet, RFC b64 won't roundtrip with this. */
	struct { size_t len; uint64_t fill; } cases[] = {
		{ 0, 0 }, { 1, 0x11 }, { 2, 0x22 }, { 3, 0x33 },
		{ 4, 0x44 }, { 31, 0x55 }, { 32, 0x66 }, { 33, 0x77 }, { 96, 0x88 },
	};
	int n = sizeof(cases)/sizeof(cases[0]);

	printf("\"b64\":[\n");
	for(int i = 0; i < n; i++) {
		uint8_t raw[128], decoded[128];
		char enc_std[256], enc_url[256];
		size_t len = cases[i].len;

		kat_seed(cases[i].fill); kat_fill(raw, len);
		size_t elen_std = b64encode_tinc(raw, enc_std, len);
		size_t elen_url = b64encode_tinc_urlsafe(raw, enc_url, len);

		/* Verify roundtrip on both alphabets. */
		size_t dlen = b64decode_tinc(enc_std, decoded, elen_std);
		if(dlen != len || memcmp(raw, decoded, len) != 0) {
			fprintf(stderr, "FATAL: b64 std roundtrip failed, case %d\n", i);
			exit(1);
		}
		dlen = b64decode_tinc(enc_url, decoded, elen_url);
		if(dlen != len || memcmp(raw, decoded, len) != 0) {
			fprintf(stderr, "FATAL: b64 url roundtrip failed, case %d\n", i);
			exit(1);
		}

		printf("  {");
		jhex("raw", raw, len); printf(",");
		jstr("encoded_std", enc_std); printf(",");
		jstr("encoded_urlsafe", enc_url);
		printf("}%s\n", i+1<n ? "," : "");
	}
	printf("]");
}

/* --- invitation crypto kernel --------------------------------------------
 *
 * Why this needs KAT vectors and not just a roundtrip test:
 *
 * The invitation URL slug binds three values via a chain of
 * compositions where every boundary is a place to be off by one:
 *
 *   fingerprint  = b64_std(pubkey)         -- 43 chars, NOT urlsafe
 *   key_hash     = sha512(fingerprint)     -- the b64 STRING, not raw key
 *   cookie_hash  = sha512(cookie || fingerprint)  -- same fingerprint reused
 *   slug         = b64_url(key_hash[..18]) || b64_url(cookie[..18])  -- 24+24
 *   filename     = b64_url(cookie_hash[..18])                        -- 24
 *
 * Three places use this identically:
 *   invitation.c:500   cmd_invite:    computes all three to make the file+URL
 *   invitation.c:1400  cmd_join:      verifies key_hash from slug after greeting
 *   protocol_auth.c:199 daemon:       recomputes cookie_hash to find the file
 *
 * Silent-failure modes a roundtrip test would miss but a KAT catches:
 *   - hashing the raw pubkey instead of its b64 ("obviously" simpler...)
 *   - using b64_urlsafe for the fingerprint (no — ecdsa_get_base64_public_key
 *     calls b64encode_tinc, the +/ variant; only the OUTPUT is urlsafe)
 *   - truncating to 16 bytes instead of 18 (still 24 b64 chars at first
 *     glance because 18 → 24 via b64, but 16 → 22)
 *   - hashing fingerprint || cookie instead of cookie || fingerprint
 *
 * The daemon recomputes cookie_hash; if invite and daemon disagree on
 * any of these, `tinc join` connects, handshakes, sends the cookie,
 * and the daemon says "non-existing invitation". Nothing in the Rust
 * test suite would catch that until the daemon exists.
 */
static void gen_invitation(void) {
	/* Three test cases. All-zeros catches the "forgot to use the input"
	   class. Two distinct random fills cover the algebraic space. */
	struct { uint64_t key_seed; uint64_t cookie_seed; } cases[] = {
		{ 0x9001, 0x9002 },
		{ 0x9003, 0x9004 },
		{ 0, 0 },  /* both kat_seed(0) → 0xdeadbeef, but distinct streams */
	};
	int n = sizeof(cases) / sizeof(cases[0]);

	printf("\"invitation\":[\n");
	for(int i = 0; i < n; i++) {
		/* Generate a real Ed25519 keypair from the seed. We need a
		   real pubkey because the fingerprint hashes its b64 form,
		   and the b64 of a random 32-byte buffer would test the
		   composition just as well — but using ed25519_create_keypair
		   means these vectors also serve as "what does an actual
		   invitation key look like", which makes debugging less
		   abstract. The Rust test parses the seed, regenerates the
		   key (already KAT'd in 'sign'), and checks the rest. */
		uint8_t seed[32], pubkey[32], privkey[64];
		kat_seed(cases[i].key_seed);
		kat_fill(seed, 32);
		ed25519_create_keypair(pubkey, privkey, seed);

		/* Cookie: 18 bytes raw. invitation.c:508 `randomize(cookie, 18)`. */
		uint8_t cookie[18];
		kat_seed(cases[i].cookie_seed);
		kat_fill(cookie, 18);

		/* === Replicate invitation.c:499-518 exactly. ===
		   Same buffer reuse, same in-place encode tricks. We don't
		   reuse buffers here (clarity > fidelity for the generator)
		   but the byte values must match. */

		/* fingerprint = b64encode_tinc(pubkey, _, 32) — the +/ variant.
		   This is ecdsa_get_base64_public_key's body (ecdsa.c:62).
		   43 chars + NUL. */
		char fingerprint[44];
		size_t fplen = b64encode_tinc(pubkey, fingerprint, 32);
		if(fplen != 43) {
			fprintf(stderr, "FATAL: pubkey b64 length %zu != 43\n", fplen);
			exit(1);
		}

		/* key_hash = sha512(fingerprint, strlen(fingerprint), _).
		   invitation.c:501. Yes, strlen — the input is the ASCII
		   string, not the raw bytes. This is the boundary that
		   matters: 32-byte raw pubkey → 43-char string → hash. */
		char key_hash[64];
		sha512(fingerprint, fplen, key_hash);

		/* key_hash_b64 = b64encode_tinc_urlsafe(key_hash, _, 18).
		   invitation.c:502. ONLY THE FIRST 18 BYTES of the digest.
		   18 → 24 chars (18*4/3). This is the first 24 chars of the
		   URL slug — it authenticates the inviting daemon. */
		char key_hash_b64[25];
		b64encode_tinc_urlsafe(key_hash, key_hash_b64, 18);

		/* cookie_hash = sha512(cookie || fingerprint).
		   invitation.c:511-517. The buffer is cookie-first; this
		   ordering is what protocol_auth.c:199 must replicate to
		   find the invitation file. */
		uint8_t hashbuf[18 + 43];
		memcpy(hashbuf, cookie, 18);
		memcpy(hashbuf + 18, fingerprint, 43);
		char cookie_hash[64];
		sha512(hashbuf, sizeof(hashbuf), cookie_hash);

		/* cookie_hash_b64 = the filename.
		   invitation.c:518 + protocol_auth.c:207. */
		char cookie_hash_b64[25];
		b64encode_tinc_urlsafe(cookie_hash, cookie_hash_b64, 18);

		/* cookie_b64 = the second 24 chars of the URL slug.
		   invitation.c:522. */
		char cookie_b64[25];
		b64encode_tinc_urlsafe(cookie, cookie_b64, 18);

		/* Roundtrip sanity: cmd_join's b64decode_tinc on the slug
		   halves must recover the same bytes. invitation.c:1310.
		   The decoder is alphabet-agnostic so urlsafe → raw works
		   without specifying which. */
		uint8_t check[18];
		if(b64decode_tinc(key_hash_b64, check, 24) != 18
		   || memcmp(check, key_hash, 18) != 0) {
			fprintf(stderr, "FATAL: key_hash slug roundtrip\n");
			exit(1);
		}
		if(b64decode_tinc(cookie_b64, check, 24) != 18
		   || memcmp(check, cookie, 18) != 0) {
			fprintf(stderr, "FATAL: cookie slug roundtrip\n");
			exit(1);
		}

		/* Emit. We give the Rust test enough to recompute
		   everything from (seed, cookie) and check intermediates.
		   Only seed is the true input — pubkey is derived,
		   fingerprint is derived from that, etc. — but emitting
		   intermediates means a KAT failure points at the broken
		   stage instead of just "slug is wrong". */
		printf("  {");
		jhex("key_seed", seed, 32);                 printf(",");
		jhex("cookie", cookie, 18);                 printf(",");
		jhex("pubkey", pubkey, 32);                 printf(",");
		jstr("fingerprint", fingerprint);           printf(",");
		jstr("key_hash_b64", key_hash_b64);         printf(",");
		jstr("cookie_b64", cookie_b64);             printf(",");
		jstr("cookie_hash_b64", cookie_hash_b64);
		printf("}%s\n", i+1<n ? "," : "");
	}
	printf("]");
}

int main(void) {
	printf("{\n");
	gen_chapoly(); printf(",\n");
	gen_ecdh();    printf(",\n");
	gen_prf();     printf(",\n");
	gen_sign();    printf(",\n");
	gen_b64();     printf(",\n");
	gen_invitation();
	printf("\n}\n");
	return 0;
}
