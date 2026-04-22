/* One-shot Poly1305 wrapper around the OpenSSL/CRYPTOGAMS
 * poly1305-armv8 kernel. The asm exposes init/blocks/emit with a
 * function-pointer dispatch (scalar vs NEON chosen at init); this file
 * supplies the OPENSSL_armcap_P capability word and the partial-block
 * tail handling that OpenSSL normally does in crypto/poly1305/poly1305.c.
 *
 * Licensed under the same terms as the asm (Apache-2.0; see
 * poly1305-armv8-*.S header). */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arm_arch.h"

/* NEON is architecturally mandatory on AArch64 (ARMv8-A AdvSIMD), so
 * there is no runtime detection to do — set the bit unconditionally and
 * let poly1305_init hand back the NEON code path. */
unsigned int OPENSSL_armcap_P = ARMV7_NEON;

#define POLY1305_BLOCK_SIZE 16

typedef void (*poly1305_blocks_f)(void *ctx, const unsigned char *inp,
                                  size_t len, unsigned int padbit);
typedef void (*poly1305_emit_f)(void *ctx, unsigned char mac[16],
                                const unsigned int nonce[4]);

/* asm entry points (poly1305-armv8.S) */
extern int poly1305_init(void *ctx, const unsigned char key[16], void *func);

/* tinc_poly1305: one-shot MAC over `inp[0..len]` with 32-byte key,
 * writing the 16-byte tag to `mac`. Mirrors OpenSSL's
 * Poly1305_Init/Update/Final flattened for the single-call shape SPTPS
 * needs (one record, no streaming). */
void tinc_poly1305(const unsigned char key[32], const unsigned char *inp,
                   size_t len, unsigned char mac[16]) {
    /* Opaque scratch sized after OpenSSL's `double opaque[24]`; the
     * NEON path lays out r^1..r^4 precompute tables past the 48-byte
     * scalar state. 16-byte alignment for the NEON ld1/st1. */
    unsigned char opaque[192] __attribute__((aligned(16)));
    struct {
        poly1305_blocks_f blocks;
        poly1305_emit_f emit;
    } func;
    unsigned int nonce[4];

    /* key[16..32] is the additive `s` half; emit() adds it at the end.
     * Explicit LE load (matching OpenSSL's U8TOU32) so __AARCH64EB__
     * targets get the same words memcpy would give on LE. */
    for (int i = 0; i < 4; i++) {
        const unsigned char *p = key + 16 + 4 * i;
        nonce[i] = (unsigned int)p[0] | (unsigned int)p[1] << 8 |
                   (unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
    }

    poly1305_init(opaque, key, &func);

    size_t bulk = len & ~(size_t)(POLY1305_BLOCK_SIZE - 1);
    if (bulk) {
        func.blocks(opaque, inp, bulk, 1);
        inp += bulk;
        len -= bulk;
    }
    if (len) {
        /* Partial tail: pad with the explicit 0x01 bit then zeros, and
         * call blocks() with padbit=0 so the asm doesn't add its own. */
        unsigned char tail[POLY1305_BLOCK_SIZE] = {0};
        memcpy(tail, inp, len);
        tail[len] = 1;
        func.blocks(opaque, tail, POLY1305_BLOCK_SIZE, 0);
    }
    func.emit(opaque, mac, nonce);
}
