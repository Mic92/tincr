/*
 * Force-included shim system.h for the SPTPS FFI harness.
 *
 * Same trick as kat/system.h: predefine the include guards for tinc's real
 * headers so they become no-ops, then force-include this file to provide
 * the handful of symbols sptps.c actually needs.
 *
 * The crypto sources are pure computation. sptps.c is *almost* pure: it
 * touches errno, stdarg, and byte-order intrinsics, but no syscalls. The
 * one I/O-shaped thing — `randomize()` — is a function pointer we hijack
 * for determinism.
 */
#ifndef TINC_FFI_SHIM_H
#define TINC_FFI_SHIM_H

/* ge.c defines a static `select()` that collides with libc's select(2)
   pulled in via <stdlib.h> on glibc. Kill that one header before any
   transitive include reaches it. */
#define _SYS_SELECT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>   /* ntohl, ntohs, htons — sptps.c byte-orders the wire format */

#ifdef _WIN32
#  include <malloc.h>
#else
#  include <alloca.h>
#endif

/*
 * Attribute macros from have.h. We no-op them — they're hints, not ABI.
 * One exception: PACKED matters. sptps_kex_t is `STATIC_ASSERT == 65`;
 * unpacked it'd round up to 68 and the wire format would shift.
 */
#define ATTR_MALLOC
#define ATTR_DEALLOCATOR(x)
#define ATTR_FORMAT(a,b,c)
#define ATTR_NONNULL
#define ATTR_WARN_UNUSED
#define PACKED(decl) decl __attribute__((__packed__))
#define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* xalloc.h surface used by sptps.c + chacha-poly1305.c. Bodies in shim.c. */
void *xzalloc(size_t n);
void  xzfree(void *p, size_t n);
void  memzero(void *buf, size_t buflen);

/* utils.h: mem_eq is the constant-time tag compare in chacha-poly1305.c. */
bool mem_eq(const void *a, const void *b, size_t n);

/* random.h: see shim.c for why this is a deterministic stream and not
   getrandom(2). Body in shim.c. */
void randomize(void *vout, size_t outlen);

/* prf.h: prototype only (body is the real nolegacy/prf.c). */
bool prf(const uint8_t *secret, size_t secretlen,
         uint8_t *seed, size_t seedlen,
         uint8_t *out, size_t outlen);

/*
 * ecdsa.h: we suppress the real header (it pulls in logger + base64 + PEM
 * machinery we don't want). sptps.c only ever does `ecdsa_t *` and the
 * three calls below. The struct body lives in shim.c — only that TU
 * dereferences. To everyone else it's a pointer-sized cookie, which is
 * exactly what TINC_ECDSA_INTERNAL would have given them anyway.
 */
typedef struct ecdsa ecdsa_t;
size_t ecdsa_size(ecdsa_t *e);
bool   ecdsa_sign(ecdsa_t *e, const void *in, size_t len, void *sig);
bool   ecdsa_verify(ecdsa_t *e, const void *in, size_t len, const void *sig);

#endif /* TINC_FFI_SHIM_H */
